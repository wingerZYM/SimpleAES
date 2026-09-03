#pragma once

#include <array>
#include <cstdint>
#include <limits>
#include <memory.h>
#include <random>
#include <vector>

#include <immintrin.h> // For AVX-512 and VAES

// AES // ECB/CBC/CTR/GCM // PKCS7Padding/ZerosPadding

constexpr size_t WAesGCMNonceSize = 12;
constexpr size_t WAesGCMTagSize = 16;

struct GCMResult {
  std::array<uint8_t, WAesGCMNonceSize> nonce{};
  std::array<uint8_t, WAesGCMTagSize> tag{};
};

enum class Padding {
  Zeros,
  PKCS7,
};

namespace waes_gcm_detail {

inline void store64BE(uint8_t *out, uint64_t value) noexcept {
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

inline void multiplyPortable(uint8_t value[16], const uint8_t h[16]) noexcept {
  uint8_t product[16] = {};
  uint8_t factor[16];
  memcpy(factor, h, sizeof(factor));
  for (size_t bit = 0; bit < 128; ++bit) {
    const uint8_t mask =
        static_cast<uint8_t>(0u - ((value[bit / 8] >> (7 - bit % 8)) & 1u));
    for (size_t i = 0; i < 16; ++i) {
      product[i] ^= factor[i] & mask;
    }
    const uint8_t reductionMask = static_cast<uint8_t>(0u - (factor[15] & 1u));
    for (size_t i = 15; i != 0; --i) {
      factor[i] =
          static_cast<uint8_t>((factor[i] >> 1) | ((factor[i - 1] & 1u) << 7));
    }
    factor[0] >>= 1;
    factor[0] ^= static_cast<uint8_t>(0xe1u & reductionMask);
  }
  memcpy(value, product, sizeof(product));
}

#if defined(_MSC_VER) || defined(__PCLMUL__)
inline __m128i reverseBitsInBytes(__m128i value) noexcept {
  const __m128i lookup =
      _mm_setr_epi8(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15);
  const __m128i nibbleMask = _mm_set1_epi8(0x0f);
  const __m128i low = _mm_and_si128(value, nibbleMask);
  const __m128i high = _mm_and_si128(_mm_srli_epi16(value, 4), nibbleMask);
  return _mm_or_si128(_mm_slli_epi16(_mm_shuffle_epi8(lookup, low), 4),
                      _mm_shuffle_epi8(lookup, high));
}

inline void multiplyPCLMUL(uint8_t value[16], const uint8_t h[16]) noexcept {
  const __m128i lhs = reverseBitsInBytes(
      _mm_loadu_si128(reinterpret_cast<const __m128i *>(value)));
  const __m128i rhs =
      reverseBitsInBytes(_mm_loadu_si128(reinterpret_cast<const __m128i *>(h)));
  const __m128i p00 = _mm_clmulepi64_si128(lhs, rhs, 0x00);
  const __m128i p01 = _mm_clmulepi64_si128(lhs, rhs, 0x01);
  const __m128i p10 = _mm_clmulepi64_si128(lhs, rhs, 0x10);
  const __m128i p11 = _mm_clmulepi64_si128(lhs, rhs, 0x11);
  const __m128i middle = _mm_xor_si128(p01, p10);
  alignas(16) uint64_t low[2];
  alignas(16) uint64_t cross[2];
  alignas(16) uint64_t high[2];
  _mm_store_si128(reinterpret_cast<__m128i *>(low), p00);
  _mm_store_si128(reinterpret_cast<__m128i *>(cross), middle);
  _mm_store_si128(reinterpret_cast<__m128i *>(high), p11);
  uint64_t low0 = low[0];
  uint64_t low1 = low[1] ^ cross[0];
  const uint64_t high0 = high[0] ^ cross[1];
  const uint64_t high1 = high[1];
  low0 ^= high0 ^ (high0 << 1) ^ (high0 << 2) ^ (high0 << 7);
  low1 ^= high1 ^ (high1 << 1) ^ (high0 >> 63) ^ (high1 << 2) ^ (high0 >> 62) ^
          (high1 << 7) ^ (high0 >> 57);
  const uint64_t overflow = (high1 >> 63) ^ (high1 >> 62) ^ (high1 >> 57);
  low0 ^= overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
  const uint64_t reducedWords[2] = {low0, low1};
  const __m128i reduced =
      _mm_loadu_si128(reinterpret_cast<const __m128i *>(reducedWords));
  _mm_storeu_si128(reinterpret_cast<__m128i *>(value),
                   reverseBitsInBytes(reduced));
}
#endif

inline void multiply(uint8_t value[16], const uint8_t h[16]) noexcept {
#if defined(_MSC_VER) || defined(__PCLMUL__)
  multiplyPCLMUL(value, h);
#else
  multiplyPortable(value, h);
#endif
}

inline void update(uint8_t hash[16], const uint8_t *data, size_t length,
                   const uint8_t h[16]) noexcept {
  while (length >= 16) {
    for (size_t i = 0; i < 16; ++i) {
      hash[i] ^= data[i];
    }
    multiply(hash, h);
    data += 16;
    length -= 16;
  }
  if (length != 0) {
    uint8_t block[16] = {};
    memcpy(block, data, length);
    for (size_t i = 0; i < 16; ++i) {
      hash[i] ^= block[i];
    }
    multiply(hash, h);
  }
}

inline bool validLengths(size_t textLength, size_t aadLength) noexcept {
  const uint64_t maxTextLength = (uint64_t(1) << 36) - 32;
  return static_cast<uint64_t>(textLength) <= maxTextLength &&
         static_cast<uint64_t>(aadLength) <=
             (std::numeric_limits<uint64_t>::max)() / 8;
}

inline void incrementCounter(uint8_t counter[16]) noexcept {
  for (size_t i = 16; i != 12; --i) {
    if (++counter[i - 1] != 0) {
      break;
    }
  }
}

template <typename EncryptBlock>
inline void crypt(const uint8_t *input, size_t length, uint8_t *output,
                  const uint8_t nonce[WAesGCMNonceSize],
                  const EncryptBlock &encryptBlock) {
  uint8_t counter[16] = {};
  memcpy(counter, nonce, WAesGCMNonceSize);
  counter[15] = 1;
  while (length != 0) {
    uint8_t stream[16];
    incrementCounter(counter);
    encryptBlock(counter, stream);
    const size_t chunk = length < 16 ? length : 16;
    for (size_t i = 0; i < chunk; ++i) {
      output[i] = input[i] ^ stream[i];
    }
    input += chunk;
    output += chunk;
    length -= chunk;
  }
}

template <typename EncryptBlock>
inline void calculateTag(const uint8_t *ciphertext, size_t textLength,
                         const uint8_t *aad, size_t aadLength,
                         const uint8_t nonce[WAesGCMNonceSize],
                         const uint8_t h[16], uint8_t tag[WAesGCMTagSize],
                         const EncryptBlock &encryptBlock) {
  uint8_t hash[16] = {};
  update(hash, aad, aadLength, h);
  update(hash, ciphertext, textLength, h);
  uint8_t lengths[16];
  store64BE(lengths, static_cast<uint64_t>(aadLength) * 8);
  store64BE(lengths + 8, static_cast<uint64_t>(textLength) * 8);
  update(hash, lengths, sizeof(lengths), h);
  uint8_t j0[16] = {};
  memcpy(j0, nonce, WAesGCMNonceSize);
  j0[15] = 1;
  uint8_t mask[16];
  encryptBlock(j0, mask);
  for (size_t i = 0; i < WAesGCMTagSize; ++i) {
    tag[i] = hash[i] ^ mask[i];
  }
}

inline bool tagsEqual(const uint8_t lhs[WAesGCMTagSize],
                      const uint8_t rhs[WAesGCMTagSize]) noexcept {
  uint8_t difference = 0;
  for (size_t i = 0; i < WAesGCMTagSize; ++i) {
    difference |= lhs[i] ^ rhs[i];
  }
  return difference == 0;
}

inline void randomNonce(uint8_t nonce[WAesGCMNonceSize]) {
  static thread_local std::mt19937 generator = [] {
    std::random_device source;
    std::array<uint32_t, 8> seed{};
    for (size_t i = 0; i < seed.size(); ++i) {
      seed[i] = source();
    }
    std::seed_seq sequence(seed.begin(), seed.end());
    return std::mt19937(sequence);
  }();
  for (size_t offset = 0; offset < WAesGCMNonceSize; offset += 4) {
    const uint32_t word = generator();
    nonce[offset] = static_cast<uint8_t>(word >> 24);
    nonce[offset + 1] = static_cast<uint8_t>(word >> 16);
    nonce[offset + 2] = static_cast<uint8_t>(word >> 8);
    nonce[offset + 3] = static_cast<uint8_t>(word);
  }
}

} // namespace waes_gcm_detail

template <int> struct aesN;
template <> struct aesN<128> {
  enum { Nk = 4, Nr = 10 };

  static void keyExpansion(const uint8_t *key, __m128i *w) {
    auto assist = [](__m128i a, const __m128i &b) {
      a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
      a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
      a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
      a = _mm_xor_si128(a, _mm_shuffle_epi32(b, 0xff));
      return a;
    };

    w[0] = _mm_loadu_si128(reinterpret_cast<const __m128i *>(key));
    w[1] = assist(w[0], _mm_aeskeygenassist_si128(w[0], 0x01));
    w[2] = assist(w[1], _mm_aeskeygenassist_si128(w[1], 0x02));
    w[3] = assist(w[2], _mm_aeskeygenassist_si128(w[2], 0x04));
    w[4] = assist(w[3], _mm_aeskeygenassist_si128(w[3], 0x08));
    w[5] = assist(w[4], _mm_aeskeygenassist_si128(w[4], 0x10));
    w[6] = assist(w[5], _mm_aeskeygenassist_si128(w[5], 0x20));
    w[7] = assist(w[6], _mm_aeskeygenassist_si128(w[6], 0x40));
    w[8] = assist(w[7], _mm_aeskeygenassist_si128(w[7], 0x80));
    w[9] = assist(w[8], _mm_aeskeygenassist_si128(w[8], 0x1b));
    w[10] = assist(w[9], _mm_aeskeygenassist_si128(w[9], 0x36));
  }
};

template <> struct aesN<192> {
  enum { Nk = 6, Nr = 12 };

  static void keyExpansion(const uint8_t *key, __m128i *w) {
    auto assist = [](__m128i &a, __m128i &b, const __m128i &c) {
      a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
      a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
      a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
      a = _mm_xor_si128(a, _mm_shuffle_epi32(c, 0x55));
      b = _mm_xor_si128(b, _mm_slli_si128(b, 0x4));
      b = _mm_xor_si128(b, _mm_shuffle_epi32(a, 0xff));
    };

    __m128i a, b;

    w[0] = a = _mm_loadu_si128(reinterpret_cast<const __m128i *>(key));
    w[1] = b = _mm_loadu_si128(reinterpret_cast<const __m128i *>(key + 16));

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x1));
    w[1] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(w[1]), _mm_castsi128_pd(a), 0));
    w[2] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x2));
    w[3] = a;
    w[4] = b;

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x4));
    w[4] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(w[4]), _mm_castsi128_pd(a), 0));
    w[5] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x8));
    w[6] = a;
    w[7] = b;

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x10));
    w[7] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(w[7]), _mm_castsi128_pd(a), 0));
    w[8] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x20));
    w[9] = a;
    w[10] = b;

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x40));
    w[10] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(w[10]), _mm_castsi128_pd(a), 0));
    w[11] = _mm_castpd_si128(
        _mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

    assist(a, b, _mm_aeskeygenassist_si128(b, 0x80));
    w[12] = a;
  }
};

template <> struct aesN<256> {
  enum { Nk = 8, Nr = 14 };

  static void keyExpansion(const uint8_t *key, __m128i *w) {
    auto assistL = [](__m128i a, const __m128i &b) {
      a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
      a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
      a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
      a = _mm_xor_si128(a, _mm_shuffle_epi32(b, 0xff));
      return a;
    };
    auto assistH = [](const __m128i &a, __m128i c) {
      c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
      c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
      c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
      c = _mm_xor_si128(
          c, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(a, 0x0), 0xaa));
      return c;
    };

    w[0] = _mm_loadu_si128(reinterpret_cast<const __m128i *>(key));
    w[1] = _mm_loadu_si128(reinterpret_cast<const __m128i *>(key + 16));
    w[2] = assistL(w[0], _mm_aeskeygenassist_si128(w[1], 0x1));
    w[3] = assistH(w[2], w[1]);
    w[4] = assistL(w[2], _mm_aeskeygenassist_si128(w[3], 0x2));
    w[5] = assistH(w[4], w[3]);
    w[6] = assistL(w[4], _mm_aeskeygenassist_si128(w[5], 0x4));
    w[7] = assistH(w[6], w[5]);
    w[8] = assistL(w[6], _mm_aeskeygenassist_si128(w[7], 0x8));
    w[9] = assistH(w[8], w[7]);
    w[10] = assistL(w[8], _mm_aeskeygenassist_si128(w[9], 0x10));
    w[11] = assistH(w[10], w[9]);
    w[12] = assistL(w[10], _mm_aeskeygenassist_si128(w[11], 0x20));
    w[13] = assistH(w[12], w[11]);
    w[14] = assistL(w[12], _mm_aeskeygenassist_si128(w[13], 0x40));
  }
};

template <int N> class CWAes {
public:
  CWAes(const void *key, size_t keyLength, const void *iv = nullptr,
        size_t ivLength = 16, Padding padding = Padding::PKCS7)
      : m_padding(padding), m_mode(Mode::ECB) {
    // Preserve legacy zero-padding/truncation while giving the AES-192
    // expansion two complete, readable SIMD blocks.
    alignas(16) uint8_t normalizedKey[32] = {};
    const size_t normalizedLength = keyLength > 4 * Nk ? 4 * Nk : keyLength;
    if (normalizedLength) {
      memcpy(normalizedKey, key, normalizedLength);
    }
    aesN<N>::keyExpansion(normalizedKey, m_w128);

    // Convert 128-bit round keys to 512-bit format
    for (int i = 0; i <= Nr; ++i) {
      m_w512[i] = _mm512_broadcast_i32x4(m_w128[i]);
    }

    // Generate inverse round keys
    for (uint8_t i = Nr + 1; i < Nr * 2; ++i) {
      m_w128[i] = _mm_aesimc_si128(m_w128[Nr * 2 - i]);
      m_w512[i] = _mm512_broadcast_i32x4(m_w128[i]);
    }

    __m128i h = _mm_setzero_si128();
    cipher128(h);
    _mm_storeu_si128(reinterpret_cast<__m128i *>(m_gcmH), h);

    if (iv) {
      m_mode = Mode::CBC;
      memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  size_t SumCipherLength(size_t nInLen) const {
    constexpr size_t blockSize = Nb * 4;
    if (m_mode == Mode::CTR || m_mode == Mode::GCM) {
      // CTR and GCM do not pad the payload.
      return nInLen;
    } else if (m_padding == Padding::Zeros) {
      return ((nInLen + blockSize - 1) / blockSize) * blockSize;
    } else { // PKCS7
      return ((nInLen / blockSize) + 1) * blockSize;
    }
  }

  void SetIV(const void *iv, size_t length) {
    m_mode = Mode::CBC;
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, iv, length > 16 ? 16 : length);
  }

  void SetCounter(const void *counter, size_t length) {
    m_mode = Mode::CTR;
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, counter, length > 16 ? 16 : length);
  }

  bool SetAAD(const void *aad = nullptr, size_t aadLength = 0) {
    if ((aadLength != 0 && aad == nullptr) ||
        !waes_gcm_detail::validLengths(0, aadLength)) {
      return false;
    }
    std::vector<uint8_t> next;
    if (aadLength != 0) {
      const auto *bytes = reinterpret_cast<const uint8_t *>(aad);
      next.assign(bytes, bytes + aadLength);
    }
    m_aad.swap(next);
    m_mode = Mode::GCM;
    return true;
  }

  bool CipherGCM(const void *in, size_t inLength, void *out, size_t &outLength,
                 const void *nonce, size_t nonceLength, void *tag,
                 size_t &tagLength) const {
    const size_t outputCapacity = outLength;
    const size_t tagCapacity = tagLength;
    outLength = 0;
    tagLength = 0;
    if (m_mode != Mode::GCM || nonceLength != WAesGCMNonceSize ||
        nonce == nullptr || tag == nullptr || outputCapacity < inLength ||
        tagCapacity < WAesGCMTagSize ||
        (inLength != 0 && (in == nullptr || out == nullptr)) ||
        !waes_gcm_detail::validLengths(inLength, m_aad.size())) {
      return false;
    }
    const auto encryptBlock = [this](const uint8_t *block, uint8_t *result) {
      __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i *>(block));
      cipher128(state);
      _mm_storeu_si128(reinterpret_cast<__m128i *>(result), state);
    };
    const auto *nonceBytes = reinterpret_cast<const uint8_t *>(nonce);
    auto *output = reinterpret_cast<uint8_t *>(out);
    if (inLength != 0) {
      cryptGCMData(reinterpret_cast<const uint8_t *>(in), inLength, output,
                   nonceBytes);
    }
    uint8_t calculatedTag[WAesGCMTagSize];
    waes_gcm_detail::calculateTag(output, inLength, m_aad.data(), m_aad.size(),
                                  nonceBytes, m_gcmH, calculatedTag,
                                  encryptBlock);
    memcpy(tag, calculatedTag, sizeof(calculatedTag));
    outLength = inLength;
    tagLength = WAesGCMTagSize;
    return true;
  }

  bool CipherGCM(const void *in, size_t inLength, void *out, size_t &outLength,
                 GCMResult &result) const {
    GCMResult next;
    waes_gcm_detail::randomNonce(next.nonce.data());
    size_t tagLength = next.tag.size();
    if (!CipherGCM(in, inLength, out, outLength, next.nonce.data(),
                   next.nonce.size(), next.tag.data(), tagLength)) {
      return false;
    }
    result = next;
    return true;
  }

  bool InvCipherGCM(const void *in, size_t inLength, void *out,
                    size_t &outLength, const void *nonce, size_t nonceLength,
                    const void *tag, size_t tagLength) const {
    const size_t outputCapacity = outLength;
    outLength = 0;
    if (m_mode != Mode::GCM || nonceLength != WAesGCMNonceSize ||
        tagLength != WAesGCMTagSize || nonce == nullptr || tag == nullptr ||
        outputCapacity < inLength ||
        (inLength != 0 && (in == nullptr || out == nullptr)) ||
        !waes_gcm_detail::validLengths(inLength, m_aad.size())) {
      return false;
    }
    const auto encryptBlock = [this](const uint8_t *block, uint8_t *result) {
      __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i *>(block));
      cipher128(state);
      _mm_storeu_si128(reinterpret_cast<__m128i *>(result), state);
    };
    const auto *input = reinterpret_cast<const uint8_t *>(in);
    const auto *nonceBytes = reinterpret_cast<const uint8_t *>(nonce);
    uint8_t calculatedTag[WAesGCMTagSize];
    waes_gcm_detail::calculateTag(input, inLength, m_aad.data(), m_aad.size(),
                                  nonceBytes, m_gcmH, calculatedTag,
                                  encryptBlock);
    if (!waes_gcm_detail::tagsEqual(calculatedTag,
                                    reinterpret_cast<const uint8_t *>(tag))) {
      return false;
    }
    if (inLength != 0) {
      cryptGCMData(input, inLength, reinterpret_cast<uint8_t *>(out),
                   nonceBytes);
    }
    outLength = inLength;
    return true;
  }

  bool InvCipherGCM(const void *in, size_t inLength, void *out,
                    size_t &outLength, const GCMResult &result) const {
    return InvCipherGCM(in, inLength, out, outLength, result.nonce.data(),
                        result.nonce.size(), result.tag.data(),
                        result.tag.size());
  }

  bool Cipher(const void *in, size_t inLength, void *out,
              size_t &outLength) const {
    switch (m_mode) {
    case Mode::ECB:
      return cipherECB(in, inLength, out, outLength);
    case Mode::CBC:
      return cipherCBC(in, inLength, out, outLength);
    case Mode::CTR:
      return cipherCTR(in, inLength, out, outLength);
    case Mode::GCM:
      outLength = 0;
      return false;
    }
    return false;
  }

  bool InvCipher(const void *in, size_t inLength, void *out,
                 size_t &outLength) const {
    switch (m_mode) {
    case Mode::ECB:
      return invCipherECB(in, inLength, out, outLength);
    case Mode::CBC:
      return invCipherCBC(in, inLength, out, outLength);
    case Mode::CTR:
      return cipherCTR(in, inLength, out,
                       outLength); // CTR mode uses same operation for both
    case Mode::GCM:
      outLength = 0;
      return false;
    }
    return false;
  }

private:
  enum {
    Nb = 4,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };

  enum class Mode {
    ECB,
    CBC,
    CTR,
    GCM,
  };

  __m512i m_w512[Nr * 2]; // For 512-bit operations
  __m128i m_w128[Nr * 2]; // For 128-bit operations
  __m128i m_iv = {};
  alignas(16) uint8_t m_gcmH[16];
  std::vector<uint8_t> m_aad;
  Padding m_padding;
  Mode m_mode;

  void cipher512(__m512i &state) const {
    state = _mm512_xor_si512(state, m_w512[0]);

    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm512_aesenc_epi128(state, m_w512[r]);
    }

    state = _mm512_aesenclast_epi128(state, m_w512[Nr]);
  }

  void invCipher512(__m512i &state) const {
    state = _mm512_xor_si512(state, m_w512[Nr]);

    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm512_aesdec_epi128(state, m_w512[r]);
    }

    state = _mm512_aesdeclast_epi128(state, m_w512[0]);
  }

  void cipher128(__m128i &state) const {
    state = _mm_xor_si128(state, m_w128[0]);

    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm_aesenc_si128(state, m_w128[r]);
    }

    state = _mm_aesenclast_si128(state, m_w128[Nr]);
  }

  void invCipher128(__m128i &state) const {
    state = _mm_xor_si128(state, m_w128[Nr]);

    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm_aesdec_si128(state, m_w128[r]);
    }

    state = _mm_aesdeclast_si128(state, m_w128[0]);
  }

  void cryptGCMData(const uint8_t *input, size_t length, uint8_t *output,
                    const uint8_t nonce[WAesGCMNonceSize]) const {
    alignas(64) uint8_t counters[64] = {};
    memcpy(counters, nonce, WAesGCMNonceSize);
    counters[15] = 1;
    while (length >= 64) {
      for (size_t lane = 0; lane < 4; ++lane) {
        if (lane != 0) {
          memcpy(counters + lane * 16, counters + (lane - 1) * 16, 16);
        }
        waes_gcm_detail::incrementCounter(counters + lane * 16);
      }
      __m512i stream = _mm512_load_si512(counters);
      cipher512(stream);
      const __m512i plaintext = _mm512_loadu_si512(input);
      _mm512_storeu_si512(output, _mm512_xor_si512(plaintext, stream));
      memcpy(counters, counters + 48, 16);
      input += 64;
      output += 64;
      length -= 64;
    }
    while (length != 0) {
      waes_gcm_detail::incrementCounter(counters);
      __m128i stream =
          _mm_load_si128(reinterpret_cast<const __m128i *>(counters));
      cipher128(stream);
      alignas(16) uint8_t bytes[16];
      _mm_store_si128(reinterpret_cast<__m128i *>(bytes), stream);
      const size_t chunk = length < 16 ? length : 16;
      for (size_t i = 0; i < chunk; ++i) {
        output[i] = input[i] ^ bytes[i];
      }
      input += chunk;
      output += chunk;
      length -= chunk;
    }
  }

  bool isValidPKCS7Padding(const __m128i &state) const {
    auto *pos = reinterpret_cast<const uint8_t *>(&state);
    if (pos[15] > 16 || pos[15] == 0) {
      return false;
    }

    for (int8_t i = 16 - pos[15]; i < 15; ++i) {
      if (pos[15] != pos[i]) {
        return false;
      }
    }

    return true;
  }

  bool cipherECB(const void *in, size_t inLength, void *out,
                 size_t &outLength) const {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }

    auto len = inLength;
    auto input512 = reinterpret_cast<const __m512i *>(in);
    auto output512 = reinterpret_cast<__m512i *>(out);

    for (; len >= 64; len -= 64, ++input512, ++output512) {
      auto state = _mm512_loadu_si512(input512);
      cipher512(state);
      _mm512_storeu_si512(output512, state);
    }

    auto input128 = reinterpret_cast<const __m128i *>(input512);
    auto output128 = reinterpret_cast<__m128i *>(output512);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      auto state = _mm_loadu_si128(input128);
      cipher128(state);
      _mm_storeu_si128(output128, state);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      alignas(16) uint8_t block[16] = {};
      if (len) {
        memcpy(block, input128, len);
      }
      auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<int>(len);
      memset(block + len, pad, 16 - len);
      auto state = _mm_load_si128(reinterpret_cast<const __m128i *>(block));

      cipher128(state);
      _mm_storeu_si128(output128, state);
    }

    outLength = nNeedLen;
    return true;
  }

  bool cipherCBC(const void *in, size_t inLength, void *out,
                 size_t &outLength) const {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }

    auto len = inLength;
    auto input = reinterpret_cast<const __m128i *>(in);
    auto output = reinterpret_cast<__m128i *>(out);

    auto state = m_iv;
    for (; len >= 16; len -= 16, ++input, ++output) {
      state = _mm_xor_si128(_mm_loadu_si128(input), state);
      cipher128(state);
      _mm_storeu_si128(output, state);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      for (uint8_t i = 0; i < len; ++i) {
        reinterpret_cast<uint8_t *>(&state)[i] ^=
            reinterpret_cast<const uint8_t *>(input)[i];
      }
      if (Padding::PKCS7 == m_padding) {
        for (auto i = len; i < 16; ++i) {
          reinterpret_cast<uint8_t *>(&state)[i] ^= 16 - len;
        }
      }

      cipher128(state);
      _mm_storeu_si128(output, state);
    }

    outLength = nNeedLen;
    return true;
  }

  bool cipherCTR(const void *in, size_t inLength, void *out,
                 size_t &outLength) const {
    if (outLength < inLength) {
      return false;
    }

    static const auto bswap_epi64 = _mm512_broadcast_i32x4(
        _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8));
    static const auto increment = _mm512_set_epi64(4, 0, 4, 0, 4, 0, 4, 0);
    auto counters = _mm512_add_epi64(
        _mm512_shuffle_epi8(_mm512_broadcast_i32x4(m_iv), bswap_epi64),
        _mm512_set_epi64(3, 0, 2, 0, 1, 0, 0, 0));

    auto len = inLength;
    auto input = reinterpret_cast<const __m512i *>(in);
    auto output = reinterpret_cast<__m512i *>(out);
    for (; len >= 64; len -= 64, ++input, ++output) {
      auto state = _mm512_shuffle_epi8(counters, bswap_epi64);
      cipher512(state);
      _mm512_storeu_si512(output,
                          _mm512_xor_si512(state, _mm512_loadu_si512(input)));

      counters = _mm512_add_epi64(counters, increment);
    }

    if (len) {
      auto state = _mm512_shuffle_epi8(counters, bswap_epi64);
      cipher512(state);
      for (uint8_t i = 0; i < len; ++i) {
        reinterpret_cast<uint8_t *>(output)[i] =
            reinterpret_cast<const uint8_t *>(input)[i] ^
            reinterpret_cast<uint8_t *>(&state)[i];
      }
    }

    outLength = inLength;
    return true;
  }

  bool invCipherECB(const void *in, size_t inLength, void *out,
                    size_t &outLength) const {
    if (!inLength || inLength % 16) // invalid data length
    {
      return false;
    }

    auto block = static_cast<int64_t>(inLength / 16) - 1;

    // sum padding length
    auto state128 =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(in) + block);
    invCipher128(state128);

    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t *>(&state128)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(state128)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t *>(&state128)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    memcpy(reinterpret_cast<__m128i *>(out) + block, &state128, endLen);

    auto len = inLength - 16;
    auto input = reinterpret_cast<const __m512i *>(in);
    auto output = reinterpret_cast<__m512i *>(out);
    for (; len >= 64; len -= 64, ++input, ++output) {
      auto state512 = _mm512_loadu_si512(input);
      invCipher512(state512);
      _mm512_storeu_si512(output, state512);
    }

    auto input128 = reinterpret_cast<const __m128i *>(input);
    auto output128 = reinterpret_cast<__m128i *>(output);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      auto state128 = _mm_loadu_si128(input128);
      invCipher128(state128);
      _mm_storeu_si128(output128, state128);
    }

    return true;
  }

  bool invCipherCBC(const void *in, size_t inLength, void *out,
                    size_t &outLength) const {
    if (!inLength || inLength % 16) // invalid data length
    {
      return false;
    }

    auto block = static_cast<int64_t>(inLength / 16) - 1;
    auto input128 = reinterpret_cast<const __m128i *>(in);

    // sum padding length
    auto state128 =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(input128 + block));
    invCipher128(state128);

    __m128i iv;
    if (block) {
      iv = _mm_loadu_si128(
          reinterpret_cast<const __m128i *>(input128 + block - 1));
    } else {
      iv = m_iv;
    }
    state128 = _mm_xor_si128(state128, iv);

    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t *>(&state128)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(state128)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t *>(&state128)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    memcpy(reinterpret_cast<__m128i *>(out) + block, &state128, endLen);

    auto input512 = reinterpret_cast<const __m512i *>(in);
    auto output512 = reinterpret_cast<__m512i *>(out);
    auto piv512 = reinterpret_cast<const __m512i *>(input128 + 3);

    auto len = inLength - 16;
    if (len < 64) {
      auto output128 = reinterpret_cast<__m128i *>(out);
      __m128i previous = m_iv;
      for (; len >= 16; len -= 16, ++input128, ++output128) {
        const auto ciphertext = _mm_loadu_si128(input128);
        auto state = ciphertext;
        invCipher128(state);
        _mm_storeu_si128(output128, _mm_xor_si128(state, previous));
        previous = ciphertext;
      }
      return true;
    }

    auto ivs = _mm512_castsi128_si512(m_iv);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128), 1);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128 + 1), 2);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128 + 2), 3);
    __m128i previous = m_iv;
    for (; len >= 64; len -= 64, ++input512, ++output512, ++piv512) {
      auto state512 = _mm512_loadu_si512(input512);
      previous = _mm512_extracti32x4_epi32(state512, 3);
      __m512i nextIvs = {};
      if (len >= 128) {
        // Load before storing so in-place decryption keeps the ciphertext IVs.
        nextIvs = _mm512_loadu_si512(piv512);
      }
      invCipher512(state512);
      _mm512_storeu_si512(output512, _mm512_xor_si512(state512, ivs));
      if (len >= 128) {
        ivs = nextIvs;
      }
    }

    input128 = reinterpret_cast<const __m128i *>(input512);
    auto output128 = reinterpret_cast<__m128i *>(output512);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      const auto ciphertext = _mm_loadu_si128(input128);
      auto state128 = ciphertext;
      invCipher128(state128);
      _mm_storeu_si128(output128, _mm_xor_si128(state128, previous));
      previous = ciphertext;
    }

    return true;
  }
};

using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;
