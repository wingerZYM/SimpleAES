#pragma once

#if (defined(__aarch64__) || defined(_M_ARM64)) &&                             \
    (defined(__ARM_FEATURE_CRYPTO) || defined(WAES_ASSUME_ARM_CRYPTO))
#define WAES_ARMV8
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||           \
    defined(_M_IX86)
#if (defined(_MSC_VER) && !defined(__clang__)) ||                              \
    (defined(__SSSE3__) && defined(__AES__))
#define WAES_X86_SIMD
#if (defined(_MSC_VER) && !defined(__clang__)) ||                              \
    (defined(__AVX2__) && defined(__AES__) && defined(__VAES__))
#define WAES_VAES
#endif
#if (defined(_MSC_VER) && !defined(__clang__)) ||                              \
    (defined(__AVX512F__) && defined(__AVX512BW__) && defined(__AVX512DQ__) && \
     defined(__AVX512VL__) && defined(__AES__) && defined(__VAES__))
#define WAES_VAES512
#endif
#endif
#endif

#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

#if defined(WAES_ARMV8)
#include <arm_neon.h>
#elif defined(WAES_X86_SIMD)
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#if defined(WAES_VAES) || defined(WAES_VAES512)
#include <immintrin.h>
#endif
#include <tmmintrin.h>
#include <wmmintrin.h>
#endif

// AES // ECB/CBC/CTR // PKCS7Padding/ZerosPadding

enum class Padding {
  Zeros,
  PKCS7,
};

namespace WAes {

namespace detail {
class Aes;
}

using Ptr = std::unique_ptr<detail::Aes>;

enum class Backend : uint8_t {
  Auto = 0,
  Generic,
#if defined(WAES_ARMV8)
  ArmV8,
#elif defined(WAES_X86_SIMD)
  AesNi,
#if defined(WAES_VAES)
  VAES,
#endif
#if defined(WAES_VAES512)
  VAES512,
#endif
#endif
};

template <int>
Ptr Create(const void *key, size_t keyLength, const void *iv = nullptr,
           size_t ivLength = 16, Padding padding = Padding::PKCS7);

template <int>
Ptr Create(Backend backend, const void *key, size_t keyLength,
           const void *iv = nullptr, size_t ivLength = 16,
           Padding padding = Padding::PKCS7);

namespace detail {

template <int> struct aesN;

template <> struct aesN<128> {
  enum { Nk = 4, Nr = 10 };
};
template <> struct aesN<192> {
  enum { Nk = 6, Nr = 12 };
};
template <> struct aesN<256> {
  enum { Nk = 8, Nr = 14 };
};

class Aes {
protected:
  enum {
    Nb = 4,
  };

  enum class Mode {
    ECB,
    CBC,
    CTR,
  };
  Padding m_padding;
  Mode m_mode;

  Aes(Padding padding) : m_padding(padding), m_mode(Mode::ECB) {}
  Aes(const Aes &) = default;
  Aes &operator=(const Aes &) = default;

  bool isValidPKCS7Padding(const void *state) const {
    auto pos = reinterpret_cast<const uint8_t *>(state);
    const auto pad = pos[15];
    if (pad > 16 || pad == 0) {
      return false;
    }

    for (int8_t i = 16 - pad; i < 15; ++i) {
      if (pad != pos[i]) {
        return false;
      }
    }

    return true;
  }

  virtual bool cipherECB(const void *in, size_t inLength, void *out,
                         size_t &outLength) const = 0;
  virtual bool cipherCBC(const void *in, size_t inLength, void *out,
                         size_t &outLength) const = 0;
  virtual bool cipherCTR(const void *in, size_t inLength, void *out,
                         size_t &outLength) const = 0;

  virtual bool invCipherECB(const void *in, size_t inLength, void *out,
                            size_t &outLength) const = 0;
  virtual bool invCipherCBC(const void *in, size_t inLength, void *out,
                            size_t &outLength) const = 0;

private:
  virtual void setIVImpl(const void *iv, size_t length) = 0;
  virtual void getIVImpl(void *iv) const = 0;

  class tempIVScope {
  private:
    Aes *m_pAes;
    uint8_t m_iv[16];
    Mode m_mode;

  public:
    tempIVScope(Aes *aes, const void *iv, size_t length, bool is_ctr)
        : m_pAes(aes) {
      m_pAes->getIVImpl(m_iv);
      m_mode = m_pAes->m_mode;

      if (is_ctr) {
        m_pAes->SetCounter(iv, length);
      } else {
        m_pAes->SetIV(iv, length);
      }
    }

    ~tempIVScope() {
      m_pAes->m_mode = m_mode;
      m_pAes->setIVImpl(m_iv, 16);
    }

    tempIVScope(const tempIVScope &) = delete;
    tempIVScope &operator=(const tempIVScope &) = delete;
    tempIVScope(tempIVScope &&) = delete;
    tempIVScope &operator=(tempIVScope &&) = delete;
  };

public:
  virtual ~Aes() = default;

  auto ScopeIV(const void *iv, size_t length) {
    return tempIVScope(this, iv, length, false);
  }

  auto ScopeIV(std::span<const uint8_t, 16> iv) {
    return tempIVScope(this, iv.data(), iv.size(), false);
  }

  auto ScopeCounter(const void *counter, size_t length) {
    return tempIVScope(this, counter, length, true);
  }

  auto ScopeCounter(std::span<const uint8_t, 16> counter) {
    return tempIVScope(this, counter.data(), counter.size(), true);
  }

  template <typename Func>
  auto WithScopeIV(const void *iv, size_t length, Func &&func)
      -> decltype(func()) {
    tempIVScope scope(this, iv, length, false);
    return func();
  }

  template <typename Func>
  auto WithScopeIV(std::span<const uint8_t, 16> iv, Func &&func)
      -> decltype(func()) {
    return WithScopeIV(iv.data(), iv.size(), std::forward<Func>(func));
  }

  template <typename Func>
  auto WithScopeCounter(const void *counter, size_t length, Func &&func)
      -> decltype(func()) {
    tempIVScope scope(this, counter, length, true);
    return func();
  }

  template <typename Func>
  auto WithScopeCounter(std::span<const uint8_t, 16> counter, Func &&func)
      -> decltype(func()) {
    return WithScopeCounter(counter.data(), counter.size(),
                            std::forward<Func>(func));
  }

  size_t SumCipherLength(size_t nInLen) const {
    constexpr size_t blockSize = Nb * 4;
    if (m_mode == Mode::CTR) {
      // In CTR mode, the length is not padded.
      return nInLen;
    } else if (m_padding == Padding::Zeros) {
      return ((nInLen + blockSize - 1) / blockSize) * blockSize;
    } else { // PKCS7
      return ((nInLen / blockSize) + 1) * blockSize;
    }
  }

  // Sets the initialization vector value when in CBC mode.
  // The maximum length is 16 byte, if not enough padding zero.
  void SetIV(const void *iv, size_t length) {
    m_mode = Mode::CBC;
    setIVImpl(iv, length);
  }

  void SetIV(std::span<const uint8_t, 16> iv) { SetIV(iv.data(), iv.size()); }

  // Sets the counter block when in CTR mode. The first 8 bytes are fixed and
  // the final 8 bytes are incremented as a big-endian integer modulo 2^64.
  // The maximum length is 16 bytes; shorter values are padded with zeroes.
  void SetCounter(const void *counter, size_t length) {
    m_mode = Mode::CTR;
    setIVImpl(counter, length);
  }

  void SetCounter(std::span<const uint8_t, 16> counter) {
    SetCounter(counter.data(), counter.size());
  }

  // Sets an 8-byte IV, 4-byte nonce, and 4-byte initial counter. Numeric
  // fields are serialized in network (big-endian) byte order.
  void SetCounter(uint64_t iv, uint32_t nonce, uint32_t counter = 0) {
    uint8_t counterData[16] = {};
    for (size_t i = 0; i < 8; ++i) {
      counterData[7 - i] = static_cast<uint8_t>(iv >> (i * 8));
    }
    for (size_t i = 0; i < 4; ++i) {
      counterData[11 - i] = static_cast<uint8_t>(nonce >> (i * 8));
      counterData[15 - i] = static_cast<uint8_t>(counter >> (i * 8));
    }
    SetCounter(counterData, sizeof(counterData));
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
    }

    return false;
  }

  template <typename I> std::vector<uint8_t> Cipher(const I &in) const {
    auto nNeedLen = SumCipherLength(in.size());
    std::vector<uint8_t> out(nNeedLen);
    Cipher(in.data(), in.size(), out.data(), nNeedLen);
    return out;
  }

  bool InvCipher(const void *in, size_t inLength, void *out,
                 size_t &outLength) const {
    switch (m_mode) {
    case Mode::ECB:
      return invCipherECB(in, inLength, out, outLength);
    case Mode::CBC:
      return invCipherCBC(in, inLength, out, outLength);
    case Mode::CTR:
      return cipherCTR(in, inLength, out, outLength);
    }

    return false;
  }

  template <typename I, typename O> bool InvCipher(const I &in, O &out) const {
    size_t outLength = in.size();
    out.resize(outLength);
    if (!InvCipher(in.data(), in.size(), out.data(), outLength)) {
      out.clear();
      return false;
    }
    out.resize(outLength);
    return true;
  }

  void SetPadding(Padding padding) { m_padding = padding; }

  virtual Ptr Clone() const = 0;
};

#if defined(WAES_ARMV8)

#define _vslliq_u8(a, imm) vextq_u8(vdupq_n_u8(0), a, (16 - imm))

// {low 64 bits of a, low 64 bits of b}
inline uint8x16_t _vzip_lo64_u8(uint8x16_t a, uint8x16_t b) {
  return vreinterpretq_u8_u64(
      vtrn1q_u64(vreinterpretq_u64_u8(a), vreinterpretq_u64_u8(b)));
}

// {high 64 bits of a, low 64 bits of b}
inline uint8x16_t _vzip_hi_lo64_u8(uint8x16_t a, uint8x16_t b) {
  return vextq_u8(a, b, 8);
}

// AES-128 / AES-256 assistL: broadcast RotWord(SubWord(word3)) + rcon
// After ShiftRows: S(o13)@9, S(o14)@6, S(o15)@3, S(o12)@12
inline uint8x16_t _vkeyassist_rot3(uint8x16_t a, const uint8_t rcon) {
  a = vaeseq_u8(a, vdupq_n_u8(0));
  static const uint8_t idx[] = {9, 6, 3, 12, 9, 6, 3, 12,
                                9, 6, 3, 12, 9, 6, 3, 12};
  a = vqtbl1q_u8(a, vld1q_u8(idx));
  uint8x16_t rv = vdupq_n_u8(0);
  rv = vsetq_lane_u8(rcon, rv, 0);
  rv = vsetq_lane_u8(rcon, rv, 4);
  rv = vsetq_lane_u8(rcon, rv, 8);
  rv = vsetq_lane_u8(rcon, rv, 12);
  return veorq_u8(a, rv);
}

// AES-192: broadcast RotWord(SubWord(word1)) + rcon
// After ShiftRows: S(o5)@1, S(o6)@14, S(o7)@11, S(o4)@4
inline uint8x16_t _vkeyassist_rot1(uint8x16_t a, const uint8_t rcon) {
  a = vaeseq_u8(a, vdupq_n_u8(0));
  static const uint8_t idx[] = {1, 14, 11, 4, 1, 14, 11, 4,
                                1, 14, 11, 4, 1, 14, 11, 4};
  a = vqtbl1q_u8(a, vld1q_u8(idx));
  uint8x16_t rv = vdupq_n_u8(0);
  rv = vsetq_lane_u8(rcon, rv, 0);
  rv = vsetq_lane_u8(rcon, rv, 4);
  rv = vsetq_lane_u8(rcon, rv, 8);
  rv = vsetq_lane_u8(rcon, rv, 12);
  return veorq_u8(a, rv);
}

// AES-256 assistH: broadcast SubWord(word3), no RotWord, rcon always 0
// After ShiftRows: S(o12)@12, S(o13)@9, S(o14)@6, S(o15)@3
inline uint8x16_t _vkeyassist_sub3(uint8x16_t a) {
  a = vaeseq_u8(a, vdupq_n_u8(0));
  static const uint8_t idx[] = {12, 9, 6, 3, 12, 9, 6, 3,
                                12, 9, 6, 3, 12, 9, 6, 3};
  return vqtbl1q_u8(a, vld1q_u8(idx));
}

template <int> inline void keyExpansion(const uint8_t *key, uint8x16_t *w);

template <> inline void keyExpansion<128>(const uint8_t *key, uint8x16_t *w) {
  auto assist = [](uint8x16_t a, const uint8x16_t &b) {
    a = veorq_u8(a, _vslliq_u8(a, 4));
    a = veorq_u8(a, _vslliq_u8(a, 4));
    a = veorq_u8(a, _vslliq_u8(a, 4));
    a = veorq_u8(a, b);
    return a;
  };

  w[0] = vld1q_u8(key);
  w[1] = assist(w[0], _vkeyassist_rot3(w[0], 0x01));
  w[2] = assist(w[1], _vkeyassist_rot3(w[1], 0x02));
  w[3] = assist(w[2], _vkeyassist_rot3(w[2], 0x04));
  w[4] = assist(w[3], _vkeyassist_rot3(w[3], 0x08));
  w[5] = assist(w[4], _vkeyassist_rot3(w[4], 0x10));
  w[6] = assist(w[5], _vkeyassist_rot3(w[5], 0x20));
  w[7] = assist(w[6], _vkeyassist_rot3(w[6], 0x40));
  w[8] = assist(w[7], _vkeyassist_rot3(w[7], 0x80));
  w[9] = assist(w[8], _vkeyassist_rot3(w[8], 0x1b));
  w[10] = assist(w[9], _vkeyassist_rot3(w[9], 0x36));
}

template <> inline void keyExpansion<192>(const uint8_t *key, uint8x16_t *w) {
  auto assist = [](uint8x16_t &a, uint8x16_t &b, const uint8x16_t &c) {
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, c);
    b = veorq_u8(b, _vslliq_u8(b, 0x4));
    b = veorq_u8(
        b, vreinterpretq_u8_u32(vdupq_laneq_u32(vreinterpretq_u32_u8(a), 3)));
  };

  uint8x16_t a, b;
  w[0] = a = vld1q_u8(key);
  w[1] = b = vld1q_u8(key + 16);

  assist(a, b, _vkeyassist_rot1(b, 0x1));
  w[1] = _vzip_lo64_u8(w[1], a);
  w[2] = _vzip_hi_lo64_u8(a, b);

  assist(a, b, _vkeyassist_rot1(b, 0x2));
  w[3] = a;
  w[4] = b;

  assist(a, b, _vkeyassist_rot1(b, 0x4));
  w[4] = _vzip_lo64_u8(w[4], a);
  w[5] = _vzip_hi_lo64_u8(a, b);

  assist(a, b, _vkeyassist_rot1(b, 0x8));
  w[6] = a;
  w[7] = b;

  assist(a, b, _vkeyassist_rot1(b, 0x10));
  w[7] = _vzip_lo64_u8(w[7], a);
  w[8] = _vzip_hi_lo64_u8(a, b);

  assist(a, b, _vkeyassist_rot1(b, 0x20));
  w[9] = a;
  w[10] = b;

  assist(a, b, _vkeyassist_rot1(b, 0x40));
  w[10] = _vzip_lo64_u8(w[10], a);
  w[11] = _vzip_hi_lo64_u8(a, b);

  assist(a, b, _vkeyassist_rot1(b, 0x80));
  w[12] = a;
}

template <> inline void keyExpansion<256>(const uint8_t *key, uint8x16_t *w) {
  auto assistL = [](uint8x16_t a, const uint8x16_t &b) {
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, b);
    return a;
  };
  auto assistH = [](const uint8x16_t &a, uint8x16_t c) {
    c = veorq_u8(c, _vslliq_u8(c, 0x4));
    c = veorq_u8(c, _vslliq_u8(c, 0x4));
    c = veorq_u8(c, _vslliq_u8(c, 0x4));
    c = veorq_u8(c, _vkeyassist_sub3(a));
    return c;
  };

  w[0] = vld1q_u8(key);
  w[1] = vld1q_u8(key + 16);
  w[2] = assistL(w[0], _vkeyassist_rot3(w[1], 0x1));
  w[3] = assistH(w[2], w[1]);
  w[4] = assistL(w[2], _vkeyassist_rot3(w[3], 0x2));
  w[5] = assistH(w[4], w[3]);
  w[6] = assistL(w[4], _vkeyassist_rot3(w[5], 0x4));
  w[7] = assistH(w[6], w[5]);
  w[8] = assistL(w[6], _vkeyassist_rot3(w[7], 0x8));
  w[9] = assistH(w[8], w[7]);
  w[10] = assistL(w[8], _vkeyassist_rot3(w[9], 0x10));
  w[11] = assistH(w[10], w[9]);
  w[12] = assistL(w[10], _vkeyassist_rot3(w[11], 0x20));
  w[13] = assistH(w[12], w[11]);
  w[14] = assistL(w[12], _vkeyassist_rot3(w[13], 0x40));
}

template <int N> class WAesArmV8 final : public Aes {
private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };

  uint8x16_t m_w[Nr * 2];
  uint8x16_t m_iv = {};

  WAesArmV8(const void *key, size_t keyLength, const void *iv, size_t ivLength,
            Padding padding)
      : Aes(padding) {
    // Always stage the key. Besides preserving legacy zero-padding/truncation,
    // the extra bytes make the two SIMD loads used by AES-192 memory-safe.
    alignas(16) uint8_t normalizedKey[32] = {};
    const size_t normalizedLength = keyLength > 4 * Nk ? 4 * Nk : keyLength;
    if (normalizedLength) {
      memcpy(normalizedKey, key, normalizedLength);
    }
    keyExpansion<N>(normalizedKey, m_w);

    // imc
    for (uint8_t i = Nr + 1; i < Nr * 2; ++i) {
      m_w[i] = vaesimcq_u8(m_w[Nr * 2 - i]);
    }

    if (iv) { // iv padding zero
      m_mode = Mode::CBC;
      memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  void cipher(uint8x16_t &state) const {
    for (uint8_t r = 0; r < Nr - 1; ++r) {
      state = vaesmcq_u8(vaeseq_u8(state, m_w[r]));
    }
    state = veorq_u8(vaeseq_u8(state, m_w[Nr - 1]), m_w[Nr]);
  }

  void invCipher(uint8x16_t &state) const {
    for (uint8_t r = Nr; r < Nr * 2 - 1; ++r) {
      state = vaesimcq_u8(vaesdq_u8(state, m_w[r]));
    }
    state = veorq_u8(vaesdq_u8(state, m_w[Nr * 2 - 1]), m_w[0]);
  }

  virtual bool cipherECB(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    uint8x16_t state;
    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t *>(in);
    auto output = reinterpret_cast<uint8_t *>(out);
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      cipher(state);
      vst1q_u8(output, state);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      alignas(16) uint8_t block[16] = {};
      if (len) {
        memcpy(block, input, len);
      }
      auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<int>(len);
      memset(block + len, pad, 16 - len);
      state = vld1q_u8(block);

      cipher(state);
      vst1q_u8(output, state);
    }

    return true;
  }

  virtual bool cipherCBC(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t *>(in);
    auto output = reinterpret_cast<uint8_t *>(out);

    auto state = m_iv;
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      state = veorq_u8(vld1q_u8(input), state);
      cipher(state);
      vst1q_u8(output, state);
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

      cipher(state);
      vst1q_u8(output, state);
    }

    return true;
  }

  virtual bool cipherCTR(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    static const uint64x2_t one = {0, 1};
    auto counter = vreinterpretq_u64_u8(vrev64q_u8(m_iv));

    int64_t len = inLength / 16;
    auto input = reinterpret_cast<const uint8_t *>(in);
    auto output = reinterpret_cast<uint8_t *>(out);
    for (int64_t i = 0; i < len; ++i, input += 16, output += 16) {
      auto state = vrev64q_u8(vreinterpretq_u8_u64(counter));
      cipher(state);
      vst1q_u8(output, veorq_u8(vld1q_u8(input), state));

      counter = vaddq_u64(counter, one);
    }

    int8_t endLen = inLength % 16;
    if (endLen) {
      auto state = vrev64q_u8(vreinterpretq_u8_u64(counter));
      cipher(state);
      for (int8_t i = 0; i < endLen; ++i) {
        reinterpret_cast<uint8_t *>(output)[i] =
            reinterpret_cast<const uint8_t *>(input)[i] ^
            reinterpret_cast<uint8_t *>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!inLength || inLength % 16) {
      // invalid data length
      return false;
    }

    auto len = static_cast<int64_t>(inLength - 16);
    auto input = reinterpret_cast<const uint8_t *>(in);

    // sum padding length
    auto state = vld1q_u8(input + len);
    invCipher(state);

    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t *>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t *>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    auto output = reinterpret_cast<uint8_t *>(out);
    memcpy(output + len, &state, endLen);

    for (int i = 0; i < len; i += 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      invCipher(state);
      vst1q_u8(output, state);
    }

    return true;
  }

  virtual bool invCipherCBC(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!inLength || inLength % 16) {
      // invalid data length
      return false;
    }

    auto len = static_cast<int64_t>(inLength - 16);
    auto input = reinterpret_cast<const uint8_t *>(in);

    // sum padding length
    auto state = vld1q_u8(input + len);
    invCipher(state);

    uint8x16_t iv;
    if (len) {
      iv = vld1q_u8(input + len - 16);
    } else {
      iv = m_iv;
    }
    state = veorq_u8(state, iv);

    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t *>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t *>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    auto output = reinterpret_cast<uint8_t *>(out);
    memcpy(output + len, &state, endLen);

    iv = m_iv;
    for (int i = 0; i < len; i += 16, input += 16, output += 16) {
      auto niv = state = vld1q_u8(input);
      invCipher(state);
      vst1q_u8(output, veorq_u8(state, iv));

      iv = niv;
    }

    return true;
  }

  virtual void setIVImpl(const void *iv, size_t length) override {
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, iv, length > 16 ? 16 : length);
  }

  virtual void getIVImpl(void *iv) const override { memcpy(iv, &m_iv, 16); }

  virtual Ptr Clone() const override { return Ptr(new WAesArmV8<N>(*this)); }

  friend Ptr WAes::Create<N>(const void *, size_t, const void *, size_t,
                             Padding);
  friend Ptr WAes::Create<N>(Backend, const void *, size_t, const void *,
                             size_t, Padding);
};

#endif // defined(WAES_ARMV8)

#if defined(WAES_X86_SIMD)

// x86 AES implementation types (for runtime CPU feature detection)
enum class X86ImplType {
  Generic = 0,
  AES_NI = 1,
  VAES = 2,
  VAES512 = 3,
};

struct X86Capabilities {
  bool aesNi = false;
  bool vaes = false;
  bool vaes512 = false;
};

inline void cpuid(int (&regs)[4], int leaf, int subleaf = 0) {
#if defined(_MSC_VER)
  __cpuidex(regs, leaf, subleaf);
#else
  __asm__ __volatile__("cpuid"
                       : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]),
                         "=d"(regs[3])
                       : "a"(leaf), "c"(subleaf));
#endif
}

inline uint64_t xgetbv(uint32_t index) {
#if defined(_MSC_VER)
  return _xgetbv(index);
#else
  uint32_t eax = 0;
  uint32_t edx = 0;
  __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(index));
  return (static_cast<uint64_t>(edx) << 32) | eax;
#endif
}

inline const X86Capabilities &getX86Capabilities() {
  static const X86Capabilities capabilities = [] {
    X86Capabilities result;
    int regs[4] = {};
    cpuid(regs, 0);
    const int maxLeaf = regs[0];
    if (maxLeaf < 1) {
      return result;
    }

    cpuid(regs, 1);
    result.aesNi = (regs[2] & (1 << 25)) != 0;

    const bool osxsave = (regs[2] & (1 << 27)) != 0;
    const bool avx = (regs[2] & (1 << 28)) != 0;
    if (maxLeaf < 7 || !result.aesNi || !osxsave || !avx) {
      return result;
    }

    const uint64_t xcr0 = xgetbv(0);
    const bool ymmStateEnabled = (xcr0 & 0x6) == 0x6;
    if (!ymmStateEnabled) {
      return result;
    }

    cpuid(regs, 7, 0);
    const bool avx2 = (regs[1] & (1 << 5)) != 0;
    const bool vaes = (regs[2] & (1 << 9)) != 0;
    result.vaes = avx2 && vaes;

    const bool avx512StateEnabled = (xcr0 & 0xe6) == 0xe6;
    const bool avx512f = (regs[1] & (1 << 16)) != 0;
    const bool avx512dq = (regs[1] & (1 << 17)) != 0;
    const bool avx512bw = (regs[1] & (1 << 30)) != 0;
    const bool avx512vl = (regs[1] & (1u << 31)) != 0;
    result.vaes512 = vaes && avx512StateEnabled && avx512f && avx512dq &&
                     avx512bw && avx512vl;
    return result;
  }();
  return capabilities;
}

inline const X86ImplType &getX86ImplType() {
  static const X86ImplType implType = [] {
    const auto &capabilities = getX86Capabilities();
#if defined(WAES_VAES512)
    if (capabilities.vaes512) {
      return X86ImplType::VAES512;
    }
#endif
#if defined(WAES_VAES)
    if (capabilities.vaes) {
      return X86ImplType::VAES;
    }
#endif
    if (capabilities.aesNi) {
      return X86ImplType::AES_NI;
    }
    return X86ImplType::Generic;
  }();
  return implType;
}

template <int> inline void keyExpansion(const uint8_t *key, __m128i *w);

template <> inline void keyExpansion<128>(const uint8_t *key, __m128i *w) {
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

template <> inline void keyExpansion<192>(const uint8_t *key, __m128i *w) {
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

template <> inline void keyExpansion<256>(const uint8_t *key, __m128i *w) {
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

template <int N> class WAesNi : public Aes {
protected:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };
  __m128i m_w[Nr * 2];
  __m128i m_iv = {};

  WAesNi(const void *key, size_t keyLength, const void *iv, size_t ivLength,
         Padding padding)
      : Aes(padding) {
    // Always stage the key. Besides preserving legacy zero-padding/truncation,
    // the extra bytes make the two SIMD loads used by AES-192 memory-safe.
    alignas(16) uint8_t normalizedKey[32] = {};
    const size_t normalizedLength = keyLength > 4 * Nk ? 4 * Nk : keyLength;
    if (normalizedLength) {
      memcpy(normalizedKey, key, normalizedLength);
    }
    keyExpansion<N>(normalizedKey, m_w);

    // imc
    for (uint8_t i = Nr + 1; i < Nr * 2; ++i) {
      m_w[i] = _mm_aesimc_si128(m_w[Nr * 2 - i]);
    }

    if (iv) { // iv padding zero
      m_mode = Mode::CBC;
      memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  void cipher(__m128i &state) const {
    state = _mm_xor_si128(state, m_w[0]);
    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm_aesenc_si128(state, m_w[r]);
    }
    state = _mm_aesenclast_si128(state, m_w[Nr]);
  }

  void invCipher(__m128i &state) const {
    state = _mm_xor_si128(state, m_w[Nr]);
    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm_aesdec_si128(state, m_w[r]);
    }
    state = _mm_aesdeclast_si128(state, m_w[0]);
  }

  void paddingECB(size_t len, const __m128i *input, __m128i *output) const {
    if (len || Padding::PKCS7 == m_padding) {
      alignas(16) uint8_t block[16] = {};
      if (len) {
        memcpy(block, input, len);
      }
      auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<int>(len);
      memset(block + len, pad, 16 - len);
      __m128i state = _mm_load_si128(reinterpret_cast<const __m128i *>(block));
      cipher(state);
      _mm_storeu_si128(output, state);
    }
  }

  bool invLastBlockECB(const void *in, size_t inLength, void *out,
                       size_t &outLength) const {
    if (!inLength || inLength % 16) { // invalid data length
      return false;
    }

    auto block = static_cast<int64_t>(inLength / 16) - 1;
    auto state = _mm_loadu_si128(reinterpret_cast<const __m128i *>(in) + block);
    invCipher(state);

    // sum padding length
    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t *>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t *>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    memcpy(reinterpret_cast<__m128i *>(out) + block, &state, endLen);

    return true;
  }

  bool invLastBlockCBC(const void *in, size_t inLength, void *out,
                       size_t &outLength) const {
    if (!inLength || inLength % 16) { // invalid data length
      return false;
    }

    auto block = static_cast<int64_t>(inLength / 16) - 1;
    auto input = reinterpret_cast<const __m128i *>(in);

    // sum padding length
    auto state =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(input + block));
    invCipher(state);

    __m128i iv;
    if (block) {
      iv =
          _mm_loadu_si128(reinterpret_cast<const __m128i *>(input + block - 1));
    } else {
      iv = m_iv;
    }
    state = _mm_xor_si128(state, iv);

    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t *>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t *>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    memcpy(reinterpret_cast<__m128i *>(out) + block, &state, endLen);

    return true;
  }

  virtual bool cipherECB(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    __m128i state;
    auto len = inLength;
    auto input = reinterpret_cast<const __m128i *>(in);
    auto output = reinterpret_cast<__m128i *>(out);
    for (; len >= 16; len -= 16, ++input, ++output) {
      state = _mm_loadu_si128(input);
      cipher(state);
      _mm_storeu_si128(output, state);
    }

    paddingECB(len, input, output);

    return true;
  }

  virtual bool cipherCBC(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const __m128i *>(in);
    auto output = reinterpret_cast<__m128i *>(out);

    auto state = m_iv;
    for (; len >= 16; len -= 16, ++input, ++output) {
      state = _mm_xor_si128(_mm_loadu_si128(input), state);
      cipher(state);
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

      cipher(state);
      _mm_storeu_si128(output, state);
    }

    return true;
  }

  virtual bool cipherCTR(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    static const auto one = _mm_set_epi32(0, 1, 0, 0);
    static const auto bswap_epi64 =
        _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);

    auto counter = _mm_shuffle_epi8(m_iv, bswap_epi64);

    int64_t len = inLength / 16;
    auto input = reinterpret_cast<const __m128i *>(in);
    auto output = reinterpret_cast<__m128i *>(out);
    for (int64_t i = 0; i < len; ++i, ++input, ++output) {
      auto state = _mm_shuffle_epi8(counter, bswap_epi64);
      cipher(state);
      _mm_storeu_si128(output, _mm_xor_si128(_mm_loadu_si128(input), state));

      counter = _mm_add_epi64(counter, one);
    }

    int8_t endLen = inLength % 16;
    if (endLen) {
      auto state = _mm_shuffle_epi8(counter, bswap_epi64);
      cipher(state);
      for (int8_t i = 0; i < endLen; ++i) {
        reinterpret_cast<uint8_t *>(output)[i] =
            reinterpret_cast<const uint8_t *>(input)[i] ^
            reinterpret_cast<uint8_t *>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!invLastBlockECB(in, inLength, out, outLength)) {
      return false;
    }

    auto len = inLength - 16;
    auto input = reinterpret_cast<const __m128i *>(in);
    auto output = reinterpret_cast<__m128i *>(out);
    for (; len >= 16; len -= 16, ++input, ++output) {
      auto state = _mm_loadu_si128(input);
      invCipher(state);
      _mm_storeu_si128(output, state);
    }

    return true;
  }

  virtual bool invCipherCBC(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!invLastBlockCBC(in, inLength, out, outLength)) {
      return false;
    }

    __m128i niv, iv = m_iv;
    auto len = static_cast<int64_t>(inLength / 16) - 1;
    auto input = reinterpret_cast<const __m128i *>(in);
    auto output = reinterpret_cast<__m128i *>(out);
    for (int i = 0; i < len; ++i, ++input, ++output) {
      auto state = niv = _mm_loadu_si128(input);
      invCipher(state);
      _mm_storeu_si128(output, _mm_xor_si128(state, iv));

      iv = niv;
    }

    return true;
  }

  virtual void setIVImpl(const void *iv, size_t length) override {
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, iv, length > 16 ? 16 : length);
  }

  virtual void getIVImpl(void *iv) const override { memcpy(iv, &m_iv, 16); }

  virtual Ptr Clone() const override { return Ptr(new WAesNi<N>(*this)); }

  friend Ptr WAes::Create<N>(const void *, size_t, const void *, size_t,
                             Padding);
  friend Ptr WAes::Create<N>(Backend, const void *, size_t, const void *,
                             size_t, Padding);
};

#if defined(WAES_VAES)
template <int N> class WAesV final : public WAesNi<N> {
private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };

  __m256i m_w256[Nr * 2];

  WAesV(const void *key, size_t keyLength, const void *iv, size_t ivLength,
        Padding padding)
      : WAesNi<N>(key, keyLength, iv, ivLength, padding) {
    for (int i = 0; i < Nr * 2; ++i) {
      m_w256[i] = _mm256_broadcastsi128_si256(WAesNi<N>::m_w[i]);
    }
  }

  void cipher(__m256i &state) const {
    state = _mm256_xor_si256(state, m_w256[0]);
    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm256_aesenc_epi128(state, m_w256[r]);
    }
    state = _mm256_aesenclast_epi128(state, m_w256[Nr]);
  }

  void invCipher(__m256i &state) const {
    state = _mm256_xor_si256(state, m_w256[Nr]);
    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm256_aesdec_epi128(state, m_w256[r]);
    }
    state = _mm256_aesdeclast_epi128(state, m_w256[0]);
  }

  virtual bool cipherECB(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = WAesNi<N>::SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input256 = reinterpret_cast<const __m256i *>(in);
    auto output256 = reinterpret_cast<__m256i *>(out);

    for (; len >= 32; len -= 32, ++input256, ++output256) {
      auto state = _mm256_loadu_si256(input256);
      cipher(state);
      _mm256_storeu_si256(output256, state);
    }

    auto input128 = reinterpret_cast<const __m128i *>(input256);
    auto output128 = reinterpret_cast<__m128i *>(output256);
    if (len >= 16) {
      auto state = _mm_loadu_si128(input128);
      WAesNi<N>::cipher(state);
      _mm_storeu_si128(output128, state);

      len -= 16;
      ++input128;
      ++output128;
    }

    WAesNi<N>::paddingECB(len, input128, output128);

    return true;
  }

  virtual bool cipherCTR(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    static const auto bswap_epi64 =
        _mm256_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
                         7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
    static const auto increment = _mm256_set_epi64x(2, 0, 2, 0);
    auto counters = _mm256_add_epi64(
        _mm256_shuffle_epi8(_mm256_broadcastsi128_si256(WAesNi<N>::m_iv),
                            bswap_epi64),
        _mm256_set_epi64x(1, 0, 0, 0));

    auto len = inLength;
    auto input = reinterpret_cast<const __m256i *>(in);
    auto output = reinterpret_cast<__m256i *>(out);
    for (; len >= 32; len -= 32, ++input, ++output) {
      auto state = _mm256_shuffle_epi8(counters, bswap_epi64);
      cipher(state);
      _mm256_storeu_si256(output,
                          _mm256_xor_si256(state, _mm256_loadu_si256(input)));

      counters = _mm256_add_epi64(counters, increment);
    }

    if (len) {
      auto state = _mm256_shuffle_epi8(counters, bswap_epi64);
      cipher(state);
      for (uint8_t i = 0; i < len; ++i) {
        reinterpret_cast<uint8_t *>(output)[i] =
            reinterpret_cast<const uint8_t *>(input)[i] ^
            reinterpret_cast<uint8_t *>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!WAesNi<N>::invLastBlockECB(in, inLength, out, outLength)) {
      return false;
    }

    auto len = inLength - 16;
    auto input = reinterpret_cast<const __m256i *>(in);
    auto output = reinterpret_cast<__m256i *>(out);
    for (; len >= 32; len -= 32, ++input, ++output) {
      auto state256 = _mm256_loadu_si256(input);
      invCipher(state256);
      _mm256_storeu_si256(output, state256);
    }

    if (len == 16) {
      auto state128 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input));
      WAesNi<N>::invCipher(state128);
      _mm_storeu_si128(reinterpret_cast<__m128i *>(output), state128);
    }

    return true;
  }

  virtual bool invCipherCBC(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!WAesNi<N>::invLastBlockCBC(in, inLength, out, outLength)) {
      return false;
    }

    auto input128 = reinterpret_cast<const __m128i *>(in);
    auto input256 = reinterpret_cast<const __m256i *>(in);
    auto output256 = reinterpret_cast<__m256i *>(out);
    auto piv256 = reinterpret_cast<const __m256i *>(input128 + 1);

    auto len = inLength - 16;
    auto ivs = _mm256_setr_m128i(WAesNi<N>::m_iv, _mm_loadu_si128(input128));
    __m128i previous = WAesNi<N>::m_iv;
    for (; len >= 32; len -= 32, ++input256, ++output256, ++piv256) {
      auto state256 = _mm256_loadu_si256(input256);
      previous = _mm256_extracti128_si256(state256, 1);
      __m256i nextIvs = {};
      if (len >= 64) {
        // Load before storing so in-place decryption keeps the ciphertext IVs.
        nextIvs = _mm256_loadu_si256(piv256);
      }
      invCipher(state256);
      _mm256_storeu_si256(output256, _mm256_xor_si256(state256, ivs));
      if (len >= 64) {
        ivs = nextIvs;
      }
    }

    if (len == 16) {
      auto state128 =
          _mm_loadu_si128(reinterpret_cast<const __m128i *>(input256));
      WAesNi<N>::invCipher(state128);
      _mm_storeu_si128(reinterpret_cast<__m128i *>(output256),
                       _mm_xor_si128(state128, previous));
    }

    return true;
  }

  virtual Ptr Clone() const override { return Ptr(new WAesV<N>(*this)); }

  friend Ptr WAes::Create<N>(const void *, size_t, const void *, size_t,
                             Padding);
  friend Ptr WAes::Create<N>(Backend, const void *, size_t, const void *,
                             size_t, Padding);
};
#endif // defined(WAES_VAES)

#if defined(WAES_VAES512)
template <int N> class WAesV512 final : public WAesNi<N> {
private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };

  __m512i m_w512[Nr * 2];

  WAesV512(const void *key, size_t keyLength, const void *iv, size_t ivLength,
           Padding padding)
      : WAesNi<N>(key, keyLength, iv, ivLength, padding) {
    for (int i = 0; i < Nr * 2; ++i) {
      m_w512[i] = _mm512_broadcast_i32x4(WAesNi<N>::m_w[i]);
    }
  }

  void cipher(__m512i &state) const {
    state = _mm512_xor_si512(state, m_w512[0]);
    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm512_aesenc_epi128(state, m_w512[r]);
    }
    state = _mm512_aesenclast_epi128(state, m_w512[Nr]);
  }

  void invCipher(__m512i &state) const {
    state = _mm512_xor_si512(state, m_w512[Nr]);
    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm512_aesdec_epi128(state, m_w512[r]);
    }
    state = _mm512_aesdeclast_epi128(state, m_w512[0]);
  }

  virtual bool cipherECB(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = WAesNi<N>::SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input512 = reinterpret_cast<const __m512i *>(in);
    auto output512 = reinterpret_cast<__m512i *>(out);

    for (; len >= 64; len -= 64, ++input512, ++output512) {
      auto state = _mm512_loadu_si512(input512);
      cipher(state);
      _mm512_storeu_si512(output512, state);
    }

    auto input128 = reinterpret_cast<const __m128i *>(input512);
    auto output128 = reinterpret_cast<__m128i *>(output512);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      auto state = _mm_loadu_si128(input128);
      WAesNi<N>::cipher(state);
      _mm_storeu_si128(output128, state);
    }

    WAesNi<N>::paddingECB(len, input128, output128);

    return true;
  }

  virtual bool cipherCTR(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    static const auto bswap_epi64 = _mm512_broadcast_i32x4(
        _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8));
    static const auto increment = _mm512_set_epi64(4, 0, 4, 0, 4, 0, 4, 0);
    auto counters = _mm512_add_epi64(
        _mm512_shuffle_epi8(_mm512_broadcast_i32x4(WAesNi<N>::m_iv),
                            bswap_epi64),
        _mm512_set_epi64(3, 0, 2, 0, 1, 0, 0, 0));

    auto len = inLength;
    auto input = reinterpret_cast<const __m512i *>(in);
    auto output = reinterpret_cast<__m512i *>(out);
    for (; len >= 64; len -= 64, ++input, ++output) {
      auto state = _mm512_shuffle_epi8(counters, bswap_epi64);
      cipher(state);
      _mm512_storeu_si512(output,
                          _mm512_xor_si512(state, _mm512_loadu_si512(input)));

      counters = _mm512_add_epi64(counters, increment);
    }

    if (len) {
      auto state = _mm512_shuffle_epi8(counters, bswap_epi64);
      cipher(state);
      for (uint8_t i = 0; i < len; ++i) {
        reinterpret_cast<uint8_t *>(output)[i] =
            reinterpret_cast<const uint8_t *>(input)[i] ^
            reinterpret_cast<uint8_t *>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!WAesNi<N>::invLastBlockECB(in, inLength, out, outLength)) {
      return false;
    }

    auto len = inLength - 16;
    auto input = reinterpret_cast<const __m512i *>(in);
    auto output = reinterpret_cast<__m512i *>(out);
    for (; len >= 64; len -= 64, ++input, ++output) {
      auto state512 = _mm512_loadu_si512(input);
      invCipher(state512);
      _mm512_storeu_si512(output, state512);
    }

    auto input128 = reinterpret_cast<const __m128i *>(input);
    auto output128 = reinterpret_cast<__m128i *>(output);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      auto state = _mm_loadu_si128(input128);
      WAesNi<N>::invCipher(state);
      _mm_storeu_si128(output128, state);
    }

    return true;
  }

  virtual bool invCipherCBC(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!WAesNi<N>::invLastBlockCBC(in, inLength, out, outLength)) {
      return false;
    }

    auto input128 = reinterpret_cast<const __m128i *>(in);
    auto input512 = reinterpret_cast<const __m512i *>(in);
    auto output512 = reinterpret_cast<__m512i *>(out);
    auto piv512 = reinterpret_cast<const __m512i *>(input128 + 3);

    auto len = inLength - 16;
    if (len < 64) {
      auto output128 = reinterpret_cast<__m128i *>(out);
      __m128i previous = WAesNi<N>::m_iv;
      for (; len >= 16; len -= 16, ++input128, ++output128) {
        const auto ciphertext = _mm_loadu_si128(input128);
        auto state = ciphertext;
        WAesNi<N>::invCipher(state);
        _mm_storeu_si128(output128, _mm_xor_si128(state, previous));
        previous = ciphertext;
      }
      return true;
    }

    auto ivs = _mm512_castsi128_si512(WAesNi<N>::m_iv);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128), 1);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128 + 1), 2);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128 + 2), 3);
    __m128i previous = WAesNi<N>::m_iv;
    for (; len >= 64; len -= 64, ++input512, ++output512, ++piv512) {
      auto state512 = _mm512_loadu_si512(input512);
      previous = _mm512_extracti32x4_epi32(state512, 3);
      __m512i nextIvs = {};
      if (len >= 128) {
        // Load before storing so in-place decryption keeps the ciphertext IVs.
        nextIvs = _mm512_loadu_si512(piv512);
      }
      invCipher(state512);
      _mm512_storeu_si512(output512, _mm512_xor_si512(state512, ivs));
      if (len >= 128) {
        ivs = nextIvs;
      }
    }

    input128 = reinterpret_cast<const __m128i *>(input512);
    auto output128 = reinterpret_cast<__m128i *>(output512);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      const auto ciphertext = _mm_loadu_si128(input128);
      auto state = ciphertext;
      WAesNi<N>::invCipher(state);
      _mm_storeu_si128(output128, _mm_xor_si128(state, previous));
      previous = ciphertext;
    }

    return true;
  }

  virtual Ptr Clone() const override { return Ptr(new WAesV512<N>(*this)); }

  friend Ptr WAes::Create<N>(const void *, size_t, const void *, size_t,
                             Padding);
  friend Ptr WAes::Create<N>(Backend, const void *, size_t, const void *,
                             size_t, Padding);
};
#endif // defined(WAES_VAES512)

#endif

alignas(64) inline const uint8_t g_sBox[256] = {
    /* 0 1 2 3 4 5 6 7 8 9 a b c d e f */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, /*0*/
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, /*1*/
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, /*2*/
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, /*3*/
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, /*4*/
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, /*5*/
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, /*6*/
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, /*7*/
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, /*8*/
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, /*9*/
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, /*a*/
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, /*b*/
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, /*c*/
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, /*d*/
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, /*e*/
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, /*f*/
};

alignas(64) inline const uint8_t g_invSbox[256] = {
    /* 0 1 2 3 4 5 6 7 8 9 a b c d e f */
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, /*0*/
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, /*1*/
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, /*2*/
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, /*3*/
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, /*4*/
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, /*5*/
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, /*6*/
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, /*7*/
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, /*8*/
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, /*9*/
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, /*a*/
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, /*b*/
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, /*c*/
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, /*d*/
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, /*e*/
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, /*f*/
};

alignas(64) inline const uint32_t Te0[256] = {
    0xa56363c6u, 0x847c7cf8u, 0x997777eeu, 0x8d7b7bf6u, 0x0df2f2ffu,
    0xbd6b6bd6u, 0xb16f6fdeu, 0x54c5c591u, 0x50303060u, 0x03010102u,
    0xa96767ceu, 0x7d2b2b56u, 0x19fefee7u, 0x62d7d7b5u, 0xe6abab4du,
    0x9a7676ecu, 0x45caca8fu, 0x9d82821fu, 0x40c9c989u, 0x877d7dfau,
    0x15fafaefu, 0xeb5959b2u, 0xc947478eu, 0x0bf0f0fbu, 0xecadad41u,
    0x67d4d4b3u, 0xfda2a25fu, 0xeaafaf45u, 0xbf9c9c23u, 0xf7a4a453u,
    0x967272e4u, 0x5bc0c09bu, 0xc2b7b775u, 0x1cfdfde1u, 0xae93933du,
    0x6a26264cu, 0x5a36366cu, 0x413f3f7eu, 0x02f7f7f5u, 0x4fcccc83u,
    0x5c343468u, 0xf4a5a551u, 0x34e5e5d1u, 0x08f1f1f9u, 0x937171e2u,
    0x73d8d8abu, 0x53313162u, 0x3f15152au, 0x0c040408u, 0x52c7c795u,
    0x65232346u, 0x5ec3c39du, 0x28181830u, 0xa1969637u, 0x0f05050au,
    0xb59a9a2fu, 0x0907070eu, 0x36121224u, 0x9b80801bu, 0x3de2e2dfu,
    0x26ebebcdu, 0x6927274eu, 0xcdb2b27fu, 0x9f7575eau, 0x1b090912u,
    0x9e83831du, 0x742c2c58u, 0x2e1a1a34u, 0x2d1b1b36u, 0xb26e6edcu,
    0xee5a5ab4u, 0xfba0a05bu, 0xf65252a4u, 0x4d3b3b76u, 0x61d6d6b7u,
    0xceb3b37du, 0x7b292952u, 0x3ee3e3ddu, 0x712f2f5eu, 0x97848413u,
    0xf55353a6u, 0x68d1d1b9u, 0x00000000u, 0x2cededc1u, 0x60202040u,
    0x1ffcfce3u, 0xc8b1b179u, 0xed5b5bb6u, 0xbe6a6ad4u, 0x46cbcb8du,
    0xd9bebe67u, 0x4b393972u, 0xde4a4a94u, 0xd44c4c98u, 0xe85858b0u,
    0x4acfcf85u, 0x6bd0d0bbu, 0x2aefefc5u, 0xe5aaaa4fu, 0x16fbfbedu,
    0xc5434386u, 0xd74d4d9au, 0x55333366u, 0x94858511u, 0xcf45458au,
    0x10f9f9e9u, 0x06020204u, 0x817f7ffeu, 0xf05050a0u, 0x443c3c78u,
    0xba9f9f25u, 0xe3a8a84bu, 0xf35151a2u, 0xfea3a35du, 0xc0404080u,
    0x8a8f8f05u, 0xad92923fu, 0xbc9d9d21u, 0x48383870u, 0x04f5f5f1u,
    0xdfbcbc63u, 0xc1b6b677u, 0x75dadaafu, 0x63212142u, 0x30101020u,
    0x1affffe5u, 0x0ef3f3fdu, 0x6dd2d2bfu, 0x4ccdcd81u, 0x140c0c18u,
    0x35131326u, 0x2fececc3u, 0xe15f5fbeu, 0xa2979735u, 0xcc444488u,
    0x3917172eu, 0x57c4c493u, 0xf2a7a755u, 0x827e7efcu, 0x473d3d7au,
    0xac6464c8u, 0xe75d5dbau, 0x2b191932u, 0x957373e6u, 0xa06060c0u,
    0x98818119u, 0xd14f4f9eu, 0x7fdcdca3u, 0x66222244u, 0x7e2a2a54u,
    0xab90903bu, 0x8388880bu, 0xca46468cu, 0x29eeeec7u, 0xd3b8b86bu,
    0x3c141428u, 0x79dedea7u, 0xe25e5ebcu, 0x1d0b0b16u, 0x76dbdbadu,
    0x3be0e0dbu, 0x56323264u, 0x4e3a3a74u, 0x1e0a0a14u, 0xdb494992u,
    0x0a06060cu, 0x6c242448u, 0xe45c5cb8u, 0x5dc2c29fu, 0x6ed3d3bdu,
    0xefacac43u, 0xa66262c4u, 0xa8919139u, 0xa4959531u, 0x37e4e4d3u,
    0x8b7979f2u, 0x32e7e7d5u, 0x43c8c88bu, 0x5937376eu, 0xb76d6ddau,
    0x8c8d8d01u, 0x64d5d5b1u, 0xd24e4e9cu, 0xe0a9a949u, 0xb46c6cd8u,
    0xfa5656acu, 0x07f4f4f3u, 0x25eaeacfu, 0xaf6565cau, 0x8e7a7af4u,
    0xe9aeae47u, 0x18080810u, 0xd5baba6fu, 0x887878f0u, 0x6f25254au,
    0x722e2e5cu, 0x241c1c38u, 0xf1a6a657u, 0xc7b4b473u, 0x51c6c697u,
    0x23e8e8cbu, 0x7cdddda1u, 0x9c7474e8u, 0x211f1f3eu, 0xdd4b4b96u,
    0xdcbdbd61u, 0x868b8b0du, 0x858a8a0fu, 0x907070e0u, 0x423e3e7cu,
    0xc4b5b571u, 0xaa6666ccu, 0xd8484890u, 0x05030306u, 0x01f6f6f7u,
    0x120e0e1cu, 0xa36161c2u, 0x5f35356au, 0xf95757aeu, 0xd0b9b969u,
    0x91868617u, 0x58c1c199u, 0x271d1d3au, 0xb99e9e27u, 0x38e1e1d9u,
    0x13f8f8ebu, 0xb398982bu, 0x33111122u, 0xbb6969d2u, 0x70d9d9a9u,
    0x898e8e07u, 0xa7949433u, 0xb69b9b2du, 0x221e1e3cu, 0x92878715u,
    0x20e9e9c9u, 0x49cece87u, 0xff5555aau, 0x78282850u, 0x7adfdfa5u,
    0x8f8c8c03u, 0xf8a1a159u, 0x80898909u, 0x170d0d1au, 0xdabfbf65u,
    0x31e6e6d7u, 0xc6424284u, 0xb86868d0u, 0xc3414182u, 0xb0999929u,
    0x772d2d5au, 0x110f0f1eu, 0xcbb0b07bu, 0xfc5454a8u, 0xd6bbbb6du,
    0x3a16162cu,
};

alignas(64) inline const uint32_t Te1[256] = {
    0xc6a56363u, 0xf8847c7cu, 0xee997777u, 0xf68d7b7bu, 0xff0df2f2u,
    0xd6bd6b6bu, 0xdeb16f6fu, 0x9154c5c5u, 0x60503030u, 0x02030101u,
    0xcea96767u, 0x567d2b2bu, 0xe719fefeu, 0xb562d7d7u, 0x4de6ababu,
    0xec9a7676u, 0x8f45cacau, 0x1f9d8282u, 0x8940c9c9u, 0xfa877d7du,
    0xef15fafau, 0xb2eb5959u, 0x8ec94747u, 0xfb0bf0f0u, 0x41ecadadu,
    0xb367d4d4u, 0x5ffda2a2u, 0x45eaafafu, 0x23bf9c9cu, 0x53f7a4a4u,
    0xe4967272u, 0x9b5bc0c0u, 0x75c2b7b7u, 0xe11cfdfdu, 0x3dae9393u,
    0x4c6a2626u, 0x6c5a3636u, 0x7e413f3fu, 0xf502f7f7u, 0x834fccccu,
    0x685c3434u, 0x51f4a5a5u, 0xd134e5e5u, 0xf908f1f1u, 0xe2937171u,
    0xab73d8d8u, 0x62533131u, 0x2a3f1515u, 0x080c0404u, 0x9552c7c7u,
    0x46652323u, 0x9d5ec3c3u, 0x30281818u, 0x37a19696u, 0x0a0f0505u,
    0x2fb59a9au, 0x0e090707u, 0x24361212u, 0x1b9b8080u, 0xdf3de2e2u,
    0xcd26ebebu, 0x4e692727u, 0x7fcdb2b2u, 0xea9f7575u, 0x121b0909u,
    0x1d9e8383u, 0x58742c2cu, 0x342e1a1au, 0x362d1b1bu, 0xdcb26e6eu,
    0xb4ee5a5au, 0x5bfba0a0u, 0xa4f65252u, 0x764d3b3bu, 0xb761d6d6u,
    0x7dceb3b3u, 0x527b2929u, 0xdd3ee3e3u, 0x5e712f2fu, 0x13978484u,
    0xa6f55353u, 0xb968d1d1u, 0x00000000u, 0xc12cededu, 0x40602020u,
    0xe31ffcfcu, 0x79c8b1b1u, 0xb6ed5b5bu, 0xd4be6a6au, 0x8d46cbcbu,
    0x67d9bebeu, 0x724b3939u, 0x94de4a4au, 0x98d44c4cu, 0xb0e85858u,
    0x854acfcfu, 0xbb6bd0d0u, 0xc52aefefu, 0x4fe5aaaau, 0xed16fbfbu,
    0x86c54343u, 0x9ad74d4du, 0x66553333u, 0x11948585u, 0x8acf4545u,
    0xe910f9f9u, 0x04060202u, 0xfe817f7fu, 0xa0f05050u, 0x78443c3cu,
    0x25ba9f9fu, 0x4be3a8a8u, 0xa2f35151u, 0x5dfea3a3u, 0x80c04040u,
    0x058a8f8fu, 0x3fad9292u, 0x21bc9d9du, 0x70483838u, 0xf104f5f5u,
    0x63dfbcbcu, 0x77c1b6b6u, 0xaf75dadau, 0x42632121u, 0x20301010u,
    0xe51affffu, 0xfd0ef3f3u, 0xbf6dd2d2u, 0x814ccdcdu, 0x18140c0cu,
    0x26351313u, 0xc32fececu, 0xbee15f5fu, 0x35a29797u, 0x88cc4444u,
    0x2e391717u, 0x9357c4c4u, 0x55f2a7a7u, 0xfc827e7eu, 0x7a473d3du,
    0xc8ac6464u, 0xbae75d5du, 0x322b1919u, 0xe6957373u, 0xc0a06060u,
    0x19988181u, 0x9ed14f4fu, 0xa37fdcdcu, 0x44662222u, 0x547e2a2au,
    0x3bab9090u, 0x0b838888u, 0x8cca4646u, 0xc729eeeeu, 0x6bd3b8b8u,
    0x283c1414u, 0xa779dedeu, 0xbce25e5eu, 0x161d0b0bu, 0xad76dbdbu,
    0xdb3be0e0u, 0x64563232u, 0x744e3a3au, 0x141e0a0au, 0x92db4949u,
    0x0c0a0606u, 0x486c2424u, 0xb8e45c5cu, 0x9f5dc2c2u, 0xbd6ed3d3u,
    0x43efacacu, 0xc4a66262u, 0x39a89191u, 0x31a49595u, 0xd337e4e4u,
    0xf28b7979u, 0xd532e7e7u, 0x8b43c8c8u, 0x6e593737u, 0xdab76d6du,
    0x018c8d8du, 0xb164d5d5u, 0x9cd24e4eu, 0x49e0a9a9u, 0xd8b46c6cu,
    0xacfa5656u, 0xf307f4f4u, 0xcf25eaeau, 0xcaaf6565u, 0xf48e7a7au,
    0x47e9aeaeu, 0x10180808u, 0x6fd5babau, 0xf0887878u, 0x4a6f2525u,
    0x5c722e2eu, 0x38241c1cu, 0x57f1a6a6u, 0x73c7b4b4u, 0x9751c6c6u,
    0xcb23e8e8u, 0xa17cddddu, 0xe89c7474u, 0x3e211f1fu, 0x96dd4b4bu,
    0x61dcbdbdu, 0x0d868b8bu, 0x0f858a8au, 0xe0907070u, 0x7c423e3eu,
    0x71c4b5b5u, 0xccaa6666u, 0x90d84848u, 0x06050303u, 0xf701f6f6u,
    0x1c120e0eu, 0xc2a36161u, 0x6a5f3535u, 0xaef95757u, 0x69d0b9b9u,
    0x17918686u, 0x9958c1c1u, 0x3a271d1du, 0x27b99e9eu, 0xd938e1e1u,
    0xeb13f8f8u, 0x2bb39898u, 0x22331111u, 0xd2bb6969u, 0xa970d9d9u,
    0x07898e8eu, 0x33a79494u, 0x2db69b9bu, 0x3c221e1eu, 0x15928787u,
    0xc920e9e9u, 0x8749ceceu, 0xaaff5555u, 0x50782828u, 0xa57adfdfu,
    0x038f8c8cu, 0x59f8a1a1u, 0x09808989u, 0x1a170d0du, 0x65dabfbfu,
    0xd731e6e6u, 0x84c64242u, 0xd0b86868u, 0x82c34141u, 0x29b09999u,
    0x5a772d2du, 0x1e110f0fu, 0x7bcbb0b0u, 0xa8fc5454u, 0x6dd6bbbbu,
    0x2c3a1616u,
};

alignas(64) inline const uint32_t Te2[256] = {
    0x63c6a563u, 0x7cf8847cu, 0x77ee9977u, 0x7bf68d7bu, 0xf2ff0df2u,
    0x6bd6bd6bu, 0x6fdeb16fu, 0xc59154c5u, 0x30605030u, 0x01020301u,
    0x67cea967u, 0x2b567d2bu, 0xfee719feu, 0xd7b562d7u, 0xab4de6abu,
    0x76ec9a76u, 0xca8f45cau, 0x821f9d82u, 0xc98940c9u, 0x7dfa877du,
    0xfaef15fau, 0x59b2eb59u, 0x478ec947u, 0xf0fb0bf0u, 0xad41ecadu,
    0xd4b367d4u, 0xa25ffda2u, 0xaf45eaafu, 0x9c23bf9cu, 0xa453f7a4u,
    0x72e49672u, 0xc09b5bc0u, 0xb775c2b7u, 0xfde11cfdu, 0x933dae93u,
    0x264c6a26u, 0x366c5a36u, 0x3f7e413fu, 0xf7f502f7u, 0xcc834fccu,
    0x34685c34u, 0xa551f4a5u, 0xe5d134e5u, 0xf1f908f1u, 0x71e29371u,
    0xd8ab73d8u, 0x31625331u, 0x152a3f15u, 0x04080c04u, 0xc79552c7u,
    0x23466523u, 0xc39d5ec3u, 0x18302818u, 0x9637a196u, 0x050a0f05u,
    0x9a2fb59au, 0x070e0907u, 0x12243612u, 0x801b9b80u, 0xe2df3de2u,
    0xebcd26ebu, 0x274e6927u, 0xb27fcdb2u, 0x75ea9f75u, 0x09121b09u,
    0x831d9e83u, 0x2c58742cu, 0x1a342e1au, 0x1b362d1bu, 0x6edcb26eu,
    0x5ab4ee5au, 0xa05bfba0u, 0x52a4f652u, 0x3b764d3bu, 0xd6b761d6u,
    0xb37dceb3u, 0x29527b29u, 0xe3dd3ee3u, 0x2f5e712fu, 0x84139784u,
    0x53a6f553u, 0xd1b968d1u, 0x00000000u, 0xedc12cedu, 0x20406020u,
    0xfce31ffcu, 0xb179c8b1u, 0x5bb6ed5bu, 0x6ad4be6au, 0xcb8d46cbu,
    0xbe67d9beu, 0x39724b39u, 0x4a94de4au, 0x4c98d44cu, 0x58b0e858u,
    0xcf854acfu, 0xd0bb6bd0u, 0xefc52aefu, 0xaa4fe5aau, 0xfbed16fbu,
    0x4386c543u, 0x4d9ad74du, 0x33665533u, 0x85119485u, 0x458acf45u,
    0xf9e910f9u, 0x02040602u, 0x7ffe817fu, 0x50a0f050u, 0x3c78443cu,
    0x9f25ba9fu, 0xa84be3a8u, 0x51a2f351u, 0xa35dfea3u, 0x4080c040u,
    0x8f058a8fu, 0x923fad92u, 0x9d21bc9du, 0x38704838u, 0xf5f104f5u,
    0xbc63dfbcu, 0xb677c1b6u, 0xdaaf75dau, 0x21426321u, 0x10203010u,
    0xffe51affu, 0xf3fd0ef3u, 0xd2bf6dd2u, 0xcd814ccdu, 0x0c18140cu,
    0x13263513u, 0xecc32fecu, 0x5fbee15fu, 0x9735a297u, 0x4488cc44u,
    0x172e3917u, 0xc49357c4u, 0xa755f2a7u, 0x7efc827eu, 0x3d7a473du,
    0x64c8ac64u, 0x5dbae75du, 0x19322b19u, 0x73e69573u, 0x60c0a060u,
    0x81199881u, 0x4f9ed14fu, 0xdca37fdcu, 0x22446622u, 0x2a547e2au,
    0x903bab90u, 0x880b8388u, 0x468cca46u, 0xeec729eeu, 0xb86bd3b8u,
    0x14283c14u, 0xdea779deu, 0x5ebce25eu, 0x0b161d0bu, 0xdbad76dbu,
    0xe0db3be0u, 0x32645632u, 0x3a744e3au, 0x0a141e0au, 0x4992db49u,
    0x060c0a06u, 0x24486c24u, 0x5cb8e45cu, 0xc29f5dc2u, 0xd3bd6ed3u,
    0xac43efacu, 0x62c4a662u, 0x9139a891u, 0x9531a495u, 0xe4d337e4u,
    0x79f28b79u, 0xe7d532e7u, 0xc88b43c8u, 0x376e5937u, 0x6ddab76du,
    0x8d018c8du, 0xd5b164d5u, 0x4e9cd24eu, 0xa949e0a9u, 0x6cd8b46cu,
    0x56acfa56u, 0xf4f307f4u, 0xeacf25eau, 0x65caaf65u, 0x7af48e7au,
    0xae47e9aeu, 0x08101808u, 0xba6fd5bau, 0x78f08878u, 0x254a6f25u,
    0x2e5c722eu, 0x1c38241cu, 0xa657f1a6u, 0xb473c7b4u, 0xc69751c6u,
    0xe8cb23e8u, 0xdda17cddu, 0x74e89c74u, 0x1f3e211fu, 0x4b96dd4bu,
    0xbd61dcbdu, 0x8b0d868bu, 0x8a0f858au, 0x70e09070u, 0x3e7c423eu,
    0xb571c4b5u, 0x66ccaa66u, 0x4890d848u, 0x03060503u, 0xf6f701f6u,
    0x0e1c120eu, 0x61c2a361u, 0x356a5f35u, 0x57aef957u, 0xb969d0b9u,
    0x86179186u, 0xc19958c1u, 0x1d3a271du, 0x9e27b99eu, 0xe1d938e1u,
    0xf8eb13f8u, 0x982bb398u, 0x11223311u, 0x69d2bb69u, 0xd9a970d9u,
    0x8e07898eu, 0x9433a794u, 0x9b2db69bu, 0x1e3c221eu, 0x87159287u,
    0xe9c920e9u, 0xce8749ceu, 0x55aaff55u, 0x28507828u, 0xdfa57adfu,
    0x8c038f8cu, 0xa159f8a1u, 0x89098089u, 0x0d1a170du, 0xbf65dabfu,
    0xe6d731e6u, 0x4284c642u, 0x68d0b868u, 0x4182c341u, 0x9929b099u,
    0x2d5a772du, 0x0f1e110fu, 0xb07bcbb0u, 0x54a8fc54u, 0xbb6dd6bbu,
    0x162c3a16u,
};

alignas(64) inline const uint32_t Te3[256] = {
    0x6363c6a5u, 0x7c7cf884u, 0x7777ee99u, 0x7b7bf68du, 0xf2f2ff0du,
    0x6b6bd6bdu, 0x6f6fdeb1u, 0xc5c59154u, 0x30306050u, 0x01010203u,
    0x6767cea9u, 0x2b2b567du, 0xfefee719u, 0xd7d7b562u, 0xabab4de6u,
    0x7676ec9au, 0xcaca8f45u, 0x82821f9du, 0xc9c98940u, 0x7d7dfa87u,
    0xfafaef15u, 0x5959b2ebu, 0x47478ec9u, 0xf0f0fb0bu, 0xadad41ecu,
    0xd4d4b367u, 0xa2a25ffdu, 0xafaf45eau, 0x9c9c23bfu, 0xa4a453f7u,
    0x7272e496u, 0xc0c09b5bu, 0xb7b775c2u, 0xfdfde11cu, 0x93933daeu,
    0x26264c6au, 0x36366c5au, 0x3f3f7e41u, 0xf7f7f502u, 0xcccc834fu,
    0x3434685cu, 0xa5a551f4u, 0xe5e5d134u, 0xf1f1f908u, 0x7171e293u,
    0xd8d8ab73u, 0x31316253u, 0x15152a3fu, 0x0404080cu, 0xc7c79552u,
    0x23234665u, 0xc3c39d5eu, 0x18183028u, 0x969637a1u, 0x05050a0fu,
    0x9a9a2fb5u, 0x07070e09u, 0x12122436u, 0x80801b9bu, 0xe2e2df3du,
    0xebebcd26u, 0x27274e69u, 0xb2b27fcdu, 0x7575ea9fu, 0x0909121bu,
    0x83831d9eu, 0x2c2c5874u, 0x1a1a342eu, 0x1b1b362du, 0x6e6edcb2u,
    0x5a5ab4eeu, 0xa0a05bfbu, 0x5252a4f6u, 0x3b3b764du, 0xd6d6b761u,
    0xb3b37dceu, 0x2929527bu, 0xe3e3dd3eu, 0x2f2f5e71u, 0x84841397u,
    0x5353a6f5u, 0xd1d1b968u, 0x00000000u, 0xededc12cu, 0x20204060u,
    0xfcfce31fu, 0xb1b179c8u, 0x5b5bb6edu, 0x6a6ad4beu, 0xcbcb8d46u,
    0xbebe67d9u, 0x3939724bu, 0x4a4a94deu, 0x4c4c98d4u, 0x5858b0e8u,
    0xcfcf854au, 0xd0d0bb6bu, 0xefefc52au, 0xaaaa4fe5u, 0xfbfbed16u,
    0x434386c5u, 0x4d4d9ad7u, 0x33336655u, 0x85851194u, 0x45458acfu,
    0xf9f9e910u, 0x02020406u, 0x7f7ffe81u, 0x5050a0f0u, 0x3c3c7844u,
    0x9f9f25bau, 0xa8a84be3u, 0x5151a2f3u, 0xa3a35dfeu, 0x404080c0u,
    0x8f8f058au, 0x92923fadu, 0x9d9d21bcu, 0x38387048u, 0xf5f5f104u,
    0xbcbc63dfu, 0xb6b677c1u, 0xdadaaf75u, 0x21214263u, 0x10102030u,
    0xffffe51au, 0xf3f3fd0eu, 0xd2d2bf6du, 0xcdcd814cu, 0x0c0c1814u,
    0x13132635u, 0xececc32fu, 0x5f5fbee1u, 0x979735a2u, 0x444488ccu,
    0x17172e39u, 0xc4c49357u, 0xa7a755f2u, 0x7e7efc82u, 0x3d3d7a47u,
    0x6464c8acu, 0x5d5dbae7u, 0x1919322bu, 0x7373e695u, 0x6060c0a0u,
    0x81811998u, 0x4f4f9ed1u, 0xdcdca37fu, 0x22224466u, 0x2a2a547eu,
    0x90903babu, 0x88880b83u, 0x46468ccau, 0xeeeec729u, 0xb8b86bd3u,
    0x1414283cu, 0xdedea779u, 0x5e5ebce2u, 0x0b0b161du, 0xdbdbad76u,
    0xe0e0db3bu, 0x32326456u, 0x3a3a744eu, 0x0a0a141eu, 0x494992dbu,
    0x06060c0au, 0x2424486cu, 0x5c5cb8e4u, 0xc2c29f5du, 0xd3d3bd6eu,
    0xacac43efu, 0x6262c4a6u, 0x919139a8u, 0x959531a4u, 0xe4e4d337u,
    0x7979f28bu, 0xe7e7d532u, 0xc8c88b43u, 0x37376e59u, 0x6d6ddab7u,
    0x8d8d018cu, 0xd5d5b164u, 0x4e4e9cd2u, 0xa9a949e0u, 0x6c6cd8b4u,
    0x5656acfau, 0xf4f4f307u, 0xeaeacf25u, 0x6565caafu, 0x7a7af48eu,
    0xaeae47e9u, 0x08081018u, 0xbaba6fd5u, 0x7878f088u, 0x25254a6fu,
    0x2e2e5c72u, 0x1c1c3824u, 0xa6a657f1u, 0xb4b473c7u, 0xc6c69751u,
    0xe8e8cb23u, 0xdddda17cu, 0x7474e89cu, 0x1f1f3e21u, 0x4b4b96ddu,
    0xbdbd61dcu, 0x8b8b0d86u, 0x8a8a0f85u, 0x7070e090u, 0x3e3e7c42u,
    0xb5b571c4u, 0x6666ccaau, 0x484890d8u, 0x03030605u, 0xf6f6f701u,
    0x0e0e1c12u, 0x6161c2a3u, 0x35356a5fu, 0x5757aef9u, 0xb9b969d0u,
    0x86861791u, 0xc1c19958u, 0x1d1d3a27u, 0x9e9e27b9u, 0xe1e1d938u,
    0xf8f8eb13u, 0x98982bb3u, 0x11112233u, 0x6969d2bbu, 0xd9d9a970u,
    0x8e8e0789u, 0x949433a7u, 0x9b9b2db6u, 0x1e1e3c22u, 0x87871592u,
    0xe9e9c920u, 0xcece8749u, 0x5555aaffu, 0x28285078u, 0xdfdfa57au,
    0x8c8c038fu, 0xa1a159f8u, 0x89890980u, 0x0d0d1a17u, 0xbfbf65dau,
    0xe6e6d731u, 0x424284c6u, 0x6868d0b8u, 0x414182c3u, 0x999929b0u,
    0x2d2d5a77u, 0x0f0f1e11u, 0xb0b07bcbu, 0x5454a8fcu, 0xbbbb6dd6u,
    0x16162c3au,
};

alignas(64) inline const uint32_t Td0[256] = {
    0x50a7f451u, 0x5365417eu, 0xc3a4171au, 0x965e273au, 0xcb6bab3bu,
    0xf1459d1fu, 0xab58faacu, 0x9303e34bu, 0x55fa3020u, 0xf66d76adu,
    0x9176cc88u, 0x254c02f5u, 0xfcd7e54fu, 0xd7cb2ac5u, 0x80443526u,
    0x8fa362b5u, 0x495ab1deu, 0x671bba25u, 0x980eea45u, 0xe1c0fe5du,
    0x02752fc3u, 0x12f04c81u, 0xa397468du, 0xc6f9d36bu, 0xe75f8f03u,
    0x959c9215u, 0xeb7a6dbfu, 0xda595295u, 0x2d83bed4u, 0xd3217458u,
    0x2969e049u, 0x44c8c98eu, 0x6a89c275u, 0x78798ef4u, 0x6b3e5899u,
    0xdd71b927u, 0xb64fe1beu, 0x17ad88f0u, 0x66ac20c9u, 0xb43ace7du,
    0x184adf63u, 0x82311ae5u, 0x60335197u, 0x457f5362u, 0xe07764b1u,
    0x84ae6bbbu, 0x1ca081feu, 0x942b08f9u, 0x58684870u, 0x19fd458fu,
    0x876cde94u, 0xb7f87b52u, 0x23d373abu, 0xe2024b72u, 0x578f1fe3u,
    0x2aab5566u, 0x0728ebb2u, 0x03c2b52fu, 0x9a7bc586u, 0xa50837d3u,
    0xf2872830u, 0xb2a5bf23u, 0xba6a0302u, 0x5c8216edu, 0x2b1ccf8au,
    0x92b479a7u, 0xf0f207f3u, 0xa1e2694eu, 0xcdf4da65u, 0xd5be0506u,
    0x1f6234d1u, 0x8afea6c4u, 0x9d532e34u, 0xa055f3a2u, 0x32e18a05u,
    0x75ebf6a4u, 0x39ec830bu, 0xaaef6040u, 0x069f715eu, 0x51106ebdu,
    0xf98a213eu, 0x3d06dd96u, 0xae053eddu, 0x46bde64du, 0xb58d5491u,
    0x055dc471u, 0x6fd40604u, 0xff155060u, 0x24fb9819u, 0x97e9bdd6u,
    0xcc434089u, 0x779ed967u, 0xbd42e8b0u, 0x888b8907u, 0x385b19e7u,
    0xdbeec879u, 0x470a7ca1u, 0xe90f427cu, 0xc91e84f8u, 0x00000000u,
    0x83868009u, 0x48ed2b32u, 0xac70111eu, 0x4e725a6cu, 0xfbff0efdu,
    0x5638850fu, 0x1ed5ae3du, 0x27392d36u, 0x64d90f0au, 0x21a65c68u,
    0xd1545b9bu, 0x3a2e3624u, 0xb1670a0cu, 0x0fe75793u, 0xd296eeb4u,
    0x9e919b1bu, 0x4fc5c080u, 0xa220dc61u, 0x694b775au, 0x161a121cu,
    0x0aba93e2u, 0xe52aa0c0u, 0x43e0223cu, 0x1d171b12u, 0x0b0d090eu,
    0xadc78bf2u, 0xb9a8b62du, 0xc8a91e14u, 0x8519f157u, 0x4c0775afu,
    0xbbdd99eeu, 0xfd607fa3u, 0x9f2601f7u, 0xbcf5725cu, 0xc53b6644u,
    0x347efb5bu, 0x7629438bu, 0xdcc623cbu, 0x68fcedb6u, 0x63f1e4b8u,
    0xcadc31d7u, 0x10856342u, 0x40229713u, 0x2011c684u, 0x7d244a85u,
    0xf83dbbd2u, 0x1132f9aeu, 0x6da129c7u, 0x4b2f9e1du, 0xf330b2dcu,
    0xec52860du, 0xd0e3c177u, 0x6c16b32bu, 0x99b970a9u, 0xfa489411u,
    0x2264e947u, 0xc48cfca8u, 0x1a3ff0a0u, 0xd82c7d56u, 0xef903322u,
    0xc74e4987u, 0xc1d138d9u, 0xfea2ca8cu, 0x360bd498u, 0xcf81f5a6u,
    0x28de7aa5u, 0x268eb7dau, 0xa4bfad3fu, 0xe49d3a2cu, 0x0d927850u,
    0x9bcc5f6au, 0x62467e54u, 0xc2138df6u, 0xe8b8d890u, 0x5ef7392eu,
    0xf5afc382u, 0xbe805d9fu, 0x7c93d069u, 0xa92dd56fu, 0xb31225cfu,
    0x3b99acc8u, 0xa77d1810u, 0x6e639ce8u, 0x7bbb3bdbu, 0x097826cdu,
    0xf418596eu, 0x01b79aecu, 0xa89a4f83u, 0x656e95e6u, 0x7ee6ffaau,
    0x08cfbc21u, 0xe6e815efu, 0xd99be7bau, 0xce366f4au, 0xd4099feau,
    0xd67cb029u, 0xafb2a431u, 0x31233f2au, 0x3094a5c6u, 0xc066a235u,
    0x37bc4e74u, 0xa6ca82fcu, 0xb0d090e0u, 0x15d8a733u, 0x4a9804f1u,
    0xf7daec41u, 0x0e50cd7fu, 0x2ff69117u, 0x8dd64d76u, 0x4db0ef43u,
    0x544daaccu, 0xdf0496e4u, 0xe3b5d19eu, 0x1b886a4cu, 0xb81f2cc1u,
    0x7f516546u, 0x04ea5e9du, 0x5d358c01u, 0x737487fau, 0x2e410bfbu,
    0x5a1d67b3u, 0x52d2db92u, 0x335610e9u, 0x1347d66du, 0x8c61d79au,
    0x7a0ca137u, 0x8e14f859u, 0x893c13ebu, 0xee27a9ceu, 0x35c961b7u,
    0xede51ce1u, 0x3cb1477au, 0x59dfd29cu, 0x3f73f255u, 0x79ce1418u,
    0xbf37c773u, 0xeacdf753u, 0x5baafd5fu, 0x146f3ddfu, 0x86db4478u,
    0x81f3afcau, 0x3ec468b9u, 0x2c342438u, 0x5f40a3c2u, 0x72c31d16u,
    0x0c25e2bcu, 0x8b493c28u, 0x41950dffu, 0x7101a839u, 0xdeb30c08u,
    0x9ce4b4d8u, 0x90c15664u, 0x6184cb7bu, 0x70b632d5u, 0x745c6c48u,
    0x4257b8d0u,
};

alignas(64) inline const uint32_t Td1[256] = {
    0x5150a7f4u, 0x7e536541u, 0x1ac3a417u, 0x3a965e27u, 0x3bcb6babu,
    0x1ff1459du, 0xacab58fau, 0x4b9303e3u, 0x2055fa30u, 0xadf66d76u,
    0x889176ccu, 0xf5254c02u, 0x4ffcd7e5u, 0xc5d7cb2au, 0x26804435u,
    0xb58fa362u, 0xde495ab1u, 0x25671bbau, 0x45980eeau, 0x5de1c0feu,
    0xc302752fu, 0x8112f04cu, 0x8da39746u, 0x6bc6f9d3u, 0x03e75f8fu,
    0x15959c92u, 0xbfeb7a6du, 0x95da5952u, 0xd42d83beu, 0x58d32174u,
    0x492969e0u, 0x8e44c8c9u, 0x756a89c2u, 0xf478798eu, 0x996b3e58u,
    0x27dd71b9u, 0xbeb64fe1u, 0xf017ad88u, 0xc966ac20u, 0x7db43aceu,
    0x63184adfu, 0xe582311au, 0x97603351u, 0x62457f53u, 0xb1e07764u,
    0xbb84ae6bu, 0xfe1ca081u, 0xf9942b08u, 0x70586848u, 0x8f19fd45u,
    0x94876cdeu, 0x52b7f87bu, 0xab23d373u, 0x72e2024bu, 0xe3578f1fu,
    0x662aab55u, 0xb20728ebu, 0x2f03c2b5u, 0x869a7bc5u, 0xd3a50837u,
    0x30f28728u, 0x23b2a5bfu, 0x02ba6a03u, 0xed5c8216u, 0x8a2b1ccfu,
    0xa792b479u, 0xf3f0f207u, 0x4ea1e269u, 0x65cdf4dau, 0x06d5be05u,
    0xd11f6234u, 0xc48afea6u, 0x349d532eu, 0xa2a055f3u, 0x0532e18au,
    0xa475ebf6u, 0x0b39ec83u, 0x40aaef60u, 0x5e069f71u, 0xbd51106eu,
    0x3ef98a21u, 0x963d06ddu, 0xddae053eu, 0x4d46bde6u, 0x91b58d54u,
    0x71055dc4u, 0x046fd406u, 0x60ff1550u, 0x1924fb98u, 0xd697e9bdu,
    0x89cc4340u, 0x67779ed9u, 0xb0bd42e8u, 0x07888b89u, 0xe7385b19u,
    0x79dbeec8u, 0xa1470a7cu, 0x7ce90f42u, 0xf8c91e84u, 0x00000000u,
    0x09838680u, 0x3248ed2bu, 0x1eac7011u, 0x6c4e725au, 0xfdfbff0eu,
    0x0f563885u, 0x3d1ed5aeu, 0x3627392du, 0x0a64d90fu, 0x6821a65cu,
    0x9bd1545bu, 0x243a2e36u, 0x0cb1670au, 0x930fe757u, 0xb4d296eeu,
    0x1b9e919bu, 0x804fc5c0u, 0x61a220dcu, 0x5a694b77u, 0x1c161a12u,
    0xe20aba93u, 0xc0e52aa0u, 0x3c43e022u, 0x121d171bu, 0x0e0b0d09u,
    0xf2adc78bu, 0x2db9a8b6u, 0x14c8a91eu, 0x578519f1u, 0xaf4c0775u,
    0xeebbdd99u, 0xa3fd607fu, 0xf79f2601u, 0x5cbcf572u, 0x44c53b66u,
    0x5b347efbu, 0x8b762943u, 0xcbdcc623u, 0xb668fcedu, 0xb863f1e4u,
    0xd7cadc31u, 0x42108563u, 0x13402297u, 0x842011c6u, 0x857d244au,
    0xd2f83dbbu, 0xae1132f9u, 0xc76da129u, 0x1d4b2f9eu, 0xdcf330b2u,
    0x0dec5286u, 0x77d0e3c1u, 0x2b6c16b3u, 0xa999b970u, 0x11fa4894u,
    0x472264e9u, 0xa8c48cfcu, 0xa01a3ff0u, 0x56d82c7du, 0x22ef9033u,
    0x87c74e49u, 0xd9c1d138u, 0x8cfea2cau, 0x98360bd4u, 0xa6cf81f5u,
    0xa528de7au, 0xda268eb7u, 0x3fa4bfadu, 0x2ce49d3au, 0x500d9278u,
    0x6a9bcc5fu, 0x5462467eu, 0xf6c2138du, 0x90e8b8d8u, 0x2e5ef739u,
    0x82f5afc3u, 0x9fbe805du, 0x697c93d0u, 0x6fa92dd5u, 0xcfb31225u,
    0xc83b99acu, 0x10a77d18u, 0xe86e639cu, 0xdb7bbb3bu, 0xcd097826u,
    0x6ef41859u, 0xec01b79au, 0x83a89a4fu, 0xe6656e95u, 0xaa7ee6ffu,
    0x2108cfbcu, 0xefe6e815u, 0xbad99be7u, 0x4ace366fu, 0xead4099fu,
    0x29d67cb0u, 0x31afb2a4u, 0x2a31233fu, 0xc63094a5u, 0x35c066a2u,
    0x7437bc4eu, 0xfca6ca82u, 0xe0b0d090u, 0x3315d8a7u, 0xf14a9804u,
    0x41f7daecu, 0x7f0e50cdu, 0x172ff691u, 0x768dd64du, 0x434db0efu,
    0xcc544daau, 0xe4df0496u, 0x9ee3b5d1u, 0x4c1b886au, 0xc1b81f2cu,
    0x467f5165u, 0x9d04ea5eu, 0x015d358cu, 0xfa737487u, 0xfb2e410bu,
    0xb35a1d67u, 0x9252d2dbu, 0xe9335610u, 0x6d1347d6u, 0x9a8c61d7u,
    0x377a0ca1u, 0x598e14f8u, 0xeb893c13u, 0xceee27a9u, 0xb735c961u,
    0xe1ede51cu, 0x7a3cb147u, 0x9c59dfd2u, 0x553f73f2u, 0x1879ce14u,
    0x73bf37c7u, 0x53eacdf7u, 0x5f5baafdu, 0xdf146f3du, 0x7886db44u,
    0xca81f3afu, 0xb93ec468u, 0x382c3424u, 0xc25f40a3u, 0x1672c31du,
    0xbc0c25e2u, 0x288b493cu, 0xff41950du, 0x397101a8u, 0x08deb30cu,
    0xd89ce4b4u, 0x6490c156u, 0x7b6184cbu, 0xd570b632u, 0x48745c6cu,
    0xd04257b8u,
};

alignas(64) inline const uint32_t Td2[256] = {
    0xf45150a7u, 0x417e5365u, 0x171ac3a4u, 0x273a965eu, 0xab3bcb6bu,
    0x9d1ff145u, 0xfaacab58u, 0xe34b9303u, 0x302055fau, 0x76adf66du,
    0xcc889176u, 0x02f5254cu, 0xe54ffcd7u, 0x2ac5d7cbu, 0x35268044u,
    0x62b58fa3u, 0xb1de495au, 0xba25671bu, 0xea45980eu, 0xfe5de1c0u,
    0x2fc30275u, 0x4c8112f0u, 0x468da397u, 0xd36bc6f9u, 0x8f03e75fu,
    0x9215959cu, 0x6dbfeb7au, 0x5295da59u, 0xbed42d83u, 0x7458d321u,
    0xe0492969u, 0xc98e44c8u, 0xc2756a89u, 0x8ef47879u, 0x58996b3eu,
    0xb927dd71u, 0xe1beb64fu, 0x88f017adu, 0x20c966acu, 0xce7db43au,
    0xdf63184au, 0x1ae58231u, 0x51976033u, 0x5362457fu, 0x64b1e077u,
    0x6bbb84aeu, 0x81fe1ca0u, 0x08f9942bu, 0x48705868u, 0x458f19fdu,
    0xde94876cu, 0x7b52b7f8u, 0x73ab23d3u, 0x4b72e202u, 0x1fe3578fu,
    0x55662aabu, 0xebb20728u, 0xb52f03c2u, 0xc5869a7bu, 0x37d3a508u,
    0x2830f287u, 0xbf23b2a5u, 0x0302ba6au, 0x16ed5c82u, 0xcf8a2b1cu,
    0x79a792b4u, 0x07f3f0f2u, 0x694ea1e2u, 0xda65cdf4u, 0x0506d5beu,
    0x34d11f62u, 0xa6c48afeu, 0x2e349d53u, 0xf3a2a055u, 0x8a0532e1u,
    0xf6a475ebu, 0x830b39ecu, 0x6040aaefu, 0x715e069fu, 0x6ebd5110u,
    0x213ef98au, 0xdd963d06u, 0x3eddae05u, 0xe64d46bdu, 0x5491b58du,
    0xc471055du, 0x06046fd4u, 0x5060ff15u, 0x981924fbu, 0xbdd697e9u,
    0x4089cc43u, 0xd967779eu, 0xe8b0bd42u, 0x8907888bu, 0x19e7385bu,
    0xc879dbeeu, 0x7ca1470au, 0x427ce90fu, 0x84f8c91eu, 0x00000000u,
    0x80098386u, 0x2b3248edu, 0x111eac70u, 0x5a6c4e72u, 0x0efdfbffu,
    0x850f5638u, 0xae3d1ed5u, 0x2d362739u, 0x0f0a64d9u, 0x5c6821a6u,
    0x5b9bd154u, 0x36243a2eu, 0x0a0cb167u, 0x57930fe7u, 0xeeb4d296u,
    0x9b1b9e91u, 0xc0804fc5u, 0xdc61a220u, 0x775a694bu, 0x121c161au,
    0x93e20abau, 0xa0c0e52au, 0x223c43e0u, 0x1b121d17u, 0x090e0b0du,
    0x8bf2adc7u, 0xb62db9a8u, 0x1e14c8a9u, 0xf1578519u, 0x75af4c07u,
    0x99eebbddu, 0x7fa3fd60u, 0x01f79f26u, 0x725cbcf5u, 0x6644c53bu,
    0xfb5b347eu, 0x438b7629u, 0x23cbdcc6u, 0xedb668fcu, 0xe4b863f1u,
    0x31d7cadcu, 0x63421085u, 0x97134022u, 0xc6842011u, 0x4a857d24u,
    0xbbd2f83du, 0xf9ae1132u, 0x29c76da1u, 0x9e1d4b2fu, 0xb2dcf330u,
    0x860dec52u, 0xc177d0e3u, 0xb32b6c16u, 0x70a999b9u, 0x9411fa48u,
    0xe9472264u, 0xfca8c48cu, 0xf0a01a3fu, 0x7d56d82cu, 0x3322ef90u,
    0x4987c74eu, 0x38d9c1d1u, 0xca8cfea2u, 0xd498360bu, 0xf5a6cf81u,
    0x7aa528deu, 0xb7da268eu, 0xad3fa4bfu, 0x3a2ce49du, 0x78500d92u,
    0x5f6a9bccu, 0x7e546246u, 0x8df6c213u, 0xd890e8b8u, 0x392e5ef7u,
    0xc382f5afu, 0x5d9fbe80u, 0xd0697c93u, 0xd56fa92du, 0x25cfb312u,
    0xacc83b99u, 0x1810a77du, 0x9ce86e63u, 0x3bdb7bbbu, 0x26cd0978u,
    0x596ef418u, 0x9aec01b7u, 0x4f83a89au, 0x95e6656eu, 0xffaa7ee6u,
    0xbc2108cfu, 0x15efe6e8u, 0xe7bad99bu, 0x6f4ace36u, 0x9fead409u,
    0xb029d67cu, 0xa431afb2u, 0x3f2a3123u, 0xa5c63094u, 0xa235c066u,
    0x4e7437bcu, 0x82fca6cau, 0x90e0b0d0u, 0xa73315d8u, 0x04f14a98u,
    0xec41f7dau, 0xcd7f0e50u, 0x91172ff6u, 0x4d768dd6u, 0xef434db0u,
    0xaacc544du, 0x96e4df04u, 0xd19ee3b5u, 0x6a4c1b88u, 0x2cc1b81fu,
    0x65467f51u, 0x5e9d04eau, 0x8c015d35u, 0x87fa7374u, 0x0bfb2e41u,
    0x67b35a1du, 0xdb9252d2u, 0x10e93356u, 0xd66d1347u, 0xd79a8c61u,
    0xa1377a0cu, 0xf8598e14u, 0x13eb893cu, 0xa9ceee27u, 0x61b735c9u,
    0x1ce1ede5u, 0x477a3cb1u, 0xd29c59dfu, 0xf2553f73u, 0x141879ceu,
    0xc773bf37u, 0xf753eacdu, 0xfd5f5baau, 0x3ddf146fu, 0x447886dbu,
    0xafca81f3u, 0x68b93ec4u, 0x24382c34u, 0xa3c25f40u, 0x1d1672c3u,
    0xe2bc0c25u, 0x3c288b49u, 0x0dff4195u, 0xa8397101u, 0x0c08deb3u,
    0xb4d89ce4u, 0x566490c1u, 0xcb7b6184u, 0x32d570b6u, 0x6c48745cu,
    0xb8d04257u,
};

alignas(64) inline const uint32_t Td3[256] = {
    0xa7f45150u, 0x65417e53u, 0xa4171ac3u, 0x5e273a96u, 0x6bab3bcbu,
    0x459d1ff1u, 0x58faacabu, 0x03e34b93u, 0xfa302055u, 0x6d76adf6u,
    0x76cc8891u, 0x4c02f525u, 0xd7e54ffcu, 0xcb2ac5d7u, 0x44352680u,
    0xa362b58fu, 0x5ab1de49u, 0x1bba2567u, 0x0eea4598u, 0xc0fe5de1u,
    0x752fc302u, 0xf04c8112u, 0x97468da3u, 0xf9d36bc6u, 0x5f8f03e7u,
    0x9c921595u, 0x7a6dbfebu, 0x595295dau, 0x83bed42du, 0x217458d3u,
    0x69e04929u, 0xc8c98e44u, 0x89c2756au, 0x798ef478u, 0x3e58996bu,
    0x71b927ddu, 0x4fe1beb6u, 0xad88f017u, 0xac20c966u, 0x3ace7db4u,
    0x4adf6318u, 0x311ae582u, 0x33519760u, 0x7f536245u, 0x7764b1e0u,
    0xae6bbb84u, 0xa081fe1cu, 0x2b08f994u, 0x68487058u, 0xfd458f19u,
    0x6cde9487u, 0xf87b52b7u, 0xd373ab23u, 0x024b72e2u, 0x8f1fe357u,
    0xab55662au, 0x28ebb207u, 0xc2b52f03u, 0x7bc5869au, 0x0837d3a5u,
    0x872830f2u, 0xa5bf23b2u, 0x6a0302bau, 0x8216ed5cu, 0x1ccf8a2bu,
    0xb479a792u, 0xf207f3f0u, 0xe2694ea1u, 0xf4da65cdu, 0xbe0506d5u,
    0x6234d11fu, 0xfea6c48au, 0x532e349du, 0x55f3a2a0u, 0xe18a0532u,
    0xebf6a475u, 0xec830b39u, 0xef6040aau, 0x9f715e06u, 0x106ebd51u,
    0x8a213ef9u, 0x06dd963du, 0x053eddaeu, 0xbde64d46u, 0x8d5491b5u,
    0x5dc47105u, 0xd406046fu, 0x155060ffu, 0xfb981924u, 0xe9bdd697u,
    0x434089ccu, 0x9ed96777u, 0x42e8b0bdu, 0x8b890788u, 0x5b19e738u,
    0xeec879dbu, 0x0a7ca147u, 0x0f427ce9u, 0x1e84f8c9u, 0x00000000u,
    0x86800983u, 0xed2b3248u, 0x70111eacu, 0x725a6c4eu, 0xff0efdfbu,
    0x38850f56u, 0xd5ae3d1eu, 0x392d3627u, 0xd90f0a64u, 0xa65c6821u,
    0x545b9bd1u, 0x2e36243au, 0x670a0cb1u, 0xe757930fu, 0x96eeb4d2u,
    0x919b1b9eu, 0xc5c0804fu, 0x20dc61a2u, 0x4b775a69u, 0x1a121c16u,
    0xba93e20au, 0x2aa0c0e5u, 0xe0223c43u, 0x171b121du, 0x0d090e0bu,
    0xc78bf2adu, 0xa8b62db9u, 0xa91e14c8u, 0x19f15785u, 0x0775af4cu,
    0xdd99eebbu, 0x607fa3fdu, 0x2601f79fu, 0xf5725cbcu, 0x3b6644c5u,
    0x7efb5b34u, 0x29438b76u, 0xc623cbdcu, 0xfcedb668u, 0xf1e4b863u,
    0xdc31d7cau, 0x85634210u, 0x22971340u, 0x11c68420u, 0x244a857du,
    0x3dbbd2f8u, 0x32f9ae11u, 0xa129c76du, 0x2f9e1d4bu, 0x30b2dcf3u,
    0x52860decu, 0xe3c177d0u, 0x16b32b6cu, 0xb970a999u, 0x489411fau,
    0x64e94722u, 0x8cfca8c4u, 0x3ff0a01au, 0x2c7d56d8u, 0x903322efu,
    0x4e4987c7u, 0xd138d9c1u, 0xa2ca8cfeu, 0x0bd49836u, 0x81f5a6cfu,
    0xde7aa528u, 0x8eb7da26u, 0xbfad3fa4u, 0x9d3a2ce4u, 0x9278500du,
    0xcc5f6a9bu, 0x467e5462u, 0x138df6c2u, 0xb8d890e8u, 0xf7392e5eu,
    0xafc382f5u, 0x805d9fbeu, 0x93d0697cu, 0x2dd56fa9u, 0x1225cfb3u,
    0x99acc83bu, 0x7d1810a7u, 0x639ce86eu, 0xbb3bdb7bu, 0x7826cd09u,
    0x18596ef4u, 0xb79aec01u, 0x9a4f83a8u, 0x6e95e665u, 0xe6ffaa7eu,
    0xcfbc2108u, 0xe815efe6u, 0x9be7bad9u, 0x366f4aceu, 0x099fead4u,
    0x7cb029d6u, 0xb2a431afu, 0x233f2a31u, 0x94a5c630u, 0x66a235c0u,
    0xbc4e7437u, 0xca82fca6u, 0xd090e0b0u, 0xd8a73315u, 0x9804f14au,
    0xdaec41f7u, 0x50cd7f0eu, 0xf691172fu, 0xd64d768du, 0xb0ef434du,
    0x4daacc54u, 0x0496e4dfu, 0xb5d19ee3u, 0x886a4c1bu, 0x1f2cc1b8u,
    0x5165467fu, 0xea5e9d04u, 0x358c015du, 0x7487fa73u, 0x410bfb2eu,
    0x1d67b35au, 0xd2db9252u, 0x5610e933u, 0x47d66d13u, 0x61d79a8cu,
    0x0ca1377au, 0x14f8598eu, 0x3c13eb89u, 0x27a9ceeeu, 0xc961b735u,
    0xe51ce1edu, 0xb1477a3cu, 0xdfd29c59u, 0x73f2553fu, 0xce141879u,
    0x37c773bfu, 0xcdf753eau, 0xaafd5f5bu, 0x6f3ddf14u, 0xdb447886u,
    0xf3afca81u, 0xc468b93eu, 0x3424382cu, 0x40a3c25fu, 0xc31d1672u,
    0x25e2bc0cu, 0x493c288bu, 0x950dff41u, 0x01a83971u, 0xb30c08deu,
    0xe4b4d89cu, 0xc1566490u, 0x84cb7b61u, 0xb632d570u, 0x5c6c4874u,
    0x57b8d042u,
};

template <int N> class WAesGen final : public Aes {
private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };
  alignas(16) uint32_t m_w[Nb * (Nr + 1)];
  alignas(16) uint32_t m_dw[Nb * (Nr + 1)];
  alignas(16) uint8_t m_iv[16] = {};

  static uint32_t load32LE(const uint8_t *p) noexcept {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
  }

  static void store32LE(uint8_t *p, uint32_t value) noexcept {
    p[0] = static_cast<uint8_t>(value);
    p[1] = static_cast<uint8_t>(value >> 8);
    p[2] = static_cast<uint8_t>(value >> 16);
    p[3] = static_cast<uint8_t>(value >> 24);
  }

  static uint64_t load64BE(const uint8_t *p) noexcept {
    return (static_cast<uint64_t>(p[0]) << 56) |
           (static_cast<uint64_t>(p[1]) << 48) |
           (static_cast<uint64_t>(p[2]) << 40) |
           (static_cast<uint64_t>(p[3]) << 32) |
           (static_cast<uint64_t>(p[4]) << 24) |
           (static_cast<uint64_t>(p[5]) << 16) |
           (static_cast<uint64_t>(p[6]) << 8) | static_cast<uint64_t>(p[7]);
  }

  static uint32_t byteSwap32(uint32_t value) noexcept {
    return (value << 24) | ((value & 0x0000ff00u) << 8) |
           ((value & 0x00ff0000u) >> 8) | (value >> 24);
  }

  static uint32_t invMixCol(uint32_t col) noexcept {
    const uint8_t b0 = col & 0xff;
    const uint8_t b1 = (col >> 8) & 0xff;
    const uint8_t b2 = (col >> 16) & 0xff;
    const uint8_t b3 = col >> 24;
    return Td0[g_sBox[b0]] ^ Td3[g_sBox[b1]] ^ Td2[g_sBox[b2]] ^
           Td1[g_sBox[b3]];
  }

  WAesGen(const void *key, size_t keyLength, const void *iv, size_t ivLength,
          Padding padding)
      : Aes(padding) {
    if (keyLength < 4 * Nk) {
      uint8_t tk[4 * Nk] = {}; // key padding zero
      memcpy(tk, key, keyLength);

      keyExpansion(tk);
    } else {
      keyExpansion(reinterpret_cast<const uint8_t *>(key));
    }

    if (iv) { // iv padding zero
      m_mode = Mode::CBC;
      memcpy(m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  void keyExpansion(const uint8_t *key) {
    static const uint8_t rc[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

    auto subWord = [](uint32_t word) {
      return static_cast<uint32_t>(g_sBox[word & 0xff]) |
             (static_cast<uint32_t>(g_sBox[(word >> 8) & 0xff]) << 8) |
             (static_cast<uint32_t>(g_sBox[(word >> 16) & 0xff]) << 16) |
             (static_cast<uint32_t>(g_sBox[word >> 24]) << 24);
    };

    for (uint8_t i = 0; i < Nk; ++i) {
      m_w[i] = load32LE(key + 4 * i);
    }

    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
      m_w[i] = m_w[i - 1];
      if (0 == i % Nk) {
        m_w[i] = (m_w[i] >> 8) | (m_w[i] << 24); // rot word
        m_w[i] = subWord(m_w[i]);
        m_w[i] ^= rc[i / Nk];
      } else if (8 == Nk && 4 == i % Nk) {
        m_w[i] = subWord(m_w[i]);
      }
      m_w[i] ^= m_w[i - Nk];
    }

    // Build decryption round key schedule (equivalent inverse cipher, FIPS 197
    // §5.3.5)
    for (int i = 0; i < Nb; ++i)
      m_dw[i] = m_w[Nb * Nr + i];
    for (int r = 1; r < Nr; ++r)
      for (int i = 0; i < Nb; ++i)
        m_dw[Nb * r + i] = invMixCol(m_w[Nb * (Nr - r) + i]);
    for (int i = 0; i < Nb; ++i)
      m_dw[Nb * Nr + i] = m_w[i];
  }

  void cipherWords(uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3,
                   uint8_t *output) const {
    const uint32_t *rk = m_w;

    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];
#define WAES_GEN_ENCRYPT_ROUND(keyOffset)                                      \
  do {                                                                         \
    const uint32_t t0 = Te0[s0 & 0xff] ^ Te3[(s1 >> 8) & 0xff] ^               \
                        Te2[(s2 >> 16) & 0xff] ^ Te1[s3 >> 24] ^               \
                        rk[(keyOffset)];                                       \
    const uint32_t t1 = Te0[s1 & 0xff] ^ Te3[(s2 >> 8) & 0xff] ^               \
                        Te2[(s3 >> 16) & 0xff] ^ Te1[s0 >> 24] ^               \
                        rk[(keyOffset) + 1];                                   \
    const uint32_t t2 = Te0[s2 & 0xff] ^ Te3[(s3 >> 8) & 0xff] ^               \
                        Te2[(s0 >> 16) & 0xff] ^ Te1[s1 >> 24] ^               \
                        rk[(keyOffset) + 2];                                   \
    const uint32_t t3 = Te0[s3 & 0xff] ^ Te3[(s0 >> 8) & 0xff] ^               \
                        Te2[(s1 >> 16) & 0xff] ^ Te1[s2 >> 24] ^               \
                        rk[(keyOffset) + 3];                                   \
    s0 = t0;                                                                   \
    s1 = t1;                                                                   \
    s2 = t2;                                                                   \
    s3 = t3;                                                                   \
  } while (false)

    WAES_GEN_ENCRYPT_ROUND(4);
    WAES_GEN_ENCRYPT_ROUND(8);
    WAES_GEN_ENCRYPT_ROUND(12);
    WAES_GEN_ENCRYPT_ROUND(16);
    WAES_GEN_ENCRYPT_ROUND(20);
    WAES_GEN_ENCRYPT_ROUND(24);
    WAES_GEN_ENCRYPT_ROUND(28);
    WAES_GEN_ENCRYPT_ROUND(32);
    WAES_GEN_ENCRYPT_ROUND(36);
    if (Nr > 10) {
      WAES_GEN_ENCRYPT_ROUND(40);
      WAES_GEN_ENCRYPT_ROUND(44);
    }
    if (Nr > 12) {
      WAES_GEN_ENCRYPT_ROUND(48);
      WAES_GEN_ENCRYPT_ROUND(52);
    }
#undef WAES_GEN_ENCRYPT_ROUND
    rk = m_w + 4 * Nr;

    // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
    store32LE(output,
              (static_cast<uint32_t>(g_sBox[s0 & 0xff]) |
               (static_cast<uint32_t>(g_sBox[(s1 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_sBox[(s2 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_sBox[s3 >> 24]) << 24)) ^
                  rk[0]);
    store32LE(output + 4,
              (static_cast<uint32_t>(g_sBox[s1 & 0xff]) |
               (static_cast<uint32_t>(g_sBox[(s2 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_sBox[(s3 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_sBox[s0 >> 24]) << 24)) ^
                  rk[1]);
    store32LE(output + 8,
              (static_cast<uint32_t>(g_sBox[s2 & 0xff]) |
               (static_cast<uint32_t>(g_sBox[(s3 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_sBox[(s0 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_sBox[s1 >> 24]) << 24)) ^
                  rk[2]);
    store32LE(output + 12,
              (static_cast<uint32_t>(g_sBox[s3 & 0xff]) |
               (static_cast<uint32_t>(g_sBox[(s0 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_sBox[(s1 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_sBox[s2 >> 24]) << 24)) ^
                  rk[3]);
  }

  void cipher(const uint8_t *input, uint8_t *output) const {
    cipherWords(load32LE(input), load32LE(input + 4), load32LE(input + 8),
                load32LE(input + 12), output);
  }

  void cipherXor(const uint8_t *input, const uint8_t *xorBlock,
                 uint8_t *output) const {
    cipherWords(load32LE(input) ^ load32LE(xorBlock),
                load32LE(input + 4) ^ load32LE(xorBlock + 4),
                load32LE(input + 8) ^ load32LE(xorBlock + 8),
                load32LE(input + 12) ^ load32LE(xorBlock + 12), output);
  }

  void invCipher(const uint8_t *input, uint8_t *output) const {
    const uint32_t *dk = m_dw;

    uint32_t s0 = load32LE(input) ^ dk[0];
    uint32_t s1 = load32LE(input + 4) ^ dk[1];
    uint32_t s2 = load32LE(input + 8) ^ dk[2];
    uint32_t s3 = load32LE(input + 12) ^ dk[3];
#define WAES_GEN_DECRYPT_ROUND(keyOffset)                                      \
  do {                                                                         \
    const uint32_t t0 = Td0[s0 & 0xff] ^ Td3[(s3 >> 8) & 0xff] ^               \
                        Td2[(s2 >> 16) & 0xff] ^ Td1[s1 >> 24] ^               \
                        dk[(keyOffset)];                                       \
    const uint32_t t1 = Td0[s1 & 0xff] ^ Td3[(s0 >> 8) & 0xff] ^               \
                        Td2[(s3 >> 16) & 0xff] ^ Td1[s2 >> 24] ^               \
                        dk[(keyOffset) + 1];                                   \
    const uint32_t t2 = Td0[s2 & 0xff] ^ Td3[(s1 >> 8) & 0xff] ^               \
                        Td2[(s0 >> 16) & 0xff] ^ Td1[s3 >> 24] ^               \
                        dk[(keyOffset) + 2];                                   \
    const uint32_t t3 = Td0[s3 & 0xff] ^ Td3[(s2 >> 8) & 0xff] ^               \
                        Td2[(s1 >> 16) & 0xff] ^ Td1[s0 >> 24] ^               \
                        dk[(keyOffset) + 3];                                   \
    s0 = t0;                                                                   \
    s1 = t1;                                                                   \
    s2 = t2;                                                                   \
    s3 = t3;                                                                   \
  } while (false)

    WAES_GEN_DECRYPT_ROUND(4);
    WAES_GEN_DECRYPT_ROUND(8);
    WAES_GEN_DECRYPT_ROUND(12);
    WAES_GEN_DECRYPT_ROUND(16);
    WAES_GEN_DECRYPT_ROUND(20);
    WAES_GEN_DECRYPT_ROUND(24);
    WAES_GEN_DECRYPT_ROUND(28);
    WAES_GEN_DECRYPT_ROUND(32);
    WAES_GEN_DECRYPT_ROUND(36);
    if (Nr > 10) {
      WAES_GEN_DECRYPT_ROUND(40);
      WAES_GEN_DECRYPT_ROUND(44);
    }
    if (Nr > 12) {
      WAES_GEN_DECRYPT_ROUND(48);
      WAES_GEN_DECRYPT_ROUND(52);
    }
#undef WAES_GEN_DECRYPT_ROUND
    dk = m_dw + 4 * Nr;

    // Final round: InvSubBytes + InvShiftRows + AddRoundKey (no InvMixColumns)
    store32LE(output,
              (static_cast<uint32_t>(g_invSbox[s0 & 0xff]) |
               (static_cast<uint32_t>(g_invSbox[(s3 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_invSbox[(s2 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_invSbox[s1 >> 24]) << 24)) ^
                  dk[0]);
    store32LE(output + 4,
              (static_cast<uint32_t>(g_invSbox[s1 & 0xff]) |
               (static_cast<uint32_t>(g_invSbox[(s0 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_invSbox[(s3 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_invSbox[s2 >> 24]) << 24)) ^
                  dk[1]);
    store32LE(output + 8,
              (static_cast<uint32_t>(g_invSbox[s2 & 0xff]) |
               (static_cast<uint32_t>(g_invSbox[(s1 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_invSbox[(s0 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_invSbox[s3 >> 24]) << 24)) ^
                  dk[2]);
    store32LE(output + 12,
              (static_cast<uint32_t>(g_invSbox[s3 & 0xff]) |
               (static_cast<uint32_t>(g_invSbox[(s2 >> 8) & 0xff]) << 8) |
               (static_cast<uint32_t>(g_invSbox[(s1 >> 16) & 0xff]) << 16) |
               (static_cast<uint32_t>(g_invSbox[s0 >> 24]) << 24)) ^
                  dk[3]);
  }

  virtual bool cipherECB(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t *>(in);
    auto output = reinterpret_cast<uint8_t *>(out);
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      cipher(input, output);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      alignas(16) uint8_t block[16];
      auto pad =
          Padding::Zeros == m_padding ? 0 : 16 - static_cast<uint8_t>(len);
      memcpy(block, input, len);
      memset(block + len, pad, 16 - len);

      cipher(block, output);
    }

    return true;
  }

  virtual bool cipherCBC(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t *>(in);
    auto output = reinterpret_cast<uint8_t *>(out);
    const auto *piv = m_iv;
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      cipherXor(input, piv, output);
      piv = output;
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      alignas(16) uint8_t block[16];
      auto pad =
          Padding::Zeros == m_padding ? 0 : 16 - static_cast<uint8_t>(len);
      memcpy(block, input, len);
      memset(block + len, pad, 16 - len);
      cipherXor(block, piv, output);
    }

    return true;
  }

  virtual bool cipherCTR(const void *in, size_t inLength, void *out,
                         size_t &outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    // Keep the first 64 bits fixed and increment only the final 64 bits. This
    // matches the AES-NI/VAES backends and the Intel-style counter layout.
    uint64_t ctr_lo = load64BE(m_iv + 8);
    const uint32_t ctr0 = load32LE(m_iv);
    const uint32_t ctr1 = load32LE(m_iv + 4);

    alignas(16) uint8_t state[4 * Nb];
    int64_t len = inLength;
    auto input = reinterpret_cast<const uint8_t *>(in);
    auto output = reinterpret_cast<uint8_t *>(out);

    for (; len > 0; len -= 16, input += 16, output += 16) {
      cipherWords(ctr0, ctr1, byteSwap32(static_cast<uint32_t>(ctr_lo >> 32)),
                  byteSwap32(static_cast<uint32_t>(ctr_lo)), state);

      if (len >= 16) {
        store32LE(output, load32LE(state) ^ load32LE(input));
        store32LE(output + 4, load32LE(state + 4) ^ load32LE(input + 4));
        store32LE(output + 8, load32LE(state + 8) ^ load32LE(input + 8));
        store32LE(output + 12, load32LE(state + 12) ^ load32LE(input + 12));
      } else {
        for (int64_t i = 0; i < len; ++i) {
          output[i] = state[i] ^ input[i];
        }
      }

      ++ctr_lo;
    }

    return true;
  }

  virtual bool invCipherECB(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!inLength || inLength % 16) { // invalid data length
      return false;
    }

    alignas(16) uint8_t state[4 * Nb];
    const auto *inputBase = reinterpret_cast<const uint8_t *>(in);
    auto input = inputBase + inLength - 16;

    // sum padding length
    invCipher(input, state);

    uint8_t padLen;
    if (Padding::Zeros == m_padding) {
      padLen = 0;
      for (int8_t i = 15; i >= 0; --i) {
        if (state[i]) {
          break;
        }
        ++padLen;
      }
    } else {
      if (!isValidPKCS7Padding(state)) {
        return false;
      }
      padLen = state[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    auto *outputBase = reinterpret_cast<uint8_t *>(out);
    auto output = outputBase + inLength - 16;
    memcpy(output, state, endLen);

    for (size_t offset = inLength - 16; offset != 0;) {
      offset -= 16;
      invCipher(inputBase + offset, outputBase + offset);
    }

    return true;
  }

  virtual bool invCipherCBC(const void *in, size_t inLength, void *out,
                            size_t &outLength) const override {
    if (!inLength || inLength % 16) { // invalid data length
      return false;
    }

    alignas(16) uint8_t state[4 * Nb];
    const auto *inputBase = reinterpret_cast<const uint8_t *>(in);
    auto input = inputBase + inLength - 16;

    // sum padding length
    invCipher(input, state);

    const auto *piv = inputBase != input ? input - 16 : m_iv;
    store32LE(state, load32LE(state) ^ load32LE(piv));
    store32LE(state + 4, load32LE(state + 4) ^ load32LE(piv + 4));
    store32LE(state + 8, load32LE(state + 8) ^ load32LE(piv + 8));
    store32LE(state + 12, load32LE(state + 12) ^ load32LE(piv + 12));

    uint8_t padLen;
    if (Padding::Zeros == m_padding) {
      padLen = 0;
      for (int8_t i = 15; i >= 0; --i) {
        if (state[i]) {
          break;
        }
        ++padLen;
      }
    } else {
      if (!isValidPKCS7Padding(state)) {
        return false;
      }
      padLen = state[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    auto *outputBase = reinterpret_cast<uint8_t *>(out);
    auto output = outputBase + inLength - 16;
    memcpy(output, state, endLen);

    for (size_t offset = inLength - 16; offset != 0;) {
      offset -= 16;
      output = outputBase + offset;
      invCipher(inputBase + offset, output);

      piv = offset ? inputBase + offset - 16 : m_iv;
      store32LE(output, load32LE(output) ^ load32LE(piv));
      store32LE(output + 4, load32LE(output + 4) ^ load32LE(piv + 4));
      store32LE(output + 8, load32LE(output + 8) ^ load32LE(piv + 8));
      store32LE(output + 12, load32LE(output + 12) ^ load32LE(piv + 12));
    }

    return true;
  }

  virtual void setIVImpl(const void *iv, size_t length) override {
    memset(m_iv, 0, sizeof(m_iv));
    memcpy(m_iv, iv, length > 16 ? 16 : length);
  }

  virtual void getIVImpl(void *iv) const override { memcpy(iv, m_iv, 16); }

  virtual Ptr Clone() const override { return Ptr(new WAesGen<N>(*this)); }

  friend Ptr WAes::Create<N>(const void *, size_t, const void *, size_t,
                             Padding);
  friend Ptr WAes::Create<N>(Backend, const void *, size_t, const void *,
                             size_t, Padding);
};

} // namespace detail

// Get name for a specific backend
inline const char *GetImplName(Backend b) {
  switch (b) {
  case Backend::Generic:
    return "Generic";
#if defined(WAES_ARMV8)
  case Backend::ArmV8:
    return "ARM-V8";
#elif defined(WAES_X86_SIMD)
  case Backend::AesNi:
    return "AES-NI";
#if defined(WAES_VAES)
  case Backend::VAES:
    return "VAES";
#endif
#if defined(WAES_VAES512)
  case Backend::VAES512:
    return "VAES512";
#endif
#endif
  default:
    break;
  }
  return "Auto";
}

// Lists every backend present in this binary, regardless of whether the
// current CPU and OS can execute it (excludes Auto).
inline std::vector<Backend> CompiledBackends() {
  return {
      Backend::Generic,
#if defined(WAES_ARMV8)
      Backend::ArmV8,
#elif defined(WAES_X86_SIMD)
      Backend::AesNi,
#if defined(WAES_VAES)
      Backend::VAES,
#endif
#if defined(WAES_VAES512)
      Backend::VAES512,
#endif
#endif
  };
}

// Returns whether a compiled backend is executable on the current CPU and OS.
inline bool IsBackendAvailable(Backend backend) {
  switch (backend) {
  case Backend::Auto:
  case Backend::Generic:
    return true;
#if defined(WAES_ARMV8)
  case Backend::ArmV8:
    // This backend is only compiled when the compiler target guarantees the
    // crypto extension (or the user explicitly defines WAES_ASSUME_ARM_CRYPTO).
    return true;
#elif defined(WAES_X86_SIMD)
  case Backend::AesNi:
    return detail::getX86Capabilities().aesNi;
#if defined(WAES_VAES)
  case Backend::VAES:
    return detail::getX86Capabilities().vaes;
#endif
#if defined(WAES_VAES512)
  case Backend::VAES512:
    return detail::getX86Capabilities().vaes512;
#endif
#endif
  default:
    return false;
  }
}

// Lists compiled backends that are executable on the current machine.
inline std::vector<Backend> AvailableBackends() {
  std::vector<Backend> available;
  for (auto backend : CompiledBackends()) {
    if (IsBackendAvailable(backend)) {
      available.push_back(backend);
    }
  }
  return available;
}

// Get name for auto-selected backend
inline const char *GetImplName() {
#if defined(WAES_ARMV8)
  return "ARM-V8";
#else
#if defined(WAES_X86_SIMD)
  switch (detail::getX86ImplType()) {
  case detail::X86ImplType::VAES512:
    return "VAES512";
  case detail::X86ImplType::VAES:
    return "VAES";
  case detail::X86ImplType::AES_NI:
    return "AES-NI";
  case detail::X86ImplType::Generic:
  default:
    break;
  }
#endif
  return "Generic";
#endif
}

template <int bit>
Ptr Create(const void *key, size_t keyLength, const void *iv, size_t ivLength,
           Padding padding) {
  static_assert(bit == 128 || bit == 192 || bit == 256,
                "Aes key only supports bit = 128, 192, or 256.");
#if defined(WAES_ARMV8)
  return Ptr(new detail::WAesArmV8<bit>(key, keyLength, iv, ivLength, padding));
#else
#if defined(WAES_X86_SIMD)
  switch (detail::getX86ImplType()) {
#if defined(WAES_VAES512)
  case detail::X86ImplType::VAES512:
    return Ptr(
        new detail::WAesV512<bit>(key, keyLength, iv, ivLength, padding));
#endif
#if defined(WAES_VAES)
  case detail::X86ImplType::VAES:
    return Ptr(new detail::WAesV<bit>(key, keyLength, iv, ivLength, padding));
#endif
  case detail::X86ImplType::AES_NI:
    return Ptr(new detail::WAesNi<bit>(key, keyLength, iv, ivLength, padding));
  case detail::X86ImplType::Generic:
  default:
    break;
  }
#endif
  return Ptr(new detail::WAesGen<bit>(key, keyLength, iv, ivLength, padding));
#endif
}

template <int bit>
Ptr Create(Backend backend, const void *key, size_t keyLength, const void *iv,
           size_t ivLength, Padding padding) {
  static_assert(bit == 128 || bit == 192 || bit == 256,
                "Aes key only supports bit = 128, 192, or 256.");
  if (backend != Backend::Auto && !IsBackendAvailable(backend)) {
    return nullptr;
  }
  switch (backend) {
  case Backend::Generic:
    return Ptr(new detail::WAesGen<bit>(key, keyLength, iv, ivLength, padding));
#if defined(WAES_ARMV8)
  case Backend::ArmV8:
    return Ptr(
        new detail::WAesArmV8<bit>(key, keyLength, iv, ivLength, padding));
#elif defined(WAES_X86_SIMD)
  case Backend::AesNi:
    return Ptr(new detail::WAesNi<bit>(key, keyLength, iv, ivLength, padding));
#if defined(WAES_VAES)
  case Backend::VAES:
    return Ptr(new detail::WAesV<bit>(key, keyLength, iv, ivLength, padding));
#endif
#if defined(WAES_VAES512)
  case Backend::VAES512:
    return Ptr(
        new detail::WAesV512<bit>(key, keyLength, iv, ivLength, padding));
#endif
#endif
  default:
    return Create<bit>(key, keyLength, iv, ivLength, padding);
  }
}

} // namespace WAes
