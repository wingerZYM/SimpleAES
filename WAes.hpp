#pragma once

#if defined(__aarch64__) || defined(_M_ARM64)
#define WAES_ARMV8
#else
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || \
    defined(_M_IX86)
#define WAES_X86_SIMD
#if (defined(_MSC_VER) && !defined(__clang__)) || \
    (defined(__AVX2__) && defined(__VAES__))
#define WAES_VAES
#endif
#if (defined(_MSC_VER) && !defined(__clang__)) || \
    (defined(__AVX512F__) && defined(__AVX512VL__) && defined(__VAES__))
#define WAES_VAES512
#endif
#endif
#endif

#include <cstdint>
#include <cstring>
#include <memory>
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

template <int>
Ptr Create(const void* key,
           size_t keyLength,
           const void* iv = nullptr,
           size_t ivLength = 16,
           Padding padding = Padding::PKCS7);

namespace detail {

template <int>
struct aesN;

template <>
struct aesN<128> {
  enum { Nk = 4, Nr = 10 };
};
template <>
struct aesN<192> {
  enum { Nk = 6, Nr = 12 };
};
template <>
struct aesN<256> {
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

  bool isValidPKCS7Padding(const void* state) const {
    auto pos = reinterpret_cast<const uint8_t*>(state);
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

  virtual bool cipherECB(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const = 0;
  virtual bool cipherCBC(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const = 0;
  virtual bool cipherCTR(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const = 0;

  virtual bool invCipherECB(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const = 0;
  virtual bool invCipherCBC(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const = 0;

 private:
  virtual void setIVImpl(const void* iv, size_t length) = 0;
  virtual void getIVImpl(void* iv) const = 0;

  class tempIVScope {
   private:
    Aes* m_pAes;
    uint8_t m_iv[16];
    Mode m_mode;

   public:
    tempIVScope(Aes* aes, const void* iv, size_t length, bool is_ctr = false)
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

    tempIVScope(const tempIVScope&) = delete;
    tempIVScope& operator=(const tempIVScope&) = delete;
    tempIVScope(tempIVScope&&) = delete;
    tempIVScope& operator=(tempIVScope&&) = delete;
  };

 public:
  virtual ~Aes() = default;

  auto ScopeIV(const void* iv, size_t length) {
    return tempIVScope(this, iv, length, false);
  }

  auto ScopeCounter(const void* counter, size_t length) {
    return tempIVScope(this, counter, length, true);
  }

  template <typename Func>
  auto WithScopeIV(const void* iv, size_t length, Func&& func)
      -> decltype(func()) {
    tempIVScope scope(this, iv, length, false);
    return func();
  }

  template <typename Func>
  auto WithScopeCounter(const void* counter, size_t length, Func&& func)
      -> decltype(func()) {
    tempIVScope scope(this, counter, length, true);
    return func();
  }

  size_t SumCipherLength(size_t nInLen) const {
    constexpr size_t blockSize = Nb * 4;
    if (m_mode == Mode::CTR) {
      // In CTR mode, the length is not padded.
      return nInLen;
    } else if (m_padding == Padding::Zeros) {
      return ((nInLen + blockSize - 1) / blockSize) * blockSize;
    } else {  // PKCS7
      return ((nInLen / blockSize) + 1) * blockSize;
    }
  }

  // Sets the initialization vector value when in CBC mode.
  // The maximum length is 16 byte, if not enough padding zero.
  void SetIV(const void* iv, size_t length) {
    m_mode = Mode::CBC;
    setIVImpl(iv, length);
  }

  // Sets the counter value when in CTR mode.
  // The maximum length is 16 byte, if not enough padding zero.
  void SetCounter(const void* counter, size_t length) {
    m_mode = Mode::CTR;
    setIVImpl(counter, length);
  }

  // Set CTR mode for FIPS compliance.
  void SetCounter(uint64_t iv, uint32_t nonce, uint32_t counter = 0) {
    uint8_t counterData[16] = {};
    *reinterpret_cast<uint64_t*>(counterData) = iv;
    *reinterpret_cast<uint32_t*>(counterData + 8) = nonce;
    *reinterpret_cast<uint32_t*>(counterData + 12) = counter;
    SetCounter(counterData, sizeof(counterData));
  }

  bool Cipher(const void* in,
              size_t inLength,
              void* out,
              size_t& outLength) const {
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

  template <typename I>
  std::vector<uint8_t> Cipher(const I& in) const {
    auto nNeedLen = SumCipherLength(in.size());
    std::vector<uint8_t> out(nNeedLen);
    Cipher(in.data(), in.size(), out.data(), nNeedLen);
    return out;
  }

  bool InvCipher(const void* in,
                 size_t inLength,
                 void* out,
                 size_t& outLength) const {
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

  template <typename I, typename O>
  bool InvCipher(const I& in, O& out) const {
    size_t outLength = in.size();
    out.resize(outLength);
    if (!InvCipher(in.data(), in.size(), out.data(), outLength)) {
      out.clear();
      return false;
    }
    out.resize(outLength);
    return true;
  }
};

#if defined(WAES_ARMV8)

#define _vslliq_u8(a, imm) vextq_u8(vdupq_n_u8(0), a, (16 - imm))

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif  // !__has_builtin

#if __has_builtin(__builtin_shufflevector)

#define _vshuffle_pi32_u8(a, imm)                                          \
  __extension__({                                                          \
    int32x4_t in = vreinterpretq_s32_u8(a);                                \
    int32x4_t out =                                                        \
        __builtin_shufflevector(in, in, (imm) & (0x3), ((imm) >> 2) & 0x3, \
                                ((imm) >> 4) & 0x3, ((imm) >> 6) & 0x3);   \
    vreinterpretq_u8_s32(out);                                             \
  })

#define _vshuffle_pi64_u8(a, b, imm)                               \
  vreinterpretq_u8_s64(__builtin_shufflevector(                    \
      vreinterpretq_s64_u8(a), vreinterpretq_s64_u8(b), imm & 0x1, \
      ((imm & 0x2) >> 1) + 2))

#elif __has_builtin(__builtin_shuffle)

#define _shuffle(type, a, b, ...) \
  __extension__({                 \
    type t = {__VA_ARGS__};       \
    __builtin_shuffle(a, b, t);   \
  })

#define _vshuffle_pi32_u8(a, imm)                                      \
  __extension__({                                                      \
    int32x4_t in = vreinterpretq_s32_u8(a);                            \
    int32x4_t out =                                                    \
        _shuffle(int32x4_t, in, in, (imm) & (0x3), ((imm) >> 2) & 0x3, \
                 ((imm) >> 4) & 0x3, ((imm) >> 6) & 0x3);              \
    vreinterpretq_u8_s32(out);                                         \
  })

#define _vshuffle_pi64_u8(a, b, imm)                                \
  vreinterpretq_u8_s64(_shuffle(int64x2_t, vreinterpretq_s64_u8(a), \
                                vreinterpretq_s64_u8(b), imm & 0x1, \
                                ((imm & 0x2) >> 1) + 2))
#else

inline uint8x16_t _vshuffle_pi32_u8(uint8x16_t a, const int imm) {
  switch (imm) {  // imm only use 0x55, 0xaa, 0xff.
    case 0x55:
      return vreinterpretq_u8_s32(vdupq_laneq_s32(vreinterpretq_s32_u8(a), 1));
    case 0xaa:
      return vreinterpretq_u8_s32(vdupq_laneq_s32(vreinterpretq_s32_u8(a), 2));
    case 0xff:
      return vreinterpretq_u8_s32(vdupq_laneq_s32(vreinterpretq_s32_u8(a), 3));
  }
  return a;
}

#define _vshuffle_pi64_u8(a, b, imm)                                   \
  vreinterpretq_u8_s64(vcombine_s64(                                   \
      vcreate_s64(vgetq_lane_s64(vreinterpretq_s64_u8(a), imm & 0x1)), \
      vcreate_s64(vgetq_lane_s64(vreinterpretq_s64_u8(b), (imm & 0x2) >> 1))))

#endif

inline uint8x16_t _vaeskeygenassist_u8(uint8x16_t a, const uint8_t rcon) {
  a = vaeseq_u8(a, vdupq_n_u8(0));
#if defined(_MSC_VER)
  auto* u8 = reinterpret_cast<uint8_t*>(&a);
  uint8x16_t dest = {
      static_cast<uint64_t>(u8[0x4]) | (static_cast<uint64_t>(u8[0x1]) << 8) |
          (static_cast<uint64_t>(u8[0xE]) << 16) |
          (static_cast<uint64_t>(u8[0xB]) << 24) |
          (static_cast<uint64_t>(u8[0x1]) << 32) |
          (static_cast<uint64_t>(u8[0xE]) << 40) |
          (static_cast<uint64_t>(u8[0xB]) << 48) |
          (static_cast<uint64_t>(u8[0x4]) << 56),
      static_cast<uint64_t>(u8[0xC]) | (static_cast<uint64_t>(u8[0x9]) << 8) |
          (static_cast<uint64_t>(u8[0x6]) << 16) |
          (static_cast<uint64_t>(u8[0x3]) << 24) |
          (static_cast<uint64_t>(u8[0x9]) << 32) |
          (static_cast<uint64_t>(u8[0x6]) << 40) |
          (static_cast<uint64_t>(u8[0x3]) << 48) |
          (static_cast<uint64_t>(u8[0xC]) << 56)};
  uint8x16_t r = {static_cast<uint64_t>(rcon) << 32, static_cast<uint64_t>(rcon)
                                                         << 32};
#else
  uint8x16_t dest = {
      // Undo ShiftRows step from AESE and extract X1 and X3
      a[0x4], a[0x1], a[0xE], a[0xB],  // SubBytes(X1)
      a[0x1], a[0xE], a[0xB], a[0x4],  // ROT(SubBytes(X1))
      a[0xC], a[0x9], a[0x6], a[0x3],  // SubBytes(X3)
      a[0x9], a[0x6], a[0x3], a[0xC],  // ROT(SubBytes(X3))
  };
  uint8x16_t r = {
      0, 0, 0, 0, rcon, 0, 0, 0, 0, 0, 0, 0, rcon, 0, 0, 0,
  };
#endif  // _MSC_VER

  return veorq_u8(dest, r);
}

template <int>
inline void keyExpansion(const uint8_t* key, uint8x16_t* w);

template <>
inline void keyExpansion<128>(const uint8_t* key, uint8x16_t* w) {
  auto assist = [](uint8x16_t a, const uint8x16_t& b) {
    a = veorq_u8(a, _vslliq_u8(a, 4));
    a = veorq_u8(a, _vslliq_u8(a, 4));
    a = veorq_u8(a, _vslliq_u8(a, 4));
    a = veorq_u8(a, _vshuffle_pi32_u8(b, 0xff));
    return a;
  };

  w[0] = vld1q_u8(key);
  w[1] = assist(w[0], _vaeskeygenassist_u8(w[0], 0x01));
  w[2] = assist(w[1], _vaeskeygenassist_u8(w[1], 0x02));
  w[3] = assist(w[2], _vaeskeygenassist_u8(w[2], 0x04));
  w[4] = assist(w[3], _vaeskeygenassist_u8(w[3], 0x08));
  w[5] = assist(w[4], _vaeskeygenassist_u8(w[4], 0x10));
  w[6] = assist(w[5], _vaeskeygenassist_u8(w[5], 0x20));
  w[7] = assist(w[6], _vaeskeygenassist_u8(w[6], 0x40));
  w[8] = assist(w[7], _vaeskeygenassist_u8(w[7], 0x80));
  w[9] = assist(w[8], _vaeskeygenassist_u8(w[8], 0x1b));
  w[10] = assist(w[9], _vaeskeygenassist_u8(w[9], 0x36));
}

template <>
inline void keyExpansion<192>(const uint8_t* key, uint8x16_t* w) {
  auto assist = [](uint8x16_t& a, uint8x16_t& b, const uint8x16_t& c) {
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vshuffle_pi32_u8(c, 0x55));
    b = veorq_u8(b, _vslliq_u8(b, 0x4));
    b = veorq_u8(b, _vshuffle_pi32_u8(a, 0xff));
  };

  uint8x16_t a, b;
  w[0] = a = vld1q_u8(key);
  w[1] = b = vld1q_u8(key + 16);

  assist(a, b, _vaeskeygenassist_u8(b, 0x1));
  w[1] = _vshuffle_pi64_u8(w[1], a, 0);
  w[2] = _vshuffle_pi64_u8(a, b, 1);

  assist(a, b, _vaeskeygenassist_u8(b, 0x2));
  w[3] = a;
  w[4] = b;

  assist(a, b, _vaeskeygenassist_u8(b, 0x4));
  w[4] = _vshuffle_pi64_u8(w[4], a, 0);
  w[5] = _vshuffle_pi64_u8(a, b, 1);

  assist(a, b, _vaeskeygenassist_u8(b, 0x8));
  w[6] = a;
  w[7] = b;

  assist(a, b, _vaeskeygenassist_u8(b, 0x10));
  w[7] = _vshuffle_pi64_u8(w[7], a, 0);
  w[8] = _vshuffle_pi64_u8(a, b, 1);

  assist(a, b, _vaeskeygenassist_u8(b, 0x20));
  w[9] = a;
  w[10] = b;

  assist(a, b, _vaeskeygenassist_u8(b, 0x40));
  w[10] = _vshuffle_pi64_u8(w[10], a, 0);
  w[11] = _vshuffle_pi64_u8(a, b, 1);

  assist(a, b, _vaeskeygenassist_u8(b, 0x80));
  w[12] = a;
}

template <>
inline void keyExpansion<256>(const uint8_t* key, uint8x16_t* w) {
  auto assistL = [](uint8x16_t a, const uint8x16_t& b) {
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vslliq_u8(a, 0x4));
    a = veorq_u8(a, _vshuffle_pi32_u8(b, 0xff));
    return a;
  };
  auto assistH = [](const uint8x16_t& a, uint8x16_t c) {
    c = veorq_u8(c, _vslliq_u8(c, 0x4));
    c = veorq_u8(c, _vslliq_u8(c, 0x4));
    c = veorq_u8(c, _vslliq_u8(c, 0x4));
    c = veorq_u8(c, _vshuffle_pi32_u8(_vaeskeygenassist_u8(a, 0x0), 0xaa));
    return c;
  };

  w[0] = vld1q_u8(key);
  w[1] = vld1q_u8(key + 16);
  w[2] = assistL(w[0], _vaeskeygenassist_u8(w[1], 0x1));
  w[3] = assistH(w[2], w[1]);
  w[4] = assistL(w[2], _vaeskeygenassist_u8(w[3], 0x2));
  w[5] = assistH(w[4], w[3]);
  w[6] = assistL(w[4], _vaeskeygenassist_u8(w[5], 0x4));
  w[7] = assistH(w[6], w[5]);
  w[8] = assistL(w[6], _vaeskeygenassist_u8(w[7], 0x8));
  w[9] = assistH(w[8], w[7]);
  w[10] = assistL(w[8], _vaeskeygenassist_u8(w[9], 0x10));
  w[11] = assistH(w[10], w[9]);
  w[12] = assistL(w[10], _vaeskeygenassist_u8(w[11], 0x20));
  w[13] = assistH(w[12], w[11]);
  w[14] = assistL(w[12], _vaeskeygenassist_u8(w[13], 0x40));
}

template <int N>
class WAesArmV8 final : public Aes {
 private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };

  uint8x16_t m_w[Nr * 2];
  uint8x16_t m_iv = {};

  WAesArmV8(const void* key,
            size_t keyLength,
            const void* iv,
            size_t ivLength,
            Padding padding)
      : Aes(padding) {
    if (keyLength < 4 * Nk) {
      uint8_t tk[4 * Nk] = {};  // key padding zero
      memcpy(tk, key, keyLength);

      keyExpansion<N>(tk, m_w);
    } else {
      keyExpansion<N>(reinterpret_cast<const uint8_t*>(key), m_w);
    }

    // imc
    for (uint8_t i = Nr + 1; i < Nr * 2; ++i) {
      m_w[i] = vaesimcq_u8(m_w[Nr * 2 - i]);
    }

    if (iv) {  // iv padding zero
      m_mode = Mode::CBC;
      memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  void cipher(uint8x16_t& state) const {
    for (uint8_t r = 0; r < Nr - 1; ++r) {
      state = vaesmcq_u8(vaeseq_u8(state, m_w[r]));
    }
    state = veorq_u8(vaeseq_u8(state, m_w[Nr - 1]), m_w[Nr]);
  }

  void invCipher(uint8x16_t& state) const {
    for (uint8_t r = Nr; r < Nr * 2 - 1; ++r) {
      state = vaesimcq_u8(vaesdq_u8(state, m_w[r]));
    }
    state = veorq_u8(vaesdq_u8(state, m_w[Nr * 2 - 1]), m_w[0]);
  }

  virtual bool cipherECB(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    uint8x16_t state;
    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      cipher(state);
      vst1q_u8(output, state);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      state = vld1q_u8(input);
      auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<int>(len);
      memset(reinterpret_cast<uint8_t*>(&state) + len, pad, 16 - len);

      cipher(state);
      vst1q_u8(output, state);
    }

    return true;
  }

  virtual bool cipherCBC(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);

    auto state = m_iv;
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      state = veorq_u8(vld1q_u8(input), state);
      cipher(state);
      vst1q_u8(output, state);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      for (uint8_t i = 0; i < len; ++i) {
        reinterpret_cast<uint8_t*>(&state)[i] ^=
            reinterpret_cast<const uint8_t*>(input)[i];
      }
      if (Padding::PKCS7 == m_padding) {
        for (auto i = len; i < 16; ++i) {
          reinterpret_cast<uint8_t*>(&state)[i] ^= 16 - len;
        }
      }

      cipher(state);
      vst1q_u8(output, state);
    }

    return true;
  }

  virtual bool cipherCTR(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    static const uint64x2_t one = {0, 1};
    static const uint8x16_t bswap_epi64 = {
#if defined(_MSC_VER)
        0x0001020304050607ull, 0x08090a0b0c0d0e0full
#else
        7,  6,  5,  4,  3,  2, 1, 0, 15,
        14, 13, 12, 11, 10, 9, 8
#endif
    };
    auto counter = vreinterpretq_u64_u8(vqtbl1q_u8(m_iv, bswap_epi64));

    int64_t len = inLength / 16;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);
    for (int64_t i = 0; i < len; ++i, input += 16, output += 16) {
      auto state = vqtbl1q_u8(vreinterpretq_u8_u64(counter), bswap_epi64);
      cipher(state);
      vst1q_u8(output, veorq_u8(vld1q_u8(input), state));

      counter = vaddq_u64(counter, one);
    }

    int8_t endLen = inLength % 16;
    if (endLen) {
      auto state = vqtbl1q_u8(vreinterpretq_u8_u64(counter), bswap_epi64);
      cipher(state);
      for (int8_t i = 0; i < endLen; ++i) {
        reinterpret_cast<uint8_t*>(output)[i] =
            reinterpret_cast<const uint8_t*>(input)[i] ^
            reinterpret_cast<uint8_t*>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!inLength || inLength % 16) {
      // invalid data length
      return false;
    }

    auto len = static_cast<int64_t>(inLength - 16);
    auto input = reinterpret_cast<const uint8_t*>(in);

    // sum padding length
    auto state = vld1q_u8(input + len);
    invCipher(state);

    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t*>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t*>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    auto output = reinterpret_cast<uint8_t*>(out);
    memcpy(output + len, &state, endLen);

    for (int i = 0; i < len; i += 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      invCipher(state);
      vst1q_u8(output, state);
    }

    return true;
  }

  virtual bool invCipherCBC(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!inLength || inLength % 16) {
      // invalid data length
      return false;
    }

    auto len = static_cast<int64_t>(inLength - 16);
    auto input = reinterpret_cast<const uint8_t*>(in);

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
        if (reinterpret_cast<uint8_t*>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t*>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    auto output = reinterpret_cast<uint8_t*>(out);
    memcpy(output + len, &state, endLen);

    iv = m_iv;
    for (int i = 0; i < len; i += 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      invCipher(state);
      vst1q_u8(output, veorq_u8(state, iv));

      iv = vld1q_u8(input);
    }

    return true;
  }

  virtual void setIVImpl(const void* iv, size_t length) override {
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, iv, length > 16 ? 16 : length);
  }

  virtual void getIVImpl(void* iv) const override { memcpy(iv, &m_iv, 16); }

  template <int>
  friend Ptr WAes::Create(const void*, size_t, const void*, size_t, Padding);
};

#else
#if defined(WAES_X86_SIMD)

// x86 AES implementation types (for runtime CPU feature detection)
enum class X86ImplType {
  Generic = 0,
  AES_NI = 1,
  VAES = 2,
  VAES512 = 3,
};

inline const X86ImplType& getX86ImplType() {
  static const X86ImplType implType = [] {
    int i[4] = {};
#if defined(WAES_VAES) || defined(WAES_VAES512)
#if defined(_MSC_VER)
    __cpuid(i, 7);
#else
    __asm__ __volatile__("cpuid"
                         : "=a"(i[0]), "=b"(i[1]), "=c"(i[2]), "=d"(i[3])
                         : "a"(7), "c"(0));
#endif
    if (i[2] & 0x200) {
      if (i[1] & 0x10000) {
        return X86ImplType::VAES512;
      }
      if (i[1] & 0x20) {
        return X86ImplType::VAES;
      }
    }
#endif
#if defined(_MSC_VER)
    __cpuid(i, 1);
#else
    __asm__ __volatile__("cpuid"
                         : "=a"(i[0]), "=b"(i[1]), "=c"(i[2]), "=d"(i[3])
                         : "a"(1));
#endif
    if (i[2] & 0x2000000) {
      return X86ImplType::AES_NI;
    }
    return X86ImplType::Generic;
  }();
  return implType;
}

template <int>
inline void keyExpansion(const uint8_t* key, __m128i* w);

template <>
inline void keyExpansion<128>(const uint8_t* key, __m128i* w) {
  auto assist = [](__m128i a, const __m128i& b) {
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 4));
    a = _mm_xor_si128(a, _mm_shuffle_epi32(b, 0xff));
    return a;
  };

  w[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
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

template <>
inline void keyExpansion<192>(const uint8_t* key, __m128i* w) {
  auto assist = [](__m128i& a, __m128i& b, const __m128i& c) {
    a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
    a = _mm_xor_si128(a, _mm_shuffle_epi32(c, 0x55));
    b = _mm_xor_si128(b, _mm_slli_si128(b, 0x4));
    b = _mm_xor_si128(b, _mm_shuffle_epi32(a, 0xff));
  };

  __m128i a, b;
  w[0] = a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
  w[1] = b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));

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

template <>
inline void keyExpansion<256>(const uint8_t* key, __m128i* w) {
  auto assistL = [](__m128i a, const __m128i& b) {
    a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
    a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
    a = _mm_xor_si128(a, _mm_shuffle_epi32(b, 0xff));
    return a;
  };
  auto assistH = [](const __m128i& a, __m128i c) {
    c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
    c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
    c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
    c = _mm_xor_si128(
        c, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(a, 0x0), 0xaa));
    return c;
  };

  w[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
  w[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));
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

template <int N>
class WAesNi : public Aes {
 protected:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };
  __m128i m_w[Nr * 2];
  __m128i m_iv = {};

  WAesNi(const void* key,
         size_t keyLength,
         const void* iv,
         size_t ivLength,
         Padding padding)
      : Aes(padding) {
    if (keyLength < 4 * Nk) {
      uint8_t tk[4 * Nk] = {};  // key padding zero
      memcpy(tk, key, keyLength);

      keyExpansion<N>(tk, m_w);
    } else {
      keyExpansion<N>(reinterpret_cast<const uint8_t*>(key), m_w);
    }

    // imc
    for (uint8_t i = Nr + 1; i < Nr * 2; ++i) {
      m_w[i] = _mm_aesimc_si128(m_w[Nr * 2 - i]);
    }

    if (iv) {  // iv padding zero
      m_mode = Mode::CBC;
      memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  void cipher(__m128i& state) const {
    state = _mm_xor_si128(state, m_w[0]);
    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm_aesenc_si128(state, m_w[r]);
    }
    state = _mm_aesenclast_si128(state, m_w[Nr]);
  }

  void invCipher(__m128i& state) const {
    state = _mm_xor_si128(state, m_w[Nr]);
    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm_aesdec_si128(state, m_w[r]);
    }
    state = _mm_aesdeclast_si128(state, m_w[0]);
  }

  void paddingECB(size_t len, const __m128i* input, __m128i* output) const {
    if (len || Padding::PKCS7 == m_padding) {
      __m128i state = _mm_loadu_si128(input);
      auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<int>(len);
      memset(reinterpret_cast<uint8_t*>(&state) + len, pad, 16 - len);
      cipher(state);
      _mm_storeu_si128(output, state);
    }
  }

  bool invLastBlockECB(const void* in,
                       size_t inLength,
                       void* out,
                       size_t& outLength) const {
    if (!inLength || inLength % 16) {  // invalid data length
      return false;
    }

    auto block = static_cast<int64_t>(inLength / 16) - 1;
    auto state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in) + block);
    invCipher(state);

    // sum padding length
    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t*>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t*>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    memcpy(reinterpret_cast<__m128i*>(out) + block, &state, endLen);

    return true;
  }

  bool invLastBlockCBC(const void* in,
                       size_t inLength,
                       void* out,
                       size_t& outLength) const {
    if (!inLength || inLength % 16) {  // invalid data length
      return false;
    }

    auto block = static_cast<int64_t>(inLength / 16) - 1;
    auto input = reinterpret_cast<const __m128i*>(in);

    // sum padding length
    auto state =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + block));
    invCipher(state);

    __m128i iv;
    if (block) {
      iv = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + block - 1));
    } else {
      iv = m_iv;
    }
    state = _mm_xor_si128(state, iv);

    uint8_t padLen = 0;
    if (Padding::Zeros == m_padding) {
      for (int8_t i = 15; i >= 0; --i, ++padLen) {
        if (reinterpret_cast<uint8_t*>(&state)[i]) {
          break;
        }
      }
    } else {
      if (!isValidPKCS7Padding(&state)) {
        return false;
      }
      padLen = reinterpret_cast<uint8_t*>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return false;
    }

    outLength = inLength - padLen;
    uint8_t endLen = padLen ? outLength % 16 : 16;
    memcpy(reinterpret_cast<__m128i*>(out) + block, &state, endLen);

    return true;
  }

  virtual bool cipherECB(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    __m128i state;
    auto len = inLength;
    auto input = reinterpret_cast<const __m128i*>(in);
    auto output = reinterpret_cast<__m128i*>(out);
    for (; len >= 16; len -= 16, ++input, ++output) {
      state = _mm_loadu_si128(input);
      cipher(state);
      _mm_storeu_si128(output, state);
    }

    paddingECB(len, input, output);

    return true;
  }

  virtual bool cipherCBC(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const __m128i*>(in);
    auto output = reinterpret_cast<__m128i*>(out);

    auto state = m_iv;
    for (; len >= 16; len -= 16, ++input, ++output) {
      state = _mm_xor_si128(_mm_loadu_si128(input), state);
      cipher(state);
      _mm_storeu_si128(output, state);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      for (uint8_t i = 0; i < len; ++i) {
        reinterpret_cast<uint8_t*>(&state)[i] ^=
            reinterpret_cast<const uint8_t*>(input)[i];
      }
      if (Padding::PKCS7 == m_padding) {
        for (auto i = len; i < 16; ++i) {
          reinterpret_cast<uint8_t*>(&state)[i] ^= 16 - len;
        }
      }

      cipher(state);
      _mm_storeu_si128(output, state);
    }

    return true;
  }

  virtual bool cipherCTR(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    static const auto one = _mm_set_epi32(0, 1, 0, 0);
    static const auto bswap_epi64 =
        _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);

    auto counter = _mm_shuffle_epi8(m_iv, bswap_epi64);

    int64_t len = inLength / 16;
    auto input = reinterpret_cast<const __m128i*>(in);
    auto output = reinterpret_cast<__m128i*>(out);
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
        reinterpret_cast<uint8_t*>(output)[i] =
            reinterpret_cast<const uint8_t*>(input)[i] ^
            reinterpret_cast<uint8_t*>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!invLastBlockECB(in, inLength, out, outLength)) {
      return false;
    }

    auto len = inLength - 16;
    auto input = reinterpret_cast<const __m128i*>(in);
    auto output = reinterpret_cast<__m128i*>(out);
    for (; len >= 16; len -= 16, ++input, ++output) {
      auto state = _mm_loadu_si128(input);
      invCipher(state);
      _mm_storeu_si128(output, state);
    }

    return true;
  }

  virtual bool invCipherCBC(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!invLastBlockCBC(in, inLength, out, outLength)) {
      return false;
    }

    __m128i niv, iv = m_iv;
    auto len = static_cast<int64_t>(inLength / 16) - 1;
    auto input = reinterpret_cast<const __m128i*>(in);
    auto output = reinterpret_cast<__m128i*>(out);
    for (int i = 0; i < len; ++i, ++input, ++output) {
      auto state = niv = _mm_loadu_si128(input);
      invCipher(state);
      _mm_storeu_si128(output, _mm_xor_si128(state, iv));

      iv = niv;
    }

    return true;
  }

  virtual void setIVImpl(const void* iv, size_t length) override {
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, iv, length > 16 ? 16 : length);
  }

  virtual void getIVImpl(void* iv) const override { memcpy(iv, &m_iv, 16); }

  template <int>
  friend Ptr WAes::Create(const void*, size_t, const void*, size_t, Padding);
};

#if defined(WAES_VAES)
template <int N>
class WAesV final : public WAesNi<N> {
 private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };

  __m256i m_w256[Nr * 2];

  WAesV(const void* key,
        size_t keyLength,
        const void* iv,
        size_t ivLength,
        Padding padding)
      : WAesNi<N>(key, keyLength, iv, ivLength, padding) {
    for (int i = 0; i < Nr * 2; ++i) {
      m_w256[i] = _mm256_broadcastsi128_si256(WAesNi<N>::m_w[i]);
    }
  }

  void cipher(__m256i& state) const {
    state = _mm256_xor_si256(state, m_w256[0]);
    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm256_aesenc_epi128(state, m_w256[r]);
    }
    state = _mm256_aesenclast_epi128(state, m_w256[Nr]);
  }

  void invCipher(__m256i& state) const {
    state = _mm256_xor_si256(state, m_w256[Nr]);
    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm256_aesdec_epi128(state, m_w256[r]);
    }
    state = _mm256_aesdeclast_epi128(state, m_w256[0]);
  }

  virtual bool cipherECB(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = WAesNi<N>::SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input256 = reinterpret_cast<const __m256i*>(in);
    auto output256 = reinterpret_cast<__m256i*>(out);

    for (; len >= 32; len -= 32, ++input256, ++output256) {
      auto state = _mm256_loadu_si256(input256);
      cipher(state);
      _mm256_storeu_si256(output256, state);
    }

    auto input128 = reinterpret_cast<const __m128i*>(input256);
    auto output128 = reinterpret_cast<__m128i*>(output256);
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

  virtual bool cipherCTR(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
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
    auto input = reinterpret_cast<const __m256i*>(in);
    auto output = reinterpret_cast<__m256i*>(out);
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
        reinterpret_cast<uint8_t*>(output)[i] =
            reinterpret_cast<const uint8_t*>(input)[i] ^
            reinterpret_cast<uint8_t*>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!WAesNi<N>::invLastBlockECB(in, inLength, out, outLength)) {
      return false;
    }

    auto len = inLength - 16;
    auto input = reinterpret_cast<const __m256i*>(in);
    auto output = reinterpret_cast<__m256i*>(out);
    for (; len >= 32; len -= 32, ++input, ++output) {
      auto state256 = _mm256_loadu_si256(input);
      invCipher(state256);
      _mm256_storeu_si256(output, state256);
    }

    if (len == 16) {
      auto state128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input));
      WAesNi<N>::invCipher(state128);
      _mm_storeu_si128(reinterpret_cast<__m128i*>(output), state128);
    }

    return true;
  }

  virtual bool invCipherCBC(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!WAesNi<N>::invLastBlockCBC(in, inLength, out, outLength)) {
      return false;
    }

    auto input128 = reinterpret_cast<const __m128i*>(in);
    auto input256 = reinterpret_cast<const __m256i*>(in);
    auto output256 = reinterpret_cast<__m256i*>(out);
    auto piv256 = reinterpret_cast<const __m256i*>(input128 + 1);

    auto len = inLength - 16;
    auto ivs = _mm256_setr_m128i(WAesNi<N>::m_iv, _mm_loadu_si128(input128));
    for (; len >= 32; len -= 32, ++input256, ++output256, ++piv256) {
      auto state256 = _mm256_loadu_si256(input256);
      invCipher(state256);
      _mm256_storeu_si256(output256, _mm256_xor_si256(state256, ivs));

      ivs = _mm256_loadu_si256(piv256);
    }

    if (len == 16) {
      auto state128 =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(input256));
      WAesNi<N>::invCipher(state128);
      _mm_storeu_si128(reinterpret_cast<__m128i*>(output256),
                       _mm_xor_si128(state128, _mm256_castsi256_si128(ivs)));
    }

    return true;
  }

  template <int>
  friend Ptr WAes::Create(const void*, size_t, const void*, size_t, Padding);
};
#endif  // defined(WAES_VAES)

#if defined(WAES_VAES512)
template <int N>
class WAesV512 final : public WAesNi<N> {
 private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };

  __m512i m_w512[Nr * 2];

  WAesV512(const void* key,
           size_t keyLength,
           const void* iv,
           size_t ivLength,
           Padding padding)
      : WAesNi<N>(key, keyLength, iv, ivLength, padding) {
    for (int i = 0; i < Nr * 2; ++i) {
      m_w512[i] = _mm512_broadcast_i32x4(WAesNi<N>::m_w[i]);
    }
  }

  void cipher(__m512i& state) const {
    state = _mm512_xor_si512(state, m_w512[0]);
    for (uint8_t r = 1; r < Nr; ++r) {
      state = _mm512_aesenc_epi128(state, m_w512[r]);
    }
    state = _mm512_aesenclast_epi128(state, m_w512[Nr]);
  }

  void invCipher(__m512i& state) const {
    state = _mm512_xor_si512(state, m_w512[Nr]);
    for (uint8_t r = Nr + 1; r < Nr * 2; ++r) {
      state = _mm512_aesdec_epi128(state, m_w512[r]);
    }
    state = _mm512_aesdeclast_epi128(state, m_w512[0]);
  }

  virtual bool cipherECB(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = WAesNi<N>::SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input512 = reinterpret_cast<const __m512i*>(in);
    auto output512 = reinterpret_cast<__m512i*>(out);

    for (; len >= 64; len -= 64, ++input512, ++output512) {
      auto state = _mm512_loadu_si512(input512);
      cipher(state);
      _mm512_storeu_si512(output512, state);
    }

    auto input128 = reinterpret_cast<const __m128i*>(input512);
    auto output128 = reinterpret_cast<__m128i*>(output512);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      auto state = _mm_loadu_si128(input128);
      WAesNi<N>::cipher(state);
      _mm_storeu_si128(output128, state);
    }

    WAesNi<N>::paddingECB(len, input128, output128);

    return true;
  }

  virtual bool cipherCTR(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
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
    auto input = reinterpret_cast<const __m512i*>(in);
    auto output = reinterpret_cast<__m512i*>(out);
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
        reinterpret_cast<uint8_t*>(output)[i] =
            reinterpret_cast<const uint8_t*>(input)[i] ^
            reinterpret_cast<uint8_t*>(&state)[i];
      }
    }

    return true;
  }

  virtual bool invCipherECB(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!WAesNi<N>::invLastBlockECB(in, inLength, out, outLength)) {
      return false;
    }

    auto len = inLength - 16;
    auto input = reinterpret_cast<const __m512i*>(in);
    auto output = reinterpret_cast<__m512i*>(out);
    for (; len >= 64; len -= 64, ++input, ++output) {
      auto state512 = _mm512_loadu_si512(input);
      invCipher(state512);
      _mm512_storeu_si512(output, state512);
    }

    auto input128 = reinterpret_cast<const __m128i*>(input);
    auto output128 = reinterpret_cast<__m128i*>(output);
    for (; len >= 16; len -= 16, ++input128, ++output128) {
      auto state = _mm_loadu_si128(input128);
      WAesNi<N>::invCipher(state);
      _mm_storeu_si128(output128, state);
    }

    return true;
  }

  virtual bool invCipherCBC(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!WAesNi<N>::invLastBlockCBC(in, inLength, out, outLength)) {
      return false;
    }

    auto input128 = reinterpret_cast<const __m128i*>(in);
    auto input512 = reinterpret_cast<const __m512i*>(in);
    auto output512 = reinterpret_cast<__m512i*>(out);
    auto piv512 = reinterpret_cast<const __m512i*>(input128 + 3);

    auto len = inLength - 16;
    auto ivs = _mm512_castsi128_si512(WAesNi<N>::m_iv);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128), 1);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128 + 1), 2);
    ivs = _mm512_inserti32x4(ivs, _mm_loadu_si128(input128 + 2), 3);
    for (; len >= 64; len -= 64, ++input512, ++output512, ++piv512) {
      auto state512 = _mm512_loadu_si512(input512);
      invCipher(state512);
      _mm512_storeu_si512(output512, _mm512_xor_si512(state512, ivs));

      ivs = _mm512_loadu_si512(piv512);
    }

    input128 = reinterpret_cast<const __m128i*>(input512);
    auto output128 = reinterpret_cast<__m128i*>(output512);
    auto block = static_cast<int64_t>(len / 16);
    for (int64_t i = 0; i < block; ++i, ++input128, ++output128) {
      auto state = _mm_loadu_si128(input128);
      WAesNi<N>::invCipher(state);

      __m128i iv;
      switch (i) {
        case 0:
          iv = _mm512_extracti32x4_epi32(ivs, 0);
          break;
        case 1:
          iv = _mm512_extracti32x4_epi32(ivs, 1);
          break;
        case 2:
          iv = _mm512_extracti32x4_epi32(ivs, 2);
          break;
      }
      _mm_storeu_si128(output128, _mm_xor_si128(state, iv));
    }

    return true;
  }

  template <int>
  friend Ptr WAes::Create(const void*, size_t, const void*, size_t, Padding);
};
#endif  // defined(WAES_VAES512)

#endif

inline const uint8_t g_sBox[256] = {
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

inline const uint8_t g_invSbox[256] = {
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

inline const uint8_t g_gfmul_2[256] = {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
    0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, /*0*/
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, /*1*/
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
    0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, /*2*/
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
    0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, /*3*/
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
    0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, /*4*/
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
    0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, /*5*/
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
    0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, /*6*/
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
    0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, /*7*/
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15,
    0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05, /*8*/
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35,
    0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25, /*9*/
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
    0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, /*a*/
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
    0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65, /*b*/
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
    0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85, /*c*/
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
    0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, /*d*/
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5,
    0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5, /*e*/
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5,
    0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5 /*f*/
};

inline const uint8_t g_gfmul_3[256] = {
    0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
    0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11, /*0*/
    0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
    0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21, /*1*/
    0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69,
    0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71, /*2*/
    0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59,
    0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41, /*3*/
    0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
    0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, /*4*/
    0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9,
    0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1, /*5*/
    0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9,
    0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1, /*6*/
    0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
    0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, /*7*/
    0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92,
    0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a, /*8*/
    0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2,
    0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba, /*9*/
    0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2,
    0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea, /*a*/
    0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2,
    0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda, /*b*/
    0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52,
    0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a, /*c*/
    0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62,
    0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, /*d*/
    0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32,
    0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a, /*e*/
    0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02,
    0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a /*f*/
};

inline const uint8_t g_gfmul_9[256] = {
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f,
    0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77, /*0*/
    0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf,
    0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, /*1*/
    0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04,
    0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c, /*2*/
    0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94,
    0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc, /*3*/
    0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49,
    0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01, /*4*/
    0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9,
    0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91, /*5*/
    0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72,
    0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a, /*6*/
    0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2,
    0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, /*7*/
    0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3,
    0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b, /*8*/
    0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43,
    0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b, /*9*/
    0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8,
    0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0, /*a*/
    0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78,
    0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30, /*b*/
    0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5,
    0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed, /*c*/
    0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35,
    0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, /*d*/
    0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e,
    0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6, /*e*/
    0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e,
    0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46 /*f*/
};

inline const uint8_t g_gfmul_b[256] = {
    0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31,
    0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69, /*0*/
    0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81,
    0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9, /*1*/
    0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a,
    0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12, /*2*/
    0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa,
    0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2, /*3*/
    0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7,
    0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f, /*4*/
    0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77,
    0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f, /*5*/
    0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc,
    0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4, /*6*/
    0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c,
    0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54, /*7*/
    0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6,
    0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e, /*8*/
    0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76,
    0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e, /*9*/
    0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd,
    0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5, /*a*/
    0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d,
    0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55, /*b*/
    0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30,
    0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68, /*c*/
    0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80,
    0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8, /*d*/
    0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b,
    0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13, /*e*/
    0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb,
    0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3 /*f*/
};

inline const uint8_t g_gfmul_d[256] = {
    0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23,
    0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b, /*0*/
    0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3,
    0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b, /*1*/
    0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98,
    0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0, /*2*/
    0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48,
    0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20, /*3*/
    0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e,
    0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26, /*4*/
    0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e,
    0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6, /*5*/
    0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5,
    0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d, /*6*/
    0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25,
    0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d, /*7*/
    0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9,
    0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91, /*8*/
    0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29,
    0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41, /*9*/
    0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42,
    0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a, /*a*/
    0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92,
    0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa, /*b*/
    0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94,
    0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc, /*c*/
    0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44,
    0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, /*d*/
    0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f,
    0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47, /*e*/
    0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff,
    0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97 /*f*/
};

inline const uint8_t g_gfmul_e[256] = {
    0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a,
    0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a, /*0*/
    0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca,
    0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba, /*1*/
    0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1,
    0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81, /*2*/
    0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11,
    0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61, /*3*/
    0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87,
    0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7, /*4*/
    0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67,
    0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17, /*5*/
    0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c,
    0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c, /*6*/
    0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc,
    0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc, /*7*/
    0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b,
    0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b, /*8*/
    0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b,
    0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb, /*9*/
    0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0,
    0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0, /*a*/
    0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50,
    0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20, /*b*/
    0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6,
    0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6, /*c*/
    0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26,
    0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56, /*d*/
    0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d,
    0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d, /*e*/
    0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd,
    0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d /*f*/
};

template <int N>
class WAesGen final : public Aes {
 private:
  enum {
    Nb = Aes::Nb,
    Nk = aesN<N>::Nk,
    Nr = aesN<N>::Nr,
  };
  alignas(16) uint32_t m_w[Nb * (Nr + 1)];
  alignas(16) uint8_t m_iv[16] = {};

  WAesGen(const void* key,
          size_t keyLength,
          const void* iv,
          size_t ivLength,
          Padding padding)
      : Aes(padding) {
    if (keyLength < 4 * Nk) {
      uint8_t tk[4 * Nk] = {};  // key padding zero
      memcpy(tk, key, keyLength);

      keyExpansion(tk);
    } else {
      keyExpansion(reinterpret_cast<const uint8_t*>(key));
    }

    if (iv) {  // iv padding zero
      m_mode = Mode::CBC;
      memcpy(m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  void keyExpansion(const uint8_t* key) {
    static const uint8_t rc[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

    auto subWord = [](uint8_t* w) {
      for (uint8_t i = 0; i < 4; ++i) {
        w[i] = g_sBox[w[i]];
      }
    };

    for (uint8_t i = 0; i < Nk; ++i) {
      m_w[i] = *reinterpret_cast<const uint32_t*>(key + 4 * i);
    }

    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
      m_w[i] = m_w[i - 1];
      if (0 == i % Nk) {
        m_w[i] = (m_w[i] >> 8) | (m_w[i] << 24);  // rot word
        subWord(reinterpret_cast<uint8_t*>(m_w + i));

        m_w[i] ^= rc[i / Nk];
      } else if (8 == Nk && 4 == i % Nk) {
        subWord(reinterpret_cast<uint8_t*>(m_w + i));
      }
      m_w[i] ^= m_w[i - Nk];
    }
  }

  uint8_t* cipher(uint8_t* state) const {
    addRoundKey(state, 0);

    for (uint8_t r = 1; r < Nr; ++r) {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, r);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, Nr);

    return state;
  }

  uint8_t* invCipher(uint8_t* state) const {
    addRoundKey(state, Nr);

    for (uint8_t r = Nr - 1; r >= 1; --r) {
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, r);
      invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, 0);

    return state;
  }

  void subBytes(uint8_t* state) const {
    for (uint8_t i = 0; i < 4 * Nb; ++i) {
      state[i] = g_sBox[state[i]];
    }
  }

  void shiftRows(uint8_t* state) const {
    // second row
    auto t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;
    // third row
    t = state[2];
    state[2] = state[10];
    state[10] = t;
    t = state[6];
    state[6] = state[14];
    state[14] = t;
    // fourth row
    t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
  }

  void mixColumns(uint8_t* state) const {
    alignas(16) uint8_t arr[4];
    for (int i = 0; i < 4; ++i, state += 4) {
      arr[0] = state[0];
      arr[1] = state[1];
      arr[2] = state[2];
      arr[3] = state[3];
      state[0] = g_gfmul_2[arr[0]] ^ g_gfmul_3[arr[1]] ^ arr[2] ^ arr[3];
      state[1] = arr[0] ^ g_gfmul_2[arr[1]] ^ g_gfmul_3[arr[2]] ^ arr[3];
      state[2] = arr[0] ^ arr[1] ^ g_gfmul_2[arr[2]] ^ g_gfmul_3[arr[3]];
      state[3] = g_gfmul_3[arr[0]] ^ arr[1] ^ arr[2] ^ g_gfmul_2[arr[3]];
    }
  }

  void addRoundKey(uint8_t* state, uint8_t r) const {
    auto rv = reinterpret_cast<uint64_t*>(state);
    auto rk = reinterpret_cast<const uint64_t*>(m_w + Nb * r);
    rv[0] ^= rk[0];
    rv[1] ^= rk[1];
  }

  void invSubBytes(uint8_t* state) const {
    for (uint8_t i = 0; i < 4 * Nb; ++i) {
      state[i] = g_invSbox[state[i]];
    }
  }

  void invShiftRows(uint8_t* state) const {
    // second row
    auto t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;
    // third row
    t = state[2];
    state[2] = state[10];
    state[10] = t;
    t = state[6];
    state[6] = state[14];
    state[14] = t;
    // fourth row
    t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
  }

  void invMixColumns(uint8_t* state) const {
    alignas(16) uint8_t arr[4];
    for (uint8_t i = 0; i < 4; ++i, state += 4) {
      arr[0] = state[0];
      arr[1] = state[1];
      arr[2] = state[2];
      arr[3] = state[3];
      state[0] = g_gfmul_e[arr[0]] ^ g_gfmul_b[arr[1]] ^ g_gfmul_d[arr[2]] ^
                 g_gfmul_9[arr[3]];
      state[1] = g_gfmul_9[arr[0]] ^ g_gfmul_e[arr[1]] ^ g_gfmul_b[arr[2]] ^
                 g_gfmul_d[arr[3]];
      state[2] = g_gfmul_d[arr[0]] ^ g_gfmul_9[arr[1]] ^ g_gfmul_e[arr[2]] ^
                 g_gfmul_b[arr[3]];
      state[3] = g_gfmul_b[arr[0]] ^ g_gfmul_d[arr[1]] ^ g_gfmul_9[arr[2]] ^
                 g_gfmul_e[arr[3]];
    }
  }

  virtual bool cipherECB(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      memcpy(output, input, 16);
      cipher(output);
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      auto pad =
          Padding::Zeros == m_padding ? 0 : 16 - static_cast<uint8_t>(len);
      memcpy(output, input, len);
      memset(output + len, pad, pad);

      cipher(output);
    }

    return true;
  }

  virtual bool cipherCBC(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }
    outLength = nNeedLen;

    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);
    const auto* piv = m_iv;
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      for (uint8_t i = 0; i < 4 * Nb; ++i) {
        output[i] = input[i] ^ piv[i];
      }
      cipher(output);
      piv = output;
    }

    // Padding
    if (len || Padding::PKCS7 == m_padding) {
      auto pad =
          Padding::Zeros == m_padding ? 0 : 16 - static_cast<uint8_t>(len);
      uint8_t pos = 0;
      for (; pos < len; ++pos) {
        output[pos] = input[pos] ^ piv[pos];
      }
      for (; pos < 16; ++pos) {
        output[pos] = pad ^ piv[pos];
      }

      cipher(output);
    }

    return true;
  }

  virtual bool cipherCTR(const void* in,
                         size_t inLength,
                         void* out,
                         size_t& outLength) const override {
    if (outLength < inLength) {
      return false;
    }
    outLength = inLength;

    alignas(16) uint8_t counter[16];
    memcpy(counter, m_iv, 16);
    auto addCounter = [&counter]() {
      for (auto pos = counter + 15; pos >= counter; --pos) {
        if (UINT8_MAX == *pos) {
          *pos = 0;
        } else {
          ++*pos;
          break;
        }
      }
    };

    alignas(16) uint8_t state[4 * Nb];
    int64_t len = inLength;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);

    for (; len > 0; len -= 16, input += 16, output += 16) {
      memcpy(state, counter, 16);
      cipher(state);

      for (uint8_t i = 0; i < 16 && i < len; ++i) {
        output[i] = state[i] ^ input[i];
      }

      addCounter();
    }

    return true;
  }

  virtual bool invCipherECB(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!inLength || inLength % 16) {  // invalid data length
      return false;
    }

    alignas(16) uint8_t state[4 * Nb];
    auto input = reinterpret_cast<const uint8_t*>(in) + inLength - 16;

    // sum padding length
    memcpy(state, input, 16);
    invCipher(state);

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
    auto output = reinterpret_cast<uint8_t*>(out) + inLength - 16;
    memcpy(output, state, endLen);

    for (input -= 16, output -= 16; input >= in; input -= 16, output -= 16) {
      memcpy(output, input, 16);
      invCipher(output);
    }

    return true;
  }

  virtual bool invCipherCBC(const void* in,
                            size_t inLength,
                            void* out,
                            size_t& outLength) const override {
    if (!inLength || inLength % 16) {  // invalid data length
      return false;
    }

    alignas(16) uint8_t state[4 * Nb];
    auto input = reinterpret_cast<const uint8_t*>(in) + inLength - 16;

    // sum padding length
    memcpy(state, input, 16);
    invCipher(state);

    const auto* piv = in != input ? input - 16 : m_iv;
    for (uint8_t i = 0; i < 4 * Nb; ++i) {
      state[i] ^= piv[i];
    }

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
    auto output = reinterpret_cast<uint8_t*>(out) + inLength - 16;
    memcpy(output, state, endLen);

    for (input -= 16, output -= 16; input >= in; input -= 16, output -= 16) {
      memcpy(output, input, 16);
      invCipher(output);

      piv = in != input ? input - 16 : m_iv;
      for (uint8_t i = 0; i < 4 * Nb; ++i) {
        output[i] ^= piv[i];
      }
    }

    return true;
  }

  virtual void setIVImpl(const void* iv, size_t length) override {
    memset(m_iv, 0, sizeof(m_iv));
    memcpy(m_iv, iv, length > 16 ? 16 : length);
  }

  virtual void getIVImpl(void* iv) const override { memcpy(iv, m_iv, 16); }

  template <int>
  friend Ptr WAes::Create(const void*, size_t, const void*, size_t, Padding);
};

#endif

}  // namespace detail

// Utility function to get current implementation name
inline const char* GetImplName() {
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
Ptr Create(const void* key,
           size_t keyLength,
           const void* iv,
           size_t ivLength,
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
      return Ptr(
          new detail::WAesNi<bit>(key, keyLength, iv, ivLength, padding));
    case detail::X86ImplType::Generic:
    default:
      break;
  }
#endif
  return Ptr(new detail::WAesGen<bit>(key, keyLength, iv, ivLength, padding));
#endif
}

}  // namespace WAes
