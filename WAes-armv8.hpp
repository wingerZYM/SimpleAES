#pragma once

#include <memory.h>
#include <cstdint>

#include <arm_neon.h>

// AES // ECB/CBC/CTR // PKCS7Padding/ZerosPadding

enum class Padding {
  Zeros,
  PKCS7,
};

// Helper function
namespace {

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
  switch (imm)  // imm only use 0x55, 0xaa, 0xff.
  {
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
#ifdef _MSC_VER
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

}  // namespace

template <int>
struct aesN;
template <>
struct aesN<128> {
  enum { Nk = 4, Nr = 10 };

  static void keyExpansion(const uint8_t* key, uint8x16_t* w) {
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
};
template <>
struct aesN<192> {
  enum { Nk = 6, Nr = 12 };

  static void keyExpansion(const uint8_t* key, uint8x16_t* w) {
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
};
template <>
struct aesN<256> {
  enum { Nk = 8, Nr = 14 };

  static void keyExpansion(const uint8_t* key, uint8x16_t* w) {
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
};

template <int N>
class CWAes {
 public:
  // If |iv| is null, mode is ECB; |iv| not be null, mode is CBC; if it is CTR,
  // after set counter. CTR mode must be NonePadding!
  CWAes(const void* key,
        size_t keyLength,
        const void* iv = nullptr,
        size_t ivLength = 16,
        Padding padding = Padding::PKCS7)
      : m_padding(padding), m_mode(Mode::ECB) {
    if (keyLength < 4 * Nk)  // key padding zero
    {
      uint8_t tk[4 * Nk] = {};

      memcpy(tk, key, keyLength);

      aesN<N>::keyExpansion(tk, m_w);
    } else {
      aesN<N>::keyExpansion(reinterpret_cast<const uint8_t*>(key), m_w);
    }

    // imc
    for (uint8_t i = Nr + 1; i < Nr * 2; ++i) {
      m_w[i] = vaesimcq_u8(m_w[Nr * 2 - i]);
    }

    if (iv)  // iv padding zero
    {
      m_mode = Mode::CBC;
      memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  ~CWAes() = default;

  static int SumCipherLength(int nInLen) {
    return (nInLen / (4 * Nb) + 1) * (4 * Nb);
  }

  // Sets the counter value when in CBC mode.
  // The maximum length is 16 byte, if not enough padding zero.
  void SetIV(const void* iv, size_t length) {
    m_mode = Mode::CBC;
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, iv, length > 16 ? 16 : length);
  }

  // Sets the counter value when in CTR mode.
  // The maximum length is 16 byte, if not enough padding zero.
  void SetCounter(const void* counter, size_t length) {
    m_mode = Mode::CTR;
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, counter, length > 16 ? 16 : length);
  }

  size_t Cipher(const void* in,
                size_t inLength,
                void* out,
                size_t outLength) const {
    switch (m_mode) {
      case Mode::ECB:
        return cipherECB(in, inLength, out, outLength);
      case Mode::CBC:
        return cipherCBC(in, inLength, out, outLength);
      case Mode::CTR:
        return cipherCTR(in, inLength, out, outLength);
    }

    return 0;
  }

  size_t InvCipher(const void* in,
                   size_t inLength,
                   void* out,
                   size_t outLength) const {
    switch (m_mode) {
      case Mode::ECB:
        return invCipherECB(in, inLength, out, outLength);
      case Mode::CBC:
        return invCipherCBC(in, inLength, out, outLength);
      case Mode::CTR:
        return cipherCTR(in, inLength, out, outLength);
    }

    return 0;
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
  };
  uint8x16_t m_w[Nr * 2];
  uint8x16_t m_iv = {};
  Padding m_padding;
  Mode m_mode;

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

  bool isValidPKCS7Padding(const uint8x16_t& state) const {
    auto* pos = reinterpret_cast<const uint8_t*>(&state);
    if (pos[15] > 16 || pos[15] == 0)
      return false;

    for (int8_t i = 16 - pos[15]; i < 15; ++i) {
      if (pos[15] != pos[i])
        return false;
    }

    return true;
  }

  size_t cipherECB(const void* in,
                   size_t inLength,
                   void* out,
                   size_t outLength) const {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return 0;
    }

    uint8x16_t state;
    auto len = inLength;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);
    for (; len >= 16; len -= 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      cipher(state);
      vst1q_u8(output, state);
    }

    state = vld1q_u8(input);
    // Padding
    auto pad = Padding::Zeros == m_padding ? 0 : 16 - len;
    memset(reinterpret_cast<uint8_t*>(&state) + len, pad, 16 - len);

    cipher(state);
    vst1q_u8(output, state);

    return nNeedLen;
  }

  size_t cipherCBC(const void* in,
                   size_t inLength,
                   void* out,
                   size_t outLength) const {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return 0;
    }

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

    return nNeedLen;
  }

  size_t cipherCTR(const void* in,
                   size_t inLength,
                   void* out,
                   size_t outLength) const {
    if (outLength < inLength) {
      return 0;
    }

    auto counter = m_iv;
    auto addCounter = [&counter]() {
      auto pos = reinterpret_cast<uint8_t*>(&counter);
      for (int8_t i = 15; i >= 0; --i) {
        if (UINT8_MAX == pos[i]) {
          pos[i] = 0;
        } else {
          ++pos[i];
          break;
        }
      }
    };

    int64_t len = inLength / 16;
    auto input = reinterpret_cast<const uint8_t*>(in);
    auto output = reinterpret_cast<uint8_t*>(out);
    for (int64_t i = 0; i < len; ++i, input += 16, output += 16) {
      auto state = counter;
      cipher(state);
      vst1q_u8(output, veorq_u8(vld1q_u8(input), state));

      addCounter();
    }

    int8_t endLen = inLength % 16;
    if (endLen) {
      auto state = counter;
      cipher(state);
      for (int8_t i = 0; i < endLen; ++i) {
        reinterpret_cast<uint8_t*>(output)[i] =
            reinterpret_cast<const uint8_t*>(input)[i] ^
            reinterpret_cast<uint8_t*>(&state)[i];
      }
    }

    return inLength;
  }

  size_t invCipherECB(const void* in,
                      size_t inLength,
                      void* out,
                      size_t outLength) const {
    if (!inLength || inLength % 16)  // invalid data length
    {
      return 0;
    }

    auto len = static_cast<int64_t>(inLength) - 16;
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
      if (!isValidPKCS7Padding(state)) {
        return 0;
      }
      padLen = reinterpret_cast<uint8_t*>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return 0;
    }

    outLength = inLength - padLen;
    uint8_t endLen = outLength % 16;
    auto output = reinterpret_cast<uint8_t*>(out);
    memcpy(output + len, reinterpret_cast<uint8_t*>(&state), endLen);

    for (int i = 0; i < len; i += 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      invCipher(state);
      vst1q_u8(output, state);
    }

    return outLength;
  }

  size_t invCipherCBC(const void* in,
                      size_t inLength,
                      void* out,
                      size_t outLength) const {
    if (!inLength || inLength % 16)  // invalid data length
    {
      return 0;
    }

    auto len = static_cast<int64_t>(inLength) - 16;
    auto input = reinterpret_cast<const uint8_t*>(in);

    // sum padding length
    auto state = vld1q_u8(input + len);
    invCipher(state);

    uint8x16_t iv;
    if (len) {
      iv = vld1q_u8(in + len - 16);
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
      if (!isValidPKCS7Padding(state)) {
        return 0;
      }
      padLen = reinterpret_cast<uint8_t*>(&state)[15];
    }

    if (outLength < inLength - padLen) {
      // out buffer too small
      return 0;
    }

    outLength = inLength - padLen;
    uint8_t endLen = outLength % 16;
    auto output = reinterpret_cast<uint8_t*>(out);
    memcpy(output + len, &state, endLen);

    iv = m_iv;
    for (int i = 0; i < len; i += 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      invCipher(state);
      vst1q_u8(output, veorq_u8(state, iv));

      iv = vld1q_u8(input);
    }

    return outLength;
  }
};

using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;
