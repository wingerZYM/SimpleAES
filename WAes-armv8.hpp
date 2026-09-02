#pragma once

#include <cstdint>
#include <memory.h>

#include <arm_neon.h>

// AES // ECB/CBC/CTR // PKCS7Padding/ZerosPadding

enum class Padding {
  Zeros,
  PKCS7,
};

// Helper function
namespace {

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

// Key expansion helpers: vaeseq_u8 produces ShiftRows(SubBytes(a)).
// A vqtbl1q_u8 lookup then extracts, rotates, and broadcasts the target word.

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

} // namespace

template <int> struct aesN;
template <> struct aesN<128> {
  enum { Nk = 4, Nr = 10 };

  static void keyExpansion(const uint8_t *key, uint8x16_t *w) {
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
};
template <> struct aesN<192> {
  enum { Nk = 6, Nr = 12 };

  static void keyExpansion(const uint8_t *key, uint8x16_t *w) {
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
};
template <> struct aesN<256> {
  enum { Nk = 8, Nr = 14 };

  static void keyExpansion(const uint8_t *key, uint8x16_t *w) {
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
};

template <int N> class CWAes {
public:
  // If |iv| is null, mode is ECB; |iv| not be null, mode is CBC; if it is CTR,
  // after set counter. CTR mode must be NonePadding!
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
    aesN<N>::keyExpansion(normalizedKey, m_w);

    // imc
    for (uint8_t i = Nr + 1; i < Nr * 2; ++i) {
      m_w[i] = vaesimcq_u8(m_w[Nr * 2 - i]);
    }

    if (iv) // iv padding zero
    {
      m_mode = Mode::CBC;
      memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
    }
  }

  ~CWAes() = default;

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

  // Sets the counter value when in CBC mode.
  // The maximum length is 16 byte, if not enough padding zero.
  void SetIV(const void *iv, size_t length) {
    m_mode = Mode::CBC;
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, iv, length > 16 ? 16 : length);
  }

  // Sets the counter value when in CTR mode.
  // The maximum length is 16 byte, if not enough padding zero.
  void SetCounter(const void *counter, size_t length) {
    m_mode = Mode::CTR;
    memset(&m_iv, 0, sizeof(m_iv));
    memcpy(&m_iv, counter, length > 16 ? 16 : length);
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

  bool isValidPKCS7Padding(const uint8x16_t &state) const {
    auto *pos = reinterpret_cast<const uint8_t *>(&state);
    if (pos[15] > 16 || pos[15] == 0)
      return false;

    for (int8_t i = 16 - pos[15]; i < 15; ++i) {
      if (pos[15] != pos[i])
        return false;
    }

    return true;
  }

  bool cipherECB(const void *in, size_t inLength, void *out,
                 size_t &outLength) const {
    auto nNeedLen = SumCipherLength(inLength);
    if (outLength < nNeedLen) {
      return false;
    }

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

    outLength = nNeedLen;
    return true;
  }

  bool cipherCTR(const void *in, size_t inLength, void *out,
                 size_t &outLength) const {
    if (outLength < inLength) {
      return false;
    }

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

    outLength = inLength;
    return true;
  }

  bool invCipherECB(const void *in, size_t inLength, void *out,
                    size_t &outLength) const {
    if (!inLength || inLength % 16) // invalid data length
    {
      return false;
    }

    auto len = static_cast<int64_t>(inLength) - 16;
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
      if (!isValidPKCS7Padding(state)) {
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
    memcpy(output + len, reinterpret_cast<uint8_t *>(&state), endLen);

    for (int i = 0; i < len; i += 16, input += 16, output += 16) {
      state = vld1q_u8(input);
      invCipher(state);
      vst1q_u8(output, state);
    }

    return true;
  }

  bool invCipherCBC(const void *in, size_t inLength, void *out,
                    size_t &outLength) const {
    if (!inLength || inLength % 16) // invalid data length
    {
      return false;
    }

    auto len = static_cast<int64_t>(inLength) - 16;
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
      if (!isValidPKCS7Padding(state)) {
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
};

using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;
