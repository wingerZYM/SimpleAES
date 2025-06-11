#pragma once

#include <cstdint>
#include <memory.h>

#include <immintrin.h> // For AVX2 and AES-NI (256-bit VAES)

// AES // ECB/CBC/CTR // PKCS7Padding/ZerosPadding
// 256-bit VAES Implementation using AVX2 + AES-NI
// Processes 2 AES blocks simultaneously (32 bytes at a time)
// Requires: AVX2 support (Haswell 2013+) and AES-NI support

enum class Padding
{
    Zeros,
    PKCS7,
};

template <int> struct aesN;
template <> struct aesN<128>
{
    enum { Nk = 4, Nr = 10 };

    static void keyExpansion(const uint8_t* key, __m128i* w)
    {
        auto assist = [](__m128i a, const __m128i& b)
        {
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
};

template <> struct aesN<192>
{
    enum { Nk = 6, Nr = 12 };

    static void keyExpansion(const uint8_t* key, __m128i* w)
    {
        auto assist = [](__m128i& a, __m128i& b, const __m128i& c)
        {
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
        w[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(w[1]), _mm_castsi128_pd(a), 0));
        w[2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

        assist(a, b, _mm_aeskeygenassist_si128(b, 0x2));
        w[3] = a;
        w[4] = b;

        assist(a, b, _mm_aeskeygenassist_si128(b, 0x4));
        w[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(w[4]), _mm_castsi128_pd(a), 0));
        w[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

        assist(a, b, _mm_aeskeygenassist_si128(b, 0x8));
        w[6] = a;
        w[7] = b;

        assist(a, b, _mm_aeskeygenassist_si128(b, 0x10));
        w[7] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(w[7]), _mm_castsi128_pd(a), 0));
        w[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

        assist(a, b, _mm_aeskeygenassist_si128(b, 0x20));
        w[9] = a;
        w[10] = b;

        assist(a, b, _mm_aeskeygenassist_si128(b, 0x40));
        w[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(w[10]), _mm_castsi128_pd(a), 0));
        w[11] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), 1));

        assist(a, b, _mm_aeskeygenassist_si128(b, 0x80));
        w[12] = a;
    }
};

template <> struct aesN<256>
{
    enum { Nk = 8, Nr = 14 };

    static void keyExpansion(const uint8_t* key, __m128i* w)
    {
        auto assistL = [](__m128i a, const __m128i& b)
        {
            a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
            a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
            a = _mm_xor_si128(a, _mm_slli_si128(a, 0x4));
            a = _mm_xor_si128(a, _mm_shuffle_epi32(b, 0xff));
            return a;
        };
        auto assistH = [](const __m128i& a, __m128i c)
        {
            c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
            c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
            c = _mm_xor_si128(c, _mm_slli_si128(c, 0x4));
            c = _mm_xor_si128(c, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(a, 0x0), 0xaa));
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
};

template <int N>
class CWAes
{
public:
    CWAes(const void* key, size_t keyLength, const void* iv = nullptr, size_t ivLength = 16, Padding padding = Padding::PKCS7)
        : m_padding(padding), m_mode(Mode::ECB)
    {
        if (keyLength < 4 * Nk)
        {
            uint8_t tk[4 * Nk] = {};
            memcpy(tk, key, keyLength);
            aesN<N>::keyExpansion(tk, m_w128);
        }
        else
        {
            aesN<N>::keyExpansion(reinterpret_cast<const uint8_t*>(key), m_w128);
        }

        // Convert 128-bit round keys to 256-bit format for AVX2
        for (int i = 0; i <= Nr; ++i)
        {
            m_w256[i] = _mm256_broadcastsi128_si256(m_w128[i]);
        }

        // Generate inverse round keys
        for (uint8_t i = Nr + 1; i < Nr * 2; ++i)
        {
            m_w128[i] = _mm_aesimc_si128(m_w128[Nr * 2 - i]);
            m_w256[i] = _mm256_broadcastsi128_si256(m_w128[i]);
        }

        if (iv)
        {
            m_mode = Mode::CBC;
            memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
        }
    }

    size_t SumCipherLength(size_t nInLen) const {
        constexpr size_t blockSize = Nb * 4;
        if (m_padding == Padding::Zeros)
            return ((nInLen + blockSize - 1) / blockSize) * blockSize;
        else // PKCS7
            return ((nInLen / blockSize) + 1) * blockSize;
    }

    void SetIV(const void* iv, size_t length)
    {
        m_mode = Mode::CBC;
        memset(&m_iv, 0, sizeof(m_iv));
        memcpy(&m_iv, iv, length > 16 ? 16 : length);
    }

    void SetCounter(const void* counter, size_t length)
    {
        m_mode = Mode::CTR;
        memset(&m_iv, 0, sizeof(m_iv));
        memcpy(&m_iv, counter, length > 16 ? 16 : length);
    }

    size_t Cipher(const void* in, size_t inLength, void* out, size_t outLength) const
    {
        switch (m_mode)
        {
        case Mode::ECB:
            return cipherECB(in, inLength, out, outLength);
        case Mode::CBC:
            return cipherCBC(in, inLength, out, outLength);
        case Mode::CTR:
            return cipherCTR(in, inLength, out, outLength);
        }
        return 0;
    }

    size_t InvCipher(const void* in, size_t inLength, void* out, size_t outLength) const
    {
        switch (m_mode)
        {
        case Mode::ECB:
            return invCipherECB(in, inLength, out, outLength);
        case Mode::CBC:
            return invCipherCBC(in, inLength, out, outLength);
        case Mode::CTR:
            return cipherCTR(in, inLength, out, outLength); // CTR mode is symmetric
        }
        return 0;
    }

private:
    enum {
        Nb = 4,
        Nk = aesN<N>::Nk,
        Nr = aesN<N>::Nr,
    };

    enum class Mode
    {
        ECB,
        CBC,
        CTR,
    };

    __m256i m_w256[Nr * 2] = {};
    __m128i m_w128[Nr * 2] = {};
    __m128i m_iv = {};
    Padding m_padding;
    Mode m_mode;

    // AVX2 cipher function for 2 blocks (256-bit)
    void cipher256(__m256i& state) const
    {
        state = _mm256_xor_si256(state, m_w256[0]);
        for (int i = 1; i < Nr; ++i)
        {
            state = _mm256_aesenc_epi128(state, m_w256[i]);
        }
        state = _mm256_aesenclast_epi128(state, m_w256[Nr]);
    }

    // AVX2 inverse cipher function for 2 blocks (256-bit)
    void invCipher256(__m256i& state) const
    {
        state = _mm256_xor_si256(state, m_w256[Nr]);
        for (int i = Nr - 1; i > 0; --i)
        {
            state = _mm256_aesdec_epi128(state, m_w256[Nr * 2 - i]);
        }
        state = _mm256_aesdeclast_epi128(state, m_w256[0]);
    }

    // Single block cipher using AES-NI (for fallback)
    void cipher128(__m128i& state) const
    {
        state = _mm_xor_si128(state, m_w128[0]);
        for (int i = 1; i < Nr; ++i)
        {
            state = _mm_aesenc_si128(state, m_w128[i]);
        }
        state = _mm_aesenclast_si128(state, m_w128[Nr]);
    }

    // Single block inverse cipher using AES-NI (for fallback)
    void invCipher128(__m128i& state) const
    {
        state = _mm_xor_si128(state, m_w128[Nr]);
        for (int i = Nr - 1; i > 0; --i)
        {
            state = _mm_aesdec_si128(state, m_w128[Nr * 2 - i]);
        }
        state = _mm_aesdeclast_si128(state, m_w128[0]);
    }

    // PKCS7 padding validation
    bool isValidPKCS7Padding(const __m128i& state) const
    {
        alignas(16) uint8_t block[16];
        _mm_store_si128(reinterpret_cast<__m128i*>(block), state);
        
        uint8_t padLen = block[15];
        if (padLen == 0 || padLen > 16) return false;
        
        for (int i = 16 - padLen; i < 16; ++i)
        {
            if (block[i] != padLen) return false;
        }
        return true;
    }

    size_t cipherECB(const void* in, size_t inLength, void* out, size_t outLength) const
    {
        auto nNeedLen = SumCipherLength(inLength);
        if (outLength < nNeedLen)
        {
            return 0;
        }

		auto len = inLength;
        auto input256 = reinterpret_cast<const __m256i*>(in);
        auto output256 = reinterpret_cast<__m256i*>(out);

		for (; len >= 32; len -= 32, ++input256, ++output256)
		{
			auto state = _mm256_loadu_si256(input256);
			cipher256(state);
			_mm256_storeu_si256(output256, state);
		}

		auto input128 = reinterpret_cast<const __m128i*>(input256);
		auto output128 = reinterpret_cast<__m128i*>(output256);
        if (len >= 16)
        {
			auto state = _mm_loadu_si128(input128);
			cipher128(state);
			_mm_storeu_si128(output128, state);

			len -= 16;
			++input128;
			++output128;
        }

        // Padding
		if (len || Padding::PKCS7 == m_padding)
		{
            auto state = _mm_loadu_si128(input128);
            auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<int>(len);
            memset(reinterpret_cast<uint8_t*>(&state) + len, pad, 16 - len);

            cipher128(state);
            _mm_storeu_si128(output128, state);
		}

        return nNeedLen;
    }

    size_t cipherCBC(const void* in, size_t inLength, void* out, size_t outLength) const
    {
        auto nNeedLen = SumCipherLength(inLength);
        if (outLength < nNeedLen)
        {
            return 0;
        }

        auto len = inLength;
        auto input = reinterpret_cast<const __m128i*>(in);
        auto output = reinterpret_cast<__m128i*>(out);

        auto state = m_iv;
        for (; len >= 16; len -= 16, ++input, ++output)
        {
            state = _mm_xor_si128(_mm_loadu_si128(input), state);
            cipher128(state);
            _mm_storeu_si128(output, state);
        }

        // Padding
        if (len || Padding::PKCS7 == m_padding)
        {
            for (uint8_t i = 0; i < len; ++i)
            {
                reinterpret_cast<uint8_t*>(&state)[i] ^= reinterpret_cast<const uint8_t*>(input)[i];
            }
            if (Padding::PKCS7 == m_padding)
            {
                for (auto i = len; i < 16; ++i)
                {
                    reinterpret_cast<uint8_t*>(&state)[i] ^= 16 - len;
                }
            }

            cipher128(state);
            _mm_storeu_si128(output, state);
        }

        return nNeedLen;
    }

    size_t cipherCTR(const void* in, size_t inLength, void* out, size_t outLength) const
    {
        if (outLength < inLength)
        {
            return 0;
        }

        static const auto bswap_epi64 = _mm256_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
        static const auto increment = _mm256_set_epi64x(2, 0, 2, 0);
        auto counters = _mm256_add_epi64(_mm256_shuffle_epi8(_mm256_broadcastsi128_si256(m_iv), bswap_epi64), _mm256_set_epi64x(1, 0, 0, 0));

        auto len = inLength;
        auto input = reinterpret_cast<const __m256i*>(in);
        auto output = reinterpret_cast<__m256i*>(out);
        for (; len >= 32; len -= 32, ++input, ++output)
        {
            auto state = _mm256_shuffle_epi8(counters, bswap_epi64);
            cipher256(state);
            _mm256_storeu_si256(output, _mm256_xor_si256(state, _mm256_loadu_si256(input)));
            
            counters = _mm256_add_epi64(counters, increment);
        }

        if (len)
        {
            auto state = _mm256_shuffle_epi8(counters, bswap_epi64);
            cipher256(state);
            for (uint8_t i = 0; i < len; ++i)
            {
                reinterpret_cast<uint8_t*>(output)[i] = reinterpret_cast<const uint8_t*>(input)[i] ^ reinterpret_cast<uint8_t*>(&state)[i];
            }
        }

        return inLength;
    }

    size_t invCipherECB(const void* in, size_t inLength, void* out, size_t outLength) const
    {
        if (!inLength || inLength % 16)// invalid data length
        {
            return 0;
        }

        auto block = static_cast<int64_t>(inLength / 16) - 1;

        // sum padding length
        auto state128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in) + block);
        invCipher128(state128);

        uint8_t padLen = 0;
        if (Padding::Zeros == m_padding)
        {
            for (int8_t i = 15; i >= 0; --i, ++padLen)
            {
                if (reinterpret_cast<uint8_t*>(&state128)[i]) break;
            }
        }
        else
        {
            if (!isValidPKCS7Padding(state128))
            {
                return 0;
            }
            padLen = reinterpret_cast<uint8_t*>(&state128)[15];
        }

        if (outLength < inLength - padLen)
        {
            // out buffer too small
            return 0;
        }

        outLength = inLength - padLen;
        uint8_t endLen = padLen ? outLength % 16 : 16;
        memcpy(reinterpret_cast<__m128i*>(out) + block, &state128, endLen);

        auto len = inLength - 16;
		auto input = reinterpret_cast<const __m256i*>(in);
		auto output = reinterpret_cast<__m256i*>(out);
		for (; len >= 32; len -= 32, ++input, ++output)
		{
			auto state256 = _mm256_loadu_si256(input);
			invCipher256(state256);
			_mm256_storeu_si256(output, state256);
		}

        if (len == 16)
        {
			state128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input));
			invCipher128(state128);
			_mm_storeu_si128(reinterpret_cast<__m128i*>(output), state128);
        }

        return outLength;
    }

    size_t invCipherCBC(const void* in, size_t inLength, void* out, size_t outLength) const
    {
        if (!inLength || inLength % 16)// invalid data length
        {
            return 0;
        }

        auto block = static_cast<int64_t>(inLength / 16) - 1;
        auto input128 = reinterpret_cast<const __m128i*>(in);

        // sum padding length
        auto state128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input128 + block));
        invCipher128(state128);

        __m128i iv;
        if (block)
        {
            iv = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input128 + block - 1));
        }
        else
        {
            iv = m_iv;
        }
        state128 = _mm_xor_si128(state128, iv);

        uint8_t padLen = 0;
        if (Padding::Zeros == m_padding)
        {
            for (int8_t i = 15; i >= 0; --i, ++padLen)
            {
                if (reinterpret_cast<uint8_t*>(&state128)[i]) break;
            }
        }
        else
        {
            if (!isValidPKCS7Padding(state128))
            {
                return 0;
            }
            padLen = reinterpret_cast<uint8_t*>(&state128)[15];
        }

        if (outLength < inLength - padLen)
        {
            // out buffer too small
            return 0;
        }

        outLength = inLength - padLen;
        uint8_t endLen = padLen ? outLength % 16 : 16;
        memcpy(reinterpret_cast<__m128i*>(out) + block, &state128, endLen);

		auto input256 = reinterpret_cast<const __m256i*>(in);
		auto output256 = reinterpret_cast<__m256i*>(out);
        auto piv256 = reinterpret_cast<const __m256i*>(input128 + 1);

		auto len = inLength - 16;
        auto ivs = _mm256_setr_m128i(m_iv, _mm_loadu_si128(input128));
        for (; len >= 32; len -= 32, ++input256, ++output256, ++piv256)
        {
			auto state256 = _mm256_loadu_si256(input256);
            invCipher256(state256);
            _mm256_storeu_si256(output256, _mm256_xor_si256(state256, ivs));

			ivs = _mm256_loadu_si256(piv256);
        }

        if (len == 16)
        {
            state128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input256));
            invCipher128(state128);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output256), _mm_xor_si128(state128, _mm256_castsi256_si128(ivs)));
		}

        return outLength;
    }
};

using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;
