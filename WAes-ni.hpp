#pragma once

#include <cstdint>
#include <memory.h>

#include <wmmintrin.h>

// AES // ECB/CBC/CTR // PKCS7Padding/ZerosPadding

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
	// If |iv| is null, mode is ECB; |iv| not be null, mode is CBC; if it is CTR, after set counter.
	// CTR mode must be NonePadding!
	CWAes(const void* key, size_t keyLength, const void *iv = nullptr, size_t ivLength = 16, Padding padding = Padding::PKCS7)
		: m_padding(padding), m_mode(Mode::ECB)
	{
		if (keyLength < 4 * Nk)// key padding zero
		{
			uint8_t tk[4 * Nk] = {};

			memcpy(tk, key, keyLength);

			aesN<N>::keyExpansion(tk, m_w);
		}
		else
		{
			aesN<N>::keyExpansion(reinterpret_cast<const uint8_t*>(key), m_w);
		}

		// imc
		for (uint8_t i = Nr + 1; i < Nr * 2; ++i)
		{
			m_w[i] = _mm_aesimc_si128(m_w[Nr * 2 - i]);
		}

		if (iv)// iv padding zero
		{
			m_mode = Mode::CBC;
			memcpy(&m_iv, iv, ivLength > 16 ? 16 : ivLength);
		}
	}

	~CWAes() = default;

	static size_t SumCipherLength(size_t nInLen)
	{
		return (nInLen / (4 * Nb) + 1) * (4 * Nb);
	}

	// Sets the counter value when in CBC mode. 
	// The maximum length is 16 byte, if not enough padding zero.
	void SetIV(const void *iv, size_t length)
	{
		m_mode = Mode::CBC;
		memset(&m_iv, 0, sizeof(m_iv));
		memcpy(&m_iv, iv, length > 16 ? 16 : length);
	}

	// Sets the counter value when in CTR mode. 
	// The maximum length is 16 byte, if not enough padding zero.
	void SetCounter(const void *counter, size_t length)
	{
		m_mode = Mode::CTR;
		memset(&m_iv, 0, sizeof(m_iv));
		memcpy(&m_iv, counter, length > 16 ? 16 : length);
	}

	size_t Cipher(const void *in, size_t inLength, void *out, size_t outLength) const
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

	size_t InvCipher(const void *in, size_t inLength, void *out, size_t outLength) const
	{
		switch (m_mode)
		{
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

	enum class Mode
	{
		ECB,
		CBC,
		CTR,
	};
	__m128i m_w[Nr * 2];
	__m128i m_iv = {};
	Padding m_padding;
	Mode m_mode;

	void cipher(__m128i& state) const
	{
		state = _mm_xor_si128(state, m_w[0]);

		for (uint8_t r = 1; r < Nr; ++r)
		{
			state = _mm_aesenc_si128(state, m_w[r]);
		}

		state = _mm_aesenclast_si128(state, m_w[Nr]);
	}

	void invCipher(__m128i& state) const
	{
		state = _mm_xor_si128(state, m_w[Nr]);

		for (uint8_t r = Nr + 1; r < Nr * 2; ++r)
		{
			state = _mm_aesdec_si128(state, m_w[r]);
		}

		state = _mm_aesdeclast_si128(state, m_w[0]);
	}

	bool isValidPKCS7Padding(const __m128i &state) const
	{
		auto* pos = reinterpret_cast<const uint8_t*>(&state);
		if (pos[15] > 16 || pos[15] == 0)
			return false;

		for (int8_t i = 16 - pos[15]; i < 15; ++i)
		{
			if (pos[15] != pos[i]) return false;
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

		__m128i state;
		auto len = inLength;
		auto input = reinterpret_cast<const __m128i*>(in);
		auto output = reinterpret_cast<__m128i*>(out);
		for (; len >= 16; len -= 16, ++input, ++output)
		{
			state = _mm_loadu_si128(input);
			cipher(state);
			_mm_storeu_si128(output, state);
		}

		state = _mm_loadu_si128(input);
		// Padding
		auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<int>(len);
		memset(reinterpret_cast<uint8_t*>(&state) + len, pad, 16 - len);

		cipher(state);
		_mm_storeu_si128(output, state);

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
			cipher(state);
			_mm_storeu_si128(output, state);
		}

		// Padding
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

		cipher(state);
		_mm_storeu_si128(output, state);

		return nNeedLen;
	}

	size_t cipherCTR(const void* in, size_t inLength, void* out, size_t outLength) const
	{
		if (outLength < inLength)
		{
			return 0;
		}

		auto counter = m_iv;
		auto addCounter = [&counter]()
		{
			auto pos = reinterpret_cast<uint8_t*>(&counter);
			for (int8_t i = 15; i >= 0; --i)
			{
				if (UINT8_MAX == pos[i])
				{
					pos[i] = 0;
				}
				else
				{
					++pos[i];
					break;
				}
			}
		};

		int64_t len = inLength / 16;
		auto input = reinterpret_cast<const __m128i*>(in);
		auto output = reinterpret_cast<__m128i*>(out);
		for (int64_t i = 0; i < len; ++i, ++input, ++output)
		{
			auto state = _mm_load_si128(&counter);
			cipher(state);
			_mm_storeu_si128(output, _mm_xor_si128(_mm_loadu_si128(input), state));

			addCounter();
		}

		int8_t endLen = inLength % 16;
		if (endLen)
		{
			auto state = _mm_load_si128(&counter);
			cipher(state);
			for (int8_t i = 0; i < endLen; ++i)
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

		auto len = static_cast<int64_t>(inLength) / 16 - 1;
		auto input = reinterpret_cast<const __m128i*>(in);

		// sum padding length
		auto state = _mm_loadu_si128(input + len);
		invCipher(state);

		uint8_t padLen = 0;
		if (Padding::Zeros == m_padding)
		{
			for (int8_t i = 15; i >= 0; --i, ++padLen)
			{
				if (reinterpret_cast<uint8_t*>(&state)[i]) break;
			}
		}
		else
		{
			if (!isValidPKCS7Padding(state))
			{
				return 0;
			}
			padLen = reinterpret_cast<uint8_t*>(&state)[15];
		}

		if (outLength < inLength - padLen)
		{
			// out buffer too small
			return 0;
		}

		outLength = inLength - padLen;
		uint8_t endLen = outLength % 16;
		auto output = reinterpret_cast<__m128i*>(out);
		memcpy(output + len, &state, endLen);

		for (int i = 0; i < len; ++i, ++input, ++output)
		{
			state = _mm_loadu_si128(input);
			invCipher(state);
			_mm_storeu_si128(output, state);
		}

		return outLength;
	}

	size_t invCipherCBC(const void* in, size_t inLength, void* out, size_t outLength) const
	{
		if (!inLength || inLength % 16)// invalid data length
		{
			return 0;
		}

		auto len = static_cast<int64_t>(inLength) / 16 - 1;
		auto input = reinterpret_cast<const __m128i*>(in);

		// sum padding length
		auto state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + len));
		invCipher(state);

		__m128i iv;
		if (len)
		{
			iv = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + len - 1));
		}
		else
		{
			iv = m_iv;
		}
		state = _mm_xor_si128(state, iv);

		uint8_t padLen = 0;
		if (Padding::Zeros == m_padding)
		{
			for (int8_t i = 15; i >= 0; --i, ++padLen)
			{
				if (reinterpret_cast<uint8_t*>(&state)[i]) break;
			}
		}
		else
		{
			if (!isValidPKCS7Padding(state))
			{
				return 0;
			}
			padLen = reinterpret_cast<uint8_t*>(&state)[15];
		}

		if (outLength < inLength - padLen)
		{
			// out buffer too small
			return 0;
		}

		outLength = inLength - padLen;
		uint8_t endLen = outLength % 16;
		auto output = reinterpret_cast<__m128i*>(out);
		memcpy(output + len, &state, endLen);

		iv = m_iv;
		for (int i = 0; i < len; ++i, ++input, ++output)
		{
			state = _mm_loadu_si128(input);
			invCipher(state);
			_mm_storeu_si128(output, _mm_xor_si128(state, iv));

			iv = _mm_loadu_si128(input);
		}

		return outLength;
	}
};

using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;
