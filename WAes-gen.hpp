#pragma once

#include <cstdint>
#include <memory.h>

// AES // ECB/CBC/CTR // PKCS7Padding/ZerosPadding

enum class Padding
{
	Zeros,
	PKCS7,
};

template <int> struct aesN;
template <> struct aesN<128> { enum { Nk = 4, Nr = 10 }; };
template <> struct aesN<192> { enum { Nk = 6, Nr = 12 }; };
template <> struct aesN<256> { enum { Nk = 8, Nr = 14 }; };

template <int N>
class CWAes
{
public:
	// If |iv| is null, mode is ECB; |iv| not be null, mode is CBC; if it is CTR, after set counter.
	// CTR mode must be NonePadding!
	CWAes(const void* key, size_t keyLength, const void* iv = nullptr, size_t ivLength = 16, Padding padding = Padding::PKCS7)
		: m_padding(padding), m_mode(Mode::ECB)
	{
		if (keyLength < 4 * Nk)// key padding zero
		{
			uint8_t tk[4 * Nk] = {};

			memcpy(tk, key, keyLength);

			keyExpansion(tk);
		}
		else
		{
			keyExpansion(reinterpret_cast<const uint8_t*>(key));
		}

		if (iv)// iv padding zero
		{
			m_mode = Mode::CBC;
			memcpy(m_iv, iv, ivLength > 16 ? 16 : ivLength);
		}
	}

	~CWAes() = default;

	static size_t SumCipherLength(size_t nInLen)
	{
		return (nInLen / (4 * Nb) + 1) * (4 * Nb);
	}

	// Sets the counter value when in CBC mode. 
	// The maximum length is 16 byte, if not enough padding zero.
	void SetIV(const void* iv, size_t length)
	{
		m_mode = Mode::CBC;
		memset(m_iv, 0, sizeof(m_iv));
		memcpy(m_iv, iv, length > 16 ? 16 : length);
	}

	// Sets the counter value when in CTR mode. 
	// The maximum length is 16 byte, if not enough padding zero.
	void SetCounter(const void* counter, size_t length)
	{
		m_mode = Mode::CTR;
		memset(m_iv, 0, sizeof(m_iv));
		memcpy(m_iv, counter, length > 16 ? 16 : length);
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

	static const uint8_t m_sBox[256];
	static const uint8_t m_invSbox[256];
	uint8_t m_w[Nb * (Nr + 1) * 4];
	uint8_t m_iv[16] = {};
	Padding m_padding;
	Mode m_mode;

	uint8_t* cipher(uint8_t* state) const
	{
		addRoundKey(state, 0);

		for (uint8_t r = 1; r < Nr; ++r)
		{
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

	uint8_t* invCipher(uint8_t* state) const
	{
		addRoundKey(state, Nr);

		for (uint8_t r = Nr - 1; r >= 1; --r)
		{
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

	void keyExpansion(const uint8_t* key)
	{
		static const uint8_t rc[] = { 0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

		auto subWord = [](uint8_t *w)
		{
			for (uint8_t i = 0; i < 4; ++i)
			{
				w[i] = m_sBox[16 * ((w[i] & 0xf0) >> 4) | (w[i] & 0x0f)];
			}
		};

		for (uint8_t i = 0; i < Nk; ++i)
		{
			m_w[4 * i + 0] = key[4 * i + 0];
			m_w[4 * i + 1] = key[4 * i + 1];
			m_w[4 * i + 2] = key[4 * i + 2];
			m_w[4 * i + 3] = key[4 * i + 3];
		}

		uint8_t temp[4];
		for (int i = Nk; i < Nb * (Nr + 1); ++i)
		{
			temp[0] = m_w[4 * (i - 1) + 0];
			temp[1] = m_w[4 * (i - 1) + 1];
			temp[2] = m_w[4 * (i - 1) + 2];
			temp[3] = m_w[4 * (i - 1) + 3];


			if (0 == i % Nk)
			{
				// rot word
				auto tmp = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = tmp;

				subWord(temp);

				temp[0] ^= rc[i / Nk];
			}
			else if (Nk > 6 && (i % Nk == 4))
			{
				subWord(temp);
			}

			m_w[4 * i + 0] = m_w[4 * (i - Nk) + 0] ^ temp[0];
			m_w[4 * i + 1] = m_w[4 * (i - Nk) + 1] ^ temp[1];
			m_w[4 * i + 2] = m_w[4 * (i - Nk) + 2] ^ temp[2];
			m_w[4 * i + 3] = m_w[4 * (i - Nk) + 3] ^ temp[3];
		}
	}

	uint8_t gfmul(uint8_t a, uint8_t b) const
	{
		uint8_t bw[4];
		uint8_t res = 0;
		bw[0] = b;
		for (uint8_t i = 1; i < Nb; ++i)
		{
			bw[i] = bw[i - 1] << 1;
			if (bw[i - 1] & 0x80)
			{
				bw[i] ^= 0x1b;
			}
		}
		for (uint8_t i = 0; i < Nb; ++i)
		{
			if ((a >> i) & 0x01)
			{
				res ^= bw[i];
			}
		}
		return res;
	}

	void subBytes(uint8_t *state) const
	{
		for (uint8_t i = 0; i < 4 * Nb; ++i)
		{
			state[i] = m_sBox[16 * ((state[i] & 0xf0) >> 4) | (state[i] & 0x0f)];
		}
	}

	void shiftRows(uint8_t *state) const
	{
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

	void mixColumns(uint8_t *state) const
	{
		uint8_t arr[4];
		for (int i = 0; i < 4; ++i, state += 4)
		{
			memcpy(arr, state, 4);

			state[0] = gfmul(0x02, arr[0]) ^ gfmul(0x03, arr[1]) ^ arr[2] ^ arr[3];
			state[1] = arr[0] ^ gfmul(0x02, arr[1]) ^ gfmul(0x03, arr[2]) ^ arr[3];
			state[2] = arr[0] ^ arr[1] ^ gfmul(0x02, arr[2]) ^ gfmul(0x03, arr[3]);
			state[3] = gfmul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ gfmul(0x02, arr[3]);
		}
	}

	void addRoundKey(uint8_t *state, uint8_t r) const
	{
		auto rv = reinterpret_cast<uint64_t*>(state);
		auto rk = reinterpret_cast<const uint64_t*>(m_w + 4 * Nb * r);
		rv[0] ^= rk[0];
		rv[1] ^= rk[1];
	}

	void invSubBytes(uint8_t *state) const
	{
		for (uint8_t i = 0; i < 4 * Nb; ++i)
		{
			state[i] = m_invSbox[16 * ((state[i] & 0xf0) >> 4) | (state[i] & 0x0f)];
		}
	}

	void invShiftRows(uint8_t *state) const
	{
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

	void invMixColumns(uint8_t *state) const
	{
		uint8_t arr[4];
		for (uint8_t i = 0; i < 4; ++i, state += 4)
		{
			memcpy(arr, state, 4);

			state[0] = gfmul(0x0e, arr[0]) ^ gfmul(0x0b, arr[1]) ^ gfmul(0x0d, arr[2]) ^ gfmul(0x09, arr[3]);
			state[1] = gfmul(0x09, arr[0]) ^ gfmul(0x0e, arr[1]) ^ gfmul(0x0b, arr[2]) ^ gfmul(0x0d, arr[3]);
			state[2] = gfmul(0x0d, arr[0]) ^ gfmul(0x09, arr[1]) ^ gfmul(0x0e, arr[2]) ^ gfmul(0x0b, arr[3]);
			state[3] = gfmul(0x0b, arr[0]) ^ gfmul(0x0d, arr[1]) ^ gfmul(0x09, arr[2]) ^ gfmul(0x0e, arr[3]);
		}
	}

	bool isValidPKCS7Padding(uint8_t *state) const
	{
		const auto pad = state[15];
		if (pad > 16 || pad == 0)
			return false;

		for (int8_t i = 16 - pad; i < 15; ++i)
		{
			if (pad != state[i]) return false;
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
		auto input = reinterpret_cast<const uint8_t*>(in);
		auto output = reinterpret_cast<uint8_t*>(out);
		for (; len >= 16; len -= 16, input += 16, output += 16)
		{
			memcpy(output, input, 16);
			cipher(output);
		}

		// Padding
		auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<uint8_t>(len);
		memcpy(output, input, len);
		memset(output + len, pad, pad);

		cipher(output);

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
		auto input = reinterpret_cast<const uint8_t*>(in);
		auto output = reinterpret_cast<uint8_t*>(out);
		const auto* piv = m_iv;
		for (; len >= 16; len -= 16, input += 16, output += 16)
		{
			for (uint8_t i = 0; i < 4 * Nb; ++i)
			{
				output[i] = input[i] ^ piv[i];
			}
			cipher(output);
			piv = output;
		}

		// Padding
		auto pad = Padding::Zeros == m_padding ? 0 : 16 - static_cast<uint8_t>(len);
		uint8_t pos = 0;
		for (; pos < len; ++pos)
		{
			output[pos] = input[pos] ^ piv[pos];
		}
		for (; pos < 16; ++pos)
		{
			output[pos] = pad ^ piv[pos];
		}

		cipher(output);

		return nNeedLen;
	}

	size_t cipherCTR(const void* in, size_t inLength, void* out, size_t outLength) const
	{
		if (outLength < inLength)
		{
			return 0;
		}

		uint8_t counter[16];
		memcpy(counter, m_iv, 16);
		auto addCounter = [&counter]()
		{
			for (auto pos = counter + 15; pos >= counter; --pos)
			{
				if (UINT8_MAX == *pos)
				{
					*pos = 0;
				}
				else
				{
					++*pos;
					break;
				}
			}
		};

		uint8_t state[4 * Nb];
		int64_t len = inLength;
		auto input = reinterpret_cast<const uint8_t*>(in);
		auto output = reinterpret_cast<uint8_t*>(out);

		for (; len > 0; len -= 16, input += 16, output += 16)
		{
			memcpy(state, counter, 16);

			cipher(state);

			for (uint8_t i = 0; i < 16 && i < len; ++i)
			{
				output[i] = state[i] ^ input[i];
			}

			addCounter();
		}

		return inLength;
	}

	size_t invCipherECB(const void* in, size_t inLength, void* out, size_t outLength) const
	{
		if (inLength % 16)// invalid data length
		{
			return 0;
		}

		uint8_t state[4 * Nb];
		auto input = reinterpret_cast<const uint8_t*>(in) + inLength - 16;

		// sum padding length
		memcpy(state, input, 16);
		invCipher(state);

		uint8_t padLen;
		if (Padding::Zeros == m_padding)
		{
			padLen = 0;
			for (int8_t i = 15; i >= 0; --i)
			{
				if (state[i])
				{
					break;
				}
				++padLen;
			}
		}
		else
		{
			if (!isValidPKCS7Padding(state))
			{
				return 0;
			}
			padLen = state[15];
		}

		if (outLength < inLength - padLen)
		{
			// out buffer too small
			return 0;
		}

		outLength = inLength - padLen;
		uint8_t endLen = outLength % 16;
		auto output = reinterpret_cast<uint8_t*>(out) + inLength - 16;

		memcpy(output, state, endLen);
		for (input -= 16, output -= 16; input >= in; input -= 16, output -= 16)
		{
			memcpy(output, input, 16);
			invCipher(output);
		}

		return outLength;
	}

	size_t invCipherCBC(const void* in, size_t inLength, void* out, size_t outLength) const
	{
		if (inLength % 16)// invalid data length
		{
			return 0;
		}

		uint8_t state[4 * Nb];
		auto input = reinterpret_cast<const uint8_t*>(in) + inLength - 16;

		// sum padding length
		memcpy(state, input, 16);
		invCipher(state);

		const auto* piv = in != input ? input - 16 : m_iv;
		for (uint8_t i = 0; i < 4 * Nb; ++i)
		{
			state[i] ^= piv[i];
		}

		uint8_t padLen;
		if (Padding::Zeros == m_padding)
		{
			padLen = 0;
			for (int8_t i = 15; i >= 0; --i)
			{
				if (state[i])
				{
					break;
				}
				++padLen;
			}
		}
		else
		{
			if (!isValidPKCS7Padding(state))
			{
				return 0;
			}
			padLen = state[15];
		}

		if (outLength < inLength - padLen)
		{
			// out buffer too small
			return 0;
		}

		outLength = inLength - padLen;
		uint8_t endLen = outLength % 16;
		auto output = reinterpret_cast<uint8_t*>(out) + inLength - 16;

		memcpy(output, state, endLen);
		for (input -= 16, output -= 16; input >= in; input -= 16, output -= 16)
		{
			memcpy(output, input, 16);
			invCipher(output);

			piv = in != input ? input - 16 : m_iv;
			for (uint8_t i = 0; i < 4 * Nb; ++i)
			{
				output[i] ^= piv[i];
			}
		}

		return outLength;
	}
};

template <int N>
const uint8_t CWAes<N>::m_sBox[256] = {
	/* 0 1 2 3 4 5 6 7 8 9 a b c d e f */
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, /*0*/
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, /*1*/
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, /*2*/
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, /*3*/
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, /*4*/
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, /*5*/
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, /*6*/
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, /*7*/
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, /*8*/
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, /*9*/
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, /*a*/
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, /*b*/
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, /*c*/
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, /*d*/
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, /*e*/
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, /*f*/
};

template <int N>
const uint8_t CWAes<N>::m_invSbox[256] = {
	/* 0 1 2 3 4 5 6 7 8 9 a b c d e f */
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, /*0*/
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, /*1*/
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, /*2*/
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, /*3*/
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, /*4*/
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, /*5*/
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, /*6*/
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, /*7*/
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, /*8*/
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, /*9*/
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, /*a*/
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, /*b*/
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, /*c*/
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, /*d*/
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, /*e*/
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, /*f*/
};

using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;
