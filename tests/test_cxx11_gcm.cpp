#if defined(WAES_TEST_AES_NI)
#include "../WAes-ni.hpp"
#elif defined(WAES_TEST_VAES)
#include "../WAes-vaes.hpp"
#elif defined(WAES_TEST_VAES512)
#include "../WAes-vaes512.hpp"
#elif defined(WAES_TEST_ARMV8)
#include "../WAes-armv8.hpp"
#else
#include "../WAes-gen.hpp"
#endif

#include <cstddef>
#include <cstdint>

int main() {
  const uint8_t key[32] = {};
  const uint8_t nonce[WAesGCMNonceSize] = {};
  const uint8_t input[1] = {0x42};
  uint8_t ciphertext[1] = {};
  uint8_t plaintext[1] = {};
  uint8_t tag[WAesGCMTagSize] = {};

  CWAes256 aes(key, sizeof(key));
  if (!aes.SetAAD(nullptr, 0)) {
    return 1;
  }

  size_t ciphertextLength = sizeof(ciphertext);
  size_t tagLength = sizeof(tag);
  if (!aes.CipherGCM(input, sizeof(input), ciphertext, ciphertextLength, nonce,
                     sizeof(nonce), tag, tagLength)) {
    return 2;
  }

  size_t plaintextLength = sizeof(plaintext);
  if (!aes.InvCipherGCM(ciphertext, ciphertextLength, plaintext,
                        plaintextLength, nonce, sizeof(nonce), tag,
                        tagLength)) {
    return 3;
  }

  GCMResult result;
  ciphertextLength = sizeof(ciphertext);
  if (!aes.CipherGCM(input, sizeof(input), ciphertext, ciphertextLength,
                     result)) {
    return 4;
  }

  plaintextLength = sizeof(plaintext);
  if (!aes.InvCipherGCM(ciphertext, ciphertextLength, plaintext,
                        plaintextLength, result)) {
    return 5;
  }

  return plaintextLength == sizeof(input) && plaintext[0] == input[0] ? 0 : 6;
}
