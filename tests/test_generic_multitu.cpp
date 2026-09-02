#include "../WAes-gen.hpp"

#include <cstddef>
#include <cstdint>

bool genericHeaderSecondTranslationUnitSmoke() {
  const uint8_t key[16] = {};
  const uint8_t plaintext[16] = {};
  uint8_t ciphertext[16] = {};

  CWAes128 aes(key, sizeof(key), nullptr, 0, Padding::Zeros);
  size_t ciphertextLength = sizeof(ciphertext);
  return aes.Cipher(plaintext, sizeof(plaintext), ciphertext,
                    ciphertextLength) &&
         ciphertextLength == sizeof(ciphertext);
}
