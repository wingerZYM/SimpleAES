#include "test_backend.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

template <int N> bool heapStorage() {
  const uint8_t key[N / 8] = {};
  std::array<uint8_t, 80> input;
  input.fill(0x42);
  std::array<uint8_t, 80> expected{};
  CWAes<N> reference(key, sizeof(key), nullptr, 0, Padding::Zeros);
  size_t size = expected.size();
  if (!reference.Cipher(input.data(), input.size(), expected.data(), size)) {
    return false;
  }
  const auto check = [&](const CWAes<N> &aes) {
    std::array<uint8_t, 80> output{};
    std::array<uint8_t, 80> recovered{};
    size_t length = output.size();
    size_t recoveredLength = recovered.size();
    return aes.Cipher(input.data(), input.size(), output.data(), length) &&
           length == expected.size() && output == expected &&
           aes.InvCipher(output.data(), length, recovered.data(),
                         recoveredLength) &&
           recoveredLength == input.size() && recovered == input;
  };
  std::unique_ptr<CWAes<N>> single(new CWAes<N>(reference));
  std::unique_ptr<CWAes<N>[]> array(new CWAes<N>[2]{reference, reference});
  auto shared = std::make_shared<CWAes<N>>(reference);
  std::vector<CWAes<N>> vector(3, reference);
  // An enclosing member also exercises storage not aligned to a SIMD width.
  struct Holder {
    char prefix;
    CWAes<N> aes;
    explicit Holder(const CWAes<N> &value) : prefix(0), aes(value) {}
  };
  auto holder = std::make_shared<Holder>(reference);
  return check(*single) && check(array[0]) && check(array[1]) &&
         check(*shared) && check(vector[2]) && check(holder->aes);
}

#if defined(WAES_TEST_VAES) || defined(WAES_TEST_VAES512)
static_assert(alignof(CWAes128) <= alignof(std::max_align_t),
              "C++11 allocation alignment");
static_assert(alignof(CWAes192) <= alignof(std::max_align_t),
              "C++11 allocation alignment");
static_assert(alignof(CWAes256) <= alignof(std::max_align_t),
              "C++11 allocation alignment");
#endif

int main() {
  if (!heapStorage<128>() || !heapStorage<192>() || !heapStorage<256>()) {
    return 7;
  }
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
