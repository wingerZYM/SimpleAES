#include <cstddef>
#include <cstdint>
#include <cstring>

static size_t calls = 0;
static bool failRandom(void *buffer, size_t length) noexcept {
  ++calls;
  std::memset(buffer, 0xa5, length);
  return false;
}
#define WAES_RANDOM_BYTES(buffer, length) failRandom(buffer, length)
#include "test_backend.hpp"

int main() {
  const uint8_t key[16] = {};
  const uint8_t input[1] = {0x42};
  uint8_t output[1] = {0x7e};
  CWAes128 aes(key, sizeof(key));
  GCMResult result{};
  result.nonce.fill(0x12);
  result.tag.fill(0x34);
  const GCMResult original = result;
  size_t size = sizeof(output);
  if (!aes.SetAAD() ||
      aes.CipherGCM(input, sizeof(input), output, size, result) || size != 0 ||
      output[0] != 0x7e || result.nonce != original.nonce ||
      result.tag != original.tag || calls != 1) {
    return 1;
  }
  // The explicit-nonce API must remain usable when the RNG is unavailable.
  const uint8_t nonce[WAesGCMNonceSize] = {};
  uint8_t tag[WAesGCMTagSize] = {};
  size_t tagSize = sizeof(tag);
  size = sizeof(output);
  return aes.CipherGCM(input, sizeof(input), output, size, nonce, sizeof(nonce),
                       tag, tagSize) &&
                 size == 1 && tagSize == sizeof(tag) && calls == 1
             ? 0
             : 2;
}
