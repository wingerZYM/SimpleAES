// Opt-in Linux regression: alias a 1 MiB backing store across a large virtual
// buffer so 2/32 GiB loop boundaries need only a small amount of physical RAM.
#include "test_backend.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

class RepeatedMapping {
public:
  RepeatedMapping(size_t length, const uint8_t block[16]) {
    const size_t chunk = 1024 * 1024;
    if (length > (size_t(-1) - chunk + 1)) {
      return;
    }
    size_ = ((length + chunk - 1) / chunk) * chunk;
    const int fd =
        static_cast<int>(syscall(SYS_memfd_create, "waes-large-test", 0));
    if (fd < 0) {
      return;
    }
    if (ftruncate(fd, chunk) != 0) {
      close(fd);
      return;
    }
    void *reserved =
        mmap(nullptr, size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserved == MAP_FAILED) {
      close(fd);
      return;
    }
    data_ = static_cast<uint8_t *>(reserved);
    for (size_t offset = 0; offset < size_; offset += chunk) {
      if (mmap(data_ + offset, chunk, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED) {
        munmap(data_, size_);
        data_ = nullptr;
        break;
      }
    }
    close(fd);
    if (data_) {
      for (size_t offset = 0; offset < chunk; offset += 16) {
        std::memcpy(data_ + offset, block, 16);
      }
    }
  }
  ~RepeatedMapping() {
    if (data_) {
      munmap(data_, size_);
    }
  }
  RepeatedMapping(const RepeatedMapping &) = delete;
  RepeatedMapping &operator=(const RepeatedMapping &) = delete;
  uint8_t *data() const { return data_; }

private:
  uint8_t *data_ = nullptr;
  size_t size_ = 0;
};

bool runLarge(size_t length, bool cbc) {
  const uint8_t key[16] = {};
  const uint8_t iv[16] = {};
  std::array<uint8_t, 16> plaintext;
  plaintext.fill(0x42);
  std::array<uint8_t, 32> block{};
  CWAes128 encryptor(key, sizeof(key), nullptr, 0, Padding::Zeros);
  size_t blockSize = block.size();
  if (!encryptor.Cipher(plaintext.data(), plaintext.size(), block.data(),
                        blockSize) ||
      blockSize != 16) {
    return false;
  }
  std::array<uint8_t, 16> expected = plaintext;
  if (cbc) {
    for (size_t i = 0; i < expected.size(); ++i) {
      expected[i] ^= block[i];
    }
  }
  // Keep zero-padding removal out of this loop-width regression.
  if (expected.back() == 0) {
    return false;
  }
  RepeatedMapping input(length, block.data());
  RepeatedMapping output(length, iv);
  if (!input.data() || !output.data()) {
    std::fprintf(stderr, "large virtual mapping failed\n");
    return false;
  }
  CWAes128 aes(key, sizeof(key), cbc ? iv : nullptr, sizeof(iv),
               Padding::Zeros);
  size_t size = length;
  return aes.InvCipher(input.data(), length, output.data(), size) &&
         size == length &&
         std::memcmp(output.data() + 16, expected.data(), 16) == 0 &&
         std::memcmp(output.data() + length - 16, expected.data(), 16) == 0;
}

int main(int argc, char **argv) {
  const size_t length =
      argc > 1 ? static_cast<size_t>(std::strtoull(argv[1], nullptr, 10))
               : size_t(2147483664ULL);
  if (sizeof(size_t) < 8 || length < 32 || length % 16 != 0) {
    return 2;
  }
#if defined(WAES_TEST_UNIFIED)
#if defined(WAES_ARMV8)
  g_testBackend = WAes::Backend::ArmV8;
#elif defined(WAES_X86_SIMD)
  g_testBackend = WAes::Backend::AesNi;
#else
  return 2;
#endif
#endif
  for (bool cbc : {false, true}) {
    std::printf("Decrypting %zu bytes, mode=%s\n", length, cbc ? "CBC" : "ECB");
    std::fflush(stdout);
    if (!runLarge(length, cbc)) {
      return 1;
    }
  }
  return 0;
}
