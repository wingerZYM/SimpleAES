#pragma once

#include "../WAes.hpp"
#include "test_data.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace WAesRegressionTests {

class GuardedBytes {
public:
  explicit GuardedBytes(size_t size) : size_(size) {
#if defined(_WIN32)
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    pageSize_ = info.dwPageSize;
    base_ = static_cast<uint8_t *>(VirtualAlloc(
        nullptr, pageSize_ * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!base_) {
      return;
    }

    DWORD oldProtection = 0;
    if (!VirtualProtect(base_ + pageSize_, pageSize_, PAGE_NOACCESS,
                        &oldProtection)) {
      VirtualFree(base_, 0, MEM_RELEASE);
      base_ = nullptr;
    }
#else
    const long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) {
      return;
    }
    pageSize_ = static_cast<size_t>(pageSize);
    void *allocation = mmap(nullptr, pageSize_ * 2, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (allocation == MAP_FAILED) {
      return;
    }
    base_ = static_cast<uint8_t *>(allocation);
    if (mprotect(base_ + pageSize_, pageSize_, PROT_NONE) != 0) {
      munmap(base_, pageSize_ * 2);
      base_ = nullptr;
    }
#endif
  }

  ~GuardedBytes() {
    if (!base_) {
      return;
    }
#if defined(_WIN32)
    VirtualFree(base_, 0, MEM_RELEASE);
#else
    munmap(base_, pageSize_ * 2);
#endif
  }

  GuardedBytes(const GuardedBytes &) = delete;
  GuardedBytes &operator=(const GuardedBytes &) = delete;

  uint8_t *data() const { return base_ ? base_ + pageSize_ - size_ : nullptr; }

private:
  uint8_t *base_ = nullptr;
  size_t pageSize_ = 0;
  size_t size_ = 0;
};

inline bool testScopedAAD(WAes::Backend backend) {
  static constexpr std::array<uint8_t, 7> outerAAD = {0x6f, 0x75, 0x74, 0x65,
                                                      0x72, 0x01, 0x02};
  static constexpr std::array<uint8_t, 5> innerAAD = {0x69, 0x6e, 0x6e, 0x65,
                                                      0x72};
  static constexpr std::array<uint8_t, WAes::GCMNonceSize> nonce = {
      0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67};
  const auto plaintext = TestData::getTestData(31);
  auto aes =
      WAes::Create<128>(backend, TestData::AES128_KEY,
                        TestData::AES128_KEY_SIZE, nullptr, 0, Padding::Zeros);
  if (!aes) {
    return false;
  }
  aes->SetIV(TestData::TEST_IV, TestData::IV_SIZE);

  auto encrypt = [&](std::array<uint8_t, 31> &ciphertext,
                     std::array<uint8_t, WAes::GCMTagSize> &tag) {
    size_t ciphertextLength = ciphertext.size();
    size_t tagLength = tag.size();
    return aes->CipherGCM(plaintext.data(), plaintext.size(), ciphertext.data(),
                          ciphertextLength, nonce.data(), nonce.size(),
                          tag.data(), tagLength) &&
           ciphertextLength == ciphertext.size() && tagLength == tag.size();
  };

  std::array<uint8_t, 31> outerCiphertext{};
  std::array<uint8_t, WAes::GCMTagSize> outerTag{};
  std::array<uint8_t, 31> innerCiphertext{};
  std::array<uint8_t, WAes::GCMTagSize> innerTag{};
  bool ok = true;
  {
    auto outer = aes->ScopeAAD(outerAAD.data(), outerAAD.size());
    const bool outerEncrypted = encrypt(outerCiphertext, outerTag);
    ok = static_cast<bool>(outer) && outerEncrypted;

    {
      auto inner = aes->ScopeAAD(std::span<const uint8_t>(innerAAD));
      const bool innerEncrypted = encrypt(innerCiphertext, innerTag);
      ok = ok && static_cast<bool>(inner) && innerEncrypted &&
           innerCiphertext == outerCiphertext && innerTag != outerTag;
    }

    std::array<uint8_t, 31> restoredCiphertext{};
    std::array<uint8_t, WAes::GCMTagSize> restoredTag{};
    const bool restoredEncrypted = encrypt(restoredCiphertext, restoredTag);
    ok = ok && restoredEncrypted && restoredCiphertext == outerCiphertext &&
         restoredTag == outerTag;

    auto invalid = aes->ScopeAAD(nullptr, 1);
    std::array<uint8_t, 31> invalidCiphertext{};
    std::array<uint8_t, WAes::GCMTagSize> invalidTag{};
    const bool invalidEncrypted = encrypt(invalidCiphertext, invalidTag);
    ok = ok && !static_cast<bool>(invalid) && invalidEncrypted &&
         invalidCiphertext == outerCiphertext && invalidTag == outerTag;
  }

  std::array<uint8_t, 31> rejectedCiphertext{};
  std::array<uint8_t, WAes::GCMTagSize> rejectedTag{};
  size_t rejectedLength = rejectedCiphertext.size();
  size_t rejectedTagLength = rejectedTag.size();
  const bool restoredMode =
      !aes->CipherGCM(plaintext.data(), plaintext.size(),
                      rejectedCiphertext.data(), rejectedLength, nonce.data(),
                      nonce.size(), rejectedTag.data(), rejectedTagLength) &&
      rejectedLength == 0 && rejectedTagLength == 0;

  bool invalidCallbackCalled = false;
  const bool invalidWithResult = aes->WithScopeAAD(nullptr, 1, [&]() {
    invalidCallbackCalled = true;
    return true;
  });

  bool validCallbackCalled = false;
  std::array<uint8_t, 31> withCiphertext{};
  std::array<uint8_t, WAes::GCMTagSize> withTag{};
  const bool validWithResult =
      aes->WithScopeAAD(std::span<const uint8_t>(innerAAD), [&]() {
        validCallbackCalled = true;
        return encrypt(withCiphertext, withTag);
      });

  std::array<uint8_t, 32> cbcCiphertext{};
  size_t cbcLength = cbcCiphertext.size();
  const bool restoredCBC = aes->Cipher(plaintext.data(), plaintext.size(),
                                       cbcCiphertext.data(), cbcLength) &&
                           cbcLength == 32;

  return ok && restoredMode && !invalidWithResult && !invalidCallbackCalled &&
         validWithResult && validCallbackCalled &&
         withCiphertext == innerCiphertext && withTag == innerTag &&
         restoredCBC;
}

inline bool run() {
  using namespace TestData;

  int passed = 0;
  int failed = 0;
  auto check = [&](bool condition, const std::string &name) {
    std::cout << (condition ? "[OK] " : "[FAIL] ") << name << '\n';
    condition ? ++passed : ++failed;
  };

  const auto available = WAes::AvailableBackends();
  std::cout << "\n=== WAes Regression Tests ===\n";

  for (auto backend : WAes::CompiledBackends()) {
    const bool listed = std::find(available.begin(), available.end(),
                                  backend) != available.end();
    const bool executable = WAes::IsBackendAvailable(backend);
    check(listed == executable,
          std::string("backend availability: ") + WAes::GetImplName(backend));
    if (!executable) {
      check(!WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE),
            std::string("reject unavailable backend: ") +
                WAes::GetImplName(backend));
    }
  }

  GuardedBytes guardedKey(AES192_KEY_SIZE);
  GuardedBytes guardedByte(1);
  GuardedBytes guardedBlock(16);
  GuardedBytes guardedCiphertext(16);
  GuardedBytes guardedOutput(16);
  const bool guardPagesReady = guardedKey.data() && guardedByte.data() &&
                               guardedBlock.data() &&
                               guardedCiphertext.data() && guardedOutput.data();
  check(guardPagesReady, "guard-page allocation");
  if (guardPagesReady) {
    std::memcpy(guardedKey.data(), AES192_KEY, AES192_KEY_SIZE);
    guardedByte.data()[0] = 0x42;
    std::memcpy(guardedBlock.data(), COMPREHENSIVE_TEST_DATA, 16);
  }

  for (auto backend : available) {
    const std::string name = WAes::GetImplName(backend);

    if (guardPagesReady) {
      auto aes192 =
          WAes::Create<192>(backend, guardedKey.data(), AES192_KEY_SIZE);
      check(static_cast<bool>(aes192), name + " AES-192 guarded key");

      std::array<uint8_t, 32> output{};
      size_t outputLength = output.size();
      auto partial = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                       nullptr, 0, Padding::PKCS7);
      check(partial &&
                partial->Cipher(guardedByte.data(), 1, output.data(),
                                outputLength) &&
                outputLength == 16,
            name + " guarded partial tail");

      outputLength = output.size();
      auto aligned = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                       nullptr, 0, Padding::PKCS7);
      check(aligned &&
                aligned->Cipher(guardedBlock.data(), 16, output.data(),
                                outputLength) &&
                outputLength == 32,
            name + " guarded aligned PKCS7 tail");

      auto exactZero = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                         nullptr, 0, Padding::Zeros);
      outputLength = 16;
      check(exactZero &&
                exactZero->Cipher(guardedBlock.data(), 16, guardedOutput.data(),
                                  outputLength) &&
                outputLength == 16,
            name + " guarded aligned Zero output");

      auto encryptor = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                         nullptr, 0, Padding::PKCS7);
      bool shortCbcOk = static_cast<bool>(encryptor);
      if (encryptor) {
        encryptor->SetIV(TEST_IV, IV_SIZE);
      }
      outputLength = 16;
      shortCbcOk = shortCbcOk &&
                   encryptor->Cipher(guardedByte.data(), 1, output.data(),
                                     outputLength) &&
                   outputLength == 16;
      if (shortCbcOk) {
        std::memcpy(guardedCiphertext.data(), output.data(), 16);
      }

      auto decryptor = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                         nullptr, 0, Padding::PKCS7);
      shortCbcOk = shortCbcOk && static_cast<bool>(decryptor);
      if (decryptor) {
        decryptor->SetIV(TEST_IV, IV_SIZE);
      }
      outputLength = output.size();
      shortCbcOk = shortCbcOk &&
                   decryptor->InvCipher(guardedCiphertext.data(), 16,
                                        output.data(), outputLength) &&
                   outputLength == 1 && output[0] == guardedByte.data()[0];
      check(shortCbcOk, name + " guarded one-block CBC decryption");
    }

    const uint8_t oneByte[] = {0x42};
    std::array<uint8_t, 16> padded{};
    padded[0] = oneByte[0];
    std::array<uint8_t, 16> shortCipher;
    std::array<uint8_t, 16> paddedCipher;
    shortCipher.fill(0xaa);
    paddedCipher.fill(0xbb);

    auto shortAes = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                      nullptr, 0, Padding::Zeros);
    auto paddedAes = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                       nullptr, 0, Padding::Zeros);
    size_t shortLength = shortCipher.size();
    size_t paddedLength = paddedCipher.size();
    const bool zeroPaddingOk =
        shortAes && paddedAes &&
        shortAes->Cipher(oneByte, 1, shortCipher.data(), shortLength) &&
        paddedAes->Cipher(padded.data(), padded.size(), paddedCipher.data(),
                          paddedLength) &&
        shortLength == 16 && paddedLength == 16 && shortCipher == paddedCipher;
    check(zeroPaddingOk, name + " Zero padding writes full tail");

    const auto inplacePlaintext = getTestData(79);
    auto cbcEncrypt = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                        nullptr, 0, Padding::PKCS7);
    bool inplaceOk = static_cast<bool>(cbcEncrypt);
    if (cbcEncrypt) {
      cbcEncrypt->SetIV(TEST_IV, IV_SIZE);
    }
    std::vector<uint8_t> inplaceBuffer(
        cbcEncrypt ? cbcEncrypt->SumCipherLength(inplacePlaintext.size()) : 0);
    size_t inplaceLength = inplaceBuffer.size();
    inplaceOk =
        inplaceOk &&
        cbcEncrypt->Cipher(inplacePlaintext.data(), inplacePlaintext.size(),
                           inplaceBuffer.data(), inplaceLength);

    auto cbcDecrypt = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                        nullptr, 0, Padding::PKCS7);
    inplaceOk = inplaceOk && static_cast<bool>(cbcDecrypt);
    if (cbcDecrypt) {
      cbcDecrypt->SetIV(TEST_IV, IV_SIZE);
    }
    size_t decryptedLength = inplaceLength;
    inplaceOk = inplaceOk &&
                cbcDecrypt->InvCipher(inplaceBuffer.data(), inplaceLength,
                                      inplaceBuffer.data(), decryptedLength) &&
                decryptedLength == inplacePlaintext.size() &&
                std::equal(inplacePlaintext.begin(), inplacePlaintext.end(),
                           inplaceBuffer.begin());
    check(inplaceOk, name + " in-place CBC decryption");

    const auto unalignedData = getTestData(31);
    std::array<uint8_t, 48> unalignedInput{};
    std::array<uint8_t, 48> unalignedCipher{};
    std::array<uint8_t, 48> unalignedPlain{};
    std::copy(unalignedData.begin(), unalignedData.end(),
              unalignedInput.begin() + 1);

    auto unalignedEncrypt = WAes::Create<128>(
        backend, AES128_KEY, AES128_KEY_SIZE, nullptr, 0, Padding::PKCS7);
    size_t unalignedCipherLength = unalignedCipher.size() - 1;
    bool unalignedOk = unalignedEncrypt &&
                       unalignedEncrypt->Cipher(
                           unalignedInput.data() + 1, unalignedData.size(),
                           unalignedCipher.data() + 1, unalignedCipherLength) &&
                       unalignedCipherLength == 32;

    auto unalignedDecrypt = WAes::Create<128>(
        backend, AES128_KEY, AES128_KEY_SIZE, nullptr, 0, Padding::PKCS7);
    size_t unalignedPlainLength = unalignedPlain.size() - 1;
    unalignedOk = unalignedOk && unalignedDecrypt &&
                  unalignedDecrypt->InvCipher(
                      unalignedCipher.data() + 1, unalignedCipherLength,
                      unalignedPlain.data() + 1, unalignedPlainLength) &&
                  unalignedPlainLength == unalignedData.size() &&
                  std::equal(unalignedData.begin(), unalignedData.end(),
                             unalignedPlain.begin() + 1);
    check(unalignedOk, name + " unaligned input/output");

    std::array<uint8_t, 16> counter = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                       0x16, 0x17, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xfe};
    std::array<uint8_t, 48> zeroInput{};
    std::array<uint8_t, 48> ctrCipher{};
    std::array<uint8_t, 48> expected{};

    auto ctr = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE);
    bool ctrOk = static_cast<bool>(ctr);
    if (ctr) {
      ctr->SetCounter(counter.data(), counter.size());
    }
    size_t ctrLength = ctrCipher.size();
    ctrOk = ctrOk &&
            ctr->Cipher(zeroInput.data(), zeroInput.size(), ctrCipher.data(),
                        ctrLength) &&
            ctrLength == ctrCipher.size();

    auto counterBlock = counter;
    for (size_t block = 0; block < 3 && ctrOk; ++block) {
      auto ecb = WAes::Create<128>(backend, AES128_KEY, AES128_KEY_SIZE,
                                   nullptr, 0, Padding::Zeros);
      size_t blockLength = 16;
      ctrOk = ecb &&
              ecb->Cipher(counterBlock.data(), counterBlock.size(),
                          expected.data() + block * 16, blockLength) &&
              blockLength == 16;
      for (int i = 15; i >= 0; --i) {
        if (++counterBlock[static_cast<size_t>(i)] != 0) {
          break;
        }
      }
    }
    check(ctrOk && ctrCipher == expected, name + " CTR full-128 carry policy");
    check(testScopedAAD(backend), name + " scoped AAD state restoration");
  }

  std::array<uint8_t, 16> serializedCounter = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  std::array<uint8_t, 17> zeroInput{};
  std::array<uint8_t, 17> numericOutput{};
  std::array<uint8_t, 17> byteOutput{};
  auto numeric =
      WAes::Create<128>(WAes::Backend::Generic, AES128_KEY, AES128_KEY_SIZE);
  auto bytes =
      WAes::Create<128>(WAes::Backend::Generic, AES128_KEY, AES128_KEY_SIZE);
  bool numericOk = numeric && bytes;
  if (numeric) {
    numeric->SetCounter(UINT64_C(0x0001020304050607), UINT32_C(0x08090a0b),
                        UINT32_C(0x0c0d0e0f));
  }
  if (bytes) {
    bytes->SetCounter(serializedCounter.data(), serializedCounter.size());
  }
  size_t numericLength = numericOutput.size();
  size_t byteLength = byteOutput.size();
  numericOk = numericOk &&
              numeric->Cipher(zeroInput.data(), zeroInput.size(),
                              numericOutput.data(), numericLength) &&
              bytes->Cipher(zeroInput.data(), zeroInput.size(),
                            byteOutput.data(), byteLength) &&
              numericOutput == byteOutput;
  check(numericOk, "numeric counter uses big-endian serialization");

  std::cout << "Regression tests: " << passed << " passed, " << failed
            << " failed\n";
  return failed == 0;
}

} // namespace WAesRegressionTests
