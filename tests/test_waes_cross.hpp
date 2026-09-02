#pragma once

#include "../WAes.hpp"
#include "test_data.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace WAesCrossTests {

class AesProxy {
  WAes::Ptr impl_;

public:
  AesProxy(WAes::Backend backend, int keyBits, const void *key,
           size_t keyLength, Padding padding) {
    switch (keyBits) {
    case 128:
      impl_ = WAes::Create<128>(backend, key, keyLength, nullptr, 0, padding);
      break;
    case 192:
      impl_ = WAes::Create<192>(backend, key, keyLength, nullptr, 0, padding);
      break;
    case 256:
      impl_ = WAes::Create<256>(backend, key, keyLength, nullptr, 0, padding);
      break;
    }
  }

  void setIV(const void *iv, size_t length) {
    if (impl_)
      impl_->SetIV(iv, length);
  }

  void setCounter(const void *counter, size_t length) {
    if (impl_)
      impl_->SetCounter(counter, length);
  }

  std::vector<uint8_t> cipher(const std::vector<uint8_t> &plaintext) const {
    if (!impl_)
      return {};
    size_t outputLength = impl_->SumCipherLength(plaintext.size());
    std::vector<uint8_t> output(outputLength);
    if (!impl_->Cipher(plaintext.data(), plaintext.size(), output.data(),
                       outputLength))
      return {};
    output.resize(outputLength);
    return output;
  }

  std::vector<uint8_t> invCipher(const std::vector<uint8_t> &ciphertext,
                                 size_t plaintextLength) const {
    if (!impl_)
      return {};
    std::vector<uint8_t> output(plaintextLength);
    size_t outputLength = output.size();
    if (!impl_->InvCipher(ciphertext.data(), ciphertext.size(), output.data(),
                          outputLength))
      return {};
    output.resize(outputLength);
    return output;
  }
};

inline bool run() {
  using namespace TestData;

  const auto backends = WAes::AvailableBackends();
  if (backends.size() < 2) {
    std::cout << "\n[Cross-validation] Only one backend available, skipping.\n";
    return true;
  }

  std::cout << "\n=== WAes Cross-Backend Validation ===\nBackends:";
  for (auto backend : backends)
    std::cout << ' ' << WAes::GetImplName(backend);
  std::cout << "\n\n";

  struct KeyCase {
    int bits;
    const uint8_t *key;
    size_t length;
  };
  const KeyCase keys[] = {{128, AES128_KEY, AES128_KEY_SIZE},
                          {192, AES192_KEY, AES192_KEY_SIZE},
                          {256, AES256_KEY, AES256_KEY_SIZE}};

  struct ModeCase {
    const char *name;
    bool usesIV;
    bool usesCounter;
  };
  const ModeCase modes[] = {{"ECB", false, false},
                            {"CBC", true, false},
                            {"CTR", false, true}};

  int passed = 0;
  int failed = 0;
  const WAes::Backend reference = backends.front();

  for (const auto &keyCase : keys) {
    for (const auto &mode : modes) {
      const int paddingCount = mode.usesCounter ? 1 : 2;
      for (int paddingIndex = 0; paddingIndex < paddingCount; ++paddingIndex) {
        const Padding padding =
            paddingIndex == 0 ? Padding::PKCS7 : Padding::Zeros;
        const char *paddingName =
            mode.usesCounter ? "NoPad"
                             : (padding == Padding::PKCS7 ? "PKCS7" : "Zeros");
        const std::string label =
            std::string(mode.name) + '-' + std::to_string(keyCase.bits) + '-' +
            paddingName;
        int groupPassed = 0;
        int groupFailed = 0;

        for (size_t dataSize : TEST_SIZES) {
          const auto plaintext = getTestData(dataSize);
          auto configure = [&](AesProxy &aes) {
            if (mode.usesIV)
              aes.setIV(TEST_IV, IV_SIZE);
            if (mode.usesCounter)
              aes.setCounter(TEST_COUNTER, COUNTER_SIZE);
          };

          AesProxy referenceAes(reference, keyCase.bits, keyCase.key,
                                keyCase.length, padding);
          configure(referenceAes);
          const auto referenceCiphertext = referenceAes.cipher(plaintext);
          bool ok = !referenceCiphertext.empty();

          if (!ok) {
            std::cout << "[FAIL] " << label << " (" << dataSize << " bytes): "
                      << WAes::GetImplName(reference)
                      << " encryption failed\n";
          }

          for (size_t i = 1; i < backends.size() && ok; ++i) {
            AesProxy aes(backends[i], keyCase.bits, keyCase.key, keyCase.length,
                         padding);
            configure(aes);
            if (aes.cipher(plaintext) != referenceCiphertext) {
              std::cout << "[FAIL] " << label << " (" << dataSize
                        << " bytes): cipher mismatch — "
                        << WAes::GetImplName(backends[i]) << " differs from "
                        << WAes::GetImplName(reference) << '\n';
              ok = false;
            }
          }

          if (!referenceCiphertext.empty()) {
            for (auto backend : backends) {
              AesProxy aes(backend, keyCase.bits, keyCase.key, keyCase.length,
                           padding);
              configure(aes);
              if (aes.invCipher(referenceCiphertext, dataSize) != plaintext) {
                std::cout << "[FAIL] " << label << " (" << dataSize
                          << " bytes): decrypt mismatch — "
                          << WAes::GetImplName(backend) << '\n';
                ok = false;
              }
            }
          }

          ok ? ++groupPassed : ++groupFailed;
        }

        passed += groupPassed;
        failed += groupFailed;
        if (groupFailed == 0)
          std::cout << "[OK] " << label << ": " << groupPassed
                    << " sizes passed\n";
      }
    }
  }

  std::cout << "\nCross-validation: " << passed << " passed, " << failed
            << " failed — "
            << (failed == 0 ? "All backends consistent"
                            : "INCONSISTENCIES DETECTED")
            << '\n';
  return failed == 0;
}

} // namespace WAesCrossTests
