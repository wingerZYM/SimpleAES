#pragma once

#include "test_data.hpp"
#include "test_utils.hpp"

#include <array>
#include <cstring>
#include <string>

namespace KnownAnswerTests {

enum class Mode { ECB, CBC, CTR };

template <int KeySize>
TestUtils::TestResult runCase(const uint8_t *key, size_t keyLength, Mode mode,
                              const uint8_t *input,
                              const uint8_t *expectedCiphertext) {
  static constexpr uint8_t cbcIV[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                        0x0c, 0x0d, 0x0e, 0x0f};
  static constexpr uint8_t ctrBlock[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                                           0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
                                           0xfc, 0xfd, 0xfe, 0xff};

  auto setMode = [&](auto &aes) {
    if (mode == Mode::CBC) {
      aes.SetIV(cbcIV, sizeof(cbcIV));
    } else if (mode == Mode::CTR) {
      aes.SetCounter(ctrBlock, sizeof(ctrBlock));
    }
  };

  CWAes<KeySize> encryptor(key, keyLength, nullptr, 0, Padding::Zeros);
  setMode(encryptor);
  // Reserve one additional block because the API supports PKCS7 as a runtime
  // option. The selected Zero padding still has to report exactly 16 bytes.
  std::array<uint8_t, 32> ciphertext{};
  size_t ciphertextLength = ciphertext.size();
  if (!encryptor.Cipher(input, 16, ciphertext.data(), ciphertextLength) ||
      ciphertextLength != 16 ||
      std::memcmp(ciphertext.data(), expectedCiphertext, 16) != 0) {
    return {false, "known ciphertext mismatch"};
  }

  CWAes<KeySize> decryptor(key, keyLength, nullptr, 0, Padding::Zeros);
  setMode(decryptor);
  std::array<uint8_t, 16> recovered{};
  size_t recoveredLength = recovered.size();
  if (!decryptor.InvCipher(ciphertext.data(), ciphertextLength,
                           recovered.data(), recoveredLength) ||
      recoveredLength != recovered.size() ||
      std::memcmp(recovered.data(), input, 16) != 0) {
    return {false, "known ciphertext decryption mismatch"};
  }

  return {true, "NIST/FIPS known-answer vector"};
}

inline TestUtils::TestResult runGCMCase() {
  // NIST SP 800-38D, Test Case 2: all-zero AES-128 key and 96-bit IV.
  static constexpr uint8_t key[16] = {};
  static constexpr uint8_t nonce[12] = {};
  static constexpr uint8_t plaintext[16] = {};
  static constexpr uint8_t expectedCiphertext[16] = {
      0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
      0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
  static constexpr uint8_t expectedTag[16] = {
      0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
      0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};

  CWAes128 aes(key, sizeof(key), nullptr, 0, Padding::PKCS7);
  if (!aes.SetAAD(nullptr, 0) || aes.SumCipherLength(sizeof(plaintext)) != 16) {
    return {false, "could not enter GCM mode"};
  }

  std::array<uint8_t, 16> ciphertext{};
  std::array<uint8_t, 16> tag{};
  size_t ciphertextLength = ciphertext.size();
  size_t tagLength = tag.size();
  if (!aes.CipherGCM(plaintext, sizeof(plaintext), ciphertext.data(),
                     ciphertextLength, nonce, sizeof(nonce), tag.data(),
                     tagLength) ||
      ciphertextLength != ciphertext.size() || tagLength != tag.size() ||
      std::memcmp(ciphertext.data(), expectedCiphertext, ciphertext.size()) !=
          0 ||
      std::memcmp(tag.data(), expectedTag, tag.size()) != 0) {
    return {false, "GCM ciphertext or tag mismatch"};
  }

  std::array<uint8_t, 16> recovered{};
  size_t recoveredLength = recovered.size();
  if (!aes.InvCipherGCM(ciphertext.data(), ciphertext.size(), recovered.data(),
                        recoveredLength, nonce, sizeof(nonce), tag.data(),
                        tag.size()) ||
      recoveredLength != recovered.size() ||
      std::memcmp(recovered.data(), plaintext, recovered.size()) != 0) {
    return {false, "GCM authenticated decryption mismatch"};
  }

  return {true, "NIST SP 800-38D known-answer vector"};
}

inline TestUtils::TestSummary run(const std::string &implementationName) {
  // FIPS-197 Appendix C ECB vectors.
  static constexpr uint8_t ecbPlaintext[16] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  static constexpr uint8_t ecbKey128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                            0x0c, 0x0d, 0x0e, 0x0f};
  static constexpr uint8_t ecbKey192[24] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  static constexpr uint8_t ecbKey256[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static constexpr uint8_t ecbCipher128[16] = {
      0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
      0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
  static constexpr uint8_t ecbCipher192[16] = {
      0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
      0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};
  static constexpr uint8_t ecbCipher256[16] = {
      0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
      0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

  // NIST SP 800-38A first-block CBC and CTR vectors.
  static constexpr uint8_t blockPlaintext[16] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  static constexpr uint8_t cbcCipher128[16] = {
      0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
      0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d};
  static constexpr uint8_t cbcCipher192[16] = {
      0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
      0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8};
  static constexpr uint8_t cbcCipher256[16] = {
      0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
      0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6};
  static constexpr uint8_t ctrCipher128[16] = {
      0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
      0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce};
  static constexpr uint8_t ctrCipher192[16] = {
      0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2,
      0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b};
  static constexpr uint8_t ctrCipher256[16] = {
      0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
      0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28};

  TestUtils::TestSummary summary;
  auto check = [&](const TestUtils::TestResult &result, const char *mode,
                   int keySize) {
    TestUtils::printTestResult(result, implementationName + "-KAT-" + mode +
                                           "-AES" + std::to_string(keySize));
    summary.addResult(result.success);
  };

  check(runCase<128>(ecbKey128, sizeof(ecbKey128), Mode::ECB, ecbPlaintext,
                     ecbCipher128),
        "ECB", 128);
  check(runCase<192>(ecbKey192, sizeof(ecbKey192), Mode::ECB, ecbPlaintext,
                     ecbCipher192),
        "ECB", 192);
  check(runCase<256>(ecbKey256, sizeof(ecbKey256), Mode::ECB, ecbPlaintext,
                     ecbCipher256),
        "ECB", 256);
  check(runCase<128>(TestData::AES128_KEY, TestData::AES128_KEY_SIZE, Mode::CBC,
                     blockPlaintext, cbcCipher128),
        "CBC", 128);
  check(runCase<192>(TestData::AES192_KEY, TestData::AES192_KEY_SIZE, Mode::CBC,
                     blockPlaintext, cbcCipher192),
        "CBC", 192);
  check(runCase<256>(TestData::AES256_KEY, TestData::AES256_KEY_SIZE, Mode::CBC,
                     blockPlaintext, cbcCipher256),
        "CBC", 256);
  check(runCase<128>(TestData::AES128_KEY, TestData::AES128_KEY_SIZE, Mode::CTR,
                     blockPlaintext, ctrCipher128),
        "CTR", 128);
  check(runCase<192>(TestData::AES192_KEY, TestData::AES192_KEY_SIZE, Mode::CTR,
                     blockPlaintext, ctrCipher192),
        "CTR", 192);
  check(runCase<256>(TestData::AES256_KEY, TestData::AES256_KEY_SIZE, Mode::CTR,
                     blockPlaintext, ctrCipher256),
        "CTR", 256);
  const auto gcmResult = runGCMCase();
  TestUtils::printTestResult(gcmResult, implementationName + "-KAT-GCM-AES128");
  summary.addResult(gcmResult.success);
  return summary;
}

} // namespace KnownAnswerTests
