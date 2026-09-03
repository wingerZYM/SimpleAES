#pragma once

#include "test_utils.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace GCMTests {

inline TestUtils::TestResult nistAADVector() {
  static constexpr uint8_t key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
                                      0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
                                      0x67, 0x30, 0x83, 0x08};
  static constexpr uint8_t nonce[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                        0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
  static constexpr uint8_t aad[20] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                                      0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                                      0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
  static constexpr uint8_t plaintext[60] = {
      0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
      0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
      0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
      0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
      0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
  static constexpr uint8_t expectedCiphertext[60] = {
      0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
      0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
      0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
      0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
      0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};
  static constexpr uint8_t expectedTag[16] = {
      0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
      0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

  CWAes128 aes(key, sizeof(key));
  std::array<uint8_t, sizeof(aad)> aadCopy{};
  std::memcpy(aadCopy.data(), aad, sizeof(aad));
  if (!aes.SetAAD(aadCopy.data(), aadCopy.size())) {
    return {false, "SetAAD failed"};
  }
  aadCopy.fill(0); // SetAAD must retain its own copy.

  std::array<uint8_t, sizeof(plaintext)> ciphertext{};
  std::array<uint8_t, WAesGCMTagSize> tag{};
  size_t ciphertextLength = ciphertext.size();
  size_t tagLength = tag.size();
  if (!aes.CipherGCM(plaintext, sizeof(plaintext), ciphertext.data(),
                     ciphertextLength, nonce, sizeof(nonce), tag.data(),
                     tagLength) ||
      ciphertextLength != ciphertext.size() || tagLength != tag.size() ||
      std::memcmp(ciphertext.data(), expectedCiphertext, ciphertext.size()) !=
          0 ||
      std::memcmp(tag.data(), expectedTag, tag.size()) != 0) {
    return {false, "AAD/partial-block vector mismatch"};
  }

  std::array<uint8_t, sizeof(plaintext)> recovered{};
  size_t recoveredLength = recovered.size();
  if (!aes.InvCipherGCM(ciphertext.data(), ciphertext.size(), recovered.data(),
                        recoveredLength, nonce, sizeof(nonce), tag.data(),
                        tag.size()) ||
      recoveredLength != recovered.size() ||
      std::memcmp(recovered.data(), plaintext, recovered.size()) != 0) {
    return {false, "AAD/partial-block decryption mismatch"};
  }
  return {true, "NIST AAD and partial-block vector"};
}

inline TestUtils::TestResult emptyMessage() {
  static constexpr uint8_t key[16] = {};
  static constexpr uint8_t nonce[12] = {};
  static constexpr uint8_t expectedTag[16] = {
      0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
      0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
  CWAes128 aes(key, sizeof(key));
  if (!aes.SetAAD()) {
    return {false, "empty AAD rejected"};
  }

  std::array<uint8_t, 16> tag{};
  size_t outputLength = 0;
  size_t tagLength = tag.size();
  if (!aes.CipherGCM(nullptr, 0, nullptr, outputLength, nonce, sizeof(nonce),
                     tag.data(), tagLength) ||
      outputLength != 0 || tagLength != tag.size() ||
      std::memcmp(tag.data(), expectedTag, tag.size()) != 0) {
    return {false, "empty-message vector mismatch"};
  }

  outputLength = 0;
  if (!aes.InvCipherGCM(nullptr, 0, nullptr, outputLength, nonce, sizeof(nonce),
                        tag.data(), tag.size()) ||
      outputLength != 0) {
    return {false, "empty-message decryption failed"};
  }
  return {true, "empty input and empty AAD"};
}

inline TestUtils::TestResult authenticationAndInPlace() {
  std::array<uint8_t, 16> key{};
  std::array<uint8_t, 12> nonce{};
  std::array<uint8_t, 7> aad{{1, 2, 3, 4, 5, 6, 7}};
  std::array<uint8_t, 37> plaintext{};
  for (size_t i = 0; i < plaintext.size(); ++i) {
    plaintext[i] = static_cast<uint8_t>(i * 7 + 3);
  }

  CWAes128 aes(key.data(), key.size());
  if (!aes.SetAAD(aad.data(), aad.size())) {
    return {false, "SetAAD failed"};
  }
  std::array<uint8_t, 37> ciphertext{};
  std::array<uint8_t, 16> tag{};
  size_t ciphertextLength = ciphertext.size();
  size_t tagLength = tag.size();
  if (!aes.CipherGCM(plaintext.data(), plaintext.size(), ciphertext.data(),
                     ciphertextLength, nonce.data(), nonce.size(), tag.data(),
                     tagLength)) {
    return {false, "setup encryption failed"};
  }

  auto badTag = tag;
  badTag[4] ^= 0x80;
  std::array<uint8_t, 37> guardedOutput{};
  guardedOutput.fill(0xa5);
  size_t outputLength = guardedOutput.size();
  if (aes.InvCipherGCM(ciphertext.data(), ciphertext.size(),
                       guardedOutput.data(), outputLength, nonce.data(),
                       nonce.size(), badTag.data(), badTag.size()) ||
      outputLength != 0 ||
      !std::all_of(guardedOutput.begin(), guardedOutput.end(),
                   [](uint8_t value) { return value == 0xa5; })) {
    return {false, "tag failure modified plaintext output"};
  }

  auto badCiphertext = ciphertext;
  badCiphertext[11] ^= 1;
  outputLength = guardedOutput.size();
  if (aes.InvCipherGCM(badCiphertext.data(), badCiphertext.size(),
                       guardedOutput.data(), outputLength, nonce.data(),
                       nonce.size(), tag.data(), tag.size()) ||
      outputLength != 0 ||
      !std::all_of(guardedOutput.begin(), guardedOutput.end(),
                   [](uint8_t value) { return value == 0xa5; })) {
    return {false, "ciphertext failure modified plaintext output"};
  }

  auto inPlace = plaintext;
  std::array<uint8_t, 16> inPlaceTag{};
  size_t inPlaceLength = inPlace.size();
  tagLength = inPlaceTag.size();
  if (!aes.CipherGCM(inPlace.data(), inPlace.size(), inPlace.data(),
                     inPlaceLength, nonce.data(), nonce.size(),
                     inPlaceTag.data(), tagLength) ||
      inPlace != ciphertext || inPlaceTag != tag) {
    return {false, "in-place encryption mismatch"};
  }
  inPlaceLength = inPlace.size();
  if (!aes.InvCipherGCM(inPlace.data(), inPlace.size(), inPlace.data(),
                        inPlaceLength, nonce.data(), nonce.size(),
                        inPlaceTag.data(), inPlaceTag.size()) ||
      inPlace != plaintext) {
    return {false, "in-place decryption mismatch"};
  }
  return {true, "authenticate-before-write and exact in-place operation"};
}

inline TestUtils::TestResult modeAndFailureSemantics() {
  std::array<uint8_t, 16> key{};
  std::array<uint8_t, 16> block{};
  std::array<uint8_t, 32> output{};
  std::array<uint8_t, 12> nonce{};
  std::array<uint8_t, 16> tag{};
  CWAes128 aes(key.data(), key.size());

  size_t outputLength = output.size();
  size_t tagLength = tag.size();
  if (aes.CipherGCM(block.data(), block.size(), output.data(), outputLength,
                    nonce.data(), nonce.size(), tag.data(), tagLength) ||
      outputLength != 0 || tagLength != 0) {
    return {false, "GCM accepted without SetAAD"};
  }

  if (!aes.SetAAD()) {
    return {false, "SetAAD failed"};
  }
  outputLength = output.size();
  if (aes.Cipher(block.data(), block.size(), output.data(), outputLength) ||
      outputLength != 0) {
    return {false, "legacy Cipher accepted GCM mode"};
  }

  aes.SetIV(key.data(), key.size());
  outputLength = output.size();
  tagLength = tag.size();
  if (aes.CipherGCM(block.data(), block.size(), output.data(), outputLength,
                    nonce.data(), nonce.size(), tag.data(), tagLength)) {
    return {false, "SetIV did not leave GCM mode"};
  }

  if (!aes.SetAAD()) {
    return {false, "SetAAD failed"};
  }
  GCMResult failedResult;
  failedResult.nonce.fill(0x5a);
  failedResult.tag.fill(0xa5);
  const auto originalResult = failedResult;
  output.fill(0x3c);
  outputLength = output.size();
  aes.SetCounter(key.data(), key.size());
  if (aes.CipherGCM(block.data(), block.size(), output.data(), outputLength,
                    failedResult) ||
      outputLength != 0 || failedResult.nonce != originalResult.nonce ||
      failedResult.tag != originalResult.tag ||
      !std::all_of(output.begin(), output.end(),
                   [](uint8_t value) { return value == 0x3c; })) {
    return {false, "SetCounter/automatic-result failure semantics mismatch"};
  }

  if (!aes.SetAAD() || aes.SetAAD(nullptr, 1)) {
    return {false, "invalid AAD handling mismatch"};
  }
  output.fill(0xa5);
  outputLength = block.size() - 1;
  tagLength = tag.size();
  const auto originalTag = tag;
  if (aes.CipherGCM(block.data(), block.size(), output.data(), outputLength,
                    nonce.data(), nonce.size(), tag.data(), tagLength) ||
      outputLength != 0 || tagLength != 0 || tag != originalTag) {
    return {false, "capacity failure modified result buffers"};
  }
  if (!std::all_of(output.begin(), output.end(),
                   [](uint8_t value) { return value == 0xa5; })) {
    return {false, "capacity failure modified ciphertext output"};
  }

  outputLength = output.size();
  tagLength = tag.size();
  if (aes.CipherGCM(block.data(), block.size(), output.data(), outputLength,
                    nonce.data(), nonce.size() - 1, tag.data(), tagLength) ||
      outputLength != 0 || tagLength != 0) {
    return {false, "invalid nonce length accepted"};
  }
  outputLength = output.size();
  tagLength = tag.size() - 1;
  if (aes.CipherGCM(block.data(), block.size(), output.data(), outputLength,
                    nonce.data(), nonce.size(), tag.data(), tagLength) ||
      outputLength != 0 || tagLength != 0) {
    return {false, "short tag capacity accepted"};
  }
  return {true, "mode transitions and failure lengths"};
}

inline TestUtils::TestResult automaticNonce() {
  std::array<uint8_t, 16> key{};
  std::array<uint8_t, 29> plaintext{};
  for (size_t i = 0; i < plaintext.size(); ++i) {
    plaintext[i] = static_cast<uint8_t>(i + 1);
  }
  CWAes128 aes(key.data(), key.size());
  if (!aes.SetAAD()) {
    return {false, "SetAAD failed"};
  }

  std::array<uint8_t, 29> first{};
  std::array<uint8_t, 29> second{};
  GCMResult firstResult;
  GCMResult secondResult;
  size_t firstLength = first.size();
  size_t secondLength = second.size();
  if (!aes.CipherGCM(plaintext.data(), plaintext.size(), first.data(),
                     firstLength, firstResult) ||
      !aes.CipherGCM(plaintext.data(), plaintext.size(), second.data(),
                     secondLength, secondResult) ||
      firstResult.nonce == secondResult.nonce) {
    return {false, "automatic nonce generation failed"};
  }

  std::array<uint8_t, 29> recovered{};
  size_t recoveredLength = recovered.size();
  if (!aes.InvCipherGCM(first.data(), firstLength, recovered.data(),
                        recoveredLength, firstResult) ||
      recovered != plaintext) {
    return {false, "automatic-nonce result did not decrypt"};
  }
  return {true, "automatic nonce result round trip"};
}

inline TestUtils::TestSummary run(const std::string &implementationName) {
  TestUtils::TestSummary summary;
  const auto check = [&](const TestUtils::TestResult &result,
                         const char *name) {
    TestUtils::printTestResult(result, implementationName + "-GCM-" + name);
    summary.addResult(result.success);
  };
  check(nistAADVector(), "NIST-AAD");
  check(emptyMessage(), "Empty");
  check(authenticationAndInPlace(), "Authentication-InPlace");
  check(modeAndFailureSemantics(), "State-Failures");
  check(automaticNonce(), "Automatic-Nonce");
  return summary;
}

} // namespace GCMTests
