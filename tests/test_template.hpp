#pragma once

#include "test_data.hpp"
#include "test_known_answers.hpp"
#include "test_options.hpp"
#include "test_utils.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <vector>

using namespace TestData;
using namespace TestUtils;

// This template contains all the test logic that can be reused across different
// implementations The actual AES header should be included before including
// this template

// Fixed FNV-1a output keeps cross-process comparison stable across standard
// library implementations. std::hash is intentionally not stable.
uint64_t calculateDataHash(const std::vector<uint8_t> &data) {
  uint64_t hash = UINT64_C(14695981039346656037);
  for (uint8_t byte : data) {
    hash ^= byte;
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

// Helper function to write test results to file for cross-implementation
// comparison
void writeTestResultToFile(const std::string &implName,
                           const std::string &testName,
                           const std::vector<uint8_t> &input,
                           const std::vector<uint8_t> &ciphertext,
                           const std::vector<uint8_t> &decrypted,
                           const std::string &mode, int keySize,
                           const std::string &padding) {
  std::string dir;
  const std::string envDir = getEnvironmentVariable("TEST_OUTPUT_DIR");
  if (!envDir.empty())
    dir = envDir + "/";
  std::string filename = dir + "test_results_" + implName + ".txt";
  std::ofstream file(filename, std::ios::app);

  if (!file.is_open())
    return;

  file << "=== Test: " << testName << " ===" << std::endl;
  file << "Implementation: " << implName << std::endl;
  file << "Mode: " << mode << std::endl;
  file << "Key Size: " << keySize << std::endl;
  file << "Padding: " << padding << std::endl;
  file << "Input Size: " << input.size() << std::endl;
  file << "Cipher Size: " << ciphertext.size() << std::endl;
  file << "Decrypted Size: " << decrypted.size() << std::endl;

  // Calculate and write hash values for integrity checking
  file << "Input Hash: " << std::hex << calculateDataHash(input) << std::endl;
  file << "Cipher Hash: " << std::hex << calculateDataHash(ciphertext)
       << std::endl;
  file << "Decrypted Hash: " << std::hex << calculateDataHash(decrypted)
       << std::endl;

  // Write input data (first 32 bytes)
  file << "Input Start: ";
  for (size_t i = 0; i < std::min(input.size(), size_t(32)); ++i) {
    file << std::hex << std::setw(2) << std::setfill('0') << (int)input[i];
  }
  file << std::endl;

  // Write input data (last 16 bytes if size > 32)
  if (input.size() > 32) {
    file << "Input End: ";
    size_t start = input.size() > 16 ? input.size() - 16 : 0;
    for (size_t i = start; i < input.size(); ++i) {
      file << std::hex << std::setw(2) << std::setfill('0') << (int)input[i];
    }
    file << std::endl;
  }

  // Write ciphertext (first 32 bytes)
  file << "Cipher Start: ";
  for (size_t i = 0; i < std::min(ciphertext.size(), size_t(32)); ++i) {
    file << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
  }
  file << std::endl;

  // Write ciphertext (last 16 bytes if size > 32)
  if (ciphertext.size() > 32) {
    file << "Cipher End: ";
    size_t start = ciphertext.size() > 16 ? ciphertext.size() - 16 : 0;
    for (size_t i = start; i < ciphertext.size(); ++i) {
      file << std::hex << std::setw(2) << std::setfill('0')
           << (int)ciphertext[i];
    }
    file << std::endl;
  }

  // Write decrypted data (first 32 bytes)
  file << "Decrypted Start: ";
  for (size_t i = 0; i < std::min(decrypted.size(), size_t(32)); ++i) {
    file << std::hex << std::setw(2) << std::setfill('0') << (int)decrypted[i];
  }
  file << std::endl;

  // Write decrypted data (last 16 bytes if size > 32)
  if (decrypted.size() > 32) {
    file << "Decrypted End: ";
    size_t start = decrypted.size() > 16 ? decrypted.size() - 16 : 0;
    for (size_t i = start; i < decrypted.size(); ++i) {
      file << std::hex << std::setw(2) << std::setfill('0')
           << (int)decrypted[i];
    }
    file << std::endl;
  }

  file << std::dec << std::endl;
  file.close();
}

template <int KeySize>
TestResult testAESImplementation(size_t dataSize, const std::string &mode,
                                 Padding padding, const std::string &implName,
                                 const TestOptions &options) {
  auto testData = getTestData(dataSize);

  // Get current parameters (custom or default)
  size_t currentKeyLen;
  const uint8_t *currentKey = getCurrentKey(options, KeySize, currentKeyLen);
  const uint8_t *currentIV = getCurrentIV(options);
  const uint8_t *currentCounter = getCurrentCounter(options);

  // Create AES instance
  CWAes<KeySize> aes(currentKey, currentKeyLen, nullptr, 0, padding);

  // Set mode
  if (mode == "CBC") {
    aes.SetIV(currentIV, IV_SIZE);
  } else if (mode == "CTR") {
    aes.SetCounter(currentCounter, COUNTER_SIZE);
  }
  // ECB is default mode

  // Prepare buffers
  size_t maxCipherLen =
      (mode == "CTR") ? dataSize : aes.SumCipherLength(dataSize);
  std::vector<uint8_t> ciphertext(maxCipherLen);
  std::vector<uint8_t> decrypted(dataSize);

  Timer timer;

  // Encrypt
  timer.start();
  size_t cipherLen = ciphertext.size();
  if (!aes.Cipher(testData.data(), dataSize, ciphertext.data(), cipherLen)) {
    return TestResult(false, "Encryption failed");
  }
  double encryptTime = timer.elapsed();

  ciphertext.resize(cipherLen);

  // Decrypt
  timer.start();
  size_t decryptedLen = decrypted.size();
  if (!aes.InvCipher(ciphertext.data(), cipherLen, decrypted.data(),
                     decryptedLen)) {
    return TestResult(false, "Decryption failed");
  }
  double decryptTime = timer.elapsed();

  if (decryptedLen != dataSize) {
    return TestResult(false, "Decrypted length mismatch: expected " +
                                 std::to_string(dataSize) + ", got " +
                                 std::to_string(decryptedLen));
  }

  decrypted.resize(decryptedLen);

  // Verify data integrity
  if (!compareData(testData, decrypted)) {
    return TestResult(false, "Data integrity check failed");
  }

  // Write test results to file for cross-implementation comparison
  if (shouldWriteToFile(options)) {
    std::string testName = mode + "_" + std::to_string(KeySize) + "_" +
                           (padding == Padding::PKCS7 ? "PKCS7" : "Zeros") +
                           "_" + std::to_string(dataSize);
    writeTestResultToFile(implName, testName, testData, ciphertext, decrypted,
                          mode, KeySize,
                          (padding == Padding::PKCS7 ? "PKCS7" : "Zeros"));
  }

  return TestResult(true, "Success", encryptTime, decryptTime, dataSize);
}

template <int KeySize>
TestResult testPaddingValidation(const std::string &mode,
                                 const TestOptions &options) {
  // Get current parameters (custom or default)
  size_t currentKeyLen;
  const uint8_t *currentKey = getCurrentKey(options, KeySize, currentKeyLen);
  const uint8_t *currentIV = getCurrentIV(options);

  // Encrypt an explicitly malformed padded block without adding padding.
  // This makes the negative test deterministic; flipping ciphertext only
  // produces invalid padding probabilistically.
  std::array<uint8_t, 16> malformed{};
  malformed.fill(0x41);
  malformed[13] = 0x03;
  malformed[14] = 0x02;
  malformed[15] = 0x03;

  CWAes<KeySize> rawEncryptor(currentKey, currentKeyLen, nullptr, 0,
                              Padding::Zeros);
  CWAes<KeySize> validator(currentKey, currentKeyLen, nullptr, 0,
                           Padding::PKCS7);
  if (mode == "CBC") {
    rawEncryptor.SetIV(currentIV, IV_SIZE);
    validator.SetIV(currentIV, IV_SIZE);
  }

  std::array<uint8_t, 32> ciphertext{};
  size_t cipherLen = ciphertext.size();
  if (!rawEncryptor.Cipher(malformed.data(), malformed.size(),
                           ciphertext.data(), cipherLen) ||
      cipherLen != 16) {
    return TestResult(false, "Malformed block encryption failed");
  }

  std::array<uint8_t, 16> decrypted{};
  size_t decryptedLen = decrypted.size();
  if (validator.InvCipher(ciphertext.data(), cipherLen, decrypted.data(),
                          decryptedLen)) {
    return TestResult(false, "Accepted malformed PKCS7 padding");
  }

  return TestResult(true, "Padding validation works correctly");
}

std::vector<uint8_t> generateLargeTestData(size_t size);

template <int KeySize>
TestResult benchmarkImplementation(const uint8_t *key, size_t keyLen,
                                   size_t dataSize, const std::string &mode,
                                   Padding padding, const std::string &implName,
                                   const TestOptions &options,
                                   int iterations = 100) {
  (void)implName; // Suppress unused parameter warning
  auto testData = generateLargeTestData(dataSize);

  CWAes<KeySize> aes(key, keyLen, nullptr, 0, padding);

  // Set mode
  if (mode == "CBC") {
    aes.SetIV(getCurrentIV(options), IV_SIZE);
  } else if (mode == "CTR") {
    aes.SetCounter(getCurrentCounter(options), COUNTER_SIZE);
  }

  // Prepare buffers
  size_t maxCipherLen =
      (mode == "CTR") ? dataSize : aes.SumCipherLength(dataSize);
  std::vector<uint8_t> ciphertext(maxCipherLen);
  std::vector<uint8_t> decrypted(dataSize);

  Timer timer;

  // Warm up
  for (int i = 0; i < 10; i++) {
    size_t tmpLen = ciphertext.size();
    if (!aes.Cipher(testData.data(), dataSize, ciphertext.data(), tmpLen))
      return TestResult(false, "Encryption warm-up failed");
    tmpLen = decrypted.size();
    if (!aes.InvCipher(ciphertext.data(), maxCipherLen, decrypted.data(),
                       tmpLen))
      return TestResult(false, "Decryption warm-up failed");
  }

  // Benchmark encryption
  timer.start();
  size_t finalCipherLen = 0;
  for (int i = 0; i < iterations; i++) {
    size_t tmpLen = ciphertext.size();
    if (!aes.Cipher(testData.data(), dataSize, ciphertext.data(), tmpLen))
      return TestResult(false, "Encryption benchmark failed");
    finalCipherLen = tmpLen;
  }
  double encryptTime = timer.elapsed() / iterations;

  // Benchmark decryption
  timer.start();
  size_t finalPlaintextLen = 0;
  for (int i = 0; i < iterations; i++) {
    size_t tmpLen = decrypted.size();
    if (!aes.InvCipher(ciphertext.data(), finalCipherLen, decrypted.data(),
                       tmpLen))
      return TestResult(false, "Decryption benchmark failed");
    finalPlaintextLen = tmpLen;
  }
  double decryptTime = timer.elapsed() / iterations;

  if (finalPlaintextLen != testData.size() ||
      !std::equal(testData.begin(), testData.end(), decrypted.begin())) {
    return TestResult(false, "Benchmark decryption verification failed");
  }

  // Calculate throughput
  double totalTime = (encryptTime + decryptTime) / 1000.0; // Convert to seconds
  double throughputMBps =
      (dataSize * 2.0) / (1024.0 * 1024.0) / totalTime; // MB/s

  return TestResult(true,
                    "Throughput: " + std::to_string(throughputMBps) + " MB/s",
                    encryptTime, decryptTime, dataSize);
}

TestSummary runImplementationTests(const std::string &implementationName,
                                   const TestOptions &options) {
  TestSummary summary;

  std::cout << "\n=== " << implementationName
            << " AES Implementation Tests ===" << std::endl;

  summary.merge(KnownAnswerTests::run(implementationName));

  // Test configurations
  struct KeyConfig {
    int keySize;
    std::string name;
  };

  KeyConfig keys[] = {{128, "AES128"}, {192, "AES192"}, {256, "AES256"}};

  std::string modes[] = {"ECB", "CBC", "CTR"};
  Padding paddings[] = {Padding::PKCS7, Padding::Zeros};
  std::string paddingNames[] = {"PKCS7", "Zeros"};

  for (const auto &keyConfig : keys) {
    for (const auto &mode : modes) {
      for (int p = 0; p < 2; p++) {
        // Skip padding for CTR mode
        if (mode == "CTR" && p > 0)
          continue;

        for (size_t dataSize : TEST_SIZES) {
          TestResult result;
          std::string testName = implementationName + "-" + mode + "-" +
                                 keyConfig.name + "-" +
                                 (mode == "CTR" ? "NoPad" : paddingNames[p]) +
                                 " (" + std::to_string(dataSize) + " bytes)";

          switch (keyConfig.keySize) {
          case 128:
            result = testAESImplementation<128>(dataSize, mode, paddings[p],
                                                implementationName, options);
            break;
          case 192:
            result = testAESImplementation<192>(dataSize, mode, paddings[p],
                                                implementationName, options);
            break;
          case 256:
            result = testAESImplementation<256>(dataSize, mode, paddings[p],
                                                implementationName, options);
            break;
          }

          printTestResult(result, testName);
          summary.addResult(result.success);
        }

        if (mode == "CTR" || paddings[p] != Padding::PKCS7)
          continue;

        // Test deterministic rejection of malformed PKCS7 padding.
        TestResult paddingResult;
        std::string paddingTestName = implementationName + "-" + mode + "-" +
                                      keyConfig.name +
                                      "-PKCS7 Padding Validation";

        switch (keyConfig.keySize) {
        case 128:
          paddingResult = testPaddingValidation<128>(mode, options);
          break;
        case 192:
          paddingResult = testPaddingValidation<192>(mode, options);
          break;
        case 256:
          paddingResult = testPaddingValidation<256>(mode, options);
          break;
        }

        printTestResult(paddingResult, paddingTestName);
        summary.addResult(paddingResult.success);
      }
    }
  }

  summary.print(implementationName + " AES Implementation");
  return summary;
}

// Generate large test data for performance benchmarks
std::vector<uint8_t> generateLargeTestData(size_t size) {
  std::vector<uint8_t> data(size);

  // Fill with non-zero pattern to avoid zero padding issues
  for (size_t i = 0; i < size; ++i) {
    data[i] = static_cast<uint8_t>((i % 255) + 1); // Range 1-255, avoiding 0
  }

  return data;
}

// Enhanced benchmark function for large data
template <int KeySize>
TestResult benchmarkLargeData(const uint8_t *key, size_t keyLen,
                              size_t dataSize, const std::string &mode,
                              Padding padding, const std::string &implName,
                              const TestOptions &options, int iterations = 1) {
  (void)implName; // Suppress unused parameter warning

  // Generate large test data
  auto testData = generateLargeTestData(dataSize);

  CWAes<KeySize> aes(key, keyLen, nullptr, 0, padding);

  // Set mode
  if (mode == "CBC") {
    aes.SetIV(getCurrentIV(options), IV_SIZE);
  } else if (mode == "CTR") {
    aes.SetCounter(getCurrentCounter(options), COUNTER_SIZE);
  }

  // Prepare buffers
  size_t maxCipherLen =
      (mode == "CTR") ? dataSize : aes.SumCipherLength(dataSize);
  std::vector<uint8_t> ciphertext(maxCipherLen);
  std::vector<uint8_t> decrypted(dataSize);

  Timer timer;

  // Warm up with smaller iterations for large data
  for (int i = 0; i < 3; i++) {
    size_t cipherLen = ciphertext.size();
    if (!aes.Cipher(testData.data(), dataSize, ciphertext.data(), cipherLen))
      return TestResult(false, "Encryption warm-up failed");
    size_t decLen = decrypted.size();
    if (!aes.InvCipher(ciphertext.data(), cipherLen, decrypted.data(), decLen))
      return TestResult(false, "Decryption warm-up failed");
  }

  // Benchmark encryption
  timer.start();
  size_t finalCipherLen = ciphertext.size();
  for (int i = 0; i < iterations; i++) {
    finalCipherLen = ciphertext.size();
    if (!aes.Cipher(testData.data(), dataSize, ciphertext.data(),
                    finalCipherLen))
      return TestResult(false, "Encryption benchmark failed");
  }
  double encryptTime = timer.elapsed() / iterations;

  // Benchmark decryption
  timer.start();
  size_t finalPlaintextLen = 0;
  for (int i = 0; i < iterations; i++) {
    size_t tmpLen = decrypted.size();
    if (!aes.InvCipher(ciphertext.data(), finalCipherLen, decrypted.data(),
                       tmpLen))
      return TestResult(false, "Decryption benchmark failed");
    finalPlaintextLen = tmpLen;
  }
  double decryptTime = timer.elapsed() / iterations;

  // Verify correctness
  bool correct =
      finalPlaintextLen == testData.size() &&
      compareData(testData.data(), decrypted.data(), testData.size());
  if (!correct) {
    return TestResult(false, "Decryption verification failed for large data");
  }

  // Calculate throughput (MB/s)
  double totalTimeSeconds = (encryptTime + decryptTime) / 1000.0;
  double dataSizeMB =
      (dataSize * 2.0) / (1024.0 * 1024.0); // *2 for encrypt+decrypt
  double throughputMBps = dataSizeMB / totalTimeSeconds;

  return TestResult(true,
                    "Throughput: " + std::to_string(throughputMBps) + " MB/s",
                    encryptTime, decryptTime, dataSize);
}

bool runPerformanceTests(const std::string &implementationName,
                         const TestOptions &options) {
  std::cout << "\n=== " << implementationName
            << " Performance Benchmark ===" << std::endl;

  // Test configurations for performance
  struct KeyConfig {
    int keySize;
    std::string name;
  };

  KeyConfig keys[] = {
      {128, "AES128"}, {256, "AES256"} // Focus on 128 and 256 for performance
  };

  std::string modes[] = {"ECB", "CBC", "CTR"};
  std::vector<size_t> perfSizes = {1024, 4096, 16384,
                                   65536}; // Regular performance sizes
  bool allSuccessful = true;

  // Print header for regular performance tests
  std::cout << "\n--- Regular Performance Tests ---" << std::endl;
  std::cout << std::left << std::setw(8) << "Mode" << std::setw(8) << "KeySize"
            << std::setw(10) << "DataSize" << std::setw(12) << "Encrypt(ms)"
            << std::setw(12) << "Decrypt(ms)" << std::setw(15)
            << "Throughput(MB/s)" << std::endl;
  std::cout << std::string(75, '-') << std::endl;

  for (const auto &keyConfig : keys) {
    for (const auto &mode : modes) {
      for (size_t dataSize : perfSizes) {
        TestResult result;
        size_t keyLength = 0;
        const uint8_t *key =
            getCurrentKey(options, keyConfig.keySize, keyLength);

        switch (keyConfig.keySize) {
        case 128:
          result = benchmarkImplementation<128>(key, keyLength, dataSize, mode,
                                                Padding::PKCS7,
                                                implementationName, options);
          break;
        case 256:
          result = benchmarkImplementation<256>(key, keyLength, dataSize, mode,
                                                Padding::PKCS7,
                                                implementationName, options);
          break;
        }

        allSuccessful = allSuccessful && result.success;
        if (result.success) {
          std::cout << std::left << std::setw(8) << mode << std::setw(8)
                    << keyConfig.name << std::setw(10) << dataSize
                    << std::setw(12) << std::fixed << std::setprecision(3)
                    << result.encryptTime << std::setw(12) << result.decryptTime
                    << std::setw(15)
                    << result.message.substr(result.message.find(":") + 2)
                    << std::endl;
        } else {
          std::cout << "[FAIL] " << mode << " " << keyConfig.name << " "
                    << dataSize << " bytes: " << result.message << std::endl;
        }
      }
    }
  }

  // 100MB Performance Benchmark
  std::cout << "\n--- 100MB Large Data Performance Benchmark ---" << std::endl;
  std::cout
      << "Testing with 100MB data size for realistic throughput measurement..."
      << std::endl;
  std::cout << std::left << std::setw(8) << "Mode" << std::setw(8) << "KeySize"
            << std::setw(12) << "Encrypt(ms)" << std::setw(12) << "Decrypt(ms)"
            << std::setw(20) << "Throughput(MB/s)" << std::setw(12) << "Status"
            << std::endl;
  std::cout << std::string(75, '-') << std::endl;

  const size_t LARGE_DATA_SIZE = 100 * 1024 * 1024; // 100MB

  for (const auto &keyConfig : keys) {
    for (const auto &mode : modes) {
      TestResult result;
      size_t keyLength = 0;
      const uint8_t *key = getCurrentKey(options, keyConfig.keySize, keyLength);

      std::cout << std::left << std::setw(8) << mode << std::setw(8)
                << keyConfig.name << std::flush;

      switch (keyConfig.keySize) {
      case 128:
        result = benchmarkLargeData<128>(key, keyLength, LARGE_DATA_SIZE, mode,
                                         Padding::PKCS7, implementationName,
                                         options);
        break;
      case 256:
        result = benchmarkLargeData<256>(key, keyLength, LARGE_DATA_SIZE, mode,
                                         Padding::PKCS7, implementationName,
                                         options);
        break;
      }

      allSuccessful = allSuccessful && result.success;
      if (result.success) {
        std::cout << std::setw(12) << std::fixed << std::setprecision(1)
                  << result.encryptTime << std::setw(12) << result.decryptTime
                  << std::setw(20)
                  << result.message.substr(result.message.find(":") + 2)
                  << std::setw(12) << "PASS" << std::endl;
      } else {
        std::cout << std::setw(12) << "N/A" << std::setw(12) << "N/A"
                  << std::setw(20) << "N/A" << std::setw(12) << "FAIL"
                  << std::endl;
        std::cout << "    Error: " << result.message << std::endl;
      }
    }
  }

  std::cout << "\nNote: 100MB benchmark practical testing time." << std::endl;
  std::cout << "Throughput includes both encryption and decryption operations."
            << std::endl;
  return allSuccessful;
}
