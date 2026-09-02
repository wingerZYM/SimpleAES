#pragma once

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>

namespace TestUtils {

// Compare two data arrays
bool compareData(const uint8_t *data1, const uint8_t *data2, size_t len) {
  return memcmp(data1, data2, len) == 0;
}

// Compare two vectors
bool compareData(const std::vector<uint8_t> &data1,
                 const std::vector<uint8_t> &data2) {
  if (data1.size() != data2.size())
    return false;
  return compareData(data1.data(), data2.data(), data1.size());
}

// Test result structure
struct TestResult {
  bool success;
  std::string message;
  double encryptTime;
  double decryptTime;
  size_t dataSize;

  TestResult(bool s = false, const std::string &msg = "", double encTime = 0.0,
             double decTime = 0.0, size_t size = 0)
      : success(s), message(msg), encryptTime(encTime), decryptTime(decTime),
        dataSize(size) {}
};

// Print test result
void printTestResult(const TestResult &result, const std::string &testName) {
  std::cout << "[" << (result.success ? "PASS" : "FAIL") << "] " << testName;
  if (result.dataSize > 0) {
    std::cout << " (" << result.dataSize << " bytes)";
  }
  if (!result.message.empty()) {
    std::cout << " - " << result.message;
  }
  if (result.success && (result.encryptTime > 0 || result.decryptTime > 0)) {
    std::cout << " [Enc: " << std::fixed << std::setprecision(3)
              << result.encryptTime << "ms";
    std::cout << ", Dec: " << result.decryptTime << "ms]";
  }
  std::cout << std::endl;
}

// High-resolution timer
class Timer {
private:
  std::chrono::high_resolution_clock::time_point start_time;

public:
  void start() { start_time = std::chrono::high_resolution_clock::now(); }

  double elapsed() const {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    return duration.count() / 1000.0; // Return milliseconds
  }
};

// Test summary structure
struct TestSummary {
  int totalTests;
  int passedTests;
  int failedTests;

  TestSummary() : totalTests(0), passedTests(0), failedTests(0) {}

  void addResult(bool success) {
    totalTests++;
    if (success) {
      passedTests++;
    } else {
      failedTests++;
    }
  }

  void merge(const TestSummary &other) {
    totalTests += other.totalTests;
    passedTests += other.passedTests;
    failedTests += other.failedTests;
  }

  bool success() const { return failedTests == 0; }

  void print(const std::string &suiteName) const {
    std::cout << "\n=== " << suiteName << " Test Summary ===" << std::endl;
    std::cout << "Total tests: " << totalTests << std::endl;
    std::cout << "Passed: " << passedTests << std::endl;
    std::cout << "Failed: " << failedTests << std::endl;
    std::cout << "Success rate: " << std::fixed << std::setprecision(1)
              << (totalTests > 0 ? (passedTests * 100.0 / totalTests) : 0.0)
              << "%" << std::endl;
  }
};

} // namespace TestUtils
