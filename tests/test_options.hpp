#pragma once

#include "test_data.hpp"

#include <cctype>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

struct TestOptions {
  bool enableFileOutput = false;
  bool useCustomParams = false;
  bool runPerformance = false;
  bool showHelp = false;
  bool valid = true;
  std::vector<uint8_t> key128;
  std::vector<uint8_t> key192;
  std::vector<uint8_t> key256;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> counter;
};

inline std::string getEnvironmentVariable(const char *name) {
#if defined(_WIN32)
  char *value = nullptr;
  size_t length = 0;
  if (_dupenv_s(&value, &length, name) != 0 || !value)
    return {};
  std::string result(value);
  std::free(value);
  return result;
#else
  const char *value = std::getenv(name);
  return value ? std::string(value) : std::string{};
#endif
}

inline bool shouldWriteToFile(const TestOptions &options) {
  return getEnvironmentVariable("ENABLE_FILE_OUTPUT") == "1" ||
         options.enableFileOutput;
}

inline bool decodeHex(const std::string &hex, size_t expectedBytes,
                      std::vector<uint8_t> &output) {
  if (hex.size() != expectedBytes * 2)
    return false;

  for (unsigned char ch : hex) {
    if (!std::isxdigit(ch))
      return false;
  }

  output.resize(expectedBytes);
  for (size_t i = 0; i < expectedBytes; ++i) {
    output[i] = static_cast<uint8_t>(
        std::strtoul(hex.substr(i * 2, 2).c_str(), nullptr, 16));
  }
  return true;
}

inline bool setCustomParameters(TestOptions &options,
                                const std::string &key128,
                                const std::string &key192,
                                const std::string &key256,
                                const std::string &iv,
                                const std::string &counter) {
  TestOptions parsed = options;
  if (!decodeHex(key128, 16, parsed.key128) ||
      !decodeHex(key192, 24, parsed.key192) ||
      !decodeHex(key256, 32, parsed.key256) ||
      !decodeHex(iv, 16, parsed.iv) ||
      !decodeHex(counter, 16, parsed.counter)) {
    return false;
  }

  parsed.useCustomParams = true;
  options = std::move(parsed);
  return true;
}

inline const uint8_t *getCurrentKey(const TestOptions &options, int keySize,
                                    size_t &keyLength) {
  using namespace TestData;
  switch (keySize) {
  case 128:
    if (options.useCustomParams) {
      keyLength = options.key128.size();
      return options.key128.data();
    }
    keyLength = AES128_KEY_SIZE;
    return AES128_KEY;
  case 192:
    if (options.useCustomParams) {
      keyLength = options.key192.size();
      return options.key192.data();
    }
    keyLength = AES192_KEY_SIZE;
    return AES192_KEY;
  case 256:
    if (options.useCustomParams) {
      keyLength = options.key256.size();
      return options.key256.data();
    }
    keyLength = AES256_KEY_SIZE;
    return AES256_KEY;
  default:
    keyLength = 0;
    return nullptr;
  }
}

inline const uint8_t *getCurrentIV(const TestOptions &options) {
  return options.useCustomParams ? options.iv.data() : TestData::TEST_IV;
}

inline const uint8_t *getCurrentCounter(const TestOptions &options) {
  return options.useCustomParams ? options.counter.data()
                                 : TestData::TEST_COUNTER;
}

inline void printTestHelp(const char *program) {
  std::cout << "Usage: " << program << " [options]\n"
            << "Options:\n"
            << "  --enable-file-output, -f         Write comparison results\n"
            << "  --custom-params <k128> <k192> <k256> <iv> <ctr>\n"
            << "                                   Use hexadecimal parameters\n"
            << "  --help, -h                       Show this help\n"
            << "  perf                             Run performance tests only\n";
}

inline TestOptions parseTestOptions(int argc, char *argv[]) {
  TestOptions options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--enable-file-output" || arg == "-f") {
      options.enableFileOutput = true;
    } else if (arg == "perf") {
      options.runPerformance = true;
    } else if (arg == "--custom-params") {
      if (i + 5 >= argc ||
          !setCustomParameters(options, argv[i + 1], argv[i + 2], argv[i + 3],
                               argv[i + 4], argv[i + 5])) {
        std::cerr << "Invalid --custom-params values\n";
        options.valid = false;
        return options;
      }
      i += 5;
      std::cout << "Using custom test parameters\n";
    } else if (arg == "--help" || arg == "-h") {
      options.showHelp = true;
    }
  }
  return options;
}
