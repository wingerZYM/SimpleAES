#pragma once

#include "test_utils.hpp"
#include <array>
#include <cerrno>
#include <limits>
#include <vector>
#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace BoundaryTests {

template <int N> bool paddedLengths() {
  const uint8_t key[N / 8] = {};
  const uint8_t iv[16] = {};
  const size_t maximum = (std::numeric_limits<size_t>::max)();
  for (Padding padding : {Padding::PKCS7, Padding::Zeros}) {
    for (bool cbc : {false, true}) {
      CWAes<N> aes(key, sizeof(key), cbc ? iv : nullptr, sizeof(iv), padding);
      const size_t largest = maximum - 15;
      if (aes.SumCipherLength(largest - 1) != largest ||
          aes.SumCipherLength(largest) !=
              (padding == Padding::Zeros ? largest : 0)) {
        return false;
      }
      // No input allocation is needed: unrepresentable lengths must be rejected
      // before either pointer is accessed, even with SIZE_MAX output capacity.
      const size_t firstInvalid =
          padding == Padding::Zeros ? largest + 1 : largest;
      for (size_t length = firstInvalid;; ++length) {
        if (aes.SumCipherLength(length) != 0) {
          return false;
        }
        for (size_t capacity : {size_t(0), maximum}) {
          uint8_t output = 0xa5;
          if (aes.Cipher(nullptr, length, &output, capacity) || capacity != 0 ||
              output != 0xa5) {
            return false;
          }
        }
        if (length == maximum) {
          break;
        }
      }
      for (size_t length : {size_t(0), size_t(1), size_t(15), size_t(16),
                            size_t(17), size_t(32)}) {
        const size_t expected = padding == Padding::PKCS7
                                    ? (length / 16 + 1) * 16
                                    : ((length + 15) / 16) * 16;
        if (aes.SumCipherLength(length) != expected) {
          return false;
        }
      }
    }
  }
  return true;
}

template <int N> bool emptyPlaintext() {
  const uint8_t key[N / 8] = {};
  const uint8_t iv[16] = {};
  const std::vector<uint8_t> empty;
  for (bool cbc : {false, true}) {
    CWAes<N> aes(key, sizeof(key), cbc ? iv : nullptr, sizeof(iv));
    std::array<uint8_t, 16> encrypted{};
    size_t size = encrypted.size();
    if (!aes.Cipher(empty.data(), empty.size(), encrypted.data(), size) ||
        size != 16) {
      return false;
    }
    size_t recovered = 0;
    if (!aes.InvCipher(encrypted.data(), size, nullptr, recovered) ||
        recovered != 0) {
      return false;
    }
    CWAes<N> zero(key, sizeof(key), cbc ? iv : nullptr, sizeof(iv),
                  Padding::Zeros);
    size = 0;
    if (!zero.Cipher(nullptr, 0, nullptr, size) || size != 0) {
      return false;
    }
  }
  return true;
}

inline TestUtils::TestResult forkNonce() {
#if defined(__unix__) || defined(__APPLE__)
  const uint8_t key[16] = {};
  CWAes128 aes(key, sizeof(key));
  GCMResult warm{};
  size_t size = 0;
  if (!aes.SetAAD() || !aes.CipherGCM(nullptr, 0, nullptr, size, warm)) {
    return {false, "nonce warm-up failed"};
  }
  int descriptors[2];
  if (pipe(descriptors) != 0) {
    return {false, "pipe failed"};
  }
  const pid_t child = fork();
  if (child < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    return {false, "fork failed"};
  }
  GCMResult result{};
  const bool ok = aes.CipherGCM(nullptr, 0, nullptr, size, result);
  if (child == 0) {
    close(descriptors[0]);
    ssize_t sent;
    do {
      sent = write(descriptors[1], result.nonce.data(), result.nonce.size());
    } while (sent < 0 && errno == EINTR);
    close(descriptors[1]);
    _exit(ok && sent == static_cast<ssize_t>(result.nonce.size()) ? 0 : 1);
  }
  close(descriptors[1]);
  std::array<uint8_t, WAesGCMNonceSize> childNonce{};
  size_t received = 0;
  while (received < childNonce.size()) {
    const ssize_t count = read(descriptors[0], childNonce.data() + received,
                               childNonce.size() - received);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      break;
    }
    received += static_cast<size_t>(count);
  }
  close(descriptors[0]);
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  return {ok && received == childNonce.size() && waited == child &&
              WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
              childNonce != result.nonce,
          "parent/child nonce after warm-up"};
#else
  return {true, "fork unavailable on this platform (skipped)"};
#endif
}

inline TestUtils::TestSummary run(const std::string &name) {
  TestUtils::TestSummary summary;
  const auto check = [&](bool ok, const char *test) {
    TestUtils::printTestResult({ok}, name + "-Boundary-" + test);
    summary.addResult(ok);
  };
  check(paddedLengths<128>(), "Lengths128");
  check(paddedLengths<192>(), "Lengths192");
  check(paddedLengths<256>(), "Lengths256");
  check(emptyPlaintext<128>(), "Empty128");
  check(emptyPlaintext<192>(), "Empty192");
  check(emptyPlaintext<256>(), "Empty256");
  const auto forkResult = forkNonce();
  TestUtils::printTestResult(forkResult, name + "-Boundary-ForkNonce");
  summary.addResult(forkResult.success);
  return summary;
}

} // namespace BoundaryTests
