# SimpleAES

[中文说明](README_CN.md)

Possibly the simplest C++ AES encryption/decryption library.

## How simple is it?

In any C++11-compatible environment, all you need is a single `hpp` header file:

```c++
#include "WAes-gen.hpp"
```

Yes, just include this header in your source file and you're ready to perform AES encryption and decryption. As long as the compiler supports C++11, there are no other dependencies. It can even be integrated into Objective-C++ `.mm` files, and it won't introduce any new runtime dependencies to your final application.

## Implementation Versions

The library now provides multiple optimized versions of AES implementation:

### 📦 Generic Version
- **`WAes-gen.hpp`** - Pure C++ implementation, compatible with all platforms and compilers supporting C++11+

### ⚡ Hardware-Accelerated Versions

#### x86/x64 Architecture
- **`WAes-ni.hpp`** - Hardware-accelerated version based on Intel AES-NI instruction set
- **`WAes-vaes.hpp`** - Advanced hardware-accelerated version based on Intel VAES (AVX2) instruction set
- **`WAes-vaes512.hpp`** - Ultra-high performance version based on Intel VAES (AVX512) instruction set

#### ARM Architecture  
- **`WAes-armv8.hpp`** - ARM64 accelerated version based on ARMv8-A AES hardware instructions

### 🚀 Performance Comparison
Performance ranking from lowest to highest:
```
Generic < AES-NI < VAES (AVX2) < VAES512 (AVX512)
```

All versions share the exact same public interface, so switching between implementations is as simple as changing the included header file.

## What can it do despite being so simple?

The library was designed with the principles of simplicity, ease of use, **sufficiency**, efficiency, and no external dependencies. Therefore, instead of supporting all encryption modes, it focuses only on the most commonly used ones to meet the needs of most real-world and testing scenarios with minimal implementation. Specifically, it supports:

* 128, 192, and 256-bit key lengths
* ECB, CBC, and CTR encryption modes
* Zero and PKCS7 padding schemes

These combinations are currently sufficient for all of my own production and testing environments.

## How to use it?

Here's how to encrypt and decrypt data using a 128-bit key as an example.

Create an AES-128 ECB object:

```c++
const uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

const uint8_t iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const uint8_t data[16] =  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

uint8_t plaintext[16] = {}, ciphertext[32] = {};

// ECB / pkcs7 padding
CWAes128 ecb(key, 16);
```

Create an AES-128 CBC object:

```c++
// CBC / Zero padding
CWAes128 cbc(key, 16, iv, 16, Padding::Zeros);
cbc.SetIV(iv2, 16); // You can change the IV and switch to CBC mode at any time.
```

Create an AES-128 CTR object:

```c++
// CTR / no padding
CWAes128 ctr(key, 16);
ctr.SetCounter(iv, 16); // Set counter and switch to CTR mode.
```

Encryption:

```c++
CWAes aes(...);
auto outLen = aes.Cipher(data, 16, ciphertext, sizeof(ciphertext));
```

Decryption:

```c++
CWAes aes(...);
auto outLen = aes.InvCipher(ciphertext, 32, plaintext, sizeof(plaintext));
```

The encryption mode and padding method are determined when constructing the AES object. You can later switch modes using `SetIV` or `SetCounter`. The encryption and decryption interfaces are the same across all modes.

## Hardware-Accelerated Versions Detailed

### Intel AES-NI Version
`WAes-ni.hpp` is based on Intel AES-NI instruction set, providing approximately 4x performance improvement over the generic version.

**Compilation Requirements**:
```shell
c++ -std=c++11 -mssse3 -maes test.cpp
```

### Intel VAES Version  
`WAes-vaes.hpp` is based on AVX2 + VAES instruction set, capable of processing 2 AES blocks in parallel for higher performance.

**Compilation Requirements**:
```shell
c++ -std=c++11 -mavx2 -mvaes test.cpp
```

### Intel VAES512 Version
`WAes-vaes512.hpp` is based on AVX512 + VAES instruction set, capable of processing 4 AES blocks in parallel for ultimate performance.

**Compilation Requirements**:
```shell
c++ -std=c++11 -mavx512f -mvaes test.cpp
```

### ARMv8 Version
`WAes-armv8.hpp` is based on ARMv8-A AES hardware instructions, suitable for ARM64 platforms.

**Compilation Requirements**:
```shell
# Linux ARM64
c++ -std=c++11 -march=armv8-a+crypto test.cpp

# macOS ARM64 (no additional flags needed)
c++ -std=c++11 test.cpp
```

## 🧪 Test Framework (`tests/` Directory)

To ensure consistency and correctness across different implementations, the project provides a comprehensive test framework:

### Test Components

#### Core Test Files
- **`test_template.hpp`** - Generic test template containing all test logic
- **`test_data.hpp`** - Test data definitions (keys, IVs, test vectors, etc.)
- **`test_utils.hpp`** - Test utility functions (timers, data comparison, etc.)

#### Implementation Test Files
- **`test_generic.cpp`** - Generic implementation tests
- **`test_aes_ni.cpp`** - AES-NI implementation tests
- **`test_vaes.cpp`** - VAES (AVX2) implementation tests
- **`test_vaes512.cpp`** - VAES512 (AVX512) implementation tests
- **`test_armv8.cpp`** - ARMv8 implementation tests

#### Cross-Implementation Comparison Tools
- **`compare_implementations.cpp`** - Cross-implementation comparison tool
- **`Makefile`** - Automated build and test system

### Test Features

#### 📋 Functionality Tests
Tests all supported configuration combinations:
- **Key Lengths**: 128-bit, 192-bit, 256-bit
- **Encryption Modes**: ECB, CBC, CTR
- **Padding Methods**: PKCS7, Zeros
- **Data Sizes**: 16, 32, 48, 64, 192, 1024 bytes

#### ⚡ Performance Tests
- Encryption/decryption throughput testing
- Performance comparison across different data sizes
- Benchmarking between different implementations

#### 🔄 Cross-Implementation Consistency Verification
- Automatic detection of available hardware implementations
- Verification that all implementations produce identical encryption results
- Random parameter testing for enhanced test coverage

### Usage

#### Check Platform Support
```bash
cd tests
make check-platform
```

#### Run Individual Implementation Tests
```bash
make run-generic     # Generic implementation
make run-aes-ni      # AES-NI implementation
make run-vaes        # VAES implementation
make run-vaes512     # VAES512 implementation (if supported)
make run-armv8       # ARMv8 implementation (ARM64 platforms)
```

#### Run Performance Tests
```bash
make run-perf-all    # Performance tests for all implementations
make run-perf-vaes512  # VAES512 performance test
```

#### Cross-Implementation Comparison
```bash
# Build comparison tool
make compare

# Auto-detect and compare all available implementations
make cross-compare
# or directly run:
./compare-implementations

# Manually specify implementations to compare
make cmp-specific IMPLS='Generic AES-NI VAES VAES512'
# or directly run:
./compare-implementations Generic AES-NI VAES VAES512

# Keep test files for debugging
./compare-implementations --keep-files --verbose
```

#### Run Complete Test Suite
```bash
make run-all         # Run functionality tests for all available implementations
make cross-compare   # Run cross-implementation comparison
```

### Test Output Example

```bash
$ make check-platform
Platform Detection:
  OS: Linux
  Architecture: x86_64
  Detected Platform: x86_64
  AES-NI Support: yes
  VAES Support: yes
  VAES512 Support: yes
  Building: Generic, AES-NI, VAES, VAES512 tests

$ ./compare-implementations
AES Implementation Comparison Tool
==================================================
Auto-detected implementations: Generic, AES-NI, VAES, VAES512
Comparing implementations: Generic, AES-NI, VAES, VAES512

Running tests for Generic...
  ✓ Generic tests completed successfully
Running tests for AES-NI...
  ✓ AES-NI tests completed successfully
Running tests for VAES...
  ✓ VAES tests completed successfully
Running tests for VAES512...
  ✓ VAES512 tests completed successfully

============================================================
Cross-Implementation Comparison Results
============================================================
[PASS] ECB_128_PKCS7_16
[PASS] ECB_128_PKCS7_32
...
[PASS] CTR_256_NoPad_1024

============================================================
SUMMARY REPORT
============================================================
Implementations tested: Generic, AES-NI, VAES, VAES512
Total tests: 54
Passed: 54
Failed: 0
Success rate: 100.0%

🎉 All tests PASSED! All implementations are equivalent.
```

## Compatibility Information

### Hardware Requirements

| Implementation | Minimum Hardware Requirements | Recommended Use |
|---------------|------------------------------|-----------------|
| Generic | Any CPU | Compatibility-first scenarios |
| AES-NI | Intel Westmere (2010+)<br>AMD Bulldozer (2011+) | General x86 servers |
| VAES | Intel Ice Lake (2019+)<br>AMD Zen 3 (2020+) | Modern high-performance servers |
| VAES512 | Intel Skylake-X (2017+)<br>Intel Ice Lake (2019+) | Specialized high-performance computing |
| ARMv8 | ARMv8-A with Crypto extensions | ARM64 servers/mobile devices |

### Version Selection Guidelines

1. **Development/Testing**: Use `Generic` version for maximum compatibility
2. **Modern x86 Servers**: Prefer `VAES` version
3. **High-Performance Computing**: Use `VAES512` version on supported platforms
4. **ARM64 Devices**: Use `ARMv8` version
5. **Cross-Platform Deployment**: Runtime detection and selection of appropriate version

## Are there any known limitations?

Some AES operations are naturally parallelizable—like ECB encryption/decryption and CBC decryption. However, introducing concurrency adds code complexity. Also, the benefits on small datasets may not justify the cost. In line with the design philosophy of satisfying most use cases with minimal implementation, this library does not implement concurrency.

However, the newly added VAES and VAES512 versions implement parallel processing at the instruction level, significantly improving performance while maintaining interface simplicity.