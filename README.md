# SimpleAES

[中文说明](README_CN.md)

Possibly the simplest C++ AES encryption/decryption library.

## How simple is it?

In any C++11-compatible environment, all you need is a single `hpp` header file:

```c++
#include "WAes-gen.hpp"
```

Yes, just include this header in your source file and you're ready to perform AES encryption and decryption. As long as the compiler supports C++11, there are no other dependencies. It can even be integrated into Objective-C++ `.mm` files, and it won't introduce any new runtime dependencies to your final application.

## Two ways to use

The library offers two approaches -- **standalone single-backend headers** and a **unified adaptive header** -- to cover different deployment scenarios.

### Standalone Headers (Single Backend)

Each `WAes-*.hpp` is a complete, self-contained AES implementation targeting a specific instruction set. Include one header, get one backend -- no abstraction overhead, no runtime dispatch.

| Header | Backend |
|--------|---------|
| `WAes-gen.hpp` | Pure C++ (Generic) |
| `WAes-ni.hpp` | Intel AES-NI |
| `WAes-vaes.hpp` | Intel VAES (AVX2) |
| `WAes-vaes512.hpp` | Intel VAES (AVX512) |
| `WAes-armv8.hpp` | ARMv8-A Crypto |

**Best for**: Server-side programs and embedded systems where the target platform is known at build time. You pick the fastest backend your hardware supports and compile directly against it -- zero indirection, maximum performance.

### Unified Adaptive Header (`WAes.hpp`)

`WAes.hpp` bundles the implementations into one file. It selects among the backends compiled for the target and, on x86, verifies CPU and OS SIMD-state support before using a hardware backend. It exposes a polymorphic `WAes::Ptr` interface with a factory function:

```c++
#include "WAes.hpp"

// Auto-select the best backend
auto aes = WAes::Create<128>(key, keyLen, iv, ivLen);
aes->Cipher(plaintext, plainLen, ciphertext, cipherLen);
```

You can also explicitly request a specific backend at runtime:

```c++
auto aes = WAes::Create<256>(WAes::Backend::Generic, key, keyLen);
```

For bulk operations, the unified version normally performs close to the selected standalone backend. The exact difference depends on message size, mode, compiler, and CPU.

**Best for**: Applications that want one API and automatic selection among the backends present in a build. See the compilation notes below before treating a GCC/Clang build as a portable x86 fat binary.

### Performance Expectations

For sufficiently large inputs on parallelizable paths such as ECB, CTR, GCM,
and CBC decryption, the usual trend is:

```text
Generic < AES-NI < VAES (AVX2) < VAES512 (AVX512)
```

This is not a universal ordering. Small inputs, CBC encryption, compiler code
generation, CPU frequency behavior, and the cost of wider vector states can
change the result. Benchmark the exact mode and message sizes used by the
application.

All standalone headers share the same public `CWAes<N>` interface. The unified `WAes.hpp` exposes the same operations through `WAes::Ptr`, plus additional convenience APIs.

## What can it do despite being so simple?

The library was designed with the principles of simplicity, ease of use, **sufficiency**, efficiency, and no external dependencies. Therefore, instead of supporting all encryption modes, it focuses only on the most commonly used ones to meet the needs of most real-world and testing scenarios with minimal implementation. Specifically, it supports:

* 128, 192, and 256-bit key lengths
* ECB, CBC, CTR, and authenticated GCM encryption modes
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

Use AES-128-GCM with a caller-managed nonce:

```c++
const uint8_t nonce[WAesGCMNonceSize] = {/* exactly 12 bytes */};
const uint8_t aad[] = {/* authenticated, but not encrypted */};
uint8_t tag[WAesGCMTagSize];

CWAes128 gcm(key, 16);
gcm.SetAAD(aad, sizeof(aad)); // Copies AAD and switches to GCM mode.

size_t cipherLen = dataLen;
size_t tagLen = sizeof(tag);
if (!gcm.CipherGCM(data, dataLen, ciphertext, cipherLen,
                   nonce, sizeof(nonce), tag, tagLen)) {
    // invalid arguments or insufficient output/tag capacity
}

size_t plainLen = dataLen;
if (!gcm.InvCipherGCM(ciphertext, cipherLen, plaintext, plainLen,
                      nonce, sizeof(nonce), tag, tagLen)) {
    // authentication failed; plaintext was not written
}
```

For convenience, the encryption overload taking `GCMResult` generates and
returns a nonce together with the tag:

```c++
GCMResult result;
size_t cipherLen = dataLen;
gcm.CipherGCM(data, dataLen, ciphertext, cipherLen, result);
```

GCM is intentionally a strict, one-shot profile: the nonce is exactly 12
bytes, the detached tag is exactly 16 bytes, and padding is ignored. Calling
`SetAAD(nullptr, 0)` selects GCM with empty AAD. `SetIV` and `SetCounter`
switch back to CBC and CTR respectively; while GCM is selected, the legacy
`Cipher`/`InvCipher` calls fail because those signatures cannot carry a nonce
and tag. Exact in-place input/output is supported; other overlapping buffer
layouts are unsupported. A payload is limited to 2^36 - 32 bytes, and the AAD
length must not exceed floor((2^64 - 1) / 8) bytes.

AAD may be reused and is copied by `SetAAD`; the nonce must never repeat with
the same key. The automatic overload uses a thread-local `std::mt19937` seeded
from `std::random_device`. It is a minimal convenience source, not a guarantee
of cryptographic randomness or uniqueness. Use the explicit-nonce overload
when nonce allocation must follow a stronger application protocol, and keep
automatic-nonce invocations well below 2^32 messages per key.

Encryption:

```c++
CWAes128 aes(key, 16);
size_t cipherLen = sizeof(ciphertext);
if (!aes.Cipher(data, 16, ciphertext, cipherLen)) {
    // encryption failed (buffer too small, etc.)
}
// cipherLen now holds the actual bytes written
```

Decryption:

```c++
CWAes128 aes(key, 16);
size_t plainLen = sizeof(plaintext);
if (!aes.InvCipher(ciphertext, cipherLen, plaintext, plainLen)) {
    // decryption failed (bad padding, etc.)
}
// plainLen now holds the actual bytes written (padding removed)
```

Both `Cipher` and `InvCipher` return `bool` -- `true` on success, `false` on failure. The `outLength` parameter is passed by reference: on input it gives the buffer capacity; on success it is updated to the actual number of bytes written.

`SumCipherLength(inLen)` returns the required output buffer size for `Cipher`.

The encryption mode and padding method are determined when constructing the AES object. You can later switch modes using `SetIV` or `SetCounter`. The encryption and decryption interfaces are the same across all modes.

Key lengths intentionally preserve the library's legacy compatibility behavior: short keys are zero-padded and long keys are truncated to 16, 24, or 32 bytes according to the selected AES strength. Applications that require strict key validation should reject non-exact lengths before construction.

Zero padding adds bytes only when the final block is partial; an already block-aligned input does not gain another block. Because trailing plaintext zeroes are indistinguishable from padding, Zero-padding decryption removes trailing zeroes. PKCS7 always adds padding, including a complete 16-byte padding block for aligned input.

CTR treats the supplied 16-byte value as a counter block: the first 8 bytes stay fixed and the final 8 bytes are incremented as a big-endian integer modulo 2^64. The numeric `SetCounter(iv, nonce, counter)` overload serializes all fields in big-endian order.

## Using the Unified Header (`WAes.hpp`)

`WAes.hpp` provides the same operations through a polymorphic interface with extra convenience features:

The GCM API is identical, with `GCMResult`, `GCMNonceSize`, and `GCMTagSize`
declared in the `WAes` namespace.

```c++
#include "WAes.hpp"

// Auto-select best backend
auto aes = WAes::Create<128>(key, 16, iv, 16);

// Encrypt
size_t cipherLen = aes->SumCipherLength(dataSize);
std::vector<uint8_t> ct(cipherLen);
aes->Cipher(data, dataSize, ct.data(), cipherLen);

// Decrypt
size_t plainLen = dataSize;
std::vector<uint8_t> pt(plainLen);
aes->InvCipher(ct.data(), ct.size(), pt.data(), plainLen);
```

Container overloads (returns `std::vector` directly):

```c++
auto ct = aes->Cipher(plainVec);          // encrypt vector → vector
std::vector<uint8_t> pt;
aes->InvCipher(ct, pt);                   // decrypt vector → vector
```

Explicit backend selection:

```c++
// List what's available on this machine
for (auto b : WAes::AvailableBackends())
    std::cout << WAes::GetImplName(b) << "\n";

// Inspect everything compiled into the binary (including unavailable backends)
for (auto b : WAes::CompiledBackends())
    std::cout << WAes::GetImplName(b) << "\n";

// Force a specific backend; returns nullptr if the CPU/OS cannot run it
auto aes = WAes::Create<256>(WAes::Backend::Generic, key, 32);
```

RAII scope IV (restores original IV/mode on scope exit):

```c++
{
    auto scope = aes->ScopeIV(tempIV, 16);
    aes->Cipher(...);   // uses tempIV
}
// back to original IV
```

## Compilation Requirements

### Standalone Headers

| Header | Required Flags |
|--------|---------------|
| `WAes-gen.hpp` | None (C++11) |
| `WAes-ni.hpp` | `-mssse3 -maes`; add `-mpclmul` for accelerated GCM |
| `WAes-vaes.hpp` | `-mavx2 -maes -mvaes`; add `-mpclmul` for accelerated GCM |
| `WAes-vaes512.hpp` | `-mavx512f -mavx512bw -mavx512dq -mavx512vl -maes -mvaes`; add `-mpclmul` for accelerated GCM |
| `WAes-armv8.hpp` | `-march=armv8-a+crypto` (Linux/macOS ARM64) |

All standalone variants require at least `-std=c++11`; `-std=c++17 -O3` is recommended.
The headers contain no exception-handling syntax and can be compiled with
`-fno-exceptions`. In such builds, allocation failures from AAD/container
storage and failures inside the standard `std::random_device` implementation
follow the host standard library's no-exception failure policy; they are not
converted into a `false` return value.

### Unified Header (`WAes.hpp`)

`WAes.hpp` requires **C++20** (uses `std::span`). It detects the target platform via preprocessor macros and enables the backends allowed by the compiler target:

```shell
# x86: enables Generic + AES-NI + VAES/VAES512 as supported
c++ -std=c++20 -O3 -march=native WAes_example.cpp

# ARM64 Linux
c++ -std=c++20 -O3 -march=armv8-a+crypto WAes_example.cpp
```

On GCC and Clang, instruction-set flags apply to the translation unit as a whole. A build made with `-march=native` is intended for that CPU class and must not be assumed to run on older x86 processors. Compile without AES/VAES target flags for a baseline Generic-only binary. MSVC builds include the x86 hardware implementations and use CPUID plus XGETBV at runtime; `AvailableBackends()` returns only implementations executable by both the current CPU and OS.

On AArch64, the unified header enables the ARM crypto backend when the compiler
exposes `__ARM_FEATURE_AES` or `__ARM_FEATURE_CRYPTO`. PMULL accelerates GCM
when the crypto feature macro is available. A toolchain that exposes neither
macro may define `WAES_ASSUME_ARM_CRYPTO`, but only when deployment hardware is
guaranteed to implement the extension.

## Security Considerations

SimpleAES provides AES primitives plus a deliberately small, one-shot GCM API.

- ECB reveals repeated-block patterns and is generally unsuitable for ordinary
  application data.
- CBC and CTR do not authenticate ciphertext. Pair them with a correctly
  designed MAC, or prefer GCM for new message encryption.
- GCM nonces must never repeat under the same key. Authentication failure is
  reported as `false` and leaves the plaintext output untouched.
- CBC IVs must be unpredictable. A CTR counter/nonce must never be reused with
  the same key.
- The Generic backend uses key-dependent T-table lookups for speed and is not
  constant-time with respect to cache access. Do not use it where local
  timing/cache side-channel attacks are in scope; prefer a hardware backend.
- Zero padding cannot distinguish padding bytes from genuine trailing zeroes.
  PKCS7 decryption failures must not be exposed in a way that creates a padding
  oracle.

## 🧪 Test Framework (`tests/` Directory)

The test suite checks every standalone implementation and the unified adaptive
header. See [`tests/README.md`](tests/README.md) for the full command reference.

### Test Components

- **Shared infrastructure**: `test_data.hpp`, `test_utils.hpp`,
  `test_options.hpp`, `test_known_answers.hpp`, `test_gcm.hpp`,
  `test_template.hpp`, and `test_entry.hpp`
- **Standalone tests**: `test_generic.cpp`, `test_generic_multitu_main.cpp`,
  `test_generic_multitu.cpp`, `test_cxx11_gcm.cpp`, `test_aes_ni.cpp`, `test_vaes.cpp`,
  `test_vaes512.cpp`, and `test_armv8.cpp`
- **Unified tests**: `test_waes.cpp`, `test_waes_adapter.hpp`,
  `test_waes_cross.hpp`, and `test_waes_regressions.hpp`
- **Cross-process comparison**: `compare_implementations.cpp`
- **Build and test automation**: `Makefile`

### Test Features

- **Known-answer tests**: 10 FIPS-197, NIST SP 800-38A, and SP 800-38D vectors
  covering ECB, CBC, CTR, and GCM
- **Focused GCM tests**: AAD, partial/empty messages, automatic nonces, exact
  in-place use, state transitions, and authenticate-before-write failures
- **Deterministic matrix**: 18 mode/key/padding configurations across 25
  boundary and multi-block lengths (1 through 271 bytes), for 450 round trips
- **Validation cases**: 6 malformed-PKCS7 rejection tests, giving 471
  functional checks per standalone backend
- **Unified validation**: direct in-process comparison of every compiled and
  executable backend, plus guard-page, padding, in-place, unaligned-I/O, and
  CTR-counter regression tests
- **Performance tests**: 1, 4, 16, and 64 KiB workloads plus a 100 MiB
  sustained-throughput benchmark; results are reported in MiB/s
- **Custom deterministic parameters**: keys, IV, and counter can be supplied
  with `--custom-params`

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
make run-waes        # Unified adaptive implementation
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
./out/bin/compare-implementations

# Manually specify implementations to compare
make cmp-specific IMPLS='Generic WAes AES-NI VAES VAES512'
# or directly run:
./out/bin/compare-implementations Generic WAes AES-NI VAES VAES512

# Keep test files for debugging
./out/bin/compare-implementations --keep-files --verbose
```

#### Run Complete Test Suite
```bash
make run-all         # Run functionality tests for all available implementations
make cross-compare   # Run cross-implementation comparison
make sanitize        # Run Generic and baseline WAes with ASan/UBSan
```

`make cross-compare` auto-detects `Generic`, `WAes`, and any supported hardware
backends. It compares the 450 deterministic matrix records. The exact backend
list is platform- and compiler-dependent.

## Compatibility Information

### Hardware Requirements

| Implementation | Minimum Hardware Requirements | Recommended Use |
|---------------|------------------------------|-----------------|
| Generic | Any target with a C++11 compiler | Compatibility-first scenarios |
| AES-NI | x86 with SSSE3 and AES | General x86 systems |
| VAES | x86 with SSSE3, AES, AVX2, and VAES | Parallelizable workloads on modern x86 systems |
| VAES512 | x86 with SSSE3, AES, AVX2, VAES, AVX512F/BW/DQ/VL | Systems verified to expose all required features |
| ARMv8 | AArch64 with the Crypto Extension | ARM64 servers/mobile devices |

### Which header should I use?

| Scenario | Recommendation |
|----------|----------------|
| Server / embedded, known platform | Standalone header matching your CPU (e.g. `WAes-vaes.hpp`) |
| Distributed x86 client, unknown hardware | MSVC-built `WAes.hpp`, or a baseline Generic-only GCC/Clang build |
| Development / CI | `WAes-gen.hpp` or `WAes.hpp` |
| ARM64 with Crypto Extension | `WAes-armv8.hpp` or a `WAes.hpp` build targeting `+crypto` |

The guiding principle: if you know the platform at build time, the standalone header gives you the most direct path -- no virtual dispatch, no abstraction layer. The unified header centralizes the API and safely selects among the implementations actually compiled into the binary; binary portability still depends on the compiler target flags described above.

## Are there any known limitations?

Some AES operations are naturally parallelizable—like ECB encryption/decryption and CBC decryption. However, introducing concurrency adds code complexity. Also, the benefits on small datasets may not justify the cost. In line with the design philosophy of satisfying most use cases with minimal implementation, this library does not implement concurrency.

However, the newly added VAES and VAES512 versions implement parallel processing at the instruction level, significantly improving performance while maintaining interface simplicity.
