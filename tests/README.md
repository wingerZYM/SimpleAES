# AES Library Test Suite

> **[中文版 / Chinese Version](README_CN.md)**

This test suite is designed to verify multiple AES implementations across different platforms: generic code (all platforms), AES-NI instruction set (x86-64), VAES instruction set (x86-64), VAES512 instruction set (x86-64), and ARMv8 Crypto Extensions (ARM64).

The standalone test programs each include one `WAes-*.hpp` implementation to
verify that the headers remain interchangeable. The unified `test_waes`
program is different: it instantiates every compiled backend that is executable
on the current machine and compares them directly in one process.

## File Structure

### Core Files
- `test_data.hpp` - Common test data and constants
- `test_utils.hpp` - Test utility functions and helper classes
- `test_options.hpp` - Validated command-line options and custom parameters
- `test_known_answers.hpp` - FIPS-197, NIST SP 800-38A, and SP 800-38D known-answer vectors
- `test_gcm.hpp` - GCM AAD, authentication-failure, in-place, state, and automatic-nonce tests
- `test_template.hpp` - Shared functional tests and benchmarks
- `test_entry.hpp` - Common standalone-header executable entry point
- `test_waes_adapter.hpp` - Adapter used to run the shared suite through `WAes.hpp`
- `test_waes_cross.hpp` - Unified-header cross-backend validation
- `test_waes_regressions.hpp` - Guard-page and bug regression tests

### Test Files
- `test_generic.cpp` - Generic AES implementation test (WAes-gen.hpp)
- `test_generic_multitu_main.cpp` - Entry point for the C++11 multi-TU link test
- `test_generic_multitu.cpp` - Second translation unit for Generic header/link testing
- `test_cxx11_gcm.cpp` - C++11 GCM API smoke test for every standalone header
- `test_aes_ni.cpp` - AES-NI instruction set implementation test (WAes-ni.hpp) [x86-64 only]
- `test_vaes.cpp` - VAES instruction set implementation test (WAes-vaes.hpp) [x86-64 only]
- `test_vaes512.cpp` - VAES512 instruction set implementation test (WAes-vaes512.hpp) [x86-64 only]
- `test_armv8.cpp` - ARMv8 Crypto Extensions implementation test (WAes-armv8.hpp) [ARM64 only]
- `test_waes.cpp` - Unified adaptive-header test and in-process backend comparison

### Build and Run Files
- `Makefile` - Build system with platform and instruction-set detection
- `.gitignore` - Ignores the `out/` output directory

### Comparison Tool
- `compare_implementations.cpp` - Cross-implementation comparison tool

### Output Directory (generated, git-ignored)
```
out/
├── bin/        ← compiled executables
└── reports/    ← timestamped test reports
```

## Test Coverage

Each standalone implementation tests:

- 10 standard known-answer encryption/decryption vectors
- 1 OpenSSL-compatible full-width CTR carry vector
- 5 focused GCM behavior and failure tests
- 450 deterministic round trips: 18 mode/key/padding configurations across
  25 boundary and multi-block lengths
- 6 deterministic malformed-PKCS7 rejection cases
- A nonzero process exit code when any correctness check fails
- All test targets compile with `-fno-exceptions`

That gives 472 functional checks per standalone backend. The unified test also
runs the same shared suite, directly cross-validates its available backends, and
runs backend availability, guard-page, padding, in-place, unaligned-I/O,
scoped-AAD restoration, and full-128-bit CTR counter regressions.

### AES Modes
- **ECB Mode** - Electronic Codebook mode
- **CBC Mode** - Cipher Block Chaining mode
- **CTR Mode** - Counter mode
- **GCM Mode** - Authenticated encryption with associated data

### Key Lengths
- **AES-128** - 128-bit key
- **AES-192** - 192-bit key
- **AES-256** - 256-bit key

### Padding Schemes
- **PKCS7 Padding** - Standard PKCS#7 padding
- **Zero Padding** - Zero byte padding
- **No Padding** - CTR and GCM do not use padding

### Data Lengths

The functional matrix uses these 25 deterministic lengths:

```text
1, 7, 15, 16, 17, 23, 31, 32, 33, 39, 47, 48, 64,
65, 71, 79, 80, 96, 112, 128, 144, 160, 192, 256, 271
```

They cover partial blocks, exact block boundaries, vector-width boundaries,
and multi-block tails. Larger inputs belong to the performance suite below.

### Performance Testing
Each implementation includes comprehensive performance benchmarks:

#### Regular Performance Tests
- **Small to Medium Data**: 1KB, 4KB, 16KB, 64KB
- **Multiple Iterations**: 100 iterations for accurate timing
- **Detailed Metrics**: Separate encryption/decryption timing and throughput calculation

#### 100 MiB Large Data Benchmark
- **Sustained Throughput**: Tests a 100 MiB buffer
- **Optimized Iterations**: Reduced to 1 iteration for practical testing time
- **Comprehensive Coverage**: All AES modes (ECB, CBC, CTR, GCM) and key sizes (128-bit, 256-bit)
- **Verification**: Includes correctness verification to ensure data integrity
- **Performance Metrics**: 
  - Individual encryption and decryption timing
  - Combined throughput in MiB/s (includes both operations)
  - Pass/Fail status for each test

The 100 MiB benchmark measures sustained performance. Results still depend on
the CPU, compiler, frequency behavior, and selected AES mode.

## Usage

### Build Tests
```bash
cd tests
make all
```

### Run All Functional Tests
```bash
make run-all
```

### Run All Performance Tests
```bash
make run-perf-all
```

### Run with Address/Undefined-Behavior Sanitizers
```bash
make sanitize
```

The sanitizer target builds the Generic implementation and a baseline
Generic-only `WAes.hpp` binary. Hardware-specific implementations keep their
own explicit compiler flags in the normal build.



### Run Specific Implementation Tests
```bash
make run-generic      # Generic implementation functional test
make run-generic-multitu # Generic C++11 multi-TU link test
make run-aes-ni       # AES-NI implementation functional test (x86-64 only)
make run-vaes         # VAES implementation functional test (x86-64, if supported)
make run-vaes512      # VAES512 implementation functional test (x86-64, if supported)
make run-armv8        # ARMv8 implementation functional test (ARM64, if supported)
```

### Run Specific Implementation Performance Tests
```bash
make run-perf-generic # Generic implementation performance test
make run-perf-aes-ni  # AES-NI implementation performance test (x86-64 only)
make run-perf-vaes    # VAES implementation performance test (x86-64, if supported)
make run-perf-vaes512 # VAES512 implementation performance test (x86-64, if supported)
make run-perf-armv8   # ARMv8 implementation performance test (ARM64, if supported)
```

### Generate Timestamped Reports (functionality + performance saved to `out/reports/`)
```bash
make report-all       # Generate reports for all implementations
make report-generic   # Generic report → out/reports/Generic_<timestamp>.txt
make report-aes-ni    # AES-NI report → out/reports/AES-NI_<timestamp>.txt
make report-vaes      # VAES report → out/reports/VAES_<timestamp>.txt
make report-vaes512   # VAES512 report → out/reports/VAES512_<timestamp>.txt
make report-armv8     # ARMv8 report → out/reports/ARMv8_<timestamp>.txt
```

### Run Individual Test Programs
```bash
./out/bin/test_generic        # Functional test
./out/bin/test_generic_multitu # C++11 multi-TU link test
./out/bin/test_generic perf   # Performance test (includes 100 MiB benchmark)
./out/bin/test_aes_ni         # Functional test (x86-64 only)
./out/bin/test_aes_ni perf    # Performance test (includes 100 MiB benchmark, x86-64 only)
./out/bin/test_vaes            # Functional test (x86-64 only)
./out/bin/test_vaes perf       # Performance test (includes 100 MiB benchmark, x86-64 only)
./out/bin/test_vaes512         # Functional test (x86-64 only)
./out/bin/test_vaes512 perf    # Performance test (includes 100 MiB benchmark, x86-64 only)
./out/bin/test_armv8           # Functional test (ARM64 only)
./out/bin/test_armv8 perf      # Performance test (includes 100 MiB benchmark, ARM64 only)
./out/bin/test_waes            # Unified functional and cross-backend tests
./out/bin/test_waes perf       # Unified performance test (includes 100 MiB benchmark)
```

### Quick Test
```bash
make quick-test       # Run every functional suite with concise output
```

### Check Platform
```bash
make check-platform
```

### Clean
```bash
make clean            # Remove entire out/ directory (binaries + reports)
```

### Help
```bash
make help
```

## Implementation Comparison Tool

The comparison tool automatically compares results from different AES implementations to ensure they produce identical outputs across all supported platforms and implementations.

### Supported Platforms and Implementations

#### x86-64 Platform
- **Generic**: Pure C++ implementation (all platforms supported)
- **WAes**: Unified adaptive header (always built; selects among compiled backends)
- **AES-NI**: Intel AES-NI hardware-accelerated implementation
- **VAES**: Intel VAES (AVX2) hardware-accelerated implementation
- **VAES512**: Intel VAES (AVX512) hardware-accelerated implementation

#### ARM64 Platform
- **Generic**: Pure C++ implementation (all platforms supported)
- **WAes**: Unified adaptive header (always built; selects among compiled backends)
- **ARMv8**: ARM Crypto Extensions hardware-accelerated implementation

The tool automatically detects the current platform and only compares available implementations.

### Comparison Tool Usage

#### Build the comparison tool
```bash
make compare
```

#### Auto-detect and compare all available implementations
```bash
make cross-compare
# or directly run:
./out/bin/compare-implementations
```

#### Specify implementations to compare
```bash
# x86-64 platform example
make cmp-specific IMPLS='Generic AES-NI VAES VAES512'
# or directly run:
./out/bin/compare-implementations Generic AES-NI VAES VAES512

# ARM64 platform example
make cmp-specific IMPLS='Generic ARMv8'
# or directly run:
./out/bin/compare-implementations Generic ARMv8
```

#### Command Line Options

**Basic Usage**:
```bash
./out/bin/compare-implementations [OPTIONS] [IMPLEMENTATIONS...]
```

**Available Options**:
- **No arguments**: Auto-detect all available implementations and compare them
- **`--keep-files, -k`**: Keep test result files for debugging and analysis
- **`--clean-only, -c`**: Only clean old test result files then exit
- **`--verbose, -v`**: Show detailed output information
- **`--help, -h`**: Show help information

#### Usage Examples

**Standard comparison (auto-clean)**:
```bash
./out/bin/compare-implementations
# Auto-detect implementations, run tests, compare results, then clean temporary files
```

**Keep test files for debugging**:
```bash
./out/bin/compare-implementations --keep-files
```

**Verbose output**:
```bash
./out/bin/compare-implementations --verbose
```

#### Comparison Features

The comparison tool provides:
- **Automatic platform detection**: Detects x86-64 vs ARM64 platforms
- **Hardware feature detection**: Checks CPU instruction set support
- **Implementation auto-discovery**: Finds available implementations
- **Detailed result comparison**: Compares cipher outputs and roundtrip integrity
- **Report generation**: Creates detailed comparison reports

#### File Management

When run via `make cross-compare`, the comparison tool writes to `out/reports/`:
- **`out/reports/test_results_<impl>.txt`**: Detailed test results for each implementation
- **`out/reports/implementation_comparison_report.txt`**: Comparison results report

By default, the tool automatically cleans these temporary files after completing the comparison. Use `--keep-files` to retain them for debugging.

#### Makefile Integration for Comparison

```bash
# Check platform and available implementations
make check-platform

# Build comparison tool
make compare

# Run complete cross-implementation comparison
make cross-compare

# Run comparison for specific implementations
make cmp-specific IMPLS='Generic AES-NI'

# Clean all build output and reports
make clean
```

## Test Verification

### Functional Verification
- **Encryption/Decryption Consistency** - Verify that decryption after encryption recovers original data
- **Padding Verification** - Verify correctness of PKCS7 padding and error detection
- **Mode Correctness** - Verify correct implementation of ECB/CBC/CTR/GCM modes
- **Edge Cases** - Test handling of various data lengths

### Performance Testing
- **Throughput Testing** - Measure encryption/decryption speed of each implementation
- **Performance Benchmarks** - Provide performance references for different data sizes
- **Implementation Comparison** - Compare performance results across different implementations manually

## Expected Results

### Generic Implementation
- Best compatibility, supports all platforms
- Relatively slower performance
- Serves as reference implementation for correctness verification

### AES-NI Implementation
- Requires CPU with AES-NI instruction set support; PCLMULQDQ accelerates GCM
- Significantly better performance than generic implementation
- Single-block processing, suitable for small to medium data

### VAES Implementation
- Requires CPU/compiler support for SSSE3, AES, AVX2, and VAES
- Uses its two-block path where the selected mode permits parallel work; 32
  bytes is an implementation threshold, not a guaranteed performance crossover
- 256-bit parallel processing, handles 2 AES blocks simultaneously
- Uses VAES instructions for vectorized AES operations

### VAES512 Implementation
- Requires SSSE3, AES, AVX2, VAES, and AVX512F/BW/DQ/VL support
- Uses its four-block path where the selected mode permits parallel work; 64
  bytes is an implementation threshold, not a guaranteed performance crossover
- 512-bit parallel processing, handles 4 AES blocks simultaneously
- Availability must be determined from CPU feature bits, not processor age

### ARMv8 Implementation
- Requires ARM64 CPU with Crypto Extensions support
- Hardware-accelerated AES operations on ARM platforms
- Uses PMULL for GCM authentication when the crypto extension is enabled
- Optimized performance compared to generic implementation
- Widely available on modern ARM64 processors (ARMv8-A with Crypto Extensions)

## Troubleshooting

### Hardware-Accelerated Tests Skipped
If you see support not detected messages, it means:

**VAES/VAES512 (x86-64)**:
- CPU doesn't support required instruction sets (AVX2/AVX-512, AES-NI, VAES)
- Compiler hasn't enabled corresponding support
- For VAES512: Very limited hardware support, most CPUs don't support AVX-512 + VAES

**ARMv8 (ARM64)**:
- CPU doesn't support ARMv8 Crypto Extensions
- Compiler hasn't enabled ARM Crypto Extensions support
- Running on non-ARM64 platform

### Compilation Errors
Ensure:
- Using a C++20-compatible compiler for this test suite and `WAes.hpp`;
  standalone headers themselves require only C++11
- Compiler supports target instruction sets
- Correctly set `-march=native` flag

### Test Failures
If tests fail:
1. Verify test data integrity
2. Confirm CPU instruction set support
3. Check compilation optimization settings
4. Compare output results from different implementations

### Implementation Consistency Verification

`test_waes` compares all available unified-header backends directly in one
process. `compare-implementations` separately runs each standalone executable
and compares their deterministic result files, which also verifies that the
independent headers remain equivalent.

### Comparison Tool Troubleshooting

**Implementation files not found**:
```
Error: Need at least 2 implementations to compare.
Available implementations: None
```
Ensure at least two header files exist:
- x86-64: `WAes-gen.hpp`, `WAes-ni.hpp`, `WAes-vaes.hpp`, `WAes-vaes512.hpp`
- ARM64: `WAes-gen.hpp`, `WAes-armv8.hpp`

**Platform doesn't support certain implementation**:
```
Skipping AES-NI test - not available on arm64 platform
```
This is normal; the tool automatically skips unsupported implementations based on platform.

**Debugging tips**:
```bash
# Keep files for inspection
./out/bin/compare-implementations --keep-files --verbose

# Check specific implementation results
cat out/reports/test_results_Generic.txt
```

## Extending Tests

To add new tests:
1. Add new test function templates in `test_template.hpp`
2. Update helper functions in `test_utils.hpp` (if needed)
3. Add new build targets in `Makefile` (if needed)
4. Update this README documentation

## Implementation Details

### VAES Implementation Details
The current VAES implementation (`WAes-vaes.hpp`) uses 256-bit VAES instructions:
- Based on SSSE3, AES, AVX2, and VAES instruction sets
- Processes 2 AES blocks at once (32 bytes)
- Uses VAES parallel processing for eligible paths with at least 32 bytes
- Uses 128-bit AES instructions for remaining blocks and serial paths
- Requires explicit VAES feature detection; AVX2-only processors such as
  Haswell are not sufficient

### 512-bit VAES Implementation
The project also includes a 512-bit VAES implementation (`WAes-vaes512.hpp`):
- Based on AVX-512 instruction set + VAES instruction set
- Processes 4 AES blocks at once (64 bytes)
- Can improve eligible large-buffer paths, but wider vectors do not guarantee
  better performance on every CPU or mode
- Requires every feature listed above and must be guarded by feature detection
