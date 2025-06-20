# AES Library Test Suite

> **[中文版 / Chinese Version](README_CN.md)**

This test suite is designed to verify multiple AES implementations across different platforms: generic code (all platforms), AES-NI instruction set (x86-64), VAES instruction set (x86-64), VAES512 instruction set (x86-64), and ARMv8 Crypto Extensions (ARM64).

**Important Design Philosophy**: These AES implementations are switched by replacing header files, not by using them simultaneously in the same program. Each test program contains only one implementation to ensure interface consistency.

## File Structure

### Core Files
- `test_data.hpp` - Common test data and constants
- `test_utils.hpp` - Test utility functions and helper classes
- `test_template.hpp` - Generic test template containing all test logic

### Test Files
- `test_generic.cpp` - Generic AES implementation test (WAes-gen.hpp)
- `test_aes_ni.cpp` - AES-NI instruction set implementation test (WAes-ni.hpp) [x86-64 only]
- `test_vaes.cpp` - VAES instruction set implementation test (WAes-vaes.hpp) [x86-64 only]
- `test_vaes512.cpp` - VAES512 instruction set implementation test (WAes-vaes512.hpp) [x86-64 only]
- `test_armv8.cpp` - ARMv8 Crypto Extensions implementation test (WAes-armv8.hpp) [ARM64 only]

### Build and Run Files
- `Makefile` - Build system with automatic VAES support detection

### Comparison Tool
- `compare_implementations.cpp` - Cross-implementation comparison tool

## Test Coverage

Each implementation tests:

### AES Modes
- **ECB Mode** - Electronic Codebook mode
- **CBC Mode** - Cipher Block Chaining mode
- **CTR Mode** - Counter mode

### Key Lengths
- **AES-128** - 128-bit key
- **AES-192** - 192-bit key
- **AES-256** - 256-bit key

### Padding Schemes
- **PKCS7 Padding** - Standard PKCS#7 padding
- **Zero Padding** - Zero byte padding
- **No Padding** - CTR mode doesn't require padding

### Data Lengths
Test various data lengths to verify all scenarios:
- Partial blocks (1-15 bytes)
- Complete blocks (16 bytes)
- Multiple blocks (32, 48, 64, 80, 96, 112, 128 bytes)
- Large datasets (256+ bytes for VAES 256-bit parallel processing, 512+ bytes for VAES512 512-bit parallel processing)

### Performance Testing
Each implementation includes comprehensive performance benchmarks:

#### Regular Performance Tests
- **Small to Medium Data**: 1KB, 4KB, 16KB, 64KB
- **Multiple Iterations**: 100 iterations for accurate timing
- **Detailed Metrics**: Separate encryption/decryption timing and throughput calculation

#### 100MB Large Data Benchmark
- **Realistic Throughput**: Tests with 100MB data size for real-world performance measurement
- **Optimized Iterations**: Reduced to 1 iterations for practical testing time
- **Comprehensive Coverage**: All AES modes (ECB, CBC, CTR) and key sizes (128-bit, 256-bit)
- **Verification**: Includes correctness verification to ensure data integrity
- **Performance Metrics**: 
  - Individual encryption and decryption timing
  - Combined throughput in MB/s (includes both operations)
  - Pass/Fail status for each test

The 100MB benchmark provides more accurate performance measurements for sustained operations and helps identify the real-world performance characteristics of each implementation.

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



### Run Specific Implementation Tests
```bash
make run-generic      # Generic implementation functional test
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

### Run Individual Test Programs
```bash
./test_generic        # Functional test
./test_generic perf   # Performance test (includes 100MB benchmark)
./test_aes_ni         # Functional test (x86-64 only)
./test_aes_ni perf    # Performance test (includes 100MB benchmark, x86-64 only)
./test_vaes           # Functional test (x86-64 only)
./test_vaes perf      # Performance test (includes 100MB benchmark, x86-64 only)
./test_vaes512        # Functional test (x86-64 only)
./test_vaes512 perf   # Performance test (includes 100MB benchmark, x86-64 only)
./test_armv8          # Functional test (ARM64 only)
./test_armv8 perf     # Performance test (includes 100MB benchmark, ARM64 only)
```

### Quick Test
```bash
make quick-test       # Run simplified tests
```

### Check VAES Support
```bash
make check-vaes
```

### Clean
```bash
make clean
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
- **AES-NI**: Intel AES-NI hardware-accelerated implementation
- **VAES**: Intel VAES (AVX2) hardware-accelerated implementation
- **VAES512**: Intel VAES (AVX512) hardware-accelerated implementation

#### ARM64 Platform
- **Generic**: Pure C++ implementation (all platforms supported)
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
./compare-implementations
```

#### Specify implementations to compare
```bash
# x86-64 platform example
make cmp-specific IMPLS='Generic AES-NI VAES VAES512'
# or directly run:
./compare-implementations Generic AES-NI VAES VAES512

# ARM64 platform example
make cmp-specific IMPLS='Generic ARMv8'
# or directly run:
./compare-implementations Generic ARMv8
```

#### Command Line Options

**Basic Usage**:
```bash
./compare-implementations [OPTIONS] [IMPLEMENTATIONS...]
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
./compare-implementations
# Auto-detect implementations, run tests, compare results, then clean temporary files
```

**Keep test files for debugging**:
```bash
./compare-implementations --keep-files
```

**Verbose output**:
```bash
./compare-implementations --verbose
```

#### Comparison Features

The comparison tool provides:
- **Automatic platform detection**: Detects x86-64 vs ARM64 platforms
- **Hardware feature detection**: Checks CPU instruction set support
- **Implementation auto-discovery**: Finds available implementations
- **Detailed result comparison**: Compares cipher outputs and roundtrip integrity
- **Report generation**: Creates detailed comparison reports

#### File Management

The comparison tool generates:
- **`test_results_<implementation_name>.txt`**: Detailed test results for each implementation
- **`implementation_comparison_report.txt`**: Comparison results report

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

# Clean test result files
make clean-results
```

## Test Verification

### Functional Verification
- **Encryption/Decryption Consistency** - Verify that decryption after encryption recovers original data
- **Padding Verification** - Verify correctness of PKCS7 padding and error detection
- **Mode Correctness** - Verify correct implementation of ECB/CBC/CTR modes
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
- Requires CPU with AES-NI instruction set support
- Significantly better performance than generic implementation
- Single-block processing, suitable for small to medium data

### VAES Implementation
- Requires CPU with AVX2 and AES-NI instruction set support
- Better performance than AES-NI for large datasets (≥32 bytes)
- 256-bit parallel processing, handles 2 AES blocks simultaneously
- Uses VAES instructions for vectorized AES operations

### VAES512 Implementation
- Requires CPU with AVX-512 and VAES instruction set support
- Highest theoretical performance for very large datasets (≥64 bytes)
- 512-bit parallel processing, handles 4 AES blocks simultaneously
- Extremely limited hardware support, only available on newest CPUs

### ARMv8 Implementation
- Requires ARM64 CPU with Crypto Extensions support
- Hardware-accelerated AES operations on ARM platforms
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
- Using a C++17 compatible compiler
- Compiler supports target instruction sets
- Correctly set `-march=native` flag

### Test Failures
If tests fail:
1. Verify test data integrity
2. Confirm CPU instruction set support
3. Check compilation optimization settings
4. Compare output results from different implementations

### Implementation Consistency Verification
Due to the design philosophy of switching implementations via header file replacement, direct comparison within the same program is not possible. Use the comparison tool for automated verification across implementations.

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
./compare-implementations --keep-files --verbose

# Check specific implementation results
cat test_results_Generic.txt
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
- Based on AVX2 instruction set + AES-NI instruction set
- Processes 2 AES blocks at once (32 bytes)
- Uses VAES parallel processing for data ≥32 bytes
- Falls back to AES-NI processing for data <32 bytes
- Broad hardware compatibility (CPUs after Haswell 2013)

### 512-bit VAES Implementation
The project also includes a 512-bit VAES implementation (`WAes-vaes512.hpp`):
- Based on AVX-512 instruction set + VAES instruction set
- Processes 4 AES blocks at once (64 bytes)
- Theoretically higher performance but extremely limited hardware support
- Cannot run on most machines due to AVX-512 support issues 