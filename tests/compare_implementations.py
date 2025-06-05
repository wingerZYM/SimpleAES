#!/usr/bin/env python3
"""
Cross-Implementation Comparison Tool for AES Library
Compares test results from different AES implementations to verify consistency.
"""

import re
import os
import sys
import subprocess
import argparse
import secrets
from collections import defaultdict
from typing import List, Tuple


class TestRecord:

    def __init__(self,
                 impl_name: str,
                 test_name: str,
                 mode: str,
                 key_size: int,
                 padding: str,
                 input_size: int,
                 cipher_size: int,
                 decrypted_size: int,
                 input_hash: str,
                 cipher_hash: str,
                 decrypted_hash: str,
                 input_start: str,
                 cipher_start: str,
                 decrypted_start: str,
                 input_end: str = "",
                 cipher_end: str = "",
                 decrypted_end: str = ""):
        self.impl_name = impl_name
        self.test_name = test_name
        self.mode = mode
        self.key_size = key_size
        self.padding = padding
        self.input_size = input_size
        self.cipher_size = cipher_size
        self.decrypted_size = decrypted_size
        self.input_hash = input_hash
        self.cipher_hash = cipher_hash
        self.decrypted_hash = decrypted_hash
        self.input_start = input_start
        self.cipher_start = cipher_start
        self.decrypted_start = decrypted_start
        self.input_end = input_end
        self.cipher_end = cipher_end
        self.decrypted_end = decrypted_end

    def get_test_id(self) -> str:
        """Generate a unique test identifier for comparison"""
        return "{}_{}_{}_{}".format(self.mode, self.key_size, self.padding,
                                    self.input_size)

    def __str__(self):
        return "{}: {}".format(self.impl_name, self.test_name)


def parse_test_file(filename: str) -> List[TestRecord]:
    """Parse a test results file and extract all test records"""
    records = []

    if not os.path.exists(filename):
        print("Warning: File {} not found".format(filename))
        return records

    with open(filename, 'r') as file:
        content = file.read()

    # Split by test sections
    test_sections = re.split(r'=== Test: (.+?) ===',
                             content)[1:]  # Skip empty first element

    for i in range(0, len(test_sections), 2):
        if i + 1 >= len(test_sections):
            break

        test_name = test_sections[i].strip()
        test_content = test_sections[i + 1]

        # Extract test metadata
        impl_match = re.search(r'Implementation: (.+)', test_content)
        mode_match = re.search(r'Mode: (.+)', test_content)
        key_size_match = re.search(r'Key Size: (\d+)', test_content)
        padding_match = re.search(r'Padding: (.+)', test_content)
        input_size_match = re.search(r'Input Size: (\d+)', test_content)
        cipher_size_match = re.search(r'Cipher Size: (\d+)', test_content)
        decrypted_size_match = re.search(r'Decrypted Size: (\d+)',
                                         test_content)

        # Extract hash values
        input_hash_match = re.search(r'Input Hash: ([0-9a-fA-F]+)',
                                     test_content)
        cipher_hash_match = re.search(r'Cipher Hash: ([0-9a-fA-F]+)',
                                      test_content)
        decrypted_hash_match = re.search(r'Decrypted Hash: ([0-9a-fA-F]+)',
                                         test_content)

        # Extract data (start and end)
        input_start_match = re.search(r'Input Start: ([0-9a-fA-F]+)',
                                      test_content)
        cipher_start_match = re.search(r'Cipher Start: ([0-9a-fA-F]+)',
                                       test_content)
        decrypted_start_match = re.search(r'Decrypted Start: ([0-9a-fA-F]+)',
                                          test_content)

        input_end_match = re.search(r'Input End: ([0-9a-fA-F]+)', test_content)
        cipher_end_match = re.search(r'Cipher End: ([0-9a-fA-F]+)',
                                     test_content)
        decrypted_end_match = re.search(r'Decrypted End: ([0-9a-fA-F]+)',
                                        test_content)

        # Check required fields
        if all([
                impl_match, mode_match, key_size_match, padding_match,
                input_size_match, cipher_size_match, decrypted_size_match,
                input_hash_match, cipher_hash_match, decrypted_hash_match,
                input_start_match, cipher_start_match, decrypted_start_match
        ]):

            record = TestRecord(
                impl_match.group(1).strip(), test_name,
                mode_match.group(1).strip(), int(key_size_match.group(1)),
                padding_match.group(1).strip(), int(input_size_match.group(1)),
                int(cipher_size_match.group(1)),
                int(decrypted_size_match.group(1)), input_hash_match.group(1),
                cipher_hash_match.group(1), decrypted_hash_match.group(1),
                input_start_match.group(1), cipher_start_match.group(1),
                decrypted_start_match.group(1),
                input_end_match.group(1) if input_end_match else "",
                cipher_end_match.group(1) if cipher_end_match else "",
                decrypted_end_match.group(1) if decrypted_end_match else "")
            records.append(record)

    return records


def compare_implementations(
        implementations: List[str]) -> Tuple[int, int, List[str]]:
    """Compare test results across different implementations"""

    # Parse all test files
    all_records = {}
    for impl in implementations:
        filename = f"test_results_{impl}.txt"
        records = parse_test_file(filename)
        all_records[impl] = {
            record.get_test_id(): record
            for record in records
        }
        print(f"Loaded {len(records)} test records from {impl}")

    if not all_records:
        print("No test results found!")
        return 0, 0, []

    # Group tests by test ID
    test_groups = defaultdict(dict)
    for impl, records in all_records.items():
        for test_id, record in records.items():
            test_groups[test_id][impl] = record

    # Compare each test group
    passed_tests = 0
    failed_tests = 0
    failure_details = []

    print(f"\n{'='*60}")
    print("Cross-Implementation Comparison Results")
    print(f"{'='*60}")

    for test_id in sorted(test_groups.keys()):
        test_records = test_groups[test_id]

        # Skip if not all implementations have this test
        if len(test_records) < len(implementations):
            missing_impls = set(implementations) - set(test_records.keys())
            print(f"[SKIP] {test_id} - Missing in: {', '.join(missing_impls)}")
            continue

        # Compare cipher outputs using hash values (more reliable than partial data)
        cipher_hashes = [
            record.cipher_hash for record in test_records.values()
        ]
        input_hashes = [record.input_hash for record in test_records.values()]

        # Check if all ciphertext hashes are identical
        cipher_match = all(cipher_hash == cipher_hashes[0]
                           for cipher_hash in cipher_hashes)

        # Check if all decrypted hashes match input hashes (roundtrip integrity)
        decrypt_integrity = all(record.decrypted_hash == record.input_hash
                                for record in test_records.values())

        # Check if all input hashes are the same (they should be)
        input_match = all(input_hash == input_hashes[0]
                          for input_hash in input_hashes)

        if cipher_match and decrypt_integrity and input_match:
            print("[PASS] {}".format(test_id))
            passed_tests += 1
        else:
            print("[FAIL] {}".format(test_id))
            failed_tests += 1

            failure_detail = "Test {} failed:".format(test_id)
            if not input_match:
                failure_detail += "\n  - Input data mismatch between implementations"
                for impl, record in test_records.items():
                    failure_detail += "\n    {}: input_hash={}".format(
                        impl, record.input_hash)
            if not cipher_match:
                failure_detail += "\n  - Ciphertext mismatch between implementations"
                for impl, record in test_records.items():
                    failure_detail += "\n    {}: cipher_hash={}".format(
                        impl, record.cipher_hash)
            if not decrypt_integrity:
                failure_detail += "\n  - Decryption roundtrip integrity failed"
                for impl, record in test_records.items():
                    if record.decrypted_hash != record.input_hash:
                        failure_detail += "\n    {}: input={}, decrypted={}".format(
                            impl, record.input_hash, record.decrypted_hash)

            failure_details.append(failure_detail)

    return passed_tests, failed_tests, failure_details


def generate_summary_report(implementations: List[str], passed: int,
                            failed: int, failures: List[str]):
    """Generate a comprehensive summary report"""

    print(f"\n{'='*60}")
    print("SUMMARY REPORT")
    print(f"{'='*60}")
    print(f"Implementations tested: {', '.join(implementations)}")
    print(f"Total tests: {passed + failed}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success rate: {(passed / (passed + failed) * 100):.1f}%" if (
        passed + failed) > 0 else "N/A")

    if failed > 0:
        print(f"\n{'='*40}")
        print("FAILURE DETAILS")
        print(f"{'='*40}")
        for failure in failures:
            print(failure)
            print("-" * 40)

    # Generate comparison file
    with open("implementation_comparison_report.txt", "w") as f:
        f.write("AES Implementation Comparison Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Implementations tested: {', '.join(implementations)}\n")
        f.write(f"Total tests: {passed + failed}\n")
        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {failed}\n")
        f.write(f"Success rate: {(passed / (passed + failed) * 100):.1f}%\n\n"
                if (passed + failed) > 0 else "Success rate: N/A\n\n")

        if failed > 0:
            f.write("FAILURE DETAILS:\n")
            f.write("-" * 20 + "\n")
            for failure in failures:
                f.write(failure + "\n\n")

    print("\nDetailed report saved to: implementation_comparison_report.txt")


def run_implementation_test(impl_name: str,
                            custom_params: List[str] = None) -> bool:
    """Run tests for a specific implementation and return success status"""

    # Map implementation names to make commands
    cmd_map = {
        "Generic": "run-generic",
        "AES-NI": "run-aes-ni",
        "VAES": "run-vaes",
        "VAES512": "run-vaes512",
        "ARMv8": "run-armv8"
    }

    if impl_name not in cmd_map:
        print("Unknown implementation: {}".format(impl_name))
        return False

    # Set environment variable to enable file output
    env = os.environ.copy()
    env['ENABLE_FILE_OUTPUT'] = '1'

    # Build make command - we need to run the executable directly to pass custom params
    if custom_params:
        # Run the test executable directly with custom parameters
        executable_map = {
            "Generic": "./test_generic",
            "AES-NI": "./test_aes_ni",
            "VAES": "./test_vaes",
            "VAES512": "./test_vaes512",
            "ARMv8": "./test_armv8"
        }

        if impl_name not in executable_map:
            print(
                "Unknown executable for implementation: {}".format(impl_name))
            return False

        # First build the executable
        build_target_map = {
            "Generic": "test_generic",
            "AES-NI": "test_aes_ni",
            "VAES": "test_vaes",
            "VAES512": "test_vaes512",
            "ARMv8": "test_armv8"
        }

        make_cmd = ["make", build_target_map[impl_name]]
        try:
            result = subprocess.run(make_cmd,
                                    env=env,
                                    capture_output=True,
                                    text=True,
                                    check=False)
            if result.returncode != 0:
                print("  ✗ Failed to build {} tests".format(impl_name))
                return False
        except Exception as e:
            print("  ✗ Error building {} tests: {}".format(impl_name, e))
            return False

        # Then run with custom parameters
        test_cmd = [executable_map[impl_name], "--enable-file-output"
                    ] + custom_params
    else:
        # Use make command for default parameters
        test_cmd = ["make", cmd_map[impl_name]]

    try:
        print("Running tests for {}{}...".format(
            impl_name, " (with custom params)" if custom_params else ""))
        result = subprocess.run(test_cmd,
                                env=env,
                                capture_output=True,
                                text=True,
                                check=False)

        if result.returncode == 0:
            print("  ✓ {} tests completed successfully".format(impl_name))
            return True
        else:
            print("  ✗ {} tests failed".format(impl_name))
            print("  Error output:",
                  result.stderr.strip()[:200])  # Show first 200 chars of error
            return False

    except FileNotFoundError:
        print("  ✗ Command not found")
        return False
    except Exception as e:
        print("  ✗ Error running {} tests: {}".format(impl_name, e))
        return False


def check_cpu_feature_support(feature_macros: List[str]) -> bool:
    """Check if CPU supports specific feature macros using compiler"""
    try:
        # Use g++ to check feature macros
        cmd = ["g++", "-march=native", "-dM", "-E", "-"]
        process = subprocess.run(cmd,
                                 input="",
                                 text=True,
                                 capture_output=True,
                                 timeout=10)

        if process.returncode != 0:
            return False

        defines = process.stdout

        # Check if all required macros are present
        for macro in feature_macros:
            if f"#define {macro}" not in defines:
                return False

        return True
    except (subprocess.TimeoutExpired, subprocess.SubprocessError,
            FileNotFoundError):
        return False


def check_implementation_availability() -> List[str]:
    """Check which AES implementations are available based on platform and hardware support"""
    available = []

    # Detect platform
    try:
        import platform
        machine = platform.machine().lower()
    except ImportError:
        machine = "unknown"

    # Determine platform type
    is_x86_64 = machine in ['x86_64', 'amd64']
    is_arm64 = machine in ['aarch64', 'arm64']

    # Generic implementation is always available
    if os.path.exists("../WAes-gen.hpp"):
        available.append("Generic")

        # x86-64 specific implementations
    if is_x86_64:
        # AES-NI: requires AES instruction support
        if (os.path.exists("../WAes-ni.hpp")
                and check_cpu_feature_support(["__AES__"])):
            available.append("AES-NI")

        # VAES: requires AVX2 + VAES instruction support
        if (os.path.exists("../WAes-vaes.hpp")
                and check_cpu_feature_support(["__AVX2__", "__VAES__"])):
            available.append("VAES")

        # VAES512: requires AVX512F + VAES instruction support
        if (os.path.exists("../WAes-vaes512.hpp")
                and check_cpu_feature_support(["__AVX512F__", "__VAES__"])):
            available.append("VAES512")

    # ARM64 specific implementations
    if is_arm64:
        # ARMv8: requires ARM Crypto Extensions
        if (os.path.exists("../WAes-armv8.hpp")
                and check_cpu_feature_support(["__ARM_FEATURE_CRYPTO"])):
            available.append("ARMv8")

    return available


def cleanup_test_files(implementations: List[str],
                       keep_files: bool = False) -> None:
    """Clean up test result files"""
    if keep_files:
        print("Keeping test result files for inspection.")
        return

    files_to_clean = []

    # Collect test result files
    for impl in implementations:
        filename = "test_results_{}.txt".format(impl)
        if os.path.exists(filename):
            files_to_clean.append(filename)

    # Add report file
    if os.path.exists("implementation_comparison_report.txt"):
        files_to_clean.append("implementation_comparison_report.txt")

    if files_to_clean:
        print("Cleaning up test files: {}".format(", ".join(files_to_clean)))
        for filename in files_to_clean:
            try:
                os.remove(filename)
            except OSError as e:
                print("Warning: Could not remove {}: {}".format(filename, e))
    else:
        print("No test files to clean up.")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AES Implementation Comparison Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python compare_implementations.py                    # Auto-detect and compare all implementations
  python compare_implementations.py Generic AES-NI     # Compare specific implementations
  python compare_implementations.py Generic VAES512    # Compare Generic and VAES512 (on AVX512 systems)
  python compare_implementations.py Generic ARMv8      # Compare Generic and ARMv8 (on ARM64 platforms)
  python compare_implementations.py --keep-files       # Keep test result files after comparison
  python compare_implementations.py --clean-only       # Just clean up old test files
  python compare_implementations.py --random-params    # Use random test parameters
        """)

    parser.add_argument(
        'implementations',
        nargs='*',
        help=
        'AES implementations to compare (Generic, AES-NI, VAES, VAES512, ARMv8). If not specified, auto-detect.'
    )

    parser.add_argument(
        '--keep-files',
        '-k',
        action='store_true',
        help='Keep test result files after comparison (useful for debugging)')

    parser.add_argument('--clean-only',
                        '-c',
                        action='store_true',
                        help='Only clean up old test result files and exit')

    parser.add_argument('--verbose',
                        '-v',
                        action='store_true',
                        help='Enable verbose output')

    parser.add_argument(
        '--random-params',
        '-r',
        action='store_true',
        help='Use randomly generated test parameters instead of defaults')

    return parser.parse_args()


def generate_random_test_params() -> dict:
    """Generate random test parameters for AES testing"""

    def generate_random_hex(byte_length: int) -> str:
        """Generate random hex string of specified byte length"""
        return secrets.token_hex(byte_length)

    params = {
        'key128': generate_random_hex(16),  # 16 bytes = 128 bits
        'key192': generate_random_hex(24),  # 24 bytes = 192 bits
        'key256': generate_random_hex(32),  # 32 bytes = 256 bits
        'iv': generate_random_hex(16),  # 16 bytes for IV
        'counter': generate_random_hex(16)  # 16 bytes for counter
    }

    return params


def format_test_params_for_command(params: dict) -> List[str]:
    """Format test parameters for command line"""
    return [
        '--custom-params', params['key128'], params['key192'],
        params['key256'], params['iv'], params['counter']
    ]


def main():
    # Parse command line arguments
    args = parse_arguments()

    print("AES Implementation Comparison Tool")
    print("=" * 50)

    # Handle clean-only mode
    if args.clean_only:
        print("Cleaning up mode - removing old test result files...")
        # Get all possible implementations for cleanup
        all_possible = ["Generic", "AES-NI", "VAES", "VAES512", "ARMv8"]
        cleanup_test_files(all_possible, keep_files=False)
        print("Cleanup completed.")
        sys.exit(0)

    # Determine implementations to test
    if args.implementations:
        implementations = args.implementations
        print("Using specified implementations: {}".format(
            ", ".join(implementations)))
    else:
        # Auto-detect available implementations
        if args.verbose:
            print(
                "Detecting available implementations with hardware support check..."
            )
        available_impls = check_implementation_availability()
        if len(available_impls) >= 2:
            implementations = available_impls
            print("Auto-detected implementations: {}".format(
                ", ".join(implementations)))
        else:
            print("Error: Need at least 2 implementations to compare.")
            print("Available implementations: {}".format(
                ", ".join(available_impls) if available_impls else "None"))
            print(
                "Make sure you have at least 2 implementation header files and CPU support."
            )
            print(
                "Note: Hardware feature detection is used to filter available implementations."
            )
            sys.exit(1)

    print("Comparing implementations: {}".format(", ".join(implementations)))

    # Generate random parameters if requested
    custom_params = None
    if args.random_params:
        random_params = generate_random_test_params()
        custom_params = format_test_params_for_command(random_params)
        print("\nUsing random test parameters:")
        print("  AES-128 Key: {}".format(random_params['key128']))
        print("  AES-192 Key: {}".format(random_params['key192']))
        print("  AES-256 Key: {}".format(random_params['key256']))
        print("  IV:          {}".format(random_params['iv']))
        print("  Counter:     {}".format(random_params['counter']))
    else:
        print("\nUsing default test parameters")

    # Clean up old result files first (but will be cleaned again at the end unless --keep-files)
    for impl in implementations:
        filename = "test_results_{}.txt".format(impl)
        if os.path.exists(filename):
            os.remove(filename)
            if args.verbose:
                print("Cleaned up old results: {}".format(filename))

    print("\nRunning tests for each implementation...")
    print("=" * 40)

    # Run tests for each implementation
    successful_runs = []
    for impl in implementations:
        if run_implementation_test(impl, custom_params):
            successful_runs.append(impl)

    print("\nTest execution summary:")
    print("  Total implementations: {}".format(len(implementations)))
    print("  Successful runs: {}".format(len(successful_runs)))

    if len(successful_runs) < 2:
        print("\nError: Need at least 2 successful test runs to compare")
        print("Please check the individual test failures above")
        # Cleanup before exit
        cleanup_test_files(implementations, keep_files=args.keep_files)
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Comparing Implementation Results")
    print("=" * 60)

    # Compare results
    passed, failed, failures = compare_implementations(successful_runs)
    generate_summary_report(successful_runs, passed, failed, failures)

    # Show file information
    if args.keep_files:
        print("\nTest result files preserved:")
        for impl in successful_runs:
            filename = "test_results_{}.txt".format(impl)
            if os.path.exists(filename):
                print("  - {}".format(filename))
        if os.path.exists("implementation_comparison_report.txt"):
            print("  - implementation_comparison_report.txt")
        print(
            "\nUse 'make clean-results' or run with --clean-only to remove these files later."
        )

    # Cleanup files unless explicitly keeping them
    cleanup_test_files(successful_runs, keep_files=args.keep_files)

    # Exit with appropriate code
    if failed == 0:
        print("\n🎉 All tests PASSED! All implementations are equivalent.")
        sys.exit(0)
    else:
        print("❌ {} tests FAILED! Implementations differ.".format(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
