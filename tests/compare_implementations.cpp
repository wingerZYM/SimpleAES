/**
 * Cross-Implementation Comparison Tool for AES Library (C++ Version)
 * Compares test results from different AES implementations to verify consistency.
 * 
 * This is a C++ port of the Python comparison tool to avoid Python dependencies.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <regex>
#include <algorithm>
#include <memory>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <random>
#include <chrono>

#ifdef _WIN32
    #include <Windows.h>
    #include <process.h>
#else
    #include <unistd.h>
    #include <sys/wait.h>
    #include <sys/utsname.h>
#endif

struct TestRecord {
    std::string impl_name;
    std::string test_name;
    std::string mode;
    int key_size;
    std::string padding;
    int input_size;
    int cipher_size;
    int decrypted_size;
    std::string input_hash;
    std::string cipher_hash;
    std::string decrypted_hash;
    std::string input_start;
    std::string cipher_start;
    std::string decrypted_start;
    std::string input_end;
    std::string cipher_end;
    std::string decrypted_end;

    std::string get_test_id() const {
        return mode + "_" + std::to_string(key_size) + "_" + padding + "_" + std::to_string(input_size);
    }
};

class ComparisonTool {
private:
    bool verbose = false;
    bool keep_files = false;
    std::vector<std::string> implementations;

    // Return path with TEST_OUTPUT_DIR prefix if set
    static std::string filePath(const std::string& filename) {
        const char* dir = std::getenv("TEST_OUTPUT_DIR");
        if (dir && dir[0] != '\0') {
            return std::string(dir) + "/" + filename;
        }
        return filename;
    }

public:
    ComparisonTool(bool verbose = false, bool keep_files = false)
        : verbose(verbose), keep_files(keep_files) {}

    std::vector<TestRecord> parse_test_file(const std::string& filename) {
        std::vector<TestRecord> records;
        std::ifstream file(filename);
        
        if (!file.is_open()) {
            if (verbose) {
                std::cout << "Warning: File " << filename << " not found\n";
            }
            return records;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        file.close();

        // Split by test sections using regex
        std::regex test_section_regex(R"(=== Test: (.+?) ===)");
        std::sregex_token_iterator iter(content.begin(), content.end(), test_section_regex, -1);
        std::sregex_token_iterator end;
        
        std::vector<std::string> sections;
        for (; iter != end; ++iter) {
            std::string section = *iter;
            if (!section.empty()) {
                sections.push_back(section);
            }
        }

        // Extract test names and content pairs
        std::sregex_iterator names_iter(content.begin(), content.end(), test_section_regex);
        std::sregex_iterator names_end;
        
        std::vector<std::string> test_names;
        for (; names_iter != names_end; ++names_iter) {
            test_names.push_back((*names_iter)[1].str());
        }

        // Process each test section
        for (size_t i = 0; i < test_names.size() && i < sections.size() - 1; ++i) {
            const std::string& test_name = test_names[i];
            const std::string& test_content = sections[i + 1];

            TestRecord record = parse_test_section(test_name, test_content);
            if (!record.impl_name.empty()) {
                records.push_back(record);
            }
        }

        return records;
    }

    TestRecord parse_test_section(const std::string& test_name, const std::string& content) {
        TestRecord record;
        record.test_name = test_name;

        // Define regex patterns for extracting data
        std::regex patterns[] = {
            std::regex(R"(Implementation:\s*(.+))"),
            std::regex(R"(Mode:\s*(.+))"),
            std::regex(R"(Key Size:\s*(\d+))"),
            std::regex(R"(Padding:\s*(.+))"),
            std::regex(R"(Input Size:\s*(\d+))"),
            std::regex(R"(Cipher Size:\s*(\d+))"),
            std::regex(R"(Decrypted Size:\s*(\d+))"),
            std::regex(R"(Input Hash:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Cipher Hash:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Decrypted Hash:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Input Start:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Cipher Start:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Decrypted Start:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Input End:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Cipher End:\s*([0-9a-fA-F]+))"),
            std::regex(R"(Decrypted End:\s*([0-9a-fA-F]+))")
        };

        std::smatch match;
        
        // Extract implementation name
        if (std::regex_search(content, match, patterns[0])) {
            record.impl_name = trim(match[1].str());
        }
        
        // Extract mode
        if (std::regex_search(content, match, patterns[1])) {
            record.mode = trim(match[1].str());
        }
        
        // Extract key size
        if (std::regex_search(content, match, patterns[2])) {
            record.key_size = std::stoi(match[1].str());
        }
        
        // Extract padding
        if (std::regex_search(content, match, patterns[3])) {
            record.padding = trim(match[1].str());
        }
        
        // Extract sizes
        if (std::regex_search(content, match, patterns[4])) {
            record.input_size = std::stoi(match[1].str());
        }
        if (std::regex_search(content, match, patterns[5])) {
            record.cipher_size = std::stoi(match[1].str());
        }
        if (std::regex_search(content, match, patterns[6])) {
            record.decrypted_size = std::stoi(match[1].str());
        }
        
        // Extract hashes
        if (std::regex_search(content, match, patterns[7])) {
            record.input_hash = match[1].str();
        }
        if (std::regex_search(content, match, patterns[8])) {
            record.cipher_hash = match[1].str();
        }
        if (std::regex_search(content, match, patterns[9])) {
            record.decrypted_hash = match[1].str();
        }
        
        // Extract data starts
        if (std::regex_search(content, match, patterns[10])) {
            record.input_start = match[1].str();
        }
        if (std::regex_search(content, match, patterns[11])) {
            record.cipher_start = match[1].str();
        }
        if (std::regex_search(content, match, patterns[12])) {
            record.decrypted_start = match[1].str();
        }
        
        // Extract data ends (optional)
        if (std::regex_search(content, match, patterns[13])) {
            record.input_end = match[1].str();
        }
        if (std::regex_search(content, match, patterns[14])) {
            record.cipher_end = match[1].str();
        }
        if (std::regex_search(content, match, patterns[15])) {
            record.decrypted_end = match[1].str();
        }

        // Validate required fields
        if (record.impl_name.empty() || record.mode.empty() || 
            record.input_hash.empty() || record.cipher_hash.empty() || 
            record.decrypted_hash.empty()) {
            return TestRecord{}; // Return empty record if validation fails
        }

        return record;
    }

    std::tuple<int, int, std::vector<std::string>> compare_implementations(
        const std::vector<std::string>& impls) {
        
        // Parse all test files
        std::map<std::string, std::map<std::string, TestRecord>> all_records;
        
        for (const auto& impl : impls) {
            std::string filename = filePath("test_results_" + impl + ".txt");
            auto records = parse_test_file(filename);
            
            for (const auto& record : records) {
                all_records[impl][record.get_test_id()] = record;
            }
            
            std::cout << "Loaded " << records.size() << " test records from " << impl << "\n";
        }

        if (all_records.empty()) {
            std::cout << "No test results found!\n";
            return std::make_tuple(0, 0, std::vector<std::string>());
        }

        // Group tests by test ID
        std::map<std::string, std::map<std::string, TestRecord>> test_groups;
        for (const auto& impl_records : all_records) {
            const std::string& impl = impl_records.first;
            for (const auto& record_pair : impl_records.second) {
                const std::string& test_id = record_pair.first;
                const TestRecord& record = record_pair.second;
                test_groups[test_id][impl] = record;
            }
        }

        // Compare each test group
        int passed_tests = 0;
        int failed_tests = 0;
        std::vector<std::string> failure_details;

        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "Cross-Implementation Comparison Results\n";
        std::cout << std::string(60, '=') << "\n";

        for (const auto& test_group : test_groups) {
            const std::string& test_id = test_group.first;
            const auto& test_records = test_group.second;

            // Skip if not all implementations have this test
            if (test_records.size() < impls.size()) {
                std::set<std::string> missing_impls;
                for (const auto& impl : impls) {
                    if (test_records.find(impl) == test_records.end()) {
                        missing_impls.insert(impl);
                    }
                }
                
                std::cout << "[SKIP] " << test_id << " - Missing in: ";
                bool first = true;
                for (const auto& missing : missing_impls) {
                    if (!first) std::cout << ", ";
                    std::cout << missing;
                    first = false;
                }
                std::cout << "\n";
                continue;
            }

            // Compare cipher outputs using hash values
            std::vector<std::string> cipher_hashes;
            std::vector<std::string> input_hashes;
            
            for (const auto& record_pair : test_records) {
                cipher_hashes.push_back(record_pair.second.cipher_hash);
                input_hashes.push_back(record_pair.second.input_hash);
            }

            // Check if all ciphertext hashes are identical
            bool cipher_match = std::all_of(cipher_hashes.begin(), cipher_hashes.end(),
                [&cipher_hashes](const std::string& hash) {
                    return hash == cipher_hashes[0];
                });

            // Check if all decrypted hashes match input hashes (roundtrip integrity)
            bool decrypt_integrity = true;
            for (const auto& record_pair : test_records) {
                if (record_pair.second.decrypted_hash != record_pair.second.input_hash) {
                    decrypt_integrity = false;
                    break;
                }
            }

            if (cipher_match && decrypt_integrity) {
                std::cout << "[PASS] " << test_id << "\n";
                passed_tests++;
            } else {
                std::cout << "[FAIL] " << test_id;
                std::string failure_detail = "Test: " + test_id + "\n";
                
                if (!cipher_match) {
                    std::cout << " - Cipher mismatch";
                    failure_detail += "  Issue: Cipher output differs between implementations\n";
                    for (const auto& record_pair : test_records) {
                        failure_detail += "    " + record_pair.first + ": " + 
                                        record_pair.second.cipher_hash + "\n";
                    }
                }
                
                if (!decrypt_integrity) {
                    std::cout << " - Decrypt integrity failure";
                    failure_detail += "  Issue: Decrypted data doesn't match original input\n";
                    for (const auto& record_pair : test_records) {
                        const auto& record = record_pair.second;
                        if (record.decrypted_hash != record.input_hash) {
                            failure_detail += "    " + record_pair.first + 
                                            " - Input: " + record.input_hash + 
                                            ", Decrypted: " + record.decrypted_hash + "\n";
                        }
                    }
                }
                
                std::cout << "\n";
                failure_details.push_back(failure_detail);
                failed_tests++;
            }
        }

        return std::make_tuple(passed_tests, failed_tests, failure_details);
    }

    void generate_summary_report(const std::vector<std::string>& impls, 
                                int passed, int failed, 
                                const std::vector<std::string>& failures) {
        
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "SUMMARY REPORT\n";
        std::cout << std::string(60, '=') << "\n";
        
        std::cout << "Implementations tested: ";
        for (size_t i = 0; i < impls.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << impls[i];
        }
        std::cout << "\n";
        
        std::cout << "Total tests: " << (passed + failed) << "\n";
        std::cout << "Passed: " << passed << "\n";
        std::cout << "Failed: " << failed << "\n";
        
        if (passed + failed > 0) {
            std::cout << "Success rate: " << std::fixed << std::setprecision(1) 
                      << (static_cast<double>(passed) / (passed + failed) * 100) << "%\n";
        }

        if (failed > 0) {
            std::cout << "\n" << std::string(40, '=') << "\n";
            std::cout << "FAILURE DETAILS\n";
            std::cout << std::string(40, '=') << "\n";
            for (const auto& failure : failures) {
                std::cout << failure << "\n";
                std::cout << std::string(40, '-') << "\n";
            }
        }

        // Generate report file
        std::ofstream report(filePath("implementation_comparison_report.txt"));
        if (report.is_open()) {
            report << "AES Implementation Comparison Report\n";
            report << std::string(50, '=') << "\n\n";
            
            report << "Implementations tested: ";
            for (size_t i = 0; i < impls.size(); ++i) {
                if (i > 0) report << ", ";
                report << impls[i];
            }
            report << "\n";
            
            report << "Total tests: " << (passed + failed) << "\n";
            report << "Passed: " << passed << "\n";
            report << "Failed: " << failed << "\n";
            
            if (passed + failed > 0) {
                report << "Success rate: " << std::fixed << std::setprecision(1) 
                       << (static_cast<double>(passed) / (passed + failed) * 100) << "%\n\n";
            }

            if (failed > 0) {
                report << "FAILURE DETAILS:\n";
                report << std::string(20, '-') << "\n";
                for (const auto& failure : failures) {
                    report << failure << "\n\n";
                }
            }
            
            report.close();
            std::cout << "\nDetailed report saved to: implementation_comparison_report.txt\n";
        }
    }

    bool run_implementation_test(const std::string& impl_name) {
        // Map implementation names to make commands
        std::map<std::string, std::string> cmd_map = {
            {"Generic", "run-generic"},
            {"AES-NI", "run-aes-ni"},
            {"VAES", "run-vaes"},
            {"VAES512", "run-vaes512"},
            {"ARMv8", "run-armv8"},
            {"WAes", "run-waes"}
        };

        if (cmd_map.find(impl_name) == cmd_map.end()) {
            std::cout << "Unknown implementation: " << impl_name << "\n";
            return false;
        }

        std::string command = "make " + cmd_map[impl_name];
        
        // Set environment variable to enable file output
#ifdef _WIN32
        _putenv("ENABLE_FILE_OUTPUT=1");
#else
        setenv("ENABLE_FILE_OUTPUT", "1", 1);
#endif

        std::cout << "Running tests for " << impl_name << "...\n";
        
        int result = std::system(command.c_str());
        
        if (result == 0) {
            std::cout << "  ✓ " << impl_name << " tests completed successfully\n";
            return true;
        } else {
            std::cout << "  ✗ " << impl_name << " tests failed\n";
            return false;
        }
    }

    bool check_cpu_feature_support(const std::vector<std::string>& feature_macros) {
        std::string command = "echo '' | g++ -march=native -dM -E -";
        
#ifdef _WIN32
        FILE* pipe = _popen(command.c_str(), "r");
#else
        FILE* pipe = popen(command.c_str(), "r");
#endif
        
        if (!pipe) return false;

        std::string result;
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }

#ifdef _WIN32
        _pclose(pipe);
#else
        pclose(pipe);
#endif

        // Check if all required macros are present
        for (const auto& macro : feature_macros) {
            std::string define_line = "#define " + macro;
            if (result.find(define_line) == std::string::npos) {
                return false;
            }
        }

        return true;
    }

    std::vector<std::string> check_implementation_availability() {
        std::vector<std::string> available;

        // Detect platform
        std::string machine = get_machine_type();
        bool is_x86_64 = (machine == "x86_64" || machine == "amd64");
        bool is_arm64 = (machine == "aarch64" || machine == "arm64");

        // Generic implementation is always available
        if (file_exists("../WAes-gen.hpp")) {
            available.push_back("Generic");
        }

        // Unified multi-backend implementation is always available
        if (file_exists("../WAes.hpp")) {
            available.push_back("WAes");
        }

        // x86-64 specific implementations
        if (is_x86_64) {
            // AES-NI: requires AES instruction support
            if (file_exists("../WAes-ni.hpp") && 
                check_cpu_feature_support({"__AES__"})) {
                available.push_back("AES-NI");
            }

            // VAES: requires AVX2 + VAES instruction support
            if (file_exists("../WAes-vaes.hpp") && 
                check_cpu_feature_support({"__AVX2__", "__VAES__"})) {
                available.push_back("VAES");
            }

            // VAES512: requires AVX512F + VAES instruction support
            if (file_exists("../WAes-vaes512.hpp") && 
                check_cpu_feature_support({"__AVX512F__", "__VAES__"})) {
                available.push_back("VAES512");
            }
        }

        // ARM64 specific implementations
        if (is_arm64) {
            // ARMv8: requires ARM Crypto Extensions
            if (file_exists("../WAes-armv8.hpp") && 
                check_cpu_feature_support({"__ARM_FEATURE_CRYPTO"})) {
                available.push_back("ARMv8");
            }
        }

        return available;
    }

    void cleanup_test_files(const std::vector<std::string>& impls) {
        if (keep_files) {
            std::cout << "Keeping test result files for inspection.\n";
            return;
        }

        std::vector<std::string> files_to_clean;

        // Collect test result files
        for (const auto& impl : impls) {
            std::string filename = filePath("test_results_" + impl + ".txt");
            if (file_exists(filename)) {
                files_to_clean.push_back(filename);
            }
        }

        // Add report file
        if (file_exists(filePath("implementation_comparison_report.txt"))) {
            files_to_clean.push_back(filePath("implementation_comparison_report.txt"));
        }

        if (!files_to_clean.empty()) {
            std::cout << "Cleaning up test files: ";
            for (size_t i = 0; i < files_to_clean.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << files_to_clean[i];
                std::remove(files_to_clean[i].c_str());
            }
            std::cout << "\n";
        } else {
            std::cout << "No test files to clean up.\n";
        }
    }

    int run_comparison(const std::vector<std::string>& target_impls) {
        std::cout << "AES Implementation Comparison Tool (C++ Version)\n";
        std::cout << std::string(50, '=') << "\n";

        // Determine implementations to test
        if (!target_impls.empty()) {
            implementations = target_impls;
            std::cout << "Using specified implementations: ";
            for (size_t i = 0; i < implementations.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << implementations[i];
            }
            std::cout << "\n";
        } else {
            // Auto-detect available implementations
            if (verbose) {
                std::cout << "Detecting available implementations with hardware support check...\n";
            }
            auto available_impls = check_implementation_availability();
            if (available_impls.size() >= 2) {
                implementations = available_impls;
                std::cout << "Auto-detected implementations: ";
                for (size_t i = 0; i < implementations.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << implementations[i];
                }
                std::cout << "\n";
            } else {
                std::cout << "Error: Need at least 2 implementations to compare.\n";
                std::cout << "Available implementations: ";
                for (size_t i = 0; i < available_impls.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << available_impls[i];
                }
                std::cout << (available_impls.empty() ? "None" : "") << "\n";
                return 1;
            }
        }

        std::cout << "Comparing implementations: ";
        for (size_t i = 0; i < implementations.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << implementations[i];
        }
        std::cout << "\n";

        // Clean up old result files first
        for (const auto& impl : implementations) {
            std::string filename = filePath("test_results_" + impl + ".txt");
            std::remove(filename.c_str());
        }

        std::cout << "\nRunning tests for each implementation...\n";
        std::cout << std::string(40, '=') << "\n";

        // Run tests for each implementation
        std::vector<std::string> successful_runs;
        for (const auto& impl : implementations) {
            if (run_implementation_test(impl)) {
                successful_runs.push_back(impl);
            }
        }

        std::cout << "\nTest execution summary:\n";
        std::cout << "  Total implementations: " << implementations.size() << "\n";
        std::cout << "  Successful runs: " << successful_runs.size() << "\n";

        if (successful_runs.size() < 2) {
            std::cout << "\nError: Need at least 2 successful test runs to compare\n";
            std::cout << "Please check the individual test failures above\n";
            cleanup_test_files(implementations);
            return 1;
        }

        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "Comparing Implementation Results\n";
        std::cout << std::string(60, '=') << "\n";

        // Compare results
        auto [passed, failed, failures] = compare_implementations(successful_runs);
        generate_summary_report(successful_runs, passed, failed, failures);

        // Show file information
        if (keep_files) {
            std::cout << "\nTest result files preserved:\n";
            for (const auto& impl : successful_runs) {
                std::string filename = filePath("test_results_" + impl + ".txt");
                if (file_exists(filename)) {
                    std::cout << "  - " << filename << "\n";
                }
            }
            if (file_exists(filePath("implementation_comparison_report.txt"))) {
                std::cout << "  - " << filePath("implementation_comparison_report.txt") << "\n";
            }
            std::cout << "\nUse 'make clean-results' or run with --clean-only to remove these files later.\n";
        }

        // Cleanup files unless explicitly keeping them
        cleanup_test_files(successful_runs);

        // Exit with appropriate code
        if (failed == 0) {
            std::cout << "\n🎉 All tests PASSED! All implementations are equivalent.\n";
            return 0;
        } else {
            std::cout << "❌ " << failed << " tests FAILED! Implementations differ.\n";
            return 1;
        }
    }

private:
    std::string trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }

    bool file_exists(const std::string& filename) {
        std::ifstream file(filename);
        return file.good();
    }

    std::string get_machine_type() {
#ifdef _WIN32
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        switch (si.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                return "x86_64";
            case PROCESSOR_ARCHITECTURE_ARM64:
                return "arm64";
            case PROCESSOR_ARCHITECTURE_INTEL:
                return "x86";
            default:
                return "unknown";
        }
#else
        struct utsname info;
        if (uname(&info) == 0) {
            return std::string(info.machine);
        }
        return "unknown";
#endif
    }
};

void print_help() {
    std::cout << R"(AES Implementation Comparison Tool (C++ Version)

Usage: compare_implementations [OPTIONS] [IMPLEMENTATIONS...]

Arguments:
  IMPLEMENTATIONS    AES implementations to compare (Generic, AES-NI, VAES, VAES512, ARMv8, WAes)
                    If not specified, auto-detect available implementations

Options:
  -h, --help        Show this help message
  -v, --verbose     Enable verbose output  
  -k, --keep-files  Keep test result files after comparison
  -c, --clean-only  Only clean up old test result files and exit

Examples:
  compare_implementations                    # Auto-detect and compare all implementations
  compare_implementations Generic AES-NI     # Compare specific implementations
  compare_implementations Generic VAES512    # Compare Generic and VAES512 (on AVX512 systems)
  compare_implementations Generic ARMv8      # Compare Generic and ARMv8 (on ARM64 platforms)
  compare_implementations --keep-files       # Keep test result files after comparison
  compare_implementations --clean-only       # Just clean up old test files
)";
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    bool keep_files = false;
    bool clean_only = false;
    std::vector<std::string> implementations;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-k" || arg == "--keep-files") {
            keep_files = true;
        } else if (arg == "-c" || arg == "--clean-only") {
            clean_only = true;
        } else if (arg[0] != '-') {
            implementations.push_back(arg);
        } else {
            std::cout << "Unknown option: " << arg << "\n";
            std::cout << "Use --help for usage information.\n";
            return 1;
        }
    }

    ComparisonTool tool(verbose, keep_files);

    // Handle clean-only mode
    if (clean_only) {
        std::cout << "Cleaning up mode - removing old test result files...\n";
        std::vector<std::string> all_possible = {"Generic", "AES-NI", "VAES", "VAES512", "ARMv8", "WAes"};
        tool.cleanup_test_files(all_possible);
        std::cout << "Cleanup completed.\n";
        return 0;
    }

    return tool.run_comparison(implementations);
}