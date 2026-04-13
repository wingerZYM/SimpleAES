#pragma once

#include "test_data.hpp"
#include "test_utils.hpp"
#include <fstream>
#include <iomanip>
#include <functional>
#include <string_view>
#include <cstdlib>
#include <vector>

using namespace TestData;
using namespace TestUtils;

// Global flag to control whether to write test results to files
// Can be set via environment variable ENABLE_FILE_OUTPUT or command line argument
bool g_enableFileOutput = false;

// Global variables for custom test parameters (will use defaults if not set)
std::vector<uint8_t> g_customKey128;
std::vector<uint8_t> g_customKey192; 
std::vector<uint8_t> g_customKey256;
std::vector<uint8_t> g_customIV;
std::vector<uint8_t> g_customCounter;
bool g_useCustomParams = false;

// This template contains all the test logic that can be reused across different implementations
// The actual AES header should be included before including this template

// Helper function to check if file output is enabled
bool shouldWriteToFile() {
    // Check environment variable first
    const char* envVar = std::getenv("ENABLE_FILE_OUTPUT");
    if (envVar && std::string(envVar) == "1") {
        return true;
    }
    
    return g_enableFileOutput;
}

// Helper function to set custom test parameters
void setCustomParameters(const std::string& key128_hex, const std::string& key192_hex, 
                        const std::string& key256_hex, const std::string& iv_hex, 
                        const std::string& counter_hex) {
    auto hexToBytes = [](const std::string& hex) -> std::vector<uint8_t> {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            if (i + 1 < hex.length()) {
                std::string byteString = hex.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
                bytes.push_back(byte);
            }
        }
        return bytes;
    };
    
    if (!key128_hex.empty() && key128_hex.length() == 32) { // 16 bytes = 32 hex chars
        g_customKey128 = hexToBytes(key128_hex);
    }
    if (!key192_hex.empty() && key192_hex.length() == 48) { // 24 bytes = 48 hex chars
        g_customKey192 = hexToBytes(key192_hex);
    }
    if (!key256_hex.empty() && key256_hex.length() == 64) { // 32 bytes = 64 hex chars
        g_customKey256 = hexToBytes(key256_hex);
    }
    if (!iv_hex.empty() && iv_hex.length() == 32) { // 16 bytes = 32 hex chars
        g_customIV = hexToBytes(iv_hex);
    }
    if (!counter_hex.empty() && counter_hex.length() == 32) { // 16 bytes = 32 hex chars
        g_customCounter = hexToBytes(counter_hex);
    }
    
    g_useCustomParams = true;
}

// Helper function to get the key for specified key size
const uint8_t* getCurrentKey(int keySize, size_t& keyLen) {
    switch (keySize) {
        case 128:
            if (g_useCustomParams && !g_customKey128.empty()) {
                keyLen = g_customKey128.size();
                return g_customKey128.data();
            } else {
                keyLen = AES128_KEY_SIZE;
                return AES128_KEY;
            }
        case 192:
            if (g_useCustomParams && !g_customKey192.empty()) {
                keyLen = g_customKey192.size();
                return g_customKey192.data();
            } else {
                keyLen = AES192_KEY_SIZE;
                return AES192_KEY;
            }
        case 256:
            if (g_useCustomParams && !g_customKey256.empty()) {
                keyLen = g_customKey256.size();
                return g_customKey256.data();
            } else {
                keyLen = AES256_KEY_SIZE;
                return AES256_KEY;
            }
        default:
            keyLen = AES128_KEY_SIZE;
            return AES128_KEY;
    }
}

// Helper function to get current IV
const uint8_t* getCurrentIV() {
    return (g_useCustomParams && !g_customIV.empty()) ? g_customIV.data() : TEST_IV;
}

// Helper function to get current Counter
const uint8_t* getCurrentCounter() {
    return (g_useCustomParams && !g_customCounter.empty()) ? g_customCounter.data() : TEST_COUNTER;
}

// Helper function to process command line arguments
void processCommandLineArgs(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "--enable-file-output" || arg == "-f") {
            g_enableFileOutput = true;
        } else if (arg == "--custom-params" && i + 5 < argc) {
            // Expected format: --custom-params <key128> <key192> <key256> <iv> <counter>
            std::string key128 = argv[++i];
            std::string key192 = argv[++i];
            std::string key256 = argv[++i];
            std::string iv = argv[++i];
            std::string counter = argv[++i];
            setCustomParameters(key128, key192, key256, iv, counter);
            std::cout << "Using custom test parameters" << std::endl;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --enable-file-output, -f         Enable writing test results to files" << std::endl;
            std::cout << "  --custom-params <k128> <k192> <k256> <iv> <ctr>" << std::endl;
            std::cout << "                                   Use custom test parameters (hex strings)" << std::endl;
            std::cout << "                                   k128: 32 hex chars, k192: 48 hex chars," << std::endl;
            std::cout << "                                   k256: 64 hex chars, iv/ctr: 32 hex chars each" << std::endl;
            std::cout << "  --help, -h                       Show this help message" << std::endl;
            std::cout << "  perf                             Run performance tests only" << std::endl;
            std::exit(0);
        }
    }
}

// Helper function to calculate hash of data for comparison using std::hash
std::size_t calculateDataHash(const std::vector<uint8_t>& data) {
    // Use std::string_view for efficient hashing without data copying
    std::string_view view(reinterpret_cast<const char*>(data.data()), data.size());
    return std::hash<std::string_view>{}(view);
}

// Helper function to write test results to file for cross-implementation comparison
void writeTestResultToFile(const std::string& implName, const std::string& testName,
                          const std::vector<uint8_t>& input, const std::vector<uint8_t>& ciphertext,
                          const std::vector<uint8_t>& decrypted, const std::string& mode,
                          int keySize, const std::string& padding) {
    std::string dir;
    const char* envDir = std::getenv("TEST_OUTPUT_DIR");
    if (envDir && envDir[0] != '\0') {
        dir = std::string(envDir) + "/";
    }
    std::string filename = dir + "test_results_" + implName + ".txt";
    std::ofstream file(filename, std::ios::app);
    
    if (!file.is_open()) return;
    
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
    file << "Cipher Hash: " << std::hex << calculateDataHash(ciphertext) << std::endl;
    file << "Decrypted Hash: " << std::hex << calculateDataHash(decrypted) << std::endl;
    
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
            file << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
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
            file << std::hex << std::setw(2) << std::setfill('0') << (int)decrypted[i];
        }
        file << std::endl;
    }
    
    file << std::dec << std::endl;
    file.close();
}

template<int KeySize>
TestResult testAESImplementation(const uint8_t* key, size_t keyLen, size_t dataSize, 
                                const std::string& mode, Padding padding, const std::string& implName) {
    (void)key; (void)keyLen; // Suppress unused parameter warnings - we'll get key from getCurrentKey
    (void)implName; // Suppress unused parameter warning
    auto testData = getTestData(dataSize);
    
    // Get current parameters (custom or default)
    size_t currentKeyLen;
    const uint8_t* currentKey = getCurrentKey(KeySize, currentKeyLen);
    const uint8_t* currentIV = getCurrentIV();
    const uint8_t* currentCounter = getCurrentCounter();
    
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
    size_t maxCipherLen = (mode == "CTR") ? dataSize : aes.SumCipherLength(dataSize);
    std::vector<uint8_t> ciphertext(maxCipherLen);
    std::vector<uint8_t> decrypted(dataSize);
    
    Timer timer;
    
    // Encrypt
    timer.start();
    size_t cipherLen = aes.Cipher(testData.data(), dataSize, ciphertext.data(), ciphertext.size());
    double encryptTime = timer.elapsed();
    
    if (cipherLen == 0) {
        return TestResult(false, "Encryption failed");
    }
    
    ciphertext.resize(cipherLen);
    
    // Decrypt
    timer.start();
    size_t decryptedLen = aes.InvCipher(ciphertext.data(), cipherLen, decrypted.data(), decrypted.size());
    double decryptTime = timer.elapsed();
    
    if (decryptedLen == 0) {
        return TestResult(false, "Decryption failed");
    }
    
    if (decryptedLen != dataSize) {
        return TestResult(false, "Decrypted length mismatch: expected " + 
                         std::to_string(dataSize) + ", got " + std::to_string(decryptedLen));
    }
    
    decrypted.resize(decryptedLen);
    
    // Verify data integrity
    if (!compareData(testData, decrypted)) {
        return TestResult(false, "Data integrity check failed");
    }
    
    // Write test results to file for cross-implementation comparison
    if (shouldWriteToFile()) {
        std::string testName = mode + "_" + std::to_string(KeySize) + "_" + 
                              (padding == Padding::PKCS7 ? "PKCS7" : "Zeros") + "_" + 
                              std::to_string(dataSize);
        writeTestResultToFile(implName, testName, testData, ciphertext, decrypted, 
                             mode, KeySize, (padding == Padding::PKCS7 ? "PKCS7" : "Zeros"));
    }
    
    return TestResult(true, "Success", encryptTime, decryptTime, dataSize);
}

template<int KeySize>
TestResult testPaddingValidation(const uint8_t* key, size_t keyLen, 
                                const std::string& mode, Padding padding, const std::string& implName) {
    (void)key; (void)keyLen; // Suppress unused parameter warnings - we'll get key from getCurrentKey
    (void)implName; // Suppress unused parameter warning
    // Skip padding validation for CTR mode (no padding used)
    if (mode == "CTR") {
        return TestResult(true, "CTR mode doesn't use padding");
    }
    
    auto testData = getTestData(32); // Use 32 bytes for this test
    
    // Get current parameters (custom or default)
    size_t currentKeyLen;
    const uint8_t* currentKey = getCurrentKey(KeySize, currentKeyLen);
    const uint8_t* currentIV = getCurrentIV();
    
    CWAes<KeySize> aes(currentKey, currentKeyLen, nullptr, 0, padding);
    
    // Set mode
    if (mode == "CBC") {
        aes.SetIV(currentIV, IV_SIZE);
    }
    
    // Encrypt
    size_t maxCipherLen = aes.SumCipherLength(testData.size());
    std::vector<uint8_t> ciphertext(maxCipherLen);
    size_t cipherLen = aes.Cipher(testData.data(), testData.size(), ciphertext.data(), ciphertext.size());
    
    if (cipherLen == 0) {
        return TestResult(false, "Encryption failed");
    }
    
    ciphertext.resize(cipherLen);
    
    // Test with corrupted padding (only for PKCS7)
    if (padding == Padding::PKCS7) {
        auto corruptedCiphertext = corruptPadding(ciphertext);
        std::vector<uint8_t> decrypted(testData.size());
        
        size_t decryptedLen = aes.InvCipher(corruptedCiphertext.data(), corruptedCiphertext.size(), 
                                          decrypted.data(), decrypted.size());
        
        if (decryptedLen != 0) {
            return TestResult(false, "Should have failed with corrupted padding");
        }
    }
    
    return TestResult(true, "Padding validation works correctly");
}

template<int KeySize>
TestResult benchmarkImplementation(const uint8_t* key, size_t keyLen, size_t dataSize, 
                                  const std::string& mode, Padding padding, const std::string& implName,
                                  int iterations = 100) {
    (void)implName; // Suppress unused parameter warning
    auto testData = getTestData(dataSize);
    
    CWAes<KeySize> aes(key, keyLen, nullptr, 0, padding);
    
    // Set mode
    if (mode == "CBC") {
        aes.SetIV(TEST_IV, IV_SIZE);
    } else if (mode == "CTR") {
        aes.SetCounter(TEST_COUNTER, COUNTER_SIZE);
    }
    
    // Prepare buffers
    size_t maxCipherLen = (mode == "CTR") ? dataSize : aes.SumCipherLength(dataSize);
    std::vector<uint8_t> ciphertext(maxCipherLen);
    std::vector<uint8_t> decrypted(dataSize);
    
    Timer timer;
    
    // Warm up
    for (int i = 0; i < 10; i++) {
        aes.Cipher(testData.data(), dataSize, ciphertext.data(), ciphertext.size());
        aes.InvCipher(ciphertext.data(), maxCipherLen, decrypted.data(), decrypted.size());
    }
    
    // Benchmark encryption
    timer.start();
    for (int i = 0; i < iterations; i++) {
        aes.Cipher(testData.data(), dataSize, ciphertext.data(), ciphertext.size());
    }
    double encryptTime = timer.elapsed() / iterations;
    
    // Benchmark decryption
    timer.start();
    for (int i = 0; i < iterations; i++) {
        aes.InvCipher(ciphertext.data(), maxCipherLen, decrypted.data(), decrypted.size());
    }
    double decryptTime = timer.elapsed() / iterations;
    
    // Calculate throughput
    double totalTime = (encryptTime + decryptTime) / 1000.0; // Convert to seconds
    double throughputMBps = (dataSize * 2.0) / (1024.0 * 1024.0) / totalTime; // MB/s
    
    return TestResult(true, "Throughput: " + std::to_string(throughputMBps) + " MB/s", 
                     encryptTime, decryptTime, dataSize);
}

void runImplementationTests(const std::string& implementationName) {
    TestSummary summary;
    
    std::cout << "\n=== " << implementationName << " AES Implementation Tests ===" << std::endl;
    
    // Test configurations
    struct KeyConfig {
        int keySize;
        const uint8_t* key;
        size_t keyLen;
        std::string name;
    };
    
    KeyConfig keys[] = {
        {128, AES128_KEY, AES128_KEY_SIZE, "AES128"},
        {192, AES192_KEY, AES192_KEY_SIZE, "AES192"},
        {256, AES256_KEY, AES256_KEY_SIZE, "AES256"}
    };
    
    std::string modes[] = {"ECB", "CBC", "CTR"};
    Padding paddings[] = {Padding::PKCS7, Padding::Zeros};
    std::string paddingNames[] = {"PKCS7", "Zeros"};
    
    for (const auto& keyConfig : keys) {
        for (const auto& mode : modes) {
            for (int p = 0; p < 2; p++) {
                // Skip padding for CTR mode
                if (mode == "CTR" && p > 0) continue;
                
                for (size_t dataSize : TEST_SIZES) {
                    TestResult result;
                    std::string testName = implementationName + "-" + mode + "-" + keyConfig.name + "-" + 
                                         (mode == "CTR" ? "NoPad" : paddingNames[p]) + 
                                         " (" + std::to_string(dataSize) + " bytes)";
                    
                    switch (keyConfig.keySize) {
                        case 128:
                            result = testAESImplementation<128>(keyConfig.key, keyConfig.keyLen, dataSize, mode, paddings[p], implementationName);
                            break;
                        case 192:
                            result = testAESImplementation<192>(keyConfig.key, keyConfig.keyLen, dataSize, mode, paddings[p], implementationName);
                            break;
                        case 256:
                            result = testAESImplementation<256>(keyConfig.key, keyConfig.keyLen, dataSize, mode, paddings[p], implementationName);
                            break;
                    }
                    
                    printTestResult(result, testName);
                    summary.addResult(result.success);
                }
                
                // Test padding validation
                TestResult paddingResult;
                std::string paddingTestName = implementationName + "-" + mode + "-" + keyConfig.name + "-" + 
                                            (mode == "CTR" ? "NoPad" : paddingNames[p]) + " Padding Validation";
                
                switch (keyConfig.keySize) {
                    case 128:
                        paddingResult = testPaddingValidation<128>(keyConfig.key, keyConfig.keyLen, mode, paddings[p], implementationName);
                        break;
                    case 192:
                        paddingResult = testPaddingValidation<192>(keyConfig.key, keyConfig.keyLen, mode, paddings[p], implementationName);
                        break;
                    case 256:
                        paddingResult = testPaddingValidation<256>(keyConfig.key, keyConfig.keyLen, mode, paddings[p], implementationName);
                        break;
                }
                
                printTestResult(paddingResult, paddingTestName);
                summary.addResult(paddingResult.success);
            }
        }
    }
    
    summary.print(implementationName + " AES Implementation");
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
template<int KeySize>
TestResult benchmarkLargeData(const uint8_t* key, size_t keyLen, size_t dataSize, 
                             const std::string& mode, Padding padding, const std::string& implName,
                             int iterations = 1) {
    (void)implName; // Suppress unused parameter warning
    
    // Generate large test data
    auto testData = generateLargeTestData(dataSize);
    
    CWAes<KeySize> aes(key, keyLen, nullptr, 0, padding);
    
    // Set mode
    if (mode == "CBC") {
        aes.SetIV(getCurrentIV(), IV_SIZE);
    } else if (mode == "CTR") {
        aes.SetCounter(getCurrentCounter(), COUNTER_SIZE);
    }
    
    // Prepare buffers
    size_t maxCipherLen = (mode == "CTR") ? dataSize : aes.SumCipherLength(dataSize);
    std::vector<uint8_t> ciphertext(maxCipherLen);
    std::vector<uint8_t> decrypted(dataSize);
    
    Timer timer;
    
    // Warm up with smaller iterations for large data
    for (int i = 0; i < 3; i++) {
        size_t cipherLen = aes.Cipher(testData.data(), dataSize, ciphertext.data(), ciphertext.size());
        aes.InvCipher(ciphertext.data(), cipherLen, decrypted.data(), decrypted.size());
    }
    
    // Benchmark encryption
    timer.start();
    size_t finalCipherLen = 0;
    for (int i = 0; i < iterations; i++) {
        finalCipherLen = aes.Cipher(testData.data(), dataSize, ciphertext.data(), ciphertext.size());
    }
    double encryptTime = timer.elapsed() / iterations;
    
    // Benchmark decryption
    timer.start();
    for (int i = 0; i < iterations; i++) {
        aes.InvCipher(ciphertext.data(), finalCipherLen, decrypted.data(), decrypted.size());
    }
    double decryptTime = timer.elapsed() / iterations;
    
    // Verify correctness
    bool correct = compareData(testData, decrypted);
    if (!correct) {
        return TestResult(false, "Decryption verification failed for large data");
    }
    
    // Calculate throughput (MB/s)
    double totalTimeSeconds = (encryptTime + decryptTime) / 1000.0;
    double dataSizeMB = (dataSize * 2.0) / (1024.0 * 1024.0); // *2 for encrypt+decrypt
    double throughputMBps = dataSizeMB / totalTimeSeconds;
    
    return TestResult(true, "Throughput: " + std::to_string(throughputMBps) + " MB/s", 
                     encryptTime, decryptTime, dataSize);
}

void runPerformanceTests(const std::string& implementationName) {
    std::cout << "\n=== " << implementationName << " Performance Benchmark ===" << std::endl;
    
    // Test configurations for performance
    struct KeyConfig {
        int keySize;
        const uint8_t* key;
        size_t keyLen;
        std::string name;
    };
    
    KeyConfig keys[] = {
        {128, AES128_KEY, AES128_KEY_SIZE, "AES128"},
        {256, AES256_KEY, AES256_KEY_SIZE, "AES256"}  // Focus on 128 and 256 for performance
    };
    
    std::string modes[] = {"ECB", "CBC", "CTR"};
    std::vector<size_t> perfSizes = {1024, 4096, 16384, 65536}; // Regular performance sizes
    
    // Print header for regular performance tests
    std::cout << "\n--- Regular Performance Tests ---" << std::endl;
    std::cout << std::left << std::setw(8) << "Mode" 
              << std::setw(8) << "KeySize" 
              << std::setw(10) << "DataSize" 
              << std::setw(12) << "Encrypt(ms)" 
              << std::setw(12) << "Decrypt(ms)" 
              << std::setw(15) << "Throughput(MB/s)" << std::endl;
    std::cout << std::string(75, '-') << std::endl;
    
    for (const auto& keyConfig : keys) {
        for (const auto& mode : modes) {
            for (size_t dataSize : perfSizes) {
                TestResult result;
                
                switch (keyConfig.keySize) {
                    case 128:
                        result = benchmarkImplementation<128>(keyConfig.key, keyConfig.keyLen, 
                                                             dataSize, mode, Padding::PKCS7, implementationName);
                        break;
                    case 256:
                        result = benchmarkImplementation<256>(keyConfig.key, keyConfig.keyLen, 
                                                             dataSize, mode, Padding::PKCS7, implementationName);
                        break;
                }
                
                std::cout << std::left << std::setw(8) << mode
                          << std::setw(8) << keyConfig.name
                          << std::setw(10) << dataSize
                          << std::setw(12) << std::fixed << std::setprecision(3) << result.encryptTime
                          << std::setw(12) << result.decryptTime
                          << std::setw(15) << result.message.substr(result.message.find(":") + 2) << std::endl;
            }
        }
    }
    
    // 100MB Performance Benchmark
    std::cout << "\n--- 100MB Large Data Performance Benchmark ---" << std::endl;
    std::cout << "Testing with 100MB data size for realistic throughput measurement..." << std::endl;
    std::cout << std::left << std::setw(8) << "Mode" 
              << std::setw(8) << "KeySize" 
              << std::setw(12) << "Encrypt(ms)" 
              << std::setw(12) << "Decrypt(ms)" 
              << std::setw(20) << "Throughput(MB/s)" 
              << std::setw(12) << "Status" << std::endl;
    std::cout << std::string(75, '-') << std::endl;
    
    const size_t LARGE_DATA_SIZE = 100 * 1024 * 1024; // 100MB
    
    for (const auto& keyConfig : keys) {
        for (const auto& mode : modes) {
            TestResult result;
            
            std::cout << std::left << std::setw(8) << mode
                      << std::setw(8) << keyConfig.name << std::flush;
            
            switch (keyConfig.keySize) {
                case 128:
                    result = benchmarkLargeData<128>(keyConfig.key, keyConfig.keyLen, 
                                                   LARGE_DATA_SIZE, mode, Padding::PKCS7, implementationName);
                    break;
                case 256:
                    result = benchmarkLargeData<256>(keyConfig.key, keyConfig.keyLen, 
                                                   LARGE_DATA_SIZE, mode, Padding::PKCS7, implementationName);
                    break;
            }
            
            if (result.success) {
                std::cout << std::setw(12) << std::fixed << std::setprecision(1) << result.encryptTime
                          << std::setw(12) << result.decryptTime
                          << std::setw(20) << result.message.substr(result.message.find(":") + 2)
                          << std::setw(12) << "PASS" << std::endl;
            } else {
                std::cout << std::setw(12) << "N/A"
                          << std::setw(12) << "N/A"
                          << std::setw(20) << "N/A"
                          << std::setw(12) << "FAIL" << std::endl;
                std::cout << "    Error: " << result.message << std::endl;
            }
        }
    }
    
    std::cout << "\nNote: 100MB benchmark practical testing time." << std::endl;
    std::cout << "Throughput includes both encryption and decryption operations." << std::endl;
} 