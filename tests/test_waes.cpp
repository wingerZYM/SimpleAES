#include "../WAes.hpp"
#include "test_data.hpp"

// Current backend used by CWAes adapter — changed between test runs
static WAes::Backend g_testBackend = WAes::Backend::Auto;

// Adapter: wrap WAes::Ptr API to match the CWAes<N> value-type interface
// expected by test_template.hpp
template <int N>
class CWAes {
    WAes::Ptr m_impl;
public:
    CWAes(const void* key, size_t keyLen, const void* iv = nullptr,
          size_t ivLen = 16, Padding padding = Padding::PKCS7)
        : m_impl(g_testBackend == WAes::Backend::Auto
                 ? WAes::Create<N>(key, keyLen, iv, ivLen, padding)
                 : WAes::Create<N>(g_testBackend, key, keyLen, iv, ivLen, padding)) {}

    size_t SumCipherLength(size_t inLen) const {
        return m_impl->SumCipherLength(inLen);
    }
    void SetIV(const void* iv, size_t len) { m_impl->SetIV(iv, len); }
    void SetCounter(const void* ctr, size_t len) { m_impl->SetCounter(ctr, len); }

    bool Cipher(const void* in, size_t inLen, void* out, size_t& outLen) const {
        return m_impl->Cipher(in, inLen, out, outLen);
    }
    bool InvCipher(const void* in, size_t inLen, void* out, size_t& outLen) const {
        return m_impl->InvCipher(in, inLen, out, outLen);
    }
};
using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;

#include "test_template.hpp"

// ── Cross-backend validation ──────────────────────────────────────────────────

// Runtime-polymorphic proxy: creates any backend+keySize combination and
// exposes a uniform interface, allowing the cross-validation loop to avoid
// compile-time template dispatch on keySize.
struct AesProxy {
    WAes::Ptr impl;

    AesProxy(WAes::Backend b, int keyBits,
             const void* key, size_t keyLen,
             const void* iv, size_t ivLen, Padding pad) {
        switch (keyBits) {
        case 128: impl = WAes::Create<128>(b, key, keyLen, iv, ivLen, pad); break;
        case 192: impl = WAes::Create<192>(b, key, keyLen, iv, ivLen, pad); break;
        default:  impl = WAes::Create<256>(b, key, keyLen, iv, ivLen, pad); break;
        }
    }

    void setIV(const void* iv, size_t len)      { impl->SetIV(iv, len); }
    void setCounter(const void* ctr, size_t len) { impl->SetCounter(ctr, len); }

    size_t sumCipherLength(size_t inLen) const { return impl->SumCipherLength(inLen); }

    std::vector<uint8_t> cipher(const std::vector<uint8_t>& plain) const {
        size_t outLen = impl->SumCipherLength(plain.size());
        std::vector<uint8_t> out(outLen);
        if (!impl->Cipher(plain.data(), plain.size(), out.data(), outLen)) return {};
        out.resize(outLen);
        return out;
    }

    std::vector<uint8_t> invCipher(const std::vector<uint8_t>& ct, size_t plainLen) const {
        std::vector<uint8_t> out(plainLen);
        size_t outLen = plainLen;
        if (!impl->InvCipher(ct.data(), ct.size(), out.data(), outLen)) return {};
        out.resize(outLen);
        return out;
    }
};

void runCrossValidation() {
    using namespace TestData;

    auto backends = WAes::AvailableBackends();
    if (backends.size() < 2) {
        std::cout << "\n[Cross-validation] Only one backend available, skipping.\n";
        return;
    }

    std::cout << "\n=== WAes Cross-Backend Validation ===\n";
    std::cout << "Backends:";
    for (auto b : backends) std::cout << " " << WAes::GetImplName(b);
    std::cout << "\n\n";

    struct KeyCfg {
        int bits;
        const uint8_t* key;
        size_t keyLen;
    };
    const KeyCfg keys[] = {
        {128, AES128_KEY, AES128_KEY_SIZE},
        {192, AES192_KEY, AES192_KEY_SIZE},
        {256, AES256_KEY, AES256_KEY_SIZE},
    };

    struct ModeCfg {
        const char* name;
        bool useIV;
        bool useCtr;
        bool skipZeros;  // CTR has no padding
    };
    const ModeCfg modes[] = {
        {"ECB", false, false, false},
        {"CBC", true,  false, false},
        {"CTR", false, true,  true },
    };

    int passed = 0, failed = 0;
    WAes::Backend ref = backends[0];  // reference backend

    for (const auto& kc : keys) {
        for (const auto& mc : modes) {
            int paddingCount = mc.skipZeros ? 1 : 2;
            for (int pi = 0; pi < paddingCount; ++pi) {
                Padding pad = (pi == 0) ? Padding::PKCS7 : Padding::Zeros;
                const char* padName = (pi == 0) ? "PKCS7" : "Zeros";

                std::string label = std::string(mc.name) + "-"
                                  + std::to_string(kc.bits) + "-"
                                  + (mc.skipZeros ? "NoPad" : padName);
                int groupPassed = 0, groupFailed = 0;

                for (size_t dataSize : TEST_SIZES) {
                    auto plain = getTestData(dataSize);

                    // Encrypt with reference backend
                    AesProxy refProxy(ref, kc.bits, kc.key, kc.keyLen,
                                      nullptr, 0, pad);
                    if (mc.useIV)  refProxy.setIV(TEST_IV, IV_SIZE);
                    if (mc.useCtr) refProxy.setCounter(TEST_COUNTER, COUNTER_SIZE);

                    auto refCipher = refProxy.cipher(plain);
                    if (refCipher.empty()) {
                        std::cout << "[FAIL] " << label << " (" << dataSize
                                  << " bytes): " << WAes::GetImplName(ref)
                                  << " encryption failed\n";
                        ++failed; ++groupFailed;
                        continue;
                    }

                    bool ok = true;

                    // Compare cipher output of every other backend
                    for (size_t bi = 1; bi < backends.size(); ++bi) {
                        WAes::Backend b = backends[bi];
                        AesProxy p(b, kc.bits, kc.key, kc.keyLen,
                                   nullptr, 0, pad);
                        if (mc.useIV)  p.setIV(TEST_IV, IV_SIZE);
                        if (mc.useCtr) p.setCounter(TEST_COUNTER, COUNTER_SIZE);

                        auto ct = p.cipher(plain);
                        if (ct != refCipher) {
                            std::cout << "[FAIL] " << label << " (" << dataSize
                                      << " bytes): cipher mismatch — "
                                      << WAes::GetImplName(b) << " differs from "
                                      << WAes::GetImplName(ref) << "\n";
                            ok = false;
                        }
                    }

                    // Decrypt reference ciphertext with every backend and check plaintext
                    for (auto b : backends) {
                        AesProxy p(b, kc.bits, kc.key, kc.keyLen,
                                   nullptr, 0, pad);
                        if (mc.useIV)  p.setIV(TEST_IV, IV_SIZE);
                        if (mc.useCtr) p.setCounter(TEST_COUNTER, COUNTER_SIZE);

                        auto dec = p.invCipher(refCipher, dataSize);
                        if (dec != plain) {
                            std::cout << "[FAIL] " << label << " (" << dataSize
                                      << " bytes): decrypt mismatch — "
                                      << WAes::GetImplName(b) << "\n";
                            ok = false;
                        }
                    }

                    if (ok) ++groupPassed; else ++groupFailed;
                }

                passed += groupPassed;
                failed += groupFailed;

                if (groupFailed == 0) {
                    std::cout << "[OK] " << label << ": "
                              << groupPassed << " sizes passed\n";
                }
            }
        }
    }

    std::cout << "\nCross-validation: " << passed << " passed, " << failed << " failed";
    if (failed == 0)
        std::cout << " — All backends consistent\n";
    else
        std::cout << " — INCONSISTENCIES DETECTED\n";
}

// ── Per-backend individual tests ──────────────────────────────────────────────

static void runBackend(WAes::Backend b, bool runPerf) {
    g_testBackend = b;
    std::string implName = (b == WAes::Backend::Auto)
        ? "WAes"
        : std::string("WAes(") + WAes::GetImplName(b) + ")";

    std::cout << "AES Library Test Suite - " << implName << "\n";
    std::cout << "===============================================\n";

    if (runPerf) {
        runPerformanceTests(implName);
    } else {
        runImplementationTests(implName);
    }
}

int main(int argc, char* argv[]) {
    processCommandLineArgs(argc, argv);

    bool runPerf = false;
    WAes::Backend forcedBackend = WAes::Backend::Auto;
    bool hasForced = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "perf") {
            runPerf = true;
        } else if (arg == "--backend" && i + 1 < argc) {
            std::string name = argv[++i];
            for (auto b : WAes::AvailableBackends()) {
                if (name == WAes::GetImplName(b)) {
                    forcedBackend = b;
                    hasForced = true;
                    break;
                }
            }
            if (!hasForced) {
                std::cerr << "Unknown backend: " << name << "\n";
                std::cerr << "Available:";
                for (auto b : WAes::AvailableBackends())
                    std::cerr << " " << WAes::GetImplName(b);
                std::cerr << "\n";
                return 1;
            }
        }
    }

    if (hasForced) {
        // Single specified backend — no cross-validation
        runBackend(forcedBackend, runPerf);
    } else if (shouldWriteToFile()) {
        // Cross-compare mode: auto-selected backend, save as "WAes"
        runBackend(WAes::Backend::Auto, runPerf);
    } else {
        // Interactive: test every backend, then cross-validate
        for (auto b : WAes::AvailableBackends()) {
            runBackend(b, runPerf);
            std::cout << "\n";
        }
        if (!runPerf) {
            runCrossValidation();
        }
    }

    return 0;
}
