#include "../WAes.hpp"

// Adapter: wrap WAes::Ptr API to match the CWAes<N> value-type interface
// expected by test_template.hpp
template <int N>
class CWAes {
    WAes::Ptr m_impl;
public:
    CWAes(const void* key, size_t keyLen, const void* iv = nullptr,
          size_t ivLen = 16, Padding padding = Padding::PKCS7)
        : m_impl(WAes::Create<N>(key, keyLen, iv, ivLen, padding)) {}

    size_t SumCipherLength(size_t inLen) const {
        return m_impl->SumCipherLength(inLen);
    }
    void SetIV(const void* iv, size_t len) { m_impl->SetIV(iv, len); }
    void SetCounter(const void* ctr, size_t len) { m_impl->SetCounter(ctr, len); }

    size_t Cipher(const void* in, size_t inLen, void* out, size_t outLen) const {
        size_t len = outLen;
        return m_impl->Cipher(in, inLen, out, len) ? len : 0;
    }
    size_t InvCipher(const void* in, size_t inLen, void* out, size_t outLen) const {
        size_t len = outLen;
        return m_impl->InvCipher(in, inLen, out, len) ? len : 0;
    }
};
using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;

#include "test_template.hpp"

int main(int argc, char* argv[]) {
    processCommandLineArgs(argc, argv);

    std::string implName = std::string("Unified(") + WAes::GetImplName() + ")";
    std::cout << "AES Library Test Suite - " << implName << " Implementation" << std::endl;
    std::cout << "===============================================" << std::endl;

    if (shouldWriteToFile()) {
        std::cout << "File output enabled - results will be saved for comparison" << std::endl;
    }

    bool runPerf = false;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "perf") {
            runPerf = true;
            break;
        }
    }

    if (runPerf) {
        runPerformanceTests(implName);
    } else {
        runImplementationTests(implName);
    }

    return 0;
}
