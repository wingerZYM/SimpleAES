#pragma once

#include "../WAes.hpp"

inline WAes::Backend g_testBackend = WAes::Backend::Auto;

// Adapts the unified pointer API to the value-style interface shared by the
// standalone header tests.
template <int N> class CWAes {
  WAes::Ptr impl_;

public:
  CWAes(const void *key, size_t keyLength, const void *iv = nullptr,
        size_t ivLength = 16, Padding padding = Padding::PKCS7)
      : impl_(g_testBackend == WAes::Backend::Auto
                  ? WAes::Create<N>(key, keyLength, iv, ivLength, padding)
                  : WAes::Create<N>(g_testBackend, key, keyLength, iv,
                                    ivLength, padding)) {}

  size_t SumCipherLength(size_t inputLength) const {
    return impl_ ? impl_->SumCipherLength(inputLength) : 0;
  }

  void SetIV(const void *iv, size_t length) {
    if (impl_)
      impl_->SetIV(iv, length);
  }

  void SetCounter(const void *counter, size_t length) {
    if (impl_)
      impl_->SetCounter(counter, length);
  }

  bool Cipher(const void *input, size_t inputLength, void *output,
              size_t &outputLength) const {
    return impl_ &&
           impl_->Cipher(input, inputLength, output, outputLength);
  }

  bool InvCipher(const void *input, size_t inputLength, void *output,
                 size_t &outputLength) const {
    return impl_ &&
           impl_->InvCipher(input, inputLength, output, outputLength);
  }
};

using CWAes128 = CWAes<128>;
using CWAes192 = CWAes<192>;
using CWAes256 = CWAes<256>;
