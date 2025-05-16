# SimpleAES

[中文说明](README_CN.md)

Possibly the simplest C++ AES encryption/decryption library.

## How simple is it?

In any C++11-compatible environment, all you need is a single `hpp` header file:

```c++
#include "WAes-gen.hpp"
```

Yes, just include this header in your source file and you're ready to perform AES encryption and decryption. As long as the compiler supports C++11, there are no other dependencies. It can even be integrated into Objective-C++ `.mm` files, and it won't introduce any new runtime dependencies to your final application.

## What can it do despite being so simple?

The library was designed with the principles of simplicity, ease of use, **sufficiency**, ~~efficiency~~, and no external dependencies. Therefore, instead of supporting all encryption modes, it focuses only on the most commonly used ones to meet the needs of most real-world and testing scenarios with minimal implementation. Specifically, it supports:

* 128, 192, and 256-bit key lengths
* ECB, CBC, and CTR encryption modes
* Zero and PKCS7 padding schemes

These combinations are currently sufficient for all of my own production and testing environments.

## How to use it?

Here’s how to encrypt and decrypt data using a 128-bit key as an example.

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

## What are the other two header files for?

You might wonder—if the single header file supports all functions, what are `WAes-ni.hpp` and `WAes-armv8.hpp` for?

This relates to CPU instruction sets, such as the well-known `SSE`. Given the increasing use of AES in modern applications, Intel introduced a set of AES-specific instructions called `AES-NI` in their Westmere architecture CPUs. According to Intel, using AES-NI can provide roughly 4x the performance with lower power consumption. Similarly, ARM added AES hardware instructions to the ARMv8-A architecture to provide hardware acceleration.

The file names make it obvious: `WAes-ni.hpp` is implemented using Intel’s AES-NI and SSE, while `WAes-armv8.hpp` uses ARMv8-A’s AES and NEON instructions. Both implementations share the exact same interface, so switching between the generic and hardware-accelerated version is as simple as changing the included file.

So does using CPU instructions improve performance? Definitely. Especially without compiler optimizations, hardware acceleration can vastly outperform generic implementations. However, it comes with compatibility risks. ARM tends to be more consistent—devices upgrade quickly, and popular chips like Apple’s M-series have always used ARMv8-A (64-bit). x86 is more complex: Intel began supporting AES-NI in 2010, and AMD added it even later. Many older machines still lack AES-NI. I've encountered this firsthand in production.

So unless you're targeting a controlled environment (e.g., server-side), the generic implementation is safer.

Could runtime detection be used to dynamically choose between generic and hardware implementations? Yes, absolutely. Version 2 has implemented runtime automatic selection.

When using the instruction set versions, you need to add specific compiler flags to enable the corresponding instruction sets.

For x86 architecture on GCC and Clang (Linux) using the `aes-ni` version, you should add the flags `-mssse3` and `-maes`:
```shell
c++ -std=c++11 -mssse3 -maes test.cpp
```
For ARM64 architecture on GCC using the `armv8` version, you need to add the flag `-march=armv8-a+crypto`:
```shell
c++ -std=c++11 -march=armv8-a+crypto test.cpp
```
On Apple's ARM64 architecture with Clang, it seems that no additional flags are needed for successful compilation.

## Are there any known limitations?

Some AES operations are naturally parallelizable—like ECB encryption/decryption and CBC decryption. However, introducing concurrency adds code complexity. Also, the benefits on small datasets may not justify the cost. In line with the design philosophy of satisfying most use cases with minimal implementation, this library does not implement concurrency.