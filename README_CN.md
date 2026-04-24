# SimpleAES
可能是最简单的一个C++ AES加解密库。
  
## 简单到什么程度？
在支持C++11的环境中，只需要一个`hpp`头文件就足够了。
```c++
#include "WAes-gen.hpp"
```
是的，只需要在源文件中包含一个头文件，就可以对数据进行AES加解密操作了。只要编译器支持C++11，就没有别的要求。甚至可以集成到oc++的.mm文件中。并且不会让最终发布的程序产生任何新的依赖。

## 两种使用方式

本库提供两种形态——**独立单后端头文件**和**统一自适应头文件**——以覆盖不同的部署场景。

### 独立头文件（单一后端）

每个 `WAes-*.hpp` 都是一个完整独立的 AES 实现，针对特定指令集。包含一个头文件，获得一个后端——没有抽象层，没有运行时分发开销。

| 头文件 | 后端 | 编译参数 |
|--------|------|----------|
| `WAes-gen.hpp` | 纯 C++（通用） | 无（C++11） |
| `WAes-ni.hpp` | Intel AES-NI | `-mssse3 -maes` |
| `WAes-vaes.hpp` | Intel VAES (AVX2) | `-mavx2 -mvaes` |
| `WAes-vaes512.hpp` | Intel VAES (AVX512) | `-mavx512f -mvaes` |
| `WAes-armv8.hpp` | ARMv8-A Crypto | `-march=armv8-a+crypto` |

**适合场景**：运行平台明确的服务端程序或嵌入式系统。编译时直接指定最优后端，零间接调用，性能最大化。

### 统一自适应头文件（`WAes.hpp`）

`WAes.hpp` 将所有后端整合到单一文件中，根据编译期平台检测自动选择最优实现。通过 `WAes::Ptr` 多态接口和工厂函数使用：

```c++
#include "WAes.hpp"

// 自动选择最优后端
auto aes = WAes::Create<128>(key, keyLen, iv, ivLen);
aes->Cipher(plaintext, plainLen, ciphertext, cipherLen);
```

也可以在运行时显式指定后端：

```c++
auto aes = WAes::Create<256>(WAes::Backend::Generic, key, keyLen);
```

性能测试表明，统一版本与独立头文件性能相当——虚函数调用开销相对于 AES 计算本身可以忽略不计。

**适合场景**：需要分发到不同硬件环境的客户端程序或库。一个二进制文件自动适配 x86、ARM 或通用回退，无需用户关心后端选择。

### 性能对比

从低到高排序：
```
Generic < AES-NI < VAES (AVX2) < VAES512 (AVX512)
```

所有独立头文件共享相同的 `CWAes<N>` 公开接口。统一版 `WAes.hpp` 通过 `WAes::Ptr` 提供相同操作，并附加了额外的便捷 API。

## 这么简单，能做什么？
设计这个库的时候，本着简单、易用、**够用**、高效、无依赖的原则。因此并没有大而全的覆盖所有加密模式。而是实现了最最常用的模式，以求用最精简的方式满足绝大多数的使用场景。具体如下：
* 128、192、256 三种密钥强度
* ECB、CBC、CTR 三种加密模式
* Zero、PKCS7 两种补位方式

以上的组合，目前已足够覆盖本人所有的生产与测试环境。

## 具体怎么用？
以128位密钥强度为例，如何对数据进行加解密。

创建一个aes128-ecb对象：
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
创建一个aes128-cbc对象：
```c++
// CBC / Zero padding
CWAes128 cbc(key, 16, iv, 16, Padding::Zeros);
cbc.SetIV(iv2, 16); // 可以修改IV，并从任意模式切为CBC模式。
```
创建一个aes128-ctr对象：
```c++
// CTR / none padding
CWAes128 ctr(key, 16);
ctr.SetCounter(iv, 16);// 设置counter并转为ctr模式。
```
加密：
```c++
CWAes128 aes(key, 16);
size_t cipherLen = sizeof(ciphertext);
if (!aes.Cipher(data, 16, ciphertext, cipherLen)) {
    // 加密失败（缓冲区太小等）
}
// cipherLen 已更新为实际写入的字节数
```
解密：
```c++
CWAes128 aes(key, 16);
size_t plainLen = sizeof(plaintext);
if (!aes.InvCipher(ciphertext, cipherLen, plaintext, plainLen)) {
    // 解密失败（填充无效等）
}
// plainLen 已更新为去除填充后的实际字节数
```

`Cipher` 和 `InvCipher` 均返回 `bool`：成功返回 `true`，失败返回 `false`。`outLength` 参数按引用传入：输入时表示缓冲区容量，成功后更新为实际写入字节数。

`SumCipherLength(inLen)` 用于预先计算 `Cipher` 所需的输出缓冲区大小。

不同的模式和补位方式都是在 AES 对象构造的时候决定。后续可以通过 `SetIV` 或者 `SetCounter` 方法来切换为对应的模式。加解密的接口方法所有模式都是通用的，没有区别。

## 使用统一头文件（`WAes.hpp`）

`WAes.hpp` 通过多态接口提供相同的操作，并附加了额外的便捷功能：

```c++
#include "WAes.hpp"

// 自动选择最优后端
auto aes = WAes::Create<128>(key, 16, iv, 16);

// 加密
size_t cipherLen = aes->SumCipherLength(dataSize);
std::vector<uint8_t> ct(cipherLen);
aes->Cipher(data, dataSize, ct.data(), cipherLen);

// 解密
size_t plainLen = dataSize;
std::vector<uint8_t> pt(plainLen);
aes->InvCipher(ct.data(), ct.size(), pt.data(), plainLen);
```

容器重载（直接返回 `std::vector`）：
```c++
auto ct = aes->Cipher(plainVec);     // 加密 vector → vector
std::vector<uint8_t> pt;
aes->InvCipher(ct, pt);              // 解密 vector → vector
```

显式指定后端：
```c++
// 查看当前机器可用的后端
for (auto b : WAes::AvailableBackends())
    std::cout << WAes::GetImplName(b) << "\n";

// 强制使用特定后端
auto aes = WAes::Create<256>(WAes::Backend::Generic, key, 32);
```

RAII 作用域 IV（离开作用域后自动恢复原始 IV/模式）：
```c++
{
    auto scope = aes->ScopeIV(tempIV, 16);
    aes->Cipher(...);   // 使用 tempIV
}
// 已恢复原始 IV
```

## 编译参数

### 独立头文件

| 头文件 | 必需编译参数 |
|--------|-------------|
| `WAes-gen.hpp` | 无（C++11） |
| `WAes-ni.hpp` | `-mssse3 -maes` |
| `WAes-vaes.hpp` | `-mavx2 -mvaes` |
| `WAes-vaes512.hpp` | `-mavx512f -mvaes` |
| `WAes-armv8.hpp` | `-march=armv8-a+crypto`（Linux/macOS ARM64） |

所有独立变体最低要求 `-std=c++11`，推荐使用 `-std=c++17 -O3`。

### 统一头文件（`WAes.hpp`）

`WAes.hpp` 要求 **C++20**（使用了 `std::span`）。通过预处理宏检测目标平台，自动启用编译参数所允许的所有后端。使用 `-march=native` 让编译器自动启用当前主机 CPU 支持的全部指令集：

```shell
# x86：自动启用 Generic + AES-NI + VAES/VAES512
c++ -std=c++20 -O3 -march=native WAes_example.cpp

# ARM64 Linux
c++ -std=c++20 -O3 -march=armv8-a+crypto WAes_example.cpp
```

## 🧪 测试框架 (`tests/` 目录)

为了确保不同实现之间的一致性和正确性，项目提供了完整的测试框架：

### 测试组件

#### 核心测试文件
- **`test_template.hpp`** - 通用测试模板，包含所有测试逻辑
- **`test_data.hpp`** - 测试数据定义（密钥、IV、测试向量等）
- **`test_utils.hpp`** - 测试工具函数（计时器、数据比较等）

#### 实现测试文件
- **`test_generic.cpp`** - 通用实现测试
- **`test_aes_ni.cpp`** - AES-NI实现测试
- **`test_vaes.cpp`** - VAES(AVX2)实现测试
- **`test_vaes512.cpp`** - VAES512(AVX512)实现测试
- **`test_armv8.cpp`** - ARMv8实现测试
- **`test_waes.cpp`** - 统一自适应版本测试（遍历所有可用后端，并进行后端间交叉验证）

#### 跨实现比较工具
- **`compare_implementations.cpp`** - 跨实现对比工具
- **`Makefile`** - 自动化构建和测试系统

### 测试功能

#### 📋 功能测试
测试所有支持的配置组合：
- **密钥长度**：128位、192位、256位
- **加密模式**：ECB、CBC、CTR
- **填充方式**：PKCS7、Zeros
- **数据大小**：16、32、48、64、192、1024字节

#### ⚡ 性能测试
- 加密/解密吞吐量测试
- 不同数据大小的性能对比
- 各实现之间的性能基准测试

#### 🔄 跨实现一致性验证
- 自动检测可用的硬件实现
- 验证所有实现产生相同的加密结果
- 随机参数测试以增加测试覆盖率

### 使用方法

#### 检查平台支持
```bash
cd tests
make check-platform
```

#### 运行单个实现测试
```bash
make run-generic     # 通用实现
make run-aes-ni      # AES-NI实现
make run-vaes        # VAES实现
make run-vaes512     # VAES512实现（如果支持）
make run-armv8       # ARMv8实现（ARM64平台）
```

#### 运行性能测试
```bash
make run-perf-all    # 所有实现的性能测试
make run-perf-vaes512  # VAES512性能测试
```

#### 跨实现比较
```bash
# 构建比较工具
make compare

# 自动检测并比较所有可用实现
make cross-compare
# 或直接运行：
./compare-implementations

# 手动指定要比较的实现
make cmp-specific IMPLS='Generic AES-NI VAES VAES512'
# 或直接运行：
./compare-implementations Generic AES-NI VAES VAES512

# 保留测试文件用于调试
./compare-implementations --keep-files --verbose
```

#### 运行完整测试套件
```bash
make run-all         # 运行所有可用实现的功能测试
make cross-compare   # 运行跨实现比较
```

### 测试输出示例

```bash
$ make check-platform
Platform Detection:
  OS: Linux
  Architecture: x86_64
  Detected Platform: x86_64
  AES-NI Support: yes
  VAES Support: yes
  VAES512 Support: yes
  Building: Generic, AES-NI, VAES, VAES512 tests

$ ./compare-implementations
AES Implementation Comparison Tool
==================================================
Auto-detected implementations: Generic, AES-NI, VAES, VAES512
Comparing implementations: Generic, AES-NI, VAES, VAES512

Running tests for Generic...
  ✓ Generic tests completed successfully
Running tests for AES-NI...
  ✓ AES-NI tests completed successfully
Running tests for VAES...
  ✓ VAES tests completed successfully
Running tests for VAES512...
  ✓ VAES512 tests completed successfully

============================================================
Cross-Implementation Comparison Results
============================================================
[PASS] ECB_128_PKCS7_16
[PASS] ECB_128_PKCS7_32
...
[PASS] CTR_256_NoPad_1024

============================================================
SUMMARY REPORT
============================================================
Implementations tested: Generic, AES-NI, VAES, VAES512
Total tests: 54
Passed: 54
Failed: 0
Success rate: 100.0%

🎉 All tests PASSED! All implementations are equivalent.
```

## 兼容性说明

### 硬件要求

| 实现版本 | 最低硬件要求 | 推荐用途 |
|---------|-------------|----------|
| Generic | 任意CPU | 兼容性优先场景 |
| AES-NI | Intel Westmere (2010+)<br>AMD Bulldozer (2011+) | 通用x86服务器 |
| VAES | Intel Ice Lake (2019+)<br>AMD Zen 3 (2020+) | 现代高性能服务器 |
| VAES512 | Intel Skylake-X (2017+)<br>Intel Ice Lake (2019+) | 专用高性能计算 |
| ARMv8 | ARMv8-A with Crypto extensions | ARM64服务器/移动设备 |

### 如何选择头文件？

| 场景 | 推荐方案 |
|------|----------|
| 服务端程序、嵌入式，平台明确 | 对应 CPU 的独立头文件（如 `WAes-vaes.hpp`） |
| 需要分发的客户端，硬件不确定 | `WAes.hpp`——自动适配每台机器的最优后端 |
| 开发调试、CI 环境 | `WAes-gen.hpp` 或 `WAes.hpp` |
| ARM64（移动端、Apple Silicon、树莓派等） | `WAes-armv8.hpp` 或 `WAes.hpp` |

核心取舍：平台确定时，独立头文件路径最直接——无虚函数调用、无抽象层、性能最大化。程序需要在不同硬件上分发时，`WAes.hpp` 在保持相同吞吐量的前提下自动完成后端选择。

## 还有什么已知的问题吗？
其实AES一部分操作是可以并发执行的。比如ECB的加解密，CBC的解密过程等。但是引入并发操作，必然导致代码的复杂。及小规模数据操作时，并发带来的性能提升，是否能够弥补并发带的开销也是个问题。因此，本着用最精简的方式满足绝大多数的使用场景的设计理念，本库就不做这方面的考虑。

不过，新增的VAES和VAES512版本在指令级别实现了并行处理，在保持接口简洁的同时显著提升了性能。