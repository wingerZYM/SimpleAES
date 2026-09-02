# SimpleAES
可能是最简单的一个C++ AES加解密库。
  
## 简单到什么程度？
在支持C++11的环境中，只需要一个`hpp`头文件就足够了。
```c++
#include "WAes-gen.hpp"
```
是的，只需要在源文件中包含一个头文件，就可以对数据进行AES加解密操作了。只要编译器支持C++11，就没有别的要求。甚至可以集成到 Objective-C++ 的 `.mm` 文件中，并且不会让最终发布的程序产生任何新的运行时依赖。

## 两种使用方式

本库提供两种形态——**独立单后端头文件**和**统一自适应头文件**——以覆盖不同的部署场景。

### 独立头文件（单一后端）

每个 `WAes-*.hpp` 都是一个完整独立的 AES 实现，针对特定指令集。包含一个头文件，获得一个后端——没有抽象层，没有运行时分发开销。

| 头文件 | 后端 | 编译参数 |
|--------|------|----------|
| `WAes-gen.hpp` | 纯 C++（通用） | 无（C++11） |
| `WAes-ni.hpp` | Intel AES-NI | `-mssse3 -maes` |
| `WAes-vaes.hpp` | Intel VAES (AVX2) | `-mavx2 -maes -mvaes` |
| `WAes-vaes512.hpp` | Intel VAES (AVX512) | `-mavx512f -mavx512bw -mavx512dq -mavx512vl -maes -mvaes` |
| `WAes-armv8.hpp` | ARMv8-A Crypto | `-march=armv8-a+crypto` |

**适合场景**：运行平台明确的服务端程序或嵌入式系统。编译时直接指定最优后端，零间接调用，性能最大化。

### 统一自适应头文件（`WAes.hpp`）

`WAes.hpp` 将各实现整合到单一文件中，从当前构建已编入的后端中自动选择；在 x86 上还会先检查 CPU 能力和操作系统 SIMD 状态。通过 `WAes::Ptr` 多态接口和工厂函数使用：

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

在批量操作中，统一版本的性能通常接近其选中的独立后端；实际差异取决于消息长度、工作模式、编译器和 CPU。

**适合场景**：希望统一 API，并在当前构建包含的后端之间自动选择的程序或库。将 GCC/Clang 构建作为可跨代 CPU 分发的 x86 fat binary 前，请先阅读下方编译说明。

### 性能预期

对于长度足够大、可以并行处理的 ECB、CTR 和 CBC 解密路径，通常有以下趋势：

```text
Generic < AES-NI < VAES (AVX2) < VAES512 (AVX512)
```

这不是在所有情况下都成立的固定排序。小数据、CBC 加密、编译器生成的代码、
CPU 频率策略以及宽向量状态的开销都可能改变结果。应使用应用实际采用的模式和
消息长度进行测试。

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

密钥长度有意保留历史兼容行为：短密钥补零，长密钥按所选 AES 强度截断为 16、24 或 32 字节。需要严格密钥检查的应用应在构造前拒绝长度不精确的密钥。

Zero padding 只在尾块不足 16 字节时补零；输入已经按块对齐时不会额外增加一块。由于明文末尾的零与填充无法区分，Zero-padding 解密会移除尾部零。PKCS7 则始终添加填充，输入按块对齐时也会增加一个完整的 16 字节填充块。

CTR 将传入的 16 字节值视为计数块：前 8 字节保持不变，后 8 字节按大端整数模 2^64 递增。数值重载 `SetCounter(iv, nonce, counter)` 会将三个字段都按大端序列化。

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

// 查看二进制中编入的全部后端（包括当前机器不可运行的后端）
for (auto b : WAes::CompiledBackends())
    std::cout << WAes::GetImplName(b) << "\n";

// 强制使用特定后端；CPU/OS 不支持时返回 nullptr
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
| `WAes-vaes.hpp` | `-mavx2 -maes -mvaes` |
| `WAes-vaes512.hpp` | `-mavx512f -mavx512bw -mavx512dq -mavx512vl -maes -mvaes` |
| `WAes-armv8.hpp` | `-march=armv8-a+crypto`（Linux/macOS ARM64） |

所有独立变体最低要求 `-std=c++11`，推荐使用 `-std=c++17 -O3`。

### 统一头文件（`WAes.hpp`）

`WAes.hpp` 要求 **C++20**（使用了 `std::span`）。它通过预处理宏检测编译目标，并启用编译参数允许的后端：

```shell
# x86：自动启用 Generic + AES-NI + VAES/VAES512
c++ -std=c++20 -O3 -march=native WAes_example.cpp

# ARM64 Linux
c++ -std=c++20 -O3 -march=armv8-a+crypto WAes_example.cpp
```

GCC 和 Clang 的指令集参数作用于整个翻译单元。使用 `-march=native` 生成的程序面向当前 CPU 等级，不能假定可在更老的 x86 CPU 上运行；若需要基线兼容，应不带 AES/VAES 目标参数进行编译，此时使用 Generic 后端。MSVC 构建会编入 x86 硬件实现，并在运行时通过 CPUID 与 XGETBV 检测；`AvailableBackends()` 只返回当前 CPU 和操作系统都能安全执行的实现。

在 AArch64 上，统一头文件只有检测到 `__ARM_FEATURE_CRYPTO` 时才启用 ARM Crypto 后端。若工具链不提供该宏，可以定义 `WAES_ASSUME_ARM_CRYPTO`，但前提是部署硬件确定具备 Crypto Extension。

## 安全注意事项

SimpleAES 提供 AES 原语和传统的保密模式，并不是完整的认证加密协议。

- ECB 会暴露重复数据块的模式，通常不适合一般应用数据。
- CBC 和 CTR 不验证密文完整性。需要配合设计正确的 MAC，或者优先使用认证加密方案。
- CBC 的 IV 必须不可预测；同一个密钥下绝不能重复使用 CTR 的 counter/nonce。
- Generic 后端为了性能使用与密钥相关的 T-table 查表，缓存访问不是常量时间。
  存在本地计时或缓存侧信道威胁时，应使用硬件后端。
- Zero padding 无法区分填充零与明文本身的尾部零。PKCS7 解密失败也不应以可能形成
  padding oracle 的方式暴露给外部。

## 🧪 测试框架 (`tests/` 目录)

测试套件会验证每个独立实现以及统一自适应头文件。完整命令说明请参阅
[`tests/README_CN.md`](tests/README_CN.md)。

### 测试组件

- **共享基础设施**：`test_data.hpp`、`test_utils.hpp`、`test_options.hpp`、
  `test_known_answers.hpp`、`test_template.hpp` 和 `test_entry.hpp`
- **独立实现测试**：`test_generic.cpp`、`test_generic_multitu_main.cpp`、
  `test_generic_multitu.cpp`、`test_aes_ni.cpp`、`test_vaes.cpp`、
  `test_vaes512.cpp` 和 `test_armv8.cpp`
- **统一实现测试**：`test_waes.cpp`、`test_waes_adapter.hpp`、
  `test_waes_cross.hpp` 和 `test_waes_regressions.hpp`
- **跨进程比较**：`compare_implementations.cpp`
- **构建与测试自动化**：`Makefile`

### 测试功能

- **标准答案测试**：9 个 FIPS-197 和 NIST SP 800-38A 向量，覆盖
  ECB、CBC、CTR 以及 128/192/256 位密钥
- **确定性组合测试**：15 种模式/密钥/填充配置乘以 25 种边界和多块长度
  （1～271 字节），共 375 次往返测试
- **校验测试**：6 个非法 PKCS7 拒绝测试，因此每个独立后端共有 390 项功能检查
- **统一实现验证**：在同一进程中直接比较所有已编入且当前可执行的后端，并覆盖
  guard page、填充、原地操作、非对齐 I/O 和 CTR 计数器回归测试
- **性能测试**：1、4、16、64 KiB，以及 100 MiB 持续吞吐测试；结果使用 MiB/s
- **自定义确定性参数**：可通过 `--custom-params` 指定密钥、IV 和 counter

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
make run-waes        # 统一自适应实现
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
./out/bin/compare-implementations

# 手动指定要比较的实现
make cmp-specific IMPLS='Generic WAes AES-NI VAES VAES512'
# 或直接运行：
./out/bin/compare-implementations Generic WAes AES-NI VAES VAES512

# 保留测试文件用于调试
./out/bin/compare-implementations --keep-files --verbose
```

#### 运行完整测试套件
```bash
make run-all         # 运行所有可用实现的功能测试
make cross-compare   # 运行跨实现比较
make sanitize        # 使用 ASan/UBSan 测试 Generic 和基线 WAes
```

`make cross-compare` 会自动检测 `Generic`、`WAes` 以及当前支持的硬件后端，
并比较 375 条确定性组合记录。具体后端列表取决于平台和编译器。

## 兼容性说明

### 硬件要求

| 实现版本 | 最低硬件要求 | 推荐用途 |
|---------|-------------|----------|
| Generic | 具备 C++11 编译器的任意目标 | 兼容性优先场景 |
| AES-NI | 支持 SSSE3 和 AES 的 x86 | 通用 x86 系统 |
| VAES | 支持 SSSE3、AES、AVX2 和 VAES 的 x86 | 现代 x86 上可并行的工作负载 |
| VAES512 | 支持 SSSE3、AES、AVX2、VAES、AVX512F/BW/DQ/VL 的 x86 | 已确认具备全部所需特性的系统 |
| ARMv8 | 具备 Crypto Extension 的 AArch64 | ARM64 服务器/移动设备 |

### 如何选择头文件？

| 场景 | 推荐方案 |
|------|----------|
| 服务端程序、嵌入式，平台明确 | 对应 CPU 的独立头文件（如 `WAes-vaes.hpp`） |
| 需要分发的 x86 客户端，硬件不确定 | MSVC 构建的 `WAes.hpp`，或 GCC/Clang 的 Generic 基线构建 |
| 开发调试、CI 环境 | `WAes-gen.hpp` 或 `WAes.hpp` |
| 具备 Crypto Extension 的 ARM64 | `WAes-armv8.hpp` 或以 `+crypto` 为目标的 `WAes.hpp` |

核心取舍：平台确定时，独立头文件路径最直接——无虚函数调用、无抽象层、性能最大化。统一头文件集中 API，并在二进制实际编入的实现之间安全选择；二进制是否能跨 CPU 运行仍取决于上文所述的编译目标参数。

## 还有什么已知的问题吗？
其实AES一部分操作是可以并发执行的。比如ECB的加解密，CBC的解密过程等。但是引入并发操作，必然导致代码的复杂。及小规模数据操作时，并发带来的性能提升，是否能够弥补并发带的开销也是个问题。因此，本着用最精简的方式满足绝大多数的使用场景的设计理念，本库就不做这方面的考虑。

不过，新增的VAES和VAES512版本在指令级别实现了并行处理，在保持接口简洁的同时显著提升了性能。
