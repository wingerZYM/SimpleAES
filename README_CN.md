# SimpleAES
可能是最简单的一个C++ AES加解密库。
  
## 简单到什么程度？
在支持C++11的环境中，只需要一个`hpp`头文件就足够了。
```c++
#include "WAes-gen.hpp"
```
是的，只需要在源文件中包含一个头文件，就可以对数据进行AES加解密操作了。只要编译器支持C++11，就没有别的要求。甚至可以集成到oc++的.mm文件中。并且不会让最终发布的程序产生任何新的依赖。

## 实现版本说明

目前提供了多个优化版本的AES实现：

### 📦 通用版本
- **`WAes-gen.hpp`** - 纯C++实现，兼容所有平台和编译器，支持C++11及以上

### ⚡ 硬件加速版本

#### x86/x64架构
- **`WAes-ni.hpp`** - 基于Intel AES-NI指令集的硬件加速版本
- **`WAes-vaes.hpp`** - 基于Intel VAES (AVX2) 指令集的高级硬件加速版本
- **`WAes-vaes512.hpp`** - 基于Intel VAES (AVX512) 指令集的极高性能版本

#### ARM架构  
- **`WAes-armv8.hpp`** - 基于ARMv8-A AES硬件指令的ARM64加速版本

### 🚀 性能对比
不同版本的性能从低到高排序：
```
Generic < AES-NI < VAES (AVX2) < VAES512 (AVX512)
```

所有版本的公共接口完全相同，只需要更改包含的头文件即可无缝切换。

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
CWAes aes(...);
auto outLen = aes.Cipher(data, 16, ciphertext, sizeof(ciphertext));
```
解密：
```c++
CWAes aes(...);
auto outLen = aes.InvCipher(ciphertext, 32, plaintext, sizeof(plaintext));
```
不同的模式和补位方式都是在AES对象构造的时候决定。后续可以通过`SetIV`或者`SetCounter`方法来切换为对应的模式。加解密的接口方法所有模式都是通用的，没有区别。

## 硬件加速版本详解

### Intel AES-NI 版本
`WAes-ni.hpp` 基于Intel AES-NI指令集实现，相比通用版本有4倍左右的性能提升。

**编译要求**：
```shell
c++ -std=c++11 -mssse3 -maes test.cpp
```

### Intel VAES 版本  
`WAes-vaes.hpp` 基于AVX2 + VAES指令集，可以并行处理2个AES块，性能更高。

**编译要求**：
```shell
c++ -std=c++11 -mavx2 -mvaes test.cpp
```

### Intel VAES512 版本
`WAes-vaes512.hpp` 基于AVX512 + VAES指令集，可以并行处理4个AES块，提供极致性能。

**编译要求**：
```shell
c++ -std=c++11 -mavx512f -mvaes test.cpp
```

### ARMv8 版本
`WAes-armv8.hpp` 基于ARMv8-A AES硬件指令实现，适用于ARM64平台。

**编译要求**：
```shell
# Linux ARM64
c++ -std=c++11 -march=armv8-a+crypto test.cpp

# macOS ARM64 (无需额外参数)
c++ -std=c++11 test.cpp
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

### 版本选择建议

1. **开发/测试环境**：使用 `Generic` 版本确保兼容性
2. **现代x86服务器**：优先使用 `VAES` 版本
3. **高性能计算**：在支持的平台上使用 `VAES512` 版本
4. **ARM64设备**：使用 `ARMv8` 版本
5. **跨平台部署**：运行时检测并选择合适版本

## 还有什么已知的问题吗？
其实AES一部分操作是可以并发执行的。比如ECB的加解密，CBC的解密过程等。但是引入并发操作，必然导致代码的复杂。及小规模数据操作时，并发带来的性能提升，是否能够弥补并发带的开销也是个问题。因此，本着用最精简的方式满足绝大多数的使用场景的设计理念，本库就不做这方面的考虑。

不过，新增的VAES和VAES512版本在指令级别实现了并行处理，在保持接口简洁的同时显著提升了性能。