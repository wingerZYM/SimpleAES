# AES 库测试套件

这个测试套件用于验证跨平台的多种AES实现：通用代码（所有平台）、AES-NI指令集（x86-64）、VAES指令集（x86-64）、VAES512指令集（x86-64）和ARMv8加密扩展（ARM64）。

各独立测试程序分别包含一个 `WAes-*.hpp` 实现，用于验证这些头文件可以互换。
统一的 `test_waes` 程序则不同：它会在同一进程中实例化所有已编入且当前机器
可以执行的后端，并直接比较结果。

## 文件结构

### 核心文件
- `test_data.hpp` - 共同的测试数据和常量
- `test_utils.hpp` - 测试工具函数和辅助类
- `test_options.hpp` - 经过校验的命令行选项和自定义参数
- `test_known_answers.hpp` - FIPS-197、NIST SP 800-38A 与 SP 800-38D 标准答案向量
- `test_gcm.hpp` - GCM AAD、认证失败、原地操作、模式状态和自动 nonce 测试
- `test_template.hpp` - 共享功能测试与性能测试
- `test_entry.hpp` - 独立头文件测试的共用程序入口
- `test_waes_adapter.hpp` - 通过 `WAes.hpp` 运行共享测试的适配器
- `test_waes_cross.hpp` - 统一头文件的跨后端验证
- `test_waes_regressions.hpp` - Guard page 与缺陷回归测试

### 测试文件
- `test_generic.cpp` - 通用AES实现测试 (WAes-gen.hpp)
- `test_generic_multitu_main.cpp` - Generic C++11 多翻译单元链接测试入口
- `test_generic_multitu.cpp` - Generic 头文件的第二翻译单元及链接测试
- `test_cxx11_gcm.cpp` - 所有独立头文件的 C++11 GCM API 烟测
- `test_aes_ni.cpp` - AES-NI指令集实现测试 (WAes-ni.hpp) [仅x86-64]
- `test_vaes.cpp` - VAES指令集实现测试 (WAes-vaes.hpp) [仅x86-64]
- `test_vaes512.cpp` - VAES512指令集实现测试 (WAes-vaes512.hpp) [仅x86-64]
- `test_armv8.cpp` - ARMv8加密扩展实现测试 (WAes-armv8.hpp) [仅ARM64]
- `test_waes.cpp` - 统一自适应头文件测试及进程内后端比较

### 构建和运行文件
- `Makefile` - 支持平台及指令集检测的构建系统
- `.gitignore` - 忽略 `out/` 输出目录

### 比较工具
- `compare_implementations.cpp` - 跨实现对比工具

### 输出目录（自动生成，已加入 git 忽略）
```
out/
├── bin/        ← 编译后的可执行文件
└── reports/    ← 带时间戳的测试报告
```

## 测试内容

每个独立实现都会测试：

- 10 个标准答案加解密向量
- 1 个与 OpenSSL 兼容的 CTR 计数器完整进位向量
- 5 个 GCM 行为与失败路径专项测试
- 450 次确定性往返测试：18 种模式/密钥/填充配置乘以 25 种边界和多块长度
- 6 个确定性非法 PKCS7 拒绝测试
- 任意正确性测试失败时返回非零进程退出码
- 所有测试目标均使用 `-fno-exceptions` 编译

因此，每个独立后端共有 472 项功能检查。统一测试还会运行相同的共享测试，
直接交叉验证所有可用后端，并执行后端可用性、guard page、填充、原地操作、
非对齐 I/O、作用域 AAD 恢复和 CTR 计数器 128 位完整进位回归测试。

### AES模式
- **ECB模式** - 电子密码本模式
- **CBC模式** - 密码块链接模式  
- **CTR模式** - 计数器模式
- **GCM模式** - 支持关联数据的认证加密模式

### 密钥长度
- **AES-128** - 128位密钥
- **AES-192** - 192位密钥
- **AES-256** - 256位密钥

### 填充方式
- **PKCS7填充** - 标准PKCS#7填充
- **零填充** - 零字节填充
- **无填充** - CTR 和 GCM 模式不使用填充

### 数据长度

功能测试矩阵使用以下 25 种确定性长度：

```text
1, 7, 15, 16, 17, 23, 31, 32, 33, 39, 47, 48, 64,
65, 71, 79, 80, 96, 112, 128, 144, 160, 192, 256, 271
```

这些长度覆盖部分块、完整块、向量宽度边界和多块尾部；更大的输入属于下方的
性能测试。

### 性能测试
每个实现都包含全面的性能基准测试：

#### 常规性能测试
- **小到中等数据**: 1KB, 4KB, 16KB, 64KB
- **多次迭代**: 100次迭代以获得准确的计时
- **详细指标**: 分别计时加密/解密操作和吞吐量计算

#### 100 MiB 大数据基准测试
- **持续吞吐量**: 测试 100 MiB 缓冲区
- **优化迭代**: 减少到 1 次迭代以控制测试时间
- **全面覆盖**: 所有AES模式（ECB、CBC、CTR、GCM）和密钥大小（128位、256位）
- **验证**: 包含正确性验证以确保数据完整性
- **性能指标**: 
  - 单独的加密和解密计时
  - 组合吞吐量（MiB/s，包含两种操作）
  - 每个测试的通过/失败状态

100 MiB 基准测试用于测量持续性能；结果仍取决于 CPU、编译器、频率策略和
所选 AES 模式。

## 使用方法

### 构建测试
```bash
cd tests
make all
```

### 运行所有功能测试
```bash
make run-all
```

### 运行所有性能测试
```bash
make run-perf-all
```

### 使用 Address/Undefined-Behavior Sanitizer
```bash
make sanitize
```

Sanitizer 目标会构建 Generic 实现和仅含 Generic 后端的基线
`WAes.hpp` 测试；各硬件实现仍在普通构建中使用各自明确的指令集参数。

### 运行特定实现测试
```bash
make run-generic      # 通用实现功能测试
make run-generic-multitu # Generic C++11 多翻译单元链接测试
make run-aes-ni       # AES-NI实现功能测试 (仅x86-64)
make run-vaes         # VAES实现功能测试 (x86-64，如果支持)
make run-vaes512      # VAES512实现功能测试 (x86-64，如果支持)
make run-armv8        # ARMv8实现功能测试 (ARM64，如果支持)
```

### 运行特定实现性能测试
```bash
make run-perf-generic # 通用实现性能测试
make run-perf-aes-ni  # AES-NI实现性能测试 (仅x86-64)
make run-perf-vaes    # VAES实现性能测试 (x86-64，如果支持)
make run-perf-vaes512 # VAES512实现性能测试 (x86-64，如果支持)
make run-perf-armv8   # ARMv8实现性能测试 (ARM64，如果支持)
```

### 生成带时间戳的报告（功能测试 + 性能测试，保存到 `out/reports/`）
```bash
make report-all       # 为所有实现生成报告
make report-generic   # 通用实现报告 → out/reports/Generic_<时间戳>.txt
make report-aes-ni    # AES-NI 报告 → out/reports/AES-NI_<时间戳>.txt
make report-vaes      # VAES 报告 → out/reports/VAES_<时间戳>.txt
make report-vaes512   # VAES512 报告 → out/reports/VAES512_<时间戳>.txt
make report-armv8     # ARMv8 报告 → out/reports/ARMv8_<时间戳>.txt
```

### 运行单个测试程序
```bash
./out/bin/test_generic        # 功能测试
./out/bin/test_generic_multitu # C++11 多翻译单元链接测试
./out/bin/test_generic perf   # 性能测试（包含 100 MiB 基准测试）
./out/bin/test_aes_ni         # 功能测试 (仅x86-64)
./out/bin/test_aes_ni perf    # 性能测试（包含 100 MiB 基准测试，仅x86-64）
./out/bin/test_vaes            # 功能测试 (仅x86-64)
./out/bin/test_vaes perf       # 性能测试（包含 100 MiB 基准测试，仅x86-64）
./out/bin/test_vaes512         # 功能测试 (仅x86-64)
./out/bin/test_vaes512 perf    # 性能测试（包含 100 MiB 基准测试，仅x86-64）
./out/bin/test_armv8           # 功能测试 (仅ARM64)
./out/bin/test_armv8 perf      # 性能测试（包含 100 MiB 基准测试，仅ARM64）
./out/bin/test_waes            # 统一实现功能和跨后端测试
./out/bin/test_waes perf       # 统一实现性能测试（包含 100 MiB 基准测试）
```

### 快速测试
```bash
make quick-test       # 运行全部功能测试，但只显示精简输出
```

### 检查平台
```bash
make check-platform
```

### 清理
```bash
make clean            # 删除整个 out/ 目录（可执行文件 + 报告）
```

### 帮助
```bash
make help
```

## 实现比较工具

比较工具自动比较不同AES实现的结果，确保它们在所有支持的平台和实现上产生相同的输出。

### 支持的平台和实现

#### x86-64 平台
- **Generic**: 通用C++实现（所有平台支持）
- **WAes**: 统一自适应头文件（始终构建，从已编入后端中选择）
- **AES-NI**: Intel AES-NI 硬件加速实现
- **VAES**: Intel VAES (AVX2) 硬件加速实现
- **VAES512**: Intel VAES (AVX512) 硬件加速实现

#### ARM64 平台  
- **Generic**: 通用C++实现（所有平台支持）
- **WAes**: 统一自适应头文件（始终构建，从已编入后端中选择）
- **ARMv8**: ARM Crypto Extensions 硬件加速实现

工具会自动检测当前平台并只比较可用的实现。

### 比较工具使用方法

#### 构建比较工具
```bash
make compare
```

#### 自动检测并比较所有可用实现
```bash
make cross-compare
# 或直接运行：
./out/bin/compare-implementations
```

#### 指定要比较的实现
```bash
# x86-64 平台示例
make cmp-specific IMPLS='Generic AES-NI VAES VAES512'
# 或直接运行：
./out/bin/compare-implementations Generic AES-NI VAES VAES512

# ARM64 平台示例  
make cmp-specific IMPLS='Generic ARMv8'
# 或直接运行：
./out/bin/compare-implementations Generic ARMv8
```

#### 命令行选项

**基本用法**：
```bash
./out/bin/compare-implementations [OPTIONS] [IMPLEMENTATIONS...]
```

**可用选项**：
- **无参数**: 自动检测所有可用的实现并进行比较
- **`--keep-files, -k`**: 保留测试结果文件，用于调试和分析
- **`--clean-only, -c`**: 仅清理旧的测试结果文件然后退出
- **`--verbose, -v`**: 显示详细输出信息
- **`--help, -h`**: 显示帮助信息

#### 使用示例

**标准比较（自动清理）**：
```bash
./out/bin/compare-implementations
# 自动检测实现，运行测试，比较结果，然后清理临时文件
```

**保留测试文件用于调试**：
```bash
./out/bin/compare-implementations --keep-files
```

**详细输出**：
```bash
./out/bin/compare-implementations --verbose
```

#### 比较功能特性

比较工具提供：
- **自动平台检测**: 检测x86-64 vs ARM64平台
- **硬件特性检测**: 检查CPU指令集支持
- **实现自动发现**: 查找可用的实现
- **详细结果比较**: 比较加密输出和往返完整性
- **报告生成**: 创建详细的比较报告

#### 文件管理

通过 `make cross-compare` 运行时，比较工具将输出写入 `out/reports/`：
- **`out/reports/test_results_<实现名>.txt`**: 每个实现的详细测试结果
- **`out/reports/implementation_comparison_report.txt`**: 比较结果报告

默认情况下，工具会在完成比较后自动清理这些临时文件。使用`--keep-files`保留它们用于调试。

#### Makefile集成的比较功能

```bash
# 检查平台和可用实现
make check-platform

# 构建比较工具
make compare

# 运行完整的跨实现比较
make cross-compare

# 运行指定实现的比较
make cmp-specific IMPLS='Generic AES-NI'

# 清理所有构建产物和报告
make clean
```

## 测试验证

### 功能验证
- **加密/解密一致性** - 验证加密后解密能恢复原始数据
- **填充验证** - 验证PKCS7填充的正确性和错误检测
- **模式正确性** - 验证ECB/CBC/CTR/GCM模式的正确实现
- **边界情况** - 测试各种数据长度的处理

### 性能测试
- **吞吐量测试** - 测量每种实现的加密/解密速度
- **性能基准** - 为不同数据大小提供性能参考
- **实现对比** - 通过手动比较不同实现的性能结果

## 预期结果

### 通用实现 (Generic)
- 兼容性最好，支持所有平台
- 性能相对较慢
- 作为参考实现验证正确性

### AES-NI实现
- 需要支持AES-NI指令集的CPU；PCLMULQDQ 可加速 GCM
- 性能显著优于通用实现
- 单块处理，适合小到中等数据

### VAES实现
- 需要 CPU 和编译器支持 SSSE3、AES、AVX2 和 VAES
- 在所选模式允许并行时使用双块路径；32 字节是实现路径阈值，不是保证超过
  AES-NI 的性能分界点
- 256位并行处理，2个AES块同时处理
- 使用VAES指令进行向量化AES运算

### VAES512实现
- 需要支持 SSSE3、AES、AVX2、VAES 和 AVX512F/BW/DQ/VL
- 在所选模式允许并行时使用四块路径；64 字节是实现路径阈值，不是保证性能
  更高的分界点
- 512位并行处理，4个AES块同时处理
- 应根据 CPU 特性位判断可用性，而不是根据处理器年份

### ARMv8实现
- 需要支持加密扩展的ARM64 CPU
- ARM平台上的硬件加速AES运算
- 启用加密扩展时使用 PMULL 加速 GCM 认证
- 相比通用实现有优化的性能
- 在现代ARM64处理器上广泛可用（带加密扩展的ARMv8-A）

## 故障排除

### 硬件加速测试跳过
如果看到支持未检测到的消息，说明：

**VAES/VAES512 (x86-64)**：
- CPU不支持所需的指令集（AVX2/AVX-512、AES-NI、VAES）
- 编译器未启用相应支持
- 对于VAES512：硬件支持极其有限，大多数CPU不支持AVX-512 + VAES

**ARMv8 (ARM64)**：
- CPU不支持ARMv8加密扩展
- 编译器未启用ARM加密扩展支持
- 运行在非ARM64平台上

### 编译错误
确保：
- 测试套件和 `WAes.hpp` 使用支持 C++20 的编译器；独立头文件本身最低为 C++11
- 编译器支持目标指令集
- 正确设置了`-march=native`标志

### 测试失败
如果测试失败：
1. 验证测试数据完整性
2. 确认CPU指令集支持
3. 检查编译优化设置
4. 对比不同实现的输出结果

### 实现一致性验证

`test_waes` 会在同一进程中直接比较统一头文件的所有可用后端；
`compare-implementations` 则分别运行各独立实现的可执行文件并比较确定性结果，
同时验证这些独立头文件保持等价。

### 比较工具故障排除

**找不到实现文件**：
```
Error: Need at least 2 implementations to compare.
Available implementations: None
```
确保存在至少两个头文件：
- x86-64: `WAes-gen.hpp`, `WAes-ni.hpp`, `WAes-vaes.hpp`, `WAes-vaes512.hpp`
- ARM64: `WAes-gen.hpp`, `WAes-armv8.hpp`

**平台不支持某个实现**：
```
Skipping AES-NI test - not available on arm64 platform
```
这是正常的，工具会根据平台自动跳过不支持的实现。

**调试技巧**：
```bash
# 保留文件进行检查
./out/bin/compare-implementations --keep-files --verbose

# 查看特定实现的详细结果
cat out/reports/test_results_Generic.txt
```

## 扩展测试

要添加新的测试：
1. 在`test_template.hpp`中添加新的测试函数模板
2. 更新`test_utils.hpp`中的辅助函数（如需要）
3. 在`Makefile`中添加新的构建目标（如需要）
4. 更新此README文档

## 实现说明

### VAES实现细节
当前的VAES实现 (`WAes-vaes.hpp`) 使用256位VAES指令：
- 基于 SSSE3、AES、AVX2 和 VAES 指令集
- 一次处理2个AES块（32字节）
- 对长度至少为 32 字节且允许并行的路径使用 VAES
- 剩余块和串行路径使用 128 位 AES 指令
- 必须显式检测 VAES；仅具备 AVX2 的 Haswell 等处理器并不满足要求

### 512位VAES实现
项目中还包含一个512位VAES实现 (`WAes-vaes512.hpp`)：
- 基于AVX-512指令集 + VAES指令集
- 一次处理4个AES块（64字节）
- 可以加速符合条件的大缓冲区路径，但宽向量并不保证在所有 CPU 或模式下更快
- 必须具备上文列出的全部特性，并通过特性检测后才能执行
