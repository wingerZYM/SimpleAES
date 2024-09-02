# SimpleAES
可能是最简单的一个C++ AES加解密库。
  
## 简单到什么程度？
在支持C++11的环境中，只需要一个`hpp`头文件就足够了。
```c++
#include "WAes-gen.hpp"
```
是的，只需要在源文件中包含一个头文件，就可以对数据进行AES加解密操作了。只要编译器支持C++11，就没有别的要求。甚至可以集成到oc++的.mm文件中。并且不会让最终发布的程序产生任何新的依赖。

## 这么简单，能做什么？
设计这个库的时候，本着简单、易用、**够用**、~~高效~~、无依赖的原则。因此并没有大而全的覆盖所有加密模式。而是实现了最最常用的模式，以求用最精简的方式满足绝大多数的使用场景。具体如下：
* 128、192、256 三种密钥强度
* ECB、CBC、CTR 三种加密模式
* Zero、PKCS7 两种补位方式

以上的组合，目前已足够覆盖本人所有的生产与测试环境。

## 具体怎么用？
以128位密钥强度为例，如何对数据进行加解密。
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
// 加密
auto outLen = sizeof(ciphertext);
ecb.Cipher(data, 16, ciphertext, outLen);
// 解密
auto outLen = sizeof(plaintext);
ecb.InvCipher(ciphertext, 32, plaintext, outLen);

// CBC / Zero padding
CWAes128 cbc(key, 16, iv, 16, Padding::Zeros);
// cbc.SetIV(iv2, 16); // 可以修改IV，并从任意模式切为CBC模式。
// 加密
auto outLen = sizeof(ciphertext);
cbc.Cipher(data, 16, ciphertext, outLen);
// 解密
auto outLen = sizeof(plaintext);
cbc.InvCipher(ciphertext, 32, plaintext, outLen);

// CTR / none padding
CWAes128 ctr(key, 16);
ctr.SetCounter(iv, 16);// 设置counter并转为ctr模式。
// 加密
auto outLen = sizeof(ciphertext);
ctr.Cipher(data, 16, ciphertext, outLen);
// 解密
auto outLen = sizeof(plaintext);
ctr.InvCipher(ciphertext, 32, plaintext, outLen);
```
不同的模式和补位方式都是在AES对象构造的时候决定。后续可以通过`SetIV`或者`SetCounter`方法来切换为对应的模式。加解密的接口方法所有模式都是通用的，没有区别。

## 还有两个头文件是干什么的？
说好的单一头文件支持全功能，那么还有`WAes-ni.hpp`与`WAes-armv8.hpp`两个文件又是用来干什么的呢？

这就要说到CPU的指令集，比如众所周知的`SSE`指令集。鉴于AES加密在各种生产、生活中的应用日渐增多，Intel公司在Westmere架构的x86 CPU中开始加入了一组名为`AES-NI`的硬件指令集。按照官方的说法，使用AES CPU指令进行AES操作，可以获得4倍左右的性能提升，包括更快的速度，更低的功耗等。随后另外一个CPU大头ARM公司，也在ARMv8-A架构中添加了类似的`AES`硬件指令，以提供硬件加速功能。

再看这两个文件的文件名，就十分清楚了。`WAes-ni.hpp`是基于intel AES-NI与SSE指令集的实现。`WAes-armv8.hpp`是基于ARMv8-A架构中的AES与neon指令集的实现。这两个实现的公共接口完全相同。因此想要切换通用实现到硬件加速的实现，只需要更改包含的文件就可以，非常简单。

那么使用CPU指令性能会有所提升吗？答案是肯定的。而且在不经过编译器优化的编译结果上，那可是遥遥领先…… 但是，这是有代价的。就是可能的兼容性问题。arm的情况可能好一些，毕竟arm的设备换代快。而且主流，比如APPLE的M系列芯片就是从一开始就使用ARMv8-A(64bit)架构。而x86系的CPU情况就复杂得多。Intel是在2010年开始加入AES-NI指令集，而另外一个x86巨头AMD支持得更晚。目前还是有很多不支持AES-NI指令集的机器在运行。而本人就切实的在生产环境中遇到过。因此除非有明确的应用场景（比如服务端），还是使用通用实现比较安全。

那么有没有可能，在运行时决定是否使用CPU指令来进行加速呢？在支持的CPU上使用指令集实例，在不支持的CPU上使用通用实例？当然是可以的。但是这样做会使用代码变得复杂，结构需要重新设计并实现。等日后有机会再考虑重新实现一版。

上面“高效”被划掉，就是出于兼容性的考虑，没有追求极致的性能。实际上本人已经力所能及的优化性能，尽可能的追求了高效！而且以gcc编译器的经验，通过`-O3`参数的优化后，性能上的差距也没有默认参数那么的巨大。

## 还有什么已知的问题吗？
其实AES一部分操作是可以并发执行的。比如ECB的加解密，CBC的解密过程等。但是引入并发操作，必然导致代码的复杂。及小规模数据操作时，并发带来的性能提升，是否能够弥补并发带的开销也是个问题。因此，本着用最精简的方式满足绝大多数的使用场景的设计理念，本库就不做这方面的考虑。