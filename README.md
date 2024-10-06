# S-DES
S-DES algorithm's simple implementation.
## 项目简介
本项目是根据重庆大学2022级“信息安全导论”课程要求，使用Python语言实现的S-DES加密算法。支持加密和解密功能，并提供图形用户界面（GUI）以支持用户交互。

## 开发团队
- 团队成员柴钰林
- 团队成员古渲宇
- 团队成员陈芳莹

## S-DES算法原理
### 2.1 分组长度
分组长度：8-bit，意味着明文和密文均以8位二进制数为单位进行处理。
### 2.2 密钥长度
密钥长度：10-bit，初始密钥长度为10位。
### 2.3 算法描述
#### 2.3.1 加密算法
加密过程：
初始置换（IP）：首先对8-bit的明文进行初始置换。
分组：将置换后的比特分为左右两半（L0, R0），各4位。
轮函数（f）：使用子密钥k1对右半部分进行处理，经过扩展置换（EP）、S盒查找和P盒置换，然后与左半部分进行异或操作，结果为SW（交换）后右半部分的结果。
交换（SW）：交换左半部分和经过轮函数处理的右半部分。
第二轮轮函数：使用子密钥k2对第一步交换后的结果重复上述轮函数处理。
最终置换（IP^{-1}）：对第二轮处理的结果进行最终置换，得到最终的8-bit密文。
#### 2.3.2 解密算法
解密过程与加密过程相反：
初始置换（IP）：对8-bit的密文进行初始置换。
分组：将置换后的比特分为左右两半。
第一轮轮函数：使用子密钥k2对右半部分进行处理，交换左右两半。
第二轮轮函数：使用子密钥k1对第一步交换后的结果重复上述轮函数处理。
最终置换（IP^{-1}）：对第二轮处理的结果进行最终置换，恢复为原始的8-bit明文。
#### 2.3.3 密钥扩展
密钥生成：
P10置换：对10-bit的初始密钥进行P10置换。
左移（Shift）：根据轮数进行左移操作，第一轮左移1位，第二轮左移2位。
P8置换：对左移后的密钥进行P8置换，生成两个子密钥k1和k2。
### 2.4 转换装置设定
初始置换盒（IP）：对8-bit的明文或密文进行初始置换。
最终置换盒（IP^{-1}）：对密钥处理后的中间结果进行最终置换。
轮函数F：
扩展置换（EP）：对右半部分进行扩展置换。
S盒（SBox）：查找两个S盒，根据输入的6-bit和子密钥的6-bit进行查表，得到4-bit输出。
P盒（SPBox）：对S盒的输出进行P盒置换，生成轮函数的输出。
S盒
SBox1 和 SBox2 是两个4x4的查找表，用于将6-bit输入映射到4-bit输出。
PBox（SPBox）：对S盒的输出进行置换。
## 实现功能

1. **多模式加解密**：支持ASCLL模式和二进制模式下8-bit数据和10-bit密钥的加密和解密。
2. **跨平台一致性**：确保算法在不同系统或平台上的一致性。
3. **扩展功能**：支持ASCII编码字符串的加密和解密。
4. **暴力破解**：实现多线程暴力破解，尝试找到正确的密钥。
5. **封闭测试**：分析是否存在多个密钥可以生成相同的密文。

## 运行环境

- Python 3.x

## 使用说明

测试结果
第1关：基本测试通过。
第2关：交叉测试通过，与另一组同学的程序结果一致。
第3关：扩展功能测试通过，支持ASCII字符串加密解密。
第4关：暴力破解测试通过，成功找到密钥。
第5关：封闭测试通过，分析了密钥和密文的关系
