# S-DES
S-DES algorithm's simple implementation.
## 项目简介
本项目是根据重庆大学2022级“信息安全导论”课程要求，使用Python语言实现的S-DES加密算法。支持加密和解密功能，并提供图形用户界面（GUI）以支持用户交互。

## S-DES算法原理
### 分组长度
明文和密文都以8位二进制数为单位处理。
### 密钥长度
初始密钥长度为10位二进制数。
### 加密算法描述
初始置换（IP）：对8-bit明文进行初始置换，生成32-bit的排列输出。
分组：将置换后的输出分为左右两半，每半4位。
#### 第一轮处理：
使用子密钥 k1 对右半部分进行处理。
经过扩展置换（EP）、S盒查找和P盒置换。
与左半部分进行异或操作。
交换（SW）左右两半。
#### 第二轮处理：
使用子密钥 k2 对交换后的结果进行处理。
重复第一轮的扩展置换（EP）、S盒查找和P盒置换。
再次与左半部分进行异或操作。
最终置换（IP^{-1}）：对第二轮处理的结果进行最终置换，生成最终的8-bit密文。
### 解密算法描述
解密过程与加密过程相似，但使用的子密钥顺序相反
### 密钥扩展
P10置换：对10-bit初始密钥进行P10置换。
左移（Shift）：
第一轮左移1位。
第二轮左移2位。
P8置换：对左移后的密钥进行P8置换，生成两个子密钥k1和k2。
### 转换装置设定
初始置换盒（IP）和最终置换盒（IP^{-1}）：分别用于加密和解密过程中的初始和最终置换。
扩展置换（EP）：对右半部分进行扩展置换。
S盒（SBox）：两个4x4的查找表，用于将6-bit输入映射到4-bit输出。
P盒（SPBox）：对S盒的输出进行置换。

## 实现功能

1. **多模式加解密**：支持ASCLL模式和二进制模式下8-bit数据和10-bit密钥的加密和解密。
2. **跨平台一致性**：确保算法在不同系统或平台上的一致性。
3. **扩展功能**：支持ASCII编码字符串的加密和解密。
4. **暴力破解**：实现多线程暴力破解，尝试找到正确的密钥。
5. **封闭测试**：分析是否存在多个密钥可以生成相同的密文。

## 运行环境

- Python 3.x
## 关键代码实现

## 用户界面展示

## 项目测试
### 第1关：基本测试：根据S-DES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是8bit的数据和10bit的密钥，输出是8bit的密文。
### 第2关：交叉测试: 检测算法和程序是否可以在异构的系统或平台上都可以正常运行。
### 第3关：扩展功能考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为1 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。
### 第4关：暴力破解：检测是否能实现多线程暴力破解，且设置时间戳，记录暴力破解时间。
### 第5关：封闭测试：分析是否存在多个密钥可以生成相同的密文

## 开发团队
- 小组：风雨无组
- 团队成员： 柴钰林、古渲宇、陈芳莹
- 单位：重庆大学大数据与软件学院
