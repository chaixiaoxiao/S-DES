# S-DES
S-DES algorithm's simple implementation.
## 一、项目简介
本项目是为满足重庆大学2022级“信息安全导论”课程的作业要求而设计的，旨在通过Python语言实现S-DES加密算法。该项目的核心功能包括数据的加密和解密，同时提供了一个图形用户界面（GUI），以便用户能够直观地与程序交互。通过图形用户界面，用户可以轻松地输入需要加密或解密的文本以及相应的密钥。程序会根据用户的输入执行相应的加密或解密操作，并在界面上展示结果。

## 二、S-DES算法原理
S-DES算法是一种对称密钥加密算法，其算法原理如下：
#### 
分组长度：明文和密文都以8位二进制数为单位处理。
密钥长度：初始密钥长度为10位二进制数。
#### 加密算法描述
初始置换（IP）：对8-bit明文进行初始置换，生成32-bit的排列输出。
分组：将置换后的输出分为左右两半，每半4位。
###### (1)第一轮处理：
使用子密钥 k1 对右半部分进行处理。
经过扩展置换（EP）、S盒查找和P盒置换。
与左半部分进行异或操作。
交换（SW）左右两半。
###### (2)第二轮处理：
使用子密钥 k2 对交换后的结果进行处理。
重复第一轮的扩展置换（EP）、S盒查找和P盒置换。
再次与左半部分进行异或操作。
最终置换（IP^{-1}）：对第二轮处理的结果进行最终置换，生成最终的8-bit密文。
#### 解密算法描述
解密过程与加密过程相似，但使用的子密钥顺序相反
#### 密钥扩展
P10置换：对10-bit初始密钥进行P10置换。
左移（Shift）：
第一轮左移1位。
第二轮左移2位。
P8置换：对左移后的密钥进行P8置换，生成两个子密钥k1和k2。
#### 转换装置设定
初始置换盒（IP）和最终置换盒（IP^{-1}）：分别用于加密和解密过程中的初始和最终置换。
扩展置换（EP）：对右半部分进行扩展置换。
S盒（SBox）：两个4x4的查找表，用于将6-bit输入映射到4-bit输出。
P盒（SPBox）：对S盒的输出进行置换。

## 三、实现功能

1. **多模式加解密**：支持ASCII模式和二进制模式下8-bit数据和10-bit密钥的加密和解密。
2. **跨平台一致性**：确保算法在不同系统或平台上的一致性。
3. **扩展功能**：支持ASCII编码字符串的加密和解密。
4. **暴力破解**：实现多线程暴力破解，尝试找到正确的密钥。
5. **封闭测试**：分析是否存在多个密钥可以生成相同的密文。


## 四、关键代码实现
##### 生成密钥函数
这个函数根据输入的10位密钥生成子密钥K1和K2。
```python
def generate_keys(key):
    key = permute(key, [3, 5, 2, 7, 4, 10, 1, 9, 6, 8])
    left_half = left_shift(key[:5], 1)
    right_half = left_shift(key[5:], 1)
    K1 = permute(left_half + right_half, [6, 3, 7, 4, 8, 5, 10, 9])
    left_half = left_shift(left_half, 2)
    right_half = left_shift(right_half, 2)
    K2 = permute(left_half + right_half, [6, 3, 7, 4, 8, 5, 10, 9])
    return K1, K2
```
##### S盒操作
这个函数实现了S盒操作，它是S-DES算法中非线性变换的关键部分。
```python
def sbox(input_bits, sbox_table):
    row = (input_bits[0] << 1) + input_bits[3]
    col = (input_bits[1] << 1) + input_bits[2]
    output = sbox_table[row][col]
    return [(output >> 1) & 1, output & 1]
```
##### 加密函数f
这个函数是S-DES算法的核心，它对右半部分执行扩展置换、S盒替换，并结合子密钥生成新数据。
```python
def f(right, subkey):
    expanded_right = permute(right, EP)
    xor_result = [expanded_right[i] ^ subkey[i] for i in range(8)]
    left_sbox = sbox(xor_result[:4], S0)
    right_sbox = sbox(xor_result[4:], S1)
    result = permute(left_sbox + right_sbox, P4)
    return result
```
##### 加密函数fk
这个函数使用子密钥对输入的左半部分进行XOR操作，并将结果与右半部分组合。
```python
def fk(bits, subkey):
    left, right = bits[:4], bits[4:]
    result = [left[i] ^ f(right, subkey)[i] for i in range(4)]
    return result + right
```

##### 加密和解密函数
这两个函数分别实现了S-DES的加密和解密过程。
```python
def encrypt(plaintext, key):
    K1, K2 = generate_keys(key)
    bits = permute(plaintext, IP)
    bits = fk(bits, K1)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K2)
    ciphertext = permute(bits, IP_inv)
    return ciphertext
```
```python
def decrypt(ciphertext, key):
    K1, K2 = generate_keys(key)
    bits = permute(ciphertext, IP)
    bits = fk(bits, K2)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K1)
    plaintext = permute(bits, IP_inv)
    return plaintext
```


## 五、用户界面展示
##### 主界面
[![image](https://imgur.la/images/2024/10/07/image14e269e9c5d634b9.md.png)](https://imgur.la/image/image.faVIN)
##### 二进制模式界面
[![image](https://imgur.la/images/2024/10/07/image9d652794bad98300.md.png)](https://imgur.la/image/image.faZJq)
##### ASCll模式界面
[![image](https://imgur.la/images/2024/10/07/image00ce509d64d8aac8.md.png)](https://imgur.la/image/image.faeNj)
##### 暴力破解界面
[![image](https://imgur.la/images/2024/10/07/imageca851f5b8fefa2f6.md.png)](https://imgur.la/image/image.faRnI)
#####  封闭测试界面
[![image](https://imgur.la/images/2024/10/07/image876603ebba6b52c9.md.png)](https://imgur.la/image/image.faz47)

## 六、项目测试
#### 第1关：基本测试：根据S-DES算法编写和调试程序，提供GUI解密支持用户交互。输入可以是8bit的数据和10bit的密钥，输出是8bit的密文。
[![image](https://imgur.la/images/2024/10/07/image024da1b83d562ee1.md.png)](https://imgur.la/image/image.faCiF)
[![image](https://imgur.la/images/2024/10/07/image91e5dff336234c14.md.png)](https://imgur.la/image/image.faP5K)



经测试，该程序能够快速实现二进制模式下的加解密。




#### 第2关：交叉测试: 检测算法和程序是否可以在异构的系统或平台上都可以正常运行。


设有A和B两组位同学(选择相同的密钥K)；则A、B组同学编写的程序对明文P进行加密得到相同的密文C；或者B组同学接收到A组程序加密的密文C，使用B组程序进行解密可得到与A相同的P。


我们与其他组进行了交叉测试：


二进制加密选择相同的明文P为：01110100  选择相同的密钥K为：1011011001



二进制解密选择相同的密文P为：10000110  选择相同的密钥K为：1011011001




[![image](https://imgur.la/images/2024/10/07/image9117bc41222c38f4.md.png)](https://imgur.la/image/image.fDZ9b)
[![image](https://imgur.la/images/2024/10/07/imagee518d347c881bcbc.md.png)](https://imgur.la/image/image.fDeNN)
[![image](https://imgur.la/images/2024/10/07/image1bef2e6172e92b2c.md.png)](https://imgur.la/image/image.fDRnQ)



经检测，我们组结果与另外一组结果相同，通过交叉检测。







#### 第3关：扩展功能考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为1 Byte)，对应地输出也可以是ACII字符串(很可能是乱码)。
[![image](https://imgur.la/images/2024/10/07/imagee242818ec3eb4275.md.png)](https://imgur.la/image/image.fajnU)
[![image](https://imgur.la/images/2024/10/07/image1c259a7497412633.md.png)](https://imgur.la/image/image.faU5L)


经测试，该程序能够完成功能扩展，实现ASCII编码的加解密。




#### 第4关：暴力破解：检测是否能够实现暴力破解，且设置时间戳，记录暴力破解时间。
[![image](https://imgur.la/images/2024/10/07/imagec65e4bae8c2750af.md.png)](https://imgur.la/image/image.fDzKa)


经测试，该程序能够实现暴力破解

#### 第5关：封闭测试：分析是否存在多个密钥可以生成相同的密文
[![image](https://imgur.la/images/2024/10/07/imaged0e8a5f4ef8946fe.md.png)](https://imgur.la/image/image.fDCip)
[![image](https://imgur.la/images/2024/10/07/image5b2694d5b886f35f.md.png)](https://imgur.la/image/image.fD4A3)


经测试，该程序能够在较短时间内分析是否存在多个密钥可以生成相同的密文。

## 七、总结
本项目成功实现了S-DES加密算法，并提供了一个用户友好的图形用户界面（GUI），使得加密和解密过程更加直观和便捷。通过详细的算法描述和关键代码实现，项目满足了课程的基本要求，还通过多模式加解密、跨平台一致性测试、扩展功能实现、暴力破解和封闭测试等相关测试。
#### 项目待改进
性能优化：进一步优化算法实现，提高加解密的速度。



安全性增强：探索更多的安全性测试方法，增强算法的安全性。



用户界面改进：继续改进用户界面，使其更加现代化和用户友好。


## 八、开发团队
- 小组：风雨无组
- 团队成员： 柴钰林、古渲宇、陈芳莹
- 单位：重庆大学大数据与软件学院
