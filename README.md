# S-DES
S-DES algorithm's simple implementation.
## 项目简介
本项目是根据“信息安全导论”课程要求，使用Python语言实现的S-DES加密算法。支持加密和解密功能，并提供图形用户界面（GUI）以支持用户交互。

## 开发团队

- 团队成员A
- 团队成员B

## 功能特点

1. **基本测试**：支持8-bit数据和10-bit密钥的加密和解密。
2. **交叉测试**：确保算法在不同系统或平台上的一致性。
3. **扩展功能**：支持ASCII编码字符串的加密和解密。
4. **暴力破解**：实现多线程暴力破解，尝试找到正确的密钥。
5. **封闭测试**：分析是否存在多个密钥可以生成相同的密文。

## 运行环境

- Python 3.x
- PyQt5（用于GUI）

## 安装指南

1. 克隆项目到本地：

```bash
git clone https://github.com/yourusername/S-DES-Project.git
cd S-DES-Project
安装依赖：
bash
pip install PyQt5
运行程序：
bash
python main.py
使用说明
加密：输入8-bit数据和10-bit密钥，点击加密按钮。
解密：输入8-bit密文和10-bit密钥，点击解密按钮。
测试结果
第1关：基本测试通过。
第2关：交叉测试通过，与另一组同学的程序结果一致。
第3关：扩展功能测试通过，支持ASCII字符串加密解密。
第4关：暴力破解测试通过，成功找到密钥。
第5关：封闭测试通过，分析了密钥和密文的关系
