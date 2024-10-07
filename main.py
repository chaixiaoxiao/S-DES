import tkinter as tk
from tkinter import messagebox
import logging
import tkinter as tk
from tkinter import messagebox
import logging
import time
import base64
# 配置日志记录
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


# 按照指定的置换表重新排列输入的位
def permute(bits, perm):
    logging.debug(f"Permuting bits {bits} using permutation table {perm}")
    return [bits[i - 1] for i in perm]


# 循环左移操作
def left_shift(bits, shifts):
    logging.debug(f"Left shifting bits {bits} by {shifts} positions")
    return bits[shifts:] + bits[:shifts]


# 根据输入的10位密钥生成密钥K1和K2
def generate_keys(key):
    logging.debug(f"Generating keys from base key {key}")
    # 初始P10置换
    key = permute(key, [3, 5, 2, 7, 4, 10, 1, 9, 6, 8])
    # 分组并左移1位
    left_half = left_shift(key[:5], 1)
    right_half = left_shift(key[5:], 1)
    # K1通过P8置换生成
    K1 = permute(left_half + right_half, [6, 3, 7, 4, 8, 5, 10, 9])
    # 左移2位生成K2
    left_half = left_shift(left_half, 2)
    right_half = left_shift(right_half, 2)
    K2 = permute(left_half + right_half, [6, 3, 7, 4, 8, 5, 10, 9])
    logging.debug(f"Generated keys K1: {K1}, K2: {K2}")
    return K1, K2


# S盒操作（替换部分数据）
def sbox(input_bits, sbox_table):
    logging.debug(f"Processing sbox for input_bits {input_bits}")
    row = (input_bits[0] << 1) + input_bits[3]
    col = (input_bits[1] << 1) + input_bits[2]
    output = sbox_table[row][col]
    logging.debug(f"S-box output: {output}")
    return [(output >> 1) & 1, output & 1]


# 加密函数，对右半部分执行扩展置换、S盒替换，并结合子密钥生成新数据
def f(right, subkey):
    logging.debug(f"Computing function f with right {right} and subkey {subkey}")
    # 扩展置换表 EP
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]
    # S盒S0和S1
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
    S1 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]
    # 右边的R通过扩展置换EP后，与子密钥进行异或
    expanded_right = permute(right, EP)
    xor_result = [expanded_right[i] ^ subkey[i] for i in range(8)]
    # 将异或结果分为左右部分，进入S盒
    left_sbox = sbox(xor_result[:4], S0)
    right_sbox = sbox(xor_result[4:], S1)
    # S盒结果通过P4置换
    result = permute(left_sbox + right_sbox, P4)
    logging.debug(f"Result after f function: {result}")
    return result


# 使用子密钥对输入的左半部分进行XOR操作，并将结果与右半部分组合
def fk(bits, subkey):
    logging.debug(f"Performing fk function with bits {bits} and subkey {subkey}")
    # 将bits分为左右两部分
    left, right = bits[:4], bits[4:]
    # 右边部分通过f函数处理，并与左边部分进行异或
    result = [left[i] ^ f(right, subkey)[i] for i in range(4)]
    return result + right


#  执行S-DES加密操作，包括两轮fk操作和初始置换、逆置换
def encrypt(plaintext, key):
    logging.info(f"Starting encryption with plaintext {plaintext} and key {key}")
    # 初始置换IP表
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    # 生成K1和K2
    K1, K2 = generate_keys(key)
    # 初始置换
    bits = permute(plaintext, IP)
    # 第一轮加密
    bits = fk(bits, K1)
    # 左右交换
    bits = bits[4:] + bits[:4]
    # 第二轮加密
    bits = fk(bits, K2)
    # 逆置换
    ciphertext = permute(bits, IP_inv)
    logging.info(f"Encryption result: {ciphertext}")
    return ciphertext


# 解密过程
def decrypt(ciphertext, key):
    logging.info(f"Starting decryption with ciphertext {ciphertext} and key {key}")
    # 初始置换IP表
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    # 生成K1和K2
    K1, K2 = generate_keys(key)
    # 初始置换
    bits = permute(ciphertext, IP)
    # 第一轮解密使用K2
    bits = fk(bits, K2)
    # 左右交换
    bits = bits[4:] + bits[:4]
    # 第二轮解密使用K1
    bits = fk(bits, K1)
    # 逆置换
    plaintext = permute(bits, IP_inv)
    logging.info(f"Decryption result: {plaintext}")
    return plaintext


# 字符与ASCII转换的工具函数
def str_to_bin_list(text, length):
    logging.debug(f"Converting string to binary list: {text}")
    return [int(bit) for bit in text.zfill(length)]


def bin_list_to_str(bin_list):
    logging.debug(f"Converting binary list to string: {bin_list}")
    return ''.join(str(bit) for bit in bin_list)


def ascii_to_bin(text):
    logging.debug(f"Converting ASCII text to binary: {text}")
    return ''.join(format(ord(c), '08b') for c in text)


def bin_to_ascii(bin_str):
    logging.debug(f"Converting binary string to ASCII text: {bin_str}")
    chars = [chr(int(bin_str[i:i + 8], 2)) for i in range(0, len(bin_str), 8)]
    return ''.join(chars)


# ASCII加密
def encrypt_ascii(plaintext, key):
    binary_plaintext = ascii_to_bin(plaintext)
    if len(binary_plaintext) % 8 != 0:
        binary_plaintext = binary_plaintext.zfill((len(binary_plaintext) // 8 + 1) * 8)
    result = []
    for i in range(0, len(binary_plaintext), 8):
        plaintext_bits = str_to_bin_list(binary_plaintext[i:i + 8], 8)
        result.extend(encrypt(plaintext_bits, key))
    binary_result = bin_list_to_str(result)
    return bin_to_ascii(binary_result)


# ASCII解密
def decrypt_ascii(ciphertext, key):
    binary_ciphertext = ascii_to_bin(ciphertext)
    result = []
    for i in range(0, len(binary_ciphertext), 8):
        ciphertext_bits = str_to_bin_list(binary_ciphertext[i:i + 8], 8)
        result.extend(decrypt(ciphertext_bits, key))

    binary_result = bin_list_to_str(result)
    return bin_to_ascii(binary_result)


# GUI部分
window = tk.Tk()
window.title("S-DES 加解密系统")
window.configure(bg='lavender')
window.geometry("600x400")
title_style = ("Helvetica", 16, "bold")
label_style = ("Helvetica", 12)
button_style = ("Helvetica", 12, "bold")
result_style = ("Helvetica", 12, "italic")
frame = tk.Frame(window, bg='lavender')
frame.pack(expand=True)

# 添加状态栏
status_bar = tk.Label(window, text="欢迎使用S-DES加解密系统", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg='lightblue')
status_bar.pack(side=tk.BOTTOM, fill=tk.X)


def main_menu():
    status_bar.config(text="请选择一个操作")
    for widget in frame.winfo_children():
        widget.destroy()

    tk.Label(frame, text="请选择一个操作：", font=title_style, bg='lavender').pack(pady=20)

    tk.Button(frame, text="二进制模式", width=20, font=button_style, command=binary_mode).pack(pady=10)
    tk.Button(frame, text="ASCII 模式", width=20, font=button_style, command=ascii_mode).pack(pady=10)
    tk.Button(frame, text="暴力破解", width=20, font=button_style, command=attempt_brute_force).pack(pady=10)
    tk.Button(frame, text="封闭测试", width=20, font=button_style, command=find_keys).pack(pady=10)


# 第一关：基本测试
def binary_mode():
    status_bar.config(text="进入二进制模式")
    for widget in frame.winfo_children():
        widget.destroy()

    result_textbox = tk.Text(frame, height=4, width=50, font=label_style, wrap='word')
    result_textbox.grid(row=3, column=0, columnspan=2, pady=10, padx=10)

    tk.Label(frame, text="输入 8-bit 二进制：", font=label_style, bg='lavender').grid(row=0, column=0, pady=10)
    binary_input = tk.Entry(frame, font=label_style)
    binary_input.grid(row=0, column=1, padx=10)

    tk.Label(frame, text="输入 10-bit 密钥：", font=label_style, bg='lavender').grid(row=1, column=0, pady=10)
    key_input = tk.Entry(frame, font=label_style)
    key_input.grid(row=1, column=1, padx=10)

    def binary_encrypt():
        binary_text = binary_input.get()
        secret_key = key_input.get()

        if len(binary_text) != 8 or not all(bit in '01' for bit in binary_text):
            messagebox.showerror("错误", "请输入8位二进制明文！")
            return
        if len(secret_key) != 10 or not all(bit in '01' for bit in secret_key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        binary_plaintext = str_to_bin_list(binary_text, 8)
        binary_key = str_to_bin_list(secret_key, 10)

        result = encrypt(binary_plaintext, binary_key)
        result_textbox.delete(1.0, tk.END)  # 清空文本框
        result_textbox.insert(tk.END, "加密结果: " + bin_list_to_str(result))
        status_bar.config(text="二进制加密完成")

    def binary_decrypt():
        binary_text = binary_input.get()
        secret_key = key_input.get()

        if len(binary_text) != 8 or not all(bit in '01' for bit in binary_text):
            messagebox.showerror("错误", "请输入8位二进制密文！")
            return
        if len(secret_key) != 10 or not all(bit in '01' for bit in secret_key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        binary_ciphertext = str_to_bin_list(binary_text, 8)
        binary_key = str_to_bin_list(secret_key, 10)

        result = decrypt(binary_ciphertext, binary_key)
        result_textbox.delete(1.0, tk.END)  # 清空文本框
        result_textbox.insert(tk.END, "解密结果: " + bin_list_to_str(result))
        status_bar.config(text="二进制解密完成")

    control_panel = tk.Frame(frame, bg='lavender')
    control_panel.grid(row=2, columnspan=2, pady=10)

    tk.Button(control_panel, text="加密", font=button_style, command=binary_encrypt, width=20).pack(pady=5)
    tk.Button(control_panel, text="解密", font=button_style, command=binary_decrypt, width=20).pack(pady=5)
    tk.Button(control_panel, text="返回", font=button_style, command=main_menu, width=20).pack(pady=5)


# 第三关：扩展功能
def ascii_mode():
    status_bar.config(text="进入ASCII模式")
    for widget in frame.winfo_children():
        widget.destroy()

    tk.Label(frame, text="输入 ASCII 文本：", font=label_style, bg='lavender').grid(row=0, column=0, pady=10)
    ascii_input = tk.Entry(frame, font=label_style)
    ascii_input.grid(row=0, column=1, padx=10)

    tk.Label(frame, text="输入 10-bit 密钥：", font=label_style, bg='lavender').grid(row=1, column=0, pady=10)
    key_input = tk.Entry(frame, font=label_style)
    key_input.grid(row=1, column=1, padx=10)

    output_text = tk.Text(frame, height=4, width=50, font=label_style, wrap='word')
    output_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def ascii_encrypt():
        plain_text = ascii_input.get()
        secret_key = key_input.get()

        if len(secret_key) != 10 or not all(bit in '01' for bit in secret_key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        binary_key = str_to_bin_list(secret_key, 10)
        result = encrypt_ascii(plain_text, binary_key)

        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, result)
        status_bar.config(text="ASCII加密完成")

    def ascii_decrypt():
        cipher_text = ascii_input.get()
        secret_key = key_input.get()

        if len(secret_key) != 10 or not all(bit in '01' for bit in secret_key):
            messagebox.showerror("错误", "请输入10位二进制密钥！")
            return

        binary_key = str_to_bin_list(secret_key, 10)
        result = decrypt_ascii(cipher_text, binary_key)

        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, result)
        status_bar.config(text="ASCII解密完成")

    control_panel = tk.Frame(frame, bg='lavender')
    control_panel.grid(row=2, columnspan=2, pady=10)

    tk.Button(control_panel, text="加密", font=button_style, command=ascii_encrypt, width=20).pack(pady=5)
    tk.Button(control_panel, text="解密", font=button_style, command=ascii_decrypt, width=20).pack(pady=5)
    tk.Button(control_panel, text="返回", font=button_style, command=main_menu, width=20).pack(pady=5)


# 第四关：暴力破解
def attempt_brute_force():
    status_bar.config(text="启动暴力破解")
    for widget in frame.winfo_children():
        widget.destroy()

    tk.Label(frame, text="输入明文：", font=label_style, bg='lavender').grid(row=0, column=0, pady=10)
    plaintext_input = tk.Entry(frame, font=label_style)
    plaintext_input.grid(row=0, column=1, padx=10)

    tk.Label(frame, text="输入密文 (Base64)：", font=label_style, bg='lavender').grid(row=1, column=0, pady=10)
    ciphertext_input = tk.Entry(frame, font=label_style)
    ciphertext_input.grid(row=1, column=1, padx=10)

    result_textbox = tk.Text(frame, height=4, width=50, font=label_style, wrap='word')
    result_textbox.grid(row=3, column=0, columnspan=2, pady=10, padx=10)

    def determine_key():
        plain_text = plaintext_input.get()
        encoded_cipher = ciphertext_input.get()

        plaintext_bits = str_to_bin_list(ascii_to_bin(plain_text), len(plain_text) * 8)

        try:
            cipher_bits = base64_to_bin(encoded_cipher)
        except (ValueError, TypeError):
            messagebox.showerror("错误", "无效的Base64编码密文。")
            return

        if len(plaintext_bits) // 8 != len(cipher_bits) // 8:
            messagebox.showerror("错误", "明文和密文的块数不一致。")
            return

        start_time = time.time()

        for potential_key in range(0, 1024):
            key_str = bin(potential_key)[2:].zfill(10)
            key_bin = [int(bit) for bit in key_str]

            encrypted_accumulated = []
            for i in range(0, len(plaintext_bits), 8):
                block = plaintext_bits[i:i + 8]
                if len(block) < 8:
                    block += [0] * (8 - len(block))
                encrypted_block = encrypt(block, key_bin)
                encrypted_accumulated.extend(encrypted_block)

            if encrypted_accumulated == cipher_bits[:len(encrypted_accumulated)]:
                end_time1 = time.time()
                run_time1 = end_time1 - start_time
                result_textbox.delete(1.0, tk.END)
                result_textbox.insert(tk.END, f"密钥已找到: {key_str}\n耗时: {run_time1:.2f}秒")
                status_bar.config(text="暴力破解成功")
                return
            else:
                end_time2 = time.time()
                run_time2 = end_time2 - start_time
                result_textbox.delete(1.0, tk.END)
                result_textbox.insert(tk.END, f"未找到密钥，耗时: {run_time2:.2f}秒")
                status_bar.config(text="暴力破解失败")

    control_panel = tk.Frame(frame, bg='lavender')
    control_panel.grid(row=2, columnspan=2, pady=10)

    tk.Button(control_panel, text="尝试破解", font=button_style, command=determine_key, width=20).pack(pady=5)
    tk.Button(control_panel, text="返回", font=button_style, command=main_menu, width=20).pack(pady=5)


#  第五关：封闭测试
def find_keys():
    status_bar.config(text="启动密钥搜索")
    for widget in frame.winfo_children():
        widget.destroy()

    tk.Label(frame, text="输入明文：", font=label_style, bg='lavender').grid(row=0, column=0, pady=10)
    plaintext_input = tk.Entry(frame, font=label_style)
    plaintext_input.grid(row=0, column=1, padx=10)

    tk.Label(frame, text="输入密文 (Base64)：", font=label_style, bg='lavender').grid(row=1, column=0, pady=10)
    ciphertext_input = tk.Entry(frame, font=label_style)
    ciphertext_input.grid(row=1, column=1, padx=10)

    result_textbox = tk.Text(frame, height=4, width=50, font=label_style, wrap='word')
    result_textbox.grid(row=3, column=0, columnspan=2, pady=10, padx=10)

    def explore_keys():
        plain_text = plaintext_input.get()
        encoded_cipher = ciphertext_input.get()

        binary_plaintext = ascii_to_bin(plain_text)
        plaintext_bits = str_to_bin_list(binary_plaintext, 8 * len(plain_text))

        try:
            cipher_bits = base64_to_bin(encoded_cipher)
        except (ValueError, TypeError):
            messagebox.showerror("错误", "无效的Base64编码密文。")
            return

        if len(plaintext_bits) // 8 != len(cipher_bits) // 8:
            messagebox.showerror("错误", "明文和密文的块数不一致。")
            return

        found_key_list = []

        for potential_key in range(0, 1024):
            key_str = bin(potential_key)[2:].zfill(10)
            key_bin = [int(bit) for bit in key_str]

            encrypted_accumulated = []
            for i in range(0, len(plaintext_bits), 8):
                block = plaintext_bits[i:i + 8]
                if len(block) < 8:
                    block += [0] * (8 - len(block))
                encrypted_block = encrypt(block, key_bin)
                encrypted_accumulated.extend(encrypted_block)

            if encrypted_accumulated == cipher_bits[:len(encrypted_accumulated)]:
                found_key_list.append(key_str)

        if found_key_list:
            result_textbox.delete(1.0, tk.END)
            result_textbox.insert(tk.END, "找到的密钥: " + '、 '.join(found_key_list))
        else:
            result_textbox.delete(1.0, tk.END)
            result_textbox.insert(tk.END, "未能找到匹配的密钥。")

        status_bar.config(text="密钥搜索完成")

    control_panel = tk.Frame(frame, bg='lavender')
    control_panel.grid(row=2, columnspan=2, pady=10)

    tk.Button(control_panel, text="列出所有密钥", font=button_style, command=explore_keys, width=20).pack(pady=5)
    tk.Button(control_panel, text="返回", font=button_style, command=main_menu, width=20).pack(pady=5)


def base64_to_bin(encoded_str):
    logging.debug(f"Converting Base64 string to binary: {encoded_str}")
    decoded_bytes = base64.b64decode(encoded_str)
    return [int(bit) for byte in decoded_bytes for bit in format(byte, "08b")]


main_menu()
window.mainloop()
