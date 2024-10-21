import tkinter as tk
from tkinter import messagebox
import time
import concurrent.futures

# S-DES常量定义
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_1 = [4, 1, 3, 5, 7, 2, 8, 6]
P10 = [3, 5, 2, 7, 4, 9, 1, 10, 8, 6]  # 注意这里应该是10而不是10
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2]
]
S1 = [
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3]
]

# 置换函数
def permute(block, table):
    return ''.join(block[i - 1] for i in table)

# 左移函数
def left_shift(key, n):
    return key[n:] + key[:n]

# 密钥生成
def generate_keys(key):
    p10_key = permute(key, P10)
    ls1 = left_shift(p10_key[:5], 1) + left_shift(p10_key[5:], 1)
    k1 = permute(ls1, P8)
    ls2 = left_shift(ls1[:5], 2) + left_shift(ls1[5:], 2)
    k2 = permute(ls2, P8)
    return k1, k2

# 轮函数F
def f_k(block, subkey):
    expanded_block = permute(block, EP)
    xor_result = bin(int(expanded_block, 2) ^ int(subkey, 2))[2:].zfill(8)
    s0_input = xor_result[:4]
    s1_input = xor_result[4:]
    s0_row = int(s0_input[0] + s0_input[3], 2)
    s0_col = int(s0_input[1:3], 2)
    s1_row = int(s1_input[0] + s1_input[3], 2)
    s1_col = int(s1_input[1:3], 2)
    s0_output = format(S0[s0_row][s0_col], '02b')
    s1_output = format(S1[s1_row][s1_col], '02b')
    s_output = s0_output + s1_output
    return permute(s_output, P4)

# S-DES加密
def sdes_encrypt(plaintext, key):
    k1, k2 = generate_keys(key)
    ip = permute(plaintext, IP)
    l, r = ip[:4], ip[4:]
    new_r = bin(int(f_k(r, k1), 2) ^ int(l, 2))[2:].zfill(4)
    new_l = r
    new_r2 = bin(int(f_k(new_r, k2), 2) ^ int(new_l, 2))[2:].zfill(4)
    new_l2 = new_r
    ciphertext = permute(new_l2 + new_r2, IP_1)
    return ciphertext

# S-DES解密
def sdes_decrypt(ciphertext, key):
    k1, k2 = generate_keys(key)
    ip = permute(ciphertext, IP)
    l, r = ip[:4], ip[4:]
    new_r = bin(int(f_k(r, k2), 2) ^ int(l, 2))[2:].zfill(4)
    new_l = r
    new_r2 = bin(int(f_k(new_r, k1), 2) ^ int(new_l, 2))[2:].zfill(4)
    new_l2 = new_r
    plaintext = permute(new_l2 + new_r2, IP_1)
    return plaintext

# ASCII字符串到二进制字符串的转换
def ascii_to_binary(ascii_str):
    return ''.join(format(ord(char), '08b') for char in ascii_str)

# 二进制字符串到ASCII字符串的转换
def binary_to_ascii(binary_str):
    return ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))

# 暴力破解单个块
def brute_force_single_block(plaintext, ciphertext, start, end):
    for i in range(start, end):
        key = format(i, '010b')
        if sdes_encrypt(plaintext, key) == ciphertext:
            return key
    return None

# 多线程暴力破解
def brute_force_attack(plaintext, ciphertext, num_threads=4):
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_key = {executor.submit(brute_force_single_block, plaintext, ciphertext, i * 256, (i + 1) * 256): i for i in range(num_threads)}
        for future in concurrent.futures.as_completed(future_to_key):
            result = future.result()
            if result is not None:
                return result
    return None

class SDESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES 加密与解密")

        # 创建标签和输入框
        self.plaintext_label = tk.Label(root, text="明文 (ASCII或8位二进制):")
        self.plaintext_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.plaintext_entry = tk.Entry(root, width=30)
        self.plaintext_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)

        self.key_label = tk.Label(root, text="密钥 (10 bits):")
        self.key_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.key_entry = tk.Entry(root, width=10)
        self.key_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)

        self.ciphertext_label = tk.Label(root, text="密文 (ASCII或8位二进制):")
        self.ciphertext_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.ciphertext_entry = tk.Entry(root, width=30)
        self.ciphertext_entry.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

        # 创建按钮
        self.encrypt_button = tk.Button(root, text="加密", command=self.encrypt, bg="#4CAF50", fg="white")
        self.encrypt_button.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W+tk.E)

        self.decrypt_button = tk.Button(root, text="解密", command=self.decrypt, bg="#f44336", fg="white")
        self.decrypt_button.grid(row=3, column=1, padx=10, pady=5, sticky=tk.W+tk.E)

        self.brute_force_button = tk.Button(root, text="暴力破解", command=self.brute_force, bg="#2196F3", fg="white")
        self.brute_force_button.grid(row=4, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E)

        self.check_multiple_keys_button = tk.Button(root, text="检查多个密钥", command=self.check_multiple_keys, bg="#FF9800", fg="white")
        self.check_multiple_keys_button.grid(row=5, columnspan=2, padx=10, pady=5, sticky=tk.W+tk.E)

        # 创建结果标签
        self.result_label = tk.Label(root, text="", font=("Helvetica", 12))
        self.result_label.grid(row=6, columnspan=2, padx=10, pady=5, sticky=tk.W)

    def encrypt(self):
        plaintext = self.plaintext_entry.get()
        key = self.key_entry.get()
        if len(key) != 10:
            messagebox.showerror("错误", "密钥必须是10位。")
            return

        if all(c in '01' for c in plaintext) and len(plaintext) % 8 == 0:
            # 输入是二进制数字
            encrypted_binary = ''
            for i in range(0, len(plaintext), 8):
                block = plaintext[i:i+8]
                encrypted_block = sdes_encrypt(block, key)
                encrypted_binary += encrypted_block
            self.result_label.config(text=f"密文: {encrypted_binary}")
        else:
            # 输入是ASCII字符串
            binary_plaintext = ascii_to_binary(plaintext)
            if len(binary_plaintext) % 8 != 0:
                messagebox.showerror("错误", "明文长度必须是8位的倍数。")
                return

            encrypted_binary = ''
            for i in range(0, len(binary_plaintext), 8):
                block = binary_plaintext[i:i+8]
                encrypted_block = sdes_encrypt(block, key)
                encrypted_binary += encrypted_block

            encrypted_text = binary_to_ascii(encrypted_binary)
            self.result_label.config(text=f"密文: {encrypted_text}")

    def decrypt(self):
        ciphertext = self.ciphertext_entry.get()
        key = self.key_entry.get()
        if len(key) != 10:
            messagebox.showerror("错误", "密钥必须是10位。")
            return

        if all(c in '01' for c in ciphertext) and len(ciphertext) % 8 == 0:
            # 输入是二进制数字
            decrypted_binary = ''
            for i in range(0, len(ciphertext), 8):
                block = ciphertext[i:i+8]
                decrypted_block = sdes_decrypt(block, key)
                decrypted_binary += decrypted_block
            self.result_label.config(text=f"明文: {decrypted_binary}")
        else:
            # 输入是ASCII字符串
            binary_ciphertext = ascii_to_binary(ciphertext)
            if len(binary_ciphertext) % 8 != 0:
                messagebox.showerror("错误", "密文长度必须是8位的倍数。")
                return

            decrypted_binary = ''
            for i in range(0, len(binary_ciphertext), 8):
                block = binary_ciphertext[i:i+8]
                decrypted_block = sdes_decrypt(block, key)
                decrypted_binary += decrypted_block

            decrypted_text = binary_to_ascii(decrypted_binary)
            self.result_label.config(text=f"明文: {decrypted_text}")

    def brute_force(self):
        plaintext = self.plaintext_entry.get()
        ciphertext = self.ciphertext_entry.get()

        if all(c in '01' for c in plaintext) and len(plaintext) % 8 == 0:
            # 输入是二进制数字
            binary_plaintext = plaintext
            binary_ciphertext = ciphertext
        else:
            # 输入是ASCII字符串
            binary_plaintext = ascii_to_binary(plaintext)
            binary_ciphertext = ascii_to_binary(ciphertext)

        if len(binary_plaintext) % 8 != 0 or len(binary_ciphertext) % 8 != 0:
            messagebox.showerror("错误", "明文和密文长度都必须是8位的倍数。")
            return

        start_time = time.time()
        found_key = brute_force_attack(binary_plaintext, binary_ciphertext)
        elapsed_time = time.time() - start_time

        if found_key:
            self.result_label.config(text=f"找到密钥: {found_key}，耗时: {elapsed_time:.2f}秒")
        else:
            self.result_label.config(text="没有找到匹配的密钥。")

    def check_multiple_keys(self):
        plaintext = self.plaintext_entry.get()
        ciphertext = self.ciphertext_entry.get()

        if all(c in '01' for c in plaintext) and len(plaintext) % 8 == 0:
            # 输入是二进制数字
            binary_plaintext = plaintext
            binary_ciphertext = ciphertext
        else:
            # 输入是ASCII字符串
            binary_plaintext = ascii_to_binary(plaintext)
            binary_ciphertext = ascii_to_binary(ciphertext)

        if len(binary_plaintext) % 8 != 0 or len(binary_ciphertext) % 8 != 0:
            messagebox.showerror("错误", "明文和密文长度都必须是8位的倍数。")
            return

        keys = []
        for i in range(1024):
            key = format(i, '010b')
            if all(sdes_encrypt(binary_plaintext[j:j+8], key) == binary_ciphertext[j:j+8] for j in range(0, len(binary_plaintext), 8)):
                keys.append(key)

        if keys:
            self.result_label.config(text=f"找到多个密钥: {', '.join(keys)}，共{len(keys)}个密钥。")
        else:
            self.result_label.config(text="没有找到匹配的密钥。")

if __name__ == "__main__":
    root = tk.Tk()
    app = SDESApp(root)
    root.mainloop()