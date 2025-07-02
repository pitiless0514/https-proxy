import socket
import threading
import select
import argparse
import os
import getpass

# --- 加密库导入 ---
# 高级加密库
from cryptography.fernet import Fernet
# 底层加密原语库，用于实现 aes_cbc 和 des
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
# 导入 base64 仅用于 Fernet 密钥编码，我们自己的数据传输将使用手写版本
import base64 as builtin_base64


class ManualBase64:
    # Base64 字符集：A-Z, a-z, 0-9, +, /
    _ENCODE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    def __init__(self):
        # 创建一个反向查找表，用于解码
        # e.g., {'A': 0, 'B': 1, ...}
        self._DECODE_MAP = {
            'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7,
            'I': 8, 'J': 9, 'K': 10, 'L': 11, 'M': 12, 'N': 13, 'O': 14, 'P': 15,
            'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21, 'W': 22, 'X': 23,
            'Y': 24, 'Z': 25, 'a': 26, 'b': 27, 'c': 28, 'd': 29, 'e': 30, 'f': 31,
            'g': 32, 'h': 33, 'i': 34, 'j': 35, 'k': 36, 'l': 37, 'm': 38, 'n': 39,
            'o': 40, 'p': 41, 'q': 42, 'r': 43, 's': 44, 't': 45, 'u': 46, 'v': 47,
            'w': 48, 'x': 49, 'y': 50, 'z': 51, '0': 52, '1': 53, '2': 54, '3': 55,
            '4': 56, '5': 57, '6': 58, '7': 59, '8': 60, '9': 61, '+': 62, '/': 63
        }

    def encode(self, data: bytes) -> str:
        """
        将字节数据编码为 Base64 字符串。
        """
        encoded_string = ""
        num_bytes = len(data)
        
        # 计算需要处理的完整3字节块的数量
        main_part_len = num_bytes // 3
        
        # 处理完整的3字节块
        for i in range(main_part_len):
            # 取出3个字节
            byte1 = data[i*3]
            byte2 = data[i*3 + 1]
            byte3 = data[i*3 + 2]
            # 将3个字节（24位）看作一个整体
            # [bbbbbbbb] [bbbbbbbb] [bbbbbbbb]
            #    byte1      byte2      byte3
            # 拆分为4个6位的块
            # [......] [......] [......] [......]
            #  块1     块2       块3      块4
            # 块1: byte1 的前6位
            chunk1 = byte1 >> 2
            # 块2: byte1 的后2位 + byte2 的前4位
            chunk2 = ((byte1 & 0b00000011) << 4) | (byte2 >> 4)
            # 块3: byte2 的后4位 + byte3 的前2位
            chunk3 = ((byte2 & 0b00001111) << 2) | (byte3 >> 6)
            # 块4: byte3 的后6位
            chunk4 = byte3 & 0b00111111
            
            # 使用6位的块作为索引，在字符表中查找对应字符
            encoded_string += (self._ENCODE_CHARS[chunk1] +
                               self._ENCODE_CHARS[chunk2] +
                               self._ENCODE_CHARS[chunk3] +
                               self._ENCODE_CHARS[chunk4])
        
        # 处理末尾不足3字节的剩余部分
        remainder = num_bytes % 3
        if remainder == 1:
            # 只剩1个字节
            last_byte = data[main_part_len*3]
            chunk1 = last_byte >> 2
            chunk2 = (last_byte & 0b00000011) << 4
            encoded_string += self._ENCODE_CHARS[chunk1] + self._ENCODE_CHARS[chunk2] + "=="
        elif remainder == 2:
            # 只剩2个字节
            byte1 = data[main_part_len*3]
            byte2 = data[main_part_len*3 + 1]
            chunk1 = byte1 >> 2
            chunk2 = ((byte1 & 0b00000011) << 4) | (byte2 >> 4)
            chunk3 = (byte2 & 0b00001111) << 2
            encoded_string += self._ENCODE_CHARS[chunk1] + self._ENCODE_CHARS[chunk2] + self._ENCODE_CHARS[chunk3] + "="
            
        return encoded_string

    def decode(self, encoded_str: str) -> bytes:
        """
        将 Base64 字符串解码为原始字节数据。
        """
        decoded_bytes = bytearray()
        
        # 移除填充符，并找到有效数据部分
        padding_count = encoded_str.count('=')
        if padding_count > 0:
            encoded_str = encoded_str[:-padding_count]
        
        num_chars = len(encoded_str)
        main_part_len = num_chars // 4
        
        # 处理完整的4字符块
        for i in range(main_part_len):
            # 取出4个字符，并查表得到它们的6位值
            val1 = self._DECODE_MAP[encoded_str[i*4]]
            val2 = self._DECODE_MAP[encoded_str[i*4 + 1]]
            val3 = self._DECODE_MAP[encoded_str[i*4 + 2]]
            val4 = self._DECODE_MAP[encoded_str[i*4 + 3]]
            # 将4个6位值合并成3个8位字节
            # [vvvvvv] [vvvvvv] [vvvvvv] [vvvvvv]
            #  val1     val2     val3     val4
            # 字节1: val1的6位 + val2的前2位
            byte1 = (val1 << 2) | (val2 >> 4)
            # 字节2: val2的后4位 + val3的前4位
            byte2 = ((val2 & 0b001111) << 4) | (val3 >> 2)
            # 字节3: val3的后2位 + val4的6位
            byte3 = ((val3 & 0b00011) << 6) | val4
            
            decoded_bytes.extend([byte1, byte2, byte3])

        # 处理末尾的剩余字符（考虑了填充）
        remainder = num_chars % 4
        if remainder == 2: # 对应原文剩1字节
            val1 = self._DECODE_MAP[encoded_str[main_part_len*4]]
            val2 = self._DECODE_MAP[encoded_str[main_part_len*4 + 1]]
            byte1 = (val1 << 2) | (val2 >> 4)
            decoded_bytes.append(byte1)
        elif remainder == 3: # 对应原文剩2字节
            val1 = self._DECODE_MAP[encoded_str[main_part_len*4]]
            val2 = self._DECODE_MAP[encoded_str[main_part_len*4 + 1]]
            val3 = self._DECODE_MAP[encoded_str[main_part_len*4 + 2]]
            byte1 = (val1 << 2) | (val2 >> 4)
            byte2 = ((val2 & 0b001111) << 4) | (val3 >> 2)
            decoded_bytes.extend([byte1, byte2])

        return bytes(decoded_bytes)

# ==============================================================================
# --- 密钥派生与加密处理 ---
# ==============================================================================
SALT = b'\x1a\xbf\x8c\x1e\x9a\xfd\x0f\x8d\xfd\x1a\x0f\x0c\x8e\x9d\xfa\xdd'
ITERATIONS = 100_000

def gen_key(password, salt, length):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=ITERATIONS, backend=default_backend())
    return kdf.derive(password.encode('utf-8'))

class CryptoHandler:
    def __init__(self, method, password):
        print(f"[*] 初始化处理器... 使用方法: {method}")
        self.method = method.lower()
        if not password and self.method not in ['manual_base64']:
            raise ValueError(f"方法 {self.method} 需要提供密码")
        self.password = password
        
        # 为各种方法初始化特定参数
        if self.method == 'fernet':
            raw_key = gen_key(self.password, SALT, 32)
            fernet_key = builtin_base64.urlsafe_b64encode(raw_key)
            self.cipher_obj = Fernet(fernet_key)
        elif self.method == 'aes_cbc':
            self.key = gen_key(self.password, SALT, 32) # AES-256
            self.block_size = 16
        elif self.method == 'des':
            print("\033[91m[警告] 您正在使用 DES，这是一个不安全的算法，仅供演示！\033[0m")
            self.key = gen_key(self.password, SALT, 8)
            self.block_size = 8
        elif self.method == 'manual_base64':
            self.cipher_obj = ManualBase64()
            print("[*] 使用手写 Base64 编码（非加密）。")
        elif self.method == 'xor':
            print("\033[91m[警告] 您正在使用 XOR，这是一个不安全的算法，仅供演示！\033[0m")
            self.key = gen_key(self.password, SALT, 128) # 生成一个长密钥流
        elif self.method == 'caesar':
            print("\033[91m[警告] 您正在使用凯撒密码变种，这是一个不安全的算法，仅供演示！\033[0m")
            # 使用密码生成一个0-255的位移量
            self.key = sum(gen_key(self.password, SALT, 8)) % 255 + 1
        else:
            raise ValueError(f"不支持的方法: {self.method}")

    def encrypt(self, data: bytes) -> bytes:
        if self.method == 'fernet':
            return self.cipher_obj.encrypt(data)
        if self.method == 'manual_base64':
            return self.cipher_obj.encode(data).encode('ascii')
        
        if self.method in ['aes_cbc', 'des']:
            iv = os.urandom(self.block_size)
            padder = padding.PKCS7(self.block_size * 8).padder()
            padded_data = padder.update(data) + padder.finalize()
            algo = algorithms.AES(self.key) if self.method == 'aes_cbc' else algorithms.DES(self.key)
            cipher = Cipher(algo, modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            return iv + (encryptor.update(padded_data) + encryptor.finalize())

        if self.method == 'xor':
            key_stream = self.key * (len(data) // len(self.key) + 1)
            return bytes([data[i] ^ key_stream[i] for i in range(len(data))])
        
        if self.method == 'caesar':
            return bytes([(b + self.key) % 256 for b in data])

    def decrypt(self, data: bytes) -> bytes:
        if self.method == 'fernet':
            return self.cipher_obj.decrypt(data)
        if self.method == 'manual_base64':
            return self.cipher_obj.decode(data.decode('ascii'))
            
        if self.method in ['aes_cbc', 'des']:
            iv = data[:self.block_size]
            encrypted_data = data[self.block_size:]
            algo = algorithms.AES(self.key) if self.method == 'aes_cbc' else algorithms.DES(self.key)
            cipher = Cipher(algo, modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(self.block_size * 8).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()

        if self.method == 'xor': # XOR解密与加密是相同操作
            key_stream = self.key * (len(data) // len(self.key) + 1)
            return bytes([data[i] ^ key_stream[i] for i in range(len(data))])

        if self.method == 'caesar':
            return bytes([(b - self.key + 256) % 256 for b in data])

# ==============================================================================
# --- 网络核心逻辑 (保持不变) ---
# ==============================================================================

def recv_all(sock, length):
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more: raise EOFError("Socket closed")
        data += more
    return data

def forward_data(browser_socket, remote_socket, crypto_handler):
    while True:
        try:
            readable, _, _ = select.select([browser_socket, remote_socket], [], [])
            for sock in readable:
                if sock is browser_socket:
                    data = browser_socket.recv(8192)
                    if not data: 
                        return
                    processed_data = crypto_handler.encrypt(data)
                    remote_socket.sendall(len(processed_data).to_bytes(4, 'big') + processed_data)
                else:
                    msg_len = int.from_bytes(recv_all(remote_socket, 4), 'big')
                    processed_data = recv_all(remote_socket, msg_len)
                    original_data = crypto_handler.decrypt(processed_data)
                    browser_socket.sendall(original_data)
        except Exception as e:
            print(f"[-] 数据转发中出错: {e}")
            return

def handle_browser(browser_socket, remote_host, remote_port, method, password):
    try:
        with socket.create_connection((remote_host, remote_port)) as remote_socket:
            print(f"[+] 已连接到服务器: {remote_host}:{remote_port}")
            crypto_handler = CryptoHandler(method, password)
            forward_data(browser_socket, remote_socket, crypto_handler)
    except Exception as e:
        print(f"[-] 处理连接时出错: {e}")
    finally:
        browser_socket.close()

def start_local_server(local_port, remote_host, remote_port, method, password):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', local_port))
    server.listen(20)
    print("=" * 60)
    print("🚀 本地代理客户端已启动")
    print(f"  本地监听:    127.0.0.1:{local_port}")
    print(f"  远程服务器:  {remote_host}:{remote_port}")
    print(f"  加密模式:    {method.upper()}")
    print("=" * 60)
    print("\n  请将您的浏览器的 HTTP/HTTPS 代理设置为此地址。")

    while True:
        try:
            browser_socket, addr = server.accept()
            print(f"\n[*] 接受来自 {addr} 的连接")
            thread = threading.Thread(target=handle_browser, args=(browser_socket, remote_host, remote_port, method, password))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            print("\n[!] 用户请求关闭。")
            break
    server.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="本地代理客户端 - 扩展多种“加密”算法", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-rh', '--remote-host', type=str, required=True, help="[必需] 远程服务器公网IP。")
    parser.add_argument('-p', '--password', type=str, help="用于生成加密密钥的密码。")
    parser.add_argument('-rp', '--remote-port', type=int, default=8888, help="远程服务器端口 (默认: 8888)")
    parser.add_argument('-lp', '--local-port', type=int, default=1080, help="本地监听端口 (默认: 1080)")
    parser.add_argument('--method', type=str, 
                        choices=['fernet', 'aes_cbc', 'des', 'manual_base64', 'xor', 'caesar'], 
                        default='fernet', 
                        help="""选择处理方法:
- fernet: (推荐, 默认) 强加密，安全易用。
- aes_cbc: 标准的AES加密模式。
- manual_base64: 手写的Base64编码 (非加密)。
- xor: (不安全!) 简单异或加密，仅供演示。
- des: (不安全!) 已过时的加密标准，仅供演示。
- caesar: (不安全!) 凯撒密码变种，仅供演示。
""")
    args = parser.parse_args()
    
    password_input = args.password
    if not password_input and args.method not in ['manual_base64']:
        try:
            password_input = getpass.getpass(f"请输入用于 '{args.method}' 的密码: ")
        except (EOFError, KeyboardInterrupt):
            print("\n操作取消。"); exit()
    if not password_input and args.method not in ['manual_base64']:
        print("[!] 错误：该方法需要密码。"); exit()

    start_local_server(args.local_port, args.remote_host, args.remote_port, args.method, password_input)