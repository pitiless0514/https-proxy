# final_server.py
import socket
import threading
import select
import argparse
import os
import getpass
from datetime import datetime, timezone, timedelta
from queue import Queue
import time
import sqlite3
from flask import Flask, jsonify, render_template_string, request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64 as builtin_base64


# 1. 手写 Base64 实现

class ManualBase64:
    _ENCODE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    def __init__(self):
        self._DECODE_MAP = {
            'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7,
            'I': 8, 'J': 9, 'K': 10, 'L': 11, 'M': 12, 'N': 13, 'O': 14, 'P': 15,
            'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21, 'W': 22, 'X': 23,
            'Y': 24, 'Z': 25, 'a': 26, 'b': 27, 'c': 28, 'd': 29, 'e': 30, 'f': 31,
            'g': 32, 'h': 33, 'i': 34, 'j': 35, 'k': 36, 'l': 37, 'm': 38, 'n': 39,
            'o': 40, 'p': 41, 'q': 42, 'r': 43, 's': 44, 't': 45, 'u': 46, 'v': 47,
            'w': 48, 'x': 49, 'y': 50, 'z': 51, '0': 52, '1': 53, '2': 54, '3': 55,
            '4': 56, '5': 57, '6': 58, '7': 59, '8': 60, '9': 61, '+': 62, '/': 63,
        }

    def encode(self, data: bytes) -> str:
        encoded_string = ""
        num_bytes = len(data)
        main_part_len = num_bytes // 3
        for i in range(main_part_len):
            byte1, byte2, byte3 = data[i*3], data[i*3 + 1], data[i*3 + 2]
            chunk1 = byte1 >> 2
            chunk2 = ((byte1 & 0b11) << 4) | (byte2 >> 4)
            chunk3 = ((byte2 & 0b1111) << 2) | (byte3 >> 6)
            chunk4 = byte3 & 0b111111
            encoded_string += (self._ENCODE_CHARS[chunk1] + self._ENCODE_CHARS[chunk2] + self._ENCODE_CHARS[chunk3] + self._ENCODE_CHARS[chunk4])
        remainder = num_bytes % 3
        if remainder == 1:
            last_byte = data[main_part_len*3]
            chunk1 = last_byte >> 2
            chunk2 = (last_byte & 0b11) << 4
            encoded_string += self._ENCODE_CHARS[chunk1] + self._ENCODE_CHARS[chunk2] + "=="
        elif remainder == 2:
            byte1, byte2 = data[main_part_len*3], data[main_part_len*3 + 1]
            chunk1 = byte1 >> 2
            chunk2 = ((byte1 & 0b11) << 4) | (byte2 >> 4)
            chunk3 = (byte2 & 0b1111) << 2
            encoded_string += self._ENCODE_CHARS[chunk1] + self._ENCODE_CHARS[chunk2] + self._ENCODE_CHARS[chunk3] + "="
        return encoded_string

    def decode(self, encoded_str: str) -> bytes:
        decoded_bytes = bytearray()
        padding_count = encoded_str.count('=')
        if padding_count > 0: encoded_str = encoded_str[:-padding_count]
        num_chars = len(encoded_str)
        main_part_len = num_chars // 4
        for i in range(main_part_len):
            val1, val2, val3, val4 = (self._DECODE_MAP[encoded_str[i*4]], self._DECODE_MAP[encoded_str[i*4+1]], self._DECODE_MAP[encoded_str[i*4+2]], self._DECODE_MAP[encoded_str[i*4+3]])
            byte1 = (val1 << 2) | (val2 >> 4)
            byte2 = ((val2 & 0b1111) << 4) | (val3 >> 2)
            byte3 = ((val3 & 0b11) << 6) | val4
            decoded_bytes.extend([byte1, byte2, byte3])
        remainder = num_chars % 4
        if remainder == 2:
            val1, val2 = self._DECODE_MAP[encoded_str[main_part_len*4]], self._DECODE_MAP[encoded_str[main_part_len*4+1]]
            byte1 = (val1 << 2) | (val2 >> 4)
            decoded_bytes.append(byte1)
        elif remainder == 3:
            val1, val2, val3 = (self._DECODE_MAP[encoded_str[main_part_len*4]], self._DECODE_MAP[encoded_str[main_part_len*4+1]], self._DECODE_MAP[encoded_str[main_part_len*4+2]])
            byte1 = (val1 << 2) | (val2 >> 4)
            byte2 = ((val2 & 0b1111) << 4) | (val3 >> 2)
            decoded_bytes.extend([byte1, byte2])
        return bytes(decoded_bytes)

# ==============================================================================
# 2. 密钥派生与加密处理 (与客户端完全一致)
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
        if self.method == 'fernet':
            raw_key = gen_key(self.password, SALT, 32)
            fernet_key = builtin_base64.urlsafe_b64encode(raw_key)
            self.cipher_obj = Fernet(fernet_key)
        elif self.method == 'aes_cbc':
            self.key = gen_key(self.password, SALT, 32); 
            self.block_size = 16
        elif self.method == 'des':
            print("\033[91m[警告] 您正在使用 DES，这是一个不安全的算法，仅供演示！\033[0m")
            self.key = gen_key(self.password, SALT, 8); 
            self.block_size = 8
        elif self.method == 'manual_base64':
            self.cipher_obj = ManualBase64()
            print("[*] 使用手写 Base64 编码（非加密）。")
        elif self.method == 'xor':
            print("\033[91m[警告] 您正在使用 XOR，这是一个不安全的算法，仅供演示！\033[0m")
            self.key = gen_key(self.password, SALT, 128)
        elif self.method == 'caesar':
            print("\033[91m[警告] 您正在使用凯撒密码变种，这是一个不安全的算法，仅供演示！\033[0m")
            self.key = sum(gen_key(self.password, SALT, 8)) % 255 + 1
        else: raise ValueError(f"不支持的方法: {self.method}")

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
        if self.method == 'fernet': return self.cipher_obj.decrypt(data)
        if self.method == 'manual_base64': return self.cipher_obj.decode(data.decode('ascii'))
        if self.method in ['aes_cbc', 'des']:
            iv = data[:self.block_size]
            encrypted_data = data[self.block_size:]
            algo = algorithms.AES(self.key) if self.method == 'aes_cbc' else algorithms.DES(self.key)
            cipher = Cipher(algo, modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(self.block_size * 8).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        if self.method == 'xor':
            key_stream = self.key * (len(data) // len(self.key) + 1)
            return bytes([data[i] ^ key_stream[i] for i in range(len(data))])
        if self.method == 'caesar': return bytes([(b - self.key + 256) % 256 for b in data])

# ==============================================================================
# 3. 后端核心服务
# ==============================================================================
DB_FILE = 'proxy_log.db'
event_queue = Queue()
TIMEZONE = timezone(timedelta(hours=8))
dashboard_app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>代理服务器客户端监控</title>
    <style>
        /* --- CSS 样式表开始 --- */
        /* --- 基础与重置样式 --- */
        :root {
            /* 定义CSS变量，方便统一管理颜色和字体等。*/
            --bg-color: #f5f7fa;        /* 页面主背景色 */
            --card-bg-color: #ffffff;   /* 卡片背景色 */
            --text-color: #333333;      /* 主要文字颜色 */
            --text-color-light: #666666;/* 次要文字颜色 */
            --border-color: #e9ecef;    /* 边框颜色 */
            --primary-color: #007bff;    /* 主题色，如链接和按钮 */
            --font-family: "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
        }

        /* 对body元素进行全局样式设置 */
        body {
            font-family: var(--font-family);
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 25px;
            line-height: 1.5; /* 设置合适的行高，增加可读性 */
        }
        
        /* --- 布局容器 --- */
        .container {
            max-width: 1600px; /* 限制内容最大宽度，使其在大屏幕上不会过宽 */
            margin: 0 auto;    /* 水平居中 */
        }
        
        /* --- 页眉 Header --- */
        .header {
            margin-bottom: 25px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }

        .header h1 {
            margin: 0;
            font-size: 32px;
            font-weight: 600;
            color: #2c3e50; /* 使用更深的颜色以突出标题 */
        }

        /* --- 统计卡片布局 --- */
        .stats-grid {
            display: grid; /* 使用CSS Grid进行网格布局 */
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); /* 响应式网格 */
            gap: 20px;
            margin-bottom: 25px;
        }

        .stat-card {
            background-color: var(--card-bg-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            display: flex;
            align-items: center;
        }

        .stat-card-icon {
            margin-right: 15px;
        }

        .stat-card-icon svg {
            width: 40px;
            height: 40px;
            fill: var(--primary-color);
            opacity: 0.7;
        }

        .stat-card-info h3 {
            margin: 0 0 5px;
            font-size: 15px;
            color: var(--text-color-light);
            font-weight: 500;
        }

        .stat-card-info .value {
            font-size: 28px;
            font-weight: 700;
            color: #2c3e50;
        }
        
        /* --- 主要内容卡片 --- */
        .main-card {
            background-color: var(--card-bg-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
        }

        .main-card h2 {
            margin-top: 0;
            margin-bottom: 20px;
            font-size: 24px;
            color: #2c3e50;
        }
        
        /* --- 控制区域 (搜索框和分页) --- */
        .controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .search-box input {
            border: 1px solid #ced4da;
            padding: 10px 15px;
            border-radius: 5px;
            width: 300px;
            font-size: 16px;
        }

        .pagination button {
            padding: 8px 16px;
            border: 1px solid #ced4da;
            background-color: #fff;
            color: var(--primary-color);
            cursor: pointer;
            border-radius: 5px;
            margin: 0 5px;
        }

        .pagination button:disabled {
            cursor: not-allowed;
            opacity: 0.6;
        }
        
        /* --- 数据表格 --- */
        table {
            width: 100%;
            border-collapse: collapse; /* 边框合并 */
        }

        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        thead th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: var(--text-color-light);
        }
        
        /* --- 页脚 Footer --- */
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            color: #888;
            font-size: 14px;
        }
        /* --- CSS 样式表结束 --- */
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>代理服务器客户端监控</h1>
            </header>
        <section class="stats-grid">
            <article class="stat-card">
                <div class="stat-card-icon">
                    
                    
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14zM11 7h2v2h-2zm0 4h2v6h-2z"/></svg>
                </div>
                <div class="stat-card-info">
                    <h3>总请求数 (数据库)</h3>
                    <div class="value" id="total-requests">-</div>
                </div>
            </article>

            <article class="stat-card">
                <div class="stat-card-icon">
                   
                    
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>
                </div>
                <div class="stat-card-info">
                    <h3>独立客户端IP数</h3>
                    <div class="value" id="unique-ips">-</div>
                </div>
            </article>
            
            <article class="stat-card">
                <div class="stat-card-icon">
                    
                    
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM17 17H6c-2.21 0-4-1.79-4-4s1.79-4 4-4h.71C7.37 6.69 9.49 5 12 5c3.04 0 5.5 2.46 5.5 5.5v.5H19c1.66 0 3 1.34 3 3s-1.34 3-3 3z"/></svg>
                </div>
                <div class="stat-card-info">
                    <h3>总传输流量 (MB)</h3>
                    <div class="value" id="total-traffic">-</div>
                </div>
            </article>

            <article class="stat-card">
                <div class="stat-card-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M16 6l2.29 2.29-4.88 4.88-4-4L2 16.59 3.41 18l6-6 4 4 6.3-6.29L22 12V6z"/></svg>
                </div>
                <div class="stat-card-info">
                    <h3>热门访问 Top 5</h3>
                    <ol id="top-targets" style="text-align:left; font-size:12px; padding-left: 18px; margin: 0;"></ol>
                </div>
            </article>
        </section>
        <section class="main-card">
            <h2>访问日志数据库 (可搜索和分页)</h2>
            
            <div class="controls">
                <div class="search-box">
                    <input type="text" id="search-input" placeholder="搜索 IP 或目标域名，按回车键确认">
                </div>
                <div class="pagination">
                    <button id="prev-btn" onclick="changePage(-1)">上一页</button>
                    <span id="page-info">第 1 / 1 页</span>
                    <button id="next-btn" onclick="changePage(1)">下一页</button>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>客户端 IP</th><th>目标地址</th><th>端口</th>
                        <th>发送 (KB)</th><th>接收 (KB)</th><th>事件时间</th>
                    </tr>
                </thead>
                <tbody id="log-table-body">
                    </tbody>
            </table>
        </section>
        <footer class="footer">
            <p>数据从后端 SQLite 数据库实时查询 | 最后更新于: <span id="last-updated">-</span></p>
        </footer>
        </div>

    <script>
        // --- JavaScript 脚本开始 ---
        let currentPage = 1, totalPages = 1, currentSearch = '';
        async function fetchData() {
            try {
                const apiUrl = `/api/data?page=${currentPage}&search=${encodeURIComponent(currentSearch)}`;
                const response = await fetch(apiUrl);
                if (!response.ok) { 
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();
                updateStats(data.stats);
                updateLogTable(data.logs);
                updatePagination(data.pagination);
            } catch (error) { console.error('获取监控数据失败:', error); }
        }
        function updateStats(stats) {
            document.getElementById('total-requests').innerText = stats.total_requests.toLocaleString();
            document.getElementById('unique-ips').innerText = stats.unique_ips.toLocaleString();
            document.getElementById('total-traffic').innerText = stats.total_traffic_mb;
            const topTargetsEl = document.getElementById('top-targets');
            topTargetsEl.innerHTML = '';
            if (stats.top_targets.length > 0) {
                stats.top_targets.forEach(item => {
                    const li = document.createElement('li');
                    li.innerText = `${item.target_host} (${item.count})`;
                    topTargetsEl.appendChild(li);
                });
            } else { topTargetsEl.innerHTML = '<li>暂无数据</li>'; }
        }
        function updateLogTable(logs) {
            const logTableBody = document.getElementById('log-table-body');
            if (logs.length === 0) {
                logTableBody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:#666;">数据库中无匹配记录</td></tr>';
            } else {
                logTableBody.innerHTML = logs.map(log => `<tr><td>${log.id}</td><td>${log.client_ip}</td><td>${log.target_host}</td><td>${log.target_port}</td><td>${log.bytes_sent_kb}</td><td>${log.bytes_received_kb}</td><td>${log.event_time}</td></tr>`).join('');
            }
        }
        function updatePagination(pagination) {
            currentPage = pagination.current_page;
            totalPages = pagination.total_pages;
            document.getElementById('page-info').innerText = `第 ${currentPage} / ${totalPages} 页`;
            document.getElementById('prev-btn').disabled = (currentPage <= 1);
            document.getElementById('next-btn').disabled = (currentPage >= totalPages);
            document.getElementById('last-updated').innerText = new Date().toLocaleTimeString('zh-CN', { hour12: false });
        }
        function changePage(direction) {
            const newPage = currentPage + direction;
            if (newPage > 0 && newPage <= totalPages) { 
                currentPage = newPage; fetchData(); 
            }
        }
        function applySearch() { 
            currentPage = 1; 
            currentSearch = document.getElementById('search-input').value; 
            fetchData(); 
        }
        document.getElementById('search-input').addEventListener('keyup', e => { if (e.key === 'Enter') { applySearch(); }});
        document.addEventListener('DOMContentLoaded', fetchData);
        setInterval(fetchData, 5000);
    </script>
</body>
</html>
"""

def init_database():
    conn = sqlite3.connect(DB_FILE); 
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS access_log (id INTEGER PRIMARY KEY AUTOINCREMENT, client_ip TEXT NOT NULL, target_host TEXT NOT NULL, target_port INTEGER NOT NULL, bytes_sent INTEGER DEFAULT 0, bytes_received INTEGER DEFAULT 0, event_time TIMESTAMP NOT NULL)"); 
    conn.commit(); 
    conn.close()
    print(f"[+] 数据库 '{DB_FILE}' 初始化或连接成功。")

def database_writer_thread():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False); cursor = conn.cursor()
    while True:
        try:
            log_event = event_queue.get()
            if log_event is None: break
            cursor.execute("INSERT INTO access_log (client_ip, target_host, target_port, bytes_sent, bytes_received, event_time) VALUES (?, ?, ?, ?, ?, ?)", (log_event['client_ip'], log_event['target_host'], log_event['target_port'], log_event['bytes_sent'], log_event['bytes_received'], log_event['event_time'])); 
            conn.commit()
        except Exception as e: print(f"[!] 数据库写入错误: {e}")
    conn.close()

@dashboard_app.route('/')
def index(): 
    return render_template_string(HTML_TEMPLATE)

@dashboard_app.route('/api/data')
def api_data():
    page = request.args.get('page', 1, type=int); 
    search_query = request.args.get('search', '', type=str); 
    limit = 50; 
    offset = (page - 1) * limit
    conn = sqlite3.connect(DB_FILE); 
    conn.row_factory = sqlite3.Row; 
    cursor = conn.cursor()
    where_clause, params = ("", [])
    if search_query: where_clause, params = "WHERE client_ip LIKE ? OR target_host LIKE ?", [f'%{search_query}%', f'%{search_query}%']
    cursor.execute(f"SELECT COUNT(*) FROM access_log {where_clause}", params); 
    total_records = cursor.fetchone()[0]; total_pages = (total_records + limit - 1) // limit or 1
    log_query_params = params + [limit, offset]; cursor.execute(f"SELECT * FROM access_log {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?", log_query_params)
    logs = [{**dict(row), 'bytes_sent_kb': f"{row['bytes_sent']/1024:.2f}", 'bytes_received_kb': f"{row['bytes_received']/1024:.2f}"} for row in cursor.fetchall()]
    cursor.execute("SELECT COUNT(*) FROM access_log"); 
    total_requests = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT client_ip) FROM access_log"); 
    unique_ips = cursor.fetchone()[0]
    cursor.execute("SELECT SUM(bytes_sent) + SUM(bytes_received) FROM access_log"); 
    total_traffic_bytes = cursor.fetchone()[0] or 0
    total_traffic_mb = f"{total_traffic_bytes / (1024*1024):.2f}"
    cursor.execute("SELECT target_host, COUNT(*) as count FROM access_log GROUP BY target_host ORDER BY count DESC LIMIT 5"); 
    top_targets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'logs': logs, 'pagination': {'current_page': page, 'total_pages': total_pages}, 'stats': {'total_requests': total_requests, 'unique_ips': unique_ips, 'total_traffic_mb': total_traffic_mb, 'top_targets': top_targets}})

def start_dashboard_web_server(port):
    print(f"📈 监控面板已启动，请在浏览器中访问 http://[你的服务器IP]:{port}")
    dashboard_app.run(host='0.0.0.0', port=port, debug=False)

def recv_all(sock, length):
    data = b'';
    while len(data) < length:
        more = sock.recv(length - len(data));
        if not more: raise EOFError("Socket closed")
        data += more;
    return data

def forward_data(client_conn, target_conn, crypto_handler):
    bytes_sent, bytes_received = 0, 0
    while True:
        try:
            readable, _, _ = select.select([client_conn, target_conn], [], [], 5)
            if not readable: continue
            for sock in readable:
                if sock is client_conn:
                    msg_len = int.from_bytes(recv_all(client_conn, 4), 'big'); 
                    encrypted_request = recv_all(client_conn, msg_len)
                    bytes_received += 4 + len(encrypted_request)
                    decrypted_request = crypto_handler.decrypt(encrypted_request); 
                    target_conn.sendall(decrypted_request)
                else:
                    data = target_conn.recv(8192)
                    if not data: return bytes_sent, bytes_received
                    bytes_sent += len(data)
                    encrypted_response = crypto_handler.encrypt(data); 
                    client_conn.sendall(len(encrypted_response).to_bytes(4, 'big') + encrypted_response)
        except Exception: return bytes_sent, bytes_received

def parse_destination(request_data):
    try:
        first_line = request_data.split(b'\n')[0]; 
        method, url, _ = first_line.split()
        if method == b'CONNECT': 
            host, port_str = url.split(b':'); 
            port = int(port_str)
        else: 
            host = request_data.split(b'Host: ')[1].split(b'\r\n')[0]; 
            port = 80
        return host.decode(), port, method
    except Exception: return None, None, None

def handle_connection(client_socket, addr, method, password):
    target_socket, bytes_sent, bytes_received, host, port = None, 0, 0, None, None
    try:
        crypto_handler = CryptoHandler(method, password)
        msg_len = int.from_bytes(recv_all(client_socket, 4), 'big')
        first_encrypted_packet = recv_all(client_socket, msg_len)
        request_data = crypto_handler.decrypt(first_encrypted_packet)
        host, port, http_method = parse_destination(request_data)
        if not host: return
        target_socket = socket.create_connection((host, port))
        if http_method == b'CONNECT':
            response_ok = b"HTTP/1.1 200 Connection Established\r\n\r\n"; 
            encrypted_ok = crypto_handler.encrypt(response_ok)
            client_socket.sendall(len(encrypted_ok).to_bytes(4, 'big') + encrypted_ok)
        else: target_socket.sendall(request_data)
        bytes_sent, bytes_received = forward_data(client_socket, target_socket, crypto_handler)
    except Exception as e: print(f"[-] 连接 {addr[0]} 出错: {e}")
    finally:
        if host and port:
            event_queue.put({'client_ip': addr[0], 'target_host': host, 'target_port': port, 'bytes_sent': bytes_sent, 'bytes_received': bytes_received, 'event_time': datetime.now(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')})
        if target_socket: target_socket.close()
        client_socket.close()

def start_proxy_server(listen_host, listen_port, method, password):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM); server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port)); 
    server.listen(50)
    print(f"🛡️  远程代理服务器已启动于 {listen_host}:{listen_port}")
    try:
        while True:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_connection, args=(client, addr, method, password), daemon=True); 
            thread.start()
    finally: 
        server.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="高级远程代理服务器 - 数据库日志与专业监控面板", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p', '--password', type=str, help="用于生成加密密钥的密码。")
    parser.add_argument('-lp', '--listen-port', type=int, default=8888, help="代理服务监听端口 (默认: 8888)")
    parser.add_argument('-lh', '--listen-host', type=str, default='0.0.0.0', help="代理服务监听IP (默认: '0.0.0.0')")
    parser.add_argument('--method', type=str, choices=['fernet', 'aes_cbc', 'des', 'manual_base64', 'xor', 'caesar'], default='fernet', help="""选择处理方法 (必须与客户端一致):
- fernet: (推荐, 默认) 强加密，安全易用。
- aes_cbc: 标准的AES加密模式。
- manual_base64: 手写的Base64编码 (非加密)。
- xor: (不安全!) 简单异或加密，仅供演示。
- des: (不安全!) 已过时的加密标准，仅供演示。
- caesar: (不安全!) 凯撒密码变种，仅供演示。
""")
    parser.add_argument('--dashboard-port', type=int, default=9999, help="监控面板的Web访问端口 (默认: 9999)")
    args = parser.parse_args()
    password_input = args.password or getpass.getpass(f"请输入用于 '{args.method}' 的密码: ")
    if not password_input and args.method not in ['manual_base64']: 
        print("[!] 错误：该方法需要密码。"); exit()
    
    init_database()
    db_writer = threading.Thread(target=database_writer_thread, daemon=True); db_writer.start()
    dashboard_thread = threading.Thread(target=lambda: start_dashboard_web_server(args.dashboard_port), daemon=True); dashboard_thread.start()
    
    try:
        start_proxy_server(args.listen_host, args.listen_port, args.method, password_input)
    except KeyboardInterrupt: 
        print("\n[!] 用户请求关闭服务器...")
    finally:
        event_queue.put(None)
        db_writer.join(timeout=2)
        print("[!] 服务器已完全关闭。")
