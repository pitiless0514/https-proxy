import requests
import time

TARGET_URLS = [
    'https://www.google.com',
    'https://www.github.com',
    'https://www.python.org',
    'https://api.github.com',  # 一个API接口，测试非HTML内容
    'https://httpbin.org/ip'   # 一个会返回你出口IP的网站
]

LOCAL_PROXY_ADDRESS = 'http://127.0.0.1:1080'
# 设置代理
PROXIES = {
    'http': LOCAL_PROXY_ADDRESS,
    'https': LOCAL_PROXY_ADDRESS,
}

def run_access_test(url, use_proxy):
    """
    执行一次访问测试，记录状态和耗时。
    :param url: 要访问的目标URL
    :param use_proxy: 布尔值，True表示使用代理，False表示直连
    """
    test_type = "代理 (Proxy)" if use_proxy else "直连 (Direct)"
    print(f"\n--- 正在测试: {url} ({test_type}) ---")
    start_time = time.time()
    status = "失败 (Failed)"
    elapsed_time = "N/A"
    content_preview = "N/A"
    try:
        if use_proxy:
            response = requests.get(url, proxies=PROXIES, timeout=20)
        else:
            response = requests.get(url, timeout=10)        
        end_time = time.time()
        elapsed_time = f"{end_time - start_time:.2f} 秒"
        if response.status_code == 200:
            status = "成功 (Success)"
            # 对于 /ip 接口，我们记录返回的IP地址
            if 'httpbin.org/ip' in url:
                content_preview = f"出口IP: {response.json().get('origin', '未知')}"
            else:
                content_preview = f"内容预览 (前50字节): {response.text[:50].replace(chr(10), '')}..."
        else:
            status = f"失败 (HTTP {response.status_code})"
    except requests.exceptions.RequestException as e:
        end_time = time.time()
        elapsed_time = f"{end_time - start_time:.2f} 秒 (超时或错误)"
        status = "失败 (Connection Error)"
        content_preview = str(e)
    print(f"状态: {status}")
    print(f"耗时: {elapsed_time}")
    print(f"备注: {content_preview}")
    return {
        "url": url,
        "method": test_type,
        "status": status,
        "time": elapsed_time,
        "notes": content_preview
    }

if __name__ == "__main__":
    results = []
    print("="*60)
    print("开始进行网络访问对比测试...")
    print("="*60)
    for url in TARGET_URLS:
        results.append(run_access_test(url, use_proxy=False))
        results.append(run_access_test(url, use_proxy=True))
    print("\n\n" + "="*60)
    print("测试结果汇总")
    print("="*60)
    print(f"{'网站':<30} | {'访问方式':<12} | {'状态':<25} | {'耗时':<15} | {'备注'}")
    print("-"*100)
    for res in results:
        print(f"{res['url']:<30} | {res['method']:<12} | {res['status']:<25} | {res['time']:<15} | {res['notes']}")
