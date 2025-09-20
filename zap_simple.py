# zap_simple.py
import time
from zapv2 import ZAPv2

def create_client(apiKey=None, proxy=None):
    if proxy:
        return ZAPv2(apikey=apiKey, proxies={'http': proxy, 'https': proxy})
    return ZAPv2(apikey=apiKey)

def run_ascan_and_watch(zap, target, poll_interval=1):
    """
    Bắt đầu active scan lên `target` và in ra các request mới ZAP gửi.
    Trả về list alerts sau khi quét xong.
    """
    # Đảm bảo target có trong site tree
    print("[*] Accessing target to add to site tree...")
    zap.urlopen(target)
    time.sleep(1)

    print("[*] Running spider to seed site tree...")
    spider_id = zap.spider.scan(target)
    while int(zap.spider.status(spider_id)) < 100:
        print("  spider:", zap.spider.status(spider_id), "%")
        time.sleep(1)
    print("[*] Spider finished.")

    # Start active scan
    scan_id = zap.ascan.scan(target, recurse=True)
    print("[*] Active scan started, scan id:", scan_id)

    if not str(scan_id).isdigit():
        print("[!] Scan failed, got scan_id:", scan_id)
        return []

    last_seen_id = 0
    while True:
        try:
            prog = int(zap.ascan.status(scan_id))
        except Exception:
            prog = 0

        msgs = zap.core.messages(last_seen_id, 1000)
        for m in msgs:
            mid = int(m.get("id", 0))
            if mid <= last_seen_id:
                continue
            url = m.get("url", "")
            if target in url:
                req_hdr = m.get("requestHeader", "")
                first_line = req_hdr.splitlines()[0] if req_hdr else ""
                req_body = m.get("requestBody", "")
                print("----")
                print("ID:", mid)
                print(first_line)
                print("URL:", url)
                if req_body:
                    print("Body:", req_body)
                print("----")
            last_seen_id = max(last_seen_id, mid)

        if prog >= 100:
            print("[*] Active scan finished (100%)")
            break
        time.sleep(poll_interval)

    return zap.core.alerts()
