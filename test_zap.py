#!/usr/bin/env python
import time
import json
from datetime import datetime
from zapv2 import ZAPv2

# The URL of the application to be tested
target = 'http://192.168.1.6:3000'
# Change to match the API key set in ZAP, or use None if the API key is disabled
apiKey = '2vvbrr3j30t0h1nfm24sgc1vnp'

# By default ZAP API client will connect to port 8080

zap = ZAPv2(apikey=apiKey, proxies={
  'http': 'http://192.168.1.5:8080',
  'https': 'http://192.168.1.5:8080'
})

# 1) Spider (static)
print("[*] Spidering...")
zap.spider.scan(target)
while int(zap.spider.status()) < 100:
    print("  spider:", zap.spider.status(), "%")
    time.sleep(1)

# 2) Ajax Spider
print("[*] Ajax spider (if available)...")
try:
    zap.ajaxSpider.scan(target)
    time.sleep(2)
    while zap.ajaxSpider.status == 'running':
        print("  ajax spider running...")
        time.sleep(2)
except Exception:
    print("  ajax spider not available, skipped")

# 3) Bật tất cả scanner và set strength HIGH (cẩn thận với hệ production)
print("[*] Enabling scanners and set HIGH strength...")
for s in zap.ascan.scanners():
    sid = s.get('id')
    try:
        zap.ascan.set_scanner_enabled(sid, 'true')
        zap.ascan.set_scanner_attack_strength(sid, 'HIGH')
    except Exception:
        pass

# 4) Start active scan
print("[*] Starting active scan...")
scan_id = zap.ascan.scan(target, recurse=True)
while int(zap.ascan.status(scan_id)) < 100:
    print("  ascan:", zap.ascan.status(scan_id), "%")
    time.sleep(5)

print("[*] Active scan finished")

# 5) Save HTML report
html = zap.core.htmlreport()
html_file = f"zap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
with open(html_file, "w", encoding="utf-8") as fh:
    fh.write(html)
print("[+] HTML saved:", html_file)

alerts = zap.core.alerts() 
# Quick summary counts
from collections import Counter
cnt = Counter([a.get("risk","UNKNOWN") for a in alerts])
print("Summary:", dict(cnt))