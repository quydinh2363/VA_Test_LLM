# debug_messages.py
import time, pprint
from zapv2 import ZAPv2

apiKey = "2vvbrr3j30t0h1nfm24sgc1vnp"
proxy = "http://192.168.1.5:8080"
target = "http://192.168.1.6:3000"

zap = ZAPv2(apikey=apiKey, proxies={"http": proxy, "https": proxy})

print("[*] Open URL...")
zap.urlopen(target)
time.sleep(1)

sites = zap.core.sites
print("[*] Sites:", sites)

n = int(zap.core.number_of_messages())
print("[*] Number of messages:", n)

# Try to fetch more to be safe
limit = min(max(10, n), 1000)
msgs = zap.core.messages(0, limit)

print("[*] msgs raw repr (type, len):", type(msgs), len(msgs))
pprint.pprint(msgs)          # dump full structure

# If msgs is a list of dicts, show keys for each item
if isinstance(msgs, (list, tuple)):
    for i, m in enumerate(msgs):
        print(f"--- message index {i} (type {type(m)}) ---")
        if isinstance(m, dict):
            print("keys:", list(m.keys()))
            # print a short preview
            print("id:", m.get("id"))
            print("url:", m.get("url"))
            hdr = m.get("requestHeader")
            if hdr:
                print("first line:", hdr.splitlines()[0])
            body = m.get("requestBody") or ""
            print("body present:", bool(body.strip()))
        else:
            # sometimes API returns JSON string per item
            print("item repr:", repr(m)[:300])
