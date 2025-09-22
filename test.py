import json

with open("WEB_APPLICATION_PAYLOADS.jsonl", "r", encoding="utf-8") as f:
    text = f.read()

# Loại bỏ BOM hoặc ký tự vô hình (như U+00a0, U+feff)
text = text.replace("\u00a0", "").replace("\ufeff", "")

# Nếu thiếu dấu phẩy trước dấu `]`, thêm vào

data = json.loads(text)
print(len(data))
