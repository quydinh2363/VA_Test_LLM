# Hướng dẫn sử dụng Security Testing Assistant

## Tổng quan

Security Testing Assistant là một trợ lý AI hỗ trợ kiểm thử bảo mật ứng dụng web. Hệ thống có thể:

- Giải thích các lỗ hổng bảo mật (OWASP Top 10)
- Tạo payload cho các loại tấn công khác nhau
- Chạy quét tự động với OWASP ZAP
- Phân tích kết quả và đưa khuyến nghị

## Giao diện chính

### 1. Chat Interface

Giao diện chat cho phép bạn tương tác với trợ lý bằng ngôn ngữ tự nhiên:

```
Bạn: "Giải thích về XSS"
Assistant: "📚 Cross-Site Scripting (XSS) là lỗ hổng cho phép attacker chèn mã JavaScript..."
```

### 2. Quick Tools

Các công cụ nhanh ở sidebar bên phải:
- **Payload Generator**: Tạo payload cho các loại lỗ hổng
- **ZAP Scan**: Chạy quét bảo mật tự động

## Các tính năng chính

### 1. Giải thích lỗ hổng

**Cách sử dụng:**
- Nhập câu hỏi về lỗ hổng bảo mật
- Ví dụ: "XSS là gì?", "Giải thích SQL Injection"

**Ví dụ:**
```
Bạn: "Giải thích về SQL Injection"
Assistant: "📚 SQL Injection là lỗ hổng cho phép attacker thực thi câu lệnh SQL tùy ý..."
```

### 2. Tạo Payload

**Cách sử dụng:**
- Sử dụng nút "Generate Payload" hoặc nhập yêu cầu
- Chọn loại lỗ hổng và độ khó

**Ví dụ:**
```
Bạn: "Tạo payload cho XSS"
Assistant: "🔧 Payloads cho XSS:
1. Basic XSS: <script>alert('XSS')</script>
2. XSS with Event Handlers: <img src=x onerror=alert('XSS')>
..."
```

**Các loại payload hỗ trợ:**
- XSS (Cross-Site Scripting)
- SQL Injection
- LFI (Local File Inclusion)
- RFI (Remote File Inclusion)
- CSRF (Cross-Site Request Forgery)
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Command Injection

### 3. Quét tự động với ZAP

**Cách sử dụng:**
1. Nhập URL mục tiêu
2. Chọn loại quét (Spider, Active, Full)
3. Nhấn "Start Scan"

**Các loại quét:**
- **Spider Scan**: Crawl website để tìm các trang và form
- **Active Scan**: Tìm lỗ hổng bảo mật
- **Full Scan**: Kết hợp cả hai

**Ví dụ:**
```
Bạn: "Quét website https://juice-shop.herokuapp.com"
Assistant: "🔍 Bắt đầu quét: https://juice-shop.herokuapp.com
Quá trình quét sẽ bao gồm:
• Spider scan (crawl website)
• Active scan (tìm lỗ hổng)
• Phân tích kết quả
⏳ Quá trình này có thể mất vài phút..."
```

### 4. Phân tích kết quả

Sau khi quét xong, hệ thống sẽ:
- Tóm tắt các lỗ hổng tìm được
- Phân loại theo mức độ rủi ro
- Đưa khuyến nghị khắc phục
- Xuất báo cáo chi tiết

## API Endpoints

### 1. Chat API

```bash
POST /chat
Content-Type: application/json

{
  "message": "Giải thích về XSS",
  "session_id": "user123"
}
```

### 2. Payload Generation API

```bash
POST /payloads
Content-Type: application/json

{
  "vulnerability_type": "xss",
  "difficulty": "medium",
  "count": 5
}
```

### 3. ZAP Scan API

```bash
POST /scan
Content-Type: application/json

{
  "target_url": "https://juice-shop.herokuapp.com",
  "scan_type": "full",
  "max_depth": 5
}
```

### 4. Scan Status API

```bash
GET /scan/{scan_id}/status
```

## Các lệnh mẫu

### Giải thích lỗ hổng

```
"Giải thích về XSS"
"SQL Injection là gì?"
"OWASP Top 10 2021"
"LFI và RFI khác nhau như thế nào?"
"CSRF attack hoạt động ra sao?"
```

### Tạo payload

```
"Tạo payload cho XSS"
"Payload SQL injection cho login form"
"LFI payload để đọc file"
"CSRF payload cho form đổi mật khẩu"
"XXE payload cho XML parser"
```

### Quét bảo mật

```
"Quét website https://juice-shop.herokuapp.com"
"Kiểm tra bảo mật cho localhost:3000"
"Scan active cho https://dvwa.local"
"Spider scan cho https://example.com"
```

### Hỗ trợ chung

```
"Help"
"Hướng dẫn sử dụng"
"Các tính năng có sẵn"
"Làm thế nào để test XSS?"
"Best practices cho security testing"
```

## Bảo mật và đạo đức

### Nguyên tắc quan trọng

1. **Chỉ test trên môi trường được phép**
   - OWASP Juice Shop
   - DVWA (Damn Vulnerable Web Application)
   - WebGoat
   - Website demo tự dựng

2. **Không quét hệ thống bên thứ ba**
   - Chỉ test trên domain được cấu hình
   - Không tấn công website thực tế

3. **Tuân thủ pháp luật**
   - Không vi phạm quyền riêng tư
   - Không gây hại cho hệ thống

### Domain được phép

Mặc định, hệ thống chỉ cho phép test trên:
- `localhost`
- `127.0.0.1`
- `juice-shop.herokuapp.com`
- `dvwa.local`

## Troubleshooting

### Lỗi kết nối ZAP

1. Kiểm tra ZAP có đang chạy không
2. Kiểm tra API key trong file `.env`
3. Kiểm tra port 8080 có bị chiếm không

### Lỗi LLM API

1. Kiểm tra API key có hợp lệ không
2. Kiểm tra kết nối internet
3. Kiểm tra quota API

### Lỗi quét

1. Kiểm tra URL mục tiêu có hợp lệ không
2. Kiểm tra domain có trong danh sách được phép không
3. Kiểm tra ZAP có đủ tài nguyên không

## Tips và Tricks

### 1. Sử dụng session ID

Sử dụng session ID để duy trì context:
```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "session_id": "user123"}'
```

### 2. Export kết quả

Sử dụng nút "Export Chat" để lưu lịch sử hội thoại.

### 3. Custom payload

Bạn có thể mở rộng payload database bằng cách chỉnh sửa file `app/security/payload_generator.py`.

### 4. Integration với CI/CD

Sử dụng API để tích hợp vào pipeline CI/CD:
```bash
# Trong script CI/CD
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://staging.example.com"}'
```

## Hỗ trợ

Nếu gặp vấn đề, hãy:

1. Kiểm tra logs trong `data/logs/`
2. Xem documentation trong thư mục `docs/`
3. Tạo issue trên GitHub repository
4. Liên hệ team phát triển
