# Hướng dẫn cài đặt Security Testing Assistant

## Yêu cầu hệ thống

- Python 3.8+
- Docker và Docker Compose
- Git
- ít nhất 4GB RAM
- 10GB dung lượng ổ cứng

## Cài đặt

### 1. Clone repository

```bash
git clone <repository-url>
cd forpentest
```

### 2. Tạo virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### 4. Cấu hình môi trường

Tạo file `.env` từ `env.example`:

```bash
cp env.example .env
```

Chỉnh sửa file `.env` với các API keys của bạn:

```env
# LLM API Keys
OPENAI_API_KEY=your_openai_api_key_here
CLAUDE_API_KEY=your_claude_api_key_here

# Security Tools
ZAP_API_KEY=your_zap_api_key_here
ZAP_URL=http://localhost:8080

# Database
DATABASE_URL=sqlite:///./data/security_assistant.db

# Vector Database
CHROMA_DB_PATH=./data/chroma_db

# Application Settings
DEBUG=True
LOG_LEVEL=INFO
SECRET_KEY=your_secret_key_here

# Security Settings
ALLOWED_DOMAINS=localhost,127.0.0.1,juice-shop.herokuapp.com,dvwa.local
```

### 5. Tạo thư mục dữ liệu

```bash
mkdir -p data/logs data/reports data/chroma_db
```

## Chạy ứng dụng

### Phương pháp 1: Chạy trực tiếp

#### Chạy API server

```bash
python main.py
```

API sẽ chạy tại: http://localhost:8000

#### Chạy Streamlit UI

```bash
streamlit run app/ui/main.py
```

UI sẽ chạy tại: http://localhost:8501

### Phương pháp 2: Sử dụng Docker

#### Chạy với Docker Compose

```bash
docker-compose up -d
```

Các service sẽ chạy tại:
- API: http://localhost:8000
- UI: http://localhost:8501
- ZAP: http://localhost:8080
- ZAP Web UI: http://localhost:8090

#### Chạy từng service riêng lẻ

```bash
# Chạy ZAP
docker-compose up zap -d

# Chạy API
docker-compose up api -d

# Chạy UI
docker-compose up ui -d
```

## Cấu hình ZAP

### 1. Khởi động ZAP

```bash
# Sử dụng Docker
docker run -d -p 8080:8080 -p 8090:8090 \
  -e ZAP_WEBSWING_OPTS="-port 8090 -host 0.0.0.0" \
  owasp/zap2docker-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.key=your_zap_api_key_here
```

### 2. Kiểm tra kết nối

Truy cập: http://localhost:8080/JSON/core/view/version

### 3. Cấu hình API key

Trong file `.env`, đặt `ZAP_API_KEY` giống với key đã cấu hình trong ZAP.

## Kiểm tra cài đặt

### 1. Kiểm tra API

```bash
curl http://localhost:8000/health
```

### 2. Kiểm tra ZAP

```bash
curl http://localhost:8000/zap/status
```

### 3. Kiểm tra UI

Truy cập: http://localhost:8501

## Troubleshooting

### Lỗi kết nối ZAP

1. Kiểm tra ZAP có đang chạy không:
   ```bash
   docker ps | grep zap
   ```

2. Kiểm tra logs:
   ```bash
   docker logs security_assistant_zap
   ```

3. Kiểm tra API key trong file `.env`

### Lỗi LLM API

1. Kiểm tra API key có hợp lệ không
2. Kiểm tra kết nối internet
3. Kiểm tra quota API

### Lỗi port đã được sử dụng

Thay đổi port trong file cấu hình hoặc dừng service đang sử dụng port đó.

## Cấu hình nâng cao

### 1. Cấu hình database

Thay đổi `DATABASE_URL` trong `.env` để sử dụng PostgreSQL:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/security_assistant
```

### 2. Cấu hình logging

Thay đổi `LOG_LEVEL` trong `.env`:

```env
LOG_LEVEL=DEBUG  # DEBUG, INFO, WARNING, ERROR
```

### 3. Cấu hình bảo mật

Thay đổi `ALLOWED_DOMAINS` để chỉ cho phép các domain cụ thể:

```env
ALLOWED_DOMAINS=your-domain.com,test.your-domain.com
```

## Gỡ cài đặt

### Gỡ cài đặt Docker

```bash
docker-compose down -v
docker system prune -f
```

### Gỡ cài đặt Python

```bash
deactivate  # Nếu đang trong virtual environment
rm -rf venv/
rm -rf data/
```
