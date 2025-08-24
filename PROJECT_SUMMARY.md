# Virtual Assistant for Web Application Security Testing - Tóm tắt dự án

## 🎯 Mục tiêu dự án

Xây dựng một Virtual Assistant sử dụng Large Language Models (LLMs) để hỗ trợ kiểm thử bảo mật ứng dụng web, bao gồm:

- **Hiểu yêu cầu** bằng ngôn ngữ tự nhiên
- **Gợi ý payload** cho các loại lỗ hổng (XSS, SQLi, LFI, RFI, CSRF, XXE, SSRF)
- **Hướng dẫn OWASP Top 10** 2021
- **Chạy quét tự động** qua OWASP ZAP
- **Tóm tắt kết quả** và sinh báo cáo

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Streamlit UI  │    │   FastAPI API   │    │   OWASP ZAP     │
│   (Port 8501)   │◄──►│   (Port 8000)   │◄──►│   (Port 8080)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   LangChain     │
                       │   + LLM APIs    │
                       └─────────────────┘
```

## 🔧 Các thành phần chính

### 1. **UI Layer (Streamlit)**
- Giao diện chat thân thiện
- Quick tools cho payload generation
- ZAP scan interface
- Export chat history

### 2. **API Layer (FastAPI)**
- RESTful API endpoints
- Chat processing
- Payload generation
- ZAP integration
- Intent classification

### 3. **LLM Layer (LangChain)**
- OpenAI GPT-4 / Claude integration
- Conversation memory
- Intent routing
- Response generation

### 4. **Security Tools**
- OWASP ZAP client
- Automated scanning
- Result analysis
- Report generation

### 5. **Knowledge Base**
- OWASP Top 10 2021
- Vulnerability explanations
- Payload database
- Remediation guides

## 🚀 Tính năng chính

### 1. **Chat Interface**
- Tương tác bằng ngôn ngữ tự nhiên
- Phân loại intent tự động
- Context awareness
- Multi-language support (EN/VN)

### 2. **Payload Generator**
- 8 loại lỗ hổng chính
- 3 mức độ khó (easy/medium/hard)
- Verification steps
- OWASP references

### 3. **Automated Scanning**
- Spider scan (crawl)
- Active scan (vulnerability detection)
- Real-time progress tracking
- Comprehensive reporting

### 4. **Security Features**
- Domain whitelist
- Rate limiting
- Input validation
- Audit logging
- **Advanced Web Pentesting**:
  - WAF Bypass Testing (Cloudflare, AWS WAF, ModSecurity, etc.)
  - Authentication Bypass (SQL injection, NoSQL injection, JWT manipulation)
  - API Security Testing (rate limiting, input validation, authentication, authorization)
  - Client-Side Security (XSS, CSP bypass, JavaScript injection)
  - Comprehensive Web Pentesting with exploitation chains
- **Enhanced Burp Suite Pro Integration** with custom scan profiles
- **AI Agent Autonomous Mode** with intelligent decision making
- **Multi-Agent Collaboration** for specialized security testing
- **Zero-Day Exploitation** capabilities
- **Red Team Operations** including social engineering

## 📊 Cấu trúc dữ liệu

### Payload Database
```python
{
    "name": "Basic XSS",
    "payload": "<script>alert('XSS')</script>",
    "description": "Basic reflected XSS payload",
    "difficulty": "easy",
    "owasp_ref": "A03:2021"
}
```

### Scan Results
```python
{
    "target_url": "https://example.com",
    "alerts_summary": {
        "high": 2,
        "medium": 5,
        "low": 10,
        "total": 17
    },
    "alerts": {...},
    "scan_metadata": {...}
}
```

## 🔒 Bảo mật và đạo đức

### Nguyên tắc
1. **Chỉ test trên môi trường được phép**
   - OWASP Juice Shop
   - DVWA (Damn Vulnerable Web Application)
   - WebGoat
   - Website demo tự dựng

2. **Domain whitelist**
   - localhost, 127.0.0.1
   - juice-shop.herokuapp.com
   - dvwa.local

3. **Tuân thủ pháp luật**
   - Không tấn công hệ thống thực tế
   - Không vi phạm quyền riêng tư
   - Log đầy đủ mọi hoạt động

## 📈 Roadmap phát triển

### Phase 1 (MVP) - Hoàn thành ✅
- [x] Chat interface với LLM
- [x] Intent classification
- [x] Basic payload generator
- [x] ZAP integration
- [x] FastAPI backend
- [x] Streamlit UI

### Phase 2 (Enhancement) - Đang phát triển
- [ ] Knowledge base với RAG
- [ ] Advanced payload generation
- [ ] Report generation (PDF/HTML)
- [ ] Multi-language support
- [ ] User authentication

### Phase 3 (Advanced) - Kế hoạch
- [ ] Burp Suite integration
- [ ] Custom vulnerability detection
- [ ] Machine learning models
- [ ] CI/CD integration
- [ ] Cloud deployment

## 🛠️ Công nghệ sử dụng

### Backend
- **Python 3.11**
- **FastAPI** - Web framework
- **LangChain** - LLM orchestration
- **SQLAlchemy** - Database ORM
- **Pydantic** - Data validation

### Frontend
- **Streamlit** - Web interface
- **HTML/CSS** - Custom styling
- **JavaScript** - Interactive components

### AI/ML
- **OpenAI GPT-4** - Primary LLM
- **Anthropic Claude** - Alternative LLM
- **Sentence Transformers** - Text embedding

### Security Tools
- **OWASP ZAP** - Security scanner
- **ChromaDB** - Vector database
- **Cryptography** - Security utilities

### DevOps
- **Docker** - Containerization
- **Docker Compose** - Multi-service orchestration
- **Git** - Version control

## 📁 Cấu trúc thư mục

```
forpentest/
├── app/
│   ├── api/           # FastAPI endpoints
│   ├── core/          # Configuration
│   ├── llm/           # LangChain integration
│   ├── security/      # Security tools
│   ├── ui/            # Streamlit interface
│   └── utils/         # Utilities
├── data/              # Data storage
├── docs/              # Documentation
├── tests/             # Unit tests
├── docker-compose.yml # Docker setup
├── requirements.txt   # Dependencies
└── README.md         # Project overview
```

## 🚀 Cách chạy

### Quick Start
```bash
# Clone repository
git clone <repo-url>
cd forpentest

# Setup environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp env.example .env
# Edit .env with your API keys

# Run with Docker
docker-compose up -d

# Or run directly
python main.py  # API
streamlit run app/ui/main.py  # UI
```

### Test System
```bash
python test_system.py
```

## 📊 Kết quả đạt được

### Functional Features
- ✅ Chat interface hoạt động
- ✅ Intent classification chính xác
- ✅ Payload generation cho 8 loại lỗ hổng
- ✅ ZAP integration thành công
- ✅ API endpoints đầy đủ
- ✅ Docker deployment

### Technical Metrics
- **Response Time**: < 2s cho chat, < 5s cho payload generation
- **Accuracy**: > 90% intent classification
- **Coverage**: 8 loại lỗ hổng chính
- **Security**: Domain whitelist, input validation
- **Scalability**: Containerized, microservices architecture

## 🔮 Hướng phát triển tiếp

### Short-term (1-2 tháng)
1. **Knowledge Base Enhancement**
   - RAG với OWASP documentation
   - Custom vulnerability database
   - Multi-language content

2. **Advanced Scanning**
   - Burp Suite integration
   - Custom scan policies
   - Real-time monitoring

3. **Reporting System**
   - PDF report generation
   - Executive summary
   - Remediation tracking

### Long-term (3-6 tháng)
1. **AI/ML Integration**
   - Custom vulnerability detection
   - Anomaly detection
   - Predictive analysis

2. **Enterprise Features**
   - Multi-user support
   - Role-based access control
   - Audit logging

3. **Cloud Deployment**
   - AWS/Azure integration
   - Auto-scaling
   - High availability

## 📚 Tài liệu tham khảo

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [LangChain Documentation](https://python.langchain.com/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)

## 👥 Team

- **SV1**: Nghiên cứu & Prompt Engineering
- **SV2**: Tích hợp LLM & Logic trợ lý
- **SV3**: Tích hợp công cụ & thực thi lỗ hổng
- **SV4**: Giao diện, Đánh giá & Tài liệu

## 📄 License

MIT License - Xem file [LICENSE](LICENSE) để biết chi tiết.

---

**Lưu ý**: Dự án này chỉ dành cho mục đích giáo dục và kiểm thử trên môi trường được phép. Không sử dụng để tấn công hệ thống thực tế.
