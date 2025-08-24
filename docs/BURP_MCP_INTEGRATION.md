# Burp Suite Pro & MCP Integration Guide

## 🔍 Burp Suite Pro Integration

### Overview
Hệ thống đã được nâng cấp để sử dụng **Burp Suite Pro** thay thế cho OWASP ZAP, cung cấp khả năng quét bảo mật web application mạnh mẽ hơn.

### Cấu hình Burp Suite Pro

#### 1. Cài đặt Burp Suite Pro
```bash
# Download Burp Suite Pro từ trang chủ
# https://portswigger.net/burp/releases/professional

# Hoặc sử dụng Docker
docker run -d --name burp-suite-pro \
  -p 1337:1337 \
  -v burp-config:/opt/BurpSuitePro \
  portswigger/burp-suite-pro
```

#### 2. Cấu hình API
```bash
# Trong Burp Suite Pro:
# 1. Mở Burp Suite Pro
# 2. Vào Extensions > APIs > REST API
# 3. Enable REST API
# 4. Set API key và port (mặc định: 1337)
```

#### 3. Environment Variables
```bash
# .env file
BURP_URL=http://localhost:1337
BURP_API_KEY=your_burp_api_key_here
```

### Sử dụng Burp Suite Pro Client

#### Basic Usage
```python
from app.security.burp_client import BurpClient

async with BurpClient() as burp_client:
    # Check connection
    is_connected = await burp_client.check_connection()
    
    # Add target to scope
    await burp_client.add_target_to_scope("https://target.com")
    
    # Start spider scan
    spider_scan_id = await burp_client.start_spider_scan("https://target.com")
    
    # Start active scan
    active_scan_id = await burp_client.start_active_scan("https://target.com")
    
    # Get scan status
    status = await burp_client.get_scan_status(spider_scan_id)
    
    # Get security issues
    issues = await burp_client.get_issues()
    
    # Export report
    report = await burp_client.export_scan_report(spider_scan_id, "html")
```

#### Advanced Scanning
```python
# Comprehensive scan with multiple types
scan_result = await burp_client.start_scan(
    target_url="https://target.com",
    scan_types=["spider", "active"]
)

# Wait for completion
completed = await burp_client.wait_for_scan_completion(
    scan_id=scan_result["spider_scan_id"],
    timeout=3600
)

# Get detailed results
results = await burp_client.get_scan_results(scan_result["spider_scan_id"])
statistics = await burp_client.get_scan_statistics(scan_result["spider_scan_id"])
```

### API Endpoints

#### Burp Suite Pro Scan
```bash
# Start scan
POST /api/scan/burp
{
    "target_url": "https://target.com",
    "scan_types": ["spider", "active"],
    "max_depth": 5
}

# Get scan status
GET /api/scan/burp/{scan_id}/status

# Get scan results
GET /api/scan/burp/{scan_id}/results

# Get issues
GET /api/scan/burp/issues

# Export report
POST /api/scan/burp/{scan_id}/export
{
    "format": "html"
}
```

## 🤖 MCP (Model Context Protocol) Integration

### Overview
MCP cho phép AI gọi các công cụ bên ngoài một cách an toàn và có kiểm soát, hỗ trợ việc thực hiện pentest tự động.

### Cấu hình MCP Server

#### 1. Setup MCP Server
```bash
# Clone MCP server repository
git clone https://github.com/modelcontextprotocol/server-python
cd server-python

# Install dependencies
pip install -r requirements.txt

# Configure MCP server
cp config.example.json config.json
# Edit config.json với các tools cần thiết

# Start MCP server
python server.py --port 8001 --api-key your_api_key
```

#### 2. Environment Variables
```bash
# .env file
MCP_SERVER_URL=http://localhost:8001
MCP_API_KEY=your_mcp_api_key_here
MCP_ENABLED=true
MCP_TIMEOUT=300
```

### Sử dụng MCP Client

#### Basic Request
```python
from app.security.mcp_client import MCPClient

mcp_client = MCPClient(server_url, api_key)

# Basic tool execution
request_data = {
    'request_id': 'test_001',
    'type': 'tool_execution',
    'target': 'scanme.nmap.org',
    'parameters': {
        'tool_name': 'nmap_scan',
        'ports': '1-100',
        'scan_type': 'stealth'
    },
    'context': {
        'user_intent': 'network_reconnaissance'
    }
}

response = await mcp_client.call_request(request_data)
```

#### Script Generation
```python
# Generate exploitation script
script_request = {
    'request_id': 'script_001',
    'type': 'script_generation',
    'target': 'https://target.com',
    'parameters': {
        'script_type': 'sql_injection',
        'technique': 'boolean_based',
        'interactive': True
    },
    'context': {
        'user_intent': 'exploitation_script'
    }
}

script_response = await mcp_client.call_request(script_request)
```

#### Batch Requests
```python
# Execute multiple requests
batch_requests = [
    {
        'request_id': 'batch_001',
        'type': 'tool_execution',
        'target': 'target.com',
        'parameters': {'tool_name': 'nuclei_scan'},
        'context': {'user_intent': 'vulnerability_scan'}
    },
    {
        'request_id': 'batch_002',
        'type': 'tool_execution',
        'target': 'target.com',
        'parameters': {'tool_name': 'ffuf_fuzzing'},
        'context': {'user_intent': 'directory_enumeration'}
    }
]

responses = await mcp_client.batch_request(batch_requests)
```

#### Stream Requests
```python
async def stream_callback(chunk):
    """Handle streaming response chunks"""
    print(f"Received: {chunk}")

stream_request = {
    'request_id': 'stream_001',
    'type': 'pentest_execution',
    'target': 'https://target.com',
    'parameters': {
        'tools': ['nmap_scan', 'nuclei_scan'],
        'phases': ['reconnaissance', 'vulnerability_scan']
    },
    'timeout': 600
}

response = await mcp_client.stream_request(stream_request, stream_callback)
```

#### Chain Exploits
```python
# Execute exploit chain
chain_request = {
    'request_id': 'chain_001',
    'type': 'chain_exploit',
    'target': 'https://target.com',
    'parameters': {
        'exploit_chain': [
            {
                'step': 1,
                'tool': 'nmap_scan',
                'parameters': {'ports': '80,443'},
                'expected_output': 'open_ports'
            },
            {
                'step': 2,
                'tool': 'nuclei_scan',
                'parameters': {'templates': 'vulnerabilities'},
                'expected_output': 'vulnerabilities'
            },
            {
                'step': 3,
                'tool': 'sqlmap_injection',
                'parameters': {'level': 1, 'risk': 1},
                'expected_output': 'sql_injection'
            }
        ]
    },
    'timeout': 900
}

chain_response = await mcp_client.call_request(chain_request)
```

### Available MCP Tools

#### Network Scanning
- **nmap_scan**: Network port scanning and service enumeration
- **masscan**: Fast port scanning for large networks

#### Web Application Testing
- **sqlmap_injection**: Automated SQL injection detection
- **nuclei_scan**: Template-based vulnerability scanning
- **ffuf_fuzzing**: Directory and file fuzzing
- **dirsearch**: Directory enumeration

#### Exploitation
- **metasploit**: Exploit framework integration
- **custom_script**: Custom exploitation scripts

### API Endpoints

#### MCP Operations
```bash
# Send MCP request
POST /api/mcp/request
{
    "request_data": {
        "type": "tool_execution",
        "target": "target.com",
        "parameters": {...}
    }
}

# Batch MCP requests
POST /api/mcp/batch
{
    "requests": [
        {"type": "tool_execution", "target": "target.com", ...},
        {"type": "script_generation", "target": "target.com", ...}
    ]
}

# Stream MCP request
POST /api/mcp/stream
{
    "request_data": {
        "type": "pentest_execution",
        "target": "target.com",
        "parameters": {...}
    }
}

# Get available tools
GET /api/mcp/tools

# Check server status
GET /api/mcp/status
```

### Security Considerations

#### Ethical Guidelines
- Chỉ test trên các target được phép
- Tuân thủ các quy định pháp luật
- Không thực hiện các hoạt động độc hại
- Báo cáo findings một cách có trách nhiệm

#### Access Control
- Sử dụng API keys cho authentication
- Implement rate limiting
- Log tất cả activities
- Monitor resource usage

#### Data Protection
- Encrypt sensitive data
- Secure API communications
- Implement data retention policies
- Regular security audits

### Troubleshooting

#### Common Issues

1. **Burp Suite Pro Connection Failed**
   ```bash
   # Check if Burp is running
   curl http://localhost:1337/api/v1/info
   
   # Verify API key
   curl -H "Authorization: Bearer your_api_key" \
        http://localhost:1337/api/v1/info
   ```

2. **MCP Server Unavailable**
   ```bash
   # Check MCP server status
   curl http://localhost:8001/health
   
   # Verify configuration
   cat config.json
   ```

3. **Request Timeout**
   ```python
   # Increase timeout
   request_data = {
       'timeout': 600,  # 10 minutes
       ...
   }
   ```

#### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable debug logging for MCP client
mcp_client.logger.setLevel(logging.DEBUG)
```

### Performance Optimization

#### Parallel Execution
```python
# Execute multiple scans in parallel
import asyncio

async def parallel_scans(targets):
    tasks = []
    for target in targets:
        task = burp_client.start_scan(target)
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    return results
```

#### Resource Management
```python
# Use connection pooling
async with BurpClient() as burp_client:
    # All operations use the same session
    await burp_client.start_scan(target)
    await burp_client.get_issues()
```

### Monitoring & Logging

#### Metrics Collection
```python
# Track scan performance
scan_start = time.time()
result = await burp_client.start_scan(target)
scan_duration = time.time() - scan_start

# Log metrics
logger.info(f"Scan completed in {scan_duration:.2f}s")
```

#### Error Handling
```python
try:
    response = await mcp_client.call_request(request_data)
    if not response.success:
        logger.error(f"MCP request failed: {response.error}")
        # Implement retry logic or fallback
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    # Handle gracefully
```

## 🚀 Best Practices

### 1. Target Validation
- Luôn validate target trước khi scan
- Kiểm tra domain whitelist
- Verify authorization

### 2. Resource Management
- Monitor CPU và memory usage
- Implement proper cleanup
- Use connection pooling

### 3. Error Handling
- Implement comprehensive error handling
- Provide meaningful error messages
- Log all errors for debugging

### 4. Security
- Validate all inputs
- Sanitize outputs
- Implement proper authentication
- Regular security updates

### 5. Documentation
- Document all configurations
- Maintain runbooks
- Update procedures regularly
