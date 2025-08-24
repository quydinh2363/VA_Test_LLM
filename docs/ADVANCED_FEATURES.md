# Advanced Features Documentation

## Overview

The Security Testing Assistant now includes advanced features for enhanced AI-powered security testing capabilities:

1. **MCP (Model Context Protocol) Server Integration**
2. **Advanced Exploitation Script Generation**
3. **Automated Pentesting Orchestration**
4. **Interactive AI-Powered Testing**

## 1. MCP Server Integration

### What is MCP?

MCP (Model Context Protocol) is a protocol that enables AI models to interact with external tools and services. In our implementation, MCP provides:

- **Tool Execution**: Run security tools like nmap, sqlmap, nuclei, ffuf
- **Script Generation**: Generate exploitation scripts dynamically
- **Data Extraction**: Extract and analyze security data
- **Chain Exploits**: Execute multi-step exploitation chains

### Configuration

Enable MCP integration in your `.env` file:

```bash
# MCP Server Settings
MCP_SERVER_URL=http://localhost:8080
MCP_API_KEY=your_mcp_api_key_here
MCP_ENABLED=true
MCP_TIMEOUT=300
```

### Available MCP Tools

| Tool | Description | Risk Level | Use Case |
|------|-------------|------------|----------|
| `nmap_scan` | Network scanning and port enumeration | Low | Reconnaissance |
| `sqlmap_injection` | Automated SQL injection detection | High | Database testing |
| `nuclei_scan` | Fast vulnerability scanning | Medium | Vulnerability assessment |
| `ffuf_fuzzing` | Directory and file discovery | Low | Information gathering |
| `custom_script` | Execute custom exploitation scripts | Variable | Custom testing |

### API Endpoints

#### Check MCP Status
```bash
GET /mcp/status
```

#### List Available Tools
```bash
GET /mcp/tools
```

#### Send MCP Request
```bash
POST /mcp/request
{
    "target": "https://example.com",
    "request_type": "script_generation",
    "parameters": {
        "script_type": "xss_payload",
        "context": "reflected"
    },
    "timeout": 300
}
```

## 2. Advanced Exploitation Script Generation

### Features

- **Context-Aware Scripts**: Generate scripts based on target environment
- **Interactive Mode**: Step-by-step script generation with user guidance
- **Verification Scripts**: Automatically generate verification steps
- **Cleanup Scripts**: Generate cleanup procedures
- **Ethical Guidelines**: Built-in ethical considerations

### Supported Script Types

| Script Type | Description | Target Type |
|-------------|-------------|-------------|
| `XSS_PAYLOAD` | Cross-Site Scripting exploits | Web Application |
| `SQL_INJECTION` | SQL injection exploits | Database |
| `COMMAND_INJECTION` | Command injection exploits | Operating System |
| `REVERSE_SHELL` | Reverse shell generation | Operating System |
| `LFI_RFI` | File inclusion exploits | File System |
| `CSRF_EXPLOIT` | CSRF attack scripts | Web Application |

### API Usage

#### Generate Exploitation Script
```bash
POST /exploitation/script
{
    "target_url": "https://example.com",
    "script_type": "XSS_PAYLOAD",
    "vulnerability_type": "XSS",
    "parameters": {
        "context": "reflected",
        "filter_bypass": true
    },
    "interactive_mode": false
}
```

### Example Generated Script

```python
import requests
import re
from urllib.parse import urljoin, quote

class XSSExploit:
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.payloads = []
        
    def generate_payloads(self, context):
        '''Generate context-aware XSS payloads'''
        base_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>'
        ]
        
        self.payloads.extend(base_payloads)
        return self.payloads
    
    def test_payload(self, payload, injection_point):
        '''Test a specific payload at injection point'''
        try:
            encoded_payload = quote(payload)
            test_url = f"{self.target_url}{injection_point}={encoded_payload}"
            response = self.session.get(test_url)
            
            if payload in response.text:
                return {
                    'success': True,
                    'payload': payload,
                    'url': test_url,
                    'reflection_point': self._find_reflection_point(response.text, payload)
                }
            
            return {'success': False, 'payload': payload, 'reason': 'No reflection detected'}
            
        except Exception as e:
            return {'success': False, 'payload': payload, 'error': str(e)}
    
    def interactive_exploit(self, context):
        '''Interactive exploitation with user guidance'''
        print("🔍 Starting interactive XSS exploitation...")
        print(f"Target: {self.target_url}")
        
        payloads = self.generate_payloads(context)
        print(f"Generated {len(payloads)} payloads")
        
        successful_exploits = []
        
        for i, payload in enumerate(payloads):
            print(f"\n[{i+1}/{len(payloads)}] Testing: {payload}")
            
            injection_points = ['?q=', '?search=', '?id=', '?name=']
            
            for point in injection_points:
                result = self.test_payload(payload, point)
                if result['success']:
                    successful_exploits.append(result)
                    print(f"✅ SUCCESS: {result['url']}")
                    print(f"   Reflection: {result['reflection_point']}")
                else:
                    print(f"❌ Failed: {result.get('reason', 'Unknown error')}")
        
        return successful_exploits
```

## 3. Automated Pentesting

### Pentest Phases

The automated pentesting system follows a structured approach:

#### Phase 1: Reconnaissance
- **Port Scanning**: Identify open ports and services
- **Directory Fuzzing**: Discover hidden files and directories
- **Vulnerability Scanning**: Initial vulnerability assessment

#### Phase 2: Exploitation
- **Vulnerability Analysis**: Analyze discovered vulnerabilities
- **Payload Generation**: Create appropriate exploitation payloads
- **Exploitation Execution**: Execute exploitation attempts

#### Phase 3: Post-Exploitation
- **Data Extraction**: Extract sensitive information
- **Privilege Escalation**: Attempt to gain higher privileges
- **Persistence**: Establish persistent access (if authorized)

### API Usage

#### Start Automated Pentest
```bash
POST /pentest/execute
{
    "target": "https://example.com",
    "phases": ["reconnaissance", "exploitation", "post_exploitation"],
    "tools": ["nmap", "nuclei", "sqlmap"],
    "parameters": {
        "scan_depth": "comprehensive",
        "risk_level": "medium"
    }
}
```

#### Check Pentest Status
```bash
GET /pentest/{pentest_id}/status
```

#### Get Pentest History
```bash
GET /pentest/history
```

### Example Pentest Report

```markdown
# Pentest Report for https://example.com

## Executive Summary
- **Target**: https://example.com
- **Duration**: 1800 seconds
- **Status**: Completed

## Phases

### 1. Reconnaissance
{
  "port_scan": {
    "open_ports": [80, 443, 22],
    "services": ["http", "https", "ssh"]
  },
  "directory_scan": {
    "discovered_paths": ["/admin", "/api", "/backup"],
    "status_codes": {"200": 15, "403": 3, "404": 87}
  },
  "vulnerability_scan": {
    "vulnerabilities": [
      {
        "type": "sql_injection",
        "severity": "high",
        "location": "/search.php?id=1"
      }
    ]
  }
}

### 2. Exploitation
{
  "sql_injection": {
    "success": true,
    "technique": "boolean_based",
    "extracted_data": {
      "database": "testdb",
      "tables": ["users", "config"]
    }
  }
}

### 3. Post-Exploitation
{
  "extracted_data": {
    "user_credentials": "3 records found",
    "configuration_files": "2 files accessed"
  }
}

## Recommendations
1. Address critical vulnerabilities immediately
2. Implement security controls
3. Regular security assessments
4. Employee security training

## Ethical Considerations
- This pentest was conducted on authorized systems only
- All findings should be reported responsibly
- No sensitive data was extracted or stored
```

## 4. UI Integration

### Advanced Tools Tab

The UI includes a dedicated "Advanced Tools" tab with:

- **Exploitation Script Generator**: Interactive script creation
- **Script Templates**: Pre-built templates for common scenarios
- **Verification Tools**: Built-in verification capabilities
- **Ethical Guidelines**: Prominent ethical warnings

### MCP Integration Tab

Features include:

- **MCP Status Monitor**: Real-time server status
- **Tool Browser**: Browse available MCP tools
- **Request Builder**: Build and send MCP requests
- **Response Viewer**: View and analyze responses

### Pentest Tab

Provides:

- **Pentest Configuration**: Configure pentest parameters
- **Phase Selection**: Choose which phases to run
- **Real-time Monitoring**: Monitor pentest progress
- **History Viewer**: View past pentest results

## 5. Security and Ethical Considerations

### Built-in Safeguards

1. **Domain Whitelisting**: Only test authorized domains
2. **Rate Limiting**: Prevent aggressive scanning
3. **Ethical Guidelines**: Built into all generated scripts
4. **Audit Logging**: Track all activities
5. **Consent Verification**: Require explicit authorization

### Ethical Guidelines

- **Authorization**: Only test systems you own or have explicit permission to test
- **Documentation**: Document all testing activities
- **Responsible Disclosure**: Report findings to appropriate parties
- **Data Protection**: Do not extract or store sensitive data
- **Resource Respect**: Do not overload target systems

### Risk Levels

| Risk Level | Description | Use Case |
|------------|-------------|----------|
| **Low** | Information gathering, non-intrusive | Reconnaissance, enumeration |
| **Medium** | Vulnerability scanning, passive testing | Security assessment |
| **High** | Active exploitation, data extraction | Authorized penetration testing |
| **Critical** | System compromise, privilege escalation | Advanced security testing |

## 6. Configuration Examples

### Basic MCP Configuration

```python
# app/core/config.py
class Settings(BaseSettings):
    # MCP Server settings
    mcp_server_url: str = "http://localhost:8080"
    mcp_api_key: Optional[str] = None
    mcp_enabled: bool = False
    mcp_timeout: int = 300
```

### Docker Configuration

```yaml
# docker-compose.yml
services:
  mcp-server:
    image: your-mcp-server:latest
    ports:
      - "8080:8080"
    environment:
      - MCP_API_KEY=your_api_key
      - MCP_ENABLED=true
    volumes:
      - ./mcp-config:/app/config
```

### Environment Variables

```bash
# .env
MCP_SERVER_URL=http://localhost:8080
MCP_API_KEY=your_mcp_api_key_here
MCP_ENABLED=true
MCP_TIMEOUT=300

# Security settings
ALLOWED_DOMAINS=localhost,127.0.0.1,juice-shop.herokuapp.com
MAX_SCAN_DURATION=3600
MAX_PAYLOAD_LENGTH=10000
```

## 7. Troubleshooting

### Common Issues

#### MCP Server Not Available
```
Error: MCP client not available
```
**Solution**: Check MCP server configuration and ensure it's running.

#### Target Domain Not Allowed
```
Error: Target domain not allowed
```
**Solution**: Add target domain to `ALLOWED_DOMAINS` in configuration.

#### Script Generation Failed
```
Error: No template found for script_type
```
**Solution**: Check script type spelling and ensure template exists.

#### Pentest Timeout
```
Error: Request timeout
```
**Solution**: Increase `MCP_TIMEOUT` value for longer-running tests.

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Health Checks

Check system health:

```bash
# API health
curl http://localhost:8000/health

# MCP status
curl http://localhost:8000/mcp/status

# ZAP status
curl http://localhost:8000/zap/status
```

## 8. Future Enhancements

### Planned Features

1. **Advanced Chain Exploits**: Multi-step exploitation chains
2. **Machine Learning Integration**: AI-powered vulnerability prediction
3. **Real-time Collaboration**: Multi-user pentest sessions
4. **Advanced Reporting**: Interactive reports with remediation guidance
5. **Integration APIs**: Third-party tool integration

### Contributing

To contribute to advanced features:

1. Follow ethical guidelines
2. Test thoroughly on authorized systems
3. Document all changes
4. Include security considerations
5. Add appropriate error handling

## 9. Support

For support with advanced features:

1. Check the troubleshooting section
2. Review configuration examples
3. Consult ethical guidelines
4. Contact the development team
5. Report issues through proper channels

---

**Remember**: Always use these tools responsibly and only on systems you own or have explicit permission to test. Security testing without authorization is illegal and unethical.
