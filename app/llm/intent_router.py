"""
Intent Router for classifying user requests
"""

import logging
from typing import Dict, Any, List
from enum import Enum
import re

logger = logging.getLogger(__name__)


class IntentType(Enum):
    """Types of user intents"""
    EXPLAIN_VULNERABILITY = "explain_vulnerability"
    GENERATE_PAYLOAD = "generate_payload"
    RUN_SCAN = "run_scan"
    ANALYZE_RESULTS = "analyze_results"
    GENERAL_HELP = "general_help"
    UNKNOWN = "unknown"


class IntentRouter:
    """Routes user messages to appropriate handlers"""
    
    def __init__(self):
        self.intent_patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[IntentType, List[str]]:
        """Initialize regex patterns for intent classification"""
        return {
            IntentType.EXPLAIN_VULNERABILITY: [
                r"giải thích|mô tả|thông tin về|owasp|vulnerability|lỗ hổng",
                r"xss là gì|sql injection|csrf|lfi|rfi|xxe",
                r"broken authentication|insecure deserialization",
                r"security misconfiguration|sensitive data exposure"
            ],
            IntentType.GENERATE_PAYLOAD: [
                r"tạo payload|sinh payload|gợi ý payload|test payload",
                r"kiểm tra xss|test sql injection|thử lfi|rfi payload",
                r"payload cho|test với|thử nghiệm|vulnerability test"
            ],
            IntentType.RUN_SCAN: [
                r"quét|scan|kiểm tra tự động|automated scan",
                r"chạy zap|burp scan|active scan|passive scan",
                r"quét toàn bộ|scan website|kiểm tra bảo mật"
            ],
            IntentType.ANALYZE_RESULTS: [
                r"phân tích|kết quả|kết luận|đánh giá",
                r"báo cáo|report|tổng hợp|summary",
                r"khuyến nghị|remediation|fix|sửa lỗi"
            ],
            IntentType.GENERAL_HELP: [
                r"giúp đỡ|help|hướng dẫn|tutorial|how to",
                r"cách sử dụng|usage|manual|guide",
                r"bắt đầu|start|begin|introduction"
            ]
        }
    
    def classify_intent(self, message: str) -> IntentType:
        """Classify user message intent"""
        message_lower = message.lower()
        
        # Check each intent type
        for intent_type, patterns in self.intent_patterns.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    logger.info(f"Classified intent: {intent_type.value}")
                    return intent_type
        
        # Default to unknown
        logger.info("Classified intent: unknown")
        return IntentType.UNKNOWN
    
    def extract_entities(self, message: str, intent: IntentType) -> Dict[str, Any]:
        """Extract relevant entities from message"""
        entities = {}
        message_lower = message.lower()
        
        if intent == IntentType.EXPLAIN_VULNERABILITY:
            # Extract vulnerability type
            vuln_patterns = {
                "xss": r"xss|cross.?site.?scripting",
                "sqli": r"sql.?injection|sqli",
                "csrf": r"csrf|cross.?site.?request.?forgery",
                "lfi": r"lfi|local.?file.?inclusion",
                "rfi": r"rfi|remote.?file.?inclusion",
                "xxe": r"xxe|xml.?external.?entity",
                "idor": r"idor|insecure.?direct.?object.?reference",
                "ssrf": r"ssrf|server.?side.?request.?forgery"
            }
            
            for vuln_type, pattern in vuln_patterns.items():
                if re.search(pattern, message_lower):
                    entities["vulnerability_type"] = vuln_type.upper()
                    break
        
        elif intent == IntentType.GENERATE_PAYLOAD:
            # Extract target parameter/URL
            url_pattern = r"https?://[^\s]+"
            param_pattern = r"parameter\s+(\w+)|param\s+(\w+)"
            
            url_match = re.search(url_pattern, message)
            if url_match:
                entities["target_url"] = url_match.group()
            
            param_match = re.search(param_pattern, message)
            if param_match:
                entities["parameter"] = param_match.group(1) or param_match.group(2)
        
        elif intent == IntentType.RUN_SCAN:
            # Extract target URL
            url_pattern = r"https?://[^\s]+"
            url_match = re.search(url_pattern, message)
            if url_match:
                entities["target_url"] = url_match.group()
        
        return entities
    
    def get_intent_confidence(self, message: str, intent: IntentType) -> float:
        """Get confidence score for intent classification"""
        if intent == IntentType.UNKNOWN:
            return 0.0
        
        message_lower = message.lower()
        patterns = self.intent_patterns.get(intent, [])
        
        if not patterns:
            return 0.0
        
        # Count matching patterns
        matches = 0
        for pattern in patterns:
            if re.search(pattern, message_lower):
                matches += 1
        
        # Calculate confidence based on pattern matches
        confidence = min(matches / len(patterns), 1.0)
        return confidence
    
    def route_message(self, message: str) -> Dict[str, Any]:
        """Route message and return intent with entities"""
        intent = self.classify_intent(message)
        entities = self.extract_entities(message, intent)
        confidence = self.get_intent_confidence(message, intent)
        
        return {
            "intent": intent,
            "entities": entities,
            "confidence": confidence,
            "original_message": message
        }
