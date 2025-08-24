"""
Chat Manager for LLM interactions
"""

import logging
from typing import List, Dict, Any, Optional
from langchain.chat_models import ChatOpenAI, ChatAnthropic
from langchain.schema import HumanMessage, AIMessage, SystemMessage
from langchain.memory import ConversationBufferMemory
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder

from app.core.config import settings

logger = logging.getLogger(__name__)


class ChatManager:
    """Manages chat interactions with LLM"""
    
    def __init__(self):
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        self.llm = self._initialize_llm()
        self.system_prompt = self._get_system_prompt()
    
    def _initialize_llm(self):
        """Initialize LLM based on configuration"""
        if settings.default_llm == "openai" and settings.openai_api_key:
            return ChatOpenAI(
                model_name=settings.model_name,
                temperature=0.7,
                api_key=settings.openai_api_key
            )
        elif settings.default_llm == "claude" and settings.claude_api_key:
            return ChatAnthropic(
                model="claude-3-sonnet-20240229",
                temperature=0.7,
                api_key=settings.claude_api_key
            )
        else:
            raise ValueError("No valid LLM configuration found")
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for security assistant"""
        return """Bạn là một trợ lý bảo mật chuyên nghiệp, chuyên hỗ trợ kiểm thử bảo mật ứng dụng web.

NGUYÊN TẮC QUAN TRỌNG:
1. CHỈ KIỂM THỬ trên các domain được phép: {allowed_domains}
2. KHÔNG BAO GIỜ tấn công hệ thống thực tế mà không được phép
3. LUÔN cảnh báo về rủi ro và hậu quả của việc test
4. TUÂN THỦ đạo đức và pháp luật

CHỨC NĂNG:
- Giải thích các lỗ hổng bảo mật (OWASP Top 10)
- Gợi ý payload cho XSS, SQLi, LFI, RFI
- Hướng dẫn sử dụng công cụ (ZAP, Burp)
- Phân tích kết quả quét và đưa khuyến nghị

CÁCH TRẢ LỜI:
1. Phân loại yêu cầu (giải thích/gợi ý payload/quét tự động)
2. Đưa ra thông tin chính xác với trích dẫn OWASP
3. Cảnh báo rủi ro và hướng dẫn an toàn
4. Gợi ý bước tiếp theo phù hợp

Hãy bắt đầu bằng việc chào hỏi và hỏi người dùng cần hỗ trợ gì.""".format(
            allowed_domains=", ".join(settings.allowed_domains)
        )
    
    async def send_message(self, message: str, session_id: str = "default") -> str:
        """Send message to LLM and get response"""
        try:
            # Add user message to memory
            self.memory.chat_memory.add_user_message(message)
            
            # Create prompt with context
            prompt = ChatPromptTemplate.from_messages([
                ("system", self.system_prompt),
                MessagesPlaceholder(variable_name="chat_history"),
                ("human", "{input}")
            ])
            
            # Get chat history
            chat_history = self.memory.chat_memory.messages
            
            # Generate response
            chain = prompt | self.llm
            response = await chain.ainvoke({
                "chat_history": chat_history,
                "input": message
            })
            
            # Add AI response to memory
            self.memory.chat_memory.add_ai_message(response.content)
            
            logger.info(f"Generated response for session {session_id}")
            return response.content
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return f"Xin lỗi, có lỗi xảy ra: {str(e)}"
    
    def get_chat_history(self) -> List[Dict[str, str]]:
        """Get chat history"""
        messages = self.memory.chat_memory.messages
        history = []
        
        for msg in messages:
            if isinstance(msg, HumanMessage):
                history.append({"role": "user", "content": msg.content})
            elif isinstance(msg, AIMessage):
                history.append({"role": "assistant", "content": msg.content})
        
        return history
    
    def clear_history(self):
        """Clear chat history"""
        self.memory.clear()
        logger.info("Chat history cleared")
