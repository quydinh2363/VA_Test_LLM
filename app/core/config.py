"""
Configuration settings for the Security Testing Assistant
"""

import os
from typing import List, Optional
from pydantic import BaseSettings, validator


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    app_name: str = "Security Testing Assistant"
    debug: bool = True
    secret_key: str = "your-secret-key-change-in-production"
    
    # LLM Settings
    openai_api_key: Optional[str] = None
    claude_api_key: Optional[str] = None
    default_llm: str = "openai"
    model_name: str = "gpt-4"
    
    # Security Tools
    zap_api_key: Optional[str] = None
    zap_url: str = "http://localhost:8080"
    burp_api_key: Optional[str] = None
    burp_url: str = "http://localhost:1337"
    
    # Database
    database_url: str = "sqlite:///./data/security_assistant.db"
    
    # Vector Database
    chroma_db_path: str = "./data/chroma_db"
    
    # Security Settings
    allowed_domains: List[str] = [
        "localhost", 
        "127.0.0.1", 
        "juice-shop.herokuapp.com",
        "dvwa.local"
    ]
    max_scan_duration: int = 3600  # seconds
    max_payload_length: int = 10000
    
    # MCP Server settings
    mcp_server_url: str = "http://localhost:8080"
    mcp_api_key: Optional[str] = None
    mcp_enabled: bool = False
    mcp_timeout: int = 300
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000
    
    # Logging
    log_level: str = "INFO"
    log_file_path: str = "./data/logs/security_assistant.log"
    
    # Report Settings
    report_template_path: str = "./templates/reports"
    report_output_path: str = "./data/reports"
    
    @validator("allowed_domains", pre=True)
    def parse_allowed_domains(cls, v):
        if isinstance(v, str):
            return [domain.strip() for domain in v.split(",")]
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
