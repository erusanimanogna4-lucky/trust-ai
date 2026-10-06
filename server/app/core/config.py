import os
from typing import List, Union
from pydantic import AnyHttpUrl, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Sentinel-AI"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "AI Trust, Privacy & Runtime Security Gateway"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # CORS Origins - Allow local dev and Vercel domains
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    
    # Regex pattern to match any vercel preview or production domain
    CORS_ORIGIN_REGEX: str = r"^https:\/\/.*\.vercel\.app$"
    
    # Secret Key for HMAC / cryptographic token salting
    SECRET_KEY: str = os.getenv("SECRET_KEY", "sentinel-ai-super-secure-runtime-gateway-key-2025")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow",
    )


settings = Settings()
