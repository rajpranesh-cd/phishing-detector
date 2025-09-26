"""Configuration management for the phishing detection system."""

import os
from typing import List, Optional
from pydantic import BaseSettings, validator


class Settings(BaseSettings):
    """Application settings."""
    
    # Database
    database_url: str
    redis_url: str
    
    # Microsoft Graph API
    azure_client_id: str
    azure_client_secret: str
    azure_tenant_id: str
    
    # External APIs
    virustotal_api_key: Optional[str] = None
    joe_sandbox_api_key: Optional[str] = None
    urlvoid_api_key: Optional[str] = None
    
    # Security
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Application
    debug: bool = False
    log_level: str = "INFO"
    max_workers: int = 4
    webhook_secret: str
    
    # ML Model Settings
    model_update_interval: int = 24  # hours
    confidence_threshold: float = 0.7
    ensemble_weights: str = "0.3,0.3,0.4"
    
    @validator('ensemble_weights')
    def parse_ensemble_weights(cls, v):
        """Parse ensemble weights from string to list of floats."""
        return [float(x.strip()) for x in v.split(',')]
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
