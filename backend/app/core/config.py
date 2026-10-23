"""
Configuration and Environment Settings for LLM Sentinel.

Enforces Safe Mode by default and provides environment-based configuration.
"""

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "LLM Sentinel"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Security & Safe Mode
    # Safe Mode restricts target execution strictly to localhost / mock targets
    SAFE_MODE: bool = Field(default=True, description="Strictly restrict tests to local mock/localhost targets")
    ALLOWED_TARGET_HOSTS: List[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "::1", "mock-target", "testserver"]
    )
    API_KEY_HEADER: str = "X-Sentinel-API-Key"
    SENTINEL_API_KEY: Optional[str] = None  # If set, validates API requests

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinel.db"
    SYNC_DATABASE_URL: str = "sqlite:///./sentinel.db"

    # Execution Bounds
    MAX_CONCURRENT_TESTS: int = 5
    DEFAULT_TEST_TIMEOUT_SECONDS: float = 15.0
    MAX_PAYLOAD_BYTES: int = 1_000_000

    # Rate Limiting & Safety
    DEFAULT_RATE_LIMIT_PER_MINUTE: int = 120

    # Synthetic Canaries & Secrets
    SYNTHETIC_CANARY_PREFIX: str = "CANARY_SEC_SENTINEL_"

    @field_validator("ALLOWED_TARGET_HOSTS", mode="before")
    @classmethod
    def assemble_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v


settings = Settings()
