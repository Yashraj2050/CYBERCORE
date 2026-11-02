"""
CYBERCORE Backend — Configuration Module
Loads all environment variables with validation via pydantic-settings.
"""

from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    admin_api_key: Optional[str] = None
    database_url: Optional[str] = None
    database_path: str = "cybercore.db"
    trusted_proxies: str = "127.0.0.1,::1"
    ingress_secret: Optional[str] = None

    @property
    def trusted_proxies_list(self) -> List[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]

    # CORS
    cors_origins: str = "http://localhost:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    # Supabase
    supabase_url: str = ""
    supabase_service_key: str = ""
    supabase_jwt_secret: str = ""

    # External Security APIs
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    hibp_api_key: str = ""
    phishtank_api_key: str = ""
    urlhaus_auth_key: str = ""

    # AI
    openai_api_key: str = ""
    gemini_api_key: str = ""
    ai_provider: str = "gemini"  # 'openai' or 'gemini'
    ai_model: str = "gemini-1.5-flash"

    # Redis
    redis_url: str = ""

    # Rate Limiting
    rate_limit_per_minute: int = 30
    rate_limit_scan_per_hour: int = 100

    # File Upload
    max_file_size_mb: int = 32
    allowed_file_types: str = "pdf,zip,exe,docx,apk,doc,xlsx,pptx"

    @property
    def allowed_file_types_list(self) -> List[str]:
        return [t.strip() for t in self.allowed_file_types.split(",")]

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024

    # SSRF Protection — blocked IP ranges
    blocked_ip_prefixes: tuple = (
        "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.", "169.254.", "0.", "::1", "fc00:", "fe80:",
    )

    # Blocked hostnames for SSRF
    blocked_hostnames: tuple = (
        "localhost", "metadata.google.internal",
        "169.254.169.254",  # AWS/GCP metadata
        "100.100.100.200",  # Alibaba Cloud metadata
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
