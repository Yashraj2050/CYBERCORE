"""
CYBERCORE Backend — Centralized Rate Limiter Instance
Shared across FastAPI application entry point and individual route decorators.
"""

from slowapi import Limiter
from app.config import get_settings
from app.utils.security import get_client_ip

settings = get_settings()

limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"],
)
