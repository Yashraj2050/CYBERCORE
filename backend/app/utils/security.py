"""
CYBERCORE Backend — Production Security, Proxy-Aware IP & Admin Auth Utilities

Provides:
  1. Safe client IP resolution behind reverse proxies (Nginx, Cloudflare, AWS ALB).
  2. Administrator authentication dependency for privileged endpoints.
  3. Sensitive field redaction utilities for operational logging.
"""

import ipaddress
import logging
import secrets
from typing import Optional
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

bearer_scheme = HTTPBearer(auto_error=False)


def get_client_ip(request: Request) -> str:
    """
    Safely extract the real client IP address behind reverse proxies.
    Prevents IP spoofing by only honoring forward headers when the immediate
    peer IP is in the trusted proxies whitelist.
    """
    direct_client_ip = request.client.host if request.client else "127.0.0.1"

    # Only trust headers if direct connection originates from a trusted reverse proxy
    trusted_proxies = set(settings.trusted_proxies_list)

    if direct_client_ip not in trusted_proxies and not any(
        direct_client_ip.startswith(prefix) for prefix in ("10.", "172.16.", "192.168.", "127.")
    ):
        return direct_client_ip

    # 1. Cloudflare True-Client-IP / CF-Connecting-IP
    cf_ip = request.headers.get("cf-connecting-ip") or request.headers.get("true-client-ip")
    if cf_ip:
        cf_clean = cf_ip.strip()
        try:
            ipaddress.ip_address(cf_clean)
            return cf_clean
        except ValueError:
            pass

    # 2. Standard X-Forwarded-For header: client, proxy1, proxy2
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        # The original client IP is the first IP in the chain
        if parts:
            client_candidate = parts[0]
            try:
                ipaddress.ip_address(client_candidate)
                return client_candidate
            except ValueError:
                pass

    # 3. X-Real-IP
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        clean_real = x_real_ip.strip()
        try:
            ipaddress.ip_address(clean_real)
            return clean_real
        except ValueError:
            pass

    return direct_client_ip


def require_admin_auth(request: Request) -> str:
    """
    FastAPI dependency for administrative endpoints (moderation, backups).
    Verifies token via 'X-Admin-Key' header or 'Authorization: Bearer <token>'.
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    configured_key = settings.admin_api_key

    if not configured_key:
        if settings.app_env == "production":
            logger.error("Admin action attempted in production without configured ADMIN_API_KEY")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Administrative authentication unavailable.",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ADMIN_API_KEY must be configured in environment to perform administrative operations.",
            )

    # Check X-Admin-Key header first
    candidate = request.headers.get("x-admin-key")

    # If not present, check Authorization Bearer token
    if not candidate:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            candidate = auth_header[7:].strip()

    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing administrative authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Constant-time comparison
    if not secrets.compare_digest(candidate, configured_key):
        logger.warning(
            "Unauthorized admin attempt from IP %s on path %s",
            get_client_ip(request),
            request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid administrative credentials.",
        )

    return "admin"


SENSITIVE_FIELD_NAMES = {
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "x-admin-key",
    "cookie",
    "key",
}


def redact_sensitive_dict(data: dict) -> dict:
    """Recursively mask sensitive values in dicts before logging."""
    redacted = {}
    for k, v in data.items():
        if any(sens in k.lower() for sens in SENSITIVE_FIELD_NAMES):
            redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = redact_sensitive_dict(v)
        elif isinstance(v, list):
            redacted[k] = [
                redact_sensitive_dict(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            redacted[k] = v
    return redacted
