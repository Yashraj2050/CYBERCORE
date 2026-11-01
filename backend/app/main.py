"""
CYBERCORE Backend — Main Application Entry Point

Sets up FastAPI with:
  - CORS middleware
  - Rate limiting (slowapi)
  - Security headers middleware
  - All routers
  - Global error handlers
"""

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import get_settings
from app.limiter import limiter
from app.routers import scan, password, messages, ip_domain, files, ai_chat, dashboard
from app.services.report_store import report_store
from app.utils.security import get_client_ip

settings = get_settings()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("CYBERCORE backend starting up...")
    logger.info("Environment: %s", settings.app_env)

    # Production safety gate: never allow placeholder secret in production
    if settings.app_env == "production":
        if settings.app_secret_key in {"CHANGE_ME_IN_PRODUCTION", ""}:
            raise RuntimeError(
                "FATAL: Default APP_SECRET_KEY cannot be used in production! "
                "Provide a cryptographically secure key via APP_SECRET_KEY."
            )
        if not settings.admin_api_key:
            logger.warning(
                "SECURITY WARNING: ADMIN_API_KEY is not configured in production. "
                "All administrative moderation and backup endpoints will be locked."
            )

    db_healthy, db_msg, db_meta = report_store.check_health()
    if not db_healthy:
        logger.error("FATAL: Database health check failed on startup: %s", db_msg)
    else:
        logger.info("Database initialized successfully: %s (Mode: %s)", report_store.db_path, db_meta.get("mode"))

    logger.info("VirusTotal: %s", "configured" if settings.virustotal_api_key else "NOT configured")
    logger.info("Google Safe Browsing: %s", "configured" if settings.google_safe_browsing_api_key else "NOT configured")
    logger.info("AI Provider: %s (%s)", settings.ai_provider, settings.ai_model)
    yield
    logger.info("CYBERCORE backend shutting down...")


# ─────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="CYBERCORE API",
    description="AI-Powered Cybersecurity Platform — Backend API",
    version="1.0.0",
    docs_url="/api/docs" if settings.app_env == "development" else None,
    redoc_url="/api/redoc" if settings.app_env == "development" else None,
    lifespan=lifespan,
)

# ─────────────────────────────────────────────────────────────
# Middleware
# ─────────────────────────────────────────────────────────────

# CORS — allow web app, local dev ports, and Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(https?://(localhost|127\.0\.0\.1)(:\d+)?|chrome-extension://.*)$",
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def operational_telemetry_and_security(request: Request, call_next):
    """
    Structured operational telemetry, request tracing, and security headers.
    Captures: Request ID, Method, Path, Client IP, Status, and Execution Duration.
    Never logs sensitive payloads, credentials, or file bytes.
    """
    # 1. Tracing Request ID
    req_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
    request.state.request_id = req_id

    # 2. Timing
    start_time = time.perf_counter()
    client_ip = get_client_ip(request)

    response = await call_next(request)

    duration_ms = (time.perf_counter() - start_time) * 1000.0

    # 3. Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

    # Remove server identification
    if "server" in response.headers:
        del response.headers["server"]

    # 4. Structured operational log entry
    logger.info(
        "ACCESS | id=%s ip=%s method=%s path=%s status=%d duration=%.2fms",
        req_id,
        client_ip,
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )

    return response


# ─────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────
API_PREFIX = "/api/v1"

app.include_router(scan.router, prefix=API_PREFIX)
app.include_router(password.router, prefix=API_PREFIX)
app.include_router(messages.router, prefix=API_PREFIX)
app.include_router(ip_domain.router, prefix=API_PREFIX)
app.include_router(files.router, prefix=API_PREFIX)
app.include_router(ai_chat.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)


# ─────────────────────────────────────────────────────────────
# Global Exception Handler
# ─────────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "unknown")
    logger.error("Unhandled exception [id=%s]: %s %s — %s", req_id, request.method, request.url, str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred. Please try again.", "request_id": req_id},
    )


# ─────────────────────────────────────────────────────────────
# Production-Grade Health & Dependency Check
# ─────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["Health"])
async def health_check():
    """
    Comprehensive system health monitor distinguishing:
      1. Application web process availability
      2. Database storage availability & integrity
      3. External intelligence service configurations
    """
    db_healthy, db_msg, db_meta = report_store.check_health()

    overall_status = "healthy" if db_healthy else "unhealthy"
    status_code = status.HTTP_200_OK if db_healthy else status.HTTP_503_SERVICE_UNAVAILABLE

    payload = {
        "status": overall_status,
        "service": "CYBERCORE API",
        "version": "1.0.0",
        "environment": settings.app_env,
        "components": {
            "application": {"status": "operational"},
            "database": {
                "status": "operational" if db_healthy else "down",
                "engine": db_meta.get("engine", "sqlite3"),
                "mode": db_meta.get("mode", "WAL"),
                "integrity": db_msg,
                "total_reports": db_meta.get("total_reports", 0),
            },
            "external_intelligence": {
                "virustotal": "configured" if settings.virustotal_api_key else "unconfigured",
                "google_safe_browsing": "configured" if settings.google_safe_browsing_api_key else "unconfigured",
                "ai_assistant": "configured" if (settings.openai_api_key or settings.gemini_api_key) else "unconfigured",
            },
        },
        "api_keys": {
            "virustotal": bool(settings.virustotal_api_key),
            "google_safe_browsing": bool(settings.google_safe_browsing_api_key),
            "ai": bool(settings.openai_api_key or settings.gemini_api_key),
        },
    }

    return JSONResponse(status_code=status_code, content=payload)


@app.get("/", tags=["Root"])
async def root():
    return {"message": "CYBERCORE API — see /api/docs for documentation"}
