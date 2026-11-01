"""
CYBERCORE Backend — Website Scanner Router
Handles all URL scan API endpoints.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import JSONResponse

from app.models.scan import ScanRequest, ScanResponse, ThreatReportRequest
from app.services.url_scanner import scan_url
from app.utils.validators import ValidationError
from app.config import get_settings
from app.limiter import limiter

router = APIRouter(prefix="/scan", tags=["Website Scanner"])
settings = get_settings()
logger = logging.getLogger(__name__)

# Simple in-memory cache for scan results (replace with Redis in production)
_scan_cache: dict = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


@router.post("/", response_model=dict, summary="Scan a URL for security threats")
@limiter.limit("30/minute")
async def scan_website(
    scan_req: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """
    Analyze a URL for security threats.

    - Validates the URL and applies SSRF protection
    - Runs threat intelligence, SSL, DNS, and pattern checks concurrently
    - Returns a comprehensive security report with risk score

    **Rate limited**: 30 requests per minute per IP
    """
    try:
        # Check cache first (by normalized URL)
        url_lower = scan_req.url.lower()
        if url_lower in _scan_cache:
            cached = _scan_cache[url_lower]
            import time
            if time.time() - cached["_cached_at"] < CACHE_TTL_SECONDS:
                result = cached.copy()
                result["from_cache"] = True
                result.pop("_cached_at", None)
                return result

        # Run scan
        result = await scan_url(scan_req.url, source=scan_req.source)

        # Cache result
        import time
        _scan_cache[url_lower] = {**result, "_cached_at": time.time()}

        # Prune old cache entries in background
        background_tasks.add_task(_prune_cache)

        return {**result, "from_cache": False}

    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Scan error for URL %s: %s", scan_req.url, str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An error occurred during URL analysis. Please try again."
        )


@router.get("/{scan_id}", summary="Retrieve a scan result by ID")
async def get_scan(scan_id: str):
    """Retrieve a previously completed scan result."""
    # Look up in cache by scan_id
    for url, cached in _scan_cache.items():
        if cached.get("scan_id") == scan_id:
            result = cached.copy()
            result.pop("_cached_at", None)
            result["from_cache"] = True
            return result

    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")


@router.get("/domain/{domain}", summary="Get latest cached scan for a domain")
async def get_scan_by_domain(domain: str):
    """Get the most recent cached scan result for a domain."""
    import time
    best = None
    best_time = 0

    for url, cached in _scan_cache.items():
        if cached.get("domain", "").lower() == domain.lower():
            cached_at = cached.get("_cached_at", 0)
            if cached_at > best_time:
                best = cached
                best_time = cached_at

    if not best:
        raise HTTPException(
            status_code=404,
            detail=f"No cached scan found for domain: {domain}"
        )

    result = best.copy()
    result.pop("_cached_at", None)
    result["from_cache"] = True
    return result


@router.post("/report", summary="Report a malicious URL")
@limiter.limit("5/minute")
async def report_threat(report: ThreatReportRequest, request: Request):
    """
    Allow users to report a URL as a threat.
    Persisted to the CYBERCORE SQLite database with duplicate detection.
    """
    from app.utils.validators import validate_url, ValidationError as VE
    from app.services.report_store import report_store
    try:
        validated_url, domain = validate_url(report.url)
    except VE as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        outcome, stored_report = report_store.add_report(
            url=validated_url,
            threat_type=report.threat_type,
            source="scan_api",
        )
    except Exception as e:
        logger.exception("Failed to store threat report from scan router: %s", str(e))
        raise HTTPException(status_code=500, detail="Database failure storing report.")

    return {
        "status": "received",
        "message": "Thank you for your report. It will be reviewed by our security team.",
        "url": validated_url,
        "threat_type": report.threat_type,
        "report_id": stored_report.get("id"),
        "duplicate": (outcome == "DUPLICATE"),
    }


def _prune_cache():
    """Remove expired cache entries."""
    import time
    now = time.time()
    expired = [k for k, v in _scan_cache.items() if now - v.get("_cached_at", 0) > CACHE_TTL_SECONDS]
    for k in expired:
        _scan_cache.pop(k, None)
