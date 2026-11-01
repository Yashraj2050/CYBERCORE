"""
CYBERCORE Backend — Password Router
Handles HIBP k-anonymity range check.

CRITICAL SECURITY DESIGN:
  Passwords are NEVER sent to the backend.
  The frontend computes SHA-1 of the password,
  sends only the first 5 characters (prefix) to HIBP,
  and checks if the full hash suffix appears in the response.

  This module simply proxies the HIBP range API to avoid CORS issues
  and to keep the API key (if any) server-side.

  The actual password never leaves the user's browser.
"""

import httpx
import logging
from fastapi import APIRouter, HTTPException, Path, Request

from app.limiter import limiter

router = APIRouter(prefix="/password", tags=["Password Security"])
logger = logging.getLogger(__name__)

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


@router.get(
    "/breached/{hash_prefix}",
    summary="Check if a password hash prefix appears in HIBP breach database",
)
@limiter.limit("60/minute")
async def check_password_breach(
    request: Request,
    hash_prefix: str = Path(
        ...,
        min_length=5,
        max_length=5,
        pattern="^[0-9A-Fa-f]{5}$",
        description="First 5 characters of the SHA-1 hash of the password (k-anonymity)",
    )
):
    """
    Privacy-preserving password breach check using HIBP k-anonymity.

    The client sends only the first 5 hex characters of the password's SHA-1 hash.
    This endpoint retrieves all matching hash suffixes from HIBP.
    The client checks locally whether the full hash appears in the results.

    The actual password is NEVER transmitted.
    """
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"{HIBP_RANGE_URL}{hash_prefix.upper()}",
                headers={
                    "User-Agent": "CYBERCORE-PasswordChecker/1.0",
                    "Add-Padding": "true",  # Protects against traffic analysis
                },
            )
        resp.raise_for_status()
        # Return raw HIBP response — list of SUFFIX:COUNT pairs
        return {"data": resp.text, "hash_prefix": hash_prefix.upper()}

    except httpx.TimeoutException:
        raise HTTPException(status_code=503, detail="HIBP service timed out. Please try again.")
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"HIBP returned error: {e.response.status_code}"
        )
    except Exception as e:
        logger.error("HIBP check error: %s", str(e))
        raise HTTPException(status_code=503, detail="Breach check service unavailable.")
