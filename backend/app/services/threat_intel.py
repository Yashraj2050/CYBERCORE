"""
CYBERCORE Backend — Threat Intelligence Service

Integrates with:
  1. VirusTotal — URL/Domain/File reputation
  2. Google Safe Browsing — Phishing/Malware detection
  3. URLhaus (abuse.ch) — Malware URL database (requires Auth-Key header)
  4. PhishTank — Phishing URL database

All API calls:
  - Use HTTPS only
  - Have configurable timeouts
  - Return structured results with source attribution
  - Never fabricate findings
  - Clearly mark unavailable checks
"""

import httpx
import hashlib
import base64
import logging
from typing import Optional
from datetime import datetime

from app.config import get_settings
from app.services.risk_scorer import ComponentScore, Confidence, FindingType

settings = get_settings()
logger = logging.getLogger(__name__)

# Timeouts
HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

async def check_virustotal_url(url: str) -> ComponentScore:
    """
    Check URL against VirusTotal.
    Uses the VT v3 API — submits URL identifier (base64-encoded).
    """
    if not settings.virustotal_api_key:
        return ComponentScore(
            name="VirusTotal URL",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={
                "error_type": "CONFIGURATION_ERROR",
                "sub_type": "MISSING_CREDENTIALS",
                "reason": "VirusTotal API key not configured",
            },
        )

    # VT v3 URL ID is URL-safe base64 of the URL without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            )

        if resp.status_code == 404:
            # URL not yet in VT database — submit for analysis
            return await _submit_url_to_virustotal(url)

        if resp.status_code in (401, 403):
            return ComponentScore(
                name="VirusTotal URL",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": resp.status_code,
                    "status_code": resp.status_code,
                    "error_type": "CONFIGURATION_ERROR",
                    "sub_type": "AUTHENTICATION_FAILURE",
                    "reason": f"VirusTotal authentication failed (HTTP {resp.status_code}). API key missing or invalid.",
                },
            )

        if resp.status_code == 400:
            return ComponentScore(
                name="VirusTotal URL",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": 400,
                    "status_code": 400,
                    "error_type": "REQUEST_ERROR",
                    "reason": "VirusTotal bad request (HTTP 400).",
                },
            )

        if resp.status_code == 429:
            return ComponentScore(
                name="VirusTotal URL",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": 429,
                    "status_code": 429,
                    "error_type": "RATE_LIMIT",
                    "reason": "VirusTotal rate limit reached",
                },
            )

        if resp.status_code >= 500:
            return ComponentScore(
                name="VirusTotal URL",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": resp.status_code,
                    "status_code": resp.status_code,
                    "error_type": "UPSTREAM_ERROR",
                    "reason": f"VirusTotal upstream error (HTTP {resp.status_code})",
                },
            )

        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception:
            return ComponentScore(
                name="VirusTotal URL",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "error_type": "MALFORMED_RESPONSE",
                    "reason": "Malformed JSON response from VirusTotal",
                },
            )
        return _parse_vt_url_result(data)

    except httpx.TimeoutException:
        logger.warning("VirusTotal request timed out for URL: %s", url)
        return ComponentScore(
            name="VirusTotal URL",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "TIMEOUT", "reason": "VirusTotal request timed out"},
        )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return ComponentScore(
            name="VirusTotal URL",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "OFFLINE", "reason": "VirusTotal service unreachable or connection failed"},
        )
    except Exception as e:
        logger.error("VirusTotal error: %s", type(e).__name__)
        return ComponentScore(
            name="VirusTotal URL",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "ERROR", "reason": f"VirusTotal unavailable: {type(e).__name__}"},
        )


async def _submit_url_to_virustotal(url: str) -> ComponentScore:
    """Submit a new URL to VirusTotal for analysis."""
    headers = {
        "x-apikey": settings.virustotal_api_key,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
            )
        resp.raise_for_status()
        # Return a pending unassessed result — scan just submitted, do not fabricate clean score
        return ComponentScore(
            name="VirusTotal URL",
            score=None,
            confidence=Confidence.LOW,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"status": "pending_analysis", "reason": "URL submitted to VirusTotal for analysis — results pending"},
            evidence=["URL submitted to VirusTotal; external reputation analysis is currently pending"],
        )
    except Exception:
        return ComponentScore(
            name="VirusTotal URL",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "ERROR", "reason": "Could not submit URL to VirusTotal"},
        )


def _parse_vt_url_result(data: dict) -> ComponentScore:
    """Parse VirusTotal URL analysis response."""
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        if total == 0:
            return ComponentScore(
                name="VirusTotal URL",
                score=None,
                confidence=Confidence.LOW,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={"stats": stats, "reason": "No engine analyses recorded in VirusTotal"},
            )

        detection_rate = (malicious + suspicious) / total

        # Calibrated scoring thresholds:
        # malicious >= 3 or rate >= 0.10 => CONFIRMED_THREAT
        # 1-2 malicious => SUSPICIOUS_INDICATOR (score >= 50, never ignored)
        # 0 malicious, suspicious > 0 => SUSPICIOUS_INDICATOR
        # 0 malicious, 0 suspicious => NO_KNOWN_DETECTION (score 5)
        if malicious == 0 and suspicious == 0:
            score = 5.0
            finding_type = FindingType.NO_KNOWN_DETECTION
            confidence = Confidence.HIGH
        elif malicious >= 3 or detection_rate >= 0.10:
            score = min(95.0, 70.0 + malicious * 2.0)
            finding_type = FindingType.CONFIRMED_THREAT
            confidence = Confidence.HIGH
        elif malicious >= 1:
            score = min(65.0, 50.0 + (malicious + suspicious) * 5.0)
            finding_type = FindingType.SUSPICIOUS_INDICATOR
            confidence = Confidence.MEDIUM
        else:
            score = min(50.0, 30.0 + suspicious * 5.0)
            finding_type = FindingType.SUSPICIOUS_INDICATOR
            confidence = Confidence.MEDIUM

        categories = attrs.get("categories", {})
        threat_names = list(attrs.get("popular_threat_classification", {}).get("popular_threat_name", []))

        return ComponentScore(
            name="VirusTotal URL",
            score=float(score),
            confidence=confidence,
            finding_type=finding_type,
            details={
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "detection_rate": round(detection_rate * 100, 1),
                "categories": categories,
            },
            evidence=[
                f"{malicious} of {total} security engines flagged this URL as malicious",
                *[f"Threat: {t}" for t in threat_names[:3]],
            ] if malicious > 0 else [f"0 of {total} engines detected any threat"],
        )
    except (KeyError, TypeError) as e:
        logger.error("Error parsing VT response: %s", str(e))
        return ComponentScore(
            name="VirusTotal URL",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "INVALID_RESPONSE", "reason": "Unexpected VirusTotal response format"},
        )


async def check_virustotal_file(sha256: str) -> ComponentScore:
    """Check a file hash against VirusTotal."""
    if not settings.virustotal_api_key:
        return ComponentScore(
            name="VirusTotal File",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={
                "error_type": "CONFIGURATION_ERROR",
                "sub_type": "MISSING_CREDENTIALS",
                "reason": "VirusTotal API key not configured",
            },
        )

    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers=headers,
            )

        if resp.status_code == 404:
            return ComponentScore(
                name="VirusTotal File",
                score=0,
                confidence=Confidence.LOW,
                finding_type=FindingType.NO_KNOWN_DETECTION,
                details={"reason": "File hash not found in VirusTotal database"},
                evidence=["File has no known detections in VirusTotal (hash not previously seen)"],
            )

        resp.raise_for_status()
        return _parse_vt_url_result(resp.json())

    except Exception as e:
        return ComponentScore(
            name="VirusTotal File",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"reason": str(e)},
        )


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

async def check_google_safe_browsing(url: str) -> ComponentScore:
    """
    Check URL against Google Safe Browsing v4 API.
    Detects MALWARE, SOCIAL_ENGINEERING (phishing), UNWANTED_SOFTWARE.
    """
    if not settings.google_safe_browsing_api_key:
        return ComponentScore(
            name="Google Safe Browsing",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={
                "error_type": "CONFIGURATION_ERROR",
                "sub_type": "MISSING_CREDENTIALS",
                "reason": "Google Safe Browsing API key not configured",
            },
        )

    payload = {
        "client": {"clientId": "cybercore", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={settings.google_safe_browsing_api_key}",
                json=payload,
            )

        if resp.status_code in (401, 403):
            return ComponentScore(
                name="Google Safe Browsing",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": resp.status_code,
                    "status_code": resp.status_code,
                    "error_type": "CONFIGURATION_ERROR",
                    "sub_type": "AUTHENTICATION_FAILURE",
                    "reason": f"Google Safe Browsing authentication failed (HTTP {resp.status_code})",
                },
            )

        if resp.status_code == 400:
            return ComponentScore(
                name="Google Safe Browsing",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": 400,
                    "status_code": 400,
                    "error_type": "REQUEST_ERROR",
                    "reason": "Google Safe Browsing API key invalid or malformed request (HTTP 400)",
                },
            )

        if resp.status_code == 429:
            return ComponentScore(
                name="Google Safe Browsing",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": 429,
                    "status_code": 429,
                    "error_type": "RATE_LIMIT",
                    "reason": "Google Safe Browsing rate limit reached (HTTP 429)",
                },
            )

        if resp.status_code >= 500:
            return ComponentScore(
                name="Google Safe Browsing",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": resp.status_code,
                    "status_code": resp.status_code,
                    "error_type": "UPSTREAM_ERROR",
                    "reason": f"Google Safe Browsing upstream error (HTTP {resp.status_code})",
                },
            )

        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception:
            return ComponentScore(
                name="Google Safe Browsing",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "error_type": "MALFORMED_RESPONSE",
                    "reason": "Malformed JSON response from Google Safe Browsing",
                },
            )

        matches = data.get("matches", [])
        if not matches:
            return ComponentScore(
                name="Google Safe Browsing",
                score=5.0,
                confidence=Confidence.HIGH,
                finding_type=FindingType.NO_KNOWN_DETECTION,
                details={"matches": []},
                evidence=["No threats detected by Google Safe Browsing"],
            )

        threat_types = [m.get("threatType", "UNKNOWN") for m in matches]
        score = 95.0 if "MALWARE" in threat_types else 90.0
        return ComponentScore(
            name="Google Safe Browsing",
            score=float(score),
            confidence=Confidence.HIGH,
            finding_type=FindingType.CONFIRMED_THREAT,
            details={"threat_types": threat_types},
            evidence=[f"Google Safe Browsing: {', '.join(set(threat_types))} detected"],
        )

    except httpx.TimeoutException:
        return ComponentScore(
            name="Google Safe Browsing",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "TIMEOUT", "reason": "Google Safe Browsing request timed out"},
        )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return ComponentScore(
            name="Google Safe Browsing",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "OFFLINE", "reason": "Google Safe Browsing service unreachable"},
        )
    except Exception as e:
        logger.error("GSB error: %s", type(e).__name__)
        return ComponentScore(
            name="Google Safe Browsing",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "ERROR", "reason": f"Google Safe Browsing unavailable: {type(e).__name__}"},
        )


# ---------------------------------------------------------------------------
# URLhaus (abuse.ch) — Requires Auth-Key
# ---------------------------------------------------------------------------

async def check_urlhaus(url: str) -> ComponentScore:
    """
    Check URL against URLhaus malware database.
    URLhaus is maintained by abuse.ch and requires an Auth-Key request header.
    """
    if not settings.urlhaus_auth_key:
        return ComponentScore(
            name="URLhaus",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={
                "error_type": "CONFIGURATION_ERROR",
                "sub_type": "MISSING_CREDENTIALS",
                "reason": "URLhaus Auth-Key not configured",
            },
        )

    payload = {"url": url}
    headers = {"Auth-Key": settings.urlhaus_auth_key}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data=payload,
                headers=headers,
            )
        if resp.status_code in (401, 403):
            return ComponentScore(
                name="URLhaus",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": resp.status_code,
                    "status_code": resp.status_code,
                    "error_type": "CONFIGURATION_ERROR",
                    "sub_type": "AUTHENTICATION_FAILURE",
                    "reason": f"URLhaus authentication failed (HTTP {resp.status_code}). Auth-Key may be invalid or expired.",
                },
            )
        if resp.status_code == 429:
            return ComponentScore(
                name="URLhaus",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": 429,
                    "status_code": 429,
                    "error_type": "RATE_LIMIT",
                    "reason": "URLhaus rate limit reached (HTTP 429)",
                },
            )
        if resp.status_code == 400:
            return ComponentScore(
                name="URLhaus",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": 400,
                    "status_code": 400,
                    "error_type": "REQUEST_ERROR",
                    "reason": "URLhaus request format error (HTTP 400)",
                },
            )
        if resp.status_code >= 500:
            return ComponentScore(
                name="URLhaus",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "status": resp.status_code,
                    "status_code": resp.status_code,
                    "error_type": "UPSTREAM_ERROR",
                    "reason": f"URLhaus upstream outage or error (HTTP {resp.status_code})",
                },
            )

        resp.raise_for_status()

        try:
            data = resp.json()
        except Exception:
            return ComponentScore(
                name="URLhaus",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "error_type": "MALFORMED_RESPONSE",
                    "reason": "Malformed JSON response from URLhaus",
                },
            )

        if not isinstance(data, dict):
            return ComponentScore(
                name="URLhaus",
                score=None,
                confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY,
                details={
                    "error_type": "MALFORMED_RESPONSE",
                    "reason": "Unexpected response format from URLhaus (expected JSON object)",
                },
            )

        query_status = data.get("query_status", "")

        if query_status in ("not_in_database", "no_results"):
            return ComponentScore(
                name="URLhaus",
                score=5.0,
                confidence=Confidence.HIGH,
                finding_type=FindingType.NO_KNOWN_DETECTION,
                details={"status": query_status},
                evidence=["URL not found in URLhaus malware database"],
            )

        if query_status in ("is_malware", "online"):
            threat = data.get("threat", "UNKNOWN")
            tags = data.get("tags", [])
            return ComponentScore(
                name="URLhaus",
                score=95.0,
                confidence=Confidence.HIGH,
                finding_type=FindingType.CONFIRMED_THREAT,
                details={"threat": threat, "tags": tags, "urlhaus_status": data.get("url_status")},
                evidence=[
                    f"URLhaus confirmed malware URL — Threat: {threat}",
                    *([f"Tags: {', '.join(tags)}"] if tags else []),
                ],
            )

        return ComponentScore(
            name="URLhaus",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={
                "error_type": "UNEXPECTED_STATUS",
                "query_status": query_status,
                "reason": f"Unexpected URLhaus query status: {query_status}",
            },
        )

    except httpx.TimeoutException:
        logger.warning("URLhaus request timed out for URL: %s", url)
        return ComponentScore(
            name="URLhaus",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "TIMEOUT", "reason": "URLhaus request timed out"},
        )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return ComponentScore(
            name="URLhaus",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "OFFLINE", "reason": "URLhaus service unreachable or connection failed"},
        )
    except Exception as e:
        logger.error("URLhaus error: %s", type(e).__name__)
        return ComponentScore(
            name="URLhaus",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"error_type": "ERROR", "reason": f"URLhaus unavailable: {type(e).__name__}"},
        )


# ---------------------------------------------------------------------------
# Combined Threat Intelligence Score
# ---------------------------------------------------------------------------

def aggregate_threat_intel(
    vt: ComponentScore,
    gsb: ComponentScore,
    urlhaus: ComponentScore,
) -> ComponentScore:
    """
    Combine VirusTotal, Google Safe Browsing, and URLhaus results
    into a single threat intelligence component score.

    Logic:
    - Any CONFIRMED_THREAT from any source → score is max of confirmed threats
    - GSB confirmation is weighted heavily (authoritative)
    - URLhaus confirmation is weighted heavily (confirmed malware)
    - VT score is used as the primary signal
    """
    available = [s for s in [vt, gsb, urlhaus] if s.is_available]

    def _source_diag(s: ComponentScore):
        if s.is_available:
            return s.details
        return s.details.get("error_type") or s.details.get("reason", "unavailable")

    if not available:
        sources_status = {
            "virustotal": _source_diag(vt),
            "google_safe_browsing": _source_diag(gsb),
            "urlhaus": _source_diag(urlhaus),
        }
        return ComponentScore(
            name="Threat Intelligence",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"sources": sources_status, "error_type": "ALL_PROVIDERS_UNAVAILABLE"},
            evidence=["All external threat intelligence providers are unavailable or unconfigured"],
        )

    # If any authoritative source confirms a threat, score high
    confirmed_threats = [s for s in available if s.finding_type == FindingType.CONFIRMED_THREAT]
    if confirmed_threats:
        max_score = max(s.score for s in confirmed_threats)
        all_evidence = []
        for s in confirmed_threats:
            all_evidence.extend(s.evidence)
        return ComponentScore(
            name="Threat Intelligence",
            score=max_score,
            confidence=Confidence.HIGH,
            finding_type=FindingType.CONFIRMED_THREAT,
            details={
                "sources": {
                    "virustotal": _source_diag(vt),
                    "gsb": _source_diag(gsb),
                    "google_safe_browsing": _source_diag(gsb),
                    "urlhaus": _source_diag(urlhaus),
                }
            },
            evidence=all_evidence,
        )

    # Weighted average of available scores
    source_weights = {"VirusTotal URL": 0.50, "Google Safe Browsing": 0.30, "URLhaus": 0.20}
    total_weight = sum(source_weights.get(s.name, 0.33) for s in available)
    weighted = sum(
        s.score * source_weights.get(s.name, 0.33) / total_weight
        for s in available
    )

    suspicious = [s for s in available if s.finding_type == FindingType.SUSPICIOUS_INDICATOR]
    finding_type = (
        FindingType.SUSPICIOUS_INDICATOR if suspicious
        else FindingType.NO_KNOWN_DETECTION
    )

    coverage = len(available) / 3
    confidence = (
        Confidence.HIGH if coverage >= 0.66
        else Confidence.MEDIUM if coverage >= 0.33
        else Confidence.LOW
    )

    return ComponentScore(
        name="Threat Intelligence",
        score=round(weighted, 1),
        confidence=confidence,
        finding_type=finding_type,
        details={
            "sources_checked": len(available),
            "sources_total": 3,
            "sources": {
                "virustotal": _source_diag(vt),
                "gsb": _source_diag(gsb),
                "google_safe_browsing": _source_diag(gsb),
                "urlhaus": _source_diag(urlhaus),
            },
        },
        evidence=[e for s in available for e in s.evidence],
    )
