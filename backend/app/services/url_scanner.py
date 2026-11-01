"""
CYBERCORE Backend — URL Scanner (Core Engine)

Orchestrates the full URL security analysis pipeline:
  1. URL Validation + SSRF Protection
  2. SSL/TLS Check
  3. DNS Analysis + Domain Reputation (RDAP)
  4. Threat Intelligence (VirusTotal + GSB + URLhaus)
  5. URL Pattern Analysis
  6. Redirect Analysis
  7. Risk Score Calculation

All checks run concurrently where safe to do so.
Results are structured and cached.
"""

import asyncio
import logging
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional
import httpx

from app.config import get_settings
from app.utils.validators import validate_url, ValidationError
from app.services.threat_intel import (
    check_virustotal_url,
    check_google_safe_browsing,
    check_urlhaus,
    aggregate_threat_intel,
)
from app.services.ssl_checker import check_ssl_tls
from app.services.dns_analyzer import analyze_dns, get_domain_rdap, build_domain_reputation_score
from app.services.risk_scorer import (
    calculate_risk_score,
    analyze_url_patterns,
    ComponentScore,
    Confidence,
    FindingType,
)

settings = get_settings()
logger = logging.getLogger(__name__)

MAX_REDIRECTS = 5
REDIRECT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


async def scan_url(url: str, source: str = "web") -> dict:
    """
    Main URL scanning function — runs full security analysis.

    Args:
        url: The URL to scan (will be validated and normalized)
        source: 'web' or 'extension'

    Returns:
        Structured scan result dict ready for API response and DB storage

    Raises:
        ValidationError: If URL fails security validation
    """
    # Step 1: Validate URL (SSRF protection happens here)
    normalized_url, domain = validate_url(url)
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    from urllib.parse import urlparse
    parsed = urlparse(normalized_url)
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)

    logger.info("Starting scan [%s] for domain: %s (scheme: %s, port: %d)", scan_id, domain, scheme, port)

    # Step 2: Run independent checks concurrently
    (
        vt_result,
        gsb_result,
        urlhaus_result,
        ssl_result,
        dns_data,
        rdap_data,
    ) = await asyncio.gather(
        check_virustotal_url(normalized_url),
        check_google_safe_browsing(normalized_url),
        check_urlhaus(normalized_url),
        check_ssl_tls(domain, port=port, scheme=scheme),
        analyze_dns(domain),
        get_domain_rdap(domain),
        return_exceptions=True,
    )

    # Handle exceptions from gather (shouldn't happen but be safe)
    vt_result = _ensure_component(vt_result, "VirusTotal URL")
    gsb_result = _ensure_component(gsb_result, "Google Safe Browsing")
    urlhaus_result = _ensure_component(urlhaus_result, "URLhaus")
    ssl_result = _ensure_component(ssl_result, "SSL/TLS")
    dns_data = dns_data if isinstance(dns_data, dict) else {}
    rdap_data = rdap_data if isinstance(rdap_data, dict) else {}

    # Step 3: Aggregate threat intelligence
    threat_intel_score = aggregate_threat_intel(vt_result, gsb_result, urlhaus_result)

    # Step 4: Domain reputation from RDAP
    domain_reputation_score = await build_domain_reputation_score(domain, rdap_data)

    # Step 5: URL pattern analysis (synchronous, deterministic)
    url_pattern_score = analyze_url_patterns(normalized_url, domain)

    # Step 6: Redirect analysis
    redirect_score = await analyze_redirects(normalized_url)

    # Step 7: Phishing/Malware indicator score
    phishing_malware_score = _build_phishing_malware_score(
        vt_result, gsb_result, urlhaus_result, url_pattern_score
    )

    # Step 8: Calculate weighted risk score
    components = {
        "threat_intelligence": threat_intel_score,
        "phishing_malware": phishing_malware_score,
        "domain_reputation": domain_reputation_score,
        "url_patterns": url_pattern_score,
        "ssl_tls": ssl_result,
        "redirect_analysis": redirect_score,
    }

    risk_result = calculate_risk_score(components)
    completed_at = datetime.now(timezone.utc)

    malware_status, is_malware = _get_malware_status(vt_result, urlhaus_result, url_pattern_score)
    phishing_status, is_phishing = _get_phishing_status(vt_result, gsb_result, url_pattern_score)

    return {
        "scan_id": scan_id,
        "url": normalized_url,
        "domain": domain,
        "risk_score": risk_result["score"],
        "risk_category": risk_result["category"],
        "confidence": risk_result["confidence"],
        "coverage_percent": risk_result["coverage"],
        "is_phishing": is_phishing,
        "is_malware": is_malware,
        "phishing_status": phishing_status,
        "malware_status": malware_status,
        "ssl_valid": ssl_result.details.get("valid") if ssl_result.is_available else None,
        "components": risk_result["components"],
        "unavailable_checks": risk_result["unavailable_checks"],
        "dns_details": dns_data,
        "whois_details": rdap_data,
        "source": source,
        "scanned_at": completed_at.isoformat(),
        "scan_duration_ms": int((completed_at - started_at).total_seconds() * 1000),
        "recommended_actions": _get_recommendations(risk_result["score"], risk_result["category"]),
    }


def _ensure_component(result, name: str) -> ComponentScore:
    """Convert exceptions to UNAVAILABLE ComponentScore."""
    if isinstance(result, ComponentScore):
        return result
    if isinstance(result, Exception):
        logger.error("Component %s failed: %s", name, str(result))
    return ComponentScore(
        name=name,
        score=None,
        confidence=Confidence.UNAVAILABLE,
        finding_type=FindingType.UNABLE_TO_VERIFY,
        details={"reason": "Check failed unexpectedly"},
    )


async def analyze_redirects(url: str) -> ComponentScore:
    """
    Follow redirects and analyze the redirect chain for suspicious patterns.
    """
    redirect_chain = []
    issues = []
    suspicious = False

    try:
        async with httpx.AsyncClient(
            timeout=REDIRECT_TIMEOUT,
            follow_redirects=False,
            verify=True,
        ) as client:
            current_url = url
            for i in range(MAX_REDIRECTS + 1):
                try:
                    resp = await client.get(current_url, headers={"User-Agent": "CYBERCORE-Scanner/1.0"})
                except httpx.ConnectError:
                    break
                except Exception:
                    break

                redirect_chain.append({
                    "url": current_url,
                    "status_code": resp.status_code,
                })

                if resp.status_code in (301, 302, 303, 307, 308):
                    next_url = resp.headers.get("location", "")
                    if not next_url:
                        break
                    # Resolve relative redirects
                    if next_url.startswith("/"):
                        from urllib.parse import urlparse
                        parsed = urlparse(current_url)
                        next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"

                    # Validate redirect target
                    try:
                        from app.utils.validators import validate_url
                        _, redirect_domain = validate_url(next_url)
                    except ValidationError as e:
                        issues.append(f"Redirect to blocked destination: {str(e)}")
                        suspicious = True
                        break

                    current_url = next_url
                else:
                    break

    except Exception as e:
        return ComponentScore(
            name="Redirect Analysis",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"reason": f"Could not follow redirects: {type(e).__name__}"},
        )

    redirect_count = len(redirect_chain) - 1 if len(redirect_chain) > 1 else 0

    if suspicious:
        score = 80.0
        finding_type = FindingType.SUSPICIOUS_INDICATOR
    elif redirect_count > 3:
        score = 40.0
        issues.append(f"Excessive redirect chain: {redirect_count} redirects")
        finding_type = FindingType.SUSPICIOUS_INDICATOR
    elif redirect_count > 1:
        score = 15.0
        finding_type = FindingType.HEURISTIC_ASSESSMENT
    else:
        score = 0.0
        finding_type = FindingType.NO_KNOWN_DETECTION

    return ComponentScore(
        name="Redirect Analysis",
        score=score,
        confidence=Confidence.MEDIUM,
        finding_type=finding_type,
        details={
            "redirect_count": redirect_count,
            "redirect_chain": redirect_chain,
        },
        evidence=issues if issues else [
            f"{redirect_count} redirect(s) detected" if redirect_count > 0
            else "No suspicious redirects detected"
        ],
    )


def _build_phishing_malware_score(
    vt: ComponentScore,
    gsb: ComponentScore,
    urlhaus: ComponentScore,
    url_patterns: ComponentScore,
) -> ComponentScore:
    """
    Synthesize a phishing & malware indicator score.
    Strictly separates external confirmed detection from heuristic detections.
    """
    external_indicators = []
    heuristic_indicators = []
    max_external_score = 0.0
    has_confirmed_external = False

    if gsb.is_available and gsb.score is not None and gsb.score >= 70:
        if gsb.finding_type == FindingType.CONFIRMED_THREAT:
            external_indicators.append("Google Safe Browsing confirmed threat detection")
            max_external_score = max(max_external_score, gsb.score)
            has_confirmed_external = True

    if urlhaus.is_available and urlhaus.score is not None and urlhaus.score >= 70:
        if urlhaus.finding_type == FindingType.CONFIRMED_THREAT:
            external_indicators.append("URLhaus confirmed malware distribution")
            max_external_score = max(max_external_score, urlhaus.score)
            has_confirmed_external = True

    if vt.is_available and vt.score is not None and vt.score >= 40:
        if vt.finding_type == FindingType.CONFIRMED_THREAT:
            external_indicators.append(f"VirusTotal confirmed detection: score {vt.score:.0f}/100")
            max_external_score = max(max_external_score, vt.score)
            has_confirmed_external = True
        elif vt.finding_type == FindingType.SUSPICIOUS_INDICATOR:
            external_indicators.append(f"VirusTotal suspicious indicator: score {vt.score:.0f}/100")
            max_external_score = max(max_external_score, vt.score)

    # Heuristic indicators
    heuristic_score = 0.0
    if url_patterns.is_available and url_patterns.score is not None:
        if url_patterns.finding_type in (FindingType.HEURISTIC_HIGH_RISK, FindingType.CONFIRMED_THREAT):
            heuristic_indicators.extend(url_patterns.evidence[:3])
            heuristic_score = url_patterns.score
        elif url_patterns.score >= 50:
            heuristic_indicators.extend(url_patterns.evidence[:2])
            heuristic_score = url_patterns.score * 0.8

    external_available = any(s.is_available for s in (vt, gsb, urlhaus))

    # Case 1: External authoritative source confirmed a threat
    if has_confirmed_external:
        return ComponentScore(
            name="Phishing & Malware",
            score=min(max_external_score, 95.0),
            confidence=Confidence.HIGH,
            finding_type=FindingType.CONFIRMED_THREAT,
            details={
                "indicator_count": len(external_indicators),
                "has_external_confirmation": True,
            },
            evidence=external_indicators + heuristic_indicators[:1],
        )

    # Case 2: Heuristic high risk detected, but NO external confirmation
    if heuristic_indicators and heuristic_score >= 70:
        return ComponentScore(
            name="Phishing & Malware",
            score=min(heuristic_score, 80.0),
            confidence=Confidence.MEDIUM,
            finding_type=FindingType.HEURISTIC_HIGH_RISK,
            details={
                "indicator_count": len(heuristic_indicators),
                "has_external_confirmation": False,
                "heuristic_suspected": True,
            },
            evidence=heuristic_indicators,
        )

    # Case 3: Suspicious indicators from external or heuristics (< 70)
    all_indicators = external_indicators + heuristic_indicators
    if all_indicators:
        max_score = max(max_external_score, heuristic_score)
        return ComponentScore(
            name="Phishing & Malware",
            score=min(max_score, 65.0),
            confidence=Confidence.MEDIUM,
            finding_type=FindingType.SUSPICIOUS_INDICATOR,
            details={"indicator_count": len(all_indicators)},
            evidence=all_indicators,
        )

    # Case 4: No indicators detected
    if not external_available:
        return ComponentScore(
            name="Phishing & Malware",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"reason": "All external threat intelligence feeds are unavailable"},
            evidence=["Threat intelligence feeds unavailable — unable to verify phishing/malware status"],
        )

    return ComponentScore(
        name="Phishing & Malware",
        score=0.0,
        confidence=Confidence.MEDIUM if sum(1 for s in (vt, gsb, urlhaus) if s.is_available) == 1 else Confidence.HIGH,
        finding_type=FindingType.NO_KNOWN_DETECTION,
        details={},
        evidence=["No phishing or malware indicators detected by available feeds"],
    )


def _get_malware_status(
    vt: ComponentScore,
    urlhaus: ComponentScore,
    patterns: Optional[ComponentScore] = None,
) -> Tuple[str, Optional[bool]]:
    """
    Determine malware status with strict separation between confirmed detection and heuristics.

    Returns:
        Tuple[str, Optional[bool]]: (malware_status, is_malware)
        malware_status in ("CONFIRMED_MALWARE", "SUSPECTED_MALWARE", "NO_KNOWN_DETECTION", "UNVERIFIED")
        is_malware is True ONLY for CONFIRMED_MALWARE.
    """
    # 1. External Confirmed Malware
    if urlhaus.is_available and urlhaus.finding_type == FindingType.CONFIRMED_THREAT:
        return "CONFIRMED_MALWARE", True
    if vt.is_available and vt.finding_type == FindingType.CONFIRMED_THREAT:
        categories = vt.details.get("categories", {})
        if any("malware" in str(v).lower() for v in categories.values()):
            return "CONFIRMED_MALWARE", True

    # 2. Heuristic Suspected Payload / Malware (Do NOT claim confirmed malware!)
    if patterns and patterns.is_available:
        if patterns.finding_type in (FindingType.HEURISTIC_HIGH_RISK, FindingType.SUSPICIOUS_INDICATOR):
            if any("dropper" in ev.lower() or "script payload" in ev.lower() or "executable" in ev.lower() for ev in patterns.evidence):
                return "SUSPECTED_MALWARE", None

    # 3. External feeds unavailable -> UNVERIFIED
    if not vt.is_available and not urlhaus.is_available:
        return "UNVERIFIED", None

    # 4. Evaluated and clean
    return "NO_KNOWN_DETECTION", False


def _get_phishing_status(
    vt: ComponentScore,
    gsb: ComponentScore,
    patterns: Optional[ComponentScore] = None,
) -> Tuple[str, Optional[bool]]:
    """
    Determine phishing status with strict separation between confirmed detection and heuristics.

    Returns:
        Tuple[str, Optional[bool]]: (phishing_status, is_phishing)
        phishing_status in ("CONFIRMED_PHISHING", "SUSPECTED_PHISHING", "NO_KNOWN_DETECTION", "UNVERIFIED")
        is_phishing is True ONLY for CONFIRMED_PHISHING.
    """
    # 1. External Confirmed Phishing
    if gsb.is_available and gsb.finding_type == FindingType.CONFIRMED_THREAT:
        gsb_threats = gsb.details.get("threat_types", [])
        if "SOCIAL_ENGINEERING" in gsb_threats:
            return "CONFIRMED_PHISHING", True
    if vt.is_available and vt.finding_type == FindingType.CONFIRMED_THREAT:
        categories = vt.details.get("categories", {})
        if any("phish" in str(v).lower() for v in categories.values()):
            return "CONFIRMED_PHISHING", True

    # 2. Heuristic Suspected Phishing (e.g. typosquatting, credential lure)
    if patterns and patterns.is_available and patterns.score and patterns.score >= 50:
        if any("typosquat" in ev.lower() or "phishing" in ev.lower() or "credential" in ev.lower() for ev in patterns.evidence):
            return "SUSPECTED_PHISHING", None

    # 3. External feeds unavailable -> UNVERIFIED
    if not gsb.is_available and not vt.is_available:
        return "UNVERIFIED", None

    # 4. Evaluated and clean
    return "NO_KNOWN_DETECTION", False


def _is_phishing(vt: ComponentScore, gsb: ComponentScore, patterns: ComponentScore) -> Optional[bool]:
    """Determine phishing boolean status (True only if confirmed)."""
    _, is_phish = _get_phishing_status(vt, gsb, patterns)
    return is_phish


def _is_malware(vt: ComponentScore, urlhaus: ComponentScore, patterns: Optional[ComponentScore] = None) -> Optional[bool]:
    """Determine malware boolean status (True only if confirmed)."""
    _, is_mal = _get_malware_status(vt, urlhaus, patterns)
    return is_mal


def _get_recommendations(score: Optional[int], category: str) -> list:
    """Generate actionable recommendations based on risk score and category."""
    if category in ("CRITICAL", "MALICIOUS"):
        return [
            "Do not visit this website.",
            "If you have already visited it, do not enter any personal information.",
            "Run a malware scan on your device if you clicked any links.",
            "Report this website to your browser vendor and local cybercrime authority.",
        ]
    elif category in ("HIGH", "HIGH_RISK"):
        return [
            "Exercise extreme caution before proceeding.",
            "Do not enter personal, financial, or login credentials.",
            "Do not download or execute any files from this source.",
            "Verify the website's legitimacy through official channels.",
            "Consider using a secondary device or isolated environment if you must visit.",
        ]
    elif category in ("MODERATE", "SUSPICIOUS"):
        return [
            "Proceed with caution.",
            "Verify the website identity before entering any information.",
            "Look for HTTPS and valid SSL certificate.",
            "Check if the domain matches the expected organization.",
        ]
    elif category in ("MODERATE_LOW", "LOW", "LOW_RISK"):
        return [
            "No major threats detected, but stay alert.",
            "Verify the site is who it claims to be.",
            "Avoid entering sensitive data if unsure.",
        ]
    elif category in ("CLEAN", "NO_KNOWN_THREATS"):
        return [
            "No threats detected across active security feeds and heuristic checks.",
            "Always verify website authenticity for sensitive transactions.",
            "Keep your browser and security software updated.",
        ]
    elif category in ("INSUFFICIENT_EVIDENCE", "UNVERIFIED"):
        return [
            "Security evidence is insufficient to verify safety.",
            "External threat intelligence feeds could not be reached.",
            "Treat this URL with caution and avoid entering credentials or downloading files until verified.",
        ]
    else:
        return [
            "Exercise standard web security caution.",
            "Keep your browser and security software updated.",
        ]
