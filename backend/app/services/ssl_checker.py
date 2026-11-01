"""
CYBERCORE Backend — SSL/TLS Checker Service
Analyzes the SSL/TLS certificate of a domain.

Checks:
  - Certificate validity
  - Expiration date
  - Certificate issuer
  - Self-signed detection
  - Subject Alternative Names
  - Domain mismatch
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Optional

from app.services.risk_scorer import ComponentScore, Confidence, FindingType

logger = logging.getLogger(__name__)


async def check_ssl_tls(domain: str, port: Optional[int] = None, scheme: str = "https") -> ComponentScore:
    """
    Check SSL/TLS certificate for a domain or host.
    Returns a ComponentScore reflecting the SSL security posture.
    """
    actual_port = port or (443 if scheme == "https" else 80)
    if scheme == "http" and actual_port != 443:
        return ComponentScore(
            name="SSL/TLS",
            score=50.0,
            confidence=Confidence.HIGH,
            finding_type=FindingType.SUSPICIOUS_INDICATOR,
            details={"scheme": "http", "ssl": False, "port": actual_port, "error": f"No SSL/TLS on port {actual_port}"},
            evidence=[f"Unencrypted connection: Site operates over plain HTTP without SSL/TLS on port {actual_port}"],
        )

    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return await loop.run_in_executor(None, _check_ssl_sync, domain, actual_port)


def _check_ssl_sync(domain: str, port: int = 443) -> ComponentScore:
    """Synchronous SSL check (run in thread pool)."""
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return ComponentScore(
            name="SSL/TLS",
            score=70.0,
            confidence=Confidence.HIGH,
            finding_type=FindingType.SUSPICIOUS_INDICATOR,
            details={"error": "Certificate verification failed", "detail": str(e)},
            evidence=[f"SSL certificate verification failed: {str(e)}"],
        )
    except ssl.SSLError as e:
        return ComponentScore(
            name="SSL/TLS",
            score=75.0,
            confidence=Confidence.HIGH,
            finding_type=FindingType.SUSPICIOUS_INDICATOR,
            details={"error": "SSL error", "detail": str(e)},
            evidence=[f"SSL error: {str(e)}"],
        )
    except (socket.timeout, OSError) as e:
        # HTTP site — no SSL
        return ComponentScore(
            name="SSL/TLS",
            score=50.0,
            confidence=Confidence.MEDIUM,
            finding_type=FindingType.SUSPICIOUS_INDICATOR,
            details={"error": f"No SSL/TLS on port {port}", "detail": str(e)},
            evidence=[f"No valid SSL/TLS certificate found — site does not use HTTPS on port {port}"],
        )
    except ValueError as e:
        # IP address cannot use SNI hostname
        return ComponentScore(
            name="SSL/TLS",
            score=65.0,
            confidence=Confidence.HIGH,
            finding_type=FindingType.SUSPICIOUS_INDICATOR,
            details={"error": "IP host cannot verify SSL SNI certificate", "detail": str(e)},
            evidence=["SSL/TLS verification failed: Direct IP address host cannot be verified via standard domain SNI"],
        )
    except Exception as e:
        logger.error("SSL check error for %s: %s", domain, str(e))
        return ComponentScore(
            name="SSL/TLS",
            score=None,
            confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY,
            details={"reason": f"SSL check failed: {type(e).__name__}"},
        )

    # Parse certificate
    issues = []
    score = 0  # Start at 0 (good), add penalties for issues

    # Check expiry
    not_after_str = cert.get("notAfter", "")
    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    subject_dict = dict(x[0] for x in cert.get("subject", []))

    expiry_info = {}
    if not_after_str:
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (not_after - now).days

            expiry_info = {
                "expires": not_after.isoformat(),
                "days_remaining": days_remaining,
            }

            if days_remaining < 0:
                score += 80
                issues.append(f"Certificate EXPIRED {abs(days_remaining)} days ago")
            elif days_remaining < 7:
                score += 50
                issues.append(f"Certificate expires in {days_remaining} days (critical)")
            elif days_remaining < 30:
                score += 20
                issues.append(f"Certificate expires soon ({days_remaining} days remaining)")

        except ValueError:
            issues.append("Could not parse certificate expiry date")

    # Check self-signed (issuer == subject)
    issuer_org = issuer_dict.get("organizationName", "")
    subject_cn = subject_dict.get("commonName", "")
    issuer_cn = issuer_dict.get("commonName", "")

    is_self_signed = (issuer_cn == subject_cn) or (not issuer_org)
    if is_self_signed and issuer_org not in ("Let's Encrypt", "ZeroSSL"):
        score += 40
        issues.append("Certificate appears to be self-signed or from unknown issuer")

    # SANs
    san_list = [
        name for _type, name in cert.get("subjectAltName", [])
        if _type == "DNS"
    ]

    # Final score cap and classification
    final_score = min(score, 90)

    if final_score == 0:
        finding_type = FindingType.NO_KNOWN_DETECTION
        confidence = Confidence.HIGH
    elif final_score >= 60:
        finding_type = FindingType.SUSPICIOUS_INDICATOR
        confidence = Confidence.HIGH
    else:
        finding_type = FindingType.HEURISTIC_ASSESSMENT
        confidence = Confidence.MEDIUM

    return ComponentScore(
        name="SSL/TLS",
        score=float(final_score),
        confidence=confidence,
        finding_type=finding_type,
        details={
            "valid": final_score < 60,
            "issuer": issuer_dict,
            "subject": subject_dict,
            "san_count": len(san_list),
            **expiry_info,
        },
        evidence=issues if issues else [
            f"Valid SSL certificate from {issuer_org or issuer_cn or 'Unknown CA'}",
            f"{len(san_list)} Subject Alternative Name(s) configured",
        ],
    )
