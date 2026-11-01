"""
CYBERCORE Backend — DNS Analyzer Service

Analyzes DNS records for a domain:
  - A / AAAA records (IPv4/IPv6)
  - MX records (email)
  - NS records (nameservers)
  - TXT records (SPF, DMARC, DKIM)
  - CNAME records
  - Domain age via RDAP

RDAP replaces the deprecated WHOIS protocol and provides structured JSON data.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx
import dns.resolver
import dns.exception
import tldextract

from app.services.risk_scorer import ComponentScore, Confidence, FindingType

logger = logging.getLogger(__name__)

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"
DNS_TIMEOUT = 5.0
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Suspicious nameserver patterns (often associated with bulletproof hosting)
SUSPICIOUS_NS_KEYWORDS = [
    "bulletproof", "no-log", "offshore", "anon", "privacy",
]


async def analyze_dns(domain: str) -> dict:
    """
    Full DNS analysis for a domain.
    Returns structured results for display and scoring.
    """
    results = {}

    # Run DNS queries concurrently
    tasks = [
        _query_a_records(domain),
        _query_mx_records(domain),
        _query_ns_records(domain),
        _query_txt_records(domain),
        _query_dmarc_records(domain),
    ]
    a_rec, mx_rec, ns_rec, txt_rec, dmarc_res = await asyncio.gather(*tasks, return_exceptions=True)

    results["a_records"] = a_rec if not isinstance(a_rec, Exception) else []
    results["mx_records"] = mx_rec if not isinstance(mx_rec, Exception) else []
    results["ns_records"] = ns_rec if not isinstance(ns_rec, Exception) else []
    results["txt_records"] = txt_rec if not isinstance(txt_rec, Exception) else []

    # SPF / DKIM analysis from TXT records
    txt_list = results.get("txt_records", [])
    results["has_spf"] = any("v=spf1" in t.lower() for t in txt_list)
    results["has_dkim_hint"] = any("v=dkim1" in t.lower() for t in txt_list)

    # DMARC analysis from dedicated _dmarc query (RFC 7489)
    dmarc_data = dmarc_res if isinstance(dmarc_res, dict) else {
        "has_dmarc": None,
        "dmarc_record": None,
        "dmarc_status": "UNAVAILABLE",
    }
    results["has_dmarc"] = dmarc_data.get("has_dmarc")
    results["dmarc_record"] = dmarc_data.get("dmarc_record")
    results["dmarc_status"] = dmarc_data.get("dmarc_status")

    return results


async def get_domain_rdap(domain: str) -> dict:
    """
    Fetch domain registration info via RDAP.
    RDAP provides structured JSON — more reliable than WHOIS.
    """
    ext = tldextract.extract(domain)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"{RDAP_BOOTSTRAP_URL}{registered_domain}",
                follow_redirects=True,
            )
        if resp.status_code != 200:
            return {"error": f"RDAP returned status {resp.status_code}"}

        data = resp.json()
        return _parse_rdap_response(data)

    except httpx.TimeoutException:
        return {"error": "RDAP request timed out"}
    except Exception as e:
        logger.error("RDAP error for %s: %s", domain, str(e))
        return {"error": f"RDAP unavailable: {type(e).__name__}"}


def _parse_rdap_response(data: dict) -> dict:
    """Parse RDAP JSON response into structured result."""
    result = {}

    # Events (registration, expiration, last update)
    events = data.get("events", [])
    for event in events:
        action = event.get("eventAction", "")
        date_str = event.get("eventDate", "")
        if action == "registration":
            result["registration_date"] = date_str
            result["domain_age_days"] = _days_since(date_str)
        elif action == "expiration":
            result["expiration_date"] = date_str
        elif action == "last changed":
            result["last_updated"] = date_str

    # Status
    result["status"] = data.get("status", [])

    # Nameservers
    ns_data = data.get("nameservers", [])
    result["nameservers"] = [ns.get("ldhName", "") for ns in ns_data]

    # Registrar
    entities = data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        result["registrar"] = item[3]
                        break

    return result


def _days_since(date_str: str) -> Optional[int]:
    """Calculate days since a date string."""
    if not date_str:
        return None
    try:
        # RDAP dates are ISO 8601
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


async def build_domain_reputation_score(domain: str, rdap_data: dict) -> ComponentScore:
    """
    Build a domain reputation score based on DNS and RDAP data.
    """
    issues = []
    score = 0

    domain_age_days = rdap_data.get("domain_age_days")

    if domain_age_days is not None:
        if domain_age_days < 7:
            score += 70
            issues.append(f"Domain registered only {domain_age_days} days ago (very new)")
        elif domain_age_days < 30:
            score += 50
            issues.append(f"Domain registered {domain_age_days} days ago (recently registered)")
        elif domain_age_days < 90:
            score += 25
            issues.append(f"Domain registered {domain_age_days} days ago (relatively new)")
        elif domain_age_days < 365:
            score += 10
    else:
        # Cannot determine age — slight uncertainty
        score += 10
        issues.append("Could not determine domain registration date")

    # Check nameserver reputation
    ns_list = rdap_data.get("nameservers", [])
    for ns in ns_list:
        for kw in SUSPICIOUS_NS_KEYWORDS:
            if kw in ns.lower():
                score += 30
                issues.append(f"Suspicious nameserver: {ns}")
                break

    # Status flags
    status = rdap_data.get("status", [])
    if "clientHold" in status or "serverHold" in status:
        score += 40
        issues.append("Domain is on hold (suspended)")

    final_score = min(score, 95)

    if domain_age_days is None and not issues:
        confidence = Confidence.LOW
        finding_type = FindingType.UNABLE_TO_VERIFY
    elif final_score == 0:
        confidence = Confidence.HIGH
        finding_type = FindingType.NO_KNOWN_DETECTION
    elif final_score >= 50:
        confidence = Confidence.HIGH if domain_age_days is not None else Confidence.MEDIUM
        finding_type = FindingType.SUSPICIOUS_INDICATOR
    else:
        confidence = Confidence.MEDIUM
        finding_type = FindingType.HEURISTIC_ASSESSMENT

    return ComponentScore(
        name="Domain Reputation",
        score=float(final_score),
        confidence=confidence,
        finding_type=finding_type,
        details={
            "domain_age_days": domain_age_days,
            "nameservers": ns_list,
            "registrar": rdap_data.get("registrar"),
            "registration_date": rdap_data.get("registration_date"),
            "expiration_date": rdap_data.get("expiration_date"),
            "status": status,
        },
        evidence=issues if issues else [
            f"Domain registered {domain_age_days} days ago",
            f"Registrar: {rdap_data.get('registrar', 'Unknown')}",
        ],
    )


# ---------------------------------------------------------------------------
# Private DNS helpers
# ---------------------------------------------------------------------------

def _run_dns_query(domain: str, record_type: str) -> list:
    """Run a DNS query synchronously."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as e:
        logger.debug("DNS query %s for %s: %s", record_type, domain, str(e))
        return []


async def _query_a_records(domain: str) -> list:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_dns_query, domain, "A")


async def _query_mx_records(domain: str) -> list:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_dns_query, domain, "MX")


async def _query_ns_records(domain: str) -> list:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_dns_query, domain, "NS")


async def _query_txt_records(domain: str) -> list:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_dns_query, domain, "TXT")


def _run_dmarc_query(domain: str) -> dict:
    """
    Query DMARC TXT record adhering to RFC 7489.
    Queries _dmarc.<domain>, falling back to organizational domain for subdomains.
    Distinguishes VALID, MISSING, MALFORMED, and UNAVAILABLE.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    candidates = [f"_dmarc.{domain}"]
    ext = tldextract.extract(domain)
    org_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain
    if org_domain != domain:
        candidates.append(f"_dmarc.{org_domain}")

    for candidate in candidates:
        try:
            answers = resolver.resolve(candidate, "TXT")
            for r in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                    for s in getattr(r, "strings", [str(r)])
                ).strip()
                if txt.lower().startswith("v=dmarc1"):
                    return {
                        "has_dmarc": True,
                        "dmarc_record": txt,
                        "dmarc_status": "VALID",
                    }
                else:
                    return {
                        "has_dmarc": False,
                        "dmarc_record": txt,
                        "dmarc_status": "MALFORMED",
                    }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException as e:
            logger.debug("DMARC DNS lookup error for %s: %s", candidate, str(e))
            return {
                "has_dmarc": None,
                "dmarc_record": None,
                "dmarc_status": "UNAVAILABLE",
            }
        except Exception as e:
            logger.error("Unexpected error querying DMARC for %s: %s", candidate, str(e))
            return {
                "has_dmarc": None,
                "dmarc_record": None,
                "dmarc_status": "UNAVAILABLE",
            }

    return {
        "has_dmarc": False,
        "dmarc_record": None,
        "dmarc_status": "MISSING",
    }


async def _query_dmarc_records(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_dmarc_query, domain)
