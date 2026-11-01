"""
CYBERCORE Backend — IP & Domain Intelligence Router

Provides detailed inspection for IP addresses and domain names:
  - DNS resolution (A, AAAA, MX, NS, TXT)
  - RDAP registration data (age, registrar, status)
  - Reverse DNS (PTR)
  - Security reputation & risk assessment
"""

import logging
import socket
import ipaddress
from typing import Optional, Union, Literal, Annotated
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app.limiter import limiter
from app.services.dns_analyzer import analyze_dns, get_domain_rdap, build_domain_reputation_score
from app.utils.validators import validate_domain, is_private_ip, ValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ip-domain", tags=["IP & Domain Intelligence"])


class IpDomainRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=253, description="IP address or domain name")


# ── Response Schemas ─────────────────────────────────────────

class IpDnsDetails(BaseModel):
    ptr: str = Field(..., description="Reverse DNS PTR hostname or resolution status")


class IpReputation(BaseModel):
    risk_score: int = Field(..., description="Calculated heuristic risk score (0-100)")
    verdict: str = Field(..., description="Host reputation verdict (e.g., BENIGN, UNKNOWN_HOST)")
    notes: list[str] = Field(default_factory=list, description="Reputation assessment notes")


class IpAnalysisResponse(BaseModel):
    type: Literal["ip"] = Field("ip", description="Analysis target type discriminator")
    target: str = Field(..., description="Normalized target IP address")
    ip_version: int = Field(..., description="IP version (4 or 6)")
    is_global: bool = Field(..., description="Whether IP address is globally routable")
    reverse_dns: Optional[str] = Field(None, description="Resolved reverse DNS PTR hostname")
    dns: IpDnsDetails = Field(..., description="DNS reverse resolution records")
    reputation: IpReputation = Field(..., description="Heuristic host reputation assessment")


class DomainDnsDetails(BaseModel):
    a_records: list[str] = Field(default_factory=list, description="IPv4 address records")
    mx_records: list[str] = Field(default_factory=list, description="Mail exchange records")
    ns_records: list[str] = Field(default_factory=list, description="Authoritative nameserver records")
    txt_records: list[str] = Field(default_factory=list, description="Apex TXT records")
    has_spf: bool = Field(..., description="Whether SPF record is present in TXT records")
    has_dmarc: Optional[bool] = Field(None, description="Whether valid DMARC record exists at _dmarc.<domain> (null if lookup unavailable)")
    has_dkim_hint: bool = Field(..., description="Whether DKIM hint is present in TXT records")
    dmarc_record: Optional[str] = Field(None, description="Raw DMARC TXT record string if found")
    dmarc_status: Optional[str] = Field(None, description="DMARC status: VALID, MISSING, MALFORMED, or UNAVAILABLE")


class DomainRegistrationDetails(BaseModel):
    registration_date: Optional[str] = Field(None, description="ISO 8601 registration timestamp")
    domain_age_days: Optional[int] = Field(None, description="Calculated age of domain in days")
    expiration_date: Optional[str] = Field(None, description="ISO 8601 expiration timestamp")
    last_updated: Optional[str] = Field(None, description="ISO 8601 last modified timestamp")
    status: Optional[list[str]] = Field(default_factory=list, description="Registry status flags")
    nameservers: Optional[list[str]] = Field(default_factory=list, description="Registered authoritative nameservers")
    registrar: Optional[str] = Field(None, description="Sponsoring registrar organization name")
    error: Optional[str] = Field(None, description="Error message if RDAP lookup failed")


class DomainReputation(BaseModel):
    score: float = Field(..., description="Domain heuristic risk score (0-95)")
    confidence: str = Field(..., description="Assessment confidence level (HIGH, MEDIUM, LOW)")
    findings: list[str] = Field(default_factory=list, description="Evidence and rationale findings")


class DomainAnalysisResponse(BaseModel):
    type: Literal["domain"] = Field("domain", description="Analysis target type discriminator")
    target: str = Field(..., description="Normalized domain name")
    dns: DomainDnsDetails = Field(..., description="DNS technical resolution details")
    registration: DomainRegistrationDetails = Field(..., description="RDAP registration data")
    reputation: DomainReputation = Field(..., description="Domain heuristic reputation assessment")


IpDomainResponse = Annotated[
    Union[IpAnalysisResponse, DomainAnalysisResponse],
    Field(discriminator="type")
]


def is_valid_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


@router.post("/analyze", response_model=IpDomainResponse)
@limiter.limit("30/minute")
async def analyze_ip_or_domain(payload: IpDomainRequest, request: Request):
    """Analyze an IP address or domain name."""
    query = payload.query.strip().lower()
    return await _process_query(query)


@router.get("/{query:path}", response_model=IpDomainResponse)
@limiter.limit("30/minute")
async def get_ip_or_domain(query: str, request: Request):
    """Retrieve intelligence for a given IP or domain."""
    return await _process_query(query.strip().lower())


async def _process_query(target: str) -> dict:
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query target cannot be empty."
        )

    # Strip scheme if accidentally pasted (e.g. https://example.com/path -> example.com)
    if "://" in target:
        target = target.split("://", 1)[1]
    if "/" in target:
        target = target.split("/", 1)[0]
    if ":" in target and not is_valid_ip(target):
        target = target.split(":", 1)[0]

    if is_valid_ip(target):
        # Handle IP Address
        ip_obj = ipaddress.ip_address(target)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security restriction: {target} is a private, loopback, or reserved IP address."
            )

        # Reverse DNS lookup
        hostname = None
        try:
            hostname, _, _ = socket.gethostbyaddr(target)
        except (socket.herror, socket.gaierror, OSError):
            hostname = None

        return {
            "type": "ip",
            "target": target,
            "ip_version": ip_obj.version,
            "is_global": ip_obj.is_global,
            "reverse_dns": hostname,
            "dns": {
                "ptr": hostname or "No PTR record found",
            },
            "reputation": {
                "risk_score": 10 if hostname else 25,
                "verdict": "BENIGN" if hostname else "UNKNOWN_HOST",
                "notes": ["Public routable IP address", f"Reverse DNS: {hostname or 'Not configured'}"]
            }
        }
    else:
        # Handle Domain
        try:
            clean_domain = validate_domain(target)
        except ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

        # Run DNS and RDAP concurrently
        dns_data = await analyze_dns(clean_domain)
        rdap_data = await get_domain_rdap(clean_domain)
        reputation = await build_domain_reputation_score(clean_domain, rdap_data)

        # Calculate high-level domain score
        risk_score = reputation.score
        if not dns_data.get("a_records"):
            risk_score = max(risk_score, 45)  # Domain doesn't resolve to any IP

        return {
            "type": "domain",
            "target": clean_domain,
            "dns": dns_data,
            "registration": rdap_data,
            "reputation": {
                "score": risk_score,
                "confidence": reputation.confidence.value if hasattr(reputation.confidence, "value") else str(reputation.confidence),
                "findings": reputation.evidence if hasattr(reputation, "evidence") else [],
            }
        }
