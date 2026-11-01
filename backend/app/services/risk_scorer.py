"""
CYBERCORE Backend — Risk Scoring Engine

Implements the calibrated risk scoring model:

  Component                          Weight
  ─────────────────────────────────────────
  Threat Intelligence (VT/GSB/URLh)   30%
  Phishing & Malware Indicators        20%
  Domain Reputation                    15%
  Suspicious URL Patterns              15%
  SSL/TLS Security                     10%
  Redirect Analysis                    10%

Each component returns a ComponentScore (0–100 + confidence).
The final risk score is calculated with:
  1. Threat Floor Precedence: Confirmed external threats and compounding
     heuristic droppers override linear weight dilution.
  2. Insufficient Evidence Detection: Unavailable intelligence feeds never
     produce a reassuring LOW THREAT verdict.
  3. Calibration: Raw IPs, high ports, and script downloads are detected
     without falsely convicting benign administrative consoles.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple
from enum import Enum
import re
from urllib.parse import urlparse
import ipaddress
import tldextract


class RiskCategory(str, Enum):
    CLEAN = "CLEAN"                                 # Verified clean (0–15)
    LOW_RISK = "LOW_RISK"                           # Low risk (16–35)
    LOW = "LOW"                                     # Backward-compatible alias
    SUSPICIOUS = "SUSPICIOUS"                       # Suspicious indicators (36–65)
    HIGH_RISK = "HIGH_RISK"                         # High risk / compounding heuristics (66–84)
    HIGH = "HIGH"                                   # Backward-compatible alias
    MALICIOUS = "MALICIOUS"                         # Confirmed external threat (85–100)
    UNVERIFIED = "UNVERIFIED"                       # Target unreachable
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE" # Absence of operational intelligence


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNAVAILABLE = "UNAVAILABLE"


class FindingType(str, Enum):
    """Distinguish between types of security findings."""
    CONFIRMED_THREAT = "CONFIRMED_THREAT"           # Trusted provider explicitly identifies threat
    HEURISTIC_HIGH_RISK = "HEURISTIC_HIGH_RISK"     # Multiple compounding heuristic characteristics
    SUSPICIOUS_INDICATOR = "SUSPICIOUS_INDICATOR"   # Moderate suspicious indicators
    HEURISTIC_ASSESSMENT = "HEURISTIC_ASSESSMENT"   # Heuristic pattern match
    NO_KNOWN_DETECTION = "NO_KNOWN_DETECTION"       # Check performed, no detection
    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"           # Check unavailable or failed


@dataclass
class ComponentScore:
    name: str
    score: Optional[float]           # 0–100, None if unavailable
    confidence: Confidence
    finding_type: FindingType
    details: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)

    @property
    def is_available(self) -> bool:
        return self.score is not None


# Weights must sum to 1.0
COMPONENT_WEIGHTS = {
    "threat_intelligence": 0.30,
    "phishing_malware":    0.20,
    "domain_reputation":   0.15,
    "url_patterns":        0.15,
    "ssl_tls":             0.10,
    "redirect_analysis":   0.10,
}


def calculate_risk_score(components: dict[str, ComponentScore]) -> dict:
    """
    Calculate the risk score from component scores with threat precedence.

    Rules:
    1. Confirmed Threat Floor: An authoritative threat (VT/GSB/URLhaus or compounding
       dropper) sets a minimum floor (MALICIOUS/HIGH) that cannot be diluted by clean checks.
    2. Insufficient Evidence: If external intelligence is unavailable and coverage < 50%
       without heuristic detections, category is INSUFFICIENT_EVIDENCE (never LOW).
    3. Re-normalized weights for available components.

    Returns:
        dict with keys: score, category, confidence, components, unavailable_checks, coverage
    """
    available_weight_total = 0.0
    weighted_sum = 0.0
    component_details = {}
    unavailable = []

    # Track threat overrides
    threat_floor = 0.0
    has_confirmed_threat = False
    has_heuristic_high_risk = False
    has_suspicious_heuristics = False

    for key, weight in COMPONENT_WEIGHTS.items():
        comp = components.get(key)
        if comp and comp.is_available:
            available_weight_total += weight
            weighted_sum += comp.score * weight
            component_details[key] = {
                "score": round(comp.score),
                "confidence": comp.confidence.value,
                "finding_type": comp.finding_type.value,
                "details": comp.details,
                "evidence": comp.evidence,
            }

            # Check threat precedence
            # A. EXTERNAL CONFIRMED DETECTION
            # Trusted provider explicitly identifies the URL as malicious
            if comp.finding_type == FindingType.CONFIRMED_THREAT and comp.score is not None:
                if key in ("threat_intelligence", "phishing_malware") and comp.score >= 70:
                    has_confirmed_threat = True
                    threat_floor = max(threat_floor, comp.score, 85.0)

            # B. HEURISTIC HIGH-RISK DETECTION
            # Multiple suspicious URL characteristics without external confirmation
            elif comp.finding_type == FindingType.HEURISTIC_HIGH_RISK and comp.score is not None:
                has_heuristic_high_risk = True
                threat_floor = max(threat_floor, min(comp.score, 80.0))

            elif comp.finding_type == FindingType.SUSPICIOUS_INDICATOR and comp.score is not None:
                if comp.score >= 40:
                    has_suspicious_heuristics = True
                    threat_floor = max(threat_floor, comp.score * 0.9)
        else:
            unavailable.append(key)
            component_details[key] = {
                "score": None,
                "confidence": Confidence.UNAVAILABLE.value,
                "finding_type": FindingType.UNABLE_TO_VERIFY.value,
                "details": comp.details if comp else {},
                "evidence": comp.evidence if comp else [],
            }

    # Evaluate coverage
    coverage_pct = round(available_weight_total * 100)

    # All security checks unavailable
    if available_weight_total == 0:
        return {
            "score": None,
            "category": RiskCategory.INSUFFICIENT_EVIDENCE.value,
            "confidence": Confidence.UNAVAILABLE.value,
            "components": component_details,
            "unavailable_checks": unavailable,
            "coverage": 0,
            "has_threat_override": False,
        }

    # Calculate weighted base score
    raw_weighted = weighted_sum / available_weight_total
    final_score = round(raw_weighted)

    # Apply Threat Floor Override (prevents dilution of confirmed threats or high heuristics)
    has_threat_override = False
    if threat_floor > 0 and final_score < threat_floor:
        final_score = round(threat_floor)
        has_threat_override = True

    # Crucial safeguard: Heuristics must NEVER masquerade as external confirmation
    # If there is no confirmed external threat, score cannot enter MALICIOUS tier (85+)
    if not has_confirmed_threat and final_score >= 85:
        final_score = 80

    # Determine assessment confidence
    if available_weight_total >= 0.75:
        overall_confidence = Confidence.HIGH
    elif available_weight_total >= 0.45:
        overall_confidence = Confidence.MEDIUM
    else:
        overall_confidence = Confidence.LOW

    # Check for Insufficient Evidence condition:
    # If threat intelligence is offline AND no threat was detected AND coverage is low
    ti_comp = components.get("threat_intelligence")
    ti_offline = not ti_comp or not ti_comp.is_available
    is_insufficient = False

    if ti_offline and not has_confirmed_threat and not has_heuristic_high_risk and not has_suspicious_heuristics:
        if available_weight_total <= 0.50:
            # Low coverage with zero external intel -> cannot establish safety
            is_insufficient = True
            final_score = None
            overall_confidence = Confidence.UNAVAILABLE

    # Map score to taxonomy
    category = score_to_category(
        final_score,
        coverage=available_weight_total,
        has_confirmed_threat=has_confirmed_threat,
        has_heuristic_high_risk=has_heuristic_high_risk,
        is_insufficient=is_insufficient,
    )

    return {
        "score": final_score,
        "category": category.value,
        "confidence": overall_confidence.value,
        "components": component_details,
        "unavailable_checks": unavailable,
        "coverage": coverage_pct,
        "has_threat_override": has_threat_override,
    }


def score_to_category(
    score: Optional[int],
    coverage: float = 1.0,
    has_confirmed_threat: bool = False,
    has_heuristic_high_risk: bool = False,
    is_insufficient: bool = False,
) -> RiskCategory:
    """Convert numeric score to calibrated risk category."""
    if is_insufficient or score is None:
        return RiskCategory.INSUFFICIENT_EVIDENCE

    # Rule 1: Confirmed authoritative malicious intelligence -> MALICIOUS
    if has_confirmed_threat:
        return RiskCategory.MALICIOUS

    # Rule 2: Strong compounding heuristics -> HIGH_RISK (never MALICIOUS!)
    if has_heuristic_high_risk or score >= 66:
        return RiskCategory.HIGH_RISK

    # Rule 3: Moderate suspicious indicators -> SUSPICIOUS
    elif score >= 36:
        return RiskCategory.SUSPICIOUS

    # Rule 4: Low risk or verified clean
    elif score > 15:
        return RiskCategory.LOW_RISK
    else:
        # Score 0-15: Only classify as CLEAN if coverage is verified high
        return RiskCategory.CLEAN if coverage >= 0.70 else RiskCategory.LOW_RISK


# ---------------------------------------------------------------------------
# URL Pattern Analysis
# ---------------------------------------------------------------------------

SUSPICIOUS_URL_PATTERNS = [
    # Typosquatting indicators
    (r"paypa[l1]|pay-pal|paypa1", "Possible PayPal typosquatting", 70),
    (r"googl[e3]|g[o0]{2}gle|g00gle", "Possible Google typosquatting", 70),
    (r"amaz[o0]n|amaz[o0]n-", "Possible Amazon typosquatting", 65),
    (r"micros[o0]ft|micr[o0]soft", "Possible Microsoft typosquatting", 70),
    (r"faceb[o0]{2}k|faceb[0o]ok", "Possible Facebook typosquatting", 70),
    (r"app[l1]e-|appl[e3]\.support", "Possible Apple typosquatting", 65),

    # Suspicious keywords in domain
    (r"secure-|security-|safe-", "Security keyword in domain (phishing tactic)", 30),
    (r"login-|signin-|account-|verify-|update-", "Action keyword in domain (phishing tactic)", 35),
    (r"-bank|-banking|-pay|-payment|-wallet", "Financial keyword in domain", 30),
    (r"free-|win-|prize-|reward-|lucky-", "Reward lure keyword in domain", 40),
    (r"urgent-|alert-|warning-|notice-", "Urgency keyword in domain", 35),
    (r"\.tk$|\.ml$|\.ga$|\.cf$|\.gq$", "High-risk free TLD", 45),
    (r"\.xyz$|\.top$|\.click$|\.link$", "Commonly abused TLD", 20),

    # Suspicious structure
    (r"-{2,}", "Multiple consecutive hyphens", 20),
    (r"https?://.{100,}", "Excessively long URL", 20),
    (r"@", "URL contains @ symbol (credential bypass attempt)", 60),
    (r"//.*//", "Multiple double-slashes in path", 30),
    (r"base64|%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}", "Heavy URL encoding (obfuscation)", 35),
]

DANGEROUS_EXTENSIONS = (
    ".sh", ".exe", ".bin", ".elf", ".bat", ".cmd", ".ps1",
    ".vbs", ".apk", ".scr", ".msi", ".jar", ".iso", ".dll"
)


def analyze_url_patterns(url: str, domain: str) -> ComponentScore:
    """
    Analyze URL, hostname, port, and path for suspicious patterns.

    Detects:
    - Raw IPv4 and IPv6 literal hosts
    - Non-standard ports (especially high/ephemeral ports > 1024)
    - Direct executable / script download paths (.sh, .exe, .bin, .elf, etc.)
    - Unencrypted HTTP script delivery combinations
    - Domain typosquatting, keywords, and structural obfuscation
    """
    matches = []
    max_score = 0.0

    parsed = urlparse(url)
    hostname = (parsed.hostname or domain).lower()
    path_lower = parsed.path.lower()

    # 1. Raw IPv4 / IPv6 Literal Host Detection
    is_raw_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_raw_ip = True
        matches.append({
            "pattern": f"Direct raw IP address host ({hostname}) used instead of registered domain name",
            "severity": 35.0,
            "type": "raw_ip",
        })
        max_score = max(max_score, 35.0)
    except ValueError:
        is_raw_ip = False

    # 2. Non-standard Port Detection
    has_high_port = False
    has_non_standard_port = False
    if parsed.port and parsed.port not in (80, 443):
        has_non_standard_port = True
        if parsed.port > 1024:
            has_high_port = True
            matches.append({
                "pattern": f"Target uses non-standard high port (:{parsed.port}) commonly associated with malware C2 or unauthorized services",
                "severity": 40.0,
                "type": "high_port",
            })
            max_score = max(max_score, 40.0)
        else:
            matches.append({
                "pattern": f"Target uses non-standard port (:{parsed.port})",
                "severity": 25.0,
                "type": "non_standard_port",
            })
            max_score = max(max_score, 25.0)

    # 3. Executable / Script Payload Extension Detection
    has_script_payload = False
    detected_ext = None
    for ext in DANGEROUS_EXTENSIONS:
        if path_lower.endswith(ext) or f"{ext}?" in path_lower or f"{ext}/" in path_lower:
            has_script_payload = True
            detected_ext = ext
            # Calibrate severity: direct script payload is high risk
            severity = 45.0 if ext in (".sh", ".exe", ".bin", ".elf", ".bat", ".ps1") else 35.0
            matches.append({
                "pattern": f"URL path targets executable script or binary payload ({ext})",
                "severity": severity,
                "type": "script_payload",
            })
            max_score = max(max_score, severity)
            break

    # 4. HTTP Cleartext Transport for Sensitive / Executable Payload
    if parsed.scheme == "http" and has_script_payload:
        matches.append({
            "pattern": "Unencrypted HTTP transport used for script/executable payload delivery",
            "severity": 30.0,
            "type": "http_script",
        })
        max_score = max(max_score, 30.0)

    # 5. Compounding Heuristic Dropper Rules
    # When multiple critical indicators coincide, establish HEURISTIC_HIGH_RISK finding
    compounding_score = 0.0
    if is_raw_ip and (has_high_port or has_non_standard_port) and has_script_payload:
        compounding_score = 80.0
        matches.append({
            "pattern": "Compounding heuristic risk: Direct IP, non-standard port, and script payload on unencrypted HTTP",
            "severity": 80.0,
            "type": "compounding_dropper",
        })
        max_score = max(max_score, 80.0)
    elif is_raw_ip and has_script_payload:
        compounding_score = 65.0
        matches.append({
            "pattern": "Suspicious payload vector: Direct IP hosting executable script payload",
            "severity": 65.0,
            "type": "ip_script",
        })
        max_score = max(max_score, 65.0)

    # 6. Lexical & Structural Domain Patterns
    for pattern, description, severity in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            matches.append({"pattern": description, "severity": float(severity), "type": "regex"})
            max_score = max(max_score, float(severity))

    # Check domain name digits only on registered domain labels (never on raw IPs or ports)
    ext = tldextract.extract(url)
    if ext.domain and not is_raw_ip:
        if re.search(r"\d{4,}", ext.domain):
            matches.append({
                "pattern": "Multiple consecutive digits in registered domain name",
                "severity": 15.0,
                "type": "domain_digits",
            })
            max_score = max(max_score, 15.0)

        # Check subdomain depth
        subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0
        if subdomain_count >= 3:
            matches.append({"pattern": f"Deep subdomain nesting ({subdomain_count} levels)", "severity": 25.0, "type": "subdomains"})
            max_score = max(max_score, 25.0)

        # Check domain length
        if len(ext.domain) > 30:
            matches.append({"pattern": "Unusually long domain name", "severity": 20.0, "type": "domain_length"})
            max_score = max(max_score, 20.0)

    # Calculate final pattern score
    if not matches:
        score = 0.0
        finding_type = FindingType.NO_KNOWN_DETECTION
    elif compounding_score >= 75.0 or max_score >= 75.0:
        score = max(max_score, compounding_score)
        # CRITICAL: Heuristics must NEVER claim CONFIRMED_THREAT!
        finding_type = FindingType.HEURISTIC_HIGH_RISK
    elif max_score >= 55.0:
        score = min(90.0, max_score + len(matches) * 4.0)
        finding_type = FindingType.SUSPICIOUS_INDICATOR
    elif max_score >= 35.0:
        score = min(75.0, max_score + len(matches) * 3.0)
        finding_type = FindingType.SUSPICIOUS_INDICATOR
    else:
        score = min(50.0, max_score + len(matches) * 2.5)
        finding_type = FindingType.HEURISTIC_ASSESSMENT

    return ComponentScore(
        name="URL Pattern Analysis",
        score=float(score),
        confidence=Confidence.HIGH,  # Pattern matching is deterministic
        finding_type=finding_type,
        details={
            "patterns_matched": len(matches),
            "is_raw_ip": is_raw_ip,
            "has_non_standard_port": has_non_standard_port,
            "has_high_port": has_high_port,
            "has_script_payload": has_script_payload,
            "detected_extension": detected_ext,
        },
        evidence=[m["pattern"] for m in matches],
    )
