"""
CYBERCORE Backend — Message Scam Analyzer Service

Analyzes suspicious emails, SMS, and other messages for scam indicators.

Detection approach:
  1. Rule-based pattern matching (primary, fast, deterministic)
  2. Keyword and phrase analysis
  3. URL extraction and flagging
  4. Urgency and manipulation tactic detection
  5. Impersonation indicator detection

NOTE: AI can be used to EXPLAIN findings but is NOT the primary detection mechanism.
Detection results must have evidence — never classify based on AI guess alone.
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MessageAnalysisResult:
    risk_score: int
    scam_type: Optional[str]
    indicators: list[dict]
    urls_found: list[str]
    manipulation_tactics: list[str]
    impersonation_targets: list[str]
    recommended_actions: list[str]
    message_hash: str  # Store hash, never raw message


# ─────────────────────────────────────────────────────────────
# SCAM PATTERN LIBRARY
# Each entry: (regex_pattern, description, scam_type, severity 0-100)
# ─────────────────────────────────────────────────────────────

# Negative signals: Legitimate warnings and security advisories that should NOT be flagged as scams
NEGATIVE_SIGNALS = [
    re.compile(r"\b(?:never|do\s+not|don'?t)\s+share\s+(?:your\s+|the\s+)?(?:otp|it|pin|password|credentials?)\b"),
    re.compile(r"\b(?:bank|organization|service|we)\s+will\s+never\s+(?:call|ask|request|demand).*(?:otp|pin|password)\b"),
    re.compile(r"\bcaution:?\s+do\s+not\s+(?:share|disclose|forward)\b"),
]

SCAM_PATTERNS = [
    # OTP / Account Verification Scams
    (r"\b(?:otp.*expire|your\s+otp\s+is|share.*otp|send.*otp|verify.*otp)\b", "OTP sharing request", "OTP_FRAUD", 85),
    (r"\b(?:never\s+share.*otp|do\s+not\s+share.*otp)\b", None, None, 0),  # Legitimate warning — negative signal

    # KYC Scams (common in India)
    (r"\b(?:kyc.*expire|complete.*kyc|kyc.*update|verify.*kyc|kyc.*pending)\b", "KYC urgency scam", "KYC_SCAM", 80),
    (r"\byour\s+account\s+will\s+be\s+(?:blocked|suspended|deactivated|frozen)\b", "Account suspension threat", "ACCOUNT_THREAT", 75),

    # Lottery / Prize Scams (Contextualized to require prize/winner context)
    (r"\b(?:you\s+have\s+(?:won|win)\b|you\s+have\s+been\s+(?:selected|chosen)\s+(?:as\s+(?:a\s+)?winner|to\s+receive|for\s+(?:a\s+)?(?:cash|prize|reward|gift|lottery|draw|jackpot|free\b)))", "Prize/Lottery claim", "LOTTERY_SCAM", 85),
    (r"\b(?:congratulations.*winner|prize.*claim|lottery.*winner|lucky\s+draw)\b", "Lottery/prize scam", "LOTTERY_SCAM", 85),
    (r"\bclaim\s+your\s+(?:prize|reward|gift|cash|money)\b", "Prize claim prompt", "LOTTERY_SCAM", 80),

    # Job / Internship Scams
    (r"\b(?:work\s+from\s+home.*earn|earn.*per\s+(?:day|week|hour).*from\s+home)\b", "Work-from-home income scam", "JOB_SCAM", 75),
    (r"\b(?:job\s+offer.*no\s+experience|easy\s+(?:job|money|income|earning))\b", "Fake job offer", "JOB_SCAM", 70),
    (r"\b(?:whatsapp.*job|telegram.*task.*earn|youtube.*like.*earn)\b", "Social media task scam", "TASK_SCAM", 85),
    (r"\b(?:part.?time.*earn|internship.*fee|training\s+fee.*job)\b", "Fake internship/job fee", "JOB_SCAM", 80),

    # Investment / Trading Scams
    (r"\b(?:guaranteed.*return|100%.*profit|risk.?free.*invest|double.*money)\b", "Guaranteed returns scam", "INVESTMENT_SCAM", 90),
    (r"\b(?:crypto.*profit.*guaranteed|forex.*guaranteed|trading.*signal.*profit)\b", "Fake trading signal", "INVESTMENT_SCAM", 85),
    (r"\bpay\s+(?:first|now|today)\s+to\s+(?:unlock|start|begin|access)\b", "Advance fee fraud", "ADVANCE_FEE", 85),

    # Courier / Delivery Scams
    (r"\b(?:parcel.*detained|package.*held|customs.*fee.*release|delivery.*fee.*pending)\b", "Courier delivery scam", "COURIER_SCAM", 80),
    (r"\b(?:fedex.*package|dhl.*parcel.*customs|courier.*clearance.*pay)\b", "Fake courier notification", "COURIER_SCAM", 75),

    # Phishing Patterns
    (r"\b(?:click.*link.*verify|tap.*link.*confirm|follow.*link.*update)\b", "Suspicious link click request", "PHISHING", 70),
    (r"\b(?:your\s+password.*expire|reset.*password.*immediately)\b", "Password urgency phishing", "PHISHING", 75),
    (r"\b(?:bank.*account.*suspend|credit\s+card.*block|upi.*suspend)\b", "Banking threat phishing", "PHISHING", 80),

    # Impersonation Patterns (Contextualized)
    (r"\b(?:income\s+tax\s+(?:department|notice|refund|penalty|order|investigation)|it\s+department.*(?:notice|refund|order))\b", "Tax authority impersonation", "IMPERSONATION", 80),
    (r"\b(?:police\s+(?:notice|department|warrant|officer|warning|complaint|summons|case)|cyber\s+crime.*(?:notice|cell|case)|cbi.*(?:notice|officer|case)|enforcement\s+directorate)\b", "Law enforcement impersonation", "IMPERSONATION", 85),
    (r"\b(?:rbi.*guidelines|reserve\s+bank.*india.*notice)\b", "RBI impersonation", "IMPERSONATION", 85),
    (r"\b(?:amazon.*gift|flipkart.*winner|google.*reward|microsoft.*winner)\b", "Tech brand impersonation", "IMPERSONATION", 80),

    # Generic Urgency
    (r"\b(?:urgent|immediate\s+action|act\s+now|limited\s+time|expires?\s+in\s+\d+\s+hours?)\b", "Urgency pressure tactic", "URGENCY", 40),
    (r"\b(?:final\s+(?:notice|warning|reminder)|last\s+(?:chance|opportunity))\b", "Final warning pressure", "URGENCY", 50),
]

MANIPULATION_TACTICS = [
    (r"\b(?:urgent|immediately|right\s+now|don'?t\s+wait)\b", "Urgency"),
    (r"\b(?:secret|confidential|private.*opportunity|exclusive)\b", "False exclusivity"),
    (r"\b(?:fear|warning|danger|serious|consequence)\b", "Fear induction"),
    (r"\blimited\s+(?:time|offer|seats?|spots?)\b", "Artificial scarcity"),
    (r"\b(?:trust\s+me|i\s+promise|guaranteed|100%\s+safe)\b", "False reassurance"),
    (r"\b(?:don'?t\s+tell|keep\s+this\s+between|don'?t\s+share\s+this)\b", "Secrecy request"),
]

# Impersonation targets with strict word boundaries and disambiguation
KNOWN_IMPERSONATION_TARGETS = {
    r"\bamazon\b": "Amazon",
    r"\bflipkart\b": "Flipkart",
    r"\bgoogle\b": "Google",
    r"\bmicrosoft\b": "Microsoft",
    r"\bapple\b": "Apple",
    r"\bpaypal\b": "PayPal",
    r"\bpaytm\b": "Paytm",
    r"\bphonepe\b": "PhonePe",
    r"\b(?:gpay|google\s+pay)\b": "Google Pay",
    r"\b(?:state\s+bank(?:\s+of\s+india)?|sbi)\b": "State Bank of India",
    r"\bhdfc(?:\s+bank)?\b": "HDFC Bank",
    r"\bicici(?:\s+bank)?\b": "ICICI Bank",
    r"\baxis\s+bank\b": "Axis Bank",
    r"\b(?:income\s+tax\s+(?:department|notice|refund|order|summons|demand|officer|inquiry)|it\s+department\s+(?:notice|refund|order))\b": "Income Tax Department",
    r"\b(?:reserve\s+bank(?:\s+of\s+india)?|rbi)\s+(?:notice|guidelines?|order|directive)\b": "Reserve Bank of India",
    # Fixed: ed\s+ replaced with explicit word boundaries and enforcement directorate contexts
    r"\b(?:police|cbi|enforcement\s+directorate|ed\s+(?:notice|summons|raid|case|department|officer|investigation|inquiry))\b": "Law Enforcement Agency",
    r"\b(?:fedex|dhl|bluedart)\b": "Courier Company",
    r"\birdai\b": "IRDAI",
    # Fixed: Bound trai with word boundaries to prevent matching 'training'
    r"\btrai\b": "TRAI",
    r"\bsebi\b": "SEBI",
}

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"{}|\\^`\[\]]+|www\.[^\s<>\"{}|\\^`\[\]]+"
)

# Pretext patterns that make a brand mention suspicious even without explicit scam rule
BRAND_PRETEXT_PATTERN = re.compile(
    r"\b(?:security\s+alert|fraud\s+alert|unauthorized\s+access|account\s+(?:locked|blocked|suspended|compromised)|verify\s+(?:identity|password|pin|details)|update\s+(?:kyc|payment\s+method)|official\s+notice)\b"
)


def analyze_message(message_text: str) -> MessageAnalysisResult:
    """
    Analyze a suspicious message for scam indicators.

    Args:
        message_text: The message text (email body, SMS, etc.)

    Returns:
        MessageAnalysisResult with risk score and evidence
    """
    if not message_text or not message_text.strip():
        return MessageAnalysisResult(
            risk_score=0,
            scam_type=None,
            indicators=[],
            urls_found=[],
            manipulation_tactics=[],
            impersonation_targets=[],
            recommended_actions=["No message content to analyze."],
            message_hash="",
        )

    # Hash the message for storage (never store raw message)
    message_hash = hashlib.sha256(message_text.encode("utf-8")).hexdigest()

    text_lower = message_text.lower()
    indicators = []
    max_score = 0
    detected_scam_type = None

    # Pre-process message: strip legitimate warning/caution clauses so they do not trigger false positive scam patterns
    clean_scam_text = text_lower
    for neg_pat in NEGATIVE_SIGNALS:
        clean_scam_text = neg_pat.sub(" ", clean_scam_text)

    # ── Pattern matching ──────────────────────────────────────
    for pattern, description, scam_type, severity in SCAM_PATTERNS:
        if description is None:
            continue  # Skip negative signal sentinel
        if re.search(pattern, clean_scam_text):
            indicators.append({
                "type": "pattern_match",
                "description": description,
                "scam_type": scam_type,
                "severity": severity,
            })
            if severity > max_score:
                max_score = severity
                detected_scam_type = scam_type

    # ── URL extraction ────────────────────────────────────────
    urls_found = URL_PATTERN.findall(message_text)
    if urls_found:
        indicators.append({
            "type": "urls_detected",
            "description": f"{len(urls_found)} URL(s) found in message",
            "severity": min(30 + len(urls_found) * 10, 60),
        })
        max_score = max(max_score, 30)

    # ── Manipulation tactics ──────────────────────────────────
    tactics_found = []
    for pattern, tactic_name in MANIPULATION_TACTICS:
        if re.search(pattern, text_lower):
            tactics_found.append(tactic_name)

    # ── Impersonation detection with contextual separation ───
    impersonation_targets = []
    has_suspicious_signals = bool(indicators or urls_found or tactics_found)

    for pattern, target_name in KNOWN_IMPERSONATION_TARGETS.items():
        if re.search(pattern, text_lower):
            # Check if brand appears in suspicious context or has other adverse signals
            has_pretext = bool(BRAND_PRETEXT_PATTERN.search(text_lower))
            if has_suspicious_signals or has_pretext or target_name in ["Law Enforcement Agency", "Income Tax Department", "Reserve Bank of India"]:
                impersonation_targets.append(target_name)
                indicators.append({
                    "type": "impersonation",
                    "description": f"Possible impersonation of: {target_name}",
                    "severity": 65,
                })
                max_score = max(max_score, 65)

    # ── Score adjustments ─────────────────────────────────────
    # De-duplicate strong indicators by distinct category to prevent stacking
    distinct_strong_categories = set(
        i.get("scam_type") or i.get("description")
        for i in indicators
        if i.get("severity", 0) >= 70
    )
    if len(distinct_strong_categories) >= 3:
        max_score = min(max_score + 15, 98)
    elif len(distinct_strong_categories) >= 2:
        max_score = min(max_score + 8, 98)

    # Add urgency tactics to score
    if len(tactics_found) >= 2:
        max_score = min(max_score + 10, 98)

    final_score = max_score

    return MessageAnalysisResult(
        risk_score=final_score,
        scam_type=_normalize_scam_type(detected_scam_type),
        indicators=sorted(indicators, key=lambda x: x.get("severity", 0), reverse=True),
        urls_found=urls_found[:20],  # Limit to first 20 URLs
        manipulation_tactics=list(set(tactics_found)),
        impersonation_targets=list(set(impersonation_targets)),
        recommended_actions=_get_message_recommendations(final_score, detected_scam_type),
        message_hash=message_hash,
    )


def _normalize_scam_type(scam_type: Optional[str]) -> Optional[str]:
    """Convert internal scam type to human-readable label."""
    labels = {
        "OTP_FRAUD": "OTP Fraud Attempt",
        "KYC_SCAM": "KYC Verification Scam",
        "ACCOUNT_THREAT": "Account Suspension Threat",
        "LOTTERY_SCAM": "Lottery / Prize Scam",
        "JOB_SCAM": "Fake Job / Internship Offer",
        "TASK_SCAM": "Social Media Task Scam",
        "INVESTMENT_SCAM": "Investment / Trading Scam",
        "ADVANCE_FEE": "Advance Fee Fraud",
        "COURIER_SCAM": "Fake Courier / Delivery Scam",
        "PHISHING": "Phishing Attempt",
        "IMPERSONATION": "Brand / Authority Impersonation",
        "URGENCY": "Urgency-based Manipulation",
    }
    return labels.get(scam_type, scam_type)


def _get_message_recommendations(score: int, scam_type: Optional[str]) -> list:
    """Generate recommendations based on message analysis."""
    base = []

    if score >= 75:
        base = [
            "This message shows strong indicators of a scam. Do not respond.",
            "Do not click any links in this message.",
            "Do not share any personal information, OTP, or passwords.",
            "Block and report the sender.",
        ]
    elif score >= 50:
        base = [
            "This message has suspicious characteristics.",
            "Do not share OTP, passwords, or financial information.",
            "Verify the sender's identity through official channels.",
            "Do not click unknown links.",
        ]
    elif score >= 25:
        base = [
            "Some caution is advised with this message.",
            "Verify the sender before responding.",
        ]
    else:
        base = [
            "No strong scam indicators detected.",
            "Always remain cautious with unexpected messages.",
        ]

    # Type-specific advice
    if scam_type == "OTP_FRAUD":
        base.append("Your bank or any legitimate service will NEVER ask for your OTP.")
    elif scam_type in ("KYC_SCAM", "ACCOUNT_THREAT"):
        base.append("Visit your bank's official website or call their official helpline to verify.")
    elif scam_type == "INVESTMENT_SCAM":
        base.append("Legitimate investments are never guaranteed. Report to SEBI if investment-related.")
    elif scam_type == "IMPERSONATION":
        base.append("Contact the impersonated organization directly using contact info from their official website.")

    return base
