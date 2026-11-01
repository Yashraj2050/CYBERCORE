"""
CYBERCORE Backend — Message Scam Analyzer Router

Provides endpoints to analyze suspicious emails, SMS messages, and chat texts.
Privacy-first: the raw text is analyzed in-memory and NEVER stored. Only a SHA-256 hash
is recorded for deduplication and rate abuse prevention.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.limiter import limiter
from app.services.message_analyzer import analyze_message

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/messages", tags=["Message Scanner"])


class MessageAnalyzeRequest(BaseModel):
    message: Optional[str] = Field(None, min_length=1, max_length=10000)
    text: Optional[str] = Field(None, min_length=1, max_length=10000)
    source: Optional[str] = Field("web", description="Source client: web or extension")


class IndicatorItem(BaseModel):
    description: str
    pattern_type: Optional[str] = None
    severity: int
    matched_snippet: Optional[str] = None


class MessageAnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    scam_type: Optional[str]
    indicators: list[dict]
    urls_found: list[str]
    manipulation_tactics: list[str]
    impersonation_targets: list[str]
    recommended_actions: list[str]
    message_hash: str
    summary: str


def get_risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH_RISK"
    elif score >= 35:
        return "SUSPICIOUS"
    elif score >= 15:
        return "LOW_RISK"
    return "SAFE"


def get_risk_summary(score: int, scam_type: Optional[str]) -> str:
    if score >= 80:
        return f"🚨 Extreme Risk: This message strongly resembles a {scam_type or 'malicious scam'}. Do not interact, do not click links, and do not provide any personal or financial information."
    elif score >= 60:
        return f"⚠️ High Risk: Suspicious characteristics detected matching {scam_type or 'known fraudulent campaigns'}. Exercise severe caution."
    elif score >= 35:
        return f"⚡ Moderate Caution: Several manipulative or urgency-inducing phrases detected. Verify the sender through official independent channels."
    return "✅ Low Risk: No overt scam keywords or manipulative patterns identified. Always verify unexpected requests."


@router.post("/analyze", response_model=MessageAnalyzeResponse)
@limiter.limit("30/minute")
async def analyze_suspicious_message(payload: MessageAnalyzeRequest, request: Request):
    """
    Analyzes message text for phishing indicators, social engineering,
    urgency tactics, OTP fraud, and brand impersonation.
    """
    text = (payload.message or payload.text or "").strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be blank.",
        )

    try:
        result = analyze_message(text)
        risk_level = get_risk_level(result.risk_score)
        summary = get_risk_summary(result.risk_score, result.scam_type)

        return MessageAnalyzeResponse(
            risk_score=result.risk_score,
            risk_level=risk_level,
            scam_type=result.scam_type,
            indicators=result.indicators,
            urls_found=result.urls_found,
            manipulation_tactics=result.manipulation_tactics,
            impersonation_targets=result.impersonation_targets,
            recommended_actions=result.recommended_actions,
            message_hash=result.message_hash,
            summary=summary,
        )
    except Exception as e:
        logger.error("Error analyzing message: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while evaluating the message.",
        )
