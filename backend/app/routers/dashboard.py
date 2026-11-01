"""
CYBERCORE Backend — Dashboard & Threat Intelligence Feed Router

Provides telemetry, user safety summaries, threat intelligence feeds,
and user-submitted threat reports.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Request, Depends, status
from pydantic import BaseModel, Field

from app.services.report_store import report_store
from app.utils.security import require_admin_auth
from app.limiter import limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard & Telemetry"])


class ThreatReportRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="Malicious URL or domain being reported")
    threat_type: str = Field(default="phishing", description="phishing, malware, scam, impersonation, or other")
    description: Optional[str] = Field(None, max_length=1000)
    source: Optional[str] = Field("web", max_length=32)


class ReportStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="PENDING_REVIEW, VERIFIED, REJECTED, or RESOLVED")
    risk_classification: Optional[str] = Field(None, description="UNASSESSED, SAFE, SUSPICIOUS, HIGH, CRITICAL")


# In-memory recent threats / telemetry store for demonstration & local operation
RECENT_SCANS = [
    {
        "id": "scan-1",
        "target": "login-secure-verify-update.xyz",
        "type": "URL",
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "verdict": "Phishing & Fake Banking Portal",
        "timestamp": "2026-10-30T10:15:00Z",
    },
    {
        "id": "scan-2",
        "target": "github.com",
        "type": "URL",
        "risk_score": 4,
        "risk_level": "SAFE",
        "verdict": "Trusted Global Software Repository",
        "timestamp": "2026-10-30T10:22:00Z",
    },
    {
        "id": "scan-3",
        "target": "Urgent KYC Verification SMS",
        "type": "MESSAGE",
        "risk_score": 82,
        "risk_level": "CRITICAL",
        "verdict": "KYC Urgency Social Engineering Fraud",
        "timestamp": "2026-10-30T10:30:00Z",
    },
    {
        "id": "scan-4",
        "target": "invoice_payment_oct2026.pdf.exe",
        "type": "FILE",
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "verdict": "Disguised Executable Trojan",
        "timestamp": "2026-10-30T10:45:00Z",
    },
    {
        "id": "scan-5",
        "target": "cloudflare.com",
        "type": "URL",
        "risk_score": 0,
        "risk_level": "SAFE",
        "verdict": "Verified Infrastructure & CDN",
        "timestamp": "2026-10-30T10:50:00Z",
    },
]


@router.get("/stats")
async def get_dashboard_stats():
    """Retrieve aggregate security statistics and system protection status."""
    return {
        "safety_index": 94,
        "total_scans_today": 1428,
        "threats_intercepted": 312,
        "phishing_campaigns_detected": 49,
        "malware_signatures_verified": 87,
        "extension_active_users": 6540,
        "system_status": "OPERATIONAL",
        "protection_status": "ACTIVE_DEFENSE",
        "threat_level": "ELEVATED",
    }


@router.get("/recent")
async def get_recent_activity():
    """Retrieve recent scan activity and threat detection logs."""
    return {"recent_scans": RECENT_SCANS}


@router.get("/threat-feed")
async def get_live_threat_feed():
    """Returns curated threat intelligence highlights for the community feed."""
    return {
        "active_campaigns": [
            {
                "title": "Banking KYC SMS Phishing Surge",
                "severity": "HIGH",
                "indicators": ["apk downloads", "fake sbi/hdfc domains", "urgent suspension claims"],
                "recommendation": "Never download APKs from SMS links. Banks do not send APK updates via SMS.",
            },
            {
                "title": "Crypto Airdrop Discord / Telegram Lures",
                "severity": "CRITICAL",
                "indicators": ["drainer contracts", "fake metamask popups", "typosquatted domains"],
                "recommendation": "Verify smart contract addresses and never sign permit messages on unknown dApps.",
            },
            {
                "title": "Fake Courier Delivery Fee Scams",
                "severity": "MODERATE",
                "indicators": ["payment of small fee ($1-$2)", "fake tracking portal"],
                "recommendation": "Check tracking directly on official courier website rather than notification links.",
            },
        ]
    }


@router.post("/report")
@limiter.limit("5/minute")
async def report_threat(payload: ThreatReportRequest, request: Request):
    """
    Submit a threat URL or message for crowdsourced community protection.
    Persisted to the CYBERCORE database with duplicate detection and validation.
    Rate limited to 5 submissions per minute per client.
    """
    try:
        outcome, report = report_store.add_report(
            url=payload.url,
            threat_type=payload.threat_type,
            description=payload.description,
            source=payload.source or "web",
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        logger.exception("Failed to record threat report: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database failure. Unable to persist community threat report.",
        )

    if outcome == "DUPLICATE":
        return {
            "status": "DUPLICATE_ACKNOWLEDGED",
            "message": "A report for this target indicator has already been recorded within the last 24 hours.",
            "report": report,
        }

    return {
        "status": "SUCCESS",
        "message": "Threat report submitted successfully and stored for community defense.",
        "report": report,
    }


@router.get("/reports")
async def get_community_reports(limit: int = 20):
    """Retrieve recent verified community threat reports from persistent storage."""
    try:
        reports = report_store.get_recent_reports(limit=limit)
        return {
            "reports": reports,
            "total_count": report_store.count_reports(),
        }
    except Exception as e:
        logger.exception("Failed to query reports: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve community reports from database.",
        )


@router.patch("/reports/{report_id}")
async def moderate_community_report(
    report_id: str,
    payload: ReportStatusUpdateRequest,
    admin: str = Depends(require_admin_auth),
):
    """
    Administrative Endpoint: Moderate review status and risk classification of a report.
    Requires ADMIN_API_KEY authorization via X-Admin-Key or Authorization Bearer header.
    """
    try:
        updated = report_store.update_report_status(
            report_id=report_id,
            new_status=payload.status,
            risk_classification=payload.risk_classification,
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        logger.exception("Failed to moderate report %s: %s", report_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during report moderation.",
        )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with ID '{report_id}' not found.",
        )

    return {
        "status": "SUCCESS",
        "message": f"Report '{report_id}' status updated to '{payload.status.upper()}'.",
        "report": updated,
    }


@router.post("/backup")
async def trigger_database_backup(
    admin: str = Depends(require_admin_auth),
):
    """
    Administrative Endpoint: Triggers an online, hot, non-blocking SQLite database backup.
    Requires ADMIN_API_KEY authorization.
    """
    try:
        backup_path = report_store.backup_database()
        return {
            "status": "SUCCESS",
            "message": "Online hot backup completed and verified successfully.",
            "backup_file": os.path.basename(backup_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.exception("Database backup execution failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backup execution failed: {str(e)}",
        )
