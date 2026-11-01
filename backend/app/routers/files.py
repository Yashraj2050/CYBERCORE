"""
CYBERCORE Backend — File Security & Malware Router

Provides endpoints for inspecting potentially dangerous files:
  1. POST /api/v1/files/analyze - Upload file for signature and hash analysis (up to 25MB)
  2. POST /api/v1/files/check-hash - Check a file's SHA-256 hash without uploading the file itself
"""

import logging
import re
from typing import Optional
from fastapi import APIRouter, File, UploadFile, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.limiter import limiter
from app.services.file_analyzer import (
    analyze_file_data,
    check_virustotal_file_hash,
    FileAnalysisResult,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files", tags=["File Security"])

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


class HashCheckRequest(BaseModel):
    hash_value: str = Field(..., min_length=32, max_length=64, description="MD5, SHA-1, or SHA-256 hash")
    filename: Optional[str] = Field(None, description="Optional original filename for extension heuristics")


@router.post("/analyze")
@limiter.limit("10/minute")
async def analyze_file(request: Request, file: UploadFile = File(...)):
    """
    Upload and analyze a file for malware indicators, disguised extensions,
    and VirusTotal threat reputation.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a filename."
        )

    # Read bytes safely with size check
    content = await file.read(MAX_FILE_SIZE + 1024)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of 25MB.",
        )

    # Calculate SHA-256 and query VirusTotal if enabled
    import hashlib
    sha256 = hashlib.sha256(content).hexdigest()
    vt_data = await check_virustotal_file_hash(sha256)

    result = analyze_file_data(file.filename, content, vt_data=vt_data)

    return {
        "filename": result.filename,
        "file_size": result.file_size,
        "md5": result.md5,
        "sha1": result.sha1,
        "sha256": result.sha256,
        "detected_mime": result.detected_mime,
        "declared_extension": result.declared_extension,
        "is_spoofed_extension": result.is_spoofed_extension,
        "risk_score": result.risk_score,
        "threat_level": result.threat_level,
        "findings": result.findings,
        "vt_reputation": result.vt_reputation,
    }


@router.post("/check-hash")
@limiter.limit("30/minute")
async def check_hash_alone(payload: HashCheckRequest, request: Request):
    """
    Privacy-first: Check a file's threat intelligence by hash alone.
    The user's file is never transmitted across the network.
    """
    h = payload.hash_value.strip().lower()
    if not (re.match(r"^[a-f0-9]{32}$", h) or re.match(r"^[a-f0-9]{40}$", h) or re.match(r"^[a-f0-9]{64}$", h)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hash format. Must be hexadecimal 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.",
        )

    vt_data = await check_virustotal_file_hash(h)

    risk_score: Optional[int] = None
    threat_level: str = "UNASSESSED"
    findings: list[str] = []

    if not vt_data or vt_data.get("status") == "unconfigured":
        threat_level = "UNASSESSED"
        risk_score = None
        findings.append("VirusTotal threat intelligence engine is unconfigured on this server. Cryptographic signature cannot be assessed.")
    elif vt_data.get("status") in {"error", "timeout"}:
        threat_level = "UNASSESSED"
        risk_score = None
        findings.append(f"Threat intelligence query failed: {vt_data.get('message', 'External query error')}. Target remains unassessed.")
    elif vt_data.get("status") == "not_found":
        threat_level = "SAFE"
        risk_score = 0
        findings.append("Hash not found in public malware databases (no threat detections recorded in VirusTotal). Note: Absence of prior detections does not guarantee that an unknown binary is harmless.")
    elif vt_data.get("malicious", 0) > 0:
        mal_count = vt_data["malicious"]
        risk_score = min(mal_count * 15, 100)
        threat_level = "CRITICAL" if mal_count >= 5 else "HIGH"
        findings.append(f"Flagged by {mal_count} security vendors as malicious on VirusTotal.")
    elif vt_data.get("suspicious", 0) > 0:
        susp_count = vt_data["suspicious"]
        risk_score = min(susp_count * 10, 50)
        threat_level = "SUSPICIOUS"
        findings.append(f"Flagged by {susp_count} security vendors as suspicious on VirusTotal.")
    else:
        # Zero malicious, zero suspicious
        total_engines = vt_data.get("total_engines", 0)
        threat_level = "SAFE"
        risk_score = 0
        if total_engines > 0:
            findings.append(f"No threat detections found in VirusTotal: evaluated across {total_engines} security vendors with 0 detections. Note: Absence of detections reduces risk but does not guarantee complete safety.")
        else:
            findings.append("No threat detections recorded for this cryptographic signature in VirusTotal.")

    return {
        "hash": h,
        "filename": payload.filename,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "findings": findings,
        "vt_reputation": vt_data,
    }
