"""
CYBERCORE Backend — File Security & Malware Analyzer Service

Features:
  - Cryptographic hash generation (SHA-256, SHA-1, MD5)
  - Magic byte / signature verification (detect extension spoofing)
  - High-risk file type heuristics (executable, script, macros)
  - VirusTotal hash reputation lookup
  - Privacy-preserving: supports hash-only queries
"""

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional
import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

DANGEROUS_EXTENSIONS = {
    ".exe": ("Windows Executable", 80),
    ".scr": ("Screensaver Executable (frequent malware)", 90),
    ".pif": ("Program Information File Executable", 90),
    ".bat": ("Windows Batch Script", 70),
    ".cmd": ("Windows Command Script", 70),
    ".vbs": ("VBScript File", 80),
    ".vbe": ("Encoded VBScript File", 85),
    ".js": ("JavaScript File", 50),
    ".jse": ("Encoded JScript File", 80),
    ".wsf": ("Windows Script File", 80),
    ".ps1": ("PowerShell Script", 75),
    ".msi": ("Windows Installer Package", 60),
    ".dll": ("Dynamic Link Library", 75),
    ".hta": ("HTML Application", 85),
    ".iso": ("Disk Image (often used to bypass mark-of-the-web)", 65),
    ".img": ("Disk Image", 65),
    ".jar": ("Java Executable Archive", 60),
    ".apk": ("Android Application Package", 50),
}

# Known file signatures (magic numbers)
MAGIC_SIGNATURES = [
    (b"MZ", "application/x-dosexec", "PE Executable (Windows Binary)"),
    (b"\x7fELF", "application/x-executable", "ELF Executable (Linux Binary)"),
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary", "Mach-O Binary (macOS)"),
    (b"%PDF-", "application/pdf", "PDF Document"),
    (b"PK\x03\x04", "application/zip", "ZIP Archive / Office Open XML"),
    (b"\x1f\x8b", "application/gzip", "GZIP Compressed File"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image"),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG Image"),
    (b"GIF87a", "image/gif", "GIF Image"),
    (b"GIF89a", "image/gif", "GIF Image"),
    (b"RIFF", "audio/video/webp", "RIFF Container"),
    (b"{\\", "text/rtf", "Rich Text Format (RTF)"),
]


@dataclass
class FileAnalysisResult:
    filename: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    detected_mime: str
    declared_extension: str
    is_spoofed_extension: bool
    risk_score: int
    threat_level: str
    findings: list[str]
    vt_reputation: Optional[dict] = None


def compute_hashes(data: bytes) -> tuple[str, str, str]:
    """Calculate MD5, SHA-1, and SHA-256 for byte data."""
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha1, sha256


def detect_file_type(header_bytes: bytes) -> tuple[str, str]:
    """Detect mime and type description from magic bytes."""
    for magic, mime, desc in MAGIC_SIGNATURES:
        if header_bytes.startswith(magic):
            return mime, desc
    return "application/octet-stream", "Binary / Text Data"


async def check_virustotal_file_hash(sha256_hash: str) -> Optional[dict]:
    """Query VirusTotal API v3 for a file hash."""
    api_key = settings.virustotal_api_key
    if not api_key:
        return {"status": "unconfigured", "message": "VirusTotal API key is not configured"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "status": "ok",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "message": "Hash not seen in VirusTotal database"}
            else:
                return {"status": "error", "message": f"VirusTotal returned HTTP {resp.status_code}"}
    except httpx.TimeoutException:
        logger.warning("VirusTotal file hash check timeout for %s", sha256_hash)
        return {"status": "timeout", "message": "VirusTotal API query timed out after 10.0s"}
    except Exception as e:
        logger.warning("VirusTotal file hash check error: %s", str(e))
        return {"status": "error", "message": f"VirusTotal query failed: {str(e)}"}


def analyze_file_data(filename: str, data: bytes, vt_data: Optional[dict] = None) -> FileAnalysisResult:
    """Analyze file bytes and metadata."""
    md5, sha1, sha256 = compute_hashes(data)
    size = len(data)

    ext = ""
    if "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()

    # Detect magic bytes
    mime, desc = detect_file_type(data[:32])

    findings = []
    risk_score = 0
    is_spoofed = False

    # Check for double extension (e.g. document.pdf.exe)
    parts = filename.lower().split(".")
    if len(parts) > 2:
        second_last = "." + parts[-2]
        last = "." + parts[-1]
        common_docs = {".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png"}
        if second_last in common_docs and last in DANGEROUS_EXTENSIONS:
            is_spoofed = True
            risk_score += 65
            findings.append(f"Deceptive double extension detected: '{second_last}{last}'. Common malware masquerading tactic.")

    # Check extension vs magic byte mismatch
    if ext in {".pdf", ".jpg", ".jpeg", ".png", ".gif"} and mime == "application/x-dosexec":
        is_spoofed = True
        risk_score += 85
        findings.append(f"CRITICAL MISMATCH: File named with '{ext}' extension but header contains Windows Executable (MZ) binary signature.")

    # High risk extension check
    if ext in DANGEROUS_EXTENSIONS:
        ext_desc, ext_risk = DANGEROUS_EXTENSIONS[ext]
        risk_score = max(risk_score, ext_risk)
        findings.append(f"High-risk extension detected: '{ext}' ({ext_desc}). Executables can run arbitrary code.")

    # VirusTotal incorporation
    if vt_data and vt_data.get("malicious", 0) > 0:
        mal_count = vt_data["malicious"]
        if mal_count >= 5:
            risk_score = 100
            findings.append(f"VirusTotal verdict: Flagged by {mal_count} security vendors as MALICIOUS.")
        elif mal_count >= 1:
            risk_score = max(risk_score, 75)
            findings.append(f"VirusTotal verdict: Flagged by {mal_count} security vendors as suspicious/malicious.")
    elif vt_data and vt_data.get("status") == "not_found":
        findings.append("File hash is new/unseen in the global VirusTotal database.")
    elif vt_data and vt_data.get("status") == "unconfigured":
        findings.append("VirusTotal reputation lookup skipped (API key not configured).")
    elif vt_data and vt_data.get("status") in {"error", "timeout"}:
        findings.append(f"VirusTotal reputation lookup unavailable ({vt_data.get('message', 'query failed')}).")

    # Baseline safe findings
    if risk_score == 0:
        findings.append("No immediate dangerous executable patterns or disguised file headers found.")

    risk_score = min(max(risk_score, 0), 100)

    if risk_score >= 80:
        threat_level = "CRITICAL"
    elif risk_score >= 60:
        threat_level = "HIGH"
    elif risk_score >= 35:
        threat_level = "SUSPICIOUS"
    elif risk_score >= 15:
        threat_level = "LOW_RISK"
    else:
        threat_level = "SAFE"

    return FileAnalysisResult(
        filename=filename,
        file_size=size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        detected_mime=mime,
        declared_extension=ext or "none",
        is_spoofed_extension=is_spoofed,
        risk_score=risk_score,
        threat_level=threat_level,
        findings=findings,
        vt_reputation=vt_data,
    )
