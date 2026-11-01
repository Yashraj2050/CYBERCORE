"""
CYBERCORE Backend — Persistent Community Threat Report Store

Thread-safe SQLite storage for community threat reports.
Provides persistent storage across server restarts, input sanitization,
length enforcement, and duplicate detection.
"""

import os
import sqlite3
import uuid
import logging
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple, Generator

from app.config import get_settings

logger = logging.getLogger(__name__)

ALLOWED_THREAT_TYPES = {
    "phishing",
    "malware",
    "scam",
    "impersonation",
    "credential_harvesting",
    "suspicious_infrastructure",
    "other",
}

MAX_URL_LENGTH = 2048
MAX_DESC_LENGTH = 1000
DUPLICATE_WINDOW_HOURS = 24


class ThreatReportStore:
    def __init__(self, db_path: Optional[str] = None):
        settings = get_settings()
        if db_path:
            self.db_path = db_path
        else:
            configured_path = settings.database_path or "cybercore.db"
            if not os.path.isabs(configured_path):
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                self.db_path = os.path.join(base_dir, configured_path)
            else:
                self.db_path = configured_path

        self._init_db()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager that guarantees connection is closed on exit with WAL concurrency pragmas."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        # Concurrency & durability pragmas: WAL mode enables concurrent readers during writes
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize SQLite table and indexes if they do not exist."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            with self._connection() as conn:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS community_threat_reports (
                            id TEXT PRIMARY KEY,
                            url TEXT NOT NULL,
                            threat_type TEXT NOT NULL,
                            description TEXT,
                            source TEXT NOT NULL DEFAULT 'web',
                            reported_at TEXT NOT NULL,
                            status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
                            risk_classification TEXT NOT NULL DEFAULT 'UNASSESSED',
                            reporter_ref TEXT
                        )
                        """
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_threat_reports_url ON community_threat_reports(url)"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_threat_reports_time ON community_threat_reports(reported_at)"
                    )
            logger.info("ThreatReportStore initialized at %s", self.db_path)
        except Exception as e:
            logger.exception("Failed to initialize threat report database: %s", str(e))
            raise

    def add_report(
        self,
        url: str,
        threat_type: str,
        description: Optional[str] = None,
        source: str = "web",
        reporter_ref: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Add a community threat report.

        Returns:
            Tuple[outcome_status, report_dict]
            where outcome_status is 'CREATED' or 'DUPLICATE'
        """
        clean_url = (url or "").strip()
        if not clean_url:
            raise ValueError("Target indicator/URL cannot be empty")
        if len(clean_url) > MAX_URL_LENGTH:
            raise ValueError(f"Indicator exceeds maximum allowed length of {MAX_URL_LENGTH} characters")

        clean_threat_type = (threat_type or "").strip().lower()
        if clean_threat_type not in ALLOWED_THREAT_TYPES:
            clean_threat_type = "other"

        clean_desc = (description or "").strip()[:MAX_DESC_LENGTH] if description else None
        clean_source = (source or "web").strip()[:32]

        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=DUPLICATE_WINDOW_HOURS)).isoformat()

        with self._connection() as conn:
            # Check for existing report for this URL within the last 24 hours
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                FROM community_threat_reports
                WHERE url = ? AND reported_at >= ?
                ORDER BY reported_at DESC
                LIMIT 1
                """,
                (clean_url, cutoff),
            )
            existing = cursor.fetchone()
            if existing:
                logger.info("Duplicate threat report detected for %s (Existing ID: %s)", clean_url, existing["id"])
                return "DUPLICATE", dict(existing)

            # Insert new report
            report_id = f"rep_{uuid.uuid4().hex[:12]}"
            reported_at_iso = now.isoformat()
            default_status = "PENDING_REVIEW"
            default_risk = "UNASSESSED"

            with conn:
                conn.execute(
                    """
                    INSERT INTO community_threat_reports (
                        id, url, threat_type, description, source, reported_at, status, risk_classification, reporter_ref
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report_id,
                        clean_url,
                        clean_threat_type,
                        clean_desc,
                        clean_source,
                        reported_at_iso,
                        default_status,
                        default_risk,
                        reporter_ref,
                    ),
                )

            report = {
                "id": report_id,
                "url": clean_url,
                "threat_type": clean_threat_type,
                "description": clean_desc,
                "source": clean_source,
                "reported_at": reported_at_iso,
                "status": default_status,
                "risk_classification": default_risk,
            }
            logger.info("New threat report recorded: %s (Type: %s)", report_id, clean_threat_type)
            return "CREATED", report

    def get_recent_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent community threat reports, omitting internal/reporter IDs."""
        limit = min(max(limit, 1), 100)
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                FROM community_threat_reports
                ORDER BY reported_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def count_reports(self) -> int:
        """Count total persisted reports."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM community_threat_reports")
            return cursor.fetchone()[0]

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single report by its primary identifier."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                FROM community_threat_reports
                WHERE id = ?
                """,
                (report_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_report_status(
        self,
        report_id: str,
        new_status: str,
        risk_classification: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Update review status and optional risk classification of a community report.
        Allowed statuses: PENDING_REVIEW, VERIFIED, REJECTED, RESOLVED.
        """
        allowed_statuses = {"PENDING_REVIEW", "VERIFIED", "REJECTED", "RESOLVED"}
        clean_status = (new_status or "").strip().upper()
        if clean_status not in allowed_statuses:
            raise ValueError(f"Invalid status. Must be one of: {allowed_statuses}")

        with self._connection() as conn:
            with conn:
                if risk_classification:
                    conn.execute(
                        """
                        UPDATE community_threat_reports
                        SET status = ?, risk_classification = ?
                        WHERE id = ?
                        """,
                        (clean_status, risk_classification.strip().upper(), report_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE community_threat_reports
                        SET status = ?
                        WHERE id = ?
                        """,
                        (clean_status, report_id),
                    )
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                FROM community_threat_reports
                WHERE id = ?
                """,
                (report_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def check_health(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify database connectivity, integrity check, and operational metrics.
        Returns: Tuple[is_healthy, message, metadata_dict]
        """
        try:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.execute("PRAGMA quick_check(1)")
                check_result = cursor.fetchone()[0]
                is_healthy = (check_result == "ok")

                cursor.execute("SELECT COUNT(*) FROM community_threat_reports")
                total = cursor.fetchone()[0]

                return is_healthy, check_result, {
                    "healthy": is_healthy,
                    "engine": "sqlite3",
                    "mode": "WAL",
                    "db_path": self.db_path,
                    "total_reports": total,
                }
        except Exception as e:
            logger.exception("Database health check error: %s", str(e))
            return False, str(e), {
                "healthy": False,
                "engine": "sqlite3",
                "error": str(e),
                "db_path": self.db_path,
            }

    def backup_database(self, backup_dir: Optional[str] = None) -> str:
        """
        Perform an online, lock-free hot backup via SQLite's conn.backup() API.
        Ensures zero-downtime, non-blocking backup with post-backup integrity validation.
        Returns the absolute destination path to the created backup.
        """
        if not backup_dir:
            backup_dir = os.path.join(os.path.dirname(os.path.abspath(self.db_path)), "backups")
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_filename = f"cybercore_backup_{timestamp}.db"
        backup_path = os.path.join(backup_dir, backup_filename)

        with self._connection() as src_conn:
            dest_conn = sqlite3.connect(backup_path)
            try:
                src_conn.backup(dest_conn, pages=100)
                # Verify backup file integrity
                dest_cursor = dest_conn.cursor()
                dest_cursor.execute("PRAGMA quick_check(1)")
                verify = dest_cursor.fetchone()[0]
                if verify != "ok":
                    raise RuntimeError(f"Backup file integrity validation failed: {verify}")
            finally:
                dest_conn.close()

        logger.info("Online database backup successfully created: %s", backup_path)
        return backup_path


# Global singleton instance for application use
report_store = ThreatReportStore()
