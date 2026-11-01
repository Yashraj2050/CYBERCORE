"""
CYBERCORE Backend — Persistent Community Threat Report Store

High-performance, thread-safe storage for community threat reports.
Supports Managed PostgreSQL via psycopg 3 with connection pooling (Production),
and SQLite in WAL mode (Development fallback and local testing).

Provides persistent storage across server restarts, input sanitization,
length enforcement, duplicate detection, and health telemetry.
"""

import os
import json
import sqlite3
import uuid
import logging
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple, Generator
from urllib.parse import urlsplit, urlunsplit

from app.config import get_settings

logger = logging.getLogger(__name__)

# Optional psycopg 3 imports with clean degradation
try:
    import psycopg
    from psycopg_pool import ConnectionPool
    from psycopg.rows import dict_row
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False
    ConnectionPool = None  # type: ignore
    dict_row = None  # type: ignore

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


def redact_db_url(url: Optional[str]) -> str:
    """Mask credentials in database connection URLs for safe operational logging."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        if parts.password:
            netloc = f"{parts.username or ''}:***@{parts.hostname or ''}"
            if parts.port:
                netloc += f":{parts.port}"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        return url
    except Exception:
        return "[REDACTED_DATABASE_URL]"


class ThreatReportStore:
    is_postgres: bool = False
    engine: str = "sqlite3"
    database_url: Optional[str] = None
    db_path: Optional[str] = None
    pool: Optional[Any] = None
    app_env: str = "development"

    def __init__(
        self,
        database_url: Optional[str] = None,
        db_path: Optional[str] = None,
        app_env: Optional[str] = None,
    ):
        settings = get_settings()

        # Determine target engine and environment
        self.app_env = app_env or settings.app_env
        self.database_url = database_url or settings.database_url
        self.db_path: Optional[str] = None
        self.pool: Optional[Any] = None
        self.is_postgres = False

        if self.app_env == "production":
            if not self.database_url:
                raise RuntimeError(
                    "FATAL: DATABASE_URL must be configured in production! "
                    "Managed PostgreSQL connection string is required. "
                    "Silent fallback to SQLite is disallowed in production mode."
                )

        if self.database_url:
            if not PSYCOPG_AVAILABLE:
                raise RuntimeError(
                    "psycopg 3 is required for PostgreSQL connections, but is not installed. "
                    "Install psycopg[binary] and psycopg-pool."
                )
            self.is_postgres = True
            self.engine = "postgresql"
            self._init_postgres_pool()
        else:
            self.is_postgres = False
            self.engine = "sqlite3"
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

    def _init_postgres_pool(self) -> None:
        """Initialize psycopg 3 connection pool with safe defaults."""
        try:
            logger.info("Initializing PostgreSQL connection pool (%s)...", redact_db_url(self.database_url))
            self.pool = ConnectionPool(
                conninfo=self.database_url,
                min_size=1,
                max_size=10,
                timeout=5.0,
                open=False,
                kwargs={
                    "row_factory": dict_row,
                    "autocommit": False,
                    "connect_timeout": 5,
                    "options": "-c statement_timeout=10000",
                },
            )
            self.pool.open(wait=True, timeout=5.0)
            logger.info("PostgreSQL connection pool established successfully.")
        except Exception as e:
            logger.exception("Failed to connect to PostgreSQL database: %s", str(e))
            raise RuntimeError(f"Database connection failure: {str(e)}") from e

    @property
    def placeholder(self) -> str:
        """SQL bind parameter placeholder: %s for PostgreSQL, ? for SQLite."""
        return "%s" if self.is_postgres else "?"

    @contextmanager
    def _connection(self) -> Generator[Any, None, None]:
        """Context manager yielding a database connection with guaranteed cleanup."""
        if self.is_postgres:
            if not self.pool:
                raise RuntimeError("PostgreSQL connection pool is closed or uninitialized.")
            with self.pool.connection(timeout=10.0) as conn:
                yield conn
        else:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            try:
                yield conn
            finally:
                conn.close()

    def _init_db(self) -> None:
        """Initialize database tables and indexes safely for multiple worker instances."""
        try:
            if self.is_postgres:
                with self._connection() as conn:
                    with conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                CREATE TABLE IF NOT EXISTS community_threat_reports (
                                    id VARCHAR(32) PRIMARY KEY,
                                    url TEXT NOT NULL,
                                    threat_type VARCHAR(64) NOT NULL,
                                    description VARCHAR(1000),
                                    source VARCHAR(32) NOT NULL DEFAULT 'web',
                                    reported_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_REVIEW',
                                    risk_classification VARCHAR(32) NOT NULL DEFAULT 'UNASSESSED',
                                    reporter_ref VARCHAR(255)
                                );
                                CREATE INDEX IF NOT EXISTS idx_threat_reports_url ON community_threat_reports(url);
                                CREATE INDEX IF NOT EXISTS idx_threat_reports_time ON community_threat_reports(reported_at DESC);
                                """
                            )
                logger.info("PostgreSQL schema initialized successfully.")
            else:
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
                logger.info("ThreatReportStore SQLite initialized at %s", self.db_path)
        except Exception as e:
            logger.exception("Failed to initialize threat report database schema: %s", str(e))
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
        cutoff = now - timedelta(hours=DUPLICATE_WINDOW_HOURS)
        cutoff_val = cutoff if self.is_postgres else cutoff.isoformat()
        reported_at_val = now if self.is_postgres else now.isoformat()

        p = self.placeholder

        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                    FROM community_threat_reports
                    WHERE url = {p} AND reported_at >= {p}
                    ORDER BY reported_at DESC
                    LIMIT 1
                    """,
                    (clean_url, cutoff_val),
                )
                existing = cursor.fetchone()
                if existing:
                    existing_dict = self._row_to_dict(existing)
                    logger.info("Duplicate threat report detected for %s (Existing ID: %s)", clean_url, existing_dict["id"])
                    return "DUPLICATE", existing_dict

                report_id = f"rep_{uuid.uuid4().hex[:12]}"
                default_status = "PENDING_REVIEW"
                default_risk = "UNASSESSED"

                cursor.execute(
                    f"""
                    INSERT INTO community_threat_reports (
                        id, url, threat_type, description, source, reported_at, status, risk_classification, reporter_ref
                    ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
                    """,
                    (
                        report_id,
                        clean_url,
                        clean_threat_type,
                        clean_desc,
                        clean_source,
                        reported_at_val,
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
            "reported_at": now.isoformat(),
            "status": default_status,
            "risk_classification": default_risk,
        }
        logger.info("New threat report recorded: %s (Type: %s, Engine: %s)", report_id, clean_threat_type, self.engine)
        return "CREATED", report

    def get_recent_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent community threat reports, omitting internal reporter references."""
        limit = min(max(limit, 1), 100)
        p = self.placeholder
        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                    FROM community_threat_reports
                    ORDER BY reported_at DESC
                    LIMIT {p}
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                return [self._row_to_dict(row) for row in rows]

    def count_reports(self) -> int:
        """Count total persisted reports."""
        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM community_threat_reports")
                result = cursor.fetchone()
                if isinstance(result, dict):
                    return list(result.values())[0]
                return result[0]

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single report by its primary identifier."""
        p = self.placeholder
        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"""
                    SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                    FROM community_threat_reports
                    WHERE id = {p}
                    """,
                    (report_id,),
                )
                row = cursor.fetchone()
                return self._row_to_dict(row) if row else None

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

        p = self.placeholder
        with self._connection() as conn:
            with conn:
                cursor = conn.cursor()
                if risk_classification:
                    cursor.execute(
                        f"""
                        UPDATE community_threat_reports
                        SET status = {p}, risk_classification = {p}
                        WHERE id = {p}
                        """,
                        (clean_status, risk_classification.strip().upper(), report_id),
                    )
                else:
                    cursor.execute(
                        f"""
                        UPDATE community_threat_reports
                        SET status = {p}
                        WHERE id = {p}
                        """,
                        (clean_status, report_id),
                    )

                cursor.execute(
                    f"""
                    SELECT id, url, threat_type, description, source, reported_at, status, risk_classification
                    FROM community_threat_reports
                    WHERE id = {p}
                    """,
                    (report_id,),
                )
                row = cursor.fetchone()
                return self._row_to_dict(row) if row else None

    def check_health(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify database connectivity, integrity check, and operational metrics.
        Returns: Tuple[is_healthy, message, metadata_dict]
        """
        try:
            with self._connection() as conn:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1")
                    if self.is_postgres:
                        check_result = "ok"
                        cursor.execute("SELECT COUNT(*) FROM community_threat_reports")
                        result = cursor.fetchone()
                        total = list(result.values())[0] if isinstance(result, dict) else result[0]
                        return True, check_result, {
                            "healthy": True,
                            "engine": "postgresql",
                            "db_url": redact_db_url(self.database_url),
                            "total_reports": total,
                        }
                    else:
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
                "engine": self.engine,
                "error": str(e),
                "target": redact_db_url(self.database_url) if self.is_postgres else self.db_path,
            }

    def backup_database(self, backup_dir: Optional[str] = None) -> str:
        """
        Perform an online database backup.
        In PostgreSQL: Exports all threat reports to a validated JSON snapshot file.
        In SQLite: Executes an online lock-free hot backup via conn.backup().
        Returns the absolute destination path to the created backup.
        """
        target_dir = backup_dir
        if not target_dir:
            if self.is_postgres:
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                target_dir = os.path.join(base_dir, "backups")
            else:
                target_dir = os.path.join(os.path.dirname(os.path.abspath(self.db_path)), "backups")

        os.makedirs(target_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if self.is_postgres:
            backup_filename = f"cybercore_pg_backup_{timestamp}.json"
            backup_path = os.path.join(target_dir, backup_filename)
            with self._connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, url, threat_type, description, source,
                               reported_at, status, risk_classification, reporter_ref
                        FROM community_threat_reports
                        ORDER BY reported_at ASC
                        """
                    )
                    rows = cur.fetchall()
            reports = [self._row_to_dict(r) for r in rows]
            total_count = len(reports)
            backup_payload = {
                "engine": "postgresql",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_records": total_count,
                "records": reports,
            }
            with open(backup_path, "w", encoding="utf-8") as f:
                json.dump(backup_payload, f, indent=2)

            if not os.path.exists(backup_path) or os.path.getsize(backup_path) == 0:
                raise RuntimeError("PostgreSQL snapshot backup creation failed: Empty or missing file.")
            logger.info("PostgreSQL database snapshot backup created: %s (%d records)", backup_path, total_count)
            return backup_path
        else:
            backup_filename = f"cybercore_backup_{timestamp}.db"
            backup_path = os.path.join(target_dir, backup_filename)
            with self._connection() as src_conn:
                dest_conn = sqlite3.connect(backup_path)
                try:
                    src_conn.backup(dest_conn, pages=100)
                    dest_cursor = dest_conn.cursor()
                    dest_cursor.execute("PRAGMA quick_check(1)")
                    verify = dest_cursor.fetchone()[0]
                    if verify != "ok":
                        raise RuntimeError(f"Backup file integrity validation failed: {verify}")
                finally:
                    dest_conn.close()
            logger.info("Online SQLite database backup successfully created: %s", backup_path)
            return backup_path

    def close(self) -> None:
        """Close connection pool cleanly during application shutdown."""
        if self.is_postgres and self.pool:
            try:
                self.pool.close()
                logger.info("PostgreSQL connection pool closed cleanly.")
            except Exception as e:
                logger.warning("Error closing PostgreSQL connection pool: %s", str(e))
            finally:
                self.pool = None

    def _row_to_dict(self, row: Any) -> Dict[str, Any]:
        """Convert database row to standardized dictionary with ISO 8601 timestamps."""
        if row is None:
            return {}
        d = dict(row)
        if "reported_at" in d and isinstance(d["reported_at"], datetime):
            d["reported_at"] = d["reported_at"].isoformat()
        return d


# Global singleton instance for application use
report_store = ThreatReportStore()
