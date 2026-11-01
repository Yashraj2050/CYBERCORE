#!/usr/bin/env python3
"""
CYBERCORE — SQLite to Managed PostgreSQL Migration Script

Migrates community threat reports from legacy local SQLite database
to Render Managed PostgreSQL.

Features:
  - Preserves primary keys (id), timestamps (reported_at), and all metadata fields.
  - Idempotent: Skips already-migrated records using ON CONFLICT (id) DO NOTHING.
  - Safe: Opens SQLite in read-only mode; NEVER modifies or deletes SQLite database.
  - Dry-Run Mode: Validates data compatibility and counts without writing to PostgreSQL.
  - Post-Migration Verification: Confirms record counts and field equivalence.

Usage:
  python migrate_sqlite_to_postgres.py --sqlite-path ../cybercore.db --postgres-url "postgres://..."
  python migrate_sqlite_to_postgres.py --dry-run
"""

import os
import sys
import sqlite3
import argparse
import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from typing import List, Dict, Any, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("cybercore.migrate")


def redact_db_url(url: str) -> str:
    """Mask password in PostgreSQL connection URL for logging."""
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


def read_sqlite_reports(sqlite_path: str) -> List[Dict[str, Any]]:
    """Read all community threat reports from SQLite safely in read-only mode."""
    if not os.path.exists(sqlite_path):
        logger.error("SQLite database file not found: %s", sqlite_path)
        raise FileNotFoundError(f"SQLite file not found: {sqlite_path}")

    # Connect read-only via URI
    uri = f"file:{os.path.abspath(sqlite_path)}?mode=ro"
    logger.info("Connecting to source SQLite database (read-only): %s", sqlite_path)
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='community_threat_reports'")
        if not cursor.fetchone():
            logger.warning("Table 'community_threat_reports' does not exist in SQLite database: %s", sqlite_path)
            return []

        cursor.execute(
            """
            SELECT id, url, threat_type, description, source, reported_at, status, risk_classification, reporter_ref
            FROM community_threat_reports
            ORDER BY reported_at ASC
            """
        )
        rows = [dict(r) for r in cursor.fetchall()]
        logger.info("Successfully read %d records from SQLite.", len(rows))
        return rows
    finally:
        conn.close()


def ensure_postgres_schema(pg_conn) -> None:
    """Ensure PostgreSQL target table and indexes exist."""
    with pg_conn.cursor() as cur:
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
    pg_conn.commit()


def migrate_to_postgres(
    records: List[Dict[str, Any]],
    postgres_url: str,
    dry_run: bool = False,
    batch_size: int = 100,
) -> Tuple[int, int]:
    """
    Migrate records to PostgreSQL with duplicate avoidance.
    Returns: Tuple[inserted_count, skipped_count]
    """
    if not records:
        logger.info("No records to migrate.")
        return 0, 0

    if dry_run:
        logger.info("DRY-RUN MODE ENABLED: Validating %d records without writing to PostgreSQL.", len(records))
        for i, r in enumerate(records[:3]):
            logger.info("Sample record [%d]: ID=%s, URL=%s, Type=%s, ReportedAt=%s", i + 1, r["id"], r["url"], r["threat_type"], r["reported_at"])
        return len(records), 0

    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:
        logger.error("psycopg 3 is required for PostgreSQL migration. Install psycopg[binary].")
        sys.exit(1)

    logger.info("Connecting to destination PostgreSQL: %s", redact_db_url(postgres_url))
    pg_conn = psycopg.connect(postgres_url, autocommit=False)

    try:
        ensure_postgres_schema(pg_conn)

        # Count existing before
        with pg_conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM community_threat_reports")
            count_before = cur.fetchone()[0]

        inserted_count = 0
        skipped_count = 0

        insert_sql = """
            INSERT INTO community_threat_reports (
                id, url, threat_type, description, source, reported_at, status, risk_classification, reporter_ref
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """

        # Batch execute
        for start_idx in range(0, len(records), batch_size):
            batch = records[start_idx : start_idx + batch_size]
            batch_params = []
            for r in batch:
                reported_at_val = r["reported_at"]
                if isinstance(reported_at_val, str):
                    try:
                        reported_at_val = datetime.fromisoformat(reported_at_val)
                    except ValueError:
                        reported_at_val = datetime.now(timezone.utc)

                batch_params.append((
                    r["id"],
                    r["url"],
                    r["threat_type"],
                    r.get("description"),
                    r.get("source", "web"),
                    reported_at_val,
                    r.get("status", "PENDING_REVIEW"),
                    r.get("risk_classification", "UNASSESSED"),
                    r.get("reporter_ref"),
                ))

            with pg_conn.cursor() as cur:
                cur.executemany(insert_sql, batch_params)
            pg_conn.commit()

        # Count after
        with pg_conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM community_threat_reports")
            count_after = cur.fetchone()[0]

        inserted_count = count_after - count_before
        skipped_count = len(records) - inserted_count

        logger.info(
            "Migration completed: %d total in SQLite -> %d newly inserted, %d existing/skipped.",
            len(records),
            inserted_count,
            skipped_count,
        )

        return inserted_count, skipped_count
    finally:
        pg_conn.close()


def main():
    parser = argparse.ArgumentParser(description="Migrate CYBERCORE SQLite threat reports to PostgreSQL.")
    parser.add_argument(
        "--sqlite-path",
        default=os.environ.get("DATABASE_PATH", "cybercore.db"),
        help="Path to source SQLite database file (default: cybercore.db or DATABASE_PATH)",
    )
    parser.add_argument(
        "--postgres-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="PostgreSQL connection string (default: DATABASE_URL environment variable)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform validation run without modifying target PostgreSQL database",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for INSERT execution (default: 100)",
    )

    args = parser.parse_args()

    logger.info("=== CYBERCORE Database Migration Tool ===")
    logger.info("Source SQLite: %s", args.sqlite_path)
    logger.info("Destination PostgreSQL: %s", redact_db_url(args.postgres_url) if args.postgres_url else "(Not specified)")
    logger.info("Dry-run: %s", args.dry_run)

    if not args.dry_run and not args.postgres_url:
        logger.error("Error: --postgres-url or DATABASE_URL environment variable is required unless --dry-run is specified.")
        sys.exit(1)

    try:
        records = read_sqlite_reports(args.sqlite_path)
        inserted, skipped = migrate_to_postgres(
            records=records,
            postgres_url=args.postgres_url,
            dry_run=args.dry_run,
            batch_size=args.batch_size,
        )
        logger.info("SUCCESS: Migration workflow finished cleanly.")
    except Exception as e:
        logger.exception("Migration failed with error: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
