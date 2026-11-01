#!/usr/bin/env python3
"""
CYBERCORE Automated Database Backup Utility
Executes an online, non-blocking hot backup of the SQLite database using conn.backup(),
verifies the quick_check integrity of the target file, and optionally prunes backups older
than a retention threshold.

Usage:
    python backend/scripts/backup_db.py [--retention-days 14] [--backup-dir /data/backups]
"""

import os
import sys
import argparse
import logging
from datetime import datetime, timezone, timedelta

# Add backend directory to sys.path so app imports resolve
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.services.report_store import report_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("backup_db")


def prune_old_backups(backup_dir: str, retention_days: int) -> int:
    """Delete backups older than retention_days."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=retention_days)
    pruned_count = 0

    if not os.path.exists(backup_dir):
        return 0

    for fname in os.listdir(backup_dir):
        if fname.startswith("cybercore_backup_") and fname.endswith(".db"):
            fpath = os.path.join(backup_dir, fname)
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc)
                if mtime < cutoff:
                    os.remove(fpath)
                    pruned_count += 1
                    logger.info("Pruned expired backup: %s (Age: %s)", fname, now - mtime)
            except OSError as e:
                logger.warning("Failed to inspect/prune %s: %s", fname, str(e))

    return pruned_count


def main():
    parser = argparse.ArgumentParser(description="CYBERCORE Online Database Backup Utility")
    parser.add_argument(
        "--backup-dir",
        default=None,
        help="Directory to store backup files (default: backend/backups or next to DB)",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=14,
        help="Number of days to retain backups before pruning (default: 14)",
    )
    args = parser.parse_args()

    logger.info("Starting online hot database backup...")
    try:
        backup_path = report_store.backup_database(backup_dir=args.backup_dir)
        size_kb = os.path.getsize(backup_path) / 1024.0
        logger.info("Backup successfully completed: %s (Size: %.2f KB)", backup_path, size_kb)

        backup_dir = os.path.dirname(backup_path)
        pruned = prune_old_backups(backup_dir, args.retention_days)
        if pruned > 0:
            logger.info("Pruned %d expired backup(s) exceeding %d-day retention limit", pruned, args.retention_days)

        print(f"SUCCESS: {backup_path}")
        sys.exit(0)
    except Exception as e:
        logger.exception("Backup execution failed: %s", str(e))
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
