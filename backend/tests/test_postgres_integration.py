"""
CYBERCORE Backend — PostgreSQL Integration & Reliability Test Suite

Executes comprehensive integration testing against real Managed PostgreSQL:
  1. Table initialization and schema migration
  2. Health check telemetry and metrics
  3. Report creation, retrieval, and ISO timestamp format
  4. 24-hour duplicate detection and idempotency
  5. Category sanitization and length validation
  6. Moderation updates and status transitions
  7. Concurrent submissions using connection pooling
  8. Transaction rollback on error
  9. Connection failure handling
 10. Production safety gate (refusal of SQLite fallback in production)
"""

import os
import sys
import unittest
import threading
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone, timedelta

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.report_store import ThreatReportStore, redact_db_url
from app.config import Settings

TEST_PG_URL = os.environ.get("TEST_DATABASE_URL", "postgresql://localhost/cybercore_test")


def is_postgres_available(url: str) -> bool:
    """Check if test PostgreSQL instance is reachable."""
    try:
        import psycopg
        conn = psycopg.connect(url, connect_timeout=3)
        conn.close()
        return True
    except Exception:
        return False


PG_AVAILABLE = is_postgres_available(TEST_PG_URL)


@unittest.skipUnless(PG_AVAILABLE, "PostgreSQL test database is unavailable on " + TEST_PG_URL)
class TestPostgreSQLIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        cls.pg_url = TEST_PG_URL
        # Clean slate before tests
        conn = psycopg.connect(cls.pg_url, autocommit=True)
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS community_threat_reports CASCADE;")
        conn.close()

    def setUp(self):
        self.store = ThreatReportStore(database_url=self.pg_url)

    def tearDown(self):
        self.store.close()

    def test_01_postgres_table_initialization_and_health(self):
        """Verify PostgreSQL table creation and /api/health report metrics."""
        healthy, msg, meta = self.store.check_health()
        self.assertTrue(healthy)
        self.assertEqual(msg, "ok")
        self.assertEqual(meta["engine"], "postgresql")
        self.assertIn("db_url", meta)
        # Ensure password is not present in logged db_url
        self.assertNotIn("password", meta["db_url"].lower())

    def test_02_report_creation_and_retrieval(self):
        """Verify report creation, retrieval, and ISO 8601 timestamp string format."""
        test_url = f"https://malicious-test-{uuid.uuid4().hex[:8]}.com/login"
        status, report = self.store.add_report(
            url=test_url,
            threat_type="phishing",
            description="Credential harvesting portal targeting bank users",
            source="test_runner",
        )
        self.assertEqual(status, "CREATED")
        self.assertTrue(report["id"].startswith("rep_"))
        self.assertEqual(report["url"], test_url)
        self.assertEqual(report["threat_type"], "phishing")
        self.assertEqual(report["status"], "PENDING_REVIEW")
        self.assertIsInstance(report["reported_at"], str)

        # Retrieve by ID
        fetched = self.store.get_report_by_id(report["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], report["id"])
        self.assertEqual(fetched["url"], test_url)
        self.assertIsInstance(fetched["reported_at"], str)

    def test_03_duplicate_detection_within_24_hours(self):
        """Verify that submitting identical URL within 24 hours returns DUPLICATE status."""
        test_url = f"https://duplicate-target-{uuid.uuid4().hex[:8]}.org/payload.bin"
        status1, report1 = self.store.add_report(url=test_url, threat_type="malware")
        self.assertEqual(status1, "CREATED")

        status2, report2 = self.store.add_report(url=test_url, threat_type="malware")
        self.assertEqual(status2, "DUPLICATE")
        self.assertEqual(report2["id"], report1["id"])

    def test_04_category_validation_and_limits(self):
        """Verify invalid threat types fall back to 'other' and bounds are respected."""
        test_url = f"https://category-test-{uuid.uuid4().hex[:8]}.net"
        status, report = self.store.add_report(
            url=test_url,
            threat_type="UNKNOWN_UNVERIFIED_TYPE",
        )
        self.assertEqual(status, "CREATED")
        self.assertEqual(report["threat_type"], "other")

        # Empty URL check
        with self.assertRaises(ValueError):
            self.store.add_report(url="   ", threat_type="phishing")

        # Max URL length check
        oversized_url = "https://example.com/" + ("a" * 2100)
        with self.assertRaises(ValueError):
            self.store.add_report(url=oversized_url, threat_type="phishing")

    def test_05_moderation_update(self):
        """Verify moderation updates: PENDING_REVIEW -> VERIFIED and risk classification."""
        test_url = f"https://moderation-test-{uuid.uuid4().hex[:8]}.com"
        _, report = self.store.add_report(url=test_url, threat_type="scam")
        report_id = report["id"]

        updated = self.store.update_report_status(
            report_id=report_id,
            new_status="VERIFIED",
            risk_classification="CONFIRMED_THREAT",
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "VERIFIED")
        self.assertEqual(updated["risk_classification"], "CONFIRMED_THREAT")

        # Invalid status must raise ValueError
        with self.assertRaises(ValueError):
            self.store.update_report_status(report_id, "ILLEGAL_STATUS")

    def test_06_concurrent_submissions(self):
        """Verify thread-safe concurrent submissions across connection pool."""
        errors = []
        created_ids = []

        def worker(idx: int):
            try:
                url = f"https://concurrency-test-{idx}-{uuid.uuid4().hex[:6]}.com"
                status, rep = self.store.add_report(url=url, threat_type="phishing")
                if status == "CREATED":
                    created_ids.append(rep["id"])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent workers encountered errors: {errors}")
        self.assertEqual(len(created_ids), 10)

    def test_07_transaction_rollback_on_error(self):
        """Verify transaction rollback when an error occurs during an atomic operation."""
        count_before = self.store.count_reports()
        test_url = f"https://rollback-test-{uuid.uuid4().hex[:8]}.com"

        try:
            with self.store._connection() as conn:
                with conn:
                    with conn.cursor() as cur:
                        p = self.store.placeholder
                        cur.execute(
                            f"INSERT INTO community_threat_reports (id, url, threat_type, reported_at) VALUES ({p}, {p}, {p}, NOW())",
                            (f"rep_{uuid.uuid4().hex[:12]}", test_url, "phishing"),
                        )
                        # Intentionally raise exception before transaction finishes
                        raise RuntimeError("Simulated mid-transaction failure")
        except RuntimeError:
            pass

        count_after = self.store.count_reports()
        self.assertEqual(count_before, count_after, "Failed transaction was not rolled back!")

    def test_08_connection_failure_handling(self):
        """Verify clear exception on invalid connection string."""
        with self.assertRaises(RuntimeError) as ctx:
            ThreatReportStore(database_url="postgresql://invalid_user:invalid_pass@127.0.0.1:5432/nonexistent_db_xyz")
        self.assertIn("Database connection failure", str(ctx.exception))

    def test_09_production_mode_refuses_sqlite(self):
        """Verify that in production mode (app_env='production'), missing DATABASE_URL raises RuntimeError."""
        with self.assertRaises(RuntimeError) as ctx:
            ThreatReportStore(database_url=None, app_env="production")
        self.assertIn("DATABASE_URL must be configured in production", str(ctx.exception))

    def test_10_backup_database_json_snapshot(self):
        """Verify online PostgreSQL database backup exports verified JSON snapshot."""
        backup_path = self.store.backup_database()
        self.assertTrue(os.path.exists(backup_path))
        self.assertTrue(backup_path.endswith(".json"))
        self.assertGreater(os.path.getsize(backup_path), 0)
        # Clean up temporary backup file
        try:
            os.remove(backup_path)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
