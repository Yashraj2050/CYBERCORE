"""
Unit and Integration Tests for Community Threat Reporting (Phase 4B & Finding DASHBOARD-01)
Tests persistent SQLite storage, duplicate prevention, input validation,
restart persistence, and API endpoints.
"""

import os
import tempfile
import unittest
from starlette.testclient import TestClient

from app.main import app
from app.limiter import limiter
from app.services.report_store import ThreatReportStore, report_store


class TestThreatReporting(unittest.TestCase):
    def setUp(self):
        limiter.reset()
        # Use a temporary isolated database for isolated test execution
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.isolated_store = ThreatReportStore(db_path=self.temp_db.name)
        self.client = TestClient(app)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            try:
                os.unlink(self.temp_db.name)
            except OSError:
                pass

    def test_direct_store_creation_and_persistence(self):
        """Report must be saved to SQLite and retrieveable."""
        status, report = self.isolated_store.add_report(
            url="https://phishing-portal-test.xyz/login",
            threat_type="phishing",
            description="Fake corporate Single Sign-On lure",
            source="test_runner",
        )
        self.assertEqual(status, "CREATED")
        self.assertTrue(report["id"].startswith("rep_"))
        self.assertEqual(report["status"], "PENDING_REVIEW")
        self.assertEqual(report["risk_classification"], "UNASSESSED")

        # Verify count
        self.assertEqual(self.isolated_store.count_reports(), 1)

        # Retrieve and verify persistence
        reports = self.isolated_store.get_recent_reports()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["url"], "https://phishing-portal-test.xyz/login")
        self.assertEqual(reports[0]["threat_type"], "phishing")

    def test_persistence_across_restart(self):
        """Simulate backend restart by opening a brand new ThreatReportStore instance on existing DB."""
        # Add report in first instance
        status, report = self.isolated_store.add_report(
            url="https://trojan-delivery-test.com/payload.exe",
            threat_type="malware",
            description="Trojan payload dropper",
        )
        self.assertEqual(status, "CREATED")

        # Open secondary instance pointing to the same file (simulating server reboot)
        restarted_store = ThreatReportStore(db_path=self.temp_db.name)
        self.assertEqual(restarted_store.count_reports(), 1)
        reports = restarted_store.get_recent_reports()
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["id"], report["id"])
        self.assertEqual(reports[0]["url"], "https://trojan-delivery-test.com/payload.exe")

    def test_duplicate_submission_prevention(self):
        """Identical URL submitted within duplicate window must be recognized as DUPLICATE."""
        status1, report1 = self.isolated_store.add_report(
            url="https://scam-airdrop-crypto.com",
            threat_type="scam",
            description="First report submission",
        )
        self.assertEqual(status1, "CREATED")

        # Second submission of same URL
        status2, report2 = self.isolated_store.add_report(
            url="https://scam-airdrop-crypto.com",
            threat_type="scam",
            description="Second submission of duplicate indicator",
        )
        self.assertEqual(status2, "DUPLICATE")
        self.assertEqual(report2["id"], report1["id"])

        # Total count remains 1
        self.assertEqual(self.isolated_store.count_reports(), 1)

    def test_input_validation_empty_url(self):
        """Empty URL indicator must raise ValueError."""
        with self.assertRaises(ValueError):
            self.isolated_store.add_report(url="", threat_type="phishing")

    def test_input_validation_oversized_url(self):
        """URL exceeding MAX_URL_LENGTH (2048 chars) must raise ValueError."""
        long_url = "https://example.com/" + "a" * 2050
        with self.assertRaises(ValueError):
            self.isolated_store.add_report(url=long_url, threat_type="phishing")

    def test_api_report_endpoint_flow(self):
        """Test POST /api/v1/dashboard/report and GET /api/v1/dashboard/reports via FastAPI."""
        test_url = f"https://threat-test-{os.urandom(4).hex()}.org"
        res = self.client.post(
            "/api/v1/dashboard/report",
            json={
                "url": test_url,
                "threat_type": "phishing",
                "description": "Integration test report submission",
                "source": "api_test",
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["report"]["url"], test_url)
        self.assertEqual(data["report"]["status"], "PENDING_REVIEW")

        # Test duplicate submission over HTTP
        res_dup = self.client.post(
            "/api/v1/dashboard/report",
            json={
                "url": test_url,
                "threat_type": "phishing",
                "description": "Duplicate attempt",
            },
        )
        self.assertEqual(res_dup.status_code, 200)
        dup_data = res_dup.json()
        self.assertEqual(dup_data["status"], "DUPLICATE_ACKNOWLEDGED")
        self.assertEqual(dup_data["report"]["id"], data["report"]["id"])

        # Test querying GET /api/v1/dashboard/reports
        res_get = self.client.get("/api/v1/dashboard/reports?limit=10")
        self.assertEqual(res_get.status_code, 200)
        get_data = res_get.json()
        self.assertIn("reports", get_data)
        self.assertGreaterEqual(get_data["total_count"], 1)
        self.assertTrue(any(r["url"] == test_url for r in get_data["reports"]))


if __name__ == "__main__":
    unittest.main()
