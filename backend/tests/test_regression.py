"""
CYBERCORE Backend — Full Regression Test Suite (Phase 4E)
Verifies all Phase 1, Phase 2, and Phase 3 API endpoints and behaviors.
"""

import io
import unittest
from starlette.testclient import TestClient

from app.main import app


class TestBackendRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_check(self):
        """GET /api/health must return service status and version."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "CYBERCORE API")

    def test_password_breached_prefix_validation(self):
        """Password endpoint enforces strict 5-hex character prefix."""
        # Valid prefix (first 5 chars of SHA-1 for 'password')
        res = self.client.get("/api/v1/password/breached/5BAA6")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("data", data)
        self.assertEqual(data["hash_prefix"], "5BAA6")

        # Invalid prefix length
        res_short = self.client.get("/api/v1/password/breached/5BA")
        self.assertEqual(res_short.status_code, 422)

        # Invalid non-hex characters
        res_invalid = self.client.get("/api/v1/password/breached/5BAAG")
        self.assertEqual(res_invalid.status_code, 422)

    def test_ai_chat_advisor(self):
        """POST /api/v1/ai/chat returns structured advisor response."""
        res = self.client.post(
            "/api/v1/ai/chat",
            json={
                "message": "Is this email asking for my password legitimate?",
                "history": [],
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("response", data)
        self.assertIn("suggested_followups", data)
        self.assertGreaterEqual(len(data["suggested_followups"]), 1)

    def test_file_analyze_multipart(self):
        """POST /api/v1/files/analyze handles multipart file upload and detects signatures."""
        content = b"MZ\x90\x00\x03\x00\x00\x00Dummy executable content for testing"
        fake_file = io.BytesIO(content)
        res = self.client.post(
            "/api/v1/files/analyze",
            files={"file": ("test_invoice.pdf.exe", fake_file, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["filename"], "test_invoice.pdf.exe")
        self.assertTrue(data["is_spoofed_extension"])
        self.assertGreaterEqual(data["risk_score"], 60)
        self.assertIn(data["threat_level"], ["HIGH", "CRITICAL"])
        self.assertIn("sha256", data)
        self.assertIn("detected_mime", data)

    def test_url_scanner(self):
        """POST /api/v1/scan/ executes full scan assessment and caches result."""
        res = self.client.post(
            "/api/v1/scan/",
            json={"url": "https://example.com", "source": "web"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("scan_id", data)
        self.assertIn("risk_score", data)
        self.assertIn("components", data)
        self.assertIn("coverage_percent", data)

        # Test lookup by scan_id
        scan_id = data["scan_id"]
        res_lookup = self.client.get(f"/api/v1/scan/{scan_id}")
        self.assertEqual(res_lookup.status_code, 200)
        lookup_data = res_lookup.json()
        self.assertEqual(lookup_data["scan_id"], scan_id)

    def test_url_scanner_ssrf_rejection(self):
        """POST /api/v1/scan/ rejects private IP / loopback addresses."""
        res = self.client.post(
            "/api/v1/scan/",
            json={"url": "http://127.0.0.1:8000/admin", "source": "web"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("private IP", res.json()["detail"])

    def test_ip_domain_analyzer(self):
        """POST /api/v1/ip-domain/analyze returns structured DNS and reputation."""
        res = self.client.post(
            "/api/v1/ip-domain/analyze",
            json={"query": "8.8.8.8"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["type"], "ip")
        self.assertEqual(data["target"], "8.8.8.8")
        self.assertIn("reputation", data)

    def test_message_analyzer_scam_and_negative_signal(self):
        """POST /api/v1/messages/analyze detects scam patterns and handles negative signals."""
        # 1. Suspicious message with OTP and account threat
        scam_res = self.client.post(
            "/api/v1/messages/analyze",
            json={"message": "Urgent: Your bank account will be suspended! Complete KYC and share your OTP immediately."},
        )
        self.assertEqual(scam_res.status_code, 200)
        scam_data = scam_res.json()
        self.assertGreaterEqual(scam_data["risk_score"], 70)
        self.assertIn(scam_data["risk_level"], ["HIGH_RISK", "CRITICAL"])
        self.assertGreaterEqual(len(scam_data["indicators"]), 1)

        # 2. Legitimate warning with negative signal
        benign_res = self.client.post(
            "/api/v1/messages/analyze",
            json={"message": "Security notice: Never share your OTP with anyone. Your bank will never call asking for PIN."},
        )
        self.assertEqual(benign_res.status_code, 200)
        benign_data = benign_res.json()
        self.assertLessEqual(benign_data["risk_score"], 25)

        # 3. Empty message rejection
        empty_res = self.client.post("/api/v1/messages/analyze", json={"message": "   "})
        self.assertEqual(empty_res.status_code, 400)

    def test_ip_domain_analyzer_ipv6_and_private_rejection(self):
        """POST /api/v1/ip-domain/analyze handles IPv6 and rejects private IP ranges."""
        # IPv6 Google DNS
        res_v6 = self.client.post("/api/v1/ip-domain/analyze", json={"query": "2001:4860:4860::8888"})
        self.assertEqual(res_v6.status_code, 200)
        data_v6 = res_v6.json()
        self.assertEqual(data_v6["type"], "ip")
        self.assertEqual(data_v6["ip_version"], 6)
        self.assertTrue(data_v6["is_global"])

        # Private IP rejection
        res_priv = self.client.post("/api/v1/ip-domain/analyze", json={"query": "192.168.1.1"})
        self.assertEqual(res_priv.status_code, 400)
        self.assertIn("private, loopback, or reserved IP", res_priv.json()["detail"])

    def test_hash_lookup_uppercase_normalization(self):
        """POST /api/v1/files/check-hash accepts and normalizes uppercase hex."""
        upper_hash = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
        res = self.client.post("/api/v1/files/check-hash", json={"hash_value": upper_hash})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["hash"], upper_hash.lower())

    def test_dashboard_stats_and_feed(self):
        """GET /api/v1/dashboard/stats and /threat-feed return valid telemetry."""
        stats_res = self.client.get("/api/v1/dashboard/stats")
        self.assertEqual(stats_res.status_code, 200)
        stats = stats_res.json()
        self.assertIn("safety_index", stats)
        self.assertIn("system_status", stats)

        feed_res = self.client.get("/api/v1/dashboard/threat-feed")
        self.assertEqual(feed_res.status_code, 200)
        feed = feed_res.json()
        self.assertIn("active_campaigns", feed)
        self.assertGreater(len(feed["active_campaigns"]), 0)


if __name__ == "__main__":
    unittest.main()
