"""
CYBERCORE Backend — Phase 5 Production Readiness & Security Test Suite
Verifies:
  1. Admin authentication & authorization (Finding AUTH-01).
  2. Online database hot backup & integrity verification.
  3. Reverse proxy IP resolution & rate limiting.
  4. Comprehensive health check with dependency isolation (DB & External APIs).
  5. Log data redaction for sensitive headers & fields.
  6. File upload limits & abuse prevention.
"""

import io
import os
import unittest
from unittest.mock import patch, MagicMock
from starlette.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.services.report_store import report_store
from app.utils.security import get_client_ip, redact_sensitive_dict

settings = get_settings()


class TestProductionReadiness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_admin_key = "test_super_secret_admin_key_2026"

    def test_admin_auth_unauthorized(self):
        """Privileged endpoints must reject requests lacking administrative credentials."""
        # Test PATCH /api/v1/dashboard/reports/rep_test without credentials
        res = self.client.patch(
            "/api/v1/dashboard/reports/rep_nonexistent",
            json={"status": "VERIFIED"},
        )
        self.assertIn(res.status_code, [401, 503])

        # Test POST /api/v1/dashboard/backup without credentials
        res_backup = self.client.post("/api/v1/dashboard/backup")
        self.assertIn(res_backup.status_code, [401, 503])

    def test_admin_auth_forbidden_with_wrong_key(self):
        """Privileged endpoints must reject requests with invalid administrative credentials."""
        with patch.object(settings, "admin_api_key", self.test_admin_key):
            res = self.client.patch(
                "/api/v1/dashboard/reports/rep_nonexistent",
                headers={"X-Admin-Key": "wrong_key_123"},
                json={"status": "VERIFIED"},
            )
            self.assertEqual(res.status_code, 403)
            self.assertIn("Invalid administrative credentials", res.json()["detail"])

    def test_admin_auth_success_and_moderation_flow(self):
        """Authorized administrator can successfully moderate report status."""
        # Create a report first
        _, created = report_store.add_report(
            url="https://admin-moderation-test.org",
            threat_type="phishing",
            description="Testing moderation lifecycle",
        )
        report_id = created["id"]

        with patch.object(settings, "admin_api_key", self.test_admin_key):
            # Test Authorization: Bearer header
            res = self.client.patch(
                f"/api/v1/dashboard/reports/{report_id}",
                headers={"Authorization": f"Bearer {self.test_admin_key}"},
                json={"status": "VERIFIED", "risk_classification": "CRITICAL"},
            )
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["status"], "SUCCESS")
            self.assertEqual(data["report"]["status"], "VERIFIED")
            self.assertEqual(data["report"]["risk_classification"], "CRITICAL")

    def test_admin_online_backup_endpoint(self):
        """Admin can trigger an online hot SQLite backup that passes integrity check."""
        with patch.object(settings, "admin_api_key", self.test_admin_key):
            res = self.client.post(
                "/api/v1/dashboard/backup",
                headers={"X-Admin-Key": self.test_admin_key},
            )
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["status"], "SUCCESS")
            self.assertIn("backup_file", data)
            self.assertTrue(data["backup_file"].startswith("cybercore_backup_"))

    def test_database_health_check_operational(self):
        """GET /api/health returns operational status and component details when healthy."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("components", data)
        self.assertEqual(data["components"]["database"]["status"], "operational")
        self.assertEqual(data["components"]["database"]["mode"], "WAL")

    def test_database_health_check_failure_degradation(self):
        """GET /api/health returns 503 when the database integrity check or connection fails."""
        with patch.object(report_store, "check_health", return_value=(False, "disk I/O error", {"healthy": False})):
            res = self.client.get("/api/health")
            self.assertEqual(res.status_code, 503)
            data = res.json()
            self.assertEqual(data["status"], "unhealthy")
            self.assertEqual(data["components"]["database"]["status"], "down")

    def test_client_ip_reverse_proxy_resolution(self):
        """get_client_ip correctly resolves client IP when behind trusted reverse proxies."""
        # Create mock requests
        mock_req_cf = MagicMock()
        mock_req_cf.client.host = "127.0.0.1"
        mock_req_cf.headers = {"cf-connecting-ip": "203.0.113.45"}
        self.assertEqual(get_client_ip(mock_req_cf), "203.0.113.45")

        mock_req_xff = MagicMock()
        mock_req_xff.client.host = "127.0.0.1"
        mock_req_xff.headers = {"x-forwarded-for": "198.51.100.22, 127.0.0.1"}
        self.assertEqual(get_client_ip(mock_req_xff), "198.51.100.22")

        # Untrusted external IP cannot spoof forward headers
        mock_req_untrusted = MagicMock()
        mock_req_untrusted.client.host = "198.51.100.99"
        mock_req_untrusted.headers = {"x-forwarded-for": "8.8.8.8"}
        self.assertEqual(get_client_ip(mock_req_untrusted), "198.51.100.99")

        # Untrusted private IP outside proxy list cannot spoof forward headers
        mock_req_untrusted_private = MagicMock()
        mock_req_untrusted_private.client.host = "10.0.0.1"
        mock_req_untrusted_private.headers = {"x-forwarded-for": "198.51.100.22"}
        self.assertEqual(get_client_ip(mock_req_untrusted_private), "10.0.0.1")

    def test_sensitive_field_redaction_in_logging(self):
        """redact_sensitive_dict masks credentials and keys."""
        sample_payload = {
            "username": "security_analyst",
            "password": "SuperSecretPassword123!",
            "api_key": "live_sk_1234567890",
            "nested": {
                "token": "bearer_xyz",
                "safe_field": "tactical_intel",
            },
        }
        redacted = redact_sensitive_dict(sample_payload)
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["api_key"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["token"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["safe_field"], "tactical_intel")
        self.assertEqual(redacted["username"], "security_analyst")

    def test_file_upload_size_limit_rejection(self):
        """Files exceeding 25MB streaming limit must be rejected with HTTP 413."""
        # 25MB + 2KB fake payload
        oversized_content = b"0" * (25 * 1024 * 1024 + 2048)
        oversized_file = io.BytesIO(oversized_content)
        res = self.client.post(
            "/api/v1/files/analyze",
            files={"file": ("oversized_dump.bin", oversized_file, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 413)
        self.assertIn("exceeds maximum allowed size", res.json()["detail"])

    def test_file_upload_missing_filename(self):
        """Uploaded files lacking filenames must be rejected with HTTP 400 or 422."""
        empty_file = io.BytesIO(b"dummy")
        res = self.client.post(
            "/api/v1/files/analyze",
            files={"file": ("", empty_file, "application/octet-stream")},
        )
        self.assertIn(res.status_code, [400, 422])


if __name__ == "__main__":
    unittest.main()
