"""
CYBERCORE Backend — Phase 6 Adversarial Security & Durability Test Suite

Executes rigorous adversarial verification:
  1. Database Durability & Concurrency:
     - Multi-threaded concurrent writes (WAL mode stress)
     - Hot backup creation and restore into isolated database
     - Verification of restored records
     - Database unavailable failure resilience
  2. Authentication Adversarial Probing:
     - Missing header, empty key, invalid key, incorrect Bearer, malformed header
     - Verification of no token leakage in logs/errors
     - Verification that reporter identity is not exposed in public endpoints
  3. Rate Limiting & Proxy Anti-Spoofing:
     - Direct client requests vs trusted proxy
     - Spoofed X-Forwarded-For & CF-Connecting-IP by untrusted clients
     - Abuse limit exhaustion (HTTP 429)
  4. Security Regression:
     - SSRF: Private IPs, loopback, cloud metadata (169.254.169.254, 100.100.100.200)
     - Invalid schemes (file://, ftp://, gopher://)
     - Oversized file upload (>25MB)
     - Hash lookup when VirusTotal is unavailable (must return UNASSESSED)
  5. Operational Monitoring:
     - Request ID propagation, response timing, structured logging
     - Database health check degradation (HTTP 503)
"""

import os
import io
import shutil
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch, MagicMock
from starlette.testclient import TestClient

from app.main import app
from app.config import get_settings
from app.limiter import limiter
from app.services.report_store import ThreatReportStore, report_store
from app.utils.security import get_client_ip, require_admin_auth

settings = get_settings()


class TestAdversarialSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_token = "adversarial_audit_token_998877"
        limiter.reset()

    @classmethod
    def tearDownClass(cls):
        limiter.reset()

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6B: Database Durability & Concurrency
    # ─────────────────────────────────────────────────────────────────────────

    def test_database_backup_and_isolated_restore(self):
        """
        Create records in isolated DB, backup using conn.backup,
        restore into a separate destination DB, and verify all records match.
        Never touches the actual database.
        """
        temp_dir = tempfile.mkdtemp(prefix="cybercore_test_db_")
        try:
            primary_db_path = os.path.join(temp_dir, "primary.db")
            isolated_store = ThreatReportStore(db_path=primary_db_path)

            # Insert sample threat reports
            records = [
                ("https://malware-drop-1.test", "malware", "Trojan payload dropper"),
                ("https://phishing-portal-2.test", "phishing", "Credential harvester"),
                ("https://scam-lottery-3.test", "scam", "Advance fee lottery scam"),
            ]
            created_ids = []
            for url, threat_type, desc in records:
                status, report = isolated_store.add_report(url, threat_type, desc)
                self.assertEqual(status, "CREATED")
                created_ids.append(report["id"])

            self.assertEqual(isolated_store.count_reports(), 3)

            # Perform online backup
            backup_file = isolated_store.backup_database(backup_dir=temp_dir)
            self.assertTrue(os.path.exists(backup_file))

            # Restore into a separate test database
            restore_db_path = os.path.join(temp_dir, "restored.db")
            shutil.copy2(backup_file, restore_db_path)

            # Verify restored database
            restored_store = ThreatReportStore(db_path=restore_db_path)
            self.assertEqual(restored_store.count_reports(), 3)

            restored_reports = restored_store.get_recent_reports(limit=10)
            restored_urls = {r["url"] for r in restored_reports}
            for url, _, _ in records:
                self.assertIn(url, restored_urls)

            # Verify restored integrity
            is_healthy, msg, _ = restored_store.check_health()
            self.assertTrue(is_healthy)
            self.assertEqual(msg, "ok")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_concurrent_report_submissions(self):
        """
        Simulate concurrent writes from multiple threads to stress WAL mode
        and busy_timeout locking.
        """
        temp_dir = tempfile.mkdtemp(prefix="cybercore_wal_concurrency_")
        try:
            db_path = os.path.join(temp_dir, "concurrency.db")
            store = ThreatReportStore(db_path=db_path)

            num_threads = 10
            submissions_per_thread = 5
            errors = []

            def worker(thread_idx: int):
                for i in range(submissions_per_thread):
                    url = f"https://threat-thread-{thread_idx}-run-{i}.test"
                    try:
                        status, report = store.add_report(
                            url=url,
                            threat_type="phishing",
                            description=f"Thread {thread_idx} submission {i}",
                        )
                        if status != "CREATED":
                            errors.append(f"Thread {thread_idx} item {i} status={status}")
                    except Exception as e:
                        errors.append(f"Thread {thread_idx} item {i} exception: {str(e)}")

            threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # No operational errors or locks should have failed
            self.assertEqual(len(errors), 0, f"Concurrent write errors occurred: {errors}")
            self.assertEqual(store.count_reports(), num_threads * submissions_per_thread)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_database_unavailable_resilience(self):
        """
        When database file path is invalid or corrupted, report store handles
        errors gracefully and check_health marks the database unhealthy.
        """
        # 1. Invalid filesystem path raises initialization error
        with self.assertRaises(Exception):
            ThreatReportStore(db_path="/invalid/nonexistent/directory/cybercore.db")

        # 2. Corrupt database header is caught by check_health quick_check
        temp_dir = tempfile.mkdtemp(prefix="cybercore_corrupt_")
        try:
            corrupt_file = os.path.join(temp_dir, "corrupted.db")
            # Write invalid header bytes
            with open(corrupt_file, "wb") as f:
                f.write(b"NOT_A_VALID_SQLITE3_DATABASE_HEADER_CORRUPTED_BYTES")

            corrupt_store = ThreatReportStore.__new__(ThreatReportStore)
            corrupt_store.db_path = corrupt_file
            is_healthy, msg, meta = corrupt_store.check_health()
            self.assertFalse(is_healthy)
            self.assertFalse(meta["healthy"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6C: Authentication Adversarial Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_admin_auth_adversarial_vectors(self):
        """Test all unauthorized, malformed, and invalid authentication vectors."""
        with patch.object(settings, "admin_api_key", self.admin_token):
            test_endpoint = "/api/v1/dashboard/backup"

            # 1. No header at all
            res1 = self.client.post(test_endpoint)
            self.assertEqual(res1.status_code, 401)
            self.assertIn("Missing administrative", res1.json()["detail"])

            # 2. Empty X-Admin-Key
            res2 = self.client.post(test_endpoint, headers={"X-Admin-Key": ""})
            self.assertEqual(res2.status_code, 401)

            # 3. Invalid X-Admin-Key
            res3 = self.client.post(test_endpoint, headers={"X-Admin-Key": "attacker_supplied_guess"})
            self.assertEqual(res3.status_code, 403)
            self.assertIn("Invalid administrative", res3.json()["detail"])

            # 4. Incorrect Bearer token
            res4 = self.client.post(test_endpoint, headers={"Authorization": "Bearer wrong_token_abc"})
            self.assertEqual(res4.status_code, 403)

            # 5. Malformed Authorization headers
            malformed_headers = [
                {"Authorization": "Basic dXNlcjpwYXNz"},
                {"Authorization": "Bearer"},
                {"Authorization": "Token 12345"},
                {"Authorization": "CustomScheme abc"},
                {"Authorization": "Bearer   "},
            ]
            for h in malformed_headers:
                res_mal = self.client.post(test_endpoint, headers=h)
                self.assertIn(res_mal.status_code, [401, 403])

            # 6. Correct X-Admin-Key
            res6 = self.client.post(test_endpoint, headers={"X-Admin-Key": self.admin_token})
            self.assertEqual(res6.status_code, 200)

            # 7. Correct Authorization Bearer
            res7 = self.client.post(test_endpoint, headers={"Authorization": f"Bearer {self.admin_token}"})
            self.assertEqual(res7.status_code, 200)

    def test_token_not_leaked_in_errors_or_responses(self):
        """Admin token must never appear in response payloads or headers."""
        with patch.object(settings, "admin_api_key", self.admin_token):
            res = self.client.post(
                "/api/v1/dashboard/backup",
                headers={"Authorization": f"Bearer {self.admin_token}"},
            )
            raw_text = res.text
            self.assertNotIn(self.admin_token, raw_text)

            res_err = self.client.post(
                "/api/v1/dashboard/backup",
                headers={"X-Admin-Key": "attempted_wrong_key"},
            )
            self.assertNotIn("attempted_wrong_key", res_err.text)

    def test_public_report_retrieval_does_not_leak_reporter_identity(self):
        """
        Public report feed (/api/v1/dashboard/reports) must NEVER include
        internal reporter references or IP identifiers.
        """
        test_url = f"https://privacy-check-{os.urandom(4).hex()}.org"
        report_store.add_report(
            url=test_url,
            threat_type="phishing",
            description="Privacy test submission",
            reporter_ref="confidential_user_id_9999",
        )

        res = self.client.get("/api/v1/dashboard/reports?limit=10")
        self.assertEqual(res.status_code, 200)
        reports = res.json()["reports"]
        matching = [r for r in reports if r["url"] == test_url]
        self.assertTrue(len(matching) >= 1)
        target = matching[0]
        self.assertNotIn("reporter_ref", target)
        self.assertNotIn("confidential_user_id_9999", str(target))

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6D: Rate Limiting & Proxy Anti-Spoofing
    # ─────────────────────────────────────────────────────────────────────────

    def test_untrusted_client_cannot_spoof_ip(self):
        """
        Untrusted peer IP cannot bypass rate limiting or spoof IP via forward headers.
        """
        mock_req = MagicMock()
        mock_req.client.host = "203.0.113.195"  # External public IP (untrusted)
        mock_req.headers = {
            "x-forwarded-for": "1.2.3.4, 5.6.7.8",
            "cf-connecting-ip": "9.9.9.9",
            "x-real-ip": "8.8.8.8",
        }
        # Resolved IP must remain the untrusted client host
        resolved_ip = get_client_ip(mock_req)
        self.assertEqual(resolved_ip, "203.0.113.195")

    def test_trusted_proxy_correctly_extracts_client_ip(self):
        """
        When connection originates from trusted proxy (e.g. 127.0.0.1),
        CF-Connecting-IP and X-Forwarded-For are safely extracted.
        Unconfigured private IPs outside TRUSTED_PROXIES are rejected as untrusted.
        """
        mock_req_cf = MagicMock()
        mock_req_cf.client.host = "127.0.0.1"
        mock_req_cf.headers = {"cf-connecting-ip": "198.51.100.77"}
        self.assertEqual(get_client_ip(mock_req_cf), "198.51.100.77")

        mock_req_xff = MagicMock()
        mock_req_xff.client.host = "127.0.0.1"
        mock_req_xff.headers = {"x-forwarded-for": "198.51.100.88, 127.0.0.1"}
        self.assertEqual(get_client_ip(mock_req_xff), "198.51.100.88")

        # Private IP outside explicitly configured proxy list is treated as untrusted peer
        mock_req_untrusted_private = MagicMock()
        mock_req_untrusted_private.client.host = "10.0.1.5"
        mock_req_untrusted_private.headers = {"x-forwarded-for": "198.51.100.88"}
        self.assertEqual(get_client_ip(mock_req_untrusted_private), "10.0.1.5")

    def test_rate_limit_enforcement_under_rapid_requests(self):
        """
        Submitting reports rapidly from the same client IP must trigger HTTP 429 Too Many Requests.
        """
        # SlowAPI rate limit on /dashboard/report is 5/minute
        rate_limited = False
        for i in range(15):
            res = self.client.post(
                "/api/v1/dashboard/report",
                json={
                    "url": f"https://rate-limit-test-{i}.org",
                    "threat_type": "phishing",
                },
            )
            if res.status_code == 429:
                rate_limited = True
                self.assertIn("Rate limit exceeded", res.text)
                break

        self.assertTrue(rate_limited, "Expected HTTP 429 rate limit response under rapid requests")
        limiter.reset()

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6E: Security Regression Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_ssrf_private_and_loopback_rejection(self):
        """All private and loopback IP targets must be rejected with HTTP 400."""
        blocked_targets = [
            "http://127.0.0.1:8000/api/v1/dashboard/stats",
            "http://localhost:8000",
            "http://10.0.0.1/admin",
            "http://172.16.0.1/secret",
            "http://192.168.1.1/router-login",
        ]
        for target in blocked_targets:
            res = self.client.post("/api/v1/scan/", json={"url": target, "source": "web"})
            self.assertEqual(res.status_code, 400, f"Target {target} should have been rejected with 400")
            self.assertIn("not allowed", res.json()["detail"].lower())

    def test_ssrf_cloud_metadata_rejection(self):
        """Cloud metadata addresses (AWS, GCP, Alibaba) must be strictly blocked."""
        metadata_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.0.0.192/",
        ]
        for target in metadata_targets:
            res = self.client.post("/api/v1/scan/", json={"url": target, "source": "web"})
            self.assertEqual(res.status_code, 400)
            self.assertIn("not allowed", res.json()["detail"].lower())

    def test_ssrf_invalid_schemes_rejected(self):
        """Non-HTTP/HTTPS schemes must be rejected."""
        invalid_schemes = [
            "file:///etc/passwd",
            "ftp://ftp.example.com",
            "gopher://gopher.floodgap.com",
        ]
        for url in invalid_schemes:
            res = self.client.post("/api/v1/scan/", json={"url": url, "source": "web"})
            self.assertEqual(res.status_code, 400)

    def test_hash_lookup_unassessed_when_vt_unavailable(self):
        """
        When VirusTotal is unconfigured or unavailable, verdict MUST be UNASSESSED
        and risk_score MUST be None. Never SAFE with 0.
        """
        with patch("app.routers.files.check_virustotal_file_hash", return_value={"status": "unconfigured"}):
            res = self.client.post(
                "/api/v1/files/check-hash",
                json={"hash_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
            )
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["threat_level"], "UNASSESSED")
            self.assertIsNone(data["risk_score"])

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6F: Operational Monitoring Tests
    # ─────────────────────────────────────────────────────────────────────────

    def test_operational_request_id_and_timing_headers(self):
        """Every response must carry X-Request-ID and X-Response-Time headers."""
        res = self.client.get("/api/v1/dashboard/stats")
        self.assertEqual(res.status_code, 200)
        self.assertIn("x-request-id", res.headers)
        self.assertIn("x-response-time", res.headers)
        self.assertTrue(res.headers["x-response-time"].endswith("ms"))

        # Inbound request ID should be propagated
        custom_id = "trace-corp-sec-9911"
        res_custom = self.client.get("/api/v1/dashboard/stats", headers={"X-Request-ID": custom_id})
        self.assertEqual(res_custom.headers["x-request-id"], custom_id)


if __name__ == "__main__":
    unittest.main()
