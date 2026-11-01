"""
Unit and Integration Tests for Hash Checker (Phase 4A & Finding HASH-03)
Tests configured, unconfigured, timeout, malicious, clean, and invalid hash scenarios.
"""

import unittest
from unittest.mock import patch, AsyncMock
from starlette.testclient import TestClient

from app.main import app
from app.services import file_analyzer


class TestHashChecker(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.test_hash_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        self.test_hash_md5 = "44d88612fea8a8f36de82e1278abb02f"

    def test_invalid_hash_length(self):
        """Invalid hash lengths must return HTTP 400 Bad Request."""
        res = self.client.post("/api/v1/files/check-hash", json={"hash_value": "abc123"})
        self.assertEqual(res.status_code, 422)  # Pydantic min_length=32 validation

        res2 = self.client.post("/api/v1/files/check-hash", json={"hash_value": "a" * 33})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Invalid hash format", res2.json()["detail"])

    def test_invalid_hash_characters(self):
        """Non-hexadecimal characters must return HTTP 400 Bad Request."""
        non_hex = "g" * 64
        res = self.client.post("/api/v1/files/check-hash", json={"hash_value": non_hex})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid hash format", res.json()["detail"])

    @patch("app.routers.files.check_virustotal_file_hash")
    def test_virustotal_unconfigured_verdict(self, mock_vt):
        """
        HASH-03 Resolution Verification:
        When VirusTotal is unconfigured, response MUST return threat_level='UNASSESSED'
        and risk_score=None. It MUST NOT default to SAFE with risk_score=0.
        """
        mock_vt.return_value = {
            "status": "unconfigured",
            "message": "VirusTotal API key is not configured",
        }

        res = self.client.post(
            "/api/v1/files/check-hash",
            json={"hash_value": self.test_hash_sha256, "filename": "sample.exe"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["threat_level"], "UNASSESSED")
        self.assertIsNone(data["risk_score"])
        self.assertEqual(data["hash"], self.test_hash_sha256)
        self.assertTrue(any("unconfigured" in f.lower() for f in data["findings"]))
        self.assertEqual(data["vt_reputation"]["status"], "unconfigured")

    @patch("app.routers.files.check_virustotal_file_hash")
    def test_virustotal_timeout_error_verdict(self, mock_vt):
        """
        When external query fails or times out, response MUST return threat_level='UNASSESSED'
        and risk_score=None.
        """
        mock_vt.return_value = {
            "status": "timeout",
            "message": "VirusTotal API query timed out after 10.0s",
        }

        res = self.client.post(
            "/api/v1/files/check-hash",
            json={"hash_value": self.test_hash_sha256},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["threat_level"], "UNASSESSED")
        self.assertIsNone(data["risk_score"])
        self.assertTrue(any("remains unassessed" in f.lower() for f in data["findings"]))

    @patch("app.routers.files.check_virustotal_file_hash")
    def test_virustotal_not_found_clean_verdict(self, mock_vt):
        """
        When hash is queried and returned 404 (not seen in database),
        it is marked SAFE with risk_score=0.
        """
        mock_vt.return_value = {
            "status": "not_found",
            "message": "Hash not seen in VirusTotal database",
        }

        res = self.client.post(
            "/api/v1/files/check-hash",
            json={"hash_value": self.test_hash_sha256},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["threat_level"], "SAFE")
        self.assertEqual(data["risk_score"], 0)
        self.assertTrue(any("not found in public malware" in f.lower() for f in data["findings"]))

    @patch("app.routers.files.check_virustotal_file_hash")
    def test_virustotal_confirmed_malicious(self, mock_vt):
        """
        When VirusTotal reports malicious engine detections, verdict is CRITICAL/HIGH
        and risk_score > 0.
        """
        mock_vt.return_value = {
            "status": "ok",
            "malicious": 14,
            "suspicious": 2,
            "harmless": 0,
            "total_engines": 70,
            "reputation": -50,
        }

        res = self.client.post(
            "/api/v1/files/check-hash",
            json={"hash_value": self.test_hash_sha256},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["threat_level"], "CRITICAL")
        self.assertEqual(data["risk_score"], 100)
        self.assertTrue(any("14 security vendors" in f for f in data["findings"]))

    @patch("app.routers.files.check_virustotal_file_hash")
    def test_virustotal_zero_detection_clean(self, mock_vt):
        """
        When VirusTotal reports 0 malicious and 0 suspicious across engines, verdict is SAFE.
        """
        mock_vt.return_value = {
            "status": "ok",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 68,
            "total_engines": 70,
            "reputation": 100,
        }

        res = self.client.post(
            "/api/v1/files/check-hash",
            json={"hash_value": self.test_hash_sha256},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["threat_level"], "SAFE")
        self.assertEqual(data["risk_score"], 0)
        self.assertTrue(any("70 security vendors with 0 detections" in f for f in data["findings"]))


if __name__ == "__main__":
    unittest.main()
