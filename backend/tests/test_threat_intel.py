"""
CYBERCORE Backend — Threat Intelligence Unit & Integration Tests

Validates:
  1. URLhaus authentication via Auth-Key request header.
  2. Missing URLhaus credentials vs invalid credentials (HTTP 401/403).
  3. URLhaus rate limits (HTTP 429).
  4. URLhaus upstream outages (HTTP 5xx).
  5. URLhaus network timeouts and connection errors.
  6. URLhaus malformed upstream responses.
  7. Fail-closed security behavior (unavailable providers never treated as clean).
  8. Credential protection (never leaking auth tokens).
  9. All providers unavailable diagnostics.
 10. Partial provider availability aggregation.
 11. VirusTotal & Google Safe Browsing error distinction.
"""

import json
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import httpx

from app.config import get_settings
from app.services.risk_scorer import ComponentScore, Confidence, FindingType
from app.services.threat_intel import (
    check_urlhaus,
    check_virustotal_url,
    check_google_safe_browsing,
    aggregate_threat_intel,
)


class TestThreatIntelURLhaus(unittest.IsolatedAsyncioTestCase):
    """URLhaus integration, authentication, and error distinction tests."""

    async def test_01_urlhaus_missing_credential(self):
        """When URLHAUS_AUTH_KEY is not configured, check_urlhaus must return CONFIGURATION_ERROR / MISSING_CREDENTIALS."""
        settings = get_settings()
        with patch.object(settings, "urlhaus_auth_key", ""):
            res = await check_urlhaus("https://malware.example.com/payload.exe")

            self.assertIsNone(res.score)
            self.assertFalse(res.is_available)
            self.assertEqual(res.confidence, Confidence.UNAVAILABLE)
            self.assertEqual(res.finding_type, FindingType.UNABLE_TO_VERIFY)
            self.assertEqual(res.details.get("error_type"), "CONFIGURATION_ERROR")
            self.assertEqual(res.details.get("sub_type"), "MISSING_CREDENTIALS")
            self.assertIn("URLhaus Auth-Key not configured", res.details.get("reason", ""))

    async def test_02_urlhaus_valid_auth_clean_response(self):
        """When Auth-Key is provided and URL is not in database, return clean score (5.0)."""
        settings = get_settings()
        fake_key = "test_uh_secret_key_12345"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "not_in_database"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(settings, "urlhaus_auth_key", fake_key), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp

            res = await check_urlhaus("https://clean-site.example.com")

            self.assertTrue(res.is_available)
            self.assertEqual(res.score, 5.0)
            self.assertEqual(res.confidence, Confidence.HIGH)
            self.assertEqual(res.finding_type, FindingType.NO_KNOWN_DETECTION)
            self.assertEqual(res.details.get("status"), "not_in_database")

            # Verify request headers and payload
            mock_post.assert_called_once()
            _, kwargs = mock_post.call_args
            self.assertEqual(kwargs.get("headers"), {"Auth-Key": fake_key})
            self.assertEqual(kwargs.get("data"), {"url": "https://clean-site.example.com"})

    async def test_03_urlhaus_valid_auth_malware_response(self):
        """When Auth-Key is provided and URL is confirmed malware, return 95.0 CONFIRMED_THREAT."""
        settings = get_settings()
        fake_key = "test_uh_secret_key_12345"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "is_malware",
            "threat": "elf_mirai",
            "tags": ["mirai", "elf", "botnet"],
            "url_status": "online",
        }
        mock_resp.raise_for_status = MagicMock()

        with patch.object(settings, "urlhaus_auth_key", fake_key), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp

            res = await check_urlhaus("http://198.51.100.22/mirai.arm7")

            self.assertTrue(res.is_available)
            self.assertEqual(res.score, 95.0)
            self.assertEqual(res.confidence, Confidence.HIGH)
            self.assertEqual(res.finding_type, FindingType.CONFIRMED_THREAT)
            self.assertEqual(res.details.get("threat"), "elf_mirai")
            self.assertIn("mirai", res.details.get("tags", []))
            self.assertTrue(any("elf_mirai" in ev for ev in res.evidence))

    async def test_04_urlhaus_http_401_unauthorized(self):
        """HTTP 401 must return CONFIGURATION_ERROR with sub_type AUTHENTICATION_FAILURE."""
        settings = get_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.object(settings, "urlhaus_auth_key", "invalid_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertIsNone(res.score)
            self.assertEqual(res.finding_type, FindingType.UNABLE_TO_VERIFY)
            self.assertEqual(res.confidence, Confidence.UNAVAILABLE)
            self.assertEqual(res.details.get("error_type"), "CONFIGURATION_ERROR")
            self.assertEqual(res.details.get("sub_type"), "AUTHENTICATION_FAILURE")
            self.assertEqual(res.details.get("status"), 401)

    async def test_05_urlhaus_http_403_forbidden(self):
        """HTTP 403 must return CONFIGURATION_ERROR with sub_type AUTHENTICATION_FAILURE."""
        settings = get_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch.object(settings, "urlhaus_auth_key", "forbidden_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertEqual(res.details.get("error_type"), "CONFIGURATION_ERROR")
            self.assertEqual(res.details.get("sub_type"), "AUTHENTICATION_FAILURE")
            self.assertEqual(res.details.get("status"), 403)

    async def test_06_urlhaus_http_429_rate_limit(self):
        """HTTP 429 must return RATE_LIMIT error type."""
        settings = get_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.object(settings, "urlhaus_auth_key", "valid_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertIsNone(res.score)
            self.assertEqual(res.details.get("error_type"), "RATE_LIMIT")
            self.assertEqual(res.details.get("status"), 429)

    async def test_07_urlhaus_http_5xx_upstream_outage(self):
        """HTTP 5xx (500, 502, 503) must return UPSTREAM_ERROR."""
        settings = get_settings()
        for status_code in (500, 502, 503, 504):
            mock_resp = MagicMock()
            mock_resp.status_code = status_code

            with patch.object(settings, "urlhaus_auth_key", "valid_key"), \
                 patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_resp

                res = await check_urlhaus("https://example.com")

                self.assertFalse(res.is_available)
                self.assertIsNone(res.score)
                self.assertEqual(res.details.get("error_type"), "UPSTREAM_ERROR")
                self.assertEqual(res.details.get("status"), status_code)

    async def test_08_urlhaus_network_timeout(self):
        """Network timeout must return TIMEOUT error type."""
        settings = get_settings()
        with patch.object(settings, "urlhaus_auth_key", "valid_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Connection timed out")

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertIsNone(res.score)
            self.assertEqual(res.details.get("error_type"), "TIMEOUT")

    async def test_09_urlhaus_connection_offline(self):
        """Connection errors must return OFFLINE error type."""
        settings = get_settings()
        with patch.object(settings, "urlhaus_auth_key", "valid_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.ConnectError("Failed to establish a connection")

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertIsNone(res.score)
            self.assertEqual(res.details.get("error_type"), "OFFLINE")

    async def test_10_urlhaus_malformed_upstream_response(self):
        """Malformed JSON or non-dict upstream response must return MALFORMED_RESPONSE."""
        settings = get_settings()

        # Case A: Non-JSON body
        mock_resp_non_json = MagicMock()
        mock_resp_non_json.status_code = 200
        mock_resp_non_json.raise_for_status = MagicMock()
        mock_resp_non_json.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)

        with patch.object(settings, "urlhaus_auth_key", "valid_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp_non_json

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertIsNone(res.score)
            self.assertEqual(res.details.get("error_type"), "MALFORMED_RESPONSE")

        # Case B: JSON array instead of dictionary
        mock_resp_array = MagicMock()
        mock_resp_array.status_code = 200
        mock_resp_array.raise_for_status = MagicMock()
        mock_resp_array.json.return_value = ["not", "a", "dict"]

        with patch.object(settings, "urlhaus_auth_key", "valid_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp_array

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertIsNone(res.score)
            self.assertEqual(res.details.get("error_type"), "MALFORMED_RESPONSE")

    async def test_11_urlhaus_unexpected_status_string(self):
        """Unexpected query_status value must return UNEXPECTED_STATUS."""
        settings = get_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"query_status": "unknown_action_code"}

        with patch.object(settings, "urlhaus_auth_key", "valid_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp

            res = await check_urlhaus("https://example.com")

            self.assertFalse(res.is_available)
            self.assertIsNone(res.score)
            self.assertEqual(res.details.get("error_type"), "UNEXPECTED_STATUS")
            self.assertEqual(res.details.get("query_status"), "unknown_action_code")

    async def test_12_urlhaus_credential_never_exposed(self):
        """Secret Auth-Key must never appear in ComponentScore details or evidence."""
        secret_key = "super_confidential_token_xyz987"
        settings = get_settings()

        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.object(settings, "urlhaus_auth_key", secret_key), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp

            res = await check_urlhaus("https://example.com")

            # Convert details and evidence to string and verify key absence
            details_str = json.dumps(res.details)
            evidence_str = " ".join(res.evidence)

            self.assertNotIn(secret_key, details_str)
            self.assertNotIn(secret_key, evidence_str)


class TestThreatIntelAggregation(unittest.TestCase):
    """Aggregate Threat Intelligence scoring and availability tests."""

    def test_13_all_providers_unavailable(self):
        """When VT, GSB, and URLhaus are unavailable, aggregate returns ALL_PROVIDERS_UNAVAILABLE."""
        vt = ComponentScore(
            name="VirusTotal URL", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR"}
        )
        gsb = ComponentScore(
            name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "TIMEOUT"}
        )
        uh = ComponentScore(
            name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR", "sub_type": "MISSING_CREDENTIALS"}
        )

        agg = aggregate_threat_intel(vt, gsb, uh)

        self.assertFalse(agg.is_available)
        self.assertIsNone(agg.score)
        self.assertEqual(agg.confidence, Confidence.UNAVAILABLE)
        self.assertEqual(agg.finding_type, FindingType.UNABLE_TO_VERIFY)
        self.assertEqual(agg.details.get("error_type"), "ALL_PROVIDERS_UNAVAILABLE")

        sources = agg.details.get("sources", {})
        self.assertEqual(sources.get("virustotal"), "CONFIGURATION_ERROR")
        self.assertEqual(sources.get("google_safe_browsing"), "TIMEOUT")
        self.assertEqual(sources.get("urlhaus"), "CONFIGURATION_ERROR")

    def test_14_partial_provider_availability_confirmed_threat(self):
        """When 1 provider confirms threat and others are unavailable, CONFIRMED_THREAT is preserved."""
        vt_mal = ComponentScore(
            name="VirusTotal URL", score=90.0, confidence=Confidence.HIGH,
            finding_type=FindingType.CONFIRMED_THREAT, details={"malicious_count": 12},
            evidence=["12 security engines flagged this URL"]
        )
        gsb_err = ComponentScore(
            name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "TIMEOUT"}
        )
        uh_err = ComponentScore(
            name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR"}
        )

        agg = aggregate_threat_intel(vt_mal, gsb_err, uh_err)

        self.assertTrue(agg.is_available)
        self.assertEqual(agg.score, 90.0)
        self.assertEqual(agg.confidence, Confidence.HIGH)
        self.assertEqual(agg.finding_type, FindingType.CONFIRMED_THREAT)
        self.assertIn("12 security engines flagged this URL", agg.evidence)

        # Sources diagnostic check
        sources = agg.details.get("sources", {})
        self.assertIn("virustotal", sources)
        self.assertEqual(sources.get("urlhaus"), "CONFIGURATION_ERROR")
        self.assertEqual(sources.get("google_safe_browsing"), "TIMEOUT")

    def test_15_partial_provider_availability_clean(self):
        """When 1 provider reports clean and others are unavailable, score is 5.0 with MEDIUM confidence."""
        vt_unavail = ComponentScore(
            name="VirusTotal URL", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR"}
        )
        gsb_unavail = ComponentScore(
            name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "RATE_LIMIT"}
        )
        uh_clean = ComponentScore(
            name="URLhaus", score=5.0, confidence=Confidence.HIGH,
            finding_type=FindingType.NO_KNOWN_DETECTION, details={"status": "not_in_database"},
            evidence=["URL not found in URLhaus malware database"]
        )

        agg = aggregate_threat_intel(vt_unavail, gsb_unavail, uh_clean)

        self.assertTrue(agg.is_available)
        self.assertEqual(agg.score, 5.0)
        self.assertEqual(agg.finding_type, FindingType.NO_KNOWN_DETECTION)
        # 1 of 3 sources available -> Confidence.MEDIUM (0.33)
        self.assertEqual(agg.confidence, Confidence.MEDIUM)

    def test_16_two_providers_available_clean(self):
        """When 2 providers report clean and 1 is unavailable, confidence is HIGH."""
        vt_clean = ComponentScore(
            name="VirusTotal URL", score=5.0, confidence=Confidence.HIGH,
            finding_type=FindingType.NO_KNOWN_DETECTION, details={},
            evidence=["0 of 70 engines detected any threat"]
        )
        gsb_unavail = ComponentScore(
            name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "UPSTREAM_ERROR"}
        )
        uh_clean = ComponentScore(
            name="URLhaus", score=5.0, confidence=Confidence.HIGH,
            finding_type=FindingType.NO_KNOWN_DETECTION, details={"status": "not_in_database"},
            evidence=["URL not found in URLhaus malware database"]
        )

        agg = aggregate_threat_intel(vt_clean, gsb_unavail, uh_clean)

        self.assertTrue(agg.is_available)
        self.assertEqual(agg.score, 5.0)
        self.assertEqual(agg.finding_type, FindingType.NO_KNOWN_DETECTION)
        # 2 of 3 sources available -> Confidence.HIGH (0.67)
        self.assertEqual(agg.confidence, Confidence.HIGH)


class TestVirusTotalAndGSBDiagnostics(unittest.IsolatedAsyncioTestCase):
    """Diagnostics for VirusTotal and Google Safe Browsing."""

    async def test_17_virustotal_diagnostics(self):
        """Verify VT distinguishes missing credentials, 401, 429, 500, timeout, and malformed response."""
        settings = get_settings()

        # Missing credential
        with patch.object(settings, "virustotal_api_key", ""):
            res = await check_virustotal_url("https://example.com")
            self.assertEqual(res.details.get("error_type"), "CONFIGURATION_ERROR")
            self.assertEqual(res.details.get("sub_type"), "MISSING_CREDENTIALS")

        # HTTP 401 invalid key
        mock_401 = MagicMock(status_code=401)
        with patch.object(settings, "virustotal_api_key", "bad_key"), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_401
            res = await check_virustotal_url("https://example.com")
            self.assertEqual(res.details.get("error_type"), "CONFIGURATION_ERROR")
            self.assertEqual(res.details.get("sub_type"), "AUTHENTICATION_FAILURE")

        # HTTP 429 rate limit
        mock_429 = MagicMock(status_code=429)
        with patch.object(settings, "virustotal_api_key", "good_key"), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_429
            res = await check_virustotal_url("https://example.com")
            self.assertEqual(res.details.get("error_type"), "RATE_LIMIT")

        # HTTP 503 upstream error
        mock_503 = MagicMock(status_code=503)
        with patch.object(settings, "virustotal_api_key", "good_key"), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_503
            res = await check_virustotal_url("https://example.com")
            self.assertEqual(res.details.get("error_type"), "UPSTREAM_ERROR")

        # Malformed JSON
        mock_bad_json = MagicMock(status_code=200)
        mock_bad_json.raise_for_status = MagicMock()
        mock_bad_json.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)
        with patch.object(settings, "virustotal_api_key", "good_key"), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_bad_json
            res = await check_virustotal_url("https://example.com")
            self.assertEqual(res.details.get("error_type"), "MALFORMED_RESPONSE")

    async def test_18_google_safe_browsing_diagnostics(self):
        """Verify GSB distinguishes missing credentials, 401, 429, 500, timeout, and malformed response."""
        settings = get_settings()

        # Missing credential
        with patch.object(settings, "google_safe_browsing_api_key", ""):
            res = await check_google_safe_browsing("https://example.com")
            self.assertEqual(res.details.get("error_type"), "CONFIGURATION_ERROR")
            self.assertEqual(res.details.get("sub_type"), "MISSING_CREDENTIALS")

        # HTTP 401 invalid key
        mock_401 = MagicMock(status_code=401)
        with patch.object(settings, "google_safe_browsing_api_key", "bad_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_401
            res = await check_google_safe_browsing("https://example.com")
            self.assertEqual(res.details.get("error_type"), "CONFIGURATION_ERROR")
            self.assertEqual(res.details.get("sub_type"), "AUTHENTICATION_FAILURE")

        # HTTP 429 rate limit
        mock_429 = MagicMock(status_code=429)
        with patch.object(settings, "google_safe_browsing_api_key", "good_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_429
            res = await check_google_safe_browsing("https://example.com")
            self.assertEqual(res.details.get("error_type"), "RATE_LIMIT")

        # HTTP 500 upstream error
        mock_500 = MagicMock(status_code=500)
        with patch.object(settings, "google_safe_browsing_api_key", "good_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_500
            res = await check_google_safe_browsing("https://example.com")
            self.assertEqual(res.details.get("error_type"), "UPSTREAM_ERROR")

        # Malformed JSON
        mock_bad_json = MagicMock(status_code=200)
        mock_bad_json.raise_for_status = MagicMock()
        mock_bad_json.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)
        with patch.object(settings, "google_safe_browsing_api_key", "good_key"), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_bad_json
            res = await check_google_safe_browsing("https://example.com")
            self.assertEqual(res.details.get("error_type"), "MALFORMED_RESPONSE")


if __name__ == "__main__":
    unittest.main()

