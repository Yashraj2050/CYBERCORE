"""
CYBERCORE Backend — Phishing False Negative Remediation & Threat Integrity Suite
Strictly validates separation between external confirmed detection and heuristic risk.

Key Requirements:
  1. Confirmed VirusTotal malicious detection -> MALICIOUS.
  2. Confirmed Google Safe Browsing detection -> MALICIOUS.
  3. Raw IP + high port + HTTP + .sh with all providers unavailable -> HIGH_RISK, not MALICIOUS.
  4. Legitimate IP-based administration URL -> not automatically MALICIOUS.
  5. Legitimate HTTPS script download -> not automatically MALICIOUS.
  6. All providers unavailable and no suspicious indicators -> INSUFFICIENT_EVIDENCE.
  7. Confirmed malicious detection cannot be diluted by weighted average.
  8. Heuristic detection cannot set confirmed malware status.
"""

import unittest
from unittest.mock import patch, AsyncMock

from app.services.url_scanner import (
    scan_url,
    _build_phishing_malware_score,
    _get_malware_status,
    _get_phishing_status,
)
from app.services.threat_intel import aggregate_threat_intel
from app.services.risk_scorer import (
    calculate_risk_score,
    analyze_url_patterns,
    ComponentScore,
    Confidence,
    FindingType,
    RiskCategory,
)


class TestThreatClassificationIntegritySuite(unittest.IsolatedAsyncioTestCase):

    # -------------------------------------------------------------------------
    # Scenario 1: Compounding Heuristic Dropper Target (HIGH_RISK, not MALICIOUS)
    # -------------------------------------------------------------------------
    async def test_01_compounding_heuristic_dropper_target(self):
        """
        Target: http://125.25.107.120:50014/bin.sh
        External API keys unconfigured (all 3 providers unavailable).
        Engine detects: raw IP + high port 50014 + script payload .sh + unencrypted HTTP.
        Must classify as HIGH_RISK (not MALICIOUS) with score >= 75.
        Must set malware_status = SUSPECTED_MALWARE, is_malware = None (never True).
        """
        with patch("app.services.url_scanner.check_virustotal_url", new_callable=AsyncMock) as mock_vt, \
             patch("app.services.url_scanner.check_google_safe_browsing", new_callable=AsyncMock) as mock_gsb, \
             patch("app.services.url_scanner.check_urlhaus", new_callable=AsyncMock) as mock_uh, \
             patch("app.services.url_scanner.check_ssl_tls", new_callable=AsyncMock) as mock_ssl, \
             patch("app.services.url_scanner.get_domain_rdap", new_callable=AsyncMock) as mock_rdap, \
             patch("app.services.url_scanner.analyze_redirects", new_callable=AsyncMock) as mock_red:

            mock_vt.return_value = ComponentScore(
                name="VirusTotal URL", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={"reason": "VirusTotal returned HTTP 401"}
            )
            mock_gsb.return_value = ComponentScore(
                name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={"reason": "GSB returned HTTP 400"}
            )
            mock_uh.return_value = ComponentScore(
                name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={"reason": "URLhaus returned HTTP 401"}
            )
            mock_ssl.return_value = ComponentScore(
                name="SSL/TLS", score=50.0, confidence=Confidence.HIGH,
                finding_type=FindingType.SUSPICIOUS_INDICATOR,
                details={"scheme": "http", "ssl": False, "port": 50014},
                evidence=["Unencrypted connection: Site operates over plain HTTP"]
            )
            mock_rdap.return_value = {"error": "RDAP returned status 404"}
            mock_red.return_value = ComponentScore(
                name="Redirect Analysis", score=0.0, confidence=Confidence.MEDIUM,
                finding_type=FindingType.NO_KNOWN_DETECTION,
                details={"redirect_count": 0, "redirect_chain": [{"url": "http://125.25.107.120:50014/bin.sh", "status_code": 200}]},
                evidence=["No suspicious redirects detected"]
            )

            result = await scan_url("http://125.25.107.120:50014/bin.sh")

            self.assertGreaterEqual(result["risk_score"], 75)
            self.assertEqual(result["risk_category"], "HIGH_RISK")
            self.assertNotEqual(result["risk_category"], "MALICIOUS")
            self.assertEqual(result["malware_status"], "SUSPECTED_MALWARE")
            self.assertIsNone(result["is_malware"])  # Heuristics cannot set confirmed malware status
            self.assertEqual(result["components"]["url_patterns"]["finding_type"], "HEURISTIC_HIGH_RISK")
            self.assertNotEqual(result["components"]["url_patterns"]["finding_type"], "CONFIRMED_THREAT")
            self.assertIn("threat_intelligence", result["unavailable_checks"])

    # -------------------------------------------------------------------------
    # Scenario 2: Confirmed Malicious VirusTotal Detection -> MALICIOUS
    # -------------------------------------------------------------------------
    async def test_02_confirmed_malicious_virustotal(self):
        """
        Confirmed VirusTotal threat (score 85) must produce MALICIOUS with threat floor active.
        """
        with patch("app.services.url_scanner.check_virustotal_url", new_callable=AsyncMock) as mock_vt, \
             patch("app.services.url_scanner.check_google_safe_browsing", new_callable=AsyncMock) as mock_gsb, \
             patch("app.services.url_scanner.check_urlhaus", new_callable=AsyncMock) as mock_uh, \
             patch("app.services.url_scanner.check_ssl_tls", new_callable=AsyncMock) as mock_ssl, \
             patch("app.services.url_scanner.get_domain_rdap", new_callable=AsyncMock) as mock_rdap, \
             patch("app.services.url_scanner.analyze_redirects", new_callable=AsyncMock) as mock_red:

            mock_vt.return_value = ComponentScore(
                name="VirusTotal URL", score=85.0, confidence=Confidence.HIGH,
                finding_type=FindingType.CONFIRMED_THREAT,
                details={"malicious_count": 14, "total_engines": 70, "categories": {"phish": "phishing"}},
                evidence=["14 of 70 security engines flagged this URL as malicious"]
            )
            mock_gsb.return_value = ComponentScore(
                name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={}
            )
            mock_uh.return_value = ComponentScore(
                name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={}
            )
            mock_ssl.return_value = ComponentScore(
                name="SSL/TLS", score=0.0, confidence=Confidence.HIGH,
                finding_type=FindingType.NO_KNOWN_DETECTION, details={"valid": True}
            )
            mock_rdap.return_value = {"domain_age_days": 500}
            mock_red.return_value = ComponentScore(
                name="Redirect Analysis", score=0.0, confidence=Confidence.MEDIUM,
                finding_type=FindingType.NO_KNOWN_DETECTION, details={"redirect_count": 0}
            )

            result = await scan_url("https://example.com/login")

            self.assertGreaterEqual(result["risk_score"], 85)
            self.assertEqual(result["risk_category"], "MALICIOUS")
            self.assertTrue(result["is_phishing"])
            self.assertEqual(result["phishing_status"], "CONFIRMED_PHISHING")

    # -------------------------------------------------------------------------
    # Scenario 3: Confirmed Malicious Google Safe Browsing -> MALICIOUS
    # -------------------------------------------------------------------------
    async def test_03_confirmed_malicious_google_safe_browsing(self):
        """
        Confirmed GSB threat (score 90) overrides score to MALICIOUS.
        """
        with patch("app.services.url_scanner.check_virustotal_url", new_callable=AsyncMock) as mock_vt, \
             patch("app.services.url_scanner.check_google_safe_browsing", new_callable=AsyncMock) as mock_gsb, \
             patch("app.services.url_scanner.check_urlhaus", new_callable=AsyncMock) as mock_uh, \
             patch("app.services.url_scanner.check_ssl_tls", new_callable=AsyncMock) as mock_ssl, \
             patch("app.services.url_scanner.get_domain_rdap", new_callable=AsyncMock) as mock_rdap, \
             patch("app.services.url_scanner.analyze_redirects", new_callable=AsyncMock) as mock_red:

            mock_vt.return_value = ComponentScore(
                name="VirusTotal URL", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={}
            )
            mock_gsb.return_value = ComponentScore(
                name="Google Safe Browsing", score=90.0, confidence=Confidence.HIGH,
                finding_type=FindingType.CONFIRMED_THREAT,
                details={"threat_types": ["SOCIAL_ENGINEERING"]},
                evidence=["Google Safe Browsing flagged target as SOCIAL_ENGINEERING"]
            )
            mock_uh.return_value = ComponentScore(
                name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={}
            )
            mock_ssl.return_value = ComponentScore(
                name="SSL/TLS", score=0.0, confidence=Confidence.HIGH,
                finding_type=FindingType.NO_KNOWN_DETECTION
            )
            mock_rdap.return_value = {"domain_age_days": 1000}
            mock_red.return_value = ComponentScore(
                name="Redirect Analysis", score=0.0, confidence=Confidence.MEDIUM,
                finding_type=FindingType.NO_KNOWN_DETECTION
            )

            result = await scan_url("https://example.com/portal")

            self.assertGreaterEqual(result["risk_score"], 85)
            self.assertEqual(result["risk_category"], "MALICIOUS")
            self.assertTrue(result["is_phishing"])
            self.assertEqual(result["phishing_status"], "CONFIRMED_PHISHING")

    # -------------------------------------------------------------------------
    # Scenario 4: Threat Intelligence Timeout -> INSUFFICIENT_EVIDENCE
    # -------------------------------------------------------------------------
    async def test_04_threat_intelligence_timeout(self):
        """
        When providers time out on a domain with no heuristic flags, the system
        must return INSUFFICIENT_EVIDENCE with risk_score None, never LOW threat.
        """
        with patch("app.services.url_scanner.check_virustotal_url", new_callable=AsyncMock) as mock_vt, \
             patch("app.services.url_scanner.check_google_safe_browsing", new_callable=AsyncMock) as mock_gsb, \
             patch("app.services.url_scanner.check_urlhaus", new_callable=AsyncMock) as mock_uh, \
             patch("app.services.url_scanner.check_ssl_tls", new_callable=AsyncMock) as mock_ssl, \
             patch("app.services.url_scanner.get_domain_rdap", new_callable=AsyncMock) as mock_rdap, \
             patch("app.services.url_scanner.analyze_redirects", new_callable=AsyncMock) as mock_red:

            mock_vt.return_value = ComponentScore(
                name="VirusTotal URL", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={"reason": "VirusTotal request timed out", "status": "TIMEOUT"}
            )
            mock_gsb.return_value = ComponentScore(
                name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={"reason": "GSB request timed out", "status": "TIMEOUT"}
            )
            mock_uh.return_value = ComponentScore(
                name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
                finding_type=FindingType.UNABLE_TO_VERIFY, details={"reason": "URLhaus timed out", "status": "TIMEOUT"}
            )
            mock_ssl.return_value = ComponentScore(
                name="SSL/TLS", score=0.0, confidence=Confidence.HIGH,
                finding_type=FindingType.NO_KNOWN_DETECTION
            )
            mock_rdap.return_value = {"domain_age_days": 400}
            mock_red.return_value = ComponentScore(
                name="Redirect Analysis", score=0.0, confidence=Confidence.MEDIUM,
                finding_type=FindingType.NO_KNOWN_DETECTION
            )

            result = await scan_url("https://example.com")

            self.assertIsNone(result["risk_score"])
            self.assertEqual(result["risk_category"], "INSUFFICIENT_EVIDENCE")
            self.assertEqual(result["confidence"], "UNAVAILABLE")
            self.assertIn("threat_intelligence", result["unavailable_checks"])

    # -------------------------------------------------------------------------
    # Scenario 5: HTTP 401/403 Configuration Error Handling
    # -------------------------------------------------------------------------
    def test_05_threat_intel_http_401_403(self):
        """
        401/403 responses must be classified as CONFIGURATION_ERROR without laundering into clean scores.
        """
        vt_err = ComponentScore(
            name="VirusTotal URL", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR", "status_code": 401}
        )
        gsb_err = ComponentScore(
            name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR", "status_code": 403}
        )
        uh_err = ComponentScore(
            name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR", "status_code": 401}
        )

        agg = aggregate_threat_intel(vt_err, gsb_err, uh_err)
        self.assertIsNone(agg.score)
        self.assertEqual(agg.finding_type, FindingType.UNABLE_TO_VERIFY)
        self.assertEqual(agg.confidence, Confidence.UNAVAILABLE)
        self.assertEqual(agg.details.get("error_type"), "ALL_PROVIDERS_UNAVAILABLE")

    # -------------------------------------------------------------------------
    # Scenario 6: Invalid Provider Response (Request Error)
    # -------------------------------------------------------------------------
    def test_06_invalid_provider_response(self):
        """
        Invalid responses (HTTP 400 or malformed JSON) must be recorded as REQUEST_ERROR.
        """
        gsb_bad = ComponentScore(
            name="Google Safe Browsing", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "REQUEST_ERROR", "status_code": 400}
        )
        unavail = ComponentScore(
            name="VirusTotal URL", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY, details={"error_type": "CONFIGURATION_ERROR"}
        )

        agg = aggregate_threat_intel(unavail, gsb_bad, unavail)
        self.assertIsNone(agg.score)
        self.assertEqual(agg.details["sources"]["google_safe_browsing"], "REQUEST_ERROR")

    # -------------------------------------------------------------------------
    # Scenario 7: All Providers Unavailable -> INSUFFICIENT_EVIDENCE
    # -------------------------------------------------------------------------
    def test_07_all_providers_unavailable_insufficient_evidence(self):
        """
        When all external providers are unavailable and coverage is <= 50% without heuristics,
        calculate_risk_score must return INSUFFICIENT_EVIDENCE (never LOW THREAT).
        """
        unavail = ComponentScore(
            name="Unavail", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY
        )
        clean = ComponentScore(
            name="Clean", score=0.0, confidence=Confidence.HIGH,
            finding_type=FindingType.NO_KNOWN_DETECTION
        )

        comps = {
            "threat_intelligence": unavail,
            "phishing_malware": unavail,
            "domain_reputation": clean,
            "url_patterns": clean,
            "ssl_tls": clean,
            "redirect_analysis": clean,
        }

        res = calculate_risk_score(comps)
        self.assertIsNone(res["score"])
        self.assertEqual(res["category"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(res["confidence"], "UNAVAILABLE")

    # -------------------------------------------------------------------------
    # Scenario 8: Raw IPv4 URL Alone Calibration
    # -------------------------------------------------------------------------
    def test_08_raw_ipv4_url_alone(self):
        """
        Raw IPv4 address alone triggers heuristic detection (+35 base), but must NOT
        trigger MALICIOUS or compounding dropper floor without other factors.
        """
        res = analyze_url_patterns("http://198.51.100.1/", "198.51.100.1")
        self.assertGreaterEqual(res.score, 35.0)
        self.assertLess(res.score, 55.0)
        self.assertTrue(res.details.get("is_raw_ip"))
        self.assertFalse(res.details.get("has_script_payload", False))
        self.assertEqual(res.finding_type, FindingType.SUSPICIOUS_INDICATOR)

    # -------------------------------------------------------------------------
    # Scenario 9: Raw IPv6 URL Alone Calibration
    # -------------------------------------------------------------------------
    def test_09_raw_ipv6_url_alone(self):
        """
        Raw IPv6 address alone triggers heuristic detection (+35 base), calibrated to SUSPICIOUS.
        """
        res = analyze_url_patterns("http://[2001:db8::1]/index.html", "[2001:db8::1]")
        self.assertGreaterEqual(res.score, 35.0)
        self.assertLess(res.score, 55.0)
        self.assertTrue(res.details.get("is_raw_ip"))
        self.assertEqual(res.finding_type, FindingType.SUSPICIOUS_INDICATOR)

    # -------------------------------------------------------------------------
    # Scenario 10: Non-Standard Port Alone Calibration
    # -------------------------------------------------------------------------
    def test_10_non_standard_port_alone(self):
        """
        Non-standard high port (:8443) on registered domain increases risk to SUSPICIOUS (not MALICIOUS).
        """
        res_high = analyze_url_patterns("https://example.com:8443/login", "example.com")
        self.assertGreaterEqual(res_high.score, 40.0)
        self.assertLess(res_high.score, 55.0)
        self.assertTrue(res_high.details.get("has_high_port"))
        self.assertEqual(res_high.finding_type, FindingType.SUSPICIOUS_INDICATOR)

    # -------------------------------------------------------------------------
    # Scenario 11: Script Download Path Alone Calibration
    # -------------------------------------------------------------------------
    def test_11_script_download_path_alone(self):
        """
        Script download (.sh, .exe) on standard domain increases score to SUSPICIOUS, not MALICIOUS.
        """
        res_sh = analyze_url_patterns("https://example.com/deploy.sh", "example.com")
        self.assertGreaterEqual(res_sh.score, 45.0)
        self.assertLess(res_sh.score, 55.0)
        self.assertTrue(res_sh.details.get("has_script_payload"))
        self.assertEqual(res_sh.finding_type, FindingType.SUSPICIOUS_INDICATOR)

    # -------------------------------------------------------------------------
    # Scenario 12: Combined Compounding Dropper Heuristics (HEURISTIC_HIGH_RISK)
    # -------------------------------------------------------------------------
    def test_12_combined_compounding_dropper_detection(self):
        """
        Combined raw IP + high port + script path + HTTP triggers HEURISTIC_HIGH_RISK (not CONFIRMED_THREAT).
        """
        res = analyze_url_patterns("http://125.25.107.120:50014/bin.sh", "125.25.107.120")
        self.assertEqual(res.score, 80.0)
        self.assertEqual(res.finding_type, FindingType.HEURISTIC_HIGH_RISK)
        self.assertNotEqual(res.finding_type, FindingType.CONFIRMED_THREAT)
        self.assertTrue(res.details.get("is_raw_ip"))
        self.assertTrue(res.details.get("has_high_port"))
        self.assertTrue(res.details.get("has_script_payload"))

    # -------------------------------------------------------------------------
    # Scenario 13: Legitimate IP-Based Administration URL
    # -------------------------------------------------------------------------
    def test_13_legitimate_ip_based_administration_url(self):
        """
        Internal/local admin IP URL (e.g. router admin) does not trigger compounding dropper.
        """
        res = analyze_url_patterns("http://198.51.100.1:8080/admin", "198.51.100.1")
        self.assertLess(res.score, 75.0)
        self.assertGreaterEqual(res.score, 35.0)
        self.assertNotEqual(res.finding_type, FindingType.CONFIRMED_THREAT)
        self.assertNotEqual(res.finding_type, FindingType.HEURISTIC_HIGH_RISK)

    # -------------------------------------------------------------------------
    # Scenario 14: Legitimate Script Download URL on HTTPS
    # -------------------------------------------------------------------------
    def test_14_legitimate_script_download_on_https(self):
        """
        Script download on registered domain over HTTPS (e.g. install script) must not trigger compounding dropper.
        """
        res = analyze_url_patterns("https://raw.githubusercontent.com/homebrew/install/HEAD/install.sh", "raw.githubusercontent.com")
        self.assertLess(res.score, 75.0)
        self.assertGreaterEqual(res.score, 35.0)
        self.assertNotEqual(res.finding_type, FindingType.CONFIRMED_THREAT)
        self.assertNotEqual(res.finding_type, FindingType.HEURISTIC_HIGH_RISK)

    # -------------------------------------------------------------------------
    # Scenario 15: Verified Clean URL Assessment
    # -------------------------------------------------------------------------
    def test_15_verified_clean_url(self):
        """
        When all 6 subsystems are online, active, and report 0 risk, category is CLEAN with score <= 15.
        """
        comps = {
            "threat_intelligence": ComponentScore("Threat Intel", 0.0, Confidence.HIGH, FindingType.NO_KNOWN_DETECTION),
            "phishing_malware": ComponentScore("Phishing/Malware", 0.0, Confidence.HIGH, FindingType.NO_KNOWN_DETECTION),
            "domain_reputation": ComponentScore("Domain Rep", 0.0, Confidence.HIGH, FindingType.NO_KNOWN_DETECTION),
            "url_patterns": ComponentScore("Patterns", 0.0, Confidence.HIGH, FindingType.NO_KNOWN_DETECTION),
            "ssl_tls": ComponentScore("SSL", 0.0, Confidence.HIGH, FindingType.NO_KNOWN_DETECTION),
            "redirect_analysis": ComponentScore("Redirects", 0.0, Confidence.HIGH, FindingType.NO_KNOWN_DETECTION),
        }

        res = calculate_risk_score(comps)
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["category"], "CLEAN")
        self.assertEqual(res["confidence"], "HIGH")
        self.assertEqual(res["coverage"], 100)

    # -------------------------------------------------------------------------
    # Scenario 16: Mixed Provider Results Resolution
    # -------------------------------------------------------------------------
    def test_16_mixed_provider_results(self):
        """
        When 1 provider confirms threat (score 85), 1 reports clean (0), and 1 times out (None),
        the confirmed threat prevails.
        """
        vt_mal = ComponentScore(
            name="VirusTotal URL", score=85.0, confidence=Confidence.HIGH,
            finding_type=FindingType.CONFIRMED_THREAT, details={"malicious_count": 5}
        )
        gsb_clean = ComponentScore(
            name="Google Safe Browsing", score=0.0, confidence=Confidence.HIGH,
            finding_type=FindingType.NO_KNOWN_DETECTION
        )
        uh_timeout = ComponentScore(
            name="URLhaus", score=None, confidence=Confidence.UNAVAILABLE,
            finding_type=FindingType.UNABLE_TO_VERIFY
        )

        agg = aggregate_threat_intel(vt_mal, gsb_clean, uh_timeout)
        self.assertGreaterEqual(agg.score, 85.0)
        self.assertEqual(agg.finding_type, FindingType.CONFIRMED_THREAT)

    # -------------------------------------------------------------------------
    # Scenario 17: Threat Floor Overrides Linear Dilution
    # -------------------------------------------------------------------------
    def test_17_threat_floor_overrides_linear_weight(self):
        """
        Even when 5 out of 6 components are 0.0 (clean), 1 confirmed threat (score 85)
        sets the threat floor to 85 (MALICIOUS), preventing dilution to ~26 (LOW).
        """
        clean = ComponentScore("Clean", 0.0, Confidence.HIGH, FindingType.NO_KNOWN_DETECTION)
        threat = ComponentScore("Threat", 85.0, Confidence.HIGH, FindingType.CONFIRMED_THREAT)

        comps = {
            "threat_intelligence": threat,
            "phishing_malware": threat,
            "domain_reputation": clean,
            "url_patterns": clean,
            "ssl_tls": clean,
            "redirect_analysis": clean,
        }

        res = calculate_risk_score(comps)
        self.assertEqual(res["score"], 85)
        self.assertEqual(res["category"], "MALICIOUS")
        self.assertTrue(res["has_threat_override"])

    # -------------------------------------------------------------------------
    # Scenario 18: Null Risk Score Contract & Unavailable Checks Telemetry
    # -------------------------------------------------------------------------
    def test_18_null_risk_score_contract(self):
        """
        When risk score is None, category must be INSUFFICIENT_EVIDENCE,
        confidence must be UNAVAILABLE, and unavailable_checks accurately reported.
        """
        unavail = ComponentScore("Unavail", None, Confidence.UNAVAILABLE, FindingType.UNABLE_TO_VERIFY)
        comps = {
            "threat_intelligence": unavail,
            "phishing_malware": unavail,
            "domain_reputation": unavail,
            "url_patterns": unavail,
            "ssl_tls": unavail,
            "redirect_analysis": unavail,
        }

        res = calculate_risk_score(comps)
        self.assertIsNone(res["score"])
        self.assertEqual(res["category"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(res["confidence"], "UNAVAILABLE")
        self.assertEqual(len(res["unavailable_checks"]), 6)

    # -------------------------------------------------------------------------
    # Scenario 19: Heuristics Cannot Set Confirmed Malware Status (Integrity Check)
    # -------------------------------------------------------------------------
    def test_19_heuristics_cannot_set_confirmed_malware(self):
        """
        Strict integrity: URL characteristics must produce SUSPECTED_MALWARE,
        and is_malware must remain None (never True).
        """
        unavail = ComponentScore("Unavail", None, Confidence.UNAVAILABLE, FindingType.UNABLE_TO_VERIFY)
        dropper_patterns = ComponentScore(
            name="URL Pattern Analysis", score=80.0, confidence=Confidence.HIGH,
            finding_type=FindingType.HEURISTIC_HIGH_RISK,
            evidence=["Compounding heuristic risk: Direct IP, non-standard port, and script payload on unencrypted HTTP"]
        )

        malware_status, is_malware = _get_malware_status(unavail, unavail, dropper_patterns)
        self.assertEqual(malware_status, "SUSPECTED_MALWARE")
        self.assertIsNone(is_malware)
        self.assertNotEqual(is_malware, True)

    # -------------------------------------------------------------------------
    # Scenario 20: Confirmed External Provider Sets Confirmed Malware Status
    # -------------------------------------------------------------------------
    def test_20_confirmed_provider_sets_confirmed_malware(self):
        """
        When URLhaus or VirusTotal explicitly identifies malware, status is CONFIRMED_MALWARE
        and is_malware is True.
        """
        uh_mal = ComponentScore(
            name="URLhaus", score=95.0, confidence=Confidence.HIGH,
            finding_type=FindingType.CONFIRMED_THREAT,
            evidence=["URLhaus confirmed malware payload distribution"]
        )
        unavail = ComponentScore("Unavail", None, Confidence.UNAVAILABLE, FindingType.UNABLE_TO_VERIFY)

        malware_status, is_malware = _get_malware_status(unavail, uh_mal)
        self.assertEqual(malware_status, "CONFIRMED_MALWARE")
        self.assertTrue(is_malware)


if __name__ == "__main__":
    unittest.main()
