"""
CYBERCORE Backend — Proxy Security & Header Spoofing Prevention Test Suite

Tests:
  1. Untrusted client IP cannot spoof X-Forwarded-For
  2. Untrusted client IP cannot spoof CF-Connecting-IP / True-Client-IP
  3. Untrusted client IP cannot spoof X-Real-IP
  4. Compound spoofed headers are rejected
  5. Untrusted client spoofing loopback (127.0.0.1) in XFF is rejected
  6. Untrusted private IP outside TRUSTED_PROXIES (10.x) is rejected
  7. Untrusted private IP outside TRUSTED_PROXIES (172.16.x) is rejected
  8. Untrusted private IP outside TRUSTED_PROXIES (192.168.x) is rejected
  9. Trusted localhost (127.0.0.1) extracts legitimate client IP
 10. Trusted IPv6 loopback (::1) extracts legitimate client IP
 11. Explicitly configured proxy IP (e.g. 10.0.0.1 in whitelist) extracts legitimate client IP
 12. Explicitly configured CIDR (e.g. 172.17.0.0/16 for Docker bridge) extracts legitimate client IP
 13. Multi-hop XFF chain extracts original client IP
 14. Malformed header values (strings, non-IPs, injection) handle gracefully without crashing
 15. Uvicorn ProxyHeadersMiddleware restriction prevents ASGI client scope overwrites
 16. Rate limiter key function integration with get_client_ip prevents header-spoofing bypass
"""

import unittest
from unittest.mock import MagicMock
import asyncio

from app.utils.security import get_client_ip, is_trusted_proxy_address, is_trusted_proxy_request
from app.limiter import limiter
from unittest.mock import patch
import app.utils.security as security_module


class TestProxySecurity(unittest.TestCase):
    def test_01_untrusted_client_xff_rejected(self):
        """Untrusted direct client IP cannot spoof X-Forwarded-For."""
        mock_req = MagicMock()
        mock_req.client.host = "203.0.113.195"
        mock_req.headers = {"x-forwarded-for": "1.2.3.4"}
        self.assertEqual(get_client_ip(mock_req), "203.0.113.195")

    def test_02_untrusted_client_cf_connecting_ip_rejected(self):
        """Untrusted direct client IP cannot spoof CF-Connecting-IP or True-Client-IP."""
        mock_req = MagicMock()
        mock_req.client.host = "198.51.100.99"
        mock_req.headers = {"cf-connecting-ip": "9.9.9.9", "true-client-ip": "8.8.8.8"}
        self.assertEqual(get_client_ip(mock_req), "198.51.100.99")

    def test_03_untrusted_client_x_real_ip_rejected(self):
        """Untrusted direct client IP cannot spoof X-Real-IP."""
        mock_req = MagicMock()
        mock_req.client.host = "8.8.8.8"
        mock_req.headers = {"x-real-ip": "1.1.1.1"}
        self.assertEqual(get_client_ip(mock_req), "8.8.8.8")

    def test_04_untrusted_client_compound_headers_rejected(self):
        """Untrusted client with all spoofing headers simultaneously gets resolved to direct peer."""
        mock_req = MagicMock()
        mock_req.client.host = "198.51.100.77"
        mock_req.headers = {
            "x-forwarded-for": "10.0.0.1, 192.168.1.1",
            "cf-connecting-ip": "1.1.1.1",
            "true-client-ip": "2.2.2.2",
            "x-real-ip": "3.3.3.3",
        }
        self.assertEqual(get_client_ip(mock_req), "198.51.100.77")

    def test_05_untrusted_client_spoofing_loopback_rejected(self):
        """Untrusted client claiming to forward 127.0.0.1 remains attributed to actual untrusted IP."""
        mock_req = MagicMock()
        mock_req.client.host = "203.0.113.50"
        mock_req.headers = {"x-forwarded-for": "127.0.0.1"}
        self.assertEqual(get_client_ip(mock_req), "203.0.113.50")

    def test_06_untrusted_private_ip_10_rejected(self):
        """Private IP (10.0.1.5) outside TRUSTED_PROXIES cannot spoof forward headers."""
        mock_req = MagicMock()
        mock_req.client.host = "10.0.1.5"
        mock_req.headers = {"x-forwarded-for": "198.51.100.88"}
        self.assertEqual(get_client_ip(mock_req), "10.0.1.5")

    def test_07_untrusted_private_ip_172_rejected(self):
        """Private IP (172.16.0.5) outside TRUSTED_PROXIES cannot spoof forward headers."""
        mock_req = MagicMock()
        mock_req.client.host = "172.16.0.5"
        mock_req.headers = {"x-forwarded-for": "198.51.100.88"}
        self.assertEqual(get_client_ip(mock_req), "172.16.0.5")

    def test_08_untrusted_private_ip_192_rejected(self):
        """Private IP (192.168.1.50) outside TRUSTED_PROXIES cannot spoof forward headers."""
        mock_req = MagicMock()
        mock_req.client.host = "192.168.1.50"
        mock_req.headers = {"x-forwarded-for": "198.51.100.88"}
        self.assertEqual(get_client_ip(mock_req), "192.168.1.50")

    def test_09_trusted_localhost_resolves_xff(self):
        """Default trusted 127.0.0.1 reverse proxy legitimately forwards client IP."""
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"
        mock_req.headers = {"x-forwarded-for": "198.51.100.22"}
        self.assertEqual(get_client_ip(mock_req), "198.51.100.22")

    def test_10_trusted_ipv6_loopback_resolves_xff(self):
        """Default trusted ::1 IPv6 reverse proxy legitimately forwards client IP."""
        mock_req = MagicMock()
        mock_req.client.host = "::1"
        mock_req.headers = {"x-forwarded-for": "198.51.100.33"}
        self.assertEqual(get_client_ip(mock_req), "198.51.100.33")

    def test_11_explicitly_configured_proxy_ip_resolves(self):
        """When an internal proxy (e.g. 10.0.0.1) is explicitly configured in TRUSTED_PROXIES, it is trusted."""
        custom_whitelist = ["127.0.0.1", "::1", "10.0.0.1"]
        self.assertTrue(is_trusted_proxy_address("10.0.0.1", trusted_list=custom_whitelist))
        # But an unlisted peer on the same subnet remains untrusted
        self.assertFalse(is_trusted_proxy_address("10.0.0.2", trusted_list=custom_whitelist))

    def test_12_explicitly_configured_docker_cidr_resolves(self):
        """When a CIDR (e.g. 172.17.0.0/16 for Docker bridge) is explicitly configured, it is trusted."""
        docker_whitelist = ["127.0.0.1", "::1", "172.17.0.0/16"]
        self.assertTrue(is_trusted_proxy_address("172.17.0.1", trusted_list=docker_whitelist))
        self.assertTrue(is_trusted_proxy_address("172.17.0.5", trusted_list=docker_whitelist))
        # An unlisted CIDR remains untrusted
        self.assertFalse(is_trusted_proxy_address("172.18.0.1", trusted_list=docker_whitelist))

    def test_13_multi_hop_xff_extracts_origin_client(self):
        """Multi-hop X-Forwarded-For chain extracts the originating client IP (first item)."""
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"
        mock_req.headers = {"x-forwarded-for": "203.0.113.44, 10.0.0.1, 10.0.0.2"}
        self.assertEqual(get_client_ip(mock_req), "203.0.113.44")

    def test_14_malformed_headers_handled_safely(self):
        """Non-IP garbage, injection attempts, and empty headers do not crash."""
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"
        for bad_val in ["not-an-ip", "<script>alert(1)</script>", "'; DROP TABLE;--", "", "  , , "]:
            mock_req.headers = {"x-forwarded-for": bad_val}
            self.assertEqual(get_client_ip(mock_req), "127.0.0.1")

    def test_15_uvicorn_proxy_headers_middleware_untrusted_rejection(self):
        """
        Verify that Uvicorn's ProxyHeadersMiddleware with restricted trusted_hosts ('127.0.0.1,::1')
        does NOT rewrite scope['client'] for an untrusted direct peer.
        """
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

        received_clients = []

        async def app(scope, receive, send):
            received_clients.append(scope.get("client"))

        middleware = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1,::1")

        # Untrusted peer sends spoofed XFF
        scope_untrusted = {
            "type": "http",
            "client": ("203.0.113.195", 41234),
            "headers": [
                (b"x-forwarded-for", b"1.2.3.4"),
                (b"x-forwarded-proto", b"https"),
            ],
        }
        asyncio.run(middleware(scope_untrusted, None, None))
        self.assertEqual(received_clients[0][0], "203.0.113.195", "Uvicorn must NOT rewrite untrusted peer IP")

        # Trusted peer sends legitimate XFF
        scope_trusted = {
            "type": "http",
            "client": ("127.0.0.1", 41234),
            "headers": [
                (b"x-forwarded-for", b"1.2.3.4"),
                (b"x-forwarded-proto", b"https"),
            ],
        }
        asyncio.run(middleware(scope_trusted, None, None))
        self.assertEqual(received_clients[1][0], "1.2.3.4", "Uvicorn must rewrite client IP for trusted proxy")

    def test_16_rate_limiter_key_func_uses_get_client_ip(self):
        """Verify that slowapi limiter key_func is get_client_ip and prevents spoofing bypass."""
        mock_untrusted_req = MagicMock()
        mock_untrusted_req.client.host = "203.0.113.88"
        mock_untrusted_req.headers = {"x-forwarded-for": "1.1.1.1"}

        # Limiter key function must evaluate to the direct IP, NOT the spoofed header
        rate_key = limiter._key_func(mock_untrusted_req)
        self.assertEqual(rate_key, "203.0.113.88")

    def test_17_execution_order_wildcard_erases_original_peer_demonstration(self):
        """
        DEMONSTRATION OF ISSUE 2 EXECUTION ORDER:
        When Uvicorn runs with trusted_hosts='*' (wildcard), ProxyHeadersMiddleware runs
        BEFORE FastAPI, overwriting scope['client']. As a result, get_client_ip() sees
        the already-rewritten address (127.0.0.1) instead of the true socket peer (203.0.113.195).
        This proves that get_client_ip() is NOT an independent defense layer if Uvicorn trusts '*'.
        """
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
        from starlette.requests import Request

        app_received_state = []

        async def downstream_app(scope, receive, send):
            req = Request(scope)
            app_received_state.append({
                "direct_socket_host": req.client.host,
                "resolved_client_ip": get_client_ip(req),
            })

        # Emulate Uvicorn started with --forwarded-allow-ips '*'
        middleware_wildcard = ProxyHeadersMiddleware(downstream_app, trusted_hosts="*")

        # Untrusted external socket peer connects and claims to be 127.0.0.1
        scope = {
            "type": "http",
            "client": ("203.0.113.195", 54321),
            "headers": [(b"x-forwarded-for", b"127.0.0.1")],
        }
        asyncio.run(middleware_wildcard(scope, None, None))

        result = app_received_state[0]
        # Uvicorn already overwrote the socket peer before the application saw it!
        self.assertEqual(result["direct_socket_host"], "127.0.0.1")
        # And get_client_ip() sees 127.0.0.1, believing it's a trusted proxy
        self.assertEqual(result["resolved_client_ip"], "127.0.0.1")

    def test_18_execution_order_restricted_preserves_peer_demonstration(self):
        """
        DEMONSTRATION OF PROPER RESTRICTED INGRESS:
        When Uvicorn runs with trusted_hosts='127.0.0.1,::1', ProxyHeadersMiddleware does NOT
        rewrite scope['client'] for untrusted socket peers. The application receives the true
        socket peer (203.0.113.195) and get_client_ip() successfully rejects the spoofed header.
        """
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
        from starlette.requests import Request

        app_received_state = []

        async def downstream_app(scope, receive, send):
            req = Request(scope)
            app_received_state.append({
                "direct_socket_host": req.client.host,
                "resolved_client_ip": get_client_ip(req),
            })

        # Emulate Uvicorn started with restricted allowlist
        middleware_restricted = ProxyHeadersMiddleware(downstream_app, trusted_hosts="127.0.0.1,::1")

        # Untrusted external socket peer connects and claims to be 127.0.0.1
        scope = {
            "type": "http",
            "client": ("203.0.113.195", 54321),
            "headers": [(b"x-forwarded-for", b"127.0.0.1")],
        }
        asyncio.run(middleware_restricted(scope, None, None))

        result = app_received_state[0]
        # The true socket peer was preserved!
        self.assertEqual(result["direct_socket_host"], "203.0.113.195")
        # get_client_ip() correctly rejects the spoofed header and returns the real peer
        self.assertEqual(result["resolved_client_ip"], "203.0.113.195")

    def test_19_ingress_secret_authenticated_resolves_cf_ip(self):
        """
        Approach D: When INGRESS_SECRET is set and request provides valid X-CYBERCORE-Ingress-Secret,
        incoming request from a dynamic private IP (e.g. Render 10.0.1.5 load balancer)
        is authenticated and extracts CF-Connecting-IP.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.1.5"  # Render private internal load balancer IP
        mock_req.headers = {
            "x-cybercore-ingress-secret": "test-super-secret-token",
            "cf-connecting-ip": "203.0.113.88",
        }
        with patch.object(security_module.settings, "ingress_secret", "test-super-secret-token"):
            self.assertTrue(is_trusted_proxy_request(mock_req))
            self.assertEqual(get_client_ip(mock_req), "203.0.113.88")

    def test_20_ingress_secret_authenticated_resolves_xff(self):
        """
        Approach D: When authenticated via INGRESS_SECRET, extracts original client from X-Forwarded-For.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.2.10"
        mock_req.headers = {
            "x-cybercore-ingress-secret": "test-super-secret-token",
            "x-forwarded-for": "198.51.100.42, 10.0.0.1",
        }
        with patch.object(security_module.settings, "ingress_secret", "test-super-secret-token"):
            self.assertTrue(is_trusted_proxy_request(mock_req))
            self.assertEqual(get_client_ip(mock_req), "198.51.100.42")

    def test_21_ingress_secret_missing_rejects_private_peer_spoofing(self):
        """
        Direct private-peer spoofing attempt: An internal service on Render's private network
        (10.0.1.5) connects directly and sends spoofed headers WITHOUT X-CYBERCORE-Ingress-Secret.
        It is rejected as an untrusted peer and attributed strictly to 10.0.1.5.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.1.5"
        mock_req.headers = {
            "cf-connecting-ip": "1.1.1.1",
            "x-forwarded-for": "2.2.2.2",
            "x-real-ip": "3.3.3.3",
        }
        with patch.object(security_module.settings, "ingress_secret", "test-super-secret-token"):
            self.assertFalse(is_trusted_proxy_request(mock_req))
            self.assertEqual(get_client_ip(mock_req), "10.0.1.5")

    def test_22_ingress_secret_invalid_rejects_private_peer_spoofing(self):
        """
        Direct private-peer spoofing attempt: An internal service sends an INVALID ingress secret.
        Constant-time comparison fails; headers are ignored, returning direct socket host.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.1.5"
        mock_req.headers = {
            "x-cybercore-ingress-secret": "forged-or-wrong-token",
            "cf-connecting-ip": "1.1.1.1",
        }
        with patch.object(security_module.settings, "ingress_secret", "test-super-secret-token"):
            self.assertFalse(is_trusted_proxy_request(mock_req))
            self.assertEqual(get_client_ip(mock_req), "10.0.1.5")

    def test_23_duplicated_cf_connecting_ip_extracts_first_clean_ip(self):
        """
        When duplicated or comma-separated CF-Connecting-IP (e.g. proxy concatenation) is received,
        get_client_ip extracts the clean primary IP rather than failing.
        """
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"
        mock_req.headers = {"cf-connecting-ip": "203.0.113.99, 10.0.0.1"}
        self.assertEqual(get_client_ip(mock_req), "203.0.113.99")

    def test_24_duplicated_xff_headers_extracts_origin_ip(self):
        """
        When duplicated or comma-separated X-Forwarded-For headers are present,
        the leftmost client IP is extracted.
        """
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"
        mock_req.headers = {"x-forwarded-for": "198.51.100.42, 10.0.0.1, 10.0.0.2"}
        self.assertEqual(get_client_ip(mock_req), "198.51.100.42")

    def test_25_malformed_and_injection_cf_connecting_ip_fallback(self):
        """
        Malformed CF-Connecting-IP values (invalid IP, non-numeric, SQL/XSS payloads)
        safely fall through without raising exceptions.
        """
        mock_req = MagicMock()
        mock_req.client.host = "127.0.0.1"
        for bad_cf in ["999.999.999.999", "not-an-ip", "<script>alert(1)</script>", ""]:
            mock_req.headers = {"cf-connecting-ip": bad_cf, "x-real-ip": "203.0.113.55"}
            self.assertEqual(get_client_ip(mock_req), "203.0.113.55")

    def test_26_rate_limiter_keys_on_authenticated_ingress_client_ip(self):
        """
        Verify that SlowAPI rate limiter correctly keys on real client IP when ingress secret
        authenticates the proxy, and keys on direct private IP when secret is missing.
        """
        with patch.object(security_module.settings, "ingress_secret", "test-super-secret-token"):
            # Authenticated ingress request
            mock_auth_req = MagicMock()
            mock_auth_req.client.host = "10.0.1.5"
            mock_auth_req.headers = {
                "x-cybercore-ingress-secret": "test-super-secret-token",
                "cf-connecting-ip": "203.0.113.77",
            }
            self.assertEqual(limiter._key_func(mock_auth_req), "203.0.113.77")

            # Unauthenticated direct private request
            mock_unauth_req = MagicMock()
            mock_unauth_req.client.host = "10.0.1.5"
            mock_unauth_req.headers = {
                "cf-connecting-ip": "203.0.113.77",
            }
            self.assertEqual(limiter._key_func(mock_unauth_req), "10.0.1.5")

    def test_27_valid_secret_non_loopback_private_peer_not_in_trusted_proxies(self):
        """
        Verify that a non-loopback private socket peer (e.g. Render load balancer 10.0.1.5)
        that is NOT in TRUSTED_PROXIES is trusted when valid X-CYBERCORE-Ingress-Secret is provided.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.1.5"  # NOT in TRUSTED_PROXIES ("127.0.0.1,::1")
        mock_req.headers = {
            "x-cybercore-ingress-secret": "render-ingress-secret-token",
            "cf-connecting-ip": "198.51.100.200",
        }
        with patch.object(security_module.settings, "ingress_secret", "render-ingress-secret-token"):
            with patch.object(security_module.settings, "trusted_proxies", "127.0.0.1,::1"):
                # Even though 10.0.1.5 is NOT in trusted_proxies_list, secret authenticates it
                self.assertNotIn("10.0.1.5", security_module.settings.trusted_proxies_list)
                self.assertTrue(is_trusted_proxy_request(mock_req))
                self.assertEqual(get_client_ip(mock_req), "198.51.100.200")

    def test_28_spoofed_xff_without_secret_rejected(self):
        """
        An attacker or internal peer on a non-loopback IP (10.0.2.55) attempts to spoof
        X-Forwarded-For without providing X-CYBERCORE-Ingress-Secret. Spoofing is rejected.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.2.55"
        mock_req.headers = {
            "x-forwarded-for": "1.2.3.4, 5.6.7.8",
        }
        with patch.object(security_module.settings, "ingress_secret", "render-ingress-secret-token"):
            self.assertFalse(is_trusted_proxy_request(mock_req))
            self.assertEqual(get_client_ip(mock_req), "10.0.2.55")

    def test_29_spoofed_cf_connecting_ip_without_secret_rejected(self):
        """
        An attacker or internal peer on a non-loopback IP (10.0.2.55) attempts to spoof
        CF-Connecting-IP without providing X-CYBERCORE-Ingress-Secret. Spoofing is rejected.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.2.55"
        mock_req.headers = {
            "cf-connecting-ip": "8.8.8.8",
        }
        with patch.object(security_module.settings, "ingress_secret", "render-ingress-secret-token"):
            self.assertFalse(is_trusted_proxy_request(mock_req))
            self.assertEqual(get_client_ip(mock_req), "10.0.2.55")

    def test_30_malformed_forwarded_addresses_fallback_to_socket_peer(self):
        """
        When valid secret is provided but forward headers contain garbage non-IP values,
        validation safely rejects the invalid addresses and falls back to socket peer.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.1.5"
        mock_req.headers = {
            "x-cybercore-ingress-secret": "render-ingress-secret-token",
            "cf-connecting-ip": "malformed.domain.or.garbage",
            "x-forwarded-for": "also_not_an_ip, 999.999.999.999",
            "x-real-ip": "totally-invalid",
        }
        with patch.object(security_module.settings, "ingress_secret", "render-ingress-secret-token"):
            self.assertTrue(is_trusted_proxy_request(mock_req))
            self.assertEqual(get_client_ip(mock_req), "10.0.1.5")

    def test_31_duplicate_and_comma_separated_with_ingress_secret(self):
        """
        When valid secret is provided with duplicate or comma-separated forward headers,
        get_client_ip properly extracts the first valid client IP.
        """
        mock_req = MagicMock()
        mock_req.client.host = "10.0.1.5"
        mock_req.headers = {
            "x-cybercore-ingress-secret": "render-ingress-secret-token",
            "cf-connecting-ip": "203.0.113.150, 10.0.1.5",
        }
        with patch.object(security_module.settings, "ingress_secret", "render-ingress-secret-token"):
            self.assertEqual(get_client_ip(mock_req), "203.0.113.150")

        # Also test with X-Forwarded-For
        mock_req_xff = MagicMock()
        mock_req_xff.client.host = "10.0.1.5"
        mock_req_xff.headers = {
            "x-cybercore-ingress-secret": "render-ingress-secret-token",
            "x-forwarded-for": "198.51.100.99, 10.0.1.5, 10.0.2.1",
        }
        with patch.object(security_module.settings, "ingress_secret", "render-ingress-secret-token"):
            self.assertEqual(get_client_ip(mock_req_xff), "198.51.100.99")


if __name__ == "__main__":
    unittest.main()
