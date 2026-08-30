from unittest.mock import MagicMock, patch

from django.test import Client, TestCase, override_settings

from .management.commands.summarize_performance import build_summary, metric_summary
from .openwrt import authenticate, reboot
from .security import TOKEN_KEY

ORIGIN = "http://router.test"


@override_settings(
    LAB_ALLOWED_ORIGINS={ORIGIN}, LAB_CONDITION="C1",
    ROUTER_AUTH_BACKEND="local", ROUTER_STATUS_ENABLED=False
)
class DefenceTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.client.get("/")
        self.token = self.client.session[TOKEN_KEY]

    def test_valid_request(self):
        response = self.client.post(
            "/login",
            {"username": "admin", "password": "routerlab", "csrf_token": self.token},
            HTTP_ORIGIN=ORIGIN,
        )
        self.assertEqual(response.status_code, 302)

    def test_missing_token_rejected(self):
        response = self.client.post("/login", {}, HTTP_ORIGIN=ORIGIN)
        self.assertEqual(response.status_code, 403)

    def test_hostile_origin_rejected_first(self):
        response = self.client.post(
            "/login", {}, HTTP_ORIGIN="http://attacker.test:8080"
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Origin", response.json()["error"])

    def test_referer_fallback(self):
        response = self.client.post(
            "/login",
            {"username": "admin", "password": "routerlab", "csrf_token": self.token},
            HTTP_REFERER=f"{ORIGIN}/",
        )
        self.assertEqual(response.status_code, 302)

    @override_settings(LAB_TOKEN_IDLE_SECONDS=-1)
    def test_expired_token_is_rejected(self):
        response = self.client.post(
            "/login",
            {"username": "admin", "password": "routerlab", "csrf_token": self.token},
            HTTP_ORIGIN=ORIGIN,
        )
        self.assertEqual(response.status_code, 403)


@override_settings(LAB_CONDITION="C0", ROUTER_AUTH_BACKEND="local")
class BaselineTests(TestCase):
    def test_cross_origin_request_is_not_blocked(self):
        response = self.client.post(
            "/login",
            {"username": "admin", "password": "routerlab"},
            HTTP_ORIGIN="http://attacker.test:8080",
        )
        self.assertEqual(response.status_code, 302)

    def test_attack_lab_is_available_to_attacker_server(self):
        response = self.client.get("/attack-lab/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CSRF attack laboratory")


class OpenWrtAuthenticationTests(TestCase):
    @patch("router.openwrt.urlopen")
    def test_valid_ubus_session_is_accepted(self, mocked_urlopen):
        response = MagicMock()
        response.read.return_value = (
            b'{"jsonrpc":"2.0","id":1,"result":[0,'
            b'{"ubus_rpc_session":"abc123","expires":300}]}'
        )
        mocked_urlopen.return_value.__enter__.return_value = response

        result = authenticate("root", "secret")

        self.assertTrue(result.authenticated)
        self.assertEqual(result.session_id, "abc123")
        sent_request = mocked_urlopen.call_args.args[0]
        self.assertIn(b'"username": "root"', sent_request.data)
        self.assertIn(b'"password": "secret"', sent_request.data)

    @patch("router.openwrt.urlopen")
    def test_rejected_credentials_are_not_accepted(self, mocked_urlopen):
        response = MagicMock()
        response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":[6]}'
        mocked_urlopen.return_value.__enter__.return_value = response

        result = authenticate("root", "wrong")

        self.assertFalse(result.authenticated)

    @patch("router.openwrt.urlopen")
    def test_reboot_uses_authenticated_ubus_session(self, mocked_urlopen):
        response = MagicMock()
        response.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":[0]}'
        mocked_urlopen.return_value.__enter__.return_value = response

        result = reboot("router-session-123")

        self.assertTrue(result.successful)
        sent = mocked_urlopen.call_args.args[0].data
        self.assertIn(b'"router-session-123"', sent)
        self.assertIn(b'"system"', sent)
        self.assertIn(b'"reboot"', sent)


@override_settings(
    LAB_CONDITION="C1",
    LAB_ALLOWED_ORIGINS={ORIGIN},
    OBSERVABILITY_ENABLED=True,
    ROUTER_AUTH_BACKEND="local",
    ROUTER_STATUS_ENABLED=False,
)
class ObservabilityTests(TestCase):
    @patch("router.middleware.log_event")
    def test_request_has_timing_headers_and_structured_event(self, mocked_log_event):
        response = self.client.get("/api/status")

        self.assertEqual(response.status_code, 200)
        self.assertIn("app;dur=", response["Server-Timing"])
        self.assertEqual(len(response["X-Request-ID"]), 16)
        event = next(
            call for call in mocked_log_event.call_args_list
            if call.args == ("http_request",)
        )
        self.assertEqual(event.kwargs["path"], "/api/status")
        self.assertEqual(event.kwargs["outcome"], "allowed")
        self.assertGreaterEqual(event.kwargs["duration_ms"], 0)
        self.assertIn("rss_start_mb", event.kwargs)
        self.assertIn("rss_end_mb", event.kwargs)
        self.assertIn("rss_delta_mb", event.kwargs)

    @patch("router.middleware.log_event")
    def test_multiple_requests_receive_distinct_ids(self, mocked_log_event):
        first = self.client.get("/api/status")
        second = self.client.get("/api/status")

        self.assertNotEqual(first["X-Request-ID"], second["X-Request-ID"])
        request_events = [
            call for call in mocked_log_event.call_args_list
            if call.args == ("http_request",)
        ]
        self.assertEqual(len(request_events), 2)

    @patch("router.middleware.log_event")
    def test_rejected_request_records_security_outcome(self, mocked_log_event):
        response = self.client.post("/dns", {"dns": "6.6.6.6"}, HTTP_ORIGIN="http://evil.test")

        self.assertEqual(response.status_code, 403)
        event = next(
            call for call in mocked_log_event.call_args_list
            if call.args == ("http_request",)
        )
        self.assertEqual(event.kwargs["outcome"], "blocked_origin")
        self.assertGreaterEqual(event.kwargs["security_duration_ms"], 0)

    @patch("router.openwrt.log_event")
    @patch("router.openwrt.urlopen")
    def test_router_event_does_not_contain_credentials(
        self, mocked_urlopen, mocked_log_event
    ):
        response = MagicMock()
        response.read.return_value = (
            b'{"jsonrpc":"2.0","id":1,"result":[0,'
            b'{"ubus_rpc_session":"session-secret","expires":300}]}'
        )
        mocked_urlopen.return_value.__enter__.return_value = response

        result = authenticate("private-user", "private-password")

        self.assertTrue(result.authenticated)
        recorded = repr(mocked_log_event.call_args)
        self.assertNotIn("private-user", recorded)
        self.assertNotIn("private-password", recorded)
        self.assertNotIn("session-secret", recorded)
        self.assertEqual(mocked_log_event.call_args.args[0], "router_call")


class PerformanceSummaryTests(TestCase):
    def test_metric_summary_calculates_p95(self):
        summary = metric_summary(range(1, 21))

        self.assertEqual(summary["median"], 10.5)
        self.assertEqual(summary["p95"], 19.0)

    def test_summary_compares_matching_allowed_requests(self):
        events = [
            {"event": "http_request", "condition": "C0", "run_id": "a", "path": "/dns", "outcome": "allowed", "status": 200, "duration_ms": 1, "cpu_ms": 0.5},
            {"event": "http_request", "condition": "C1", "run_id": "b", "path": "/dns", "outcome": "allowed", "status": 200, "duration_ms": 1.5, "cpu_ms": 0.7},
        ]

        summary = build_summary(events)

        comparison = summary["allowed_request_comparisons"][0]
        self.assertEqual(comparison["overhead_ms"], 0.5)
        self.assertEqual(comparison["relative_overhead_percent"], 50.0)
