from unittest.mock import MagicMock, patch

from django.test import Client, TestCase, override_settings

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
