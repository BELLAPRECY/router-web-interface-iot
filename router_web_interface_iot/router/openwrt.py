import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

from django.conf import settings


@dataclass
class RouterLoginResult:
    authenticated: bool
    session_id: str = ""
    expires: int = 0
    error: str = ""


@dataclass
class RouterConnection:
    host: str
    luci_url: str
    reachable: bool
    detail: str


@dataclass
class RouterCallResult:
    successful: bool
    error: str = ""


def connection_status():
    """Perform a short, read-only reachability check against LuCI."""
    host = urlsplit(settings.ROUTER_LUCI_URL).hostname or "unknown"
    if not settings.ROUTER_STATUS_ENABLED:
        return RouterConnection(host, settings.ROUTER_LUCI_URL, False, "Check disabled")
    request = Request(settings.ROUTER_LUCI_URL, method="GET")
    try:
        with urlopen(request, timeout=settings.ROUTER_STATUS_TIMEOUT):
            return RouterConnection(host, settings.ROUTER_LUCI_URL, True, "Reachable")
    except HTTPError as error:
        # An HTTP response still proves that the router web server is reachable.
        return RouterConnection(
            host, settings.ROUTER_LUCI_URL, True, f"Reachable (HTTP {error.code})"
        )
    except (URLError, TimeoutError, OSError):
        return RouterConnection(host, settings.ROUTER_LUCI_URL, False, "Offline")


def authenticate(username, password):
    """Authenticate against OpenWrt ubus without retaining the password."""
    if not username or not password:
        return RouterLoginResult(False, error="Enter the router username and password.")

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": [
            "00000000000000000000000000000000",
            "session",
            "login",
            {"username": username, "password": password},
        ],
    }
    request = Request(
        settings.ROUTER_UBUS_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=settings.ROUTER_UBUS_TIMEOUT) as response:
            result = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return RouterLoginResult(
            False,
            error="Django could not contact the OpenWrt authentication service.",
        )

    # A successful ubus call is [0, {ubus_rpc_session: ..., expires: ...}].
    rpc_result = result.get("result", [])
    if (
        len(rpc_result) >= 2
        and rpc_result[0] == 0
        and isinstance(rpc_result[1], dict)
        and rpc_result[1].get("ubus_rpc_session")
    ):
        data = rpc_result[1]
        return RouterLoginResult(
            True,
            session_id=data["ubus_rpc_session"],
            expires=int(data.get("expires", 0)),
        )
    return RouterLoginResult(False, error="The router rejected those credentials.")


def call(session_id, object_name, method_name, arguments=None):
    """Call a fixed OpenWrt ubus method using the authenticated router session."""
    if not session_id:
        return RouterCallResult(False, "The router session is missing; sign in again.")
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "call",
        "params": [session_id, object_name, method_name, arguments or {}],
    }
    request = Request(
        settings.ROUTER_UBUS_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=settings.ROUTER_UBUS_TIMEOUT) as response:
            result = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return RouterCallResult(False, "The router did not confirm the command.")

    rpc_result = result.get("result", [])
    if rpc_result and rpc_result[0] == 0:
        return RouterCallResult(True)
    if rpc_result and rpc_result[0] in {6, 7}:
        return RouterCallResult(False, "Router session expired; sign out and sign in again.")
    return RouterCallResult(False, "OpenWrt rejected the command.")


def reboot(session_id):
    return call(session_id, "system", "reboot")
