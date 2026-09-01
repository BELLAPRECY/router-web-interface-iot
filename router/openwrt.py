import json
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

from django.conf import settings

from .observability import log_event


ANONYMOUS_UBUS_SESSION = "00000000000000000000000000000000"


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


def _log_router_call(operation, started_ns, outcome, successful, **fields):
    log_event(
        "router_call",
        operation=operation,
        outcome=outcome,
        successful=successful,
        duration_ms=round((time.perf_counter_ns() - started_ns) / 1_000_000, 3),
        **fields,
    )


def connection_status():
    """Perform a short, read-only reachability check against LuCI."""
    started_ns = time.perf_counter_ns()
    host = urlsplit(settings.ROUTER_LUCI_URL).hostname or "unknown"
    if not settings.ROUTER_STATUS_ENABLED:
        _log_router_call("luci_status", started_ns, "disabled", None)
        return RouterConnection(host, settings.ROUTER_LUCI_URL, False, "Check disabled")
    request = Request(settings.ROUTER_LUCI_URL, method="GET")
    try:
        with urlopen(request, timeout=settings.ROUTER_STATUS_TIMEOUT):
            _log_router_call("luci_status", started_ns, "reachable", True)
            return RouterConnection(host, settings.ROUTER_LUCI_URL, True, "Reachable")
    except HTTPError as error:
        # An HTTP response still proves that the router web server is reachable.
        _log_router_call(
            "luci_status", started_ns, "http_response", True, http_status=error.code
        )
        return RouterConnection(
            host, settings.ROUTER_LUCI_URL, True, f"Reachable (HTTP {error.code})"
        )
    except (URLError, TimeoutError, OSError) as error:
        _log_router_call(
            "luci_status",
            started_ns,
            "unreachable",
            False,
            error_type=type(error).__name__,
        )
        return RouterConnection(host, settings.ROUTER_LUCI_URL, False, "Offline")


def authenticate(username, password):
    """Authenticate against OpenWrt ubus without retaining the password."""
    started_ns = time.perf_counter_ns()
    if not username or not password:
        _log_router_call("ubus_login", started_ns, "invalid_input", False)
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
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        _log_router_call(
            "ubus_login",
            started_ns,
            "request_failed",
            False,
            error_type=type(error).__name__,
            http_status=error.code if isinstance(error, HTTPError) else None,
        )
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
        _log_router_call("ubus_login", started_ns, "authenticated", True)
        return RouterLoginResult(
            True,
            session_id=data["ubus_rpc_session"],
            expires=int(data.get("expires", 0)),
        )
    _log_router_call(
        "ubus_login",
        started_ns,
        "rejected",
        False,
        rpc_code=rpc_result[0] if rpc_result else None,
    )
    return RouterLoginResult(False, error="The router rejected those credentials.")


def call(
    session_id, object_name, method_name, arguments=None, allow_anonymous=False
):
    """Call a fixed OpenWrt ubus method using the authenticated router session."""
    started_ns = time.perf_counter_ns()
    operation = f"ubus_{object_name}_{method_name}"
    if not session_id:
        if allow_anonymous:
            session_id = ANONYMOUS_UBUS_SESSION
        else:
            _log_router_call(operation, started_ns, "missing_session", False)
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
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        _log_router_call(
            operation,
            started_ns,
            "request_failed",
            False,
            error_type=type(error).__name__,
            http_status=error.code if isinstance(error, HTTPError) else None,
        )
        return RouterCallResult(False, "The router did not confirm the command.")

    rpc_result = result.get("result", [])
    if rpc_result and rpc_result[0] == 0:
        _log_router_call(operation, started_ns, "accepted", True, rpc_code=0)
        return RouterCallResult(True)
    if rpc_result and rpc_result[0] in {6, 7}:
        _log_router_call(
            operation, started_ns, "session_expired", False, rpc_code=rpc_result[0]
        )
        return RouterCallResult(False, "Router session expired; sign out and sign in again.")
    _log_router_call(
        operation,
        started_ns,
        "rejected",
        False,
        rpc_code=rpc_result[0] if rpc_result else None,
    )
    return RouterCallResult(False, "OpenWrt rejected the command.")


def reboot(session_id, allow_anonymous=False):
    return call(
        session_id,
        "system",
        "reboot",
        allow_anonymous=allow_anonymous,
    )
