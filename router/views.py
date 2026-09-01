from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_POST

from .openwrt import authenticate as authenticate_openwrt
from .openwrt import connection_status
from .openwrt import reboot as reboot_openwrt


DEFAULT_ROUTER_STATE = {
    "dns": "1.1.1.1",
    "password_changes": 0,
    "reboot_count": 0,
}
C0_STATE_CACHE_KEY = "router:c0:shared-state"

def router_login_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if (
            settings.LAB_REQUIRE_AUTH
            and not request.session.get("router_authenticated")
        ):
            request._observability_outcome = "unauthenticated"
            return JsonResponse({"error": "Authentication required"}, status=401)
        return view(request, *args, **kwargs)
    return wrapped


def state(request):
    if not settings.LAB_REQUIRE_AUTH:
        return cache.get(C0_STATE_CACHE_KEY, DEFAULT_ROUTER_STATE.copy())
    return request.session.setdefault("router_state", DEFAULT_ROUTER_STATE.copy())


def save_state(request, current):
    if not settings.LAB_REQUIRE_AUTH:
        cache.set(C0_STATE_CACHE_KEY, current, timeout=None)
    else:
        request.session["router_state"] = current


@require_GET
def dashboard(request):
    return render(
        request,
        "router/dashboard.html",
        {"state": state(request), "router_connection": connection_status()},
    )


@require_POST
def login_view(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    if settings.ROUTER_AUTH_BACKEND == "ubus":
        result = authenticate_openwrt(username, password)
    else:
        valid = (
            username == settings.LAB_ADMIN_USER
            and password == settings.LAB_ADMIN_PASSWORD
        )
        from .openwrt import RouterLoginResult
        result = RouterLoginResult(valid, error="Invalid lab username or password.")

    if not result.authenticated:
        return render(
            request, "router/dashboard.html",
            {
                "state": state(request),
                "login_error": result.error,
                "router_connection": connection_status(),
            },
            status=401,
        )
    request.session.cycle_key()
    request.session["router_authenticated"] = True
    request.session["router_username"] = username
    request.session["router_ubus_session"] = result.session_id
    request.session["router_ubus_expires"] = result.expires
    return redirect("dashboard")


@require_POST
def logout_view(request):
    request.session.flush()
    return redirect("dashboard")


@require_POST
@router_login_required
def dns_view(request):
    dns = request.POST.get("dns", "").strip()
    if not dns:
        return JsonResponse({"error": "DNS value is required"}, status=400)
    current = state(request)
    current["dns"] = dns[:64]
    save_state(request, current)
    return JsonResponse({"ok": True, "dns": current["dns"]})


@require_POST
@router_login_required
def password_view(request):
    if len(request.POST.get("password", "")) < 8:
        return JsonResponse({"error": "Password must be at least 8 characters"}, status=400)
    current = state(request)
    current["password_changes"] += 1
    save_state(request, current)
    return JsonResponse({"ok": True})


@require_POST
@router_login_required
def reboot_view(request):
    session_id = request.session.get("router_ubus_session", "")
    result = reboot_openwrt(
        session_id, allow_anonymous=not settings.LAB_REQUIRE_AUTH
    )
    if not result.successful:
        return JsonResponse({"error": result.error}, status=502)
    current = state(request)
    current["reboot_count"] += 1
    save_state(request, current)
    return JsonResponse({
        "ok": True,
        "message": "OpenWrt accepted the reboot command.",
        "reboot_count": current["reboot_count"],
    })


@require_GET
def status_view(request):
    connection = connection_status()
    return JsonResponse({
        "condition": settings.LAB_CONDITION,
        "authentication_required": settings.LAB_REQUIRE_AUTH,
        "authenticated": bool(request.session.get("router_authenticated")),
        "router": {
            "host": connection.host,
            "luci_url": connection.luci_url,
            "reachable": connection.reachable,
            "detail": connection.detail,
        },
        "state": state(request),
    })


@require_GET
def attack_lab_view(request):
    """Serve the controlled browser attack launcher on an attacker origin."""
    return render(request, "router/attack_lab.html")
