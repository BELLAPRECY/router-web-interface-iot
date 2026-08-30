import hmac
import time
import uuid
from urllib.parse import urlsplit

from django.conf import settings
from django.http import JsonResponse

from .security import TOKEN_KEY, TOKEN_SEEN_KEY
from .observability import (
    log_event,
    process_snapshot,
    reset_request_id,
    set_request_id,
)


class PerformanceLoggingMiddleware:
    """Record one correlated performance event for every HTTP request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not settings.OBSERVABILITY_ENABLED:
            return self.get_response(request)

        request_id = uuid.uuid4().hex[:16]
        context_token = set_request_id(request_id)
        rss_start = process_snapshot().get("rss_mb")
        wall_start = time.perf_counter_ns()
        cpu_start = time.thread_time_ns()
        response = None
        try:
            response = self.get_response(request)
            return response
        finally:
            duration_ms = (time.perf_counter_ns() - wall_start) / 1_000_000
            cpu_ms = (time.thread_time_ns() - cpu_start) / 1_000_000
            snapshot = process_snapshot()
            rss_end = snapshot.get("rss_mb")
            rss_delta = (
                round(rss_end - rss_start, 3)
                if rss_start is not None and rss_end is not None
                else None
            )
            status = response.status_code if response is not None else 500
            outcome = getattr(request, "_observability_outcome", None)
            if not outcome:
                if status >= 500:
                    outcome = "server_error"
                elif status >= 400:
                    outcome = "client_error"
                else:
                    outcome = "allowed"

            if response is not None:
                response["X-Request-ID"] = request_id
                server_timing = f"app;dur={duration_ms:.3f}"
                if response.get("Server-Timing"):
                    server_timing = f'{response["Server-Timing"]}, {server_timing}'
                response["Server-Timing"] = server_timing

            try:
                log_event(
                    "http_request",
                    method=request.method,
                    path=request.path,
                    view_name=(
                        request.resolver_match.view_name
                        if getattr(request, "resolver_match", None)
                        else None
                    ),
                    status=status,
                    outcome=outcome,
                    duration_ms=round(duration_ms, 3),
                    cpu_ms=round(cpu_ms, 3),
                    security_duration_ms=getattr(
                        request, "_security_duration_ms", None
                    ),
                    rss_start_mb=rss_start,
                    rss_end_mb=rss_end,
                    rss_delta_mb=rss_delta,
                    thread_count=snapshot.get("thread_count"),
                )
            finally:
                reset_request_id(context_token)


class FullStackCSRFMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        security_start = time.perf_counter_ns()
        if settings.LAB_CONDITION == "C1" and request.method not in {
            "GET", "HEAD", "OPTIONS", "TRACE"
        }:
            error = self._origin_error(request)
            if error:
                request._observability_outcome = (
                    "blocked_missing_origin"
                    if error == "Missing Origin and Referer headers"
                    else "blocked_origin"
                )
                request._security_duration_ms = round(
                    (time.perf_counter_ns() - security_start) / 1_000_000, 3
                )
                return JsonResponse({"error": error}, status=403)
            supplied = (
                request.headers.get("X-CSRF-Token")
                or request.POST.get("csrf_token", "")
            )
            expected = request.session.get(TOKEN_KEY, "")
            last_seen = request.session.get(TOKEN_SEEN_KEY, 0)
            expired = time.time() - last_seen > settings.LAB_TOKEN_IDLE_SECONDS
            if (
                expired
                or not supplied
                or not expected
                or not hmac.compare_digest(supplied, expected)
            ):
                request._observability_outcome = "blocked_csrf"
                request._security_duration_ms = round(
                    (time.perf_counter_ns() - security_start) / 1_000_000, 3
                )
                return JsonResponse(
                    {"error": "Missing or invalid CSRF token"}, status=403
                )
        request._security_duration_ms = round(
            (time.perf_counter_ns() - security_start) / 1_000_000, 3
        )
        return self.get_response(request)

    @staticmethod
    def _origin_error(request):
        origin = request.headers.get("Origin")
        if origin:
            candidate = origin.rstrip("/")
        else:
            referer = request.headers.get("Referer")
            if not referer:
                return "Missing Origin and Referer headers"
            parsed = urlsplit(referer)
            candidate = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if candidate not in settings.LAB_ALLOWED_ORIGINS:
            return "Origin is not allowed"
        return None
