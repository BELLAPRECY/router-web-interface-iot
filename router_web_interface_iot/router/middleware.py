import hmac
from urllib.parse import urlsplit

from django.conf import settings
from django.http import JsonResponse

from .security import TOKEN_KEY


class FullStackCSRFMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.LAB_CONDITION == "C1" and request.method not in {
            "GET", "HEAD", "OPTIONS", "TRACE"
        }:
            error = self._origin_error(request)
            if error:
                return JsonResponse({"error": error}, status=403)
            supplied = (
                request.headers.get("X-CSRF-Token")
                or request.POST.get("csrf_token", "")
            )
            expected = request.session.get(TOKEN_KEY, "")
            if not supplied or not expected or not hmac.compare_digest(supplied, expected):
                return JsonResponse(
                    {"error": "Missing or invalid CSRF token"}, status=403
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
