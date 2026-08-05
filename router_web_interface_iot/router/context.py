from django.conf import settings

from .security import get_csrf_token


def lab_context(request):
    return {
        "lab_condition": settings.LAB_CONDITION,
        "lab_csrf_token": (
            get_csrf_token(request) if settings.LAB_CONDITION == "C1" else ""
        ),
        "router_logged_in": bool(request.session.get("router_authenticated")),
    }
