import secrets
import time

from django.conf import settings

TOKEN_KEY = "lab_csrf_token"
TOKEN_SEEN_KEY = "lab_csrf_seen"


def get_csrf_token(request):
    now = int(time.time())
    token = request.session.get(TOKEN_KEY)
    last_seen = request.session.get(TOKEN_SEEN_KEY, 0)
    if not token or now - last_seen > settings.LAB_TOKEN_IDLE_SECONDS:
        token = secrets.token_hex(16)  # 128 bits
        request.session[TOKEN_KEY] = token
    request.session[TOKEN_SEEN_KEY] = now
    return token
