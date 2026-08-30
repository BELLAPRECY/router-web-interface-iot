"""Request-triggered structured performance events."""

import contextvars
import json
import logging
import os
from datetime import datetime, timezone

import psutil


_request_id = contextvars.ContextVar("observability_request_id", default="")
_process = psutil.Process()


class JsonEventFormatter(logging.Formatter):
    """Serialize the event dictionary attached to a log record as JSONL."""

    def format(self, record):
        event = dict(getattr(record, "event_data", {}))
        event.setdefault(
            "timestamp", datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        )
        if record.exc_info:
            event.setdefault("exception", record.exc_info[0].__name__)
        return json.dumps(event, separators=(",", ":"), sort_keys=True)


def set_request_id(value):
    return _request_id.set(value)


def reset_request_id(token):
    _request_id.reset(token)


def current_request_id():
    return _request_id.get()


def process_snapshot():
    """Return a small, safe process resource snapshot."""
    try:
        memory = _process.memory_info()
        return {
            "rss_mb": round(memory.rss / (1024 * 1024), 3),
            "thread_count": _process.num_threads(),
        }
    except (psutil.Error, OSError):
        return {}


def log_event(event, **fields):
    """Write one structured event when observability is enabled."""
    from django.conf import settings

    if not settings.OBSERVABILITY_ENABLED:
        return
    payload = {
        "event": event,
        "run_id": settings.LAB_RUN_ID,
        "condition": settings.LAB_CONDITION,
        "pid": os.getpid(),
    }
    request_id = current_request_id()
    if request_id:
        payload["request_id"] = request_id
    payload.update({key: value for key, value in fields.items() if value is not None})
    logging.getLogger("router.performance").info("", extra={"event_data": payload})
