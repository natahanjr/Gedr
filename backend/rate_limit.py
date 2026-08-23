"""
Simple in-memory rate limiter for FastAPI endpoints.

Uses a sliding-window counter per client key (IP or user).
No external dependencies.
"""
import time
import threading
from collections import defaultdict

_lock = threading.Lock()
_window: float = 60.0          # seconds
_store: dict[str, list[float]] = defaultdict(list)


def _key(request) -> str:
    """Best-effort client identifier: X-Forwarded-For, then remote host."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check(limit: int, request) -> tuple[bool, dict]:
    """
    Return (allowed, info).

    ``limit`` is max requests per ``_window`` seconds.
    """
    now = time.monotonic()
    key = f"{limit}:{_key(request)}"
    with _lock:
        _store[key] = [t for t in _store[key] if now - t < _window]
        if len(_store[key]) >= limit:
            oldest = _store[key][0]
            retry_after = max(1, _window - (now - oldest))
            return False, {"retry_after": round(retry_after, 1)}
        _store[key].append(now)
        return True, {"remaining": limit - len(_store[key])}
