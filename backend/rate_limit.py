"""
Simple in-memory rate limiter for FastAPI endpoints.

Uses a sliding-window counter per client key.
When CCI_TRUST_PROXY=true the first X-Forwarded-For hop is trusted
(use only behind a reverse proxy you control). When false (the
default) only the raw socket peer is used, preventing clients from
spoofing their identity by setting the XFF header themselves.
"""
import os
import time
import threading
from collections import defaultdict


_lock = threading.Lock()
_window: float = float(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
_store: dict[str, list[float]] = defaultdict(list)


def _key(request) -> str:
    """Best-effort client identifier.

    When the deployment is behind a trusted reverse proxy (env
    CCI_TRUST_PROXY=true), the first hop in X-Forwarded-For is used.
    Otherwise the raw socket peer is used, so a client cannot bypass
    per-IP limits by sending a forged XFF header.
    """
    trust_proxy = os.getenv("CCI_TRUST_PROXY", "false").lower() in (
        "1", "true", "yes", "on",
    )
    if trust_proxy:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check(limit: int, request) -> tuple[bool, dict]:
    """Return (allowed, info).

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