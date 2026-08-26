"""
Simple in-memory rate limiter for FastAPI endpoints.

Uses a sliding-window counter per client key (IP or user).
No external dependencies.
"""
import os
import time
import threading
from collections import defaultdict

_lock = threading.Lock()
_window: float = 60.0          # seconds
_store: dict[str, list[float]] = defaultdict(list)

# Configurable rate limits per endpoint type
RATE_LIMITS = {
    "auth": 10,        # Login attempts per minute
    "scan": 5,         # Scan requests per minute
    "api": 100,        # General API calls per minute
    "report": 20,      # Report generation per minute
}

# Trusted proxy IPs (configure via CCI_TRUSTED_PROXIES env var, comma-separated)
_TRUSTED_PROXIES = set(
    p.strip() for p in os.getenv("CCI_TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if p.strip()
)


def _cleanup_expired():
    """Remove expired entries to prevent memory leak."""
    now = time.monotonic()
    with _lock:
        expired_keys = [k for k, v in _store.items() if not v or now - v[-1] >= _window]
        for k in expired_keys:
            del _store[k]


def _key(request) -> str:
    """Best-effort client identifier: X-Forwarded-For, then remote host."""
    client_ip = request.client.host if request.client else "unknown"
    
    # Only trust X-Forwarded-For if client is a known proxy
    if client_ip in _TRUSTED_PROXIES:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    
    return client_ip


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


# Start background cleanup thread (runs every 5 minutes)
def _cleanup_loop():
    while True:
        time.sleep(300)
        _cleanup_expired()

_cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
_cleanup_thread.start()
