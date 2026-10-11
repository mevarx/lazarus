"""guard.py — small, stdlib-only request guards for the Lazarus web app.

Input validation, per-client rate limiting, secret scrubbing and maintainer
redaction live here so they can be unit-tested without starting a server.
"""

from __future__ import annotations

import os
import re
import threading
import time

__all__ = [
    "RateLimiter",
    "valid_domain",
    "scrub_secrets",
    "redact_maintainer_text",
]

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def valid_domain(value) -> str | None:
    """Return the normalised ASCII hostname, or None if it is not a plausible
    registrable domain. Rejects URLs, paths, ports, spaces, IP literals and
    single-label names so user input is never turned into a request or a
    lookup key unchecked."""
    if not isinstance(value, str):
        return None
    raw = value.strip().rstrip(".").lower()
    if not raw or len(raw) > 253 or any(c in raw for c in " /\\:@?#[]%\x00\r\n\t"):
        return None
    try:
        ascii_name = raw.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_name) > 253 or _IPV4.match(ascii_name):
        return None
    labels = ascii_name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lab) for lab in labels):
        return None
    if labels[-1].isdigit():
        return None
    return ascii_name


class RateLimiter:
    """Thread-safe token bucket per (client, bucket). ``allow`` returns
    ``(ok, retry_after_seconds)``. The clock is injectable for tests."""

    def __init__(self, clock=time.monotonic, max_clients: int = 2048):
        self._clock = clock
        self._max_clients = max_clients
        self._lock = threading.Lock()
        self._state: dict[tuple[str, str], tuple[float, float]] = {}

    def allow(self, client: str, bucket: str, capacity: int, per_minute: float) -> tuple[bool, int]:
        rate = per_minute / 60.0
        now = self._clock()
        key = (client, bucket)
        with self._lock:
            tokens, last = self._state.get(key, (float(capacity), now))
            tokens = min(float(capacity), tokens + (now - last) * rate)
            if tokens >= 1.0:
                self._state[key] = (tokens - 1.0, now)
                self._prune(now)
                return True, 0
            self._state[key] = (tokens, now)
            wait = (1.0 - tokens) / rate if rate > 0 else 60.0
            return False, max(1, int(wait + 0.999))

    def _prune(self, now: float) -> None:
        if len(self._state) <= self._max_clients:
            return
        for k in sorted(self._state, key=lambda k: self._state[k][1])[: len(self._state) // 4]:
            del self._state[k]


_KEY_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"(?i)(x-goog-api-key|api[_-]?key|key)=([^&\s\"']+)"),
    re.compile(r"(?i)(authorization|x-goog-api-key)\s*[:=]\s*\S+"),
)


def scrub_secrets(text) -> str:
    """Remove API keys from a string destined for logs or error responses."""
    out = str(text)
    for env in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        secret = (os.environ.get(env) or "").strip()
        if len(secret) >= 8:
            out = out.replace(secret, "[redacted-key]")
    out = _KEY_PATTERNS[0].sub("[redacted-key]", out)
    out = _KEY_PATTERNS[1].sub(lambda m: f"{m.group(1)}=[redacted-key]", out)
    out = _KEY_PATTERNS[2].sub(lambda m: m.group(0).split(m.group(1))[0] + m.group(1) + ": [redacted]", out)
    return out


_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def redact_maintainer_text(text, handles=()) -> str:
    """Mask email addresses entirely (the domain is public registry data and is
    kept) and replace any known maintainer handle with a neutral phrase."""
    out = _EMAIL.sub(lambda m: "[redacted]@" + m.group(1), text or "")
    for h in sorted({str(h) for h in handles if h}, key=len, reverse=True):
        local = h.split("@", 1)[0]
        for needle in {h, local}:
            if len(needle) >= 3:
                out = re.sub(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", "the maintainer", out, flags=re.I)
    return out
