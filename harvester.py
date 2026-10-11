"""Lazarus harvester -- discover npm / PyPI maintainer email domains.

Pure stdlib (Python 3.11). Every network call funnels through ``_transport`` so
tests can inject a fake transport with zero network access.

Contract: see INTERFACES.md.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

# --------------------------------------------------------------------------
# Endpoints (verified live 2026-10-10)
# --------------------------------------------------------------------------
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week/"
PYPI_TOP_URL = (
    "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"
)
PYPI_PACKUMENT_URL = "https://pypi.org/pypi/{package}/json"

USER_AGENT = "lazarus-research/1.0 (contact: lazarus-hackathon@example.com)"

# 51 names per bulk call is the verified ceiling; stay just under it.
NPM_BULK_SIZE = 50
# popularity:1 result set is finite; this is a runaway guard, not a limit.
NPM_MAX_PAGES = 40
PYPI_FETCH_WORKERS = 8
MAX_TIMEOUT = 12
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CACHE_TTL_SECONDS = 15 * 60
HOST_INTERVAL_SECONDS = 0.1

# --------------------------------------------------------------------------
# Free-mail providers -- these domains can never "expire", so they carry no
# supply-chain signal and are excluded by extract_domains().
# --------------------------------------------------------------------------
FREE_MAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "outlook.com",
        "yahoo.com",
        "proton.me",
        "protonmail.com",
        "icloud.com",
        "hotmail.com",
        "live.com",
        "gmx.de",
        "mail.ru",
        "qq.com",
        "163.com",
        "yandex.ru",
    }
)

# Free-text fields look like "Alice Example <alice@example.com>, Bob
# Example <bob@example.com>" -- or sometimes a bare address.
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# --------------------------------------------------------------------------
# Transport layer
# --------------------------------------------------------------------------
Transport = Callable[..., bytes]

_transport: Transport | None = None
_clock: Callable[[], float] = time.monotonic
_sleep: Callable[[float], None] = time.sleep
_deadline: float | None = None
_rate_lock = threading.Lock()
_host_last_request: dict[str, float] = {}
_cache_lock = threading.Lock()
_response_cache: dict[str, tuple[float, bytes]] = {}


def set_transport(fn: Transport | None) -> None:
    """Install a fake transport (tests). ``fn(url, timeout=20, headers=None)``."""
    global _transport
    _transport = fn
    with _cache_lock:
        _response_cache.clear()
    with _rate_lock:
        _host_last_request.clear()


def set_clock(clock: Callable[[], float] | None = None,
              sleep_fn: Callable[[float], None] | None = None) -> None:
    """Inject time functions for cache and per-host rate-limit tests."""
    global _clock, _sleep
    _clock = clock or time.monotonic
    _sleep = sleep_fn or time.sleep


def set_deadline(deadline: float | None) -> None:
    """Set an absolute monotonic deadline for all HTTP requests in a run."""
    global _deadline
    _deadline = deadline


def validate_package_name(name: object, ecosystem: str = "npm") -> bool:
    """Accept package path segments only; npm scopes are the sole slash case."""
    if not isinstance(name, str) or not name or len(name) > 214 or name.strip() != name:
        return False
    if ecosystem == "npm":
        if name.startswith("@"):
            parts = name[1:].split("/")
            if len(parts) != 2 or any(not part or part in {".", ".."} for part in parts):
                return False
            return all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]*", part) for part in parts)
        return ("/" not in name and name not in {".", ".."}
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]*", name) is not None)
    if ecosystem == "pypi":
        return ("/" not in name and name not in {".", ".."}
                and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name) is not None)
    return False


def _limit_host(url: str) -> None:
    host = urllib.parse.urlsplit(url).hostname or ""
    with _rate_lock:
        now = _clock()
        delay = HOST_INTERVAL_SECONDS - (now - _host_last_request.get(host, 0.0))
        if delay > 0:
            _sleep(delay)
        _host_last_request[host] = _clock()


def _request(url: str, timeout: int = 20, headers: dict | None = None) -> bytes:
    timeout = max(1, min(int(timeout), MAX_TIMEOUT))
    if _deadline is not None:
        remaining = _deadline - _clock()
        if remaining <= 0:
            raise TimeoutError("harvest time budget exhausted")
        timeout = max(1, min(timeout, int(remaining)))
    with _cache_lock:
        cached = _response_cache.get(url)
    if cached and _clock() - cached[0] < CACHE_TTL_SECONDS:
        return cached[1]
    _limit_host(url)
    if _transport is not None:
        body = _transport(url, timeout=timeout, headers=dict(headers or {}))
    else:
        req = urllib.request.Request(
            url, headers=dict(headers or {}, **{"User-Agent": USER_AGENT})
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("package registry response exceeded size limit")
    with _cache_lock:
        _response_cache[url] = (_clock(), body)
        if len(_response_cache) > 2048:
            oldest = min(_response_cache, key=lambda key: _response_cache[key][0])
            _response_cache.pop(oldest, None)
    return body


def _get_json(url: str, timeout: int = 20) -> Any:
    return json.loads(_request(url, timeout=timeout).decode("utf-8"))


# --------------------------------------------------------------------------
# Email helpers
# --------------------------------------------------------------------------
def extract_emails(text: str | None) -> list[str]:
    """Pull every address out of a free-text blob, lowercased + deduped."""
    if not text:
        return []
    out: list[str] = []
    for match in EMAIL_RE.findall(text):
        addr = match.strip().strip(",;").lower()
        if addr and addr not in out:
            out.append(addr)
    return out


def extract_domains(emails: list[str]) -> list[str]:
    """Domain part of each email, lowercased, deduped, free-mail removed."""
    domains: list[str] = []
    for raw in emails or []:
        if not isinstance(raw, str) or "@" not in raw:
            continue
        local, _, domain = raw.rpartition("@")
        domain = domain.strip().strip(">").lower()
        # Require a non-empty local part and a dot in the domain -- "x@" and
        # "@y" are malformed and would poison an RDAP lookup.
        if not local.strip() or not domain or "." not in domain:
            continue
        if domain in FREE_MAIL_DOMAINS or domain in domains:
            continue
        domains.append(domain)
    return domains


def _parse_int(value: Any) -> int:
    """npm's ``dependents`` field is a *string* -- "20705" -> 20705."""
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    digits = re.sub(r"[^0-9]", "", str(value))
    return int(digits) if digits else 0


# --------------------------------------------------------------------------
# npm
# --------------------------------------------------------------------------
def _npm_search_page(from_: int, size: int = 250) -> list[dict]:
    query = urllib.parse.urlencode(
        {"text": "popularity:1", "size": size, "from": from_}
    )
    data = _get_json(f"{NPM_SEARCH_URL}?{query}")
    return (data or {}).get("objects") or []


def _npm_bulk_downloads(names: list[str]) -> dict[str, int]:
    """Fetch weekly downloads, batching unscoped names 50-per-comma-call.

    The bulk endpoint rejects scoped packages ("@scope/name" -- the slash makes
    it ambiguous in a comma list), so those are fetched one at a time.
    """
    out: dict[str, int] = {}
    if not names:
        return out

    names = [n for n in names if validate_package_name(n, "npm")]
    unscoped = [n for n in names if "/" not in n]
    scoped = [n for n in names if "/" in n]

    for start in range(0, len(unscoped), NPM_BULK_SIZE):
        chunk = unscoped[start : start + NPM_BULK_SIZE]
        try:
            encoded = ",".join(urllib.parse.quote(n, safe="") for n in chunk)
            payload = _get_json(NPM_DOWNLOADS_URL + encoded)
        except Exception:
            # Downloads are a bonus signal; never lose the harvest over them.
            continue
        if not isinstance(payload, dict):
            continue
        # A single-name call answers with the FLAT point response
        # ({"downloads": N, "package": name, ...}); multi-name nests under the
        # package name. Support both so a one-package chunk isn't lost.
        if "downloads" in payload and "package" in payload:
            if isinstance(payload["downloads"], int):
                out[str(payload["package"])] = payload["downloads"]
            continue
        for name, entry in payload.items():
            if isinstance(entry, dict) and isinstance(entry.get("downloads"), int):
                out[name] = entry["downloads"]

    for name in scoped:
        try:
            payload = _get_json(
                NPM_DOWNLOADS_URL + urllib.parse.quote(name, safe="")
            )
        except Exception:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("downloads"), int):
            out[name] = payload["downloads"]

    return out


def _npm_item(obj: dict) -> dict | None:
    pkg = obj.get("package") or {}
    name = pkg.get("name")
    if not validate_package_name(name, "npm"):
        return None
    maintainers = []
    for person in pkg.get("maintainers") or []:
        email = (person.get("email") or "").strip()
        who = person.get("username") or person.get("name") or ""
        if email:
            maintainers.append({"name": who, "email": email.lower()})
    return {
        "package": name,
        "maintainers": maintainers,
        "dependents": _parse_int(obj.get("dependents")),
        "downloads_week": 0,
    }


def harvest_npm(max_packages: int = 500) -> list[dict]:
    """Top npm packages by popularity with maintainer emails + weekly downloads."""
    try:
        limit = max(0, int(max_packages))
    except (TypeError, ValueError):
        return []
    if limit == 0:
        return []

    items: list[dict] = []
    seen: set[str] = set()
    from_ = 0
    for _ in range(NPM_MAX_PAGES):
        if len(items) >= limit:
            break
        try:
            page = _npm_search_page(from_)
        except Exception:
            break
        if not page:
            break
        for obj in page:
            if len(items) >= limit:
                break
            item = _npm_item(obj)
            if item and item["package"] not in seen:
                seen.add(item["package"])
                items.append(item)
        # Short page => end of the result set.
        if len(page) < 250:
            break
        from_ += 250

    if not items:
        return []

    try:
        downloads = _npm_bulk_downloads([i["package"] for i in items])
    except Exception:
        downloads = {}
    for item in items:
        item["downloads_week"] = downloads.get(item["package"], 0)
    return items


# --------------------------------------------------------------------------
# PyPI
# --------------------------------------------------------------------------
def _pypi_item(row: dict) -> dict | None:
    project = row.get("project")
    if not validate_package_name(project, "pypi"):
        return None
    try:
        packument = _get_json(
            PYPI_PACKUMENT_URL.format(package=urllib.parse.quote(project, safe=""))
        )
    except Exception:
        return None
    info = (packument or {}).get("info") or {}

    emails: list[str] = []
    for field in ("maintainer_email", "author_email"):
        for addr in extract_emails(info.get(field)):
            if addr not in emails:
                emails.append(addr)

    downloads = row.get("download_count")
    if not isinstance(downloads, int) or downloads < 0:
        # info["downloads"] is deprecated and returns -1; don't trust it.
        downloads = None

    return {
        "package": project,
        "maintainer_emails": emails,
        "downloads": downloads,
    }


def harvest_pypi(max_packages: int = 200) -> list[dict]:
    """Seed from the top-pypi-packages list, then scrape packument emails."""
    try:
        limit = max(0, int(max_packages))
    except (TypeError, ValueError):
        return []
    if limit == 0:
        return []

    try:
        seed = _get_json(PYPI_TOP_URL)
    except Exception:
        return []
    rows = (seed or {}).get("rows") or []
    rows = [r for r in rows if isinstance(r, dict)
            and validate_package_name(r.get("project"), "pypi")][:limit]
    if not rows:
        return []

    workers = max(1, min(PYPI_FETCH_WORKERS, len(rows)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_pypi_item, rows))
    return [r for r in results if r]


__all__ = [
    "FREE_MAIL_DOMAINS",
    "NPM_BULK_SIZE",
    "NPM_DOWNLOADS_URL",
    "NPM_SEARCH_URL",
    "PYPI_TOP_URL",
    "USER_AGENT",
    "extract_domains",
    "extract_emails",
    "harvest_npm",
    "harvest_pypi",
    "set_transport",
    "set_clock",
    "set_deadline",
    "validate_package_name",
]
