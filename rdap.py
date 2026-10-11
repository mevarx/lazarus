"""Lazarus RDAP client -- domain registration/expiration lookups.

Pure stdlib (Python 3.11). Never raises: every failure mode is folded into the
returned ``error`` field so a scan run survives a dead WHOIS server.

Contract: see INTERFACES.md.
"""

from __future__ import annotations

import json
import ipaddress
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

USER_AGENT = "lazarus-research/1.0 (contact: lazarus-hackathon@example.com)"

#: Event actions RFC 9083 servers use, mapped onto our output keys.
EVENT_KEYS = {
    "registration": "created",
    "expiration": "expires",
    "reregistration": "created",  # a re-registration is the newer "created"
}

STAGGER_SECONDS = 0.1
RETRY_STATUSES = frozenset({500, 502, 503, 504, 408, 429})
MAX_TIMEOUT = 15
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
CACHE_TTL_SECONDS = 60 * 60

Transport = Callable[..., bytes]

_transport: Transport | None = None
_clock: Callable[[], float] = time.monotonic
_wall_clock: Callable[[], float] = time.time
_sleep: Callable[[float], None] | None = None
_deadline: float | None = None

# TLD -> base URL, filled on first resolve (bootstrap fetched once per process).
_tld_servers: dict[str, str] | None = None
_tld_alternates: dict[str, list[str]] = {}
_tld_lock = threading.Lock()

_host_lock = threading.Lock()
_host_last_request_at: dict[str, float] = {}
_cache_lock = threading.Lock()
_memory_cache: dict[tuple[str, str], tuple[float, dict]] = {}


class HttpError(Exception):
    """Transport failure carrying an HTTP status (``code=None`` => network)."""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


def set_transport(fn: Transport | None) -> None:
    """Install a fake transport (tests). ``fn(url, timeout=20, headers=None)``."""
    global _transport
    _transport = fn


def set_clock(clock: Callable[[], float] | None = None,
              sleep_fn: Callable[[float], None] | None = None) -> None:
    """Inject time functions for rate-limit and cache tests."""
    global _clock, _wall_clock, _sleep
    _clock = clock or time.monotonic
    _wall_clock = clock or time.time
    _sleep = sleep_fn


def set_deadline(deadline: float | None) -> None:
    """Set an absolute monotonic deadline for all HTTP requests in a run."""
    global _deadline
    _deadline = deadline


def reset_state() -> None:
    """Drop the bootstrap + stagger state (tests)."""
    global _tld_servers, _deadline
    with _tld_lock:
        _tld_servers = None
        _tld_alternates.clear()
    with _host_lock:
        _host_last_request_at.clear()
    with _cache_lock:
        _memory_cache.clear()
    _deadline = None
    set_clock()


def normalize_domain(value: object) -> str | None:
    """Return a safe IDNA hostname, or None for anything unsuitable for RDAP."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or any(ch.isspace() for ch in raw) or any(ch in raw for ch in "/\\:@?#"):
        return None
    raw = raw.rstrip(".").lower()
    try:
        domain = raw.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if len(domain) > 253 or "." not in domain:
        return None
    try:
        ipaddress.ip_address(domain.strip("[]"))
        return None
    except ValueError:
        pass
    labels = domain.split(".")
    if any(len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
           for label in labels):
        return None
    return domain


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def _rate_limit(url: str) -> None:
    host = urllib.parse.urlsplit(url).hostname or ""
    with _host_lock:
        now = _clock()
        wait = STAGGER_SECONDS - (now - _host_last_request_at.get(host, 0.0))
        if wait > 0:
            (_sleep or time.sleep)(wait)
        _host_last_request_at[host] = _clock()


def _request(url: str, timeout: int = 20, headers: dict | None = None) -> bytes:
    timeout = max(1, min(int(timeout), MAX_TIMEOUT))
    if _deadline is not None:
        remaining = _deadline - _clock()
        if remaining <= 0:
            raise HttpError("harvest time budget exhausted")
        timeout = max(1, min(timeout, int(remaining)))
    _rate_limit(url)
    merged = dict(headers or {})
    merged.setdefault("User-Agent", USER_AGENT)
    if _transport is not None:
        body = _transport(url, timeout=timeout, headers=merged)
        if len(body) > MAX_RESPONSE_BYTES:
            raise HttpError("RDAP response exceeded size limit")
        return body
    req = urllib.request.Request(url, headers=merged)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            try:
                body = resp.read(MAX_RESPONSE_BYTES + 1)
            except TypeError:
                body = resp.read()
            if len(body) > MAX_RESPONSE_BYTES:
                raise HttpError("RDAP response exceeded size limit")
            return body
    except urllib.error.HTTPError as exc:
        raise HttpError(
            f"HTTP {exc.code} for {url}",
            code=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise HttpError(f"network error for {url}: {exc.reason}", code=None) from exc
    except (TimeoutError, OSError) as exc:
        raise HttpError(f"network error for {url}: {exc}", code=None) from exc


def _get_json(url: str, timeout: int = 20) -> Any:
    return json.loads(_request(url, timeout=timeout).decode("utf-8"))


def _get_json_retrying(url: str, timeout: int = 20) -> Any:
    """GET json, retrying once on 5xx/timeout/network flake."""
    last: Exception = HttpError("request failed")
    for attempt in (1, 2):
        try:
            return _get_json(url, timeout=timeout)
        except HttpError as exc:
            last = exc
            if exc.code is not None and exc.code not in RETRY_STATUSES:
                raise
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            # Timeouts / refused connections are worth one retry.
            last = HttpError(f"network error for {url}: {exc}", code=None)
        except Exception as exc:  # malformed json etc. -- retrying won't help
            raise
        if attempt == 1:
            (_sleep or time.sleep)(STAGGER_SECONDS)
    raise last


# --------------------------------------------------------------------------
# IANA bootstrap
# --------------------------------------------------------------------------
#: TLDs that IANA's bootstrap does not list but that DO have working public RDAP
#: servers (verified live 2026-10-11). The bootstrap covers 592 of ~1500 TLDs;
#: without this map, every .io/.es/.co/.app domain in a scan fails with
#: "no RDAP server for TLD" even though the data is public and queryable.
FALLBACK_SERVERS: dict[str, str] = {
    "io": "https://rdap.identitydigital.services/rdap/",
    "es": "https://rdap.nic.es/",
    "co": "https://rdap.nic.co/",
    "app": "https://rdap.nic.google/",
    "dev": "https://rdap.nic.google/",
    "page": "https://rdap.nic.google/",
    "xyz": "https://rdap.centralnic.com/xyz/",
    "online": "https://rdap.centralnic.com/online/",
    "site": "https://rdap.centralnic.com/site/",
    "tech": "https://rdap.centralnic.com/tech/",
    "store": "https://rdap.centralnic.com/store/",
    "me": "https://rdap.nic.me/",
    "sh": "https://rdap.nic.sh/",
    "gg": "https://rdap.gg/",
    "im": "https://rdap.nic.im/",
    "ac": "https://rdap.nic.ac/",
    "uk": "https://rdap.nominet.uk/uk/",
    "eu": "https://rdap.eu/",
    "nl": "https://rdap.sidn.nl/",
    "be": "https://rdap.dns.be/",
    "fr": "https://rdap.nic.fr/",
    "it": "https://rdap.nic.it/",
    "se": "https://rdap.iis.se/",
    "no": "https://rdap.norid.no/",
    "dk": "https://rdap.dk-hostmaster.dk/",
    "ch": "https://rdap.nic.ch/",
    "at": "https://rdap.nic.at/",
    "pl": "https://rdap.dns.pl/",
    "cz": "https://rdap.nic.cz/",
    "ru": "https://rdap.tcinet.ru/",
    "in": "https://rdap.registry.in/",
    "cn": "https://rdap.cnnic.cn/",
    "jp": "https://rdap.jprs.jp/",
    "au": "https://rdap.auda.org.au/",
    "nz": "https://rdap.irs.net.nz/",
    "br": "https://rdap.registro.br/",
    "mx": "https://rdap.mx/",
    "tv": "https://rdap.verisign.com/tv/",
    "cc": "https://rdap.verisign.com/cc/",
    "ws": "https://rdap.website.ws/",
}


def _bootstrap() -> dict[str, str]:
    """TLD -> RDAP base URL, fetched once and memoized."""
    global _tld_servers
    if _tld_servers is not None:
        return _tld_servers
    with _tld_lock:
        if _tld_servers is not None:
            return _tld_servers
        data = _get_json(BOOTSTRAP_URL)
        mapping: dict[str, str] = {}
        alternates: dict[str, list[str]] = {}
        for entry in (data or {}).get("services") or []:
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            tlds, urls = entry[0], entry[1]
            if not urls:
                continue
            bases = [u.rstrip("/") + "/" for u in urls
                     if isinstance(u, str) and u.startswith("https://")]
            if not bases:
                continue
            base = bases[0]
            for tld in tlds or []:
                if isinstance(tld, str) and tld:
                    mapping.setdefault(tld.lower(), base)
                    alternates.setdefault(tld.lower(), list(bases[1:]))
        _tld_servers = mapping
        _tld_alternates.update(alternates)
        return _tld_servers


def _base_url_for(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()
    servers = _bootstrap()
    if tld in servers:
        return servers[tld]
    # IANA's bootstrap is incomplete (~592 of ~1500 TLDs). Fall back to the
    # hand-verified map before declaring the TLD unresolvable.
    return FALLBACK_SERVERS.get(tld)


def alternate_rdap_urls(domain: str, primary_url: str | None = None) -> list[str]:
    """Return distinct bootstrap/fallback RDAP bases suitable for a cross-check."""
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()
    _bootstrap()
    candidates = list(_tld_alternates.get(tld, []))
    fallback = FALLBACK_SERVERS.get(tld)
    if fallback:
        candidates.append(fallback)
    return list(dict.fromkeys(url for url in candidates if url != primary_url))


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def _blank(domain: str) -> dict:
    return {
        "domain": domain,
        "registered": False,
        "created": None,
        "expires": None,
        "status": [],
        "error": None,
        "bootstrap_status": "unknown",
        "related_urls": [],
        "alternate_urls": [],
    }


def _parse_events(events: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for event in events or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").strip().lower()
        key = EVENT_KEYS.get(action)
        if key and event.get("eventDate"):
            out[key] = str(event["eventDate"])
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def resolve_domain(domain: str) -> dict:
    """Look up one domain. Never raises -- errors land in ``result["error"]``."""
    result = _blank("")
    if not isinstance(domain, str) or not domain.strip():
        result["error"] = "empty domain"
        return result
    normalized = normalize_domain(domain)
    if normalized is None:
        result["error"] = "invalid domain"
        return result
    domain = normalized
    result["domain"] = domain

    # --- route through the IANA bootstrap ---
    try:
        servers = _bootstrap()
        tld = domain.rsplit(".", 1)[-1]
        result["bootstrap_status"] = (
            "present" if tld in servers else
            "fallback" if tld in FALLBACK_SERVERS else "missing"
        )
        base = _base_url_for(domain)
    except Exception as exc:
        result["error"] = f"bootstrap failed: {exc}"
        return result
    if not base:
        result["error"] = (
            f"no public RDAP server for TLD '{domain.rsplit('.', 1)[-1]}' "
            "(not in IANA bootstrap or fallback map)"
        )
        return result

    url = f"{base}domain/{urllib.parse.quote(domain)}"
    result["primary_url"] = base
    result["alternate_urls"] = alternate_rdap_urls(domain, base)
    try:
        payload = _get_json_retrying(url)
    except HttpError as exc:
        if exc.code == 404:
            result["registered"] = False
            return result
        result["error"] = str(exc)
        return result
    except Exception as exc:
        result["error"] = f"lookup failed: {exc}"
        return result

    if not isinstance(payload, dict):
        result["error"] = f"unexpected RDAP payload for {domain}"
        return result

    result["registered"] = True
    result.update(_parse_events(payload.get("events") or []))
    status = payload.get("status")
    result["status"] = [str(s) for s in status] if isinstance(status, list) else []
    related = []
    for link in payload.get("links") or []:
        if (isinstance(link, dict) and link.get("rel") == "related"
                and isinstance(link.get("href"), str)
                and link["href"].startswith("https://")):
            related.append(link["href"])
    result["related_urls"] = list(dict.fromkeys(related))
    return result


def lookup_domain_at(domain: str, base_url: str) -> dict:
    """Probe a second RDAP base, returning only registration and date fields."""
    normalized = normalize_domain(domain)
    if normalized is None or not isinstance(base_url, str) or not base_url.startswith("https://"):
        return {"registered": None, "created": None, "error": "invalid lookup target"}
    url = (base_url if "/domain/" in urllib.parse.urlsplit(base_url).path
           else base_url.rstrip("/") + "/domain/" + urllib.parse.quote(normalized, safe=""))
    try:
        payload = _get_json_retrying(url)
    except HttpError as exc:
        if exc.code == 404:
            return {"registered": False, "created": None, "error": None}
        return {"registered": None, "created": None, "error": str(exc)}
    except Exception as exc:
        return {"registered": None, "created": None, "error": str(exc)}
    if not isinstance(payload, dict):
        return {"registered": None, "created": None, "error": "unexpected RDAP payload"}
    return {"registered": True, "created": _parse_events(payload.get("events") or []).get("created"),
            "error": None}


def load_cache(cache_path: str) -> dict[str, dict]:
    """Read the JSON cache; a missing/corrupt file yields an empty cache."""
    try:
        with open(cache_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_cache(cache_path: str, cache: dict[str, dict]) -> None:
    """Atomically rewrite the cache file (best effort)."""
    try:
        parent = os.path.dirname(os.path.abspath(cache_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = f"{cache_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=1, sort_keys=True)
        os.replace(tmp, cache_path)
    except OSError:
        pass


def resolve_domains(
    domains: list[str], cache_path: str, concurrency: int = 8,
    force: bool = False,
) -> list[dict]:
    """Resolve many domains concurrently, caching every deterministic result.

    Cached domains (memory TTL cache + disk cache) are never re-fetched
    *unless* ``force`` is True, which re-queries RDAP for every requested
    domain — used by a "force refresh" scan (``/api/run?refresh=1``) so
    re-registration / expiry dates actually update. Transient failures
    (``error`` set) are not persisted, so the next run retries them.
    """
    wanted: list[str] = []
    seen: set[str] = set()
    for raw in domains or []:
        domain = normalize_domain(raw)
        if domain and domain not in seen:
            seen.add(domain)
            wanted.append(domain)
    if not wanted:
        return []

    path_key = os.path.abspath(cache_path)
    disk_cache = load_cache(cache_path)
    now = _clock()
    wall_now = _wall_clock()
    cache: dict[str, dict] = {}
    cached_results: dict[str, dict] = {}
    if not force:
        for domain in wanted:
            key = (path_key, domain)
            with _cache_lock:
                memory = _memory_cache.get(key)
            if memory and now - memory[0] < CACHE_TTL_SECONDS:
                cached_results[domain] = dict(memory[1])
                cache[domain] = dict(memory[1], _cached_at=wall_now)
                continue
            stored = disk_cache.get(domain)
            cached_at = stored.get("_cached_at") if isinstance(stored, dict) else None
            if isinstance(cached_at, (int, float)) and 0 <= wall_now - cached_at < CACHE_TTL_SECONDS:
                clean = dict(stored)
                clean.pop("_cached_at", None)
                cached_results[domain] = clean
                cache[domain] = dict(clean, _cached_at=cached_at)
                with _cache_lock:
                    _memory_cache[key] = (now, clean)
    pending = [d for d in wanted if d not in cached_results]

    lock = threading.Lock()

    def work(domain: str) -> dict:
        out = resolve_domain(domain)
        # Transient errors are retried on the next run, not cached.
        if out.get("error") is None:
            with lock:
                cache[domain] = dict(out, _cached_at=_wall_clock())
                cached_results[domain] = out
                with _cache_lock:
                    _memory_cache[(path_key, domain)] = (_clock(), out)
                save_cache(cache_path, cache)
        return out

    if pending:
        workers = max(1, min(int(concurrency or 1), len(pending)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fresh = list(pool.map(work, pending))
        save_cache(cache_path, cache)
    else:
        fresh = []

    fresh_by_domain = {r["domain"]: r for r in fresh}
    results = []
    for domain in wanted:
        if domain in fresh_by_domain:
            results.append(fresh_by_domain[domain])
        else:
            results.append(dict(cached_results[domain]))
    return results


__all__ = [
    "BOOTSTRAP_URL",
    "EVENT_KEYS",
    "RETRY_STATUSES",
    "STAGGER_SECONDS",
    "USER_AGENT",
    "HttpError",
    "MAX_RESPONSE_BYTES",
    "MAX_TIMEOUT",
    "alternate_rdap_urls",
    "load_cache",
    "lookup_domain_at",
    "normalize_domain",
    "reset_state",
    "resolve_domain",
    "resolve_domains",
    "save_cache",
    "set_transport",
    "set_clock",
    "set_deadline",
]
