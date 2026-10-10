"""Lazarus RDAP client -- domain registration/expiration lookups.

Pure stdlib (Python 3.11). Never raises: every failure mode is folded into the
returned ``error`` field so a scan run survives a dead WHOIS server.

Contract: see INTERFACES.md.
"""

from __future__ import annotations

import json
import os
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

Transport = Callable[..., bytes]

_transport: Transport | None = None

# TLD -> base URL, filled on first resolve (bootstrap fetched once per process).
_tld_servers: dict[str, str] | None = None
_tld_lock = threading.Lock()

# Serializes the polite 0.1s stagger across worker threads.
_stagger_lock = threading.Lock()
_last_request_at = 0.0


class HttpError(Exception):
    """Transport failure carrying an HTTP status (``code=None`` => network)."""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


def set_transport(fn: Transport | None) -> None:
    """Install a fake transport (tests). ``fn(url, timeout=20, headers=None)``."""
    global _transport
    _transport = fn


def reset_state() -> None:
    """Drop the bootstrap + stagger state (tests)."""
    global _tld_servers, _last_request_at
    with _tld_lock:
        _tld_servers = None
    with _stagger_lock:
        _last_request_at = 0.0


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def _request(url: str, timeout: int = 20, headers: dict | None = None) -> bytes:
    merged = dict(headers or {})
    merged.setdefault("User-Agent", USER_AGENT)
    if _transport is not None:
        return _transport(url, timeout=timeout, headers=merged)
    req = urllib.request.Request(url, headers=merged)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        raise HttpError(
            f"HTTP {exc.code} for {url}{': ' + detail if detail else ''}",
            code=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise HttpError(f"network error for {url}: {exc.reason}", code=None) from exc
    except (TimeoutError, OSError) as exc:
        raise HttpError(f"network error for {url}: {exc}", code=None) from exc


def _get_json(url: str, timeout: int = 20) -> Any:
    return json.loads(_request(url, timeout=timeout).decode("utf-8"))


def _stagger() -> None:
    """Hold each worker so requests stay ~0.1s apart, globally."""
    global _last_request_at
    with _stagger_lock:
        now = time.monotonic()
        wait = STAGGER_SECONDS - (now - _last_request_at)
        if wait > 0:
            time.sleep(wait)
        _last_request_at = time.monotonic()


def _get_json_retrying(url: str, timeout: int = 20) -> Any:
    """GET json, retrying once on 5xx/timeout/network flake."""
    last: Exception = HttpError("request failed")
    for attempt in (1, 2):
        _stagger()
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
            time.sleep(STAGGER_SECONDS)
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
        for entry in (data or {}).get("services") or []:
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            tlds, urls = entry[0], entry[1]
            if not urls:
                continue
            base = urls[0].rstrip("/") + "/"
            for tld in tlds or []:
                if isinstance(tld, str) and tld:
                    mapping.setdefault(tld.lower(), base)
        _tld_servers = mapping
        return _tld_servers


def _base_url_for(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()
    servers = _bootstrap()
    if tld in servers:
        return servers[tld]
    # IANA's bootstrap is incomplete (~592 of ~1500 TLDs). Fall back to the
    # hand-verified map before declaring the TLD unresolvable.
    return FALLBACK_SERVERS.get(tld)


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
    result = _blank(domain)
    if not domain or not str(domain).strip():
        result["error"] = "empty domain"
        return result
    domain = str(domain).strip().lower().strip(".")
    result["domain"] = domain

    # --- route through the IANA bootstrap ---
    try:
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
    return result


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
    domains: list[str], cache_path: str, concurrency: int = 8
) -> list[dict]:
    """Resolve many domains concurrently, caching every deterministic result.

    Cached domains are never re-fetched. Transient failures (``error`` set) are
    not persisted, so the next run retries them.
    """
    wanted: list[str] = []
    seen: set[str] = set()
    for raw in domains or []:
        if not isinstance(raw, str):
            continue
        domain = raw.strip().lower().strip(".")
        if domain and domain not in seen:
            seen.add(domain)
            wanted.append(domain)
    if not wanted:
        return []

    cache = load_cache(cache_path)
    pending = [d for d in wanted if d not in cache]

    lock = threading.Lock()

    def work(domain: str) -> dict:
        out = resolve_domain(domain)
        # Transient errors are retried on the next run, not cached.
        if out.get("error") is None:
            with lock:
                cache[domain] = out
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
            results.append(dict(cache[domain]))
    return results


__all__ = [
    "BOOTSTRAP_URL",
    "EVENT_KEYS",
    "RETRY_STATUSES",
    "STAGGER_SECONDS",
    "USER_AGENT",
    "HttpError",
    "load_cache",
    "reset_state",
    "resolve_domain",
    "resolve_domains",
    "save_cache",
    "set_transport",
]
