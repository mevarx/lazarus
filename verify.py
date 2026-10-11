"""Independent DNS and alternate-RDAP checks for high-risk findings."""

from __future__ import annotations

import copy
import json
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from typing import Callable

import rdap

DNS_JSON_URL = "https://dns.google/resolve"
DNS_TIMEOUT = 5
DNS_HOST_INTERVAL = 0.15
_dns_lock = threading.Lock()
_dns_last_request = 0.0
_deadline: float | None = None


def set_deadline(deadline: float | None) -> None:
    global _deadline
    _deadline = deadline


def _doh_lookup(domain: str, qtype: str) -> dict:
    """Use Google's DNS JSON endpoint; urllib keeps DNS checks stdlib-only."""
    global _dns_last_request
    timeout = DNS_TIMEOUT
    if _deadline is not None:
        remaining = _deadline - time.monotonic()
        if remaining <= 0:
            return {"status": "ERROR", "answers": [], "error": "time budget exhausted"}
        timeout = max(1, min(timeout, int(remaining)))
    with _dns_lock:
        wait = DNS_HOST_INTERVAL - (time.monotonic() - _dns_last_request)
        if wait > 0:
            time.sleep(wait)
        _dns_last_request = time.monotonic()
    query = urllib.parse.urlencode({"name": domain, "type": qtype})
    req = urllib.request.Request(
        f"{DNS_JSON_URL}?{query}",
        headers={"Accept": "application/dns-json", "User-Agent": rdap.USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            return {"status": "ERROR", "answers": [], "error": "DNS response too large"}
        data = json.loads(raw.decode("utf-8"))
        code = data.get("Status")
        status = {0: "NOERROR", 3: "NXDOMAIN"}.get(code, f"DNS_{code}")
        answers = [r.get("data", "") for r in data.get("Answer", []) if isinstance(r, dict)]
        return {"status": status, "answers": answers}
    except Exception as exc:
        return {"status": "ERROR", "answers": [], "error": type(exc).__name__}


def _date_only(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10]).isoformat()
    except ValueError:
        return None


def _answers(result: dict) -> int:
    if isinstance(result.get("answers"), list):
        return len(result["answers"])
    value = result.get("answer_count", 0)
    return value if isinstance(value, int) and value > 0 else 0


def _second_endpoint(finding: dict, rdap_result: dict) -> str | None:
    primary = rdap_result.get("primary_url")
    primary_host = urllib.parse.urlsplit(primary or "").hostname
    candidates = list(rdap_result.get("related_urls") or [])
    candidates.extend(rdap_result.get("alternate_urls") or [])
    for url in candidates:
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        if urllib.parse.urlsplit(url).hostname != primary_host:
            return url
    return None


def _verify_one(finding: dict, dns_lookup: Callable, second_lookup: Callable) -> dict:
    severity = str(finding.get("severity", "LOW")).upper()
    if severity not in {"CRITICAL", "HIGH"}:
        finding["verification"] = {
            "status": "not_applicable", "reasons": [],
            "checks": {"rdap": "not_checked", "dns": "not_checked", "second_rdap": "unavailable"},
        }
        finding["verified_severity"] = severity
        finding["needs_manual_check"] = False
        return finding

    domain = rdap.normalize_domain(finding.get("domain"))
    raw_rdap = finding.get("rdap")
    raw_rdap = raw_rdap if isinstance(raw_rdap, dict) else {}
    reasons: list[str] = []
    checks: dict = {"rdap": {}, "dns": {}, "second_rdap": "unavailable"}
    registered = raw_rdap.get("registered")
    created = raw_rdap.get("created")
    rdap_error = bool(raw_rdap.get("error"))
    checks["rdap"] = {"registered": registered, "created": created, "error": rdap_error}

    bootstrap_status = raw_rdap.get("bootstrap_status")
    if bootstrap_status in {"missing", "fallback"} or "no public RDAP server" in str(raw_rdap.get("error", "")):
        reasons.append("tld_bootstrap_missing")
    if rdap_error:
        reasons.append("rdap_error")

    dns_results: dict[str, dict] = {}
    if domain:
        for qtype in ("NS", "SOA", "MX"):
            try:
                value = dns_lookup(domain, qtype)
            except Exception:
                value = {"status": "ERROR", "answers": []}
            if not isinstance(value, dict):
                value = {"status": "ERROR", "answers": []}
            dns_results[qtype] = value
            checks["dns"][qtype] = {
                "status": str(value.get("status", "ERROR")),
                "answer_count": _answers(value),
            }
    else:
        dns_results = {q: {"status": "ERROR", "answers": []} for q in ("NS", "SOA", "MX")}
        checks["dns"] = {q: {"status": "ERROR", "answer_count": 0} for q in dns_results}

    required_dns_failed = any(
        dns_results[q].get("status") not in {"NOERROR", "NXDOMAIN"}
        for q in ("NS", "SOA")
    )
    if required_dns_failed:
        reasons.append("dns_lookup_failed")
    ns_soa_present = any(_answers(dns_results[q]) for q in ("NS", "SOA"))
    any_dns_present = ns_soa_present or _answers(dns_results["MX"]) > 0
    both_nxdomain = all(dns_results[q].get("status") == "NXDOMAIN" for q in ("NS", "SOA"))

    if registered is False and any_dns_present:
        reasons.append("rdap_not_found_dns_present")
    if registered is True and not ns_soa_present and both_nxdomain:
        reasons.append("dns_no_delegation")

    endpoint = _second_endpoint(finding, raw_rdap)
    if endpoint and domain:
        try:
            second = second_lookup(domain, endpoint)
        except Exception:
            second = None
        if isinstance(second, dict) and second.get("error") is None and second.get("registered") in {True, False}:
            checks["second_rdap"] = {
                "registered": second.get("registered"), "created": second.get("created")
            }
            if second.get("registered") != registered:
                reasons.append("second_rdap_disagreement")
            elif (second.get("registered") is True and created and second.get("created")
                  and _date_only(created) != _date_only(second.get("created"))):
                reasons.append("second_rdap_disagreement")

    rdap_clean = not rdap_error and registered in {True, False}
    corroborated = ns_soa_present if registered else both_nxdomain
    if rdap_clean and not corroborated:
        reasons.append("no_independent_corroboration")
    if registered is True and any(
        dns_results[q].get("status") == "NXDOMAIN" for q in ("NS", "SOA")
    ) and not ns_soa_present:
        if "dns_no_delegation" not in reasons:
            reasons.append("dns_no_delegation")

    reasons = list(dict.fromkeys(reasons))
    confirmed = rdap_clean and not reasons and corroborated
    status = "confirmed" if confirmed else "needs_manual_check"
    finding["verification"] = {"status": status, "reasons": reasons, "checks": checks}
    finding["verified_severity"] = severity if confirmed else "UNVERIFIED"
    finding["needs_manual_check"] = not confirmed
    return finding


def verify_findings(
    findings: list[dict], *, dns_lookup: Callable | None = None,
    second_rdap_lookup: Callable | None = None, concurrency: int = 4,
) -> list[dict]:
    """Return copied findings with once-per-domain verification metadata."""
    dns_lookup = dns_lookup or _doh_lookup
    second_rdap_lookup = second_rdap_lookup or rdap.lookup_domain_at
    copied = copy.deepcopy(findings or [])
    eligible: dict[str, list[int]] = {}
    for index, finding in enumerate(copied):
        if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"}:
            domain = rdap.normalize_domain(finding.get("domain")) or f"invalid-{index}"
            eligible.setdefault(domain, []).append(index)
    memo: dict[str, dict] = {}
    memo_lock = threading.Lock()

    def work(domain: str, index: int) -> tuple[str, dict]:
        result = _verify_one(copied[index], dns_lookup, second_rdap_lookup)
        return domain, result["verification"]

    jobs = [(domain, indexes[0]) for domain, indexes in eligible.items()]
    if jobs:
        workers = max(1, min(int(concurrency or 1), len(jobs), 4))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for domain, verification in pool.map(lambda pair: work(*pair), jobs):
                with memo_lock:
                    memo[domain] = verification
    for domain, indexes in eligible.items():
        verification = memo[domain]
        for index in indexes:
            finding = copied[index]
            finding["verification"] = copy.deepcopy(verification)
            severity = str(finding.get("severity", "LOW")).upper()
            confirmed = verification["status"] == "confirmed"
            finding["verified_severity"] = severity if confirmed else "UNVERIFIED"
            finding["needs_manual_check"] = not confirmed
    for finding in copied:
        if str(finding.get("severity", "")).upper() not in {"CRITICAL", "HIGH"}:
            _verify_one(finding, dns_lookup, second_rdap_lookup)
    return copied


__all__ = ["set_deadline", "verify_findings"]
