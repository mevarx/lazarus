"""Scan npm maintainer email domains without exposing maintainer identities."""

from __future__ import annotations

from datetime import datetime
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import harvester
import lockfile
import rdap
import scorer

_NPM_PACKUMENT = "https://registry.npmjs.org/{name}"
_DEFAULT_CACHE = "data/rdap_cache.json"
MAX_CONCURRENCY = 16
last_lookup_failures = 0


def _safe_date(value) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    parsed = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        datetime.fromisoformat(parsed)
    except ValueError:
        return None
    return text


def _public_rdap_record(record: dict, domain: str) -> dict:
    status = record.get("status")
    safe_status = []
    if isinstance(status, list):
        safe_status = [value for value in status if
                       isinstance(value, str) and len(value) <= 64
                       and all(char.isalnum() or char in "-_" for char in value)]
    return {
        "domain": domain,
        "registered": record.get("registered")
        if isinstance(record.get("registered"), bool) else None,
        "created": _safe_date(record.get("created")),
        "expires": _safe_date(record.get("expires")),
        "status": safe_status,
        "error": "RDAP lookup failed" if record.get("error") else None,
    }


def mask_email(email: str) -> str:
    """Mask the complete mailbox while retaining the domain for grouping."""
    value = str(email or "")
    at = value.find("@")
    if at <= 0:
        return value
    return "***@" + value[at + 1:]


def _packument_maintainers(name: str) -> dict:
    item = {"package": name, "maintainers": [], "dependents": 0,
            "downloads_week": 0, "error": None}
    if not lockfile.is_valid_package_name(name):
        item["error"] = "invalid package name"
        return item
    try:
        data = harvester._get_json(
            _NPM_PACKUMENT.format(name=urllib.parse.quote(name, safe=""))
        )
    except Exception:  # noqa: BLE001
        item["error"] = "package lookup failed"
        return item
    if not isinstance(data, dict):
        item["error"] = "package lookup returned an unexpected response"
        return item
    for person in data.get("maintainers") or []:
        if not isinstance(person, dict):
            continue
        raw_email = person.get("email")
        email = raw_email.strip().lower() if isinstance(raw_email, str) else ""
        if email:
            item["maintainers"].append(email)
    return item


def scan_dependencies(package_names: list[str], *, concurrency: int = 8) -> list[dict]:
    """Resolve and score dependency-domain findings, reporting lookup failures."""
    global last_lookup_failures
    last_lookup_failures = 0
    names = []
    seen = set()
    for name in package_names or []:
        if isinstance(name, str) and lockfile.is_valid_package_name(name) and name not in seen:
            names.append(name)
            seen.add(name)
    if not names:
        return []

    try:
        workers = max(1, min(int(concurrency), MAX_CONCURRENCY))
    except (TypeError, ValueError):
        workers = 8
    with ThreadPoolExecutor(max_workers=workers) as executor:
        packuments = list(executor.map(_packument_maintainers, names))
    last_lookup_failures += sum(1 for item in packuments if item.get("error"))

    downloads = {}
    try:
        downloads = harvester._npm_bulk_downloads([item["package"] for item in packuments])
    except Exception:  # noqa: BLE001
        last_lookup_failures += 1
    if not isinstance(downloads, dict):
        last_lookup_failures += 1
        downloads = {}

    by_domain: dict[str, dict] = {}
    for item in packuments:
        package = item["package"]
        value = downloads.get(package, 0)
        item["downloads_week"] = (
            value if isinstance(value, int) and not isinstance(value, bool) else 0
        )
        domains = harvester.extract_domains(item["maintainers"])
        for raw_domain in domains:
            domain = rdap.normalize_domain(raw_domain)
            if domain is None:
                continue
            entry = by_domain.setdefault(domain, {
                "domain": domain, "packages": [], "maintainers": set(),
                "dependents": 0, "downloads_week": 0, "errors": [],
            })
            entry["packages"].append(package)
            entry["dependents"] += item.get("dependents", 0)
            entry["downloads_week"] += item["downloads_week"]
            entry["maintainers"].update(
                email for email in item["maintainers"]
                if email.endswith("@" + domain)
            )
            if item.get("error"):
                entry["errors"].append(item["error"])

    if not by_domain:
        return []

    domains = sorted(by_domain)
    try:
        resolved = rdap.resolve_domains(
            domains, cache_path=_DEFAULT_CACHE, concurrency=workers
        )
    except Exception:  # noqa: BLE001
        resolved = []
    rdap_by_domain = {record["domain"]: record for record in (resolved or [])
                      if isinstance(record, dict) and isinstance(record.get("domain"), str)}
    findings: list[dict] = []
    for finding_index, domain in enumerate(domains, 1):
        entry = by_domain[domain]
        record = rdap_by_domain.get(domain)
        if record is None:
            record = {"domain": domain, "registered": None, "created": None,
                      "expires": None, "status": [], "error": "RDAP lookup failed"}
        record = _public_rdap_record(record, domain)
        if record.get("error"):
            last_lookup_failures += 1
            record["error"] = "RDAP lookup failed"
        finding = {
            "domain": domain,
            "ecosystem": "npm",
            "packages": sorted(set(entry["packages"])),
            "maintainer_count": len(entry["maintainers"]),
            "maintainers": [f"maintainer-{finding_index}-{i + 1}"
                            for i in range(len(entry["maintainers"]))],
            "dependents": entry["dependents"],
            "downloads_week": entry["downloads_week"],
            "rdap": record,
        }
        if entry["errors"] and not record.get("error"):
            finding["rdap"] = dict(record, error="package lookup failed")
        finding.update(scorer.score_finding(finding))
        findings.append(finding)

    findings.sort(key=lambda finding: -finding.get("risk", 0))
    return findings
