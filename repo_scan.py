"""repo_scan.py — scan the maintainer email domains behind a dependency set.

Given a list of npm package names (from a package.json / lockfile), look up
each package's maintainers, collect the custom email domains, resolve them
via RDAP, and score takeover risk. Reuses harvester / rdap / scorer / graph.

Pure stdlib. Never raises on network failure — a dead registry becomes an
``error`` on the affected finding, and the caller decides how to surface it.
"""

from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import harvester
import rdap
import scorer

# npm packument endpoint — returns current maintainers (name + email) per pkg.
_NPM_PACKUMENT = "https://registry.npmjs.org/{name}"

# Default RDAP cache location (mirrors app.py's data/rdap_cache.json).
_DEFAULT_CACHE = "data/rdap_cache.json"


def mask_email(email: str) -> str:
    """Mask a maintainer email for display: a***@domain (domain is public
    registry data; the mailbox is not). Non-email strings pass through."""
    s = str(email or "")
    at = s.find("@")
    if at <= 0:
        return s
    return s[: min(3, at)] + "***@" + s[at + 1 :]


def _packument_maintainers(name: str) -> dict:
    """Fetch one package's current maintainers. Returns a harvest-shaped item
    (package/maintainers/dependents/downloads_week) or an item with an error."""
    item = {"package": name, "maintainers": [], "dependents": 0,
            "downloads_week": 0, "error": None}
    try:
        data = harvester._get_json(_NPM_PACKUMENT.format(name=urllib.parse.quote(name, safe="")))
    except Exception as exc:  # noqa: BLE001
        item["error"] = f"registry lookup failed: {exc}"
        return item
    if not isinstance(data, dict):
        item["error"] = "unexpected registry response"
        return item
    for person in data.get("maintainers") or []:
        email = (person.get("email") or "").strip()
        who = person.get("username") or person.get("name") or ""
        if email:
            item["maintainers"].append({"name": who, "email": email.lower()})
    return item


def scan_dependencies(package_names: list[str], *, concurrency: int = 8) -> list[dict]:
    """Resolve maintainer email domains for the given packages and score them.

    Returns findings in the same shape as a live scan (see INTERFACES.md /
    lib/types.ts): one per at-risk domain, with rdap, risk, severity, signals,
    reasoning, packages, maintainers, dependents, downloads_week.
    """
    names = [n for n in dict.fromkeys(package_names) if n]
    if not names:
        return []

    # 1. maintainers per package (concurrent)
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        packuments = list(ex.map(_packument_maintainers, names))

    # 2. weekly downloads in bulk (best-effort, reuses harvester)
    downloads = {}
    try:
        downloads = harvester._npm_bulk_downloads([p["package"] for p in packuments])
    except Exception:  # noqa: BLE001
        downloads = {}

    # 3. group packages by custom email domain
    by_domain: dict[str, dict] = {}
    for item in packuments:
        pkg = item["package"]
        item["downloads_week"] = downloads.get(pkg, 0)
        emails = [m["email"] for m in item["maintainers"]]
        domains = harvester.extract_domains(emails)
        if not domains:
            continue
        for dom in domains:
            entry = by_domain.setdefault(dom, {
                "domain": dom,
                "packages": [],
                "maintainers": [],
                "dependents": 0,
                "downloads_week": 0,
                "errors": [],
            })
            entry["packages"].append(pkg)
            entry["dependents"] += item.get("dependents", 0)
            entry["downloads_week"] += item["downloads_week"]
            for m in item["maintainers"]:
                if m["email"].endswith("@" + dom):
                    entry["maintainers"].append(m["email"])
        if item.get("error"):
            # surface per-package lookup failures against the first domain seen
            for dom in domains:
                by_domain[dom]["errors"].append(f"{pkg}: {item['error']}")

    if not by_domain:
        return []

    # 4. RDAP-resolve every domain (cached), then score
    domains = sorted(by_domain.keys())
    resolved = rdap.resolve_domains(
        domains, cache_path=_DEFAULT_CACHE, concurrency=concurrency
    )
    rdap_by_domain = {r["domain"]: r for r in resolved}

    findings: list[dict] = []
    for dom in domains:
        entry = by_domain[dom]
        record = rdap_by_domain.get(dom) or {"domain": dom, "registered": None,
                                             "created": None, "expires": None,
                                             "status": [], "error": "not resolved"}
        finding = {
            "domain": dom,
            "ecosystem": "npm",
            "packages": sorted(set(entry["packages"])),
            "maintainers": sorted(set(entry["maintainers"])),
            "dependents": entry["dependents"],
            "downloads_week": entry["downloads_week"],
            "rdap": record,
        }
        if record.get("error") and entry["errors"]:
            finding["rdap"] = dict(record, error=record["error"])
        elif entry["errors"]:
            finding["rdap"] = dict(record, error="; ".join(entry["errors"][:3]))
        scored = scorer.score_finding(finding)
        finding.update(scored)
        findings.append(finding)

    findings.sort(key=lambda f: -f.get("risk", 0))
    return findings
