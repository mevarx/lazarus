#!/usr/bin/env python
"""tools/harvest_all.py — unattended real harvest + RDAP scan over the top
npm packages, saving REAL measured counts to data/.

This is the antithesis of the seeded demo: it performs live network calls and
writes only what it actually observed. Nothing here is invented. If the
network is down it writes an error file and exits non-zero rather than
fabricating results.

Usage:
    python tools/harvest_all.py [--npm 2000] [--pypi 500] [--out data/harvest.json]

Output: a JSON file with the harvest date, package/domain counts, severity
breakdown, blast radius, and the full (email-redacted) findings list.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import harvester  # noqa: E402
import rdap  # noqa: E402
import scorer  # noqa: E402
from repo_scan import mask_email  # noqa: E402


def build_findings(npm_items: list[dict]) -> list[dict]:
    """Group harvested packages by custom email domain, RDAP-resolve, score."""
    by_domain: dict[str, dict] = {}
    for item in npm_items:
        emails = [m["email"] for m in item.get("maintainers", [])]
        domains = harvester.extract_domains(emails)
        if not domains:
            continue
        for dom in domains:
            entry = by_domain.setdefault(dom, {
                "domain": dom, "packages": [], "maintainers": [],
                "dependents": 0, "downloads_week": 0,
            })
            entry["packages"].append(item["package"])
            entry["dependents"] += item.get("dependents", 0)
            entry["downloads_week"] += item.get("downloads_week", 0)
            for m in item["maintainers"]:
                if m["email"].endswith("@" + dom):
                    entry["maintainers"].append(m["email"])

    domains = sorted(by_domain.keys())
    resolved = rdap.resolve_domains(domains, cache_path=str(BASE / "data" / "rdap_cache.json"))
    rdap_by = {r["domain"]: r for r in resolved}

    findings = []
    for dom in domains:
        e = by_domain[dom]
        f = {
            "domain": dom, "ecosystem": "npm",
            "packages": sorted(set(e["packages"])),
            "maintainers": sorted(set(e["maintainers"])),
            "dependents": e["dependents"], "downloads_week": e["downloads_week"],
            "rdap": rdap_by.get(dom) or {"domain": dom, "registered": None,
                                         "created": None, "expires": None,
                                         "status": [], "error": "not resolved"},
        }
        f.update(scorer.score_finding(f))
        findings.append(f)
    findings.sort(key=lambda x: -x["risk"])
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--npm", type=int, default=2000)
    ap.add_argument("--out", default=str(BASE / "data" / "harvest.json"))
    args = ap.parse_args()

    print(f"[harvest] npm top {args.npm} ...", flush=True)
    npm_items = harvester.harvest_npm(args.npm)
    if not npm_items:
        print("[harvest] FAILED: no packages harvested (network down?)", file=sys.stderr)
        Path(args.out).write_text(json.dumps({
            "error": "harvest returned no packages — network unavailable",
            "harvested_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2), encoding="utf-8")
        return 1

    print(f"[harvest] {len(npm_items)} packages -> resolving domains ...", flush=True)
    findings = build_findings(npm_items)

    # redact emails before saving — never persist raw maintainer addresses
    for f in findings:
        f["maintainers"] = [mask_email(m) for m in f.get("maintainers", [])]

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    payload = {
        "harvested_at": datetime.now(timezone.utc).isoformat(),
        "source": "live harvest (npm search API + IANA RDAP) — real measured data",
        "npm_packages_scanned": len(npm_items),
        "custom_domains_found": len(findings),
        "severity": sev,
        "findings": findings,
    }
    Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[harvest] wrote {args.out}")
    print(f"[harvest] {len(npm_items)} packages -> {len(findings)} domains | "
          f"CRITICAL {sev['CRITICAL']} HIGH {sev['HIGH']} MEDIUM {sev['MEDIUM']} LOW {sev['LOW']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
