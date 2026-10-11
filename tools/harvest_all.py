#!/usr/bin/env python
"""Run a bounded live npm harvest, RDAP scan, and independent verification."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

import harvester  # noqa: E402
import rdap  # noqa: E402
import scorer  # noqa: E402
import verify  # noqa: E402


def build_findings(npm_items: list[dict]) -> list[dict]:
    """Group package records by maintainer domain without retaining addresses."""
    by_domain: dict[str, dict] = {}
    for item in npm_items:
        domains = harvester.extract_domains(
            [m.get("email", "") for m in item.get("maintainers", [])]
        )
        for domain in domains:
            entry = by_domain.setdefault(domain, {
                "domain": domain, "packages": [], "dependents": 0, "downloads_week": 0,
            })
            entry["packages"].append(item["package"])
            entry["dependents"] += item.get("dependents", 0)
            entry["downloads_week"] += item.get("downloads_week", 0)

    domains = sorted(by_domain)
    resolved = rdap.resolve_domains(
        domains, cache_path=str(BASE / "data" / "rdap_cache.json"), concurrency=4
    )
    rdap_by = {row["domain"]: row for row in resolved}
    findings = []
    for domain in domains:
        entry = by_domain[domain]
        finding = {
            "domain": domain,
            "ecosystem": "npm",
            "packages": sorted(set(entry["packages"])),
            "dependents": entry["dependents"],
            "downloads_week": entry["downloads_week"],
            "rdap": rdap_by.get(domain) or {
                "domain": domain, "registered": None, "created": None,
                "expires": None, "error": "not resolved",
            },
        }
        finding.update(scorer.score_finding(finding))
        findings.append(finding)
    findings.sort(key=lambda row: -row["risk"])
    return findings


def _payload(npm_count: int, findings: list[dict], args, notes: list[str]) -> dict:
    severity_counts = Counter(row.get("severity", "LOW") for row in findings)
    status_counts = Counter(
        row.get("verification", {}).get("status", "not_applicable") for row in findings
    )
    reasons = Counter(
        reason for row in findings
        for reason in row.get("verification", {}).get("reasons", [])
    )
    saved_findings = []
    for row in findings:
        saved_findings.append({
            "domain": row["domain"],
            "ecosystem": row["ecosystem"],
            "packages": row["packages"],
            "risk": row["risk"],
            "severity": row["severity"],
            "verified_severity": row.get("verified_severity", "UNVERIFIED"),
            "needs_manual_check": row.get("needs_manual_check", True),
            "signals": row.get("signals", []),
            "rdap": {
                "registered": row.get("rdap", {}).get("registered"),
                "created": row.get("rdap", {}).get("created"),
                "expires": row.get("rdap", {}).get("expires"),
                "error": row.get("rdap", {}).get("error"),
            },
            "verification": row.get("verification", {
                "status": "not_applicable", "reasons": [],
            }),
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_config": {
            "source_lists": ["npm registry search API, popularity:1"],
            "package_limit": args.npm,
            "time_budget_seconds": args.budget,
            "request_timeout_seconds": {
                "npm_pypi": harvester.MAX_TIMEOUT,
                "rdap": rdap.MAX_TIMEOUT,
                "dns": verify.DNS_TIMEOUT,
            },
            "rdap_servers": [rdap.BOOTSTRAP_URL, "repository TLD fallback map"],
            "dns_server": verify.DNS_JSON_URL,
            "verification_concurrency": 4,
        },
        "counts": {
            "packages_scanned": npm_count,
            "maintainer_domains_found": len(findings),
            "domains_checked": len(findings),
            "severity": {label: severity_counts.get(label, 0)
                         for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        },
        "verification": {
            "confirmed": status_counts.get("confirmed", 0),
            "uncertain": status_counts.get("needs_manual_check", 0),
            "not_applicable": status_counts.get("not_applicable", 0),
            "reasons": dict(sorted(reasons.items())),
        },
        "findings": saved_findings,
        "notes": notes,
    }


def _write(path: str, payload: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--npm", type=int, default=300)
    parser.add_argument("--budget", type=int, default=540)
    parser.add_argument("--out", default=str(BASE / "data" / "harvest.json"))
    args = parser.parse_args()
    if args.npm < 1 or args.budget < 1 or args.budget > 600:
        parser.error("--npm must be positive and --budget must be between 1 and 600 seconds")

    deadline = time.monotonic() + args.budget
    harvester.set_deadline(deadline)
    rdap.set_deadline(deadline)
    verify.set_deadline(deadline)
    npm_items: list[dict] = []
    findings: list[dict] = []
    notes: list[str] = []
    try:
        print(f"[harvest] npm popularity search, limit {args.npm}", flush=True)
        npm_items = harvester.harvest_npm(args.npm)
        if not npm_items:
            notes.append("npm harvest returned no packages; network or source unavailable")
        elif time.monotonic() >= deadline:
            notes.append("time budget exhausted before RDAP lookups")
        else:
            print(f"[harvest] {len(npm_items)} packages; resolving domains", flush=True)
            findings = build_findings(npm_items)
            if time.monotonic() < deadline:
                findings = verify.verify_findings(findings, concurrency=4)
            else:
                notes.append("time budget exhausted before independent verification")
        if time.monotonic() >= deadline:
            notes.append("global time budget reached")
    except KeyboardInterrupt:
        notes.append("interrupted by operator; partial results only")
    except Exception as exc:
        notes.append(f"harvest stopped after {type(exc).__name__}")
    finally:
        harvester.set_deadline(None)
        rdap.set_deadline(None)
        verify.set_deadline(None)

    payload = _payload(len(npm_items), findings, args, notes)
    _write(args.out, payload)
    if any(note.startswith("npm harvest returned no packages") for note in notes):
        print("[harvest] no packages returned; wrote an empty result with a note", file=sys.stderr)
        return 1
    print(f"[harvest] wrote {args.out}")
    counts = payload["counts"]
    verification = payload["verification"]
    print(
        f"[harvest] {counts['packages_scanned']} packages -> "
        f"{counts['domains_checked']} domains | "
        f"CRITICAL {counts['severity']['CRITICAL']} HIGH {counts['severity']['HIGH']} "
        f"MEDIUM {counts['severity']['MEDIUM']} LOW {counts['severity']['LOW']} | "
        f"confirmed {verification['confirmed']} uncertain {verification['uncertain']} "
        f"not-applicable {verification['not_applicable']}"
    )
    return 130 if "interrupted by operator; partial results only" in notes else 0


if __name__ == "__main__":
    raise SystemExit(main())
