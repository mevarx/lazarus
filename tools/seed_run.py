#!/usr/bin/env python3
"""Rebuild the offline replay fixture from the checked-in, source-backed evaluation snapshot.

This script performs no network requests and never initializes the model judge.
To refresh facts, verify them independently and update data/backtest/labeled_set.json.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scorer import score_finding  # noqa: E402

SOURCE_PATH = ROOT / "data" / "backtest" / "labeled_set.json"
OUTPUT_PATH = ROOT / "data" / "cached_run.json"


def _cached_finding(record: dict) -> dict:
    package = record.get("package")
    finding = {
        "domain": record["domain"],
        "packages": [package] if isinstance(package, str) and package else [],
        "maintainers": ["maintainer-1"] if package else [],
        "dependents": record.get("dependents"),
        "downloads_week": record.get("downloads_week"),
        "rdap": record.get("rdap") or {},
    }
    as_of = dt.datetime.fromisoformat(record["as_of"].replace("Z", "+00:00"))
    finding.update(score_finding(finding, now=as_of))
    finding["as_of"] = record["as_of"]
    if package == "node-ipc":
        finding["incident"] = (
            "Public reports associate the maintainer account and malicious node-ipc releases "
            "published on 2026-05-14 with this domain. Email takeover is a reported hypothesis, "
            "not directly observed."
        )
        finding["provenance"] = {
            "source": "historical-reconstruction",
            "fetched_at": record["rdap"].get("fetched_at"),
            "source_urls": [
                record["rdap"].get("source_url"),
                record.get("package_source_url"),
                record.get("downloads_source_url"),
                *(record.get("label_source") if isinstance(record.get("label_source"), list) else []),
            ],
            "source_fetches": {
                "rdap": record["rdap"].get("fetched_at"),
                "npm_registry": record.get("package_fetched_at"),
                "npm_downloads": record.get("downloads_fetched_at"),
            },
            "notes": (
                "Scored as of the day before the first malicious npm publish using the verified RDAP creation event; "
                "weekly downloads are the live npm snapshot in this record, not a historical value."
            ),
        }
        finding["unverified"] = [
            "dependents",
            "historical_downloads_week",
            "historical_mx_present",
            "prior_domain_expiration_or_deletion_event",
            "email_takeover_mechanism",
        ]
    else:
        finding["provenance"] = {
            "source": "rdap-live-fetch",
            "fetched_at": record["rdap"].get("fetched_at"),
            "source_urls": [record["rdap"].get("source_url")],
            "notes": "Stable-domain control; not an identified package-maintainer association.",
        }
        finding["unverified"] = ["package_association", "dependents", "downloads_week"]
    return finding


def build_cached_run(dataset: dict | None = None) -> dict:
    """Build deterministic replay findings and stats from the local verified snapshot."""
    if dataset is None:
        with SOURCE_PATH.open(encoding="utf-8") as stream:
            dataset = json.load(stream)
    findings = [_cached_finding(record) for record in dataset.get("domains") or []]
    findings.sort(key=lambda row: row["risk"], reverse=True)
    stats = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding["severity"].lower()
        if severity in stats:
            stats[severity] += 1
    recorded_at = dataset.get("recorded_at")
    return {
        "mode": "replay",
        "recorded_at": recorded_at,
        "generated": recorded_at,
        "seeded": True,
        "note": (
            "Offline replay built from checked-in public-source snapshots. No network or model calls are made; "
            "unknown values remain null and are listed per finding."
        ),
        "stats": stats,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args(argv)
    replay = build_cached_run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(replay, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        "Wrote replay data: "
        + ", ".join(f"{key}={value}" for key, value in replay["stats"].items())
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
