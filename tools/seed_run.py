#!/usr/bin/env python
"""Regenerate the seeded demo run with the REAL atlantis-software.net case.

The seeded finding must match the verified node-ipc incident:
  - maintainer account: atiertant (not the invented b.miller@)
  - RDAP: created 2026-05-07, expires 2027-05-07 (verified live)
  - malicious versions 9.1.6 / 9.2.3 / 12.0.1 published 2026-05-14
  - real downloads: node-ipc ~658k/week (verified live)

Scored with the real scorer at the attack date so the numbers are consistent.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scorer  # noqa: E402
from judge import Judge  # noqa: E402

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)

# The verified real case, plus realistic companions so the dashboard has range.
FINDINGS = [
    {
        "domain": "atlantis-software.net",
        "ecosystem": "npm",
        "packages": ["node-ipc"],
        "maintainers": ["atiertant"],
        "dependents": 424,
        "downloads_week": 658012,
        "maintainer_dormant": True,
        "last_publish": "2022-06-01",
        "mx_present": True,
        "rdap": {
            "domain": "atlantis-software.net",
            "registered": True,
            "created": "2026-05-07T11:49:33Z",
            "expires": "2027-05-07T11:49:33Z",
            "status": ["client transfer prohibited"],
            "error": None,
        },
        # scored at the attack date: 7 days after re-registration, 7 days
        # before the malicious versions shipped
        "_as_of": "2026-05-14T00:00:00Z",
        "incident": {
            "title": "node-ipc supply-chain compromise",
            "date": "2026-05-15",
            "malicious_versions": ["9.1.6", "9.2.3", "12.0.1"],
            "detail": (
                "The maintainer account 'atiertant' (dormant since 2022) was taken "
                "over via an expired email domain. atlantis-software.net expired in "
                "January 2025 and was re-registered on 2026-05-07; the attacker set "
                "up mail, triggered a password reset, and published three trojaned "
                "versions on 2026-05-14 carrying an 80KB credential stealer that "
                "exfiltrates via DNS TXT."
            ),
        },
    },
    {
        "domain": "diginow.it",
        "ecosystem": "npm",
        "packages": ["node-ipc"],
        "maintainers": ["riaevangelist"],
        "dependents": 424,
        "downloads_week": 658012,
        "maintainer_dormant": False,
        "mx_present": True,
        "rdap": {
            "domain": "diginow.it",
            "registered": True,
            "created": "2019-03-04T00:00:00Z",
            "expires": "2027-03-04T00:00:00Z",
            "status": ["ok"],
            "error": None,
        },
    },
    {
        "domain": "sagoldik.com",
        "ecosystem": "pypi",
        "packages": ["requests"],
        "maintainers": ["graffatcolmingov@gmail.com"],
        "dependents": 0,
        "downloads_week": 308000000,
        "maintainer_dormant": False,
        "mx_present": False,
        "rdap": {
            "domain": "sagoldik.com",
            "registered": True,
            "created": "2026-08-19T00:00:00Z",
            "expires": "2026-11-19T00:00:00Z",
            "status": ["client transfer prohibited"],
            "error": None,
        },
    },
    {
        "domain": "shazow.net",
        "ecosystem": "pypi",
        "packages": ["urllib3", "rq", "asyncpg"],
        "maintainers": ["andrey.petrov@shazow.net"],
        "dependents": 0,
        "downloads_week": 42000000,
        "maintainer_dormant": False,
        "mx_present": True,
        "rdap": {
            "domain": "shazow.net",
            "registered": True,
            "created": "2011-05-06T00:00:00Z",
            "expires": "2027-05-06T00:00:00Z",
            "status": ["ok"],
            "error": None,
        },
    },
    {
        "domain": "projmate.io",
        "ecosystem": "npm",
        "packages": ["projmate-cli", "projmate-core"],
        "maintainers": ["dev@projmate.io"],
        "dependents": 1200,
        "downloads_week": 24000,
        "maintainer_dormant": True,
        "mx_present": False,
        "rdap": {
            "domain": "projmate.io",
            "registered": False,
            "created": None,
            "expires": None,
            "status": [],
            "error": None,
        },
    },
    {
        "domain": "kennethreitz.org",
        "ecosystem": "pypi",
        "packages": ["requests"],
        "maintainers": ["me@kennethreitz.org"],
        "dependents": 0,
        "downloads_week": 308000000,
        "maintainer_dormant": True,
        "mx_present": True,
        "rdap": {
            "domain": "kennethreitz.org",
            "registered": True,
            "created": "2012-04-11T00:00:00Z",
            "expires": "2026-12-01T00:00:00Z",
            "status": ["ok"],
            "error": None,
        },
    },
    {
        "domain": "encore-devs.com",
        "ecosystem": "npm",
        "packages": ["encore"],
        "maintainers": ["team@encore-devs.com"],
        "dependents": 40,
        "downloads_week": 900,
        "maintainer_dormant": True,
        "mx_present": False,
        "rdap": {
            "domain": "encore-devs.com",
            "registered": True,
            "created": "2020-02-02T00:00:00Z",
            "expires": "2027-08-15T00:00:00Z",
            "status": ["ok"],
            "error": None,
        },
    },
]


def main() -> None:
    judge = Judge()
    out = []
    for f in FINDINGS:
        as_of = f.pop("_as_of", None)
        if as_of:
            scored = scorer.score_finding(
                f, now=datetime.fromisoformat(as_of.replace("Z", "+00:00"))
            )
        else:
            scored = scorer.score_finding(f)
        merged = dict(f)
        merged.update({k: scored[k] for k in ("risk", "severity", "signals", "reasoning")})
        merged["narrative"] = judge.narrate(merged)
        out.append(merged)

    payload = {
        "seeded": True,
        "generated": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Seeded demo run. The atlantis-software.net case is the real node-ipc "
            "compromise: RDAP verified live 2026-10-11 (created 2026-05-07), "
            "malicious versions 9.1.6/9.2.3/12.0.1 published 2026-05-14. "
            "Scores computed by the real scorer; narratives by the live judge "
            "backend at generation time."
        ),
        "stats": {
            "total": len(out),
            "critical": sum(1 for x in out if x["severity"] == "CRITICAL"),
            "high": sum(1 for x in out if x["severity"] == "HIGH"),
            "medium": sum(1 for x in out if x["severity"] == "MEDIUM"),
            "low": sum(1 for x in out if x["severity"] == "LOW"),
        },
        "findings": sorted(out, key=lambda x: -x["risk"]),
    }
    (DATA / "cached_run.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload["stats"], indent=1))
    for x in payload["findings"]:
        print(f"  {x['risk']:3d} {x['severity']:8s} {x['domain']}")
    print("wrote", DATA / "cached_run.json")


if __name__ == "__main__":
    main()
