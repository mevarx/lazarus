#!/usr/bin/env python
"""lazarus — command-line interface.

Usage:
    lazarus check package-lock.json     # scan a dependency file; exit 1 on CRITICAL
    lazarus check package.json
    lazarus check -                      # read from stdin

Exit codes:
    0  no CRITICAL findings
    1  at least one CRITICAL finding (use in CI to fail the build)
    2  usage / input error

Stdlib only. Reuses lockfile + repo_scan + scorer. Emails are masked in
output; no maintainer names are published.
"""

from __future__ import annotations

import argparse
import json
import sys

import lockfile
import repo_scan
from repo_scan import mask_email


def _print_findings(findings: list[dict], as_json: bool) -> int:
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    if as_json:
        # mask maintainer emails before printing
        safe = []
        for f in findings:
            g = dict(f)
            g["maintainers"] = [mask_email(m) for m in (f.get("maintainers") or [])]
            safe.append(g)
        print(json.dumps({"critical": len(critical), "findings": safe}, indent=2))
        return 1 if critical else 0

    if not findings:
        print("No maintainer email domains at risk.")
        return 0

    print(f"{len(findings)} maintainer email domain(s) assessed. "
          f"{len(critical)} CRITICAL.\n")
    for f in findings:
        sev = f.get("severity", "LOW")
        mark = "!!" if sev == "CRITICAL" else "  "
        print(f"{mark} [{sev:8s}] {f['domain']}  risk={f.get('risk')}")
        print(f"     packages: {', '.join(f.get('packages', [])[:5])}")
        print(f"     maintainer: {mask_email(f['maintainers'][0]) if f.get('maintainers') else '—'}")
        for s in (f.get("signals") or [])[:3]:
            print(f"       - {s}")
        print()
    if critical:
        print(f"RESULT: {len(critical)} CRITICAL finding(s) — treat as a pre-attack signal.")
    return 1 if critical else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lazarus", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="scan a package.json / package-lock.json")
    check.add_argument("file", help="path to the dependency file, or - for stdin")
    check.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    if args.command == "check":
        try:
            if args.file == "-":
                text = sys.stdin.read()
                names = lockfile.parse_dependencies(text)
            else:
                names = lockfile.parse_dependencies_file(args.file)
        except lockfile.LockfileError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        findings = repo_scan.scan_dependencies(names)
        return _print_findings(findings, args.json)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
