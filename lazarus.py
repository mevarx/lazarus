#!/usr/bin/env python
"""CLI: lazarus check <package.json|package-lock.json|-> [--json].

Exit 0 if no CRITICAL findings, 1 if any, 2 on usage/input error, or 130 when
interrupted. Output never includes maintainer names, handles, or email addresses.
"""
from __future__ import annotations

import argparse
import json
import sys

import lockfile
import repo_scan

MAX_DEPENDENCIES = 500


def _print_findings(findings: list[dict], as_json: bool) -> int:
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    if as_json:
        safe = []
        for finding_index, finding in enumerate(findings, 1):
            public = dict(finding)
            maintainers = finding.get("maintainers") or []
            count = len(maintainers) if isinstance(maintainers, (list, tuple, set)) else 0
            public["maintainer_count"] = count
            # Unique per finding (not just per position): the graph builder
            # namespaces by this label, so a shared "maintainer-1" across
            # findings would collapse them into one node.
            public["maintainers"] = [
                f"maintainer-{finding_index}-{index + 1}" for index in range(count)
            ]
            public.pop("maintainer_names", None)
            public.pop("maintainer_handles", None)
            safe.append(public)
        print(json.dumps({"critical": len(critical), "findings": safe}, indent=2))
        return 1 if critical else 0

    if not findings:
        print("No maintainer email domains at risk.")
        return 0

    print(f"{len(findings)} maintainer email domain(s) assessed. "
          f"{len(critical)} CRITICAL.\n")
    for finding in findings:
        severity = finding.get("severity", "LOW")
        mark = "!!" if severity == "CRITICAL" else "  "
        print(f"{mark} [{severity:8s}] {finding.get('domain', 'unknown')}  "
              f"risk={finding.get('risk')}")
        print(f"     packages: {', '.join(finding.get('packages', [])[:5])}")
        for signal in (finding.get("signals") or [])[:3]:
            print(f"       - {signal}")
        print()
    if critical:
        print(f"RESULT: {len(critical)} CRITICAL finding(s) — "
              "treat as a pre-attack signal.")
    return 1 if critical else 0


def _read_stdin() -> str:
    limit = lockfile.max_input_bytes()
    stream = getattr(sys.stdin, "buffer", None)
    raw = stream.read(limit + 1) if stream is not None else sys.stdin.read(limit + 1)
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise lockfile.LockfileError("input is not valid UTF-8 text") from exc
        if len(encoded) > limit:
            raise lockfile.LockfileError(f"input exceeds the {limit} byte limit")
        return raw
    if len(raw) > limit:
        raise lockfile.LockfileError(f"input exceeds the {limit} byte limit")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise lockfile.LockfileError("input is not valid UTF-8 text") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lazarus", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="scan a package.json / package-lock.json")
    check.add_argument("file", help="dependency-file path, or - for stdin")
    check.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if args.command != "check":
        return 2
    try:
        names, invalid_count = (
            lockfile.parse_dependencies_with_stats(_read_stdin())
            if args.file == "-"
            else lockfile.parse_dependencies_file_with_stats(args.file)
        )
    except lockfile.LockfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    if invalid_count:
        print(f"{invalid_count} invalid dependency name(s) skipped.", file=sys.stderr)
    if len(names) > MAX_DEPENDENCIES:
        print(f"Dependency limit reached; scanning first {MAX_DEPENDENCIES} "
              f"of {len(names)} packages.", file=sys.stderr)
        names = names[:MAX_DEPENDENCIES]

    try:
        repo_scan.last_lookup_failures = 0
        findings = repo_scan.scan_dependencies(names)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    failures = getattr(repo_scan, "last_lookup_failures", 0)
    if failures:
        print(f"{failures} lookups failed (unverified).", file=sys.stderr)
    return _print_findings(findings, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
