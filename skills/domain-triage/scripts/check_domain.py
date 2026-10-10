#!/usr/bin/env python3
"""check_domain.py — one-shot RDAP risk assessment for a maintainer domain.

Usage:
    python check_domain.py <domain> [--offline]

Prints a JSON risk assessment on stdout and exits 0. Network failures are
reported inside the JSON rather than raised, so the output is always parseable.

Implements the triage policy documented in the parent SKILL.md: the scoring
table mirrors scorer.py so the numbers agree with the rest of the pipeline.
"""

from __future__ import annotations

import json
import os
import sys

# The skill lives in <project>/skills/domain-triage/scripts/; rdap.py sits at
# the project root. Add it to sys.path so this script works no matter the cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

FREE_MAIL = {
    "gmail.com", "outlook.com", "yahoo.com", "proton.me", "protonmail.com",
    "icloud.com", "hotmail.com", "live.com", "gmx.de", "mail.ru", "qq.com",
    "163.com", "yandex.ru",
}


def _fallback_resolve(domain: str) -> dict:
    """Minimal RDAP lookup used when rdap.py is not importable yet."""
    import urllib.error
    import urllib.request

    result = {
        "domain": domain,
        "registered": None,
        "created": None,
        "expires": None,
        "status": [],
        "error": None,
    }
    try:
        req = urllib.request.Request(
            "https://rdap.org/domain/" + domain,
            headers={
                "User-Agent": "lazarus-research/1.0 (contact: maintainers@example.net)",
                "Accept": "application/rdap+json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        result["registered"] = True
        for event in payload.get("events") or []:
            action = str(event.get("eventAction") or "").lower()
            if action == "registration":
                result["created"] = event.get("eventDate")
            elif action == "expiration":
                result["expires"] = event.get("eventDate")
        result["status"] = [str(s) for s in (payload.get("status") or [])]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result["registered"] = False
        else:
            result["error"] = f"RDAP HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _resolve(domain: str) -> dict:
    try:
        from rdap import resolve_domain  # type: ignore
    except Exception:  # noqa: BLE001
        return _fallback_resolve(domain)
    try:
        return resolve_domain(domain)
    except Exception as exc:  # noqa: BLE001
        out = _fallback_resolve(domain)
        out["error"] = f"rdap.resolve_domain failed: {exc}"
        return out


def _days_until(iso: str | None):
    """Whole days from now to an ISO-8601 timestamp; None if unusable."""
    if not iso:
        return None
    import datetime

    text = str(iso).strip().replace("Z", "+00:00")
    try:
        when = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return (when - now).days


def _age_days(iso: str | None):
    if not iso:
        return None
    import datetime

    text = str(iso).strip().replace("Z", "+00:00")
    try:
        when = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now - when).days


def severity_label(risk: int) -> str:
    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 35:
        return "MEDIUM"
    return "LOW"


def assess(domain: str) -> dict:
    """Score a single domain against the SKILL.md policy table."""
    domain = (domain or "").strip().lower().strip(".")
    if not domain or "@" in domain or "." not in domain:
        return {
            "domain": domain,
            "error": "not a bare domain name",
            "risk": 0,
            "severity": "LOW",
            "signals": [],
            "recommendation": "Pass a bare domain such as example.net.",
        }

    if domain in FREE_MAIL:
        return {
            "domain": domain,
            "rdap": {"registered": None},
            "risk": 0,
            "severity": "LOW",
            "signals": ["free-mail provider"],
            "recommendation": (
                "Free-mail addresses cannot be taken over by domain lapse; no action."
            ),
        }

    rdap = _resolve(domain)
    signals: list[str] = []
    risk = 0

    registered = rdap.get("registered")
    error = rdap.get("error")

    if registered is False and not error:
        risk += 60
        signals.append("domain unregistered")

    age = _age_days(rdap.get("created"))
    if age is not None and age < 180:
        risk += 50
        signals.append("recently re-registered")

    expiry_days = _days_until(rdap.get("expires"))
    if expiry_days is not None:
        if expiry_days < 90:
            risk += 35
            signals.append("expiring soon")
        if expiry_days < 30:
            risk += 15
            signals.append("expires within 30 days")

    if error:
        signals.append(f"lookup error: {error}")

    severity = severity_label(min(risk, 100))
    return {
        "domain": domain,
        "rdap": {
            "registered": registered,
            "created": rdap.get("created"),
            "expires": rdap.get("expires"),
            "status": rdap.get("status") or [],
            "error": error,
        },
        "risk": min(risk, 100),
        "severity": severity,
        "signals": signals,
        "recommendation": _recommendation(severity, signals),
    }


_RECOMMENDATIONS = {
    "CRITICAL": (
        "Treat as an active takeover window: move maintainers off this domain now, "
        "rotate any credential ever mailed to it, and register the domain yourself "
        "until the addresses are migrated."
    ),
    "HIGH": (
        "Re-verify that the named maintainers still control this domain, add it to a "
        "registration watchlist, and plan migration within the quarter."
    ),
    "MEDIUM": (
        "Confirm who currently controls the domain and diarise a re-check before the "
        "next renewal date; no emergency action is indicated yet."
    ),
    "LOW": (
        "No action required beyond the standing watchlist — the signals present do "
        "not indicate an imminent takeover."
    ),
}


def _recommendation(severity: str, signals: list[str]) -> str:
    if any(s.startswith("lookup error") for s in signals):
        return (
            "The RDAP lookup failed, so the risk is unknown. Re-run the scan; if the "
            "error persists, check the domain manually before drawing conclusions."
        )
    return _RECOMMENDATIONS.get(severity, _RECOMMENDATIONS["LOW"])


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print(
            "usage: check_domain.py <domain> [--offline]\n"
            "  prints a JSON risk assessment for one maintainer domain",
            file=sys.stderr,
        )
        return 2

    result = assess(args[0])
    print(json.dumps(result, indent=2))
    return 0 if not result.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
