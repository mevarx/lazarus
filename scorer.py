"""Deterministic risk scoring for domain-takeover findings.

Implements the scorer contract from INTERFACES.md. Pure stdlib, no network,
no hidden state. Every rule is a fixed point value and the time reference can
be pinned via the optional ``now`` keyword argument, so scoring is fully
reproducible.

Input finding shape (per INTERFACES.md)::

    {
        "domain": str,
        "packages": [str],
        "dependents": int,
        "downloads_week": int,
        "rdap": {"domain": str, "registered": bool, "created": str|None,
                 "expires": str|None, "status": [str], "error": str|None},
        "maintainers": [str],
        # flags passed in by the caller (they need DNS/registry lookups):
        "maintainer_dormant": bool,  # no publish in 24 months
        "mx_present": bool,          # DNS MX record exists for the domain
    }

Notes on rule semantics (documented decisions where the contract is terse):
  * ``dependents`` thresholds are tiered, not stacked: >=1000 scores +20 and
    NOT an additional +10 (mirrors the tiered expiry rules the contract spells
    out explicitly).
  * ``expires`` thresholds stack: <90d is +35, and a domain also <30d away
    gets an extra +15 (the contract marks this "(extra)").
  * Time comparisons use ``now`` (default: real UTC now). Boundaries are
    strict: created must be < 180 days old, expires < 90 / < 30 days.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# --- Point values, fixed by the INTERFACES.md scorer contract ---------------
POINTS_UNREGISTERED = 60
POINTS_RECENTLY_REREGISTERED = 50
POINTS_EXPIRING_SOON = 35
POINTS_EXPIRING_IMMINENT = 15  # extra, on top of POINTS_EXPIRING_SOON
POINTS_DEPENDENTS_MAJOR = 20
POINTS_DEPENDENTS_NOTABLE = 10
POINTS_DOWNLOADS_POPULAR = 10
POINTS_MAINTAINER_DORMANT = 15
POINTS_MX_REREGISTERED = 10
POINTS_ABANDONED_LONGTAIL = 25  # no publish in 48+ months on a custom domain

# --- Thresholds ---------------------------------------------------------------
CREATED_AGE_DAYS = 180
EXPIRES_SOON_DAYS = 90
EXPIRES_IMMINENT_DAYS = 30
DEPENDENTS_MAJOR = 1000
DEPENDENTS_NOTABLE = 100
DOWNLOADS_POPULAR = 100_000
ABANDONED_LONGTAIL_DAYS = 1460  # 48 months without a publish

RISK_CAP = 100

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"


def severity_label(risk: int) -> str:
    """Map a 0-100 risk score to its severity band."""
    if risk >= 80:
        return SEVERITY_CRITICAL
    if risk >= 60:
        return SEVERITY_HIGH
    if risk >= 35:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _parse_date(value) -> datetime | None:
    """Parse an ISO-8601 date/datetime string from RDAP into an aware datetime.

    Returns None for missing or unparseable values. Naive datetimes are
    assumed to be UTC.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _as_int(value) -> int:
    """Coerce a possibly-string numeric field to int (API JSON quirk safety)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def score_finding(finding: dict, *, now: datetime | None = None) -> dict:
    """Score one domain-takeover finding. Deterministic for a given ``now``.

    Returns {"risk": int 0-100, "severity": str, "signals": [str],
    "reasoning": [str]}. Each rule that fires appends one entry to both
    signals and reasoning.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    rdap = finding.get("rdap") or {}
    signals: list[str] = []
    reasoning: list[str] = []
    risk = 0

    def fire(points: int, signal: str, reason: str) -> None:
        nonlocal risk
        risk += points
        signals.append(signal)
        reasoning.append(reason)

    reregistered = False

    # --- Domain registration state -------------------------------------------
    # Only fires when RDAP positively reports the domain as unregistered
    # (registered=False) with no lookup error. An error means "unknown", not
    # "unregistered".
    if rdap.get("registered") is False and not rdap.get("error"):
        fire(
            POINTS_UNREGISTERED,
            "domain unregistered",
            "RDAP reports the domain is not registered (+60): "
            "anyone can claim it and take over the maintainer's email.",
        )

    # --- Recently re-registered -------------------------------------------------
    created = _parse_date(rdap.get("created"))
    if created is not None:
        age_days = (now - created).days
        if age_days < CREATED_AGE_DAYS:
            reregistered = True
            fire(
                POINTS_RECENTLY_REREGISTERED,
                "recently re-registered",
                f"Domain was created only {age_days} days ago "
                f"(< {CREATED_AGE_DAYS}d), consistent with a re-registration "
                f"after expiry (+50).",
            )

    # --- Expiry horizon ---------------------------------------------------------
    expires = _parse_date(rdap.get("expires"))
    if expires is not None:
        days_left = (expires - now).days
        if days_left < EXPIRES_SOON_DAYS:
            fire(
                POINTS_EXPIRING_SOON,
                "expiring soon",
                f"Domain expires in {days_left} days "
                f"(< {EXPIRES_SOON_DAYS}d) (+35).",
            )
            if days_left < EXPIRES_IMMINENT_DAYS:
                fire(
                    POINTS_EXPIRING_IMMINENT,
                    "expires within 30 days",
                    f"Domain expires in {days_left} days "
                    f"(< {EXPIRES_IMMINENT_DAYS}d) — takeover window is open "
                    f"(+15 extra).",
                )

    # --- Ecosystem blast radius --------------------------------------------------
    dependents = _as_int(finding.get("dependents"))
    if dependents >= DEPENDENTS_MAJOR:
        fire(
            POINTS_DEPENDENTS_MAJOR,
            f"{dependents} dependents",
            f"{dependents} dependent packages (>= {DEPENDENTS_MAJOR}) ride on "
            f"this domain (+20).",
        )
    elif dependents >= DEPENDENTS_NOTABLE:
        fire(
            POINTS_DEPENDENTS_NOTABLE,
            f"{dependents} dependents",
            f"{dependents} dependent packages (>= {DEPENDENTS_NOTABLE}) ride on "
            f"this domain (+10).",
        )

    downloads = _as_int(finding.get("downloads_week"))
    if downloads >= DOWNLOADS_POPULAR:
        fire(
            POINTS_DOWNLOADS_POPULAR,
            f"{downloads} weekly downloads",
            f"{downloads} weekly downloads (>= {DOWNLOADS_POPULAR}): a hijacked "
            f"release reaches a large audience (+10).",
        )

    # --- Maintainer / DNS flags (passed in by the caller) ------------------------
    if finding.get("maintainer_dormant"):
        fire(
            POINTS_MAINTAINER_DORMANT,
            "dormant maintainer",
            "Maintainer has not published in 24+ months, so a domain-loss "
            "event would likely go unnoticed (+15).",
        )

    # --- Long-tail abandonment --------------------------------------------------
    # A package untouched for 48+ months whose maintainer uses a custom
    # (non-free-mail) domain is the canonical lapsed-domain candidate: the
    # maintainer has moved on and the personal domain can quietly expire.
    # The caller sets last_publish_days (days since last registry publish).
    ltp_days = _as_int(finding.get("last_publish_days"))
    if ltp_days >= ABANDONED_LONGTAIL_DAYS and not finding.get("free_mail_only"):
        fire(
            POINTS_ABANDONED_LONGTAIL,
            "abandoned long-tail package",
            f"No publish in {ltp_days} days (>= {ABANDONED_LONGTAIL_DAYS}d) and "
            "maintainer is on a custom domain — a prime lapsed-domain target "
            f"(+{POINTS_ABANDONED_LONGTAIL}).",
        )

    if finding.get("mx_present") and reregistered:
        fire(
            POINTS_MX_REREGISTERED,
            "MX present on re-registered domain",
            "Domain has MX records and was recently re-registered — the "
            "mailbox is live and could receive a password-reset email (+10).",
        )

    risk = min(risk, RISK_CAP)
    return {
        "risk": risk,
        "severity": severity_label(risk),
        "signals": signals,
        "reasoning": reasoning,
    }
