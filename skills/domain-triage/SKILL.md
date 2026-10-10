---
name: domain-triage
description: Assess domain-takeover risk for package maintainer email domains and write the plain-English risk narrative. Use when a scored finding has signals such as an unregistered domain, recent re-registration, imminent expiry, dormant maintainer, or live MX records, and you must decide a verdict, severity, and next step for the maintainer.
license: MIT
metadata:
  author: lazarus
  version: "1.0"
  stage: judge
allowed-tools: Bash(python:*) Read
---

# Domain takeover triage

This skill is the policy the Lazarus judge follows. `judge.py` calls the model
(or the offline template) to turn a numeric risk score into a short narrative a
maintainer can act on. Everything here is deterministic so the same finding
always produces the same words — the demo never changes its story.

## Input

A finding, as produced by `scorer.py`:

```json
{
  "domain": "atlantis-software.net",
  "packages": ["swift-validator"],
  "dependents": 1420,
  "downloads_week": 88400,
  "rdap": {"registered": false, "created": null, "expires": null, "status": []},
  "maintainers": ["ops@atlantis-software.net"],
  "risk": 90,
  "severity": "CRITICAL",
  "signals": ["domain unregistered", "dependents >= 1000"]
}
```

## Signal weights

The judge ranks signals by the same weights the scorer used, highest first.
The narrative gets the opener plus up to three signals, so a signal that never
makes the cut is still covered by the score.

| Signal | Weight | Meaning |
| --- | --- | --- |
| domain unregistered | 60 | Anyone can register it and receive its mail |
| recently re-registered | 50 | A lapse someone else has already taken |
| expires within 30 days | 50 | An immediate takeover window |
| expiring soon (< 90 days) | 35 | Renewal is coming up |
| dependents >= 1000 | 20 | High blast radius |
| dormant maintainer (24 months) | 15 | Nobody is watching the domain |
| live MX + re-registered | 10 | Mail is still being delivered somewhere |
| dependents >= 100 | 10 | Non-trivial blast radius |
| downloads_week >= 100000 | 10 | High-volume supply-chain target |

Severity bands: >= 80 CRITICAL, >= 60 HIGH, >= 35 MEDIUM, else LOW. Risk is
capped at 100.

## Output contract

`Judge.narrate(finding)` returns exactly three keys and never raises:

- `verdict` — one line, `SEVERITY (risk/100): domain — top signal.`
- `narrative` — 2 to 4 sentences. Sentence 1 states what the domain is worth
  to the ecosystem (packages, dependents, weekly downloads). The rest explain
  what the signals mean in plain English and what an attacker could do.
- `recommendation` — one concrete next step, chosen by severity band.

### Recommendation by severity

- **CRITICAL** — treat as an active takeover window: move maintainers off the
  domain now, rotate any credential ever mailed to it, register the domain
  yourself until the addresses are migrated.
- **HIGH** — re-verify maintainer control, add the domain to a registration
  watchlist, plan migration within the quarter.
- **MEDIUM** — confirm who controls the domain, diarise a re-check before the
  next renewal. No emergency action yet.
- **LOW** — no action beyond the standing watchlist.

## Writing rules

1. Lead with the ecosystem blast radius, not the score. The score is context;
   what the maintainer needs to know is how many people are affected.
2. One idea per sentence. Never chain three clauses with commas.
3. Name the attacker's capability concretely — "receive password-reset mail
   for ops@" beats "be used maliciously".
4. No hedging when a signal is decisive. If the domain is unregistered, say so
   in the verdict, not "may be at risk".
5. Never invent facts. If `rdap.error` is set, say the lookup failed rather
   than assuming the domain is registered.
6. Keep the whole narrative under 80 words.

## Offline mode

When no backend is reachable the judge falls back to the deterministic
template built from `signals`. It is not a degraded experience — it is the
documented output above, assembled without a model. Use it to verify the
policy before touching any API key.

## Running the checker

```bash
python scripts/check_domain.py atlantis-software.net
```

Prints a JSON risk assessment on stdout:

```json
{
  "domain": "atlantis-software.net",
  "rdap": {"registered": false, "error": null},
  "risk": 60,
  "severity": "HIGH",
  "signals": ["domain unregistered"],
  "recommendation": "..."
}
```

The script is network-dependent (RDAP). If RDAP is unreachable it reports the
error in the JSON instead of raising.
