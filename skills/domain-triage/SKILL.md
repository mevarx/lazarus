---
name: domain-triage
description: Triage Lazarus maintainer-domain findings using the deterministic score, observed RDAP evidence, and cautious disclosure guidance.
license: MIT
---

# Domain Triage

Treat each finding as a heuristic risk flag, not proof of compromise. Separate
observed registry data from inferred risk, identify RDAP gaps, and recommend
manual verification when evidence is incomplete. Do not include maintainer
names, handles, or email addresses in summaries.

## Full scanner scoring

The deterministic `scorer.py` score is capped at 100. Add:

| Signal | Points |
| --- | ---: |
| RDAP confirms the domain is unregistered and the lookup has no error | +60 |
| RDAP creation date is less than 180 days old | +50 |
| Expiry is in less than 90 days | +35 |
| Expiry is in less than 30 days | +15 additional |
| At least 1,000 dependents | +20 |
| At least 100 but fewer than 1,000 dependents | +10 |
| At least 100,000 weekly downloads | +10 |
| Maintainer is dormant for at least 24 months | +15 |
| MX exists on a recently re-registered domain | +10 |

Severity thresholds are **CRITICAL ≥80**, **HIGH ≥60**, **MEDIUM ≥35**, and
**LOW <35**. Missing or unparseable RDAP dates do not score. The dependent
tiers are mutually exclusive; expiry points stack. An RDAP lookup error does
not count as an unregistered domain.

The separate `scripts/check_domain.py` helper only scores unregistered status,
recent creation, and expiry. It does not calculate the full scanner's
dependents, downloads, dormancy, or MX signals.

## Blast radius and reporting

Per-finding scoring uses impact signals such as dependents and weekly downloads.
The dashboard's **aggregate blast radius includes only CRITICAL and HIGH
findings**; MEDIUM and LOW domains never contribute to that aggregate. Do not
conflate the aggregate with per-finding scoring.

When explaining a finding, identify which data was observed, explain the
relevant score signals, and state uncertainty or lookup failures. Recommend
independent verification and responsible disclosure; do not claim exploitation,
takeover, or compromise without evidence. Do not invent sources or statistics.
