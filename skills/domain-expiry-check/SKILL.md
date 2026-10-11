---
name: domain-expiry-check
description: Check RDAP registration and expiry signals for npm or PyPI maintainer email domains, and explain the limits of those signals.
license: MIT
---

# Domain Expiry Check

Use this skill to review a Lazarus finding about a maintainer email domain. A
risk flag is a lead for verification, not evidence that an account or package
has been compromised.

## Workflow

1. Run `python lazarus.py check package-lock.json --json` (or pass
   `package.json`) to inspect dependencies. This makes live npm/RDAP requests;
   the CLI does not provide an offline replay mode.
2. For one bare domain, run
   `python skills/domain-triage/scripts/check_domain.py example.net` from the
   repository root. This helper uses RDAP online and accepts no email address.
3. Check lookup errors or missing registration dates against an independent
   source before drawing a conclusion. RDAP coverage and returned events vary.

The one-domain helper scores only unregistered status (+60), creation within
180 days (+50), expiry within 90 days (+35), and expiry within 30 days (+15
additional). It does not include package dependents, weekly downloads,
maintainer dormancy, or MX signals from the full scanner. The full scanner's
weights and severity bands are documented in the `domain-triage` skill.

The dashboard's aggregate blast radius counts **CRITICAL and HIGH findings
only**; it excludes MEDIUM and LOW findings. This aggregate is distinct from
per-finding scoring signals such as dependent count and weekly downloads.

The helper returns JSON and exits 0 after a successful lookup, 1 on an RDAP
failure, or 2 for a missing or invalid domain argument. The main CLI exits 0
with no CRITICAL findings, 1 with at least one CRITICAL finding, and 2 for
usage or input errors.
