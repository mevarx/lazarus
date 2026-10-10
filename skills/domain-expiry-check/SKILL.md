---
name: domain-expiry-check
description: Check a maintainer email domain's RDAP registration and expiry, then score takeover risk. Use when auditing npm/PyPI maintainer domains for expired or re-registered addresses.
license: MIT
---

# Domain Expiry Check

Audits one maintainer email domain for takeover risk and prints a verdict.

## What it does

1. Takes a domain from the first argument (or stdin).
2. Resolves registration via the IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`).
3. Applies the deterministic scoring rules from `INTERFACES.md` (scorer.py):
   unregistered domain, recent re-registration, near expiry, dependent count,
   weekly downloads, maintainer dormancy.
4. Prints a one-line verdict plus the signals that fired.

## Usage

    python scripts/expiry_check.py example.com
    echo example.com | python scripts/expiry_check.py

## Notes

- Network optional: without connectivity the script reports `registered: unknown`
  and scores conservatively rather than guessing.
- Free-mail providers (gmail.com, proton.me, ...) are out of scope — they cannot
  expire and cannot be squatted.
- Exit code is 0 for LOW/MEDIUM and 1 for HIGH/CRITICAL, so it composes into
  CI gates.
