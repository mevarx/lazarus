#!/usr/bin/env python
"""Backtest: does the model's independent triage beat the rules-only baseline?

The DigitalOcean track asks whether the open-weight model is load-bearing or
decorative. This answers it with numbers. It runs Gemma's triage (raw evidence,
no scorer verdict) and the rules-only baseline over the same findings, then
compares their rankings against the known incident.

Ground truth: atlantis-software.net is the one domain we KNOW was taken over
(the node-ipc compromise, May 2026). A good triage ranks it at or near the top
and does not rank known-safe long-held domains above it.

Usage:
    python tools/backtest.py            # uses the seeded run
    python tools/backtest.py --ollama   # force local backend
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from judge import Judge  # noqa: E402

# The one confirmed compromise in the corpus (RDAP-verified, May 2026 incident).
KNOWN_INCIDENT = "atlantis-software.net"
# Long-held, active-maintainer domains that must NOT outrank the incident.
KNOWN_SAFE = {"microsoft.com", "algolia.com", "github.com"}


def rank_distance(a: list[str], b: list[str]) -> int:
    """Sum of absolute position differences (Kendall-ish, simple and readable)."""
    pos_b = {d: i for i, d in enumerate(b)}
    return sum(abs(i - pos_b.get(d, len(b))) for i, d in enumerate(a))


def top_k_overlap(a: list[str], b: list[str], k: int) -> float:
    """Fraction of the top-k shared between two rankings."""
    sa, sb = set(a[:k]), set(b[:k])
    return len(sa & sb) / k if k else 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ollama", action="store_true", help="force local backend")
    ap.add_argument("--run", default=str(BASE / "data" / "cached_run.json"))
    args = ap.parse_args()

    run = json.loads(Path(args.run).read_text(encoding="utf-8"))
    findings = [f for f in run.get("findings", []) if f.get("domain")]
    if not findings:
        print("no findings to backtest")
        return 1

    judge = Judge(backend="ollama" if args.ollama else "auto")
    print(f"backend: {judge.describe()}")
    print(f"findings: {len(findings)}")

    # --- rules-only baseline: the scorer's own risk ordering ---
    baseline = sorted(findings, key=lambda f: -int(f.get("risk") or 0))
    baseline_rank = [f["domain"].lower() for f in baseline]

    # --- model triage: raw evidence, no scorer verdict ---
    triage = judge.triage(findings)
    model_rank = triage.get("ranking", [])

    print("\n=== RULES-ONLY BASELINE ===")
    for i, d in enumerate(baseline_rank, 1):
        f = next(x for x in findings if x["domain"].lower() == d)
        print(f"  {i}. {d:28s} risk={f.get('risk')}")

    print(f"\n=== MODEL TRIAGE ({'live' if triage.get('live') else 'offline fallback'}) ===")
    for i, d in enumerate(model_rank, 1):
        a = next((x for x in triage.get("assessments", []) if x["domain"] == d), {})
        print(f"  {i}. {d:28s} model_risk={a.get('model_risk')} conf={a.get('confidence')}")
        if a.get("reasoning"):
            print(f"       {a['reasoning'][:120]}")

    # --- comparison ---
    print("\n=== COMPARISON ===")
    incident_pos_baseline = baseline_rank.index(KNOWN_INCIDENT) + 1 if KNOWN_INCIDENT in baseline_rank else -1
    incident_pos_model = model_rank.index(KNOWN_INCIDENT) + 1 if KNOWN_INCIDENT in model_rank else -1
    print(f"  {KNOWN_INCIDENT} (known compromise):")
    print(f"    baseline rank: {incident_pos_baseline}/{len(baseline_rank)}")
    print(f"    model rank:    {incident_pos_model}/{len(model_rank)}")
    print(f"  ranking agreement: top-3 overlap {top_k_overlap(model_rank, baseline_rank, 3):.0%}, "
          f"total position distance {rank_distance(model_rank, baseline_rank)}")

    safe_above_baseline = [d for d in baseline_rank if d in KNOWN_SAFE and baseline_rank.index(d) < incident_pos_baseline]
    safe_above_model = [d for d in model_rank if d in KNOWN_SAFE and model_rank.index(d) < incident_pos_model]
    print(f"  known-safe domains ranked ABOVE the incident:")
    print(f"    baseline: {safe_above_baseline or 'none'}")
    print(f"    model:    {safe_above_model or 'none'}")

    # --- verdict ---
    better = incident_pos_model <= incident_pos_baseline and not safe_above_model
    same = incident_pos_model == incident_pos_baseline
    print("\n=== VERDICT ===")
    if not triage.get("live"):
        print("  model offline — ran the rules-only baseline as its own triage "
              "(proves the fallback works, but this is NOT a live-model result).")
    elif better:
        print(f"  model triage is BETTER: incident ranked {incident_pos_model} "
              f"vs baseline {incident_pos_baseline}, no safe domain above it.")
    elif same:
        print(f"  model AGREES with the baseline (both rank the incident {incident_pos_model}). "
              "The model corroborates rather than improves — still evidence it reasons correctly.")
    else:
        print(f"  model is WORSE here: incident ranked {incident_pos_model} vs baseline "
              f"{incident_pos_baseline}. Honest result — small models can misfire; "
              "that's why the baseline is the fallback.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
