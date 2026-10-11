#!/usr/bin/env python3
"""Score the small, source-backed domain evaluation set without network data collection."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scorer import score_finding  # noqa: E402

DATA_PATH = ROOT / "data" / "backtest" / "labeled_set.json"
RESULTS_PATH = ROOT / "data" / "backtest" / "results.json"
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def at_least_severity(severity: str | None, threshold: str) -> bool:
    """Return whether a known severity meets the requested cutoff."""
    value = SEVERITY_RANK.get(str(severity or "").upper())
    cutoff = SEVERITY_RANK.get(str(threshold or "").upper())
    return value is not None and cutoff is not None and value >= cutoff


def classification_metrics(labels: list[bool], predictions: list[bool]) -> dict:
    """Calculate binary metrics; undefined precision/recall are reported as 0."""
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have the same length")
    tp = sum(bool(y) and bool(p) for y, p in zip(labels, predictions))
    fp = sum(not bool(y) and bool(p) for y, p in zip(labels, predictions))
    fn = sum(bool(y) and not bool(p) for y, p in zip(labels, predictions))
    tn = sum(not bool(y) and not bool(p) for y, p in zip(labels, predictions))
    precision_defined = tp + fp > 0
    recall_defined = tp + fn > 0
    return {
        "n": len(labels),
        "positives": sum(bool(value) for value in labels),
        "negatives": sum(not bool(value) for value in labels),
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": round(tp / (tp + fp), 4) if precision_defined else 0.0,
        "precision_defined": precision_defined,
        "recall": round(tp / (tp + fn), 4) if recall_defined else 0.0,
        "recall_defined": recall_defined,
    }


def _scorer_input(record: dict) -> dict:
    package = record.get("package")
    return {
        "domain": record["domain"],
        "packages": [package] if isinstance(package, str) and package else [],
        "dependents": record.get("dependents"),
        "downloads_week": record.get("downloads_week"),
        "rdap": record.get("rdap") or {},
    }


def _assessment_details(assessment: dict | None, judge_reason: str | None) -> dict:
    assessment = assessment if isinstance(assessment, dict) else {}
    backend = assessment.get("backend")
    model_id = assessment.get("model")
    family = assessment.get("model_family")
    severity = str(assessment.get("severity") or "").upper() or None
    live = assessment.get("live") is True
    is_gemma = isinstance(family, str) and family.lower().startswith("gemma ")
    independent = (
        live
        and backend in {"gemini", "ollama"}
        and bool(model_id)
        and model_id != "offline-template"
        and is_gemma
        and severity in SEVERITY_RANK
    )
    reason = assessment.get("reason") or assessment.get("degraded_from") or judge_reason
    if not independent and not reason:
        reason = "No live Gemma response with an independent severity was available."
    return {
        "measured": independent,
        "reason": None if independent else str(reason),
        "severity": severity,
        "risk": assessment.get("risk"),
        "model_id": model_id,
        "model_family": family,
        "backend": backend,
        "provider_label": assessment.get("provider_label"),
        "live": live,
    }


def _summarize_threshold(rows: list[dict], prediction_key: str) -> dict | None:
    if any(row[prediction_key] is None for row in rows):
        return None
    return classification_metrics(
        [row["label"] == "positive" for row in rows],
        [row[prediction_key] for row in rows],
    )


def evaluate_records(records: list[dict], judge=None, *, not_measured_reason: str | None = None) -> dict:
    """Score records and compare rules-only with an independent Gemma verdict."""
    rows = []
    judge_reason = not_measured_reason or getattr(judge, "reason", None)
    for record in records:
        scored_input = _scorer_input(record)
        as_of = dt.datetime.fromisoformat(record["as_of"].replace("Z", "+00:00"))
        rule = score_finding(scored_input, now=as_of)
        assessment = judge.analyze(scored_input) if judge is not None else None
        model = _assessment_details(assessment, judge_reason)
        rule_high = at_least_severity(rule["severity"], "HIGH")
        rule_critical = at_least_severity(rule["severity"], "CRITICAL")
        model_high = at_least_severity(model["severity"], "HIGH") if model["measured"] else None
        model_critical = at_least_severity(model["severity"], "CRITICAL") if model["measured"] else None
        rows.append({
            "domain": record["domain"],
            "label": record["label"],
            "as_of": record["as_of"],
            "rule_score": rule["risk"],
            "rule_severity": rule["severity"],
            "rule_signals": rule["signals"],
            "rules_only_high_or_above": rule_high,
            "rules_only_critical_only": rule_critical,
            "gemma_assessment": model,
            "gemma_assisted_high_or_above": (
                rule_high or model_high if model_high is not None else None
            ),
            "gemma_assisted_critical_only": (
                rule_critical or model_critical if model_critical is not None else None
            ),
        })

    labels = [row["label"] == "positive" for row in rows]
    positive_count = sum(labels)
    negative_count = len(rows) - positive_count
    measured = bool(rows) and all(row["gemma_assessment"]["measured"] for row in rows)
    reasons = [
        row["gemma_assessment"]["reason"]
        for row in rows
        if not row["gemma_assessment"]["measured"] and row["gemma_assessment"]["reason"]
    ]
    not_measured = None if measured else (
        reasons[0] if reasons else "No live Gemma response with an independent severity was available for every row."
    )
    model_ids = {row["gemma_assessment"]["model_id"] for row in rows if row["gemma_assessment"]["model_id"]}
    families = {row["gemma_assessment"]["model_family"] for row in rows if row["gemma_assessment"]["model_family"]}
    backends = {row["gemma_assessment"]["backend"] for row in rows if row["gemma_assessment"]["backend"]}
    comparison = {
        "set_size": len(rows),
        "positive_count": positive_count,
        "negative_count": negative_count,
        "thresholds": {
            "high_or_above": "severity >= HIGH",
            "critical_only": "severity >= CRITICAL",
        },
        "rules_only": {
            "measured": True,
            "high_or_above": _summarize_threshold(rows, "rules_only_high_or_above"),
            "critical_only": _summarize_threshold(rows, "rules_only_critical_only"),
        },
        "gemma_assisted": {
            "measured": measured,
            "reason": not_measured,
            "model_ids": sorted(model_ids) if measured else [],
            "model_families": sorted(families) if measured else [],
            "backends": sorted(backends) if measured else [],
            "high_or_above": _summarize_threshold(rows, "gemma_assisted_high_or_above") if measured else None,
            "critical_only": _summarize_threshold(rows, "gemma_assisted_critical_only") if measured else None,
        },
    }
    return {"comparison": comparison, "rows": rows}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DATA_PATH, help="labeled set JSON")
    parser.add_argument("--output", type=Path, default=RESULTS_PATH, help="results JSON destination")
    parser.add_argument(
        "--judge", choices=("auto", "gemini", "ollama", "offline"), default=None,
        help="select a judge; explicitly choosing auto allows local Ollama when no API key is set",
    )
    parser.add_argument(
        "--offline-only", action="store_true",
        help="do not call Gemini or Ollama; this is the default when GEMINI_API_KEY is absent",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    with args.input.open(encoding="utf-8") as stream:
        dataset = json.load(stream)
    records = dataset.get("domains") or []
    has_key = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    if args.offline_only:
        backend = "offline"
        default_reason = "Offline-only requested; no independent model severity was measured."
    elif args.judge is None and not has_key:
        backend = "offline"
        default_reason = (
            "GEMINI_API_KEY is not set; defaulted to offline-only. Local Ollama was not probed."
        )
    else:
        backend = args.judge or "auto"
        default_reason = None

    from judge import Judge  # local import keeps metric helpers independent of provider code

    judge = Judge(backend=backend)
    not_measured_reason = default_reason or getattr(judge, "reason", None)
    evaluated = evaluate_records(records, judge, not_measured_reason=not_measured_reason)
    positives = sum(record.get("label") == "positive" for record in records)
    result = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "set_size": len(records),
        "positive_count": positives,
        "negative_count": len(records) - positives,
        "score_as_of": dataset.get("score_as_of"),
        "judge_requested": args.judge or ("offline-only-default" if backend == "offline" else "auto"),
        "comparison": evaluated["comparison"],
        "rows": evaluated["rows"],
        "caveats": list(dataset.get("caveats") or []) + [
            "Positives are hand-selected documented cases, so selection bias is substantial.",
            "The rules score is reconstructed as of the day before the first malicious publish, but current download counts and current RDAP snapshots are not historical snapshots.",
            "Precision and recall describe only this labeled set of three records and are not estimates of ecosystem-wide performance.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rules = result["comparison"]["rules_only"]
    high = rules["high_or_above"]
    critical = rules["critical_only"]
    print(f"Backtest N={len(records)} (positive={positives}, negative={len(records) - positives})")
    print(f"Rules >= HIGH: precision={high['precision']:.4f}, recall={high['recall']:.4f}")
    print(f"Rules CRITICAL-only: precision={critical['precision']:.4f}, recall={critical['recall']:.4f}")
    model_result = result["comparison"]["gemma_assisted"]
    if model_result["measured"]:
        print("Gemma-assisted: measured; model=" + ", ".join(model_result["model_ids"]))
    else:
        print("Gemma-assisted: NOT MEASURED (" + str(model_result["reason"]) + ")")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
