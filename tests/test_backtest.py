"""Synthetic tests for the source-backed evaluation harness."""
import json
import unittest
from pathlib import Path

from tools.backtest import (
    at_least_severity,
    classification_metrics,
    evaluate_records,
)

ROOT = Path(__file__).resolve().parents[1]


class ClassificationMetricTests(unittest.TestCase):
    def test_precision_and_recall_math(self):
        result = classification_metrics([True, True, False], [True, False, True])
        self.assertEqual(result["confusion_matrix"], {"tp": 1, "fp": 1, "fn": 1, "tn": 0})
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertTrue(result["precision_defined"])
        self.assertTrue(result["recall_defined"])

    def test_zero_division_is_explicit(self):
        result = classification_metrics([True], [False])
        self.assertIsNone(result["precision"])
        self.assertFalse(result["precision_defined"])
        self.assertEqual(result["recall"], 0.0)
        self.assertTrue(result["recall_defined"])
        self.assertEqual(classification_metrics([], [])["n"], 0)

    def test_threshold_behavior(self):
        self.assertTrue(at_least_severity("HIGH", "HIGH"))
        self.assertTrue(at_least_severity("CRITICAL", "HIGH"))
        self.assertFalse(at_least_severity("MEDIUM", "HIGH"))
        self.assertTrue(at_least_severity("CRITICAL", "CRITICAL"))
        self.assertFalse(at_least_severity("HIGH", "CRITICAL"))
        self.assertFalse(at_least_severity("unknown", "HIGH"))

    def test_offline_template_is_not_an_independent_gemma_measurement(self):
        class OfflineJudge:
            reason = "No live model."

            def analyze(self, finding):
                return {
                    "backend": "offline", "live": False, "model": "offline-template",
                    "model_family": "offline", "severity": None,
                }

        records = [{
            "domain": "example.net", "label": "positive", "as_of": "2026-05-13T23:59:59Z",
            "package": None, "dependents": None, "downloads_week": None,
            "rdap": {"registered": True, "created": "2025-01-01T00:00:00Z", "expires": "2030-01-01T00:00:00Z"},
        }]
        result = evaluate_records(records, OfflineJudge())
        comparison = result["comparison"]["gemma_assisted"]
        self.assertFalse(comparison["measured"])
        self.assertIsNone(comparison["high_or_above"])
        self.assertIsNone(result["rows"][0]["gemma_assisted_high_or_above"])
        self.assertEqual(result["rows"][0]["gemma_assessment"]["model_id"], "offline-template")


class GemmaComparisonTests(unittest.TestCase):
    def test_live_gemma_severity_is_combined_with_rules(self):
        class LiveJudge:
            reason = None

            def analyze(self, finding):
                severity = "HIGH" if finding["domain"] == "model.net" else "LOW"
                return {
                    "backend": "gemini", "live": True,
                    "model": "gemma-4-31b-it", "model_family": "Gemma 4",
                    "provider_label": "Gemini API", "severity": severity,
                }

        common = {"as_of": "2026-05-13T23:59:59Z", "package": None, "dependents": None}
        records = [
            {**common, "domain": "model.net", "label": "positive", "downloads_week": None,
             "rdap": {"registered": True, "created": "2010-01-01T00:00:00Z", "expires": "2030-01-01T00:00:00Z"}},
            {**common, "domain": "rules.net", "label": "positive", "downloads_week": 100000,
             "rdap": {"registered": True, "created": "2026-05-12T00:00:00Z", "expires": "2027-05-12T00:00:00Z"}},
            {**common, "domain": "control.net", "label": "negative", "downloads_week": None,
             "rdap": {"registered": True, "created": "2010-01-01T00:00:00Z", "expires": "2030-01-01T00:00:00Z"}},
        ]
        result = evaluate_records(records, LiveJudge())
        comparison = result["comparison"]["gemma_assisted"]
        self.assertTrue(comparison["measured"])
        self.assertEqual(comparison["model_families"], ["Gemma 4"])
        self.assertTrue(result["rows"][0]["gemma_assisted_high_or_above"])
        self.assertEqual(result["rows"][1]["rule_severity"], "HIGH")
        self.assertEqual(result["rows"][1]["gemma_assessment"]["severity"], "LOW")
        self.assertTrue(result["rows"][1]["gemma_assisted_high_or_above"])
        self.assertFalse(result["rows"][2]["gemma_assisted_high_or_above"])


class ScorableSetTests(unittest.TestCase):
    def test_unscorable_incidents_are_excluded_from_metrics(self):
        records = [
            {
                "case_type": "incident",
                "domain": "incident.example",
                "label": "positive",
                "scorable": False,
                "scorable_reason": "No attack-time RDAP state.",
            },
            {
                "case_type": "control",
                "domain": "recent.example",
                "label": "negative",
                "as_of": "2026-10-11T00:00:00Z",
                "scorable": True,
                "rdap": {
                    "registered": True,
                    "created": "2024-03-15T10:02:38Z",
                    "expires": "2027-03-15T10:02:38Z",
                },
            },
            {
                "case_type": "control",
                "domain": "old.example",
                "label": "negative",
                "as_of": "2026-10-11T00:00:00Z",
                "scorable": True,
                "rdap": {
                    "registered": True,
                    "created": "2010-01-01T00:00:00Z",
                    "expires": "2030-01-01T00:00:00Z",
                },
            },
        ]
        result = evaluate_records(records)
        comparison = result["comparison"]
        self.assertEqual(comparison["record_count"], 3)
        self.assertEqual(comparison["set_size"], 2)
        self.assertEqual(comparison["positive_count"], 0)
        self.assertEqual(comparison["negative_count"], 2)
        self.assertEqual(comparison["documented_incident_count"], 1)
        self.assertEqual(comparison["scorable_incident_count"], 0)
        self.assertEqual(comparison["unscorable_incident_count"], 1)
        self.assertEqual(comparison["harder_negative_count"], 1)
        self.assertIsNone(result["rows"][0]["rule_score"])
        metrics = comparison["rules_only"]["high_or_above"]
        self.assertEqual(metrics["confusion_matrix"], {"tp": 0, "fp": 0, "fn": 0, "tn": 2})
        self.assertIsNone(metrics["precision"])
        self.assertIsNone(metrics["recall"])


class SourceDataSafetyTests(unittest.TestCase):
    def test_labeled_set_and_results_have_no_email_or_maintainer_fields(self):
        for path in (ROOT / "data/backtest/labeled_set.json", ROOT / "data/backtest/results.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            serialized = json.dumps(data)
            self.assertNotIn("@", serialized, str(path))

            def inspect(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        self.assertNotIn("maintainer", str(key).lower(), f"{path}: {key}")
                        inspect(child)
                elif isinstance(value, list):
                    for child in value:
                        inspect(child)

        inspect(data)

    def test_labeled_set_and_results_counts_match_scorable_rows(self):
        labeled = json.loads((ROOT / "data/backtest/labeled_set.json").read_text(encoding="utf-8"))
        results = json.loads((ROOT / "data/backtest/results.json").read_text(encoding="utf-8"))
        records = labeled["records"]
        scorable = [record for record in records if record.get("scorable") is not False]
        comparison = results["comparison"]

        self.assertEqual(results["record_count"], len(records))
        self.assertEqual(len(results["rows"]), len(records))
        self.assertEqual(results["set_size"], len(scorable))
        self.assertEqual(comparison["set_size"], len(scorable))
        self.assertEqual(results["positive_count"], sum(r["label"] == "positive" for r in scorable))
        self.assertEqual(results["negative_count"], sum(r["label"] == "negative" for r in scorable))
        self.assertEqual(
            results["documented_incident_count"],
            sum(record.get("case_type") == "incident" for record in records),
        )
        self.assertEqual(
            results["scorable_incident_count"],
            sum(r.get("case_type") == "incident" for r in scorable),
        )
        self.assertEqual(results["harder_negative_count"], 3)

        for record in scorable:
            self.assertTrue(record.get("source_urls"), record.get("domain"))
            self.assertTrue(record.get("fetched_at"), record.get("domain"))
            self.assertTrue(record.get("domain"), record)
            self.assertTrue(record.get("rdap", {}).get("registered"), record.get("domain"))
            self.assertTrue(record.get("rdap", {}).get("created"), record.get("domain"))
            self.assertTrue(record.get("rdap", {}).get("expires"), record.get("domain"))


if __name__ == "__main__":
    unittest.main()
