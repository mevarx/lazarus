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
        self.assertEqual(result["precision"], 0.0)
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


if __name__ == "__main__":
    unittest.main()
