"""Contract tests for comparison payloads and their TTL cache."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import compare  # noqa: E402


FINDING = {
    "domain": "packages.example.test",
    "risk": 86,
    "severity": "CRITICAL",
    "signals": ["domain unregistered", "MX present"],
    "reasoning": ["unregistered with live mail"],
    "maintainers": ["ops@packages.example.test", "Example Maintainer"],
    "packages": ["package-a"],
    "rdap": {"registered": False, "created": None},
}


def assessment(severity="CRITICAL", backend="gemini", model="gemma-4-31b-it", **updates):
    result = {
        "evidence": ["domain registration is missing"],
        "risk_reasoning": ["mail may be redirected"],
        "confidence": "medium",
        "disclosure_email": "Subject: Review\n\nPlease verify the domain.",
        "severity": severity,
        "risk": 87,
        "backend": backend,
        "live": backend in {"gemini", "ollama"},
        "model": model,
        "model_family": "Gemma 4" if model and "gemma-4" in model else "Unknown",
        "provider_label": "Gemma 4 · gemma-4-31b-it · Gemini API",
        "degraded_from": None,
        "fallback_chain": [],
        "models_verified": True,
    }
    result.update(updates)
    return result


class FakeJudge:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def analyze(self, finding):
        self.calls += 1
        return dict(self.result)

    def describe(self):
        return {"backend": self.result.get("backend"), "models_verified": self.result.get("models_verified")}


class CompareFindingTests(unittest.TestCase):
    def setUp(self):
        compare.clear_cache()

    def test_payload_has_exact_public_sections_and_utc_timestamp(self):
        result = compare.compare_finding(FINDING, FakeJudge(assessment()))
        self.assertEqual(set(result), {"domain", "rules", "gemma", "agreement", "provider", "generated_at"})
        self.assertEqual(set(result["rules"]), {"risk", "severity", "signals", "reasoning"})
        self.assertEqual(set(result["gemma"]), {"available", "independent", "severity", "risk", "evidence", "risk_reasoning", "confidence", "disclosure_email"})
        self.assertEqual(set(result["provider"]), {"backend", "model", "family", "label", "live", "degraded_from", "fallback_chain", "models_verified"})
        self.assertTrue(result["generated_at"].endswith("Z"))
        self.assertEqual(datetime.fromisoformat(result["generated_at"].replace("Z", "+00:00")).utcoffset().total_seconds(), 0)
        self.assertEqual(result["agreement"]["status"], "agree")

    def test_severity_agreement_matrix(self):
        cases = (
            ("CRITICAL", "agree"),
            ("HIGH", "partial"),
            ("MEDIUM", "disagree"),
            ("LOW", "disagree"),
        )
        for model_severity, expected in cases:
            with self.subTest(model_severity=model_severity):
                compare.clear_cache()
                result = compare.compare_finding(FINDING, FakeJudge(assessment(model_severity)))
                self.assertEqual(result["agreement"]["status"], expected)

    def test_offline_template_is_not_an_independent_assessment(self):
        offline = assessment(
            severity=None,
            backend="offline",
            model="offline-template",
            live=False,
            model_family="Offline template",
            provider_label="Offline template · no model ran",
            models_verified=None,
        )
        result = compare.compare_finding(FINDING, FakeJudge(offline))
        self.assertTrue(result["gemma"]["available"])
        self.assertFalse(result["gemma"]["independent"])
        self.assertEqual(result["agreement"]["status"], "not_independent")
        self.assertEqual(result["provider"]["family"], "Offline template")

    def test_missing_severity_or_failed_call_is_unavailable(self):
        result = compare.compare_finding(FINDING, FakeJudge(assessment(None)))
        self.assertEqual(result["agreement"]["status"], "unavailable")

        class FailedJudge:
            def analyze(self, finding):
                raise RuntimeError("internal detail")

            def describe(self):
                return {"backend": "gemini", "live": True}

        compare.clear_cache()
        failed = compare.compare_finding(FINDING, FailedJudge())
        self.assertEqual(failed["agreement"]["status"], "unavailable")
        self.assertNotIn("internal detail", str(failed))

    def test_missing_model_provenance_is_never_called_gemma4(self):
        unknown = assessment(
            backend="gemini",
            model=None,
            model_family="Gemma 4",
            provider_label="Gemma 4 · guessed · Gemini API",
        )
        result = compare.compare_finding(FINDING, FakeJudge(unknown))
        self.assertFalse(result["gemma"]["independent"])
        self.assertEqual(result["provider"]["family"], "Unknown")
        self.assertEqual(result["provider"]["label"], "Unverified provenance · model not recorded")
        self.assertTrue(result["provider"]["live"])
        self.assertEqual(result["agreement"]["status"], "unavailable")

    def test_gemma3_provider_is_not_labeled_gemma4(self):
        ollama = assessment(
            severity="HIGH",
            backend="ollama",
            model="gemma3:4b",
            model_family="Gemma 3",
            provider_label="Gemma 3 · gemma3:4b · local Ollama",
            models_verified=None,
        )
        result = compare.compare_finding(FINDING, FakeJudge(ollama))
        self.assertEqual(result["provider"]["family"], "Gemma 3")
        self.assertIn("Gemma 3", result["provider"]["label"])
        self.assertNotIn("Gemma 4", result["provider"]["label"])

    def test_email_addresses_and_maintainer_strings_are_scrubbed(self):
        output = assessment(
            evidence=["ops@packages.example.test and Example Maintainer own this."],
            risk_reasoning=["Send details to ops@packages.example.test"],
            disclosure_email="Hi Example Maintainer (ops@packages.example.test), migrate soon.",
        )
        result = compare.compare_finding(FINDING, FakeJudge(output))
        text = str(result["gemma"])
        self.assertNotIn("ops@packages.example.test", text)
        self.assertNotIn("Example Maintainer", text)
        self.assertIn("[redacted", text)

    def test_compare_finding_never_raises_on_invalid_input(self):
        offline = assessment(
            severity=None, backend="offline", model="offline-template", live=False,
            model_family="Offline template", models_verified=None,
        )
        result = compare.compare_finding(None, judge=FakeJudge(offline))
        self.assertEqual(result["domain"], "")
        self.assertEqual(result["agreement"]["status"], "not_independent")


class ComparisonCacheTests(unittest.TestCase):
    def setUp(self):
        compare.clear_cache()

    def test_cache_expires_using_injected_clock(self):
        now = [10.0]
        cache = compare.ComparisonCache(ttl=5, clock=lambda: now[0])
        cache.set(FINDING, {"value": [1]})
        retrieved = cache.get(FINDING)
        retrieved["value"].append(2)
        self.assertEqual(cache.get(FINDING), {"value": [1]})
        now[0] = 15.0
        self.assertIsNone(cache.get(FINDING))

    def test_cache_key_changes_when_finding_evidence_changes(self):
        cache = compare.ComparisonCache()
        other = {**FINDING, "rdap": {"registered": True}}
        cache.set(FINDING, {"cached": True})
        self.assertIsNone(cache.get(other))

    def test_compare_finding_reuses_cached_model_result(self):
        cached = compare.ComparisonCache(ttl=300)
        judge = FakeJudge(assessment())
        with mock.patch.object(compare, "_CACHE", cached):
            first = compare.compare_finding(FINDING, judge)
            second = compare.compare_finding(FINDING, judge)
        self.assertEqual(judge.calls, 1)
        self.assertEqual(first["provider"], second["provider"])

    def test_compare_all_honours_limit_and_reuses_judge(self):
        judge = FakeJudge(assessment())
        results = compare.compare_all([FINDING, {**FINDING, "domain": "other.example"}], judge=judge, limit=1)
        self.assertEqual(len(results), 1)
        self.assertEqual(judge.calls, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
