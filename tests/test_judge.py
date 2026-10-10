"""Tests for judge.py — offline template, backend selection, gemini request shape.

Run:  python -m unittest tests.test_judge -v
Stdlib only (unittest), per INTERFACES.md.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from judge import (  # noqa: E402
    GEMINI_FALLBACK_MODEL,
    GEMINI_MODEL,
    OLLAMA_MODEL,
    OLLAMA_URL,
    Judge,
)

SAMPLE_FINDING = {
    "domain": "atlantis-software.net",
    "packages": ["swift-validator", "swift-core"],
    "dependents": 1420,
    "downloads_week": 88400,
    "rdap": {"registered": False, "created": None, "expires": None, "status": []},
    "maintainers": ["ops@atlantis-software.net"],
    "risk": 90,
    "severity": "CRITICAL",
    "signals": [
        "domain unregistered",
        "dependents >= 1000",
        "MX present + re-registered",
    ],
    "reasoning": ["unregistered domain with live MX"],
}


class FakeResponse:
    """Minimal stand-in for the object urlopen returns."""

    def __init__(self, payload: dict, status: int = 200):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class OfflineTemplateTests(unittest.TestCase):
    """The offline path is the demo's insurance policy — it must be perfect."""

    def setUp(self):
        self.judge = Judge("offline")
        self.result = self.judge.narrate(SAMPLE_FINDING)

    def test_returns_exact_contract_keys(self):
        self.assertEqual(
            set(self.result), {"verdict", "narrative", "recommendation"}
        )
        for key, value in self.result.items():
            self.assertIsInstance(value, str, f"{key} must be a string")
            self.assertTrue(value.strip(), f"{key} must be non-empty")

    def test_verdict_is_one_line(self):
        self.assertNotIn("\n", self.result["verdict"])
        self.assertLessEqual(len(self.result["verdict"]), 200)
        self.assertIn("atlantis-software.net", self.result["verdict"])
        self.assertIn("CRITICAL", self.result["verdict"])

    def test_narrative_is_two_to_four_sentences(self):
        import re

        sentences = [
            s for s in re.split(r"(?<=[.!?])\s+", self.result["narrative"]) if s.strip()
        ]
        self.assertGreaterEqual(
            len(sentences), 2, f"narrative too short: {self.result['narrative']!r}"
        )
        self.assertLessEqual(
            len(sentences), 4, f"narrative too long: {self.result['narrative']!r}"
        )

    def test_narrative_uses_finding_facts(self):
        text = self.result["narrative"]
        self.assertIn("atlantis-software.net", text)
        self.assertIn("swift-validator", text)
        self.assertIn("1,420", text, "dependents should be formatted with a comma")
        self.assertIn("88,400", text, "weekly downloads should be formatted")

    def test_narrative_explains_unregistered_domain(self):
        self.assertIn("not currently registered", self.result["narrative"])

    def test_recommendation_matches_severity(self):
        self.assertIn("takeover window", self.result["recommendation"])

    def test_deterministic(self):
        again = self.judge.narrate(dict(SAMPLE_FINDING))
        self.assertEqual(self.result, again)

    def test_never_raises_on_garbage(self):
        for bad in ({}, None, [], "string", {"domain": None, "signals": "oops"}):
            out = self.judge.narrate(bad)
            self.assertEqual(set(out), {"verdict", "narrative", "recommendation"})
            self.assertTrue(out["narrative"].strip())

    def test_empty_signals_still_produces_narrative(self):
        out = self.judge.narrate(
            {"domain": "example.net", "risk": 0, "severity": "LOW", "signals": []}
        )
        self.assertEqual(set(out), {"verdict", "narrative", "recommendation"})
        self.assertIn("example.net", out["narrative"])

    def test_is_live_false_offline(self):
        self.assertFalse(self.judge.is_live())


class BackendSelectionTests(unittest.TestCase):
    """is_live() and backend resolution — auto / gemini / ollama / offline."""

    def test_offline_is_not_live(self):
        self.assertFalse(Judge("offline").is_live())

    def test_gemini_backend_is_live_with_key(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-123"}):
            judge = Judge("gemini")
            self.assertTrue(judge.is_live())
            self.assertEqual(judge.backend, "gemini")

    def test_gemini_backend_without_key_falls_back_offline(self):
        env = dict(os.environ)
        env.pop("GEMINI_API_KEY", None)
        with mock.patch.dict(os.environ, env, clear=True):
            judge = Judge("gemini")
            self.assertFalse(judge.is_live())
            self.assertEqual(judge.backend, "offline")
            self.assertIn("GEMINI_API_KEY", judge.reason or "")

    def test_auto_picks_gemini_when_key_present(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key-123"}):
            judge = Judge("auto")
            self.assertEqual(judge.backend, "gemini")
            self.assertTrue(judge.is_live())

    def test_auto_picks_ollama_when_no_key(self):
        env = dict(os.environ)
        env.pop("GEMINI_API_KEY", None)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch(
            "judge._ollama_reachable", return_value=True
        ):
            judge = Judge("auto")
            self.assertEqual(judge.backend, "ollama")
            self.assertTrue(judge.is_live())

    def test_auto_falls_back_to_offline_when_nothing_reachable(self):
        env = dict(os.environ)
        env.pop("GEMINI_API_KEY", None)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch(
            "judge._ollama_reachable", return_value=False
        ):
            judge = Judge("auto")
            self.assertEqual(judge.backend, "offline")
            self.assertFalse(judge.is_live())

    def test_explicit_ollama_backend_unreachable_is_offline(self):
        with mock.patch("judge._ollama_reachable", return_value=False):
            judge = Judge("ollama")
            self.assertFalse(judge.is_live())
            self.assertEqual(judge.backend, "offline")

    def test_invalid_backend_rejected(self):
        with self.assertRaises(ValueError):
            Judge("banana")

    def test_narrate_offline_judge_matches_template(self):
        judge = Judge("auto")  # resolves per environment; narrate must not raise
        out = judge.narrate(SAMPLE_FINDING)
        self.assertEqual(set(out), {"verdict", "narrative", "recommendation"})
        self.assertIn("atlantis-software.net", out["verdict"])


class GeminiRequestTests(unittest.TestCase):
    """The POST body and headers must match the contract exactly."""

    def setUp(self):
        self.captured = {}

        def fake_urlopen(req, timeout=None):
            self.captured["url"] = req.full_url
            self.captured["method"] = req.get_method()
            self.captured["headers"] = dict(req.header_items())
            self.captured["body"] = json.loads(req.data.decode("utf-8"))
            self.captured["timeout"] = timeout
            return FakeResponse(
                {
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": json.dumps(
                                            {
                                                "verdict": "CRITICAL: atlantis-software.net unregistered.",
                                                "narrative": (
                                                    "The domain atlantis-software.net is not registered. "
                                                    "Anyone can claim it. "
                                                    "It serves 1,420 dependents. "
                                                    "Password resets would be interceptable."
                                                ),
                                                "recommendation": "Register the domain today.",
                                            }
                                        )
                                    }
                                ]
                            }
                        }
                    ]
                }
            )

        self.patcher_urlopen = mock.patch(
            "urllib.request.urlopen", side_effect=fake_urlopen
        )
        self.patcher_urlopen.start()
        self.addCleanup(self.patcher_urlopen.stop)

    def _judge(self):
        env = dict(os.environ)
        env["GEMINI_API_KEY"] = "test-key-123"
        with mock.patch.dict(os.environ, env, clear=True):
            return Judge("gemini")

    def test_request_targets_default_model(self):
        self._judge().narrate(SAMPLE_FINDING)
        self.assertIn(GEMINI_MODEL, self.captured["url"])
        self.assertTrue(self.captured["url"].endswith(":generateContent"))
        self.assertTrue(
            self.captured["url"].startswith(
                "https://generativelanguage.googleapis.com/v1beta/models/"
            )
        )

    def test_request_method_and_body_shape(self):
        self._judge().narrate(SAMPLE_FINDING)
        self.assertEqual(self.captured["method"], "POST")
        self.assertEqual(
            list(self.captured["body"]), ["contents"]
        )
        contents = self.captured["body"]["contents"]
        self.assertIsInstance(contents, list)
        self.assertEqual(len(contents), 1)
        self.assertEqual(list(contents[0]), ["parts"])
        parts = contents[0]["parts"]
        self.assertEqual(len(parts), 1)
        self.assertEqual(list(parts[0]), ["text"])
        self.assertIsInstance(parts[0]["text"], str)
        self.assertIn("atlantis-software.net", parts[0]["text"])

    def test_request_api_key_header(self):
        self._judge().narrate(SAMPLE_FINDING)
        # urllib capitalizes header keys ("Content-Type" -> "Content-type"),
        # so compare case-insensitively.
        headers = {k.lower(): v for k, v in self.captured["headers"].items()}
        self.assertEqual(headers.get("x-goog-api-key"), "test-key-123")
        self.assertEqual(headers.get("content-type"), "application/json")

    def test_gemini_response_is_normalised_to_contract(self):
        out = self._judge().narrate(SAMPLE_FINDING)
        self.assertEqual(set(out), {"verdict", "narrative", "recommendation"})
        self.assertNotIn("\n", out["verdict"])
        import re

        sentences = [
            s for s in re.split(r"(?<=[.!?])\s+", out["narrative"]) if s.strip()
        ]
        self.assertGreaterEqual(len(sentences), 2)
        self.assertLessEqual(len(sentences), 4)
        self.assertIn("Register the domain", out["recommendation"])

    def test_fallback_model_used_when_primary_fails(self):
        attempts = []

        def flaky(req, timeout=None):
            attempts.append(req.full_url)
            if GEMINI_FALLBACK_MODEL in req.full_url:
                return FakeResponse(
                    {
                        "candidates": [
                            {
                                "content": {
                                    "parts": [
                                        {
                                            "text": json.dumps(
                                                {
                                                    "verdict": "HIGH: fallback used.",
                                                    "narrative": (
                                                        "The primary model was unavailable. "
                                                        "The fallback model produced this. "
                                                        "Risk remains high."
                                                    ),
                                                    "recommendation": "Re-run the scan.",
                                                }
                                            )
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                )
            raise OSError("primary model down")

        with mock.patch("urllib.request.urlopen", side_effect=flaky):
            out = self._judge().narrate(SAMPLE_FINDING)

        self.assertEqual(len(attempts), 2)
        self.assertIn(GEMINI_MODEL, attempts[0])
        self.assertIn(GEMINI_FALLBACK_MODEL, attempts[1])
        self.assertEqual(out["verdict"], "HIGH: fallback used.")

    def test_both_models_failing_falls_back_to_template(self):
        with mock.patch(
            "urllib.request.urlopen", side_effect=OSError("network down")
        ):
            out = self._judge().narrate(SAMPLE_FINDING)
        self.assertEqual(set(out), {"verdict", "narrative", "recommendation"})
        self.assertIn("not currently registered", out["narrative"])

    def test_malformed_model_output_does_not_raise(self):
        def weird(req, timeout=None):
            return FakeResponse(
                {"candidates": [{"content": {"parts": [{"text": "not json at all"}]}}]}
            )

        with mock.patch("urllib.request.urlopen", side_effect=weird):
            out = self._judge().narrate(SAMPLE_FINDING)
        self.assertEqual(set(out), {"verdict", "narrative", "recommendation"})
        self.assertTrue(out["narrative"].strip())


class OllamaRequestTests(unittest.TestCase):
    """The local path is the one that will actually run on this machine."""

    def _judge(self):
        env = dict(os.environ)
        env.pop("GEMINI_API_KEY", None)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch(
            "judge._ollama_reachable", return_value=True
        ):
            return Judge("ollama")

    def test_request_body_shape_and_model(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return FakeResponse(
                {"response": "The domain is unregistered and at risk of takeover."}
            )

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = self._judge().narrate(SAMPLE_FINDING)

        self.assertEqual(captured["url"], OLLAMA_URL)
        self.assertEqual(captured["body"]["model"], OLLAMA_MODEL)
        self.assertIs(captured["body"]["stream"], False)
        self.assertIn("atlantis-software.net", captured["body"]["prompt"])
        self.assertEqual(set(out), {"verdict", "narrative", "recommendation"})
        self.assertTrue(out["narrative"].strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
