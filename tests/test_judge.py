"""Tests for judge.py — offline template, backend selection, gemini request shape.

Run:  python -m unittest tests.test_judge -v
Stdlib only (unittest), per INTERFACES.md.
"""

from __future__ import annotations

import json
import contextlib
import io
import os
import sys
import unittest
from email.message import Message
from urllib.error import HTTPError
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from judge import (  # noqa: E402
    GEMINI_FALLBACK_MODEL,
    GEMINI_MODEL,
    OLLAMA_MODEL,
    OLLAMA_URL,
    Judge,
)
import judge as judge_module  # noqa: E402

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

    def __init__(self, payload: dict, status: int = 200, headers=None):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = status
        self.headers = headers or {}

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
        contract = {"verdict", "narrative", "recommendation"}
        self.assertTrue(contract.issubset(self.result))
        for key in contract:
            value = self.result[key]
            self.assertIsInstance(value, str, f"{key} must be a string")
            self.assertTrue(value.strip(), f"{key} must be non-empty")
        self.assertEqual(self.result["model"], "offline-template")
        self.assertEqual(self.result["model_family"], "Offline template")
        self.assertFalse(self.result["live"])

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
            self.assertTrue({"verdict", "narrative", "recommendation"}.issubset(out))
            self.assertTrue(out["narrative"].strip())

    def test_empty_signals_still_produces_narrative(self):
        out = self.judge.narrate(
            {"domain": "example.net", "risk": 0, "severity": "LOW", "signals": []}
        )
        self.assertTrue({"verdict", "narrative", "recommendation"}.issubset(out))
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
        self.assertTrue({"verdict", "narrative", "recommendation"}.issubset(out))
        # The verdict must name the domain. Case-insensitive: a live model may
        # capitalise it ("Atlantis-software.net") while the template keeps the
        # raw lowercase form — either satisfies the contract.
        self.assertIn("atlantis-software.net", out["verdict"].lower())


class GeminiRequestTests(unittest.TestCase):
    """The POST body and headers must match the contract exactly."""

    def setUp(self):
        self.captured = {}

        def fake_urlopen(req, timeout=None):
            if req.get_method() == "GET":
                return FakeResponse({"models": [
                    {"name": f"models/{GEMINI_MODEL}", "supportedGenerationMethods": ["generateContent"]},
                    {"name": f"models/{GEMINI_FALLBACK_MODEL}", "supportedGenerationMethods": ["generateContent"]},
                ]})
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
            judge_module._MODEL_CACHE.clear()
            instance = Judge("gemini")
            instance._ollama_available = False
            return instance

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
        self.assertTrue({"verdict", "narrative", "recommendation"}.issubset(out))
        self.assertEqual(out["model"], GEMINI_MODEL)
        self.assertEqual(out["model_family"], "Gemma 4")
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
            if req.get_method() == "GET":
                return FakeResponse({"models": [
                    {"name": f"models/{GEMINI_MODEL}", "supportedGenerationMethods": ["generateContent"]},
                    {"name": f"models/{GEMINI_FALLBACK_MODEL}", "supportedGenerationMethods": ["generateContent"]},
                ]})
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

        judge = self._judge()
        with mock.patch("urllib.request.urlopen", side_effect=flaky):
            out = judge.narrate(SAMPLE_FINDING)

        self.assertEqual(len(attempts), 2)
        self.assertIn(GEMINI_MODEL, attempts[0])
        self.assertIn(GEMINI_FALLBACK_MODEL, attempts[1])
        self.assertEqual(out["verdict"], "HIGH: fallback used.")
        self.assertEqual(out["model"], GEMINI_FALLBACK_MODEL)
        self.assertEqual(judge._model_name(), GEMINI_FALLBACK_MODEL)

    def test_both_models_failing_falls_back_to_template(self):
        with mock.patch(
            "urllib.request.urlopen", side_effect=OSError("network down")
        ):
            out = self._judge().narrate(SAMPLE_FINDING)
        self.assertTrue({"verdict", "narrative", "recommendation"}.issubset(out))
        self.assertIn("not currently registered", out["narrative"])

    def test_malformed_model_output_does_not_raise(self):
        def weird(req, timeout=None):
            if req.get_method() == "GET":
                return FakeResponse({"models": [
                    {"name": f"models/{GEMINI_MODEL}", "supportedGenerationMethods": ["generateContent"]}
                ]})
            return FakeResponse(
                {"candidates": [{"content": {"parts": [{"text": "not json at all"}]}}]}
            )

        with mock.patch("urllib.request.urlopen", side_effect=weird):
            out = self._judge().narrate(SAMPLE_FINDING)
        self.assertTrue({"verdict", "narrative", "recommendation"}.issubset(out))
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
        self.assertTrue({"verdict", "narrative", "recommendation"}.issubset(out))
        self.assertEqual(out["model_family"], "Gemma 3")
        self.assertNotEqual(out["model_family"], "Gemma 4")


class GeminiReliabilityTests(unittest.TestCase):
    def setUp(self):
        judge_module._MODEL_CACHE.clear()

    def _judge(self, key="reliability-test-key", **kwargs):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": key}, clear=True):
            instance = Judge("gemini", **kwargs)
        instance._ollama_available = False
        return instance

    @staticmethod
    def _model_list(models=None, next_token=None):
        result = {"models": models or [
            {"name": f"models/{GEMINI_MODEL}", "supportedGenerationMethods": ["generateContent"]},
            {"name": f"models/{GEMINI_FALLBACK_MODEL}", "supportedGenerationMethods": ["generateContent"]},
        ]}
        if next_token:
            result["nextPageToken"] = next_token
        return result

    @staticmethod
    def _gemini_reply(text=None):
        text = text or json.dumps({
            "verdict": "HIGH: independently assessed.",
            "narrative": "The domain has current evidence. This response came from a model.",
            "recommendation": "Verify its registration.",
        })
        return FakeResponse({"candidates": [{"content": {"parts": [{"text": text}]}}]})

    @staticmethod
    def _http_error(req, status, retry_after=None):
        headers = Message()
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)
        return HTTPError(req.full_url, status, "fake response", headers, None)

    def test_list_models_paginates_filters_and_prefers_documented_ids(self):
        seen = {"gets": [], "posts": []}

        def fake(req, timeout=None):
            if req.get_method() == "GET":
                seen["gets"].append(req.full_url)
                if "pageToken" not in req.full_url:
                    return FakeResponse(self._model_list([
                        {"name": "models/gemma3:4b", "supportedGenerationMethods": ["generateContent"]},
                        {"name": "models/gemma-4-unknown-it", "supportedGenerationMethods": ["embedContent"]},
                        {"name": f"models/{GEMINI_FALLBACK_MODEL}", "supportedGenerationMethods": ["generateContent"]},
                    ], next_token="page-2"))
                return FakeResponse(self._model_list([
                    {"name": f"models/{GEMINI_MODEL}", "supportedGenerationMethods": ["generateContent"]},
                ]))
            seen["posts"].append(req.full_url)
            return self._gemini_reply()

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            result = self._judge().narrate(SAMPLE_FINDING)
        self.assertEqual(len(seen["gets"]), 2)
        self.assertIn("pageToken=page-2", seen["gets"][1])
        self.assertEqual(result["model"], GEMINI_MODEL)
        self.assertTrue(result["models_verified"])
        self.assertTrue(all("reliability-test-key" not in url for url in seen["gets"]))

    def test_list_models_is_cached_across_judges_with_same_key(self):
        gets = []

        def fake(req, timeout=None):
            if req.get_method() == "GET":
                gets.append(req.full_url)
                return FakeResponse(self._model_list())
            return self._gemini_reply()

        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "shared-cache-key"}, clear=True), mock.patch(
            "urllib.request.urlopen", side_effect=fake
        ):
            first = Judge("gemini")
            first._ollama_available = False
            first.narrate(SAMPLE_FINDING)
            second = Judge("gemini")
            second._ollama_available = False
            second.narrate(SAMPLE_FINDING)
        self.assertEqual(len(gets), 1)

    def test_successful_model_list_without_gemma4_does_not_guess_ids(self):
        called = []

        def fake(req, timeout=None):
            called.append(req.full_url)
            return FakeResponse({"models": [
                {"name": "models/gemma3:4b", "supportedGenerationMethods": ["generateContent"]},
            ]})

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            result = self._judge().narrate(SAMPLE_FINDING)
        self.assertEqual(len(called), 1)
        self.assertEqual(result["backend"], "offline")
        self.assertTrue(result["models_verified"])
        self.assertEqual(result["degraded_from"], "gemini")
        self.assertIn("no_supported_gemma4_models", [x["outcome"] for x in result["fallback_chain"]])

    def test_list_models_failure_uses_documented_ids_but_marks_unverified(self):
        calls = []

        def fake(req, timeout=None):
            calls.append(req.full_url)
            if req.get_method() == "GET":
                raise self._http_error(req, 403)
            return self._gemini_reply()

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            result = self._judge().narrate(SAMPLE_FINDING)
        self.assertEqual(result["model"], GEMINI_MODEL)
        self.assertFalse(result["models_verified"])
        self.assertTrue(any(url.endswith(":generateContent") for url in calls))

    def test_429_retries_and_honours_retry_after(self):
        calls = []
        sleeps = []

        def fake(req, timeout=None):
            if req.get_method() == "GET":
                return FakeResponse(self._model_list())
            calls.append(req.full_url)
            if len(calls) == 1:
                raise self._http_error(req, 429, retry_after=2)
            return self._gemini_reply()

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            result = self._judge(sleep=sleeps.append, jitter=lambda: 0).narrate(SAMPLE_FINDING)
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, [2.0])
        self.assertEqual([x["outcome"] for x in result["fallback_chain"] if x["model"] == GEMINI_MODEL], ["http_429", "success"])

    def test_list_models_retries_429_before_caching_verified_ids(self):
        gets = []
        sleeps = []

        def fake(req, timeout=None):
            if req.get_method() == "GET":
                gets.append(req.full_url)
                if len(gets) == 1:
                    raise self._http_error(req, 429, retry_after=1)
                return FakeResponse(self._model_list())
            return self._gemini_reply()

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            result = self._judge(sleep=sleeps.append, jitter=lambda: 0).narrate(SAMPLE_FINDING)
        self.assertEqual(len(gets), 2)
        self.assertEqual(sleeps, [1.0])
        self.assertTrue(result["models_verified"])

    def test_persistent_provider_errors_fall_through_to_offline_with_attempts(self):
        def fake(req, timeout=None):
            if req.get_method() == "GET":
                return FakeResponse(self._model_list())
            if GEMINI_MODEL in req.full_url:
                raise self._http_error(req, 429)
            if GEMINI_FALLBACK_MODEL in req.full_url or req.full_url == judge_module.OLLAMA_URL:
                raise self._http_error(req, 500)
            raise AssertionError("unexpected request")

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            j = self._judge(sleep=lambda _: None, jitter=lambda: 0)
            j._ollama_available = True
            result = j.analyze(SAMPLE_FINDING)
        self.assertEqual(result["backend"], "offline")
        self.assertEqual(result["model"], "offline-template")
        self.assertEqual(result["model_family"], "Offline template")
        self.assertEqual(result["degraded_from"], "gemini")
        chain = result["fallback_chain"]
        for model, outcome in ((GEMINI_MODEL, "http_429"), (GEMINI_FALLBACK_MODEL, "http_500"), (OLLAMA_MODEL, "http_500")):
            attempts = [entry for entry in chain if entry["model"] == model and entry["outcome"] == outcome]
            self.assertEqual(len(attempts), 3, model)

    def test_analysis_validates_own_severity_risk_and_scrubs_emails(self):
        output = {
            "evidence": ["ops@atlantis-software.net controls the domain"],
            "risk_reasoning": ["A takeover could redirect ops@atlantis-software.net"],
            "severity": " high ",
            "risk": 140,
            "confidence": "high",
            "disclosure_email": "Subject: Check\n\nHi ops@atlantis-software.net, migrate this mailbox.",
        }

        def fake(req, timeout=None):
            if req.get_method() == "GET":
                return FakeResponse(self._model_list())
            return self._gemini_reply(json.dumps(output))

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            result = self._judge().analyze(SAMPLE_FINDING)
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["risk"], 100)
        serialized = json.dumps(result)
        self.assertNotIn("ops@atlantis-software.net", serialized)
        self.assertEqual(result["model_family"], "Gemma 4")

    def test_invalid_analysis_severity_and_missing_risk_are_none(self):
        output = {
            "evidence": ["publicly observable evidence"],
            "disclosure_email": "Subject: Review\n\nPlease verify the domain.",
            "severity": "urgent",
        }

        def fake(req, timeout=None):
            if req.get_method() == "GET":
                return FakeResponse(self._model_list())
            return self._gemini_reply(json.dumps(output))

        with mock.patch("urllib.request.urlopen", side_effect=fake):
            result = self._judge().analyze(SAMPLE_FINDING)
        self.assertIsNone(result["severity"])
        self.assertIsNone(result["risk"])

    def test_secret_never_leaks_from_errors_or_diagnostics(self):
        secret = "recognizable-fake-api-key-987"

        def fail(req, timeout=None):
            raise OSError(f"transport failed with {secret}")

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("urllib.request.urlopen", side_effect=fail), mock.patch(
            "judge._ollama_reachable", return_value=False
        ), mock.patch.dict(os.environ, {"GEMINI_API_KEY": secret}, clear=True), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            j = Judge("gemini")
            result = j.analyze(SAMPLE_FINDING)
            description = j.describe()
            rendered = repr(j) + str(j) + json.dumps(result) + json.dumps(description)
            self.assertNotIn(secret, rendered + stdout.getvalue() + stderr.getvalue())
            self.assertTrue(result["disclosure_email"].strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
