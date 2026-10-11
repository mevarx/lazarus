"""judge.py — plain-English risk narrative for domain-takeover findings.

Part of the Lazarus pipeline. The scorer decides *how bad* a finding is
numerically; the Judge explains it to a human package maintainer.

Backends (selected in ``__init__``):

  auto     GEMINI_API_KEY set -> gemini; else localhost:11434 reachable
           -> ollama; else offline
  gemini   Google Generative Language API (Gemma 4 models)
  ollama   Local Ollama server (gemma3:4b)
  offline  Deterministic template built from the finding's signals

``narrate()`` NEVER raises — any network/parse failure degrades to the
offline template so the demo always produces a narrative.

Stdlib only (per INTERFACES.md: ``python`` 3.11, not ``python3``).
"""

from __future__ import annotations

import json
import hashlib
import http.client
import os
import random
import re
import socket
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

__all__ = [
    "Judge",
    "GEMINI_BASE_URL",
    "GEMINI_MODEL",
    "GEMINI_FALLBACK_MODEL",
    "OLLAMA_URL",
    "OLLAMA_MODEL",
    "SIGNAL_WEIGHTS",
]

# --- backend endpoints -------------------------------------------------------

GEMINI_BASE_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
# Google documents these Gemini API IDs at https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api.
GEMINI_MODEL = "gemma-4-31b-it"
GEMINI_FALLBACK_MODEL = "gemma-4-26b-a4b-it"
GEMINI_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"
OLLAMA_MODEL = (os.environ.get("OLLAMA_MODEL") or "gemma3:4b").strip()

VALID_BACKENDS = ("auto", "gemini", "ollama", "offline")

# --- signal catalog (mirrors scorer.py weights) ------------------------------
# Ordered by descending risk weight. The first N matches fill the narrative,
# so the most severe signals are never trimmed by the 4-sentence cap.
# Matching is substring/regex based so it tolerates scorer wording drift.

SIGNAL_WEIGHTS: list[tuple[re.Pattern, int, str]] = [
    (
        re.compile(r"unregistered|not\s+registered", re.I),
        60,
        "The domain is not currently registered, which means anyone can claim it "
        "and begin receiving mail addressed to its users.",
    ),
    (
        re.compile(r"re-?registered|recently\s+registered", re.I),
        50,
        "It was re-registered very recently, the classic signature of a lapse that "
        "someone else has already picked up.",
    ),
    (
        re.compile(r"\b30\s*(d|day)", re.I),
        50,
        "Registration lapses within 30 days, an immediate takeover window.",
    ),
    (
        re.compile(r"expir", re.I),
        35,
        "Registration expires within 90 days.",
    ),
    (
        re.compile(r"dormant|stale|inactive\s+maintainer", re.I),
        15,
        "The maintainer of record has not published in over two years, so nobody is "
        "watching this domain.",
    ),
    (
        re.compile(r"\bMX\b|mail\s+exchanger|mail\s+server", re.I),
        10,
        "It still has live MX records, so mail sent to these addresses is actually "
        "being delivered somewhere.",
    ),
    (
        re.compile(r"1000|1,?000", re.I),
        20,
        "More than a thousand packages depend on it.",
    ),
    (
        re.compile(r"dependent", re.I),
        10,
        "A meaningful number of packages depend on it.",
    ),
    (
        re.compile(r"download|100\s?000|100,?000", re.I),
        10,
        "It sees very high weekly download volume.",
    ),
]

_RECOMMENDATIONS = {
    "CRITICAL": (
        "Treat this as an active takeover window: move maintainers off this domain "
        "now, rotate any credential or token that was ever mailed to it, and "
        "register the domain yourself until the addresses are migrated."
    ),
    "HIGH": (
        "Re-verify that the named maintainers still control this domain, add it to "
        "a watchlist for registration changes, and plan to migrate the addresses "
        "within the quarter."
    ),
    "MEDIUM": (
        "Confirm who currently controls the domain and diarise a re-check before "
        "the next renewal date; no emergency action is indicated yet."
    ),
    "LOW": (
        "No action required beyond the standing watchlist — the signals present do "
        "not indicate an imminent takeover."
    ),
}

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
_JSON_BLOCK = re.compile(r"\{.*\}", re.S)

_MODEL_CACHE: dict[str, tuple[bool, tuple[str, ...], str]] = {}
_MODEL_CACHE_LOCK = threading.Lock()
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class Judge:
    """Writes the plain-English narrative for a scored domain-takeover finding."""

    def __init__(self, backend: str = "auto", timeout: int = 30, *, sleep=None, jitter=None):
        if backend not in VALID_BACKENDS:
            raise ValueError(
                f"unknown backend {backend!r}; expected one of {VALID_BACKENDS}"
            )
        self.requested = backend
        self.timeout = max(1, int(timeout))
        self.reason: str | None = None
        self.api_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
        self.ollama_model = (os.environ.get("OLLAMA_MODEL") or OLLAMA_MODEL).strip()
        self._sleep = sleep or time.sleep
        self._jitter = jitter or random.random
        self._ollama_available: bool | None = None
        self._models_verified: bool | None = None
        self._last_provider: dict | None = None
        self.backend = self._resolve(backend)

    def _resolve(self, backend: str) -> str:
        if backend == "offline":
            self.reason = "offline backend requested explicitly"
            return "offline"
        if backend == "gemini":
            if not self.api_key:
                self.reason = "GEMINI_API_KEY is not set"
                return "offline"
            return "gemini"
        if backend == "ollama":
            self._ollama_available = _ollama_reachable(timeout=2)
            if self._ollama_available:
                return "ollama"
            self.reason = "no Ollama server on localhost:11434"
            return "offline"
        if self.api_key:
            return "gemini"
        self._ollama_available = _ollama_reachable(timeout=2)
        if self._ollama_available:
            return "ollama"
        self.reason = "no GEMINI_API_KEY and no Ollama server on localhost:11434"
        return "offline"

    @property
    def api_key(self) -> str:
        """Gemini API key, captured at construction time."""
        return self._api_key

    @api_key.setter
    def api_key(self, value: str) -> None:
        self._api_key = (value or "").strip()

    def is_live(self) -> bool:
        if self._last_provider is not None:
            return bool(self._last_provider["live"])
        return self.backend != "offline"

    def describe(self) -> dict:
        """Return safe provider diagnostics; API credentials are never included."""
        if self._last_provider is not None:
            info = self._last_provider
        elif self.backend == "offline":
            info = _provider_info("offline", "offline-template", False, None, [], self._models_verified)
        else:
            label = "Gemini API" if self.backend == "gemini" else "local Ollama"
            info = {
                "backend": self.backend,
                "model": None,
                "model_family": "Unknown",
                "provider_label": f"{label} · configured; no response yet",
                "live": True,
                "degraded_from": None,
                "fallback_chain": [],
                "models_verified": self._models_verified,
            }
        return {
            "requested": self.requested,
            "backend": info["backend"],
            "live": info["live"],
            "reason": self.reason,
            "model": info["model"],
            "model_family": info["model_family"],
            "provider_label": info["provider_label"],
            "models_verified": info["models_verified"],
        }

    def __repr__(self) -> str:
        return f"Judge({json.dumps(self.describe(), sort_keys=True)})"

    __str__ = __repr__

    def _model_name(self) -> str | None:
        """Return the model that last answered, never merely the preferred ID."""
        if self._last_provider is not None:
            return self._last_provider["model"]
        return "offline-template" if self.backend == "offline" else None

    def _remember(self, info: dict) -> None:
        self._last_provider = info
        self._models_verified = info["models_verified"]

    def _gemini_model_ids(self, chain: list[dict], deadline: float) -> list[str]:
        cache_key = hashlib.sha256(self.api_key.encode("utf-8")).hexdigest()
        with _MODEL_CACHE_LOCK:
            cached = _MODEL_CACHE.get(cache_key)
        if cached is not None:
            verified, ids, outcome = cached
            chain.append({"backend": "gemini", "model": None, "attempt": 1, "outcome": "models_cached"})
        else:
            token = None
            names: list[str] = []
            failure = None
            pages = 0
            while True:
                pages += 1
                if pages > 100 or time.monotonic() >= deadline:
                    failure = "list_models_budget_exhausted"
                    break
                query = urllib.parse.urlencode({"pageToken": token}) if token else ""
                url = GEMINI_MODELS_URL + (f"?{query}" if query else "")
                payload = None
                for attempt in range(1, 4):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        failure = "list_models_budget_exhausted"
                        break
                    request = urllib.request.Request(
                        url,
                        headers={"Accept": "application/json", "x-goog-api-key": self.api_key},
                        method="GET",
                    )
                    payload, status, retry_after, error = _fetch_json(
                        request, min(float(self.timeout), remaining)
                    )
                    outcome = f"http_{status}" if error and status is not None else (error or "success")
                    chain.append({"backend": "gemini", "model": None, "attempt": attempt, "outcome": outcome})
                    if not error:
                        failure = None
                        break
                    failure = f"list_models_{error}"
                    if status is not None:
                        failure = f"list_models_http_{status}"
                    if status not in _RETRYABLE_STATUS or attempt == 3:
                        break
                    delay = retry_after if retry_after is not None else 0.5 * (2 ** (attempt - 1)) + max(0.0, min(1.0, float(self._jitter()))) * 0.25
                    delay = min(30.0, max(0.0, delay), max(0.0, deadline - time.monotonic()))
                    if delay:
                        try:
                            self._sleep(delay)
                        except Exception:
                            pass
                if failure:
                    break
                models = payload.get("models") if isinstance(payload, dict) else None
                if not isinstance(models, list):
                    failure = "list_models_invalid_response"
                    break
                for item in models:
                    if not isinstance(item, dict):
                        continue
                    methods = item.get("supportedGenerationMethods") or []
                    name = str(item.get("name") or "")
                    if "generateContent" in methods and _model_family(name) == "Gemma 4":
                        model_id = name.rsplit("/", 1)[-1]
                        if model_id and model_id not in names:
                            names.append(model_id)
                token = payload.get("nextPageToken")
                if not token:
                    break
            if failure:
                verified, ids, outcome = False, (), failure
            else:
                preferred = [GEMINI_MODEL, GEMINI_FALLBACK_MODEL]
                ids = tuple([name for name in preferred if name in names] + [
                    name for name in names if name not in preferred
                ])
                verified = True
                outcome = "models_listed" if ids else "no_supported_gemma4_models"
            with _MODEL_CACHE_LOCK:
                cached = _MODEL_CACHE.setdefault(cache_key, (verified, ids, outcome))
            verified, ids, outcome = cached

        self._models_verified = verified
        chain.append({"backend": "gemini", "model": None, "attempt": 1, "outcome": outcome})
        if not verified:
            return [GEMINI_MODEL, GEMINI_FALLBACK_MODEL]
        return list(ids)

    def _request_text(self, backend: str, model: str, prompt: str, deadline: float) -> tuple[str | None, list[dict]]:
        if backend == "gemini":
            url = GEMINI_BASE_URL.format(model=model)
            headers = {"Content-Type": "application/json", "x-goog-api-key": self.api_key}
            body = {"contents": [{"parts": [{"text": prompt}]}]}
            extract = _gemini_text
            request_timeout = min(self.timeout, 15)
        else:
            url = OLLAMA_URL
            headers = {"Content-Type": "application/json"}
            body = {"model": model, "prompt": prompt, "stream": False}
            extract = _ollama_text
            request_timeout = min(self.timeout, 15)

        entries: list[dict] = []
        for attempt in range(1, 4):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                entries.append({"backend": backend, "model": model, "attempt": attempt, "outcome": "budget_exhausted"})
                break
            request = urllib.request.Request(
                url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
            )
            payload, status, retry_after, error = _fetch_json(
                request, min(float(request_timeout), remaining)
            )
            text = None
            if not error and isinstance(payload, dict):
                try:
                    text = extract(payload)
                except Exception:  # malformed provider response
                    text = None
            if error:
                outcome = f"http_{status}" if status is not None else error
            elif not isinstance(text, str) or not text.strip():
                outcome = "empty_response"
            else:
                outcome = "success"
            entries.append({"backend": backend, "model": model, "attempt": attempt, "outcome": outcome})
            if outcome == "success":
                return text, entries
            if status not in _RETRYABLE_STATUS or attempt == 3:
                break
            delay = retry_after if retry_after is not None else 0.5 * (2 ** (attempt - 1)) + max(0.0, min(1.0, float(self._jitter()))) * 0.25
            delay = min(30.0, max(0.0, delay), max(0.0, deadline - time.monotonic()))
            if delay:
                try:
                    self._sleep(delay)
                except Exception:  # an injected sleeper must not escape public APIs
                    pass
        return None, entries

    def _run_providers(self, prompt: str, parse, finding: dict) -> tuple[dict | None, dict]:
        chain: list[dict] = []
        deadline = time.monotonic() + min(30.0, max(10.0, float(self.timeout)))
        degraded_from = None
        models_verified = None

        def try_model(backend: str, model: str):
            text, attempts = self._request_text(backend, model, prompt, deadline)
            chain.extend(attempts)
            if text is None:
                return None
            try:
                parsed = parse(text)
            except Exception:
                parsed = None
            if parsed is None:
                if attempts:
                    attempts[-1]["outcome"] = "invalid_model_output"
                return None
            return parsed

        use_gemini = self.requested in {"auto", "gemini"} and bool(self.api_key)
        if use_gemini:
            models = self._gemini_model_ids(chain, deadline)
            models_verified = self._models_verified
            if not models:
                degraded_from = "gemini"
            for model in models:
                parsed = try_model("gemini", model)
                if parsed is not None:
                    info = _provider_info("gemini", model, True, None, chain, models_verified)
                    info["degraded_from"] = None
                    if not models_verified:
                        self.reason = "ListModels unavailable; documented Gemma 4 IDs are unverified"
                    self._remember(info)
                    return parsed, info
            if models:
                degraded_from = "gemini"

        use_ollama = self.requested in {"auto", "gemini", "ollama"}
        if use_ollama:
            if self._ollama_available is None:
                self._ollama_available = _ollama_reachable(timeout=2)
            chain.append({
                "backend": "ollama", "model": self.ollama_model, "attempt": 1,
                "outcome": "reachable" if self._ollama_available else "unreachable",
            })
            if self._ollama_available:
                parsed = try_model("ollama", self.ollama_model)
                if parsed is not None:
                    info = _provider_info("ollama", self.ollama_model, True, degraded_from, chain, models_verified)
                    self.reason = "Gemini API unavailable; using local Ollama" if degraded_from == "gemini" else None
                    self._remember(info)
                    return parsed, info
            elif degraded_from is None:
                degraded_from = "ollama"
            if self._ollama_available and degraded_from is None:
                degraded_from = "ollama"

        info = _provider_info("offline", "offline-template", False, degraded_from, chain, models_verified)
        if degraded_from:
            self.reason = f"{degraded_from} unavailable; using offline template"
        self._remember(info)
        return None, info

    def narrate(self, finding: dict) -> dict:
        """Explain a finding and identify the provider that actually answered."""
        finding = finding if isinstance(finding, dict) else {}
        try:
            parsed, info = self._run_providers(
                build_prompt(finding),
                lambda text: _normalise(_parse_model_json(text), finding),
                finding,
            )
            narrative = parsed if parsed is not None else self._narrate_offline(finding)
            return _with_provider(_scrub_result(narrative, finding, self.api_key), info)
        except Exception:  # noqa: BLE001 — narrate() must never raise
            info = _provider_info("offline", "offline-template", False, self.backend, [], self._models_verified)
            self._remember(info)
            return _with_provider(_scrub_result(self._narrate_offline(finding), finding, self.api_key), info)

    def analyze(self, finding: dict) -> dict:
        """Load-bearing structured analysis of ONE finding.

        Returns JSON that (a) cites the specific evidence behind the risk
        (dormancy, dependent count, expiry, recent re-registration), and
        (b) drafts a plain-English disclosure email to the maintainer with a
        concrete fix. The model is given raw evidence only — never the
        scorer's verdict — so it must reason, not copy. Falls back to a
        deterministic template offline.
        """
        finding = finding if isinstance(finding, dict) else {}
        try:
            prompt = build_analyze_prompt(finding)
            parsed, info = self._run_providers(
                prompt, lambda text: _parse_analyze_json(text, finding), finding
            )
        except Exception:  # noqa: BLE001
            parsed = None
            info = _provider_info("offline", "offline-template", False, self.backend, [], self._models_verified)
            self._remember(info)
        result = parsed if parsed is not None else self._analyze_offline(finding)
        return _with_provider(_scrub_result(result, finding, self.api_key), info)

    def _analyze_offline(self, finding: dict) -> dict:
        """Deterministic fallback: cite the scorer's own signals and template
        a disclosure email from them. Honest that it is not model-generated."""
        domain = str(finding.get("domain") or "the domain")
        signals = [str(s) for s in _as_list(finding.get("signals"))]
        reasoning = [str(r) for r in _as_list(finding.get("reasoning"))]
        evidence = signals or reasoning or ["no signals recorded"]
        email = (
            f"Subject: Action needed — the email domain behind your npm packages "
            f"may be at risk\n\n"
            f"Hi,\n\n"
            f"Our scanner flagged {domain}, the domain behind the maintainer email "
            f"for your package(s), as a possible expired/re-registered domain. "
            f"If you no longer control this mailbox, anyone who does can reset "
            f"your registry password.\n\n"
            f"Recommended fix: move your maintainer email to a domain you "
            f"actively control (or an org-owned address), and rotate any "
            f"credential tied to the old address.\n\n"
            f"— Lazarus (automated scan)"
        )
        return {
            "evidence": evidence[:5],
            "risk_reasoning": reasoning[:3] or ["rules-only assessment"],
            "disclosure_email": email,
            "confidence": "low",
            "severity": None,
            "risk": None,
        }

    def triage(self, findings: list[dict]) -> dict:
        """Independently rank findings by takeover risk from RAW evidence only.

        This is the load-bearing use of the model: the prompt deliberately
        withholds the scorer's risk/severity/signals so Gemma cannot copy
        them. It receives only ground-truth fields (RDAP dates, dependents,
        downloads, dormancy, MX) and must reason about which combinations are
        dangerous. Returns its own ranking plus a per-domain verdict.

        Falls back to the rules-only baseline ordering when offline, so the
        backtest always has something to compare against.
        """
        try:
            clean = [f for f in (findings or []) if isinstance(f, dict) and f.get("domain")]
        except Exception:
            clean = []
        if not clean:
            info = _provider_info("offline", "offline-template", False, None, [], self._models_verified)
            return _with_provider({"ranking": [], "assessments": []}, info)
        try:
            prompt = build_triage_prompt(clean)
            parsed, info = self._run_providers(
                prompt, lambda text: _parse_triage_json(text, clean), {}
            )
        except Exception:  # noqa: BLE001
            parsed = None
            info = _provider_info("offline", "offline-template", False, self.backend, [], self._models_verified)
            self._remember(info)
        result = parsed if parsed is not None else self._triage_offline(clean)
        return _with_provider(_scrub_result(result, {}, self.api_key), info)

    def _triage_offline(self, clean: list[dict]) -> dict:
        """Rules-only baseline: order by the scorer's existing risk field."""
        ordered = sorted(clean, key=lambda f: -_as_int(f.get("risk")))
        return {
            "backend": self.backend,
            "live": False,
            "ranking": [str(f["domain"]) for f in ordered],
            "assessments": [
                {
                    "domain": str(f["domain"]),
                    "model_risk": _as_int(f.get("risk")),
                    "confidence": "low",
                    "key_evidence": [str(s) for s in _as_list(f.get("signals"))][:3],
                    "reasoning": "rules-only baseline (no live model available)",
                }
                for f in ordered
            ],
        }

    def _narrate_offline(self, finding: dict) -> dict:
        """Deterministic narrative assembled from the finding's signals."""
        domain = str(finding.get("domain") or "this domain").strip()
        signals = [str(s) for s in _as_list(finding.get("signals")) if str(s).strip()]
        packages = [str(p) for p in _as_list(finding.get("packages")) if str(p).strip()]
        severity = str(finding.get("severity") or "LOW").upper()
        risk = finding.get("risk")
        try:
            risk_val = int(risk)
        except (TypeError, ValueError):
            risk_val = 0

        dependents = _as_int(finding.get("dependents"))
        downloads = _as_int(finding.get("downloads_week"))

        # Lead with what the domain is worth to the ecosystem.
        if packages:
            pkg_list = ", ".join(packages[:4]) + ("..." if len(packages) > 4 else "")
            opener = (
                f"The domain {domain} backs {len(packages)} package(s) "
                f"({pkg_list}) with {dependents:,} dependent(s) and "
                f"{downloads:,} weekly downloads."
            )
        else:
            opener = (
                f"The domain {domain} is referenced by maintainer contact "
                f"addresses with {dependents:,} dependent(s) downstream."
            )

        # Then the ranked signals, capped so the narrative stays at 4 sentences.
        matched = _rank_signals(signals)
        if matched:
            signal_sentences = [_sentence(p) for _, _, p in matched[:3]]
            body = [opener] + signal_sentences
        else:
            body = [
                opener,
                "No takeover signals were raised, so the risk assessment is "
                "based on registration state alone.",
            ]

        verdict = _verdict_line(domain, severity, risk_val, matched)
        recommendation = _RECOMMENDATIONS.get(severity, _RECOMMENDATIONS["LOW"])

        return {
            "verdict": verdict,
            "narrative": " ".join(body),
            "recommendation": recommendation,
        }


# --- helpers -----------------------------------------------------------------


def _fetch_json(request, timeout: float):
    """Read one JSON response without retaining or surfacing exception text."""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            raw = response.read().decode("utf-8", "replace")
            headers = getattr(response, "headers", {})
    except urllib.error.HTTPError as exc:
        status = getattr(exc, "code", None)
        headers = getattr(exc, "headers", {}) or {}
        return None, status, _retry_after(headers), "http_error"
    except (socket.timeout, TimeoutError, urllib.error.URLError, http.client.HTTPException, OSError):
        return None, None, None, "network_error"
    except Exception:
        return None, None, None, "network_error"
    if status is not None and not 200 <= status < 300:
        return None, status, _retry_after(headers), "http_error"
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None, status, None, "invalid_json"
    return payload, status, None, None


def _retry_after(headers) -> float | None:
    value = None
    try:
        value = headers.get("Retry-After")
    except Exception:
        return None
    if value is None:
        return None
    try:
        return max(0.0, min(30.0, float(value)))
    except (TypeError, ValueError):
        try:
            date = parsedate_to_datetime(str(value))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return max(0.0, min(30.0, (date - datetime.now(timezone.utc)).total_seconds()))
        except Exception:
            return None


def _model_family(model: str | None) -> str:
    value = str(model or "").lower().rsplit("/", 1)[-1]
    if re.match(r"^gemma-?4(?:[-:]|$)", value):
        return "Gemma 4"
    if re.match(r"^gemma-?3(?:n)?(?:[-:]|$)", value):
        return "Gemma 3"
    if value == "offline-template":
        return "Offline template"
    return "Unknown"


def _provider_info(backend, model, live, degraded_from, fallback_chain, models_verified):
    family = _model_family(model)
    if backend == "offline":
        label = "Offline template · no model ran"
    else:
        provider = "Gemini API" if backend == "gemini" else "local Ollama"
        label = f"{family} · {model} · {provider}" if model else f"{provider} · no model answered"
    return {
        "backend": backend,
        "model": model,
        "model_family": family,
        "provider_label": label,
        "live": bool(live),
        "degraded_from": degraded_from,
        "fallback_chain": [dict(entry) for entry in fallback_chain],
        "models_verified": models_verified,
    }


def _with_provider(result: dict, info: dict) -> dict:
    return {**result, **info}


def _scrub_text(value, finding: dict, secret: str = "") -> str:
    text = str(value)
    text = _EMAIL_RE.sub("[redacted email]", text)
    maintainers = finding.get("maintainers") if isinstance(finding, dict) else []
    if isinstance(maintainers, (str, bytes)):
        maintainers = [maintainers]
    if not isinstance(maintainers, (list, tuple, set)):
        maintainers = []
    for maintainer in sorted((str(item) for item in (maintainers or []) if item), key=len, reverse=True):
        text = re.sub(re.escape(maintainer), "[redacted]", text, flags=re.I)
    if secret:
        text = text.replace(secret, "[redacted]")
    return text


def _scrub_result(value, finding: dict, secret: str = ""):
    if isinstance(value, dict):
        return {key: _scrub_result(item, finding, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub_result(item, finding, secret) for item in value]
    if isinstance(value, str):
        return _scrub_text(value, finding, secret)
    return value


def build_prompt(finding: dict) -> str:
    """Render the scorer's finding as a prompt for either live backend."""
    domain = str(finding.get("domain") or "unknown")
    signals = [str(s) for s in _as_list(finding.get("signals"))]
    packages = [str(p) for p in _as_list(finding.get("packages"))]
    lines = [
        "You are the risk analyst for Lazarus, a scanner that finds package",
        "maintainers whose email domain is at risk of being taken over.",
        "",
        f"Domain: {domain}",
        f"Risk score: {finding.get('risk', 'n/a')}/100",
        f"Severity: {str(finding.get('severity', 'n/a')).upper()}",
        f"Packages: {', '.join(packages) if packages else 'none recorded'}",
        "Maintainer identities: redacted; do not include email addresses in the response.",
        f"Dependents: {_as_int(finding.get('dependents')):,}",
        f"Weekly downloads: {_as_int(finding.get('downloads_week')):,}",
        "",
        "Signals raised by the scanner:",
    ]
    lines.extend(f"- {s}" for s in signals) if signals else lines.append("- none")
    lines += [
        "",
        "Write a risk assessment for the maintainer of these packages.",
        "Reply with ONLY a JSON object, no markdown fence, with exactly these keys:",
        '  "verdict": one line, <=140 chars, states the domain and the risk',
        '  "narrative": 2 to 4 sentences explaining what the signals mean in',
        '               plain English and what an attacker could do',
        '  "recommendation": one concrete next step for the maintainer',
    ]
    return "\n".join(lines)



def build_triage_prompt(findings: list[dict]) -> str:
    """Render findings as RAW evidence for independent triage ranking.

    Deliberately excludes the scorer's risk/severity/signals — the model must
    reason from ground truth (RDAP dates, counts, dormancy, MX) or it is just
    echoing the baseline. This is what makes the model load-bearing.
    """
    lines = [
        "You are a supply-chain security analyst triaging package-maintainer",
        "email domains for takeover risk. An attacker who controls a domain",
        "controls the password-reset flow for every registry account using it.",
        "",
        "Below are domains with their raw evidence. There is NO pre-computed",
        "score — you must judge which are dangerous and why. Consider that a",
        "recently-created domain hosting a dormant maintainer's email, with",
        "mail (MX) live, is the classic pre-attack signature; a long-held",
        "domain with an active maintainer is not.",
        "",
        "For EACH domain return an assessment, and then rank them all.",
        "Reply with ONLY a JSON object, no markdown fence:",
        '  "ranking": ["most-risky.domain", ...],   // all domains, worst first',
        '  "assessments": [',
        '    {"domain": "...", "model_risk": 0-100,',
        '     "confidence": "high|medium|low",',
        '     "key_evidence": ["the facts that drove your call"],',
        '     "reasoning": "one sentence on the attack path"}',
        "  ]",
        "",
        "=== DOMAINS ===",
    ]
    for f in findings:
        rdap = f.get("rdap") or {}
        domain = f.get("domain")
        age = ""
        created = rdap.get("created")
        if created:
            try:
                from datetime import datetime, timezone
                cd = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                age = f" (registered {max(0, (datetime.now(timezone.utc) - cd).days)} days ago)"
            except Exception:  # noqa: BLE001
                age = ""
        lines += [
            f"- {domain}",
            f"    registered: {rdap.get('registered')}",
            f"    created: {created or 'unknown'}{age}",
            f"    expires: {rdap.get('expires') or 'unknown'}",
            f"    maintainers dormant (no publish 24mo): {f.get('maintainer_dormant')}",
            f"    last publish: {f.get('last_publish') or 'unknown'}",
            f"    mail (MX) live on domain: {f.get('mx_present')}",
            f"    dependents: {_as_int(f.get('dependents'))}",
            f"    weekly downloads: {_as_int(f.get('downloads_week'))}",
            f"    packages: {', '.join(str(p) for p in _as_list(f.get('packages'))) or 'none'}",
        ]
    return "\n".join(lines)


def build_analyze_prompt(finding: dict) -> str:
    """Render ONE finding's raw evidence for structured analysis + disclosure.

    Withholds the scorer's verdict (risk/severity/signals) so the model must
    cite the underlying facts itself. This is what makes the model
    load-bearing rather than a paraphraser.
    """
    rdap = finding.get("rdap") or {}
    lines = [
        "You are a supply-chain security analyst. A scanner collected the raw",
        "evidence below about a package maintainer's email domain. There is NO",
        "pre-computed risk score — judge it yourself and cite the specific",
        "facts that matter.",
        "",
        f"Domain: {finding.get('domain')}",
        f"Packages maintained via this domain: {', '.join(str(p) for p in _as_list(finding.get('packages'))) or 'unknown'}",
        f"Maintainer dormant (no publish 24mo): {finding.get('maintainer_dormant')}",
        f"Last publish: {finding.get('last_publish') or 'unknown'}",
        f"Mail (MX) live on domain: {finding.get('mx_present')}",
        f"Domain registered: {rdap.get('registered')}",
        f"Domain created: {rdap.get('created') or 'unknown'}",
        f"Domain expires: {rdap.get('expires') or 'unknown'}",
        f"Dependent packages: {_as_int(finding.get('dependents'))}",
        f"Weekly downloads: {_as_int(finding.get('downloads_week'))}",
        "",
        "Reply with ONLY a JSON object, no markdown fence, exactly these keys:",
        '  "evidence": [ up to 5 short strings, each citing a SPECIFIC fact that',
        '                drives the risk, e.g. "domain created 2026-05-07, only',
        '                N days old", "maintainer dormant since <date>",',
        '                "expires in N days", "N dependent packages" ],',
        '  "risk_reasoning": [ up to 3 strings explaining the attack path ],',
        '  "severity": independently chosen critical|high|medium|low,',
        '  "risk": independently chosen integer from 0 to 100,',
        '  "confidence": "high" | "medium" | "low",',
        '  "disclosure_email": a plain-English email to the maintainer: a',
        '       subject line, why this matters (domain takeover -> password',
        '       reset -> malicious publish), and ONE concrete fix. Address it',
        '       to the maintainer, sign it "Lazarus (automated scan)". Do not',
        '       include the maintainer\'s email address.',
    ]
    return "\n".join(lines)


def _parse_analyze_json(text: str | None, finding: dict) -> dict | None:
    if not text:
        return None
    data = _extract_json(text)
    if not isinstance(data, dict):
        return None
    evidence = data.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return None
    # disclosure_email may be a plain string OR a {subject, body} object —
    # small models like Gemma 3 often return the structured form. Accept both.
    email_field = data.get("disclosure_email")
    if isinstance(email_field, str) and email_field.strip():
        email = email_field.strip()
    elif isinstance(email_field, dict):
        subj = str(email_field.get("subject") or "").strip()
        bod = str(email_field.get("body") or "").strip()
        if not (subj or bod):
            return None
        email = (f"Subject: {subj}\n\n{bod}" if subj else bod)
    else:
        return None
    severity_value = str(data.get("severity") or "").strip().upper()
    severity = severity_value if severity_value in _VALID_SEVERITIES else None
    risk_value = data.get("risk")
    risk = None
    if not isinstance(risk_value, bool) and risk_value is not None:
        try:
            risk = max(0, min(100, int(risk_value)))
        except (TypeError, ValueError, OverflowError):
            risk = None
    return {
        "evidence": [str(x) for x in evidence][:5],
        "risk_reasoning": [str(x) for x in (data.get("risk_reasoning") or [])][:3],
        "confidence": str(data.get("confidence") or "low"),
        "disclosure_email": email,
        "severity": severity,
        "risk": risk,
    }


def _parse_triage_json(text: str | None, clean: list[dict]) -> dict | None:
    """Parse and validate the triage response; None if unusable."""
    if not text:
        return None
    data = _extract_json(text)
    if not isinstance(data, dict):
        return None
    ranking = data.get("ranking")
    assessments = data.get("assessments")
    known = {str(f["domain"]).lower() for f in clean}
    if not isinstance(ranking, list) or not isinstance(assessments, list):
        return None
    # keep only domains we actually asked about, de-duplicated, order preserved
    seen, out_rank = set(), []
    for d in ranking:
        dl = str(d).strip().lower()
        if dl in known and dl not in seen:
            seen.add(dl)
            out_rank.append(dl)
    # any domain the model omitted still gets assessed, appended at the end
    for f in clean:
        if str(f["domain"]).lower() not in seen:
            out_rank.append(str(f["domain"]).lower())
    valid_assess = []
    for a in assessments:
        if isinstance(a, dict) and str(a.get("domain", "")).lower() in known:
            try:
                mr = max(0, min(100, int(a.get("model_risk"))))
            except (TypeError, ValueError):
                mr = None
            valid_assess.append({
                "domain": str(a["domain"]).lower(),
                "model_risk": mr,
                "confidence": str(a.get("confidence") or "low"),
                "key_evidence": [str(x) for x in (a.get("key_evidence") or [])][:4],
                "reasoning": str(a.get("reasoning") or "")[:300],
            })
    if not out_rank:
        return None
    return {"ranking": out_rank, "assessments": valid_assess}


def _extract_json(text: str):
    """Tolerant JSON extraction: strip fences, find the outermost object."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:  # noqa: BLE001
            return None
    return None


def _sentence(text: str) -> str:
    """Capitalise and terminate a phrase so sentences join cleanly."""
    text = (text or "").strip()
    if not text:
        return ""
    text = text[0].upper() + text[1:]
    if text[-1] not in ".!?":
        text += "."
    return text

def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _as_list(value) -> list:
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str) and value:
        return [value]
    return []


def _rank_signals(signals: list[str]) -> list[tuple[str, int, str]]:
    """Match signals against the catalog, highest risk weight first."""
    matched: list[tuple[str, int, str]] = []
    for signal in signals:
        for pattern, weight, phrase in SIGNAL_WEIGHTS:
            if pattern.search(signal):
                matched.append((signal, weight, phrase))
                break
    matched.sort(key=lambda item: -item[1])
    return matched


def _verdict_line(domain: str, severity: str, risk: int, matched) -> str:
    if matched:
        top = matched[0][0]
        reason = top if len(top) <= 60 else top[:57].rstrip() + "..."
        return f"{severity} ({risk}/100): {domain} — {reason}."
    return f"{severity} ({risk}/100): {domain} shows no takeover signals."


def _ollama_reachable(timeout: int = 2) -> bool:
    """Cheap liveness probe — GET /api/tags, never raises."""
    try:
        req = urllib.request.Request(
            OLLAMA_TAGS_URL, headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception:  # noqa: BLE001 — probe must never raise
        return False


def _http_json_text(url, headers, body, timeout, extract):
    """POST JSON and pull the model's text out of the response. Never raises."""
    try:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers=dict(headers), method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
        return extract(json.loads(raw))
    except Exception:  # noqa: BLE001
        return None


def _gemini_text(payload: dict):
    try:
        return payload["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:  # noqa: BLE001
        return None


def _ollama_text(payload: dict):
    try:
        return payload["response"]
    except Exception:  # noqa: BLE001
        return None


def _parse_model_json(text: str) -> dict:
    """Tolerant JSON recovery from a model reply."""
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:  # noqa: BLE001
        pass
    block = _JSON_BLOCK.search(text)
    if block:
        try:
            parsed = json.loads(block.group(0))
            if isinstance(parsed, dict):
                return parsed
        except Exception:  # noqa: BLE001
            pass
    # Last resort: treat the whole reply as the narrative.
    return {"narrative": text.strip()}


def _normalise(result: dict, finding: dict) -> dict:
    """Force any model reply into the 3-key contract, 2-4 sentence narrative."""
    verdict = _one_line(str(result.get("verdict") or ""))
    narrative = str(result.get("narrative") or "").strip()
    recommendation = _one_line(str(result.get("recommendation") or ""))

    sentences = [s for s in _SENTENCE_SPLIT.split(narrative) if s.strip()]
    if not sentences:
        # The model gave us nothing usable — fall back to the template.
        return Judge("offline")._narrate_offline(finding)
    if len(sentences) > 4:
        sentences = sentences[:4]
    elif len(sentences) < 2:
        domain = str(finding.get("domain") or "the domain")
        sentences.append(
            f"No further takeover signals were identified for {domain}."
        )

    if not verdict:
        severity = str(finding.get("severity") or "LOW").upper()
        verdict = f"{severity}: see narrative for {finding.get('domain', 'the domain')}."
    if not recommendation:
        severity = str(finding.get("severity") or "LOW").upper()
        recommendation = _RECOMMENDATIONS.get(severity, _RECOMMENDATIONS["LOW"])

    return {
        "verdict": verdict[:200],
        "narrative": " ".join(sentences),
        "recommendation": recommendation,
    }


def _one_line(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\n", " ")).strip()


# --- CLI (smoke test) --------------------------------------------------------


def _load_finding(argv: list[str]) -> dict:
    import sys

    if len(argv) > 1:
        with open(argv[1], "r", encoding="utf-8") as handle:
            return json.load(handle)
    return json.load(sys.stdin)


if __name__ == "__main__":
    import sys

    _finding = _load_finding(sys.argv)
    _backend = sys.argv[2] if len(sys.argv) > 2 else "auto"
    _judge = Judge(_backend)
    _result = _judge.narrate(_finding)
    print(json.dumps({"backend": _judge.describe(), **_result}, indent=2))
