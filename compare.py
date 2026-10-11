"""Rules-versus-model comparison payloads for the Lazarus dashboard."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from datetime import datetime, timezone

import judge as judge_module


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_EVIDENCE_FIELDS = (
    "domain", "packages", "rdap", "maintainer_dormant", "last_publish",
    "mx_present", "dependents", "downloads_week", "risk", "severity",
    "signals", "reasoning",
)


class ComparisonCache:
    """Small process-local TTL cache; the clock is injectable for tests."""

    def __init__(self, ttl: float = 300, clock=None):
        self.ttl = max(0.0, float(ttl))
        self.clock = clock or time.monotonic
        self._entries: dict[tuple[str, str], tuple[float, dict]] = {}

    @staticmethod
    def key(finding: dict) -> tuple[str, str]:
        domain = str(finding.get("domain") or "")
        evidence = {field: finding.get(field) for field in _EVIDENCE_FIELDS}
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
        return domain, hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def get(self, finding: dict):
        key = self.key(finding)
        cached = self._entries.get(key)
        if cached is None:
            return None
        expires, value = cached
        if self.clock() >= expires:
            self._entries.pop(key, None)
            return None
        return copy.deepcopy(value)

    def set(self, finding: dict, value: dict) -> None:
        self._entries[self.key(finding)] = (self.clock() + self.ttl, copy.deepcopy(value))

    def clear(self) -> None:
        self._entries.clear()


_CACHE = ComparisonCache()


def clear_cache() -> None:
    """Clear the module's default comparison cache."""
    _CACHE.clear()


def _compare_finding(finding: dict, judge=None) -> dict:
    """Build the API payload for one finding."""
    finding = finding if isinstance(finding, dict) else {}
    try:
        cached = _CACHE.get(finding)
        if cached is not None:
            return cached
    except Exception:
        pass

    rules = {
        "risk": _safe_int(finding.get("risk")),
        "severity": _severity(finding.get("severity")) or "UNKNOWN",
        "signals": _safe_strings(finding.get("signals"), finding),
        "reasoning": _safe_strings(finding.get("reasoning"), finding),
    }
    source = judge
    if source is None:
        try:
            source = judge_module.Judge()
        except Exception:
            source = None

    analysis = None
    if source is not None:
        try:
            candidate = source.analyze(finding)
            if isinstance(candidate, dict):
                analysis = candidate
        except Exception:
            analysis = None

    diagnostics = {}
    if source is not None:
        try:
            diagnostics = source.describe()
            if not isinstance(diagnostics, dict):
                diagnostics = {}
        except Exception:
            diagnostics = {}
    if analysis is None:
        analysis = {}

    backend = str(analysis.get("backend") or diagnostics.get("backend") or "unknown")
    model_value = analysis.get("model")
    model = str(model_value) if model_value else None
    live = bool(analysis.get("live", diagnostics.get("live", False)))
    if backend == "offline" or model == "offline-template":
        family = "Offline template"
        label = "Offline template · no model ran"
        independent = False
        backend = "offline"
    elif not model or backend not in {"gemini", "ollama"}:
        family = "Unknown"
        label = "Unverified provenance · model not recorded"
        independent = False
    else:
        family = _family(model)
        label = _provider_label(backend, model, family)
        independent = live

    severity = _severity(analysis.get("severity"))
    risk = _optional_int(analysis.get("risk"), 0, 100)
    available = bool(analysis)
    gemma = {
        "available": available,
        "independent": independent,
        "severity": severity,
        "risk": risk,
        "evidence": _safe_strings(analysis.get("evidence"), finding),
        "risk_reasoning": _safe_strings(analysis.get("risk_reasoning"), finding),
        "confidence": _redact(analysis.get("confidence") or "low", finding),
        "disclosure_email": _redact(analysis.get("disclosure_email") or "", finding),
    }
    rules_severity = _severity(rules["severity"])
    if backend == "offline":
        agreement = {
            "status": "not_independent",
            "detail": "The offline template restates the rules and is not an independent assessment.",
        }
    elif not available or not independent or severity is None or rules_severity is None:
        agreement = {
            "status": "unavailable",
            "detail": "An independent severity comparison is unavailable because a model severity or verified response is missing.",
        }
    else:
        distance = abs(_SEVERITIES.index(rules_severity) - _SEVERITIES.index(severity))
        if distance == 0:
            status = "agree"
            detail = f"Both assessments report {severity}."
        elif distance == 1:
            status = "partial"
            detail = f"The assessments differ by one severity level ({rules_severity} vs {severity})."
        else:
            status = "disagree"
            detail = f"The assessments differ by at least two severity levels ({rules_severity} vs {severity})."
        agreement = {"status": status, "detail": detail}

    provider = {
        "backend": backend,
        "model": model,
        "family": family,
        "label": label,
        "live": live,
        "degraded_from": analysis.get("degraded_from"),
        "fallback_chain": _safe_fallback_chain(analysis.get("fallback_chain")),
        "models_verified": analysis.get("models_verified", diagnostics.get("models_verified")),
    }
    result = {
        "domain": _redact(finding.get("domain") or "", finding),
        "rules": rules,
        "gemma": gemma,
        "agreement": agreement,
        "provider": provider,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    try:
        _CACHE.set(finding, result)
    except Exception:
        pass
    return result


def compare_finding(finding: dict, judge=None) -> dict:
    """Build the API payload for one finding. This function never raises."""
    try:
        return _compare_finding(finding, judge=judge)
    except Exception:
        finding = finding if isinstance(finding, dict) else {}
        return {
            "domain": _redact(finding.get("domain") or "", finding),
            "rules": {
                "risk": _safe_int(finding.get("risk")),
                "severity": _severity(finding.get("severity")) or "UNKNOWN",
                "signals": [],
                "reasoning": [],
            },
            "gemma": {
                "available": False, "independent": False, "severity": None,
                "risk": None, "evidence": [], "risk_reasoning": [],
                "confidence": "low", "disclosure_email": "",
            },
            "agreement": {
                "status": "unavailable",
                "detail": "A comparison could not be generated for this finding.",
            },
            "provider": {
                "backend": "unknown", "model": None, "family": "Unknown",
                "label": "Unverified provenance · model not recorded", "live": False,
                "degraded_from": None, "fallback_chain": [], "models_verified": None,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }


def compare_all(findings, judge=None, limit: int = 100) -> list[dict]:
    """Compare up to ``limit`` findings while reusing one Judge instance."""
    try:
        clean = [finding for finding in findings if isinstance(finding, dict)]
    except Exception:
        return []
    try:
        count = max(0, int(limit))
    except (TypeError, ValueError):
        count = 100
    source = judge
    if source is None and clean:
        try:
            source = judge_module.Judge()
        except Exception:
            source = None
    return [compare_finding(finding, judge=source) for finding in clean[:count]]


def _safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _optional_int(value: object, low: int, high: int) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError, OverflowError):
        return None


def _severity(value: object) -> str | None:
    normalized = str(value or "").strip().upper()
    return normalized if normalized in _SEVERITIES else None


def _safe_strings(value: object, finding: dict | None = None) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        values = []
    return [_redact(item, finding or {}) for item in values if item is not None][:5]


def _redact(value: object, finding: dict) -> str:
    text = _EMAIL_RE.sub("[redacted email]", str(value))
    maintainers = finding.get("maintainers") or []
    if isinstance(maintainers, str):
        maintainers = [maintainers]
    if not isinstance(maintainers, (list, tuple, set)):
        maintainers = []
    for maintainer in sorted((str(item) for item in maintainers if item), key=len, reverse=True):
        text = re.sub(re.escape(maintainer), "[redacted]", text, flags=re.I)
    return text


def _safe_fallback_chain(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    safe = []
    for item in value:
        if isinstance(item, dict):
            safe.append({
                "backend": _redact(item.get("backend", ""), {}),
                "model": _redact(item.get("model", ""), {}) or None,
                "outcome": _redact(item.get("outcome", ""), {}),
                **({"attempt": _safe_int(item["attempt"])} if "attempt" in item else {}),
            })
    return safe


def _family(model: str) -> str:
    value = model.lower().rsplit("/", 1)[-1]
    if re.match(r"^gemma-?4(?:[-:]|$)", value):
        return "Gemma 4"
    if re.match(r"^gemma-?3(?:n)?(?:[-:]|$)", value):
        return "Gemma 3"
    return "Unknown"


def _provider_label(backend: str, model: str, family: str) -> str:
    provider = "Gemini API" if backend == "gemini" else "local Ollama"
    return f"{family} · {model} · {provider}"
