#!/usr/bin/env python3
"""Lazarus — expired-domain supply-chain watch (web app).

Stdlib-only HTTP backend on ThreadingHTTPServer — no pip installs, no FastAPI.

Routes (see INTERFACES.md):
    GET  /              static/index.html — the dark dashboard
    GET  /api/skills    bundled fixture skills (name + description)
    GET  /api/findings  scan results: last run (in-memory + data/last_run.json),
                        falling back to the seeded data/cached_run.json
    GET  /api/graph     graph.build_graph(findings) -> {"nodes": [...], "edges": [...]}
    POST /api/narrate   {"domain": "..."} -> judge.narrate(finding)
    GET  /api/run       SSE scan stream: start -> progress* -> finding* -> done
    GET  /api/cached    pre-seeded full run — works with no key and no network

Run:
    python app.py
"""

from __future__ import annotations

import importlib
import json
import mimetypes
import os
import socket
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import guard

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
SKILLS_DIR = BASE_DIR / "skills"
CACHED_RUN_PATH = DATA_DIR / "cached_run.json"
LAST_RUN_PATH = DATA_DIR / "last_run.json"
RDAP_CACHE_PATH = DATA_DIR / "rdap_cache.json"

HOST = os.environ.get("HOST", "127.0.0.1")  # loopback by default: a security
                                          # tool should not listen on the
                                          # venue network. Set HOST=0.0.0.0
                                          # explicitly to expose it.
try:
    PORT = int(os.environ.get("PORT", "8741"))
except ValueError:
    sys.exit("lazarus: PORT must be an integer")

def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except ValueError:
        return default


# Pasted lockfile / package.json cap (bytes) and per-scan dependency cap.
MAX_UPLOAD_BYTES = _int_env("LAZARUS_MAX_UPLOAD_BYTES", 2_000_000, 1_000, 50_000_000)
MAX_SCAN_DEPS = _int_env("LAZARUS_MAX_SCAN_DEPS", 200, 1, 5_000)
MAX_CONCURRENT_SCANS = 2
_SCAN_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)
RATE_LIMITER = guard.RateLimiter()
# (capacity, refills per minute) per client IP
RATE_LIMITS = {"read": (120, 600), "ai": (10, 20), "scan": (3, 6)}

CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".txt": "text/plain; charset=utf-8",
}

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

_STATE_LOCK = threading.Lock()
LAST_RUN: dict | None = None
_CACHED_RUN: dict | None = None
_JUDGE = None


def _try_import(name: str):
    try:
        return importlib.import_module(name)
    except Exception:
        return None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json_file(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json_file(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def load_cached_run() -> dict:
    global _CACHED_RUN
    if _CACHED_RUN is None:
        _CACHED_RUN = load_json_file(CACHED_RUN_PATH, {"findings": []})
        if not isinstance(_CACHED_RUN, dict):
            _CACHED_RUN = {"findings": []}
    return _CACHED_RUN


def _load_persisted_run() -> None:
    global LAST_RUN
    run = load_json_file(LAST_RUN_PATH, None)
    if isinstance(run, dict) and run.get("findings"):
        LAST_RUN = run


def _mask_email_in_text(text: str, handles=()) -> str:
    """Mask any email in prose and any known maintainer handle."""
    return guard.redact_maintainer_text(text, handles)


def redact_maintainers(findings: list[dict]) -> list[dict]:
    """Strip maintainer identities before anything leaves the process.

    A judge can hit /api/findings with curl, so the API boundary redacts, not
    just the UI. Maintainers become neutral placeholders ("maintainer-1");
    the count is kept. The domain is public registry data and stays. Handles
    and emails are also scrubbed from narrative/incident prose.
    """
    out = []
    for f in findings:
        if not isinstance(f, dict):
            out.append(f)
            continue
        g = dict(f)
        maint = g.get("maintainers")
        handles = [str(m) for m in maint] if isinstance(maint, list) else []
        if isinstance(maint, list):
            g["maintainers"] = [f"maintainer-{i}" for i in range(1, len(maint) + 1)]
            g["maintainer_count"] = len(maint)
        for key in ("narrative", "incident", "analysis", "verification"):
            val = g.get(key)
            if isinstance(val, dict):
                g[key] = {
                    k: (_mask_email_in_text(v, handles) if isinstance(v, str) else v)
                    for k, v in val.items()
                }
        out.append(g)
    return out


def current_mode() -> str:
    """'live' only when the findings on screen came from a live scan."""
    with _STATE_LOCK:
        if LAST_RUN and LAST_RUN.get("findings"):
            mode = str((LAST_RUN.get("meta") or {}).get("mode") or "")
            return "live" if mode == "live" else ("repo-scan" if mode == "repo-scan" else "replay")
    return "replay"


def current_findings() -> tuple[list[dict], str]:
    with _STATE_LOCK:
        if LAST_RUN and LAST_RUN.get("findings"):
            return list(LAST_RUN["findings"]), "last-run"
    return list(load_cached_run().get("findings", [])), "cached"


def _record_run(findings: list[dict], meta: dict) -> None:
    global LAST_RUN
    run = {"findings": redact_maintainers(findings), "meta": meta}
    with _STATE_LOCK:
        LAST_RUN = run
    try:
        save_json_file(LAST_RUN_PATH, run)
    except Exception:
        traceback.print_exc()


def compute_stats(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    risks: list[int] = []
    dependents = 0
    for f in findings:
        sev = str(f.get("severity") or "LOW").upper()
        if sev not in counts:
            sev = "LOW"
        counts[sev] += 1
        try:
            risks.append(int(f.get("risk") or 0))
        except (TypeError, ValueError):
            pass
        try:
            dependents += int(f.get("dependents") or 0)
        except (TypeError, ValueError):
            pass
    return {
        "total": len(findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "avg_risk": round(sum(risks) / len(risks)) if risks else 0,
        "total_dependents": dependents,
        "domains": len({f.get("domain") for f in findings if f.get("domain")}),
    }


AT_RISK_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


def blast_radius(findings: list[dict]) -> dict:
    """Aggregate the weekly-download reach controlled by at-risk domains.

    Answers: 'lapsed domains put packages with X combined weekly downloads
    within reach of a takeover.' Only CRITICAL and HIGH domains count; MEDIUM
    and LOW never do, and the threshold is deliberately not a parameter so
    the UI, docs and API cannot drift apart. A domain is counted once.
    """
    at_risk_downloads = 0
    at_risk_dependents = 0
    at_risk_domains: set[str] = set()
    at_risk_packages: set[str] = set()
    unverified_dependents = 0
    unverified_downloads = 0
    worst_domain = None
    worst_downloads = 0
    for f in findings:
        sev = str(f.get("severity") or "LOW").upper()
        if sev not in AT_RISK_SEVERITIES:
            continue
        dom = f.get("domain")
        if not dom or dom in at_risk_domains:
            continue
        at_risk_domains.add(dom)
        # None means "not verified", which is different from a measured zero.
        unverified_dependents += f.get("dependents") is None
        unverified_downloads += f.get("downloads_week") is None
        try:
            dl = int(f.get("downloads_week") or 0)
        except (TypeError, ValueError):
            dl = 0
        try:
            dep = int(f.get("dependents") or 0)
        except (TypeError, ValueError):
            dep = 0
        at_risk_downloads += dl
        at_risk_dependents += dep
        for p in (f.get("packages") or []):
            at_risk_packages.add(str(p))
        if dl > worst_downloads:
            worst_downloads = dl
            worst_domain = dom
    return {
        "at_risk_domains": len(at_risk_domains),
        "at_risk_packages": len(at_risk_packages),
        "combined_weekly_downloads": at_risk_downloads,
        "combined_dependents": at_risk_dependents,
        "domains_with_unverified_dependents": unverified_dependents,
        "domains_with_unverified_downloads": unverified_downloads,
        "largest_single_domain": worst_domain,
        "largest_single_downloads": worst_downloads,
    }


class OfflineJudge:
    """Template narrator used until judge.py exists, and whenever the
    configured judge backend is offline. Deterministic, never raises."""

    backend_name = "offline-template"

    def is_live(self) -> bool:
        return False

    def narrate(self, finding: dict) -> dict:
        f = finding or {}
        domain = f.get("domain", "unknown domain")
        severity = str(f.get("severity") or "LOW").upper()
        signals = [str(s) for s in (f.get("signals") or [])]
        rdap = f.get("rdap") or {}
        created = rdap.get("created") or "unknown"
        expires = rdap.get("expires") or "unknown"
        packages = f.get("packages") or []
        pkg_str = ", ".join(packages[:3]) if packages else "several packages"
        unregistered = rdap.get("registered") is False and not rdap.get("error")

        if unregistered:
            verdict = f"CRITICAL — {domain} is unregistered and can be acquired by anyone"
            narrative = (
                f"RDAP shows no active registration for {domain}: the domain has fully lapsed, "
                f"so any attacker can register it and inherit every account still bound to its "
                f"email addresses. The maintainer address still fronts {pkg_str}."
            )
            recommendation = (
                "Assume takeover is imminent: rotate credentials, move contact email to an "
                "org-owned domain, and deprecate affected package versions."
            )
        elif "recently re-registered" in signals:
            verdict = f"HIGH — {domain} was re-registered recently and still fronts {pkg_str}"
            narrative = (
                f"The domain behind the maintainer contact address was created on {created}, "
                f"inside the 180-day window that typically precedes account-recovery takeovers, "
                f"and is valid until {expires}. Whoever controls the registrar now controls "
                f"password resets for accounts still using it."
            )
            recommendation = (
                "Verify the current registrant with the maintainer, rotate credentials, and "
                "pin dependent packages until domain control is confirmed."
            )
        elif any(s.startswith("expiring") for s in signals):
            verdict = f"MEDIUM — {domain} expires soon ({expires}) while packages still depend on it"
            narrative = (
                f"The registration is valid but lapses on {expires}, inside the window where a "
                f"missed renewal becomes a hijack. {pkg_str} still reference the maintainer "
                f"address hosted here."
            )
            recommendation = (
                "Ask the maintainer to enable auto-renewal and re-check the domain within 30 days."
            )
        elif severity in ("CRITICAL", "HIGH"):
            verdict = f"{severity} — {domain} shows active takeover risk signals"
            narrative = (
                f"The scoring rules fired on: {'; '.join(signals) if signals else 'no explicit signals'}. "
                f"Packages affected: {pkg_str}. Registration created {created}, expires {expires}."
            )
            recommendation = (
                "Review the maintainer's domain ownership and rotate credentials before the next publish."
            )
        else:
            verdict = f"LOW — {domain} shows no active takeover signals"
            narrative = (
                f"Registration is healthy (created {created}, expires {expires}) and no takeover "
                f"signals fired for {pkg_str}."
            )
            recommendation = "No action needed; re-scan on the normal cycle."
        return {"verdict": verdict, "narrative": narrative, "recommendation": recommendation}


def get_judge():
    global _JUDGE
    if _JUDGE is None:
        judge_mod = _try_import("judge")
        if judge_mod is not None and hasattr(judge_mod, "Judge"):
            try:
                _JUDGE = judge_mod.Judge()
            except Exception:
                _JUDGE = OfflineJudge()
        else:
            _JUDGE = OfflineJudge()
    return _JUDGE


def _judge_backend_name(judge) -> str:
    name = getattr(judge, "backend", None) or getattr(judge, "backend_name", None) or "judge"
    return str(name)


def _seeded_narrative(domain: str) -> dict | None:
    for f in load_cached_run().get("findings", []):
        if f.get("domain") == domain and f.get("narrative"):
            return dict(f["narrative"])
    return None


def find_finding(domain: str) -> dict | None:
    for candidates in (current_findings()[0], load_cached_run().get("findings", [])):
        for f in candidates:
            if f.get("domain") == domain:
                return f
    return None


def narrate_for(finding: dict) -> dict:
    judge = get_judge()
    domain = finding.get("domain", "")
    if judge is not None and judge.is_live():
        try:
            out = dict(judge.narrate(finding))
            out["backend"] = _judge_backend_name(judge)
            return out
        except Exception:
            traceback.print_exc()
    seeded = _seeded_narrative(domain)
    if seeded is not None:
        seeded["backend"] = "cached-seed"
        return seeded
    if judge is not None:
        out = dict(judge.narrate(finding))
        out["backend"] = _judge_backend_name(judge)
        return out
    return {
        "verdict": "narration unavailable",
        "narrative": "No judge backend is available and no seeded narrative exists for this domain.",
        "recommendation": "Set GEMINI_API_KEY or run a local Ollama gemma3:4b instance, then retry.",
        "backend": "none",
    }


def _fallback_build_graph(findings: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(nid: str, ntype: str, label: str, risk: int) -> None:
        n = nodes.get(nid)
        if n is None:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, "risk": int(risk or 0)}
        else:
            nodes[nid]["risk"] = max(nodes[nid]["risk"], int(risk or 0))

    for f in findings:
        domain = f.get("domain") or "?"
        risk = f.get("risk") or 0
        add_node(domain, "domain", domain, risk)
        for m in f.get("maintainers") or []:
            mid = "maintainer:" + str(m)
            add_node(mid, "maintainer", str(m).split("@")[0] or str(m), risk)
            edges.append({"source": domain, "target": mid, "label": "hosts email"})
            for p in f.get("packages") or []:
                pid = "package:" + str(p)
                add_node(pid, "package", str(p), risk)
                edges.append({"source": mid, "target": pid, "label": "maintains"})
    return {"nodes": list(nodes.values()), "edges": edges}


def build_graph(findings: list[dict]) -> dict:
    gmod = _try_import("graph")
    if gmod is not None and hasattr(gmod, "build_graph"):
        try:
            return gmod.build_graph(findings)
        except Exception:
            traceback.print_exc()
    return _fallback_build_graph(findings)


def _parse_frontmatter(path: Path) -> dict:
    meta: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return meta
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return meta
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" in line and not line.startswith((" ", "\t")):
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip().strip("'\"")
    return meta


def skills_payload() -> dict:
    skills: list[dict] = []
    loader = _try_import("skill_loader")
    if SKILLS_DIR.is_dir():
        for child in sorted(SKILLS_DIR.iterdir()):
            skill_md = child / "SKILL.md"
            if not child.is_dir() or not skill_md.is_file():
                continue
            name, description = child.name, ""
            if loader is not None and hasattr(loader, "load_skill"):
                try:
                    meta = loader.load_skill(str(skill_md))
                    name = str(meta.get("name") or child.name)
                    description = str(meta.get("description") or "")
                except Exception:
                    fm = _parse_frontmatter(skill_md)
                    name, description = fm.get("name", child.name), fm.get("description", "")
            else:
                fm = _parse_frontmatter(skill_md)
                name, description = fm.get("name", child.name), fm.get("description", "")
            skills.append({"name": name, "description": description, "path": f"skills/{child.name}"})
    return {"skills": skills, "count": len(skills)}


def judge_status() -> dict:
    judge = get_judge()
    live = bool(judge is not None and judge.is_live())
    backend = _judge_backend_name(judge) if judge is not None else "none"
    out = {
        "live": live,
        "backend": f"{backend} (live)" if live else backend,
        "has_key": bool(os.environ.get("GEMINI_API_KEY")),
    }
    describe = getattr(judge, "describe", None)
    if callable(describe):
        try:
            d = describe()
            out["provider"] = {k: d.get(k) for k in (
                "backend", "model", "model_family", "provider_label", "live",
                "reason", "models_verified") if k in d}
        except Exception:  # noqa: BLE001 — status must never break a page load
            traceback.print_exc()
    return out


def status_payload() -> dict:
    """Runtime facts the UI and the fresh-clone check can rely on. Never
    includes secrets — only whether a key is present."""
    findings, source = current_findings()
    return {
        "app": "lazarus",
        "mode": current_mode(),
        "source": source,
        "findings": len(findings),
        "limits": {
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "max_scan_dependencies": MAX_SCAN_DEPS,
            "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        },
        "host": HOST,
        **judge_status(),
    }


def cached_payload() -> dict:
    cached = dict(load_cached_run())
    findings = cached.get("findings", [])
    cached["source"] = "cached"
    cached["seeded"] = True
    safe = redact_maintainers(findings)
    cached["findings"] = safe
    cached.update(judge_status())
    # Always derived from the findings so recorded files cannot carry a stale
    # or differently-defined blast radius.
    cached["stats"] = compute_stats(safe)
    cached["blast_radius"] = blast_radius(safe)
    cached.setdefault("graph", build_graph(safe))
    return cached


def findings_payload() -> dict:
    findings, source = current_findings()
    safe = redact_maintainers(findings)
    payload = {
        "findings": safe,
        "source": source,
        "seeded": source in ("cached", "seed"),
        "mode": current_mode(),
        "count": len(findings),
        "stats": compute_stats(safe),
        "blast_radius": blast_radius(safe),
        "updated_at": now_iso(),
    }
    payload.update(judge_status())
    return payload


class _ClientGone(Exception):
    """The browser closed the SSE stream. Not an error — unwind quietly."""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Lazarus/1.0"

    def log_message(self, fmt: str, *args) -> None:
        line = guard.scrub_secrets(fmt % args)
        sys.stderr.write("  %s %s\n" % (self.log_date_time_string(), line))

    def end_headers(self) -> None:
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def _host_ok(self) -> bool:
        """Reject foreign Host headers on loopback binds (DNS rebinding)."""
        if HOST not in ("127.0.0.1", "localhost", "::1"):
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        name = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        return name in ("127.0.0.1", "localhost", "[::1]")

    def _limited(self, bucket: str) -> bool:
        """Send 429 and return True when this client exceeded ``bucket``."""
        cap, per_min = RATE_LIMITS[bucket]
        ok, retry = RATE_LIMITER.allow(self.client_address[0], bucket, cap, per_min)
        if ok:
            return False
        body = json.dumps({"error": "rate limit exceeded", "status": 429,
                           "retry_after": retry}).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", str(retry))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        return True

    def _send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json({"error": message, "status": status}, status=status)

    def _read_json_body(self, limit: int | None = None) -> tuple[dict | None, tuple[int, str] | None]:
        """Parse a bounded JSON object body. Returns (body, None) or
        (None, (http_status, message)); the size check runs before any read."""
        limit = (MAX_UPLOAD_BYTES + 4096) if limit is None else limit
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            return None, (411, "chunked bodies are not supported; send Content-Length")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, (400, "invalid Content-Length")
        if length <= 0:
            return None, (400, "empty request body")
        if length > limit:
            self.close_connection = True
            return None, (413, f"request body too large (limit {limit} bytes)")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return None, (400, "invalid JSON body")
        if not isinstance(body, dict):
            return None, (400, "JSON body must be an object")
        return body, None

    def _json_or_fail(self, limit: int | None = None) -> dict | None:
        body, err = self._read_json_body(limit)
        if err:
            self._send_error_json(err[0], err[1])
            return None
        return body

    def _domain_arg(self, raw) -> str | None:
        """Validate a domain argument; sends 400 and returns None if bad."""
        dom = guard.valid_domain(raw)
        if dom is None:
            self._send_error_json(400, "domain must be a valid hostname such as example.com")
        return dom

    def _serve_static(self, rel: str) -> None:
        rel = (rel or "index.html").lstrip("/") or "index.html"
        target = (STATIC_DIR / rel).resolve()
        try:
            target.relative_to(STATIC_DIR.resolve())
        except ValueError:
            return self._send_error_json(403, "forbidden")
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file():
            return self._send_error_json(404, f"not found: /{rel}")
        ctype = CONTENT_TYPES.get(
            target.suffix.lower(),
            mimetypes.guess_type(str(target))[0] or "application/octet-stream",
        )
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _sse_start(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def _sse_send(self, event: str, data: dict) -> None:
        frame = (f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n").encode("utf-8")
        try:
            self.wfile.write(f"{len(frame):X}\r\n".encode("ascii") + frame + b"\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            # Tab closed / network dropped mid-scan. Raising _ClientGone lets
            # the run unwind cleanly instead of crashing the handler thread.
            raise _ClientGone("client disconnected") from None

    def _sse_heartbeat(self) -> None:
        frame = b": keep-alive\n\n"
        try:
            self.wfile.write(f"{len(frame):X}\r\n".encode("ascii") + frame + b"\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            raise _ClientGone("client disconnected") from None

    def _sse_end(self) -> None:
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        self.close_connection = True

    def _stream_repo_scan(self, content: str) -> None:
        """Stream a repo-dependency scan: parse the pasted lockfile, resolve
        every maintainer email domain, score, and emit findings over SSE.
        A bad file or dead network surfaces as an SSE error, never a crash."""
        self._sse_start()
        started = time.time()

        def progress(stage: str, message: str, done: int = 0, total: int = 0) -> None:
            self._sse_send("progress", {
                "stage": stage, "message": message,
                "done": done, "total": total,
                "elapsed": round(time.time() - started, 1),
            })

        def emit(f: dict) -> None:
            self._sse_send("finding", {"finding": redact_maintainers([f])[0]})

        try:
            lock_mod = _try_import("lockfile")
            scan_mod = _try_import("repo_scan")
            if lock_mod is None or scan_mod is None:
                self._sse_send("failed", {
                    "message": "scan-repo modules unavailable (lockfile/repo_scan)"
                })
                self._sse_end()
                return
            try:
                names = lock_mod.parse_dependencies(content)
            except lock_mod.LockfileError as exc:
                self._sse_send("failed", {"message": f"could not parse input: {guard.scrub_secrets(exc)[:200]}"})
                self._sse_end()
                return

            capped = len(names) > MAX_SCAN_DEPS
            names = names[:MAX_SCAN_DEPS]
            self._sse_send("start", {
                "mode": "repo-scan",
                "timestamp": now_iso(),
                "note": f"scanning {len(names)} dependencies for maintainer email domains"
                        + (f" (capped at {MAX_SCAN_DEPS})" if capped else ""),
            })
            progress("deps", f"parsed {len(names)} dependencies", 0, len(names))

            findings = scan_mod.scan_dependencies(names)
            total = len(findings)
            progress("score", f"resolved {total} maintainer email domain(s)", total, total)
            for i, f in enumerate(findings, 1):
                emit(f)
                progress("emit", f"finding {i}/{total}: {f.get('domain')}", i, total)

            self._sse_send("done", {
                "mode": "repo-scan",
                "finished_at": now_iso(),
                "elapsed_s": round(time.time() - started, 1),
                "findings_count": total,
                "stats": compute_stats(findings),
            })
        except _ClientGone:
            pass
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            try:
                self._sse_send("failed", {"message": guard.scrub_secrets(e)[:300]})
            except Exception:
                pass
        finally:
            try:
                self._sse_end()
            except Exception:
                self.close_connection = True

    def _stream_run(self, query: dict) -> None:
        self._sse_start()
        started = time.time()
        findings_out: list[dict] = []

        def progress(stage: str, message: str, done: int = 0, total: int = 0) -> None:
            self._sse_send("progress", {
                "stage": stage,
                "message": message,
                "done": done,
                "total": total,
                "elapsed": round(time.time() - started, 1),
            })

        def emit_finding(f: dict) -> None:
            findings_out.append(f)
            # Redact before the event leaves the process — the SSE stream is
            # as reachable as the JSON APIs.
            self._sse_send("finding", {"finding": redact_maintainers([f])[0],
                                       "index": len(findings_out)})

        mode = "replay"
        try:
            modules = {n: _try_import(n) for n in ("harvester", "rdap", "scorer", "graph", "judge")}
            forced_live = query.get("live", [""])[0] == "1" or os.environ.get("LAZARUS_LIVE") == "1"
            forced_demo = "1" in (query.get("demo", [""])[0], query.get("replay", [""])[0])
            live_ok = bool(
                forced_live
                or (
                    not forced_demo
                    and modules.get("harvester")
                    and modules.get("rdap")
                    and modules.get("scorer")
                )
            )
            mode = "live" if live_ok else "replay"
            self._sse_send("start", {
                "mode": mode,
                "timestamp": now_iso(),
                "note": (
                    "live scan via harvester/rdap/scorer"
                    if live_ok
                    else "replay of the seeded run (data/cached_run.json) — no network required"
                ),
            })

            ran_live = False
            if live_ok:
                try:
                    force = query.get("refresh", [""])[0] == "1"
                    self._run_live(progress, emit_finding, modules, force=force)
                    ran_live = True
                except _ClientGone:
                    raise  # client hung up — nothing to fall back to
                except Exception as e:
                    traceback.print_exc()
                    findings_out = []
                    progress("error", f"live pipeline failed ({guard.scrub_secrets(e)[:200]}); replaying seeded run")
            if not ran_live:
                self._run_demo(progress, emit_finding)

            meta = {
                "mode": mode if ran_live else "replay",
                "finished_at": now_iso(),
                "elapsed_s": round(time.time() - started, 1),
                "findings_count": len(findings_out),
                "stats": compute_stats(findings_out),
            }
            _record_run(findings_out, meta)
            self._sse_send("done", meta)
        except _ClientGone:
            pass  # browser closed the tab mid-scan — normal, not an error
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            traceback.print_exc()
            try:
                self._sse_send("failed", {"message": guard.scrub_secrets(e)[:300]})
            except Exception:
                pass
        finally:
            try:
                self._sse_end()
            except Exception:
                self.close_connection = True

    def _run_demo(self, progress, emit_finding) -> None:
        """REPLAY: stream the recorded findings. No network calls are made and
        nothing here is re-measured; the messages say so."""
        cached = load_cached_run()
        findings = cached.get("findings", [])
        total = len(findings)
        recorded = cached.get("recorded_at") or cached.get("generated") or "unknown date"
        progress("replay", f"replaying {total} recorded finding(s) from data/cached_run.json (recorded {recorded}); no network calls", 0, total)
        time.sleep(0.3)
        self._sse_heartbeat()
        for i, finding in enumerate(findings, 1):
            time.sleep(0.25)
            emit_finding(finding)
            progress("emit", f"finding {i}/{total}: {finding.get('domain')}", i, total)

    def _run_live(self, progress, emit_finding, modules, force: bool = False) -> None:
        harvester = modules["harvester"]
        rdap_mod = modules["rdap"]
        scorer = modules["scorer"]

        progress("harvest", "querying npm search API (popularity-ranked packages)", 0, 2)
        npm_items = harvester.harvest_npm(max_packages=60)
        progress("harvest", f"npm: {len(npm_items)} packages", 1, 2)
        pypi_items = harvester.harvest_pypi(max_packages=15)
        progress("harvest", f"pypi: {len(pypi_items)} packages", 2, 2)

        emails: list[str] = []
        domain_index: dict[str, dict] = {}

        def register(domain: str, package, dependents, downloads, maintainer, ecosystem: str) -> None:
            if not domain:
                return
            d = domain_index.setdefault(domain, {
                "packages": set(), "dependents": 0, "downloads": 0,
                "maintainers": set(), "ecosystem": ecosystem,
            })
            if package:
                d["packages"].add(str(package))
            try:
                d["dependents"] = max(d["dependents"], int(dependents or 0))
            except (TypeError, ValueError):
                pass
            try:
                d["downloads"] = max(d["downloads"], int(downloads or 0))
            except (TypeError, ValueError):
                pass
            if maintainer:
                d["maintainers"].add(str(maintainer))

        for item in npm_items:
            for m in item.get("maintainers", []) or []:
                email = (m.get("email") or "").strip().lower()
                if "@" not in email:
                    continue
                domain = email.split("@", 1)[1]
                register(domain, item.get("package"), item.get("dependents", 0),
                         item.get("downloads_week", 0), email, "npm")
                emails.append(email)
        for item in pypi_items:
            for email in item.get("maintainer_emails", []) or []:
                email = email.strip().lower()
                if "@" not in email:
                    continue
                domain = email.split("@", 1)[1]
                register(domain, item.get("package"), 0, item.get("downloads") or 0, email, "pypi")
                emails.append(email)

        domains = harvester.extract_domains(emails)[:25]
        progress("domains", f"{len(emails)} maintainer emails -> {len(domains)} unique domains (free mail excluded)", len(domains), len(domains))

        progress("rdap", "resolving registrations via IANA RDAP bootstrap", 0, len(domains))
        rdap_results = rdap_mod.resolve_domains(
            domains, str(RDAP_CACHE_PATH), force=force
        )
        progress(
            "rdap",
            f"{'re-resolved' if force else 'resolved'} {len(rdap_results)} domains"
            + (" (forced refresh)" if force else ""),
            len(rdap_results), len(domains),
        )

        rdap_by_domain = {r.get("domain"): r for r in rdap_results}
        findings: list[dict] = []
        for domain in domains:
            info = domain_index[domain]
            finding = {
                "domain": domain,
                "ecosystem": info["ecosystem"],
                "packages": sorted(info["packages"]),
                "maintainers": sorted(info["maintainers"]),
                "dependents": info["dependents"],
                "downloads_week": info["downloads"],
                "dormant": False,
                "rdap": rdap_by_domain.get(domain, {"domain": domain, "registered": None, "error": "no rdap result"}),
            }
            try:
                finding.update(scorer.score_finding(finding))
            except Exception:
                traceback.print_exc()
                finding.update({"risk": 0, "severity": "LOW", "signals": ["scorer error"], "reasoning": []})
            findings.append(finding)

        progress("score", f"scored {len(findings)} findings", len(findings), len(findings))
        findings.sort(key=lambda f: f.get("risk", 0), reverse=True)
        progress("emit", "streaming findings", 0, len(findings))
        for i, f in enumerate(findings, 1):
            time.sleep(0.3)
            emit_finding(f)
            progress("emit", f"finding {i}/{len(findings)}: {f.get('domain')}", i, len(findings))

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if not self._host_ok():
                return self._send_error_json(403, "forbidden host")
            if path in ("/", "/index.html"):
                return self._serve_static("index.html")
            if path.startswith("/api/") and self._limited("read"):
                return None
            if path == "/api/skills":
                return self._send_json(skills_payload())
            if path == "/api/findings":
                return self._send_json(findings_payload())
            if path == "/api/graph":
                findings, _ = current_findings()
                return self._send_json(build_graph(redact_maintainers(findings)))
            if path == "/api/cached":
                return self._send_json(cached_payload())
            if path == "/api/status":
                return self._send_json(status_payload())
            if path == "/api/compare":
                return self._compare(query)
            if path == "/api/run":
                if self._limited("scan"):
                    return None
                return self._guarded_scan(lambda: self._stream_run(query))
            if path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if path.startswith("/api/"):
                return self._send_error_json(404, f"unknown endpoint: {path}")
            return self._serve_static(path.lstrip("/"))
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            self._internal_error()
        return None

    def _internal_error(self) -> None:
        traceback.print_exc()
        try:
            self._send_error_json(500, "internal error")
        except Exception:
            self.close_connection = True

    def _guarded_scan(self, run) -> None:
        """Cap concurrent scans; each one fans out to RDAP/npm/PyPI."""
        if not _SCAN_SLOTS.acquire(blocking=False):
            return self._send_error_json(429, "too many scans running; try again shortly")
        try:
            return run()
        finally:
            _SCAN_SLOTS.release()

    def _find_for(self, domain: str) -> dict | None:
        findings, _ = current_findings()
        found = next((f for f in findings if f.get("domain") == domain), None)
        return found if found is not None else find_finding(domain)

    def _compare(self, query: dict) -> None:
        if self._limited("ai"):
            return None
        domain = self._domain_arg((query.get("domain") or [""])[0])
        if domain is None:
            return None
        finding = self._find_for(domain)
        if finding is None:
            return self._send_error_json(404, f"no finding for domain: {domain}")
        compare_mod = _try_import("compare")
        if compare_mod is None:
            return self._send_error_json(503, "comparison module unavailable")
        out = compare_mod.compare_finding(finding, get_judge())
        return self._send_json(out)

    def do_POST(self) -> None:
        try:
            parsed = urlparse(self.path)
            if not self._host_ok():
                return self._send_error_json(403, "forbidden host")
            route = parsed.path
            if route in ("/api/narrate", "/api/analyze", "/api/triage") and self._limited("ai"):
                return None
            if route == "/api/scan-repo" and self._limited("scan"):
                return None
            if route in ("/api/narrate", "/api/analyze"):
                body = self._json_or_fail(limit=16_384)
                if body is None:
                    return None
                domain = self._domain_arg(body.get("domain"))
                if domain is None:
                    return None
                finding = self._find_for(domain)
                if finding is None:
                    return self._send_error_json(404, f"no finding for domain: {domain}")
                if route == "/api/narrate":
                    return self._send_json({"domain": domain, **narrate_for(finding)})
                judge = get_judge()
                if judge is None:
                    return self._send_error_json(503, "no judge backend available")
                return self._send_json({"domain": domain, **judge.analyze(finding)})
            if route == "/api/scan-repo":
                body = self._json_or_fail()
                if body is None:
                    return None
                content = body.get("content")
                if not content or not isinstance(content, str):
                    return self._send_error_json(
                        400, 'body must be {"content": "<package.json or package-lock.json text>"}'
                    )
                if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
                    return self._send_error_json(
                        413, f"lockfile too large (limit {MAX_UPLOAD_BYTES} bytes)")
                if "\x00" in content:
                    return self._send_error_json(400, "content must be text")
                return self._guarded_scan(lambda: self._stream_repo_scan(content))
            if route == "/api/triage":
                findings, _ = current_findings()
                judge = get_judge()
                if judge is None:
                    return self._send_error_json(503, "no judge backend available")
                return self._send_json(judge.triage(redact_maintainers(findings)))
            return self._send_error_json(404, f"unknown endpoint: {route}")
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            self._internal_error()
        return None


def _parse_args(argv: list[str]) -> tuple[str, int]:
    host, port = HOST, PORT
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in ("--port", "--host") and i + 1 < len(argv):
            val, i = argv[i + 1], i + 1
        elif arg.startswith(("--port=", "--host=")):
            arg, val = arg.split("=", 1)
        else:
            raise SystemExit(f"lazarus: unknown argument {arg!r}\nusage: python app.py [--host H] [--port N]")
        if arg == "--port":
            if not val.isdigit() or not 1 <= int(val) <= 65535:
                raise SystemExit(f"lazarus: invalid port {val!r}")
            port = int(val)
        else:
            host = val
        i += 1
    return host, port


def main() -> None:
    global PORT, HOST
    HOST, PORT = _parse_args(sys.argv)
    _load_persisted_run()
    if not CACHED_RUN_PATH.is_file():
        print(f"[lazarus] WARNING: {CACHED_RUN_PATH} not found — /api/cached will be empty", file=sys.stderr)
    if HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"[lazarus] WARNING: listening on {HOST}; the API has no authentication. "
              "Use only on a trusted network.", file=sys.stderr)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"[lazarus] serving on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[lazarus] stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
