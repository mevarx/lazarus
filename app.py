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
PORT = int(os.environ.get("PORT", "8741"))

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


def _mask_email_in_text(text: str) -> str:
    """Mask any bare email inside prose (narratives/recommendations)."""
    import re as _re
    return _re.sub(r"([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
                   lambda m: m.group(1)[:3] + "****@" + m.group(2), text or "")


def redact_maintainers(findings: list[dict]) -> list[dict]:
    """Mask maintainer emails before they leave the process.

    The dashboard also redacts client-side, but a judge can hit /api/findings
    directly with curl — so the API boundary redacts too. Domain is public
    registry data and stays; only the mailbox is masked
    (atiertant@x.net -> ati****@x.net). Non-email usernames pass through.
    Narrative/recommendation prose is masked too, since seeded narratives
    name the maintainer inline.
    """
    out = []
    for f in findings:
        if not isinstance(f, dict):
            out.append(f)
            continue
        g = dict(f)
        maint = g.get("maintainers")
        if isinstance(maint, list):
            masked = []
            for m in maint:
                s = str(m)
                at = s.find("@")
                if at > 0:
                    masked.append(s[:min(3, at)] + "****" + s[at:])
                else:
                    masked.append(s)
            g["maintainers"] = masked
        narr = g.get("narrative")
        if isinstance(narr, dict):
            g["narrative"] = {
                k: (_mask_email_in_text(v) if isinstance(v, str) else v)
                for k, v in narr.items()
            }
        out.append(g)
    return out


def current_findings() -> tuple[list[dict], str]:
    with _STATE_LOCK:
        if LAST_RUN and LAST_RUN.get("findings"):
            return list(LAST_RUN["findings"]), "last-run"
    return list(load_cached_run().get("findings", [])), "cached"


def _record_run(findings: list[dict], meta: dict) -> None:
    global LAST_RUN
    run = {"findings": findings, "meta": meta}
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


def blast_radius(findings: list[dict], *, min_severity: str = "HIGH") -> dict:
    """Aggregate the weekly-download reach controlled by at-risk domains.

    Answers: 'one lapsed domain controls packages with X combined weekly
    downloads.' Only domains at or above ``min_severity`` (CRITICAL/HIGH by
    default) count as at-risk; downloads are summed across their packages.
    A domain appears once even if several findings reference it.
    """
    order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    threshold = order.get(min_severity.upper(), 2)
    at_risk_downloads = 0
    at_risk_dependents = 0
    at_risk_domains: set[str] = set()
    at_risk_packages: set[str] = set()
    worst_domain = None
    worst_downloads = 0
    for f in findings:
        sev = str(f.get("severity") or "LOW").upper()
        if order.get(sev, 0) < threshold:
            continue
        dom = f.get("domain")
        if not dom:
            continue
        at_risk_domains.add(dom)
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
    return {
        "live": live,
        "backend": f"{backend} (live)" if live else backend,
        "has_key": bool(os.environ.get("GEMINI_API_KEY")),
    }


def cached_payload() -> dict:
    cached = dict(load_cached_run())
    findings = cached.get("findings", [])
    cached["source"] = "cached"
    cached["seeded"] = True
    safe = redact_maintainers(findings)
    cached["findings"] = safe
    cached.update(judge_status())
    cached.setdefault("stats", compute_stats(safe))
    cached.setdefault("blast_radius", blast_radius(safe))
    cached.setdefault("graph", build_graph(safe))
    return cached


def findings_payload() -> dict:
    findings, source = current_findings()
    safe = redact_maintainers(findings)
    payload = {
        "findings": safe,
        "source": source,
        "seeded": source in ("cached", "seed"),
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
        sys.stderr.write("  %s %s\n" % (self.log_date_time_string(), fmt % args))

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

    def _read_json_body(self) -> tuple[dict | None, str | None]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return None, "empty request body"
        if length > 1_000_000:
            return None, "request body too large"
        try:
            return json.loads(self.rfile.read(length).decode("utf-8")), None
        except Exception as e:
            return None, f"invalid JSON: {e}"

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
        self.send_header("X-Content-Type-Options", "nosniff")
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
                self._sse_send("failed", {"message": f"could not parse input: {exc}"})
                self._sse_end()
                return

            self._sse_send("start", {
                "mode": "repo-scan",
                "timestamp": now_iso(),
                "note": f"scanning {len(names)} dependencies for maintainer email domains",
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
                self._sse_send("failed", {"message": str(e)})
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

        mode = "demo"
        try:
            modules = {n: _try_import(n) for n in ("harvester", "rdap", "scorer", "graph", "judge")}
            forced_live = query.get("live", [""])[0] == "1" or os.environ.get("LAZARUS_LIVE") == "1"
            forced_demo = query.get("demo", [""])[0] == "1"
            live_ok = bool(
                forced_live
                or (
                    not forced_demo
                    and modules.get("harvester")
                    and modules.get("rdap")
                    and modules.get("scorer")
                )
            )
            mode = "live" if live_ok else "demo"
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
                    progress("error", f"live pipeline failed ({e}); replaying seeded run")
            if not ran_live:
                self._run_demo(progress, emit_finding)

            meta = {
                "mode": mode if ran_live else "demo",
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
                self._sse_send("failed", {"message": str(e)})
            except Exception:
                pass
        finally:
            try:
                self._sse_end()
            except Exception:
                self.close_connection = True

    def _run_demo(self, progress, emit_finding) -> None:
        findings = load_cached_run().get("findings", [])
        total = len(findings)
        progress("harvest", "replay: maintainer emails harvested — npm search API (500 pkgs) + PyPI top-packages (200)", 0, total)
        time.sleep(0.4)
        self._sse_heartbeat()
        progress("domains", f"replay: {total} unique maintainer domains (free-mail providers excluded)", 0, total)
        time.sleep(0.4)
        self._sse_heartbeat()
        progress("rdap", "replay: registration and expiry resolved via IANA RDAP bootstrap", 0, total)
        time.sleep(0.5)
        progress("score", "replay: deterministic risk scoring (INTERFACES.md rules)", 0, total)
        time.sleep(0.3)
        for i, finding in enumerate(findings, 1):
            time.sleep(0.4)
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
            if path in ("/", "/index.html"):
                return self._serve_static("index.html")
            if path == "/api/skills":
                return self._send_json(skills_payload())
            if path == "/api/findings":
                return self._send_json(findings_payload())
            if path == "/api/graph":
                findings, _ = current_findings()
                return self._send_json(build_graph(redact_maintainers(findings)))
            if path == "/api/cached":
                return self._send_json(cached_payload())
            if path == "/api/run":
                return self._stream_run(query)
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
        except Exception as e:
            traceback.print_exc()
            try:
                self._send_error_json(500, f"internal error: {e}")
            except Exception:
                self.close_connection = True
        return None

    def do_POST(self) -> None:
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/narrate":
                body, err = self._read_json_body()
                if err:
                    return self._send_error_json(400, err)
                domain = (body or {}).get("domain")
                if not domain:
                    return self._send_error_json(400, 'body must be {"domain": "..."}')
                findings, _ = current_findings()
                finding = next((f for f in findings if f.get("domain") == domain), None)
                if finding is None:
                    finding = find_finding(domain)
                if finding is None:
                    return self._send_error_json(404, f"no finding for domain: {domain}")
                out = narrate_for(finding)
                return self._send_json({"domain": domain, **out})
            if parsed.path == "/api/scan-repo":
                body, err = self._read_json_body()
                if err:
                    return self._send_error_json(400, err)
                content = (body or {}).get("content")
                if not content or not isinstance(content, str):
                    return self._send_error_json(
                        400, 'body must be {"content": "<package.json text>"}'
                    )
                return self._stream_repo_scan(content)
            if parsed.path == "/api/analyze":
                body, err = self._read_json_body()
                if err:
                    return self._send_error_json(400, err)
                domain = (body or {}).get("domain")
                if not domain:
                    return self._send_error_json(400, 'body must be {"domain": "..."}')
                findings, _ = current_findings()
                finding = next((f for f in findings if f.get("domain") == domain), None)
                if finding is None:
                    finding = find_finding(domain)
                if finding is None:
                    return self._send_error_json(404, f"no finding for domain: {domain}")
                judge = get_judge()
                if judge is None:
                    return self._send_error_json(503, "no judge backend available")
                return self._send_json({"domain": domain, **judge.analyze(finding)})
            if parsed.path == "/api/triage":
                findings, _ = current_findings()
                judge = get_judge()
                if judge is None:
                    return self._send_error_json(503, "no judge backend available")
                return self._send_json(judge.triage(findings))
            return self._send_error_json(404, f"unknown endpoint: {parsed.path}")
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as e:
            traceback.print_exc()
            try:
                self._send_error_json(500, f"internal error: {e}")
            except Exception:
                self.close_connection = True
        return None


def main() -> None:
    global PORT, HOST
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            PORT = int(sys.argv[i + 1])
        elif arg.startswith("--port="):
            PORT = int(arg.split("=", 1)[1])
        elif arg == "--host" and i + 1 < len(sys.argv):
            HOST = sys.argv[i + 1]
    _load_persisted_run()
    if not CACHED_RUN_PATH.is_file():
        print(f"[lazarus] WARNING: {CACHED_RUN_PATH} not found — /api/cached will be empty", file=sys.stderr)
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
