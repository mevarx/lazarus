#!/usr/bin/env python3
"""Fresh-clone check: clone the repo into a temp dir, run the tests, start the
app, hit every route, and run the CLI on the sample lockfile.

    python3 tools/fresh_clone_check.py [--repo URL_OR_PATH] [--branch NAME]

Exits 0 only if every step passed. Needs network for the clone (unless --repo
is a local path), the lockfile scan and the CLI lookups. GEMINI_API_KEY is
removed from the child environment so the run is deterministic and offline-model.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""), flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(base: str, method: str, path: str, body: dict | None = None, timeout: int = 150):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="https://github.com/mevarx/lazarus.git")
    ap.add_argument("--branch", default=None)
    args = ap.parse_args()

    env = {k: v for k, v in os.environ.items() if k not in ("GEMINI_API_KEY", "GOOGLE_API_KEY")}
    with tempfile.TemporaryDirectory(prefix="lazarus-fresh-") as tmp:
        dest = Path(tmp) / "lazarus"
        cmd = ["git", "clone", "--quiet", "--depth", "1"] + (["--branch", args.branch] if args.branch else []) + [args.repo, str(dest)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        record("git clone", r.returncode == 0, r.stderr.strip()[-200:])
        if r.returncode:
            return 1
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=dest, capture_output=True, text=True).stdout.strip()
        print(f"       commit {head} in {dest}")

        t = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                           cwd=dest, env=env, capture_output=True, text=True, timeout=600)
        tail = [ln for ln in t.stderr.splitlines() if ln.startswith(("Ran ", "OK", "FAILED"))]
        record("unit tests", t.returncode == 0, " / ".join(tail))

        port = free_port()
        server = subprocess.Popen([sys.executable, "app.py", "--port", str(port)], cwd=dest, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base = f"http://127.0.0.1:{port}"
        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen(base + "/api/status", timeout=1).read()
                    break
                except Exception:
                    time.sleep(0.2)
            status, body = call(base, "GET", "/api/status")
            record("app starts on loopback", status == 200 and json.loads(body).get("host") == "127.0.0.1", f"port {port}")

            findings = json.loads(call(base, "GET", "/api/findings")[1])["findings"]
            domain = findings[0]["domain"] if findings else "example.com"
            expect = [
                ("GET", "/", None, 200, "<title>"),
                ("GET", "/app.js", None, 200, ""),
                ("GET", "/styles.css", None, 200, ""),
                ("GET", "/favicon.ico", None, 204, ""),
                ("GET", "/api/status", None, 200, '"mode"'),
                ("GET", "/api/findings", None, 200, '"blast_radius"'),
                ("GET", "/api/cached", None, 200, '"findings"'),
                ("GET", "/api/graph", None, 200, '"nodes"'),
                ("GET", "/api/skills", None, 200, ""),
                ("GET", f"/api/compare?domain={domain}", None, 200, '"agreement"'),
                ("GET", "/api/compare?domain=not%20a%20domain", None, 400, ""),
                ("GET", "/api/nope", None, 404, ""),
                ("GET", "/api/run?replay=1", None, 200, "event: done"),
                ("POST", "/api/narrate", {"domain": domain}, 200, ""),
                ("POST", "/api/analyze", {"domain": domain}, 200, '"evidence"'),
                ("POST", "/api/triage", {}, 200, ""),
                ("POST", "/api/narrate", {"domain": "bad domain"}, 400, ""),
                ("POST", "/api/scan-repo", {"content": json.dumps({"dependencies": {"left-pad": "1.3.0"}})}, 200, "event: "),
            ]
            for method, path, payload, want, needle in expect:
                try:
                    status, text = call(base, method, path, payload)
                    ok = status == want and needle in text
                    detail = f"HTTP {status}" + ("" if not needle or needle in text else f", missing {needle!r}")
                except Exception as exc:  # noqa: BLE001
                    ok, detail = False, f"{type(exc).__name__}: {exc}"
                record(f"{method} {path.split('?')[0]}" + (" (invalid input)" if want == 400 else ""), ok, detail)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()

        def cli(*a):
            return subprocess.run([sys.executable, "lazarus.py", *a], cwd=dest, env=env,
                                  capture_output=True, text=True, timeout=300)
        c = cli("check", "examples/package-lock.json")
        record("CLI on sample lockfile (expect exit 0)", c.returncode == 0, f"exit {c.returncode}")
        c = cli("check", "does-not-exist.json")
        record("CLI missing file (expect exit 2)", c.returncode == 2, f"exit {c.returncode}")
        c = cli()
        record("CLI no arguments (expect exit 2)", c.returncode == 2, f"exit {c.returncode}")

    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed" + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
