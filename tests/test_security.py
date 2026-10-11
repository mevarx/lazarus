"""Input validation, size caps, rate limiting, headers and secret hygiene."""

import http.client
import io
import json
import os
import re
import subprocess
import sys
import threading
import unittest
from contextlib import redirect_stderr
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import app
import guard

ROOT = Path(__file__).resolve().parent.parent
FAKE_KEY = "AIzaSyFAKEKEYFORTESTS0123456789abcdefg"


class GuardUnitTests(unittest.TestCase):
    def test_valid_domain_accepts_normal_names(self):
        self.assertEqual(guard.valid_domain("Example.COM."), "example.com")
        self.assertEqual(guard.valid_domain("atlantis-software.net"), "atlantis-software.net")
        self.assertEqual(guard.valid_domain("bücher.example"), "xn--bcher-kva.example")

    def test_valid_domain_rejects_hostile_input(self):
        bad = [
            "", " ", "localhost", "a", "1.2.3.4", "http://x.com", "x.com/path", "x.com:80",
            "user@x.com", "a b.com", "x.com\r\nHost: evil", "../etc/passwd", "-a.com", "a-.com",
            "a" * 64 + ".com", ("a." * 130) + "com", "x.com?q=1", "x.com#f", "x.123", "[::1]",
            "x\x00.com", None, 5, ["x.com"], {"d": "x.com"},
        ]
        for value in bad:
            self.assertIsNone(guard.valid_domain(value), repr(value))

    def test_rate_limiter_refills_with_clock(self):
        now = [0.0]
        rl = guard.RateLimiter(clock=lambda: now[0])
        self.assertTrue(all(rl.allow("c", "b", 3, 60)[0] for _ in range(3)))
        ok, retry = rl.allow("c", "b", 3, 60)
        self.assertFalse(ok)
        self.assertGreaterEqual(retry, 1)
        now[0] += 1.01
        self.assertTrue(rl.allow("c", "b", 3, 60)[0])
        self.assertTrue(rl.allow("other", "b", 3, 60)[0])

    def test_scrub_secrets(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": FAKE_KEY}):
            text = f"GET /x?key={FAKE_KEY} failed with {FAKE_KEY} and x-goog-api-key: {FAKE_KEY}"
            out = guard.scrub_secrets(text)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn("SyFAKE", out)

    def test_redaction_masks_emails_and_handles(self):
        out = guard.redact_maintainer_text(
            "Mail dev.person@old-domain.net or ask dev.person (handle zed99).", ["dev.person@old-domain.net", "zed99"])
        self.assertNotIn("dev.person", out)
        self.assertNotIn("zed99", out)
        self.assertIn("@old-domain.net", out)

    def test_api_redaction_replaces_maintainers_with_placeholders(self):
        f = {"domain": "x.example", "maintainers": ["someone@x.example", "handle1"],
             "narrative": {"narrative": "Contact someone@x.example or handle1 now."}}
        g = app.redact_maintainers([f])[0]
        self.assertEqual(g["maintainers"], ["maintainer-1-1", "maintainer-1-2"])
        self.assertEqual(g["maintainer_count"], 2)
        blob = json.dumps(g)
        self.assertNotIn("someone", blob)
        self.assertNotIn("handle1", blob)
        self.assertEqual(f["maintainers"][0], "someone@x.example", "input must not be mutated")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        app.RATE_LIMITER = guard.RateLimiter()

    def req(self, method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        conn.close()
        return resp, payload

    def test_security_headers_on_static_and_api(self):
        for path in ("/", "/api/status"):
            resp, _ = self.req("GET", path)
            self.assertEqual(resp.status, 200, path)
            self.assertIn("default-src 'none'", resp.getheader("Content-Security-Policy"))
            self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")

    def test_foreign_host_header_rejected(self):
        resp, _ = self.req("GET", "/api/status", headers={"Host": "evil.example"})
        self.assertEqual(resp.status, 403)

    def test_status_never_exposes_key(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": FAKE_KEY}):
            resp, payload = self.req("GET", "/api/status")
        self.assertEqual(resp.status, 200)
        self.assertNotIn(FAKE_KEY.encode(), payload)
        self.assertIn(b'"has_key": true', payload)

    def test_path_traversal_blocked(self):
        resp, _ = self.req("GET", "/..%2f..%2fapp.py")
        self.assertIn(resp.status, (403, 404))
        resp, payload = self.req("GET", "/../app.py")
        self.assertIn(resp.status, (403, 404))
        self.assertNotIn(b"ThreadingHTTPServer", payload)

    def test_domain_validation_on_get_and_post(self):
        resp, _ = self.req("GET", "/api/compare?domain=" + "x.com%2Fpath")
        self.assertEqual(resp.status, 400)
        for bad in ("", "http://x.com", 5, None, "a b"):
            resp, _ = self.req("POST", "/api/narrate", {"domain": bad})
            self.assertEqual(resp.status, 400, repr(bad))

    def test_unknown_domain_is_404(self):
        resp, _ = self.req("POST", "/api/narrate", {"domain": "no-such-finding.example"})
        self.assertEqual(resp.status, 404)

    def test_oversized_body_rejected_before_read(self):
        resp, payload = self.req("POST", "/api/narrate", raw=b"x" * 20_000,
                                 headers={"Content-Type": "application/json"})
        self.assertEqual(resp.status, 413)
        self.assertIn(b"too large", payload)

    def test_lockfile_upload_cap(self):
        with mock.patch.object(app, "MAX_UPLOAD_BYTES", 5_000):
            big = json.dumps({"content": "a" * 6_000}).encode()
            resp, _ = self.req("POST", "/api/scan-repo", raw=big)
        self.assertEqual(resp.status, 413)

    def test_bad_json_and_shapes(self):
        resp, _ = self.req("POST", "/api/narrate", raw=b"{not json")
        self.assertEqual(resp.status, 400)
        resp, _ = self.req("POST", "/api/narrate", raw=b"[1,2]")
        self.assertEqual(resp.status, 400)
        resp, _ = self.req("POST", "/api/scan-repo", {"content": 12})
        self.assertEqual(resp.status, 400)
        resp, _ = self.req("POST", "/api/scan-repo", {"content": "a\x00b"})
        self.assertEqual(resp.status, 400)

    def test_chunked_body_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/narrate")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.putheader("Content-Type", "application/json")
        conn.endheaders()
        conn.send(b"5\r\n{\"a\":\r\n0\r\n\r\n")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 411)

    def test_ai_routes_are_rate_limited(self):
        statuses = [self.req("POST", "/api/narrate", {"domain": "no-such-finding.example"})[0].status
                    for _ in range(app.RATE_LIMITS["ai"][0] + 3)]
        self.assertIn(429, statuses)
        resp, payload = self.req("POST", "/api/narrate", {"domain": "no-such-finding.example"})
        self.assertEqual(resp.status, 429)
        self.assertIsNotNone(resp.getheader("Retry-After"))

    def test_unexpected_error_is_generic_and_logged_without_key(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": FAKE_KEY}), \
                mock.patch.object(app, "skills_payload", side_effect=RuntimeError(f"boom {FAKE_KEY}")), \
                redirect_stderr(err):
            resp, payload = self.req("GET", "/api/skills")
        self.assertEqual(resp.status, 500)
        self.assertNotIn(b"boom", payload)
        self.assertNotIn(FAKE_KEY.encode(), payload)

    def test_request_log_never_contains_key(self):
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": FAKE_KEY}), redirect_stderr(err):
            self.req("GET", f"/api/status?key={FAKE_KEY}")
        self.assertNotIn(FAKE_KEY, err.getvalue())

    def test_compare_route_uses_compare_module(self):
        fake = mock.Mock()
        fake.compare_finding.return_value = {"domain": "x", "agreement": {"status": "agree"}}
        target = app.current_findings()[0][0]["domain"]
        with mock.patch.object(app, "_try_import", side_effect=lambda n: fake if n == "compare" else None):
            resp, payload = self.req("GET", f"/api/compare?domain={target}")
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(payload)["agreement"]["status"], "agree")
        fake.compare_finding.assert_called_once()


class DefaultsTests(unittest.TestCase):
    def test_default_bind_is_loopback(self):
        env = {k: v for k, v in os.environ.items() if k not in ("HOST", "PORT")}
        out = subprocess.run([sys.executable, "-c", "import app; print(app.HOST, app.PORT)"],
                             cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.stdout.split(), ["127.0.0.1", "8741"], out.stderr)

    def test_usage_errors_exit_nonzero(self):
        for argv in (["--port", "abc"], ["--port", "70000"], ["--bogus"]):
            out = subprocess.run([sys.executable, "app.py", *argv], cwd=ROOT,
                                 capture_output=True, text=True, timeout=30)
            self.assertNotEqual(out.returncode, 0, argv)


class SecretHygieneTests(unittest.TestCase):
    SECRET_PATTERNS = [
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        re.compile(r"sk-[A-Za-z0-9]{32,}"),
    ]

    def _tracked_files(self):
        try:
            out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, timeout=30)
            if out.returncode == 0 and out.stdout.strip():
                return [ROOT / p for p in out.stdout.splitlines()]
        except (OSError, subprocess.SubprocessError):
            pass
        return [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]

    def test_gitignore_covers_secret_and_runtime_files(self):
        lines = {ln.strip() for ln in (ROOT / ".gitignore").read_text().splitlines()}
        for needed in (".env", ".env.*", "*.pem", "*.key", "data/last_run.json", "data/rdap_cache.json"):
            self.assertIn(needed, lines, f".gitignore must list {needed}")

    def test_git_actually_ignores_env_files(self):
        for name in (".env", ".env.local", "secrets.key", "server.pem"):
            out = subprocess.run(["git", "check-ignore", "-q", name], cwd=ROOT, timeout=30)
            if out.returncode == 128:
                self.skipTest("not a git checkout")
            self.assertEqual(out.returncode, 0, f"{name} is not ignored")

    def test_no_secrets_or_env_files_tracked(self):
        for path in self._tracked_files():
            self.assertFalse(path.name == ".env" or path.suffix in (".pem", ".key"), str(path))
            if path.suffix in (".png", ".jpg", ".ico", ".woff", ".woff2") or not path.is_file():
                continue
            text = path.read_text(errors="ignore")
            for pat in self.SECRET_PATTERNS:
                if pat.search(text) and path.name != "test_security.py":
                    self.fail(f"possible secret ({pat.pattern}) in {path.relative_to(ROOT)}")

    def test_source_never_logs_or_prints_key_variable(self):
        for name in ("app.py", "judge.py", "compare.py", "lazarus.py"):
            path = ROOT / name
            if not path.exists():
                continue
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if re.search(r"\b(print|log\w*|write)\(.*(api_key|GEMINI_API_KEY)", line) \
                        and "has_key" not in line and "bool(" not in line:
                    self.fail(f"{name}:{n} may log the API key: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
