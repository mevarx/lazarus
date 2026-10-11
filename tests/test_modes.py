"""LIVE vs REPLAY: replay streams recorded data, makes no network calls, and is labelled as such."""

import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import app
import guard


def _events(raw: str) -> list[tuple[str, dict]]:
    out, event = [], None
    for line in raw.splitlines():
        if line.startswith("event:"):
            event = line.split(":", 1)[1].strip()
        elif line.startswith("data:") and event:
            out.append((event, json.loads(line.split(":", 1)[1])))
    return out


class ReplayModeTests(unittest.TestCase):
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
        self._tmp = tempfile.TemporaryDirectory()
        self._patches = [
            mock.patch.object(app, "LAST_RUN_PATH", Path(self._tmp.name) / "last_run.json"),
            mock.patch.object(app, "LAST_RUN", None),
            mock.patch("time.sleep", lambda *_: None),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def _get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp.status, body

    def test_replay_param_streams_recorded_findings_labelled_replay(self):
        for query in ("demo=1", "replay=1"):
            status, body = self._get("/api/run?" + query)
            self.assertEqual(status, 200)
            events = _events(body)
            kinds = [k for k, _ in events]
            self.assertEqual(kinds[0], "start")
            self.assertEqual(events[0][1]["mode"], "replay")
            self.assertIn("finding", kinds)
            done = dict(events)["done"]
            self.assertEqual(done["mode"], "replay")
            self.assertNotIn("live", json.dumps(done["mode"]))

    def test_replay_makes_no_network_calls(self):
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network used in replay")):
            status, body = self._get("/api/run?replay=1")
        self.assertEqual(status, 200)
        self.assertIn("done", [k for k, _ in _events(body)])

    def test_findings_payload_reports_replay_after_replay_run(self):
        self._get("/api/run?replay=1")
        status, body = self._get("/api/findings")
        self.assertEqual(json.loads(body)["mode"], "replay")

    def test_persisted_last_run_contains_no_maintainer_identities(self):
        finding = {"domain": "x.example", "maintainers": ["someone@x.example"], "severity": "LOW"}
        app._record_run([finding], {"mode": "live"})
        saved = json.loads(app.LAST_RUN_PATH.read_text())
        self.assertNotIn("someone", json.dumps(saved))
        self.assertEqual(app.current_mode(), "live")

    def test_status_reports_mode(self):
        status, body = self._get("/api/status")
        self.assertEqual(json.loads(body)["mode"], "replay")


if __name__ == "__main__":
    unittest.main()
