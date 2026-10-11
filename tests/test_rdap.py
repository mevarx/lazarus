"""RDAP tests -- fully mocked transport, no network access.

Runs under `python -m pytest tests/` or `python -m unittest tests.test_rdap`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rdap  # noqa: E402


_UNSET = object()

BOOTSTRAP = {
    "version": "1.0",
    "services": [
        [["net"], ["https://rdap.verisign.com/net/v1/"]],
        [["com"], ["https://rdap.verisign.com/com/v1/"]],
        [
            ["dev", "io"],
            ["https://rdap.nic.io/v1/", "https://www.registry.google/rdap/"],
        ],
        [[""], ["https://rdap.example/fallback/"]],
    ],
}


def domain_payload(events=_UNSET, status=_UNSET):
    return {
        "objectClassName": "domain",
        "handle": "123",
        "ldhName": "EXAMPLE.NET",
        "events": events
        if events is not _UNSET
        else [
            {"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"},
            {"eventAction": "expiration", "eventDate": "2027-01-02T03:04:05Z"},
            {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
        ],
        "status": status if status is not _UNSET else ["client transfer prohibited"],
    }


class RDAPCase(unittest.TestCase):
    def setUp(self):
        rdap.set_transport(None)
        rdap.reset_state()

    def tearDown(self):
        rdap.set_transport(None)
        rdap.reset_state()

    # ---------------- TLD bootstrap routing ----------------
    def test_tld_bootstrap_routing(self):
        seen = []

        def router(url, timeout=20, headers=None):
            seen.append(url)
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps(domain_payload()).encode()

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertTrue(result["registered"])
        # .net must route to the verisign net base URL, not .com or .io.
        self.assertEqual(
            seen[-1], "https://rdap.verisign.com/net/v1/domain/example.net"
        )

    def test_tld_routing_picks_first_server_of_multi_server_tld(self):
        seen = []

        def router(url, timeout=20, headers=None):
            seen.append(url)
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps(domain_payload()).encode()

        rdap.set_transport(router)
        rdap.resolve_domain("thing.dev")
        self.assertEqual(seen[-1], "https://rdap.nic.io/v1/domain/thing.dev")

    def test_tld_bootstrap_fetched_once_per_process(self):
        seen = []

        def router(url, timeout=20, headers=None):
            seen.append(url)
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps(domain_payload()).encode()

        rdap.set_transport(router)
        rdap.resolve_domain("a.net")
        rdap.resolve_domain("b.net")
        self.assertEqual(sum(1 for u in seen if u == rdap.BOOTSTRAP_URL), 1)

    def test_unknown_tld_gives_error_not_raise(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            raise AssertionError(f"should not query {url}")

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.zzzznotatld")
        self.assertFalse(result["registered"])
        self.assertIn("no public RDAP server", result["error"])

    # ---------------- fallback map for TLDs missing from IANA bootstrap ----
    def test_fallback_map_resolves_tld_absent_from_bootstrap(self):
        """io/es/co are absent from the real IANA bootstrap but have public
        RDAP servers; the fallback map must route them. (.es is absent from
        the test fixture BOOTSTRAP too, unlike .io.)"""
        seen = []

        def router(url, timeout=20, headers=None):
            seen.append(url)
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            if "rdap.nic.es" in url:  # the .es fallback endpoint
                return json.dumps(
                    {"events": [{"eventAction": "registration",
                                 "eventDate": "2016-03-04T00:00:00Z"}]}
                ).encode()
            raise AssertionError(f"unexpected URL {url}")

        rdap.set_transport(router)
        result = rdap.resolve_domain("sitnik.es")
        self.assertTrue(result["registered"])
        self.assertEqual(result["created"], "2016-03-04T00:00:00Z")
        self.assertIsNone(result["error"])

    def test_bootstrap_takes_precedence_over_fallback(self):
        """When the bootstrap DOES know a TLD, it wins over the fallback map."""
        base = rdap._base_url_for("example.net")
        self.assertIn("verisign", base)  # from the fake BOOTSTRAP, not a fallback

    def test_known_fallback_tlds_are_https(self):
        for tld, url in rdap.FALLBACK_SERVERS.items():
            self.assertTrue(url.startswith("https://"), tld)
            self.assertTrue(url.endswith("/"), tld)

    # ---------------- 404 -> unregistered ----------------
    def test_404_means_unregistered(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            raise rdap.HttpError("HTTP 404 Not Found", code=404)

        rdap.set_transport(router)
        result = rdap.resolve_domain("atlantis-software.net")
        self.assertFalse(result["registered"])
        self.assertIsNone(result["created"])
        self.assertIsNone(result["expires"])
        self.assertIsNone(result["error"])

    def test_404_survives_urllib_httperror_shape(self):
        import urllib.error

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        # Wrap so the real code path (HTTPError -> code 404) is exercised:
        # our _request converts it, so call through the real converter.
        rdap.set_transport(None)
        original = rdap.urllib.request.urlopen

        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload

            def read(self):
                return self._payload

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=20):
            url = req.full_url
            if url == rdap.BOOTSTRAP_URL:
                return FakeResponse(json.dumps(BOOTSTRAP).encode())
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        rdap.urllib.request.urlopen = fake_urlopen
        try:
            result = rdap.resolve_domain("atlantis-software.net")
        finally:
            rdap.urllib.request.urlopen = original
        self.assertFalse(result["registered"])
        self.assertIsNone(result["error"])

    # ---------------- event parsing ----------------
    def test_event_parsing_registration_and_expiration(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps(
                domain_payload(
                    events=[
                        {"eventAction": "registration", "eventDate": "2026-05-07T11:49:33Z"},
                        {"eventAction": "expiration", "eventDate": "2027-05-07T11:49:33Z"},
                    ]
                )
            ).encode()

        rdap.set_transport(router)
        result = rdap.resolve_domain("atlantis-software.net")
        self.assertTrue(result["registered"])
        self.assertEqual(result["created"], "2026-05-07T11:49:33Z")
        self.assertEqual(result["expires"], "2027-05-07T11:49:33Z")
        self.assertEqual(result["status"], ["client transfer prohibited"])
        self.assertIsNone(result["error"])

    def test_created_date_is_2026_05_07(self):
        """The atlantis-software.net registration date is a verified fact."""

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps(
                domain_payload(
                    events=[
                        {"eventAction": "registration", "eventDate": "2026-05-07T11:49:33Z"},
                        {"eventAction": "expiration", "eventDate": "2027-05-07T11:49:33Z"},
                    ]
                )
            ).encode()

        rdap.set_transport(router)
        self.assertTrue(
            rdap.resolve_domain("atlantis-software.net")["created"].startswith("2026-05-07")
        )

    def test_reregistration_event_sets_created(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps(
                domain_payload(
                    events=[
                        {"eventAction": "registration", "eventDate": "2011-04-04T00:00:00Z"},
                        {"eventAction": "reregistration", "eventDate": "2026-05-07T11:49:33Z"},
                        {"eventAction": "expiration", "eventDate": "2027-05-07T11:49:33Z"},
                    ]
                )
            ).encode()

        rdap.set_transport(router)
        self.assertEqual(
            rdap.resolve_domain("node-ipc.com")["created"], "2026-05-07T11:49:33Z"
        )

    def test_missing_events_leaves_none(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps({"status": ["active"]}).encode()

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertTrue(result["registered"])
        self.assertIsNone(result["created"])
        self.assertIsNone(result["expires"])
        self.assertEqual(result["status"], ["active"])

    def test_status_missing_or_not_a_list(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return json.dumps(domain_payload(status=None)).encode()

        rdap.set_transport(router)
        self.assertEqual(rdap.resolve_domain("example.net")["status"], [])

    def test_non_dict_payload_gives_error(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            return b'"just a string"'

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertFalse(result["registered"])
        self.assertIn("unexpected RDAP payload", result["error"])

    # ---------------- never raises ----------------
    def test_network_error_becomes_error_field(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            raise OSError("connection reset by peer")

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertFalse(result["registered"])
        self.assertIn("network error", result["error"])
        self.assertIsNone(result["created"])

    def test_httperror_code_field_carries_message(self):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            raise rdap.HttpError("HTTP 500 boom", code=500)

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertIn("500", result["error"])

    def test_empty_domain(self):
        self.assertFalse(rdap.resolve_domain("")["registered"])
        self.assertEqual(rdap.resolve_domain("   ")["error"], "empty domain")

    def test_bootstrap_failure_becomes_error(self):
        def router(url, timeout=20, headers=None):
            raise OSError("no dns")

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertFalse(result["registered"])
        self.assertIn("bootstrap failed", result["error"])

    def test_user_agent_is_polite(self):
        seen_headers = []

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            seen_headers.append(headers)
            return json.dumps(domain_payload()).encode()

        rdap.set_transport(router)
        rdap.resolve_domain("example.net")
        self.assertIn("User-Agent", seen_headers[0])
        self.assertIn("lazarus-research", seen_headers[0]["User-Agent"])
        self.assertIn("contact:", seen_headers[0]["User-Agent"])

    def test_stagger_between_requests(self):
        import time as _time

        sleeps = []
        real_sleep = _time.sleep
        rdap.time.sleep = lambda s: sleeps.append(s)  # type: ignore[assignment]
        try:
            def router(url, timeout=20, headers=None):
                if url == rdap.BOOTSTRAP_URL:
                    return json.dumps(BOOTSTRAP).encode()
                return json.dumps(domain_payload()).encode()

            rdap.set_transport(router)
            rdap.resolve_domain("a.net")
            rdap.resolve_domain("b.net")
        finally:
            rdap.time.sleep = real_sleep
        self.assertTrue(sleeps, "expected at least one stagger sleep")
        self.assertGreaterEqual(min(sleeps), rdap.STAGGER_SECONDS * 0.99)

    def test_retry_once_on_5xx(self):
        attempts = {"n": 0}

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise rdap.HttpError("HTTP 503 busy", code=503)
            return json.dumps(domain_payload()).encode()

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertEqual(attempts["n"], 2)
        self.assertTrue(result["registered"])

    def test_5xx_gives_up_after_two_attempts(self):
        attempts = {"n": 0}

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            attempts["n"] += 1
            raise rdap.HttpError("HTTP 500 dead", code=500)

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertEqual(attempts["n"], 2)
        self.assertFalse(result["registered"])
        self.assertIn("500", result["error"])

    def test_404_is_not_retried(self):
        attempts = {"n": 0}

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            attempts["n"] += 1
            raise rdap.HttpError("HTTP 404", code=404)

        rdap.set_transport(router)
        result = rdap.resolve_domain("example.net")
        self.assertEqual(attempts["n"], 1)
        self.assertFalse(result["registered"])
        self.assertIsNone(result["error"])


class TestResolveDomainsCache(RDAPCase):
    def _router(self, counter, extra=()):
        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            counter["n"] += 1
            for tld, events in extra:
                if tld in url:
                    return json.dumps(domain_payload(events=events)).encode()
            return json.dumps(domain_payload()).encode()

        return router

    def test_cache_hit_avoids_refetch(self):
        counter = {"n": 0}
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "rdap.json")

            rdap.set_transport(self._router(counter))
            first = rdap.resolve_domains(["a.net", "b.net"], cache_path, concurrency=2)
            calls_first = counter["n"]
            self.assertEqual(calls_first, 2)

            # Second run with a transport that explodes if touched.
            def boom(url, timeout=20, headers=None):
                raise AssertionError(f"cache miss on {url}")

            rdap.set_transport(boom)
            second = rdap.resolve_domains(["a.net", "b.net"], cache_path)
            self.assertEqual(len(second), 2)
            self.assertEqual(second[0]["domain"], "a.net")
            self.assertTrue(second[0]["registered"])
            self.assertEqual(second, first)

            # A genuinely new domain still hits the network.
            rdap.set_transport(self._router(counter))
            third = rdap.resolve_domains(["c.net"], cache_path)
            self.assertEqual(counter["n"], calls_first + 1)
            self.assertTrue(third[0]["registered"])

    def test_cache_file_written_and_reloadable(self):
        counter = {"n": 0}
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "nested", "rdap.json")
            rdap.set_transport(self._router(counter))
            rdap.resolve_domains(["a.net"], cache_path)
            self.assertTrue(os.path.exists(cache_path))
            with open(cache_path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertIn("a.net", data)
            self.assertTrue(data["a.net"]["registered"])

    def test_result_order_follows_input(self):
        counter = {"n": 0}
        with tempfile.TemporaryDirectory() as tmp:
            rdap.set_transport(self._router(counter))
            out = rdap.resolve_domains(
                ["z.net", "a.net", "m.net"], os.path.join(tmp, "c.json")
            )
            self.assertEqual([r["domain"] for r in out], ["z.net", "a.net", "m.net"])

    def test_duplicate_domains_deduped(self):
        counter = {"n": 0}
        with tempfile.TemporaryDirectory() as tmp:
            rdap.set_transport(self._router(counter))
            out = rdap.resolve_domains(
                ["A.net", "a.net", " a.NET ", "b.net"], os.path.join(tmp, "c.json")
            )
            # Case/whitespace variants collapse to one fetch per unique domain.
            self.assertEqual(counter["n"], 2)
            # One result per unique domain, in first-seen order.
            self.assertEqual([r["domain"] for r in out], ["a.net", "b.net"])

    def test_transient_error_not_cached_so_next_run_retries(self):
        counter = {"n": 0}

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            counter["n"] += 1
            raise OSError("connection reset")

        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "c.json")
            rdap.set_transport(router)
            first = rdap.resolve_domains(["a.net"], cache_path)
            self.assertIn("network error", first[0]["error"])
            with open(cache_path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), {})

            # Second run succeeds and gets cached.
            rdap.set_transport(self._router(counter))
            second = rdap.resolve_domains(["a.net"], cache_path)
            self.assertTrue(second[0]["registered"])
            with open(cache_path, encoding="utf-8") as fh:
                self.assertIn("a.net", json.load(fh))

    def test_empty_and_bad_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(rdap.resolve_domains([], os.path.join(tmp, "c.json")), [])
            self.assertEqual(
                rdap.resolve_domains(None, os.path.join(tmp, "c.json")), []
            )
            self.assertEqual(
                rdap.resolve_domains(["  ", None], os.path.join(tmp, "c.json")), []
            )

    def test_corrupt_cache_file_treated_as_empty(self):
        counter = {"n": 0}
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = os.path.join(tmp, "c.json")
            with open(cache_path, "w", encoding="utf-8") as fh:
                fh.write("{not json at all")
            rdap.set_transport(self._router(counter))
            out = rdap.resolve_domains(["a.net"], cache_path)
            self.assertTrue(out[0]["registered"])

    def test_concurrency_uses_thread_pool(self):
        import threading

        counter = {"n": 0}
        threads = set()
        lock = threading.Lock()

        def router(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            with lock:
                threads.add(threading.current_thread().name)
                counter["n"] += 1
            return json.dumps(domain_payload()).encode()

        with tempfile.TemporaryDirectory() as tmp:
            rdap.set_transport(router)
            rdap.resolve_domains(
                [f"d{i}.net" for i in range(6)],
                os.path.join(tmp, "c.json"),
                concurrency=4,
            )
            self.assertEqual(counter["n"], 6)
            self.assertGreater(len(threads), 1, "expected worker threads to run")


class TestCacheHelpers(RDAPCase):
    def test_load_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(rdap.load_cache(os.path.join(tmp, "nope.json")), {})

    def test_load_non_dict_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("[1,2,3]")
            self.assertEqual(rdap.load_cache(path), {})

    def test_save_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a", "b", "c.json")
            rdap.save_cache(path, {"x": {"y": 1}})
            self.assertTrue(os.path.exists(path))
            self.assertEqual(rdap.load_cache(path), {"x": {"y": 1}})

    def test_save_is_atomic_no_tmp_left(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            rdap.save_cache(path, {"a": 1})
            self.assertEqual(
                sorted(os.listdir(tmp)), ["c.json"], "temp file should be replaced"
            )

    def test_domain_validation_and_idna_normalization(self):
        self.assertEqual(rdap.normalize_domain(" EXAMPLE.NET. "), "example.net")
        self.assertTrue(rdap.normalize_domain("bücher.example").startswith("xn--"))
        for hostile in ("../x", "a b", "http://x", "127.0.0.1", "x" * 300):
            self.assertIsNone(rdap.normalize_domain(hostile), hostile)
        result = rdap.resolve_domain("http://x")
        self.assertEqual(result["error"], "invalid domain")

    def test_response_size_and_timeout_caps(self):
        seen = []

        def fake(url, timeout=20, headers=None):
            seen.append(timeout)
            return b"x" * (rdap.MAX_RESPONSE_BYTES + 1)

        rdap.set_transport(fake)
        with self.assertRaises(rdap.HttpError):
            rdap._request("https://example.test/data", timeout=999)
        self.assertEqual(seen, [rdap.MAX_TIMEOUT])

    def test_per_host_limiter_with_injected_clock(self):
        now = [10.0]
        sleeps = []

        def sleep_for(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        rdap.set_clock(lambda: now[0], sleep_for)
        rdap.set_transport(lambda url, timeout=20, headers=None: b"ok")
        rdap._request("https://one.example/a")
        rdap._request("https://one.example/b")
        rdap._request("https://two.example/a")
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], rdap.STAGGER_SECONDS)

    def test_domain_cache_ttl_with_injected_clock(self):
        now = [100.0]
        calls = {"domain": 0}

        def fake(url, timeout=20, headers=None):
            if url == rdap.BOOTSTRAP_URL:
                return json.dumps(BOOTSTRAP).encode()
            calls["domain"] += 1
            return json.dumps(domain_payload()).encode()

        rdap.set_clock(lambda: now[0], lambda seconds: now.__setitem__(0, now[0] + seconds))
        rdap.set_transport(fake)
        with tempfile.TemporaryDirectory() as tmp:
            cache = os.path.join(tmp, "rdap.json")
            rdap.resolve_domains(["a.net"], cache)
            rdap.resolve_domains(["a.net"], cache)
            self.assertEqual(calls["domain"], 1)
            now[0] += rdap.CACHE_TTL_SECONDS + 1
            rdap.resolve_domains(["a.net"], cache)
            self.assertEqual(calls["domain"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
