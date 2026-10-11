"""Harvester tests -- fully mocked transport, no network access.

Runs under `python -m pytest tests/` or `python -m unittest tests.test_harvester`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import harvester  # noqa: E402


class FakeTransport:
    """URL -> canned response, recording every request it served."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url, timeout=20, headers=None):
        self.calls.append(url)
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                if isinstance(payload, bytes):
                    return payload
                if isinstance(payload, dict):
                    return json.dumps(payload).encode("utf-8")
                raise AssertionError(f"bad fixture for {prefix!r}")
        raise AssertionError(f"unrouted URL in test: {url}")


def npm_page(names, dependents="100"):
    """Build one npm search page for the given package names."""
    objects = []
    for name in names:
        objects.append(
            {
                "package": {
                    "name": name,
                    "maintainers": [
                        {
                            "username": "alice",
                            "email": f"alice@{name.replace('-', '')}.dev",
                        },
                        {"username": "bob", "email": "bob@gmail.com"},
                    ],
                },
                "dependents": dependents,
                "downloads": {"weekly": 1, "monthly": 4},
            }
        )
    return {"objects": objects, "total": len(objects)}


class TransportCase(unittest.TestCase):
    def setUp(self):
        harvester.set_transport(None)

    def tearDown(self):
        harvester.set_transport(None)

    def test_package_name_validation(self):
        for hostile in ("../x", "a b", "http://x", "name/extra", "x" * 300):
            self.assertFalse(harvester.validate_package_name(hostile, "npm"), hostile)
        self.assertTrue(harvester.validate_package_name("@scope/name", "npm"))
        self.assertTrue(harvester.validate_package_name("valid_project-1", "pypi"))
        self.assertFalse(harvester.validate_package_name("../x", "pypi"))

    def test_response_size_timeout_and_ttl_cache(self):
        now = [10.0]
        calls = []
        timeouts = []

        def sleep_for(seconds):
            now[0] += seconds

        def fake(url, timeout=20, headers=None):
            calls.append(url)
            timeouts.append(timeout)
            return b"ok"

        harvester.set_clock(lambda: now[0], sleep_for)
        harvester.set_transport(fake)
        harvester._request("https://registry.example/a", timeout=999)
        harvester._request("https://registry.example/a")
        self.assertEqual(len(calls), 1)
        self.assertEqual(timeouts[0], harvester.MAX_TIMEOUT)
        now[0] += harvester.CACHE_TTL_SECONDS + 1
        harvester._request("https://registry.example/a")
        self.assertEqual(len(calls), 2)

        harvester.set_transport(lambda url, timeout=20, headers=None:
                                b"x" * (harvester.MAX_RESPONSE_BYTES + 1))
        with self.assertRaises(ValueError):
            harvester._request("https://registry.example/oversized")


class TestNpmHarvest(TransportCase):
    def test_pagination_and_dependents_and_bulk_downloads(self):
        page1 = npm_page([f"pkg{i}" for i in range(250)])
        page2 = npm_page([f"pkg{i}" for i in range(250, 300)], dependents="42")

        downloads = {
            f"pkg{i}": {"downloads": 1000 + i, "package": f"pkg{i}"}
            for i in range(300)
        }
        fake = FakeTransport(
            {
                harvester.NPM_SEARCH_URL: page1,
                harvester.NPM_DOWNLOADS_URL: downloads,
            }
        )
        fake.routes[harvester.NPM_SEARCH_URL + "?"] = page1
        # Route by `from=` so page 2 differs from page 1.
        fake.routes = {
            harvester.NPM_SEARCH_URL: page1,
            harvester.NPM_DOWNLOADS_URL: downloads,
        }

        def router(url, timeout=20, headers=None):
            fake.calls.append(url)
            if url.startswith(harvester.NPM_SEARCH_URL):
                if "from=250" in url:
                    return json.dumps(page2).encode()
                if "from=0" in url or "from=" not in url:
                    return json.dumps(page1).encode()
                return json.dumps({"objects": [], "total": 0}).encode()
            if url.startswith(harvester.NPM_DOWNLOADS_URL):
                names = url.rsplit("/", 1)[-1].split(",")
                return json.dumps(
                    {n: {"downloads": 1000 + int(n[3:]), "package": n} for n in names}
                ).encode()
            raise AssertionError(f"unrouted URL: {url}")

        harvester.set_transport(router)
        results = harvester.harvest_npm(300)

        self.assertEqual(len(results), 300)
        self.assertEqual(results[0]["package"], "pkg0")
        # Pagination: page 2 (from=250) must have been requested.
        search_calls = [c for c in fake.calls if c.startswith(harvester.NPM_SEARCH_URL)]
        self.assertTrue(any("from=250" in c for c in search_calls))
        # Bulk downloads: comma-separated, chunked under 51 names per call.
        dl_calls = [c for c in fake.calls if c.startswith(harvester.NPM_DOWNLOADS_URL)]
        self.assertTrue(dl_calls)
        for call in dl_calls:
            names = call.rsplit("/", 1)[-1].split(",")
            self.assertLessEqual(len(names), 51)
            self.assertIn(",", call)
        # Every package got a real download count.
        self.assertEqual(results[0]["downloads_week"], 1000)
        self.assertEqual(results[299]["downloads_week"], 1299)

    def test_dependents_string_parsed_to_int(self):
        def router(url, timeout=20, headers=None):
            if url.startswith(harvester.NPM_SEARCH_URL):
                return json.dumps(npm_page(["alpha"], dependents="20705")).encode()
            raise AssertionError(f"unrouted URL: {url}")

        harvester.set_transport(router)
        results = harvester.harvest_npm(1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["dependents"], 20705)
        self.assertIsInstance(results[0]["dependents"], int)

    def test_maintainer_name_and_email_extracted(self):
        def router(url, timeout=20, headers=None):
            if url.startswith(harvester.NPM_SEARCH_URL):
                return json.dumps(npm_page(["alpha"])).encode()
            raise AssertionError(f"unrouted URL: {url}")

        harvester.set_transport(router)
        results = harvester.harvest_npm(1)
        maintainers = results[0]["maintainers"]
        self.assertEqual(maintainers[0]["name"], "alice")
        self.assertEqual(maintainers[0]["email"], "alice@alpha.dev")
        self.assertEqual(maintainers[1]["name"], "bob")
        self.assertEqual(maintainers[1]["email"], "bob@gmail.com")

    def test_network_failure_returns_empty_not_raise(self):
        def boom(url, timeout=20, headers=None):
            raise OSError("connection refused")

        harvester.set_transport(boom)
        self.assertEqual(harvester.harvest_npm(10), [])

    def test_scoped_packages_fetched_individually(self):
        """The bulk endpoint 400s on "@scope/name"; those go one at a time."""
        search_urls, bulk_urls, single_urls = [], [], []

        def router(url, timeout=20, headers=None):
            if url.startswith(harvester.NPM_SEARCH_URL):
                search_urls.append(url)
                objects = [
                    {
                        "package": {
                            "name": name,
                            "maintainers": [{"username": "a", "email": "a@b.dev"}],
                        },
                        "dependents": "7",
                    }
                    for name in ("plain-pkg", "@vscode/web-custom-data")
                ]
                return json.dumps({"objects": objects, "total": 2}).encode()
            if url.startswith(harvester.NPM_DOWNLOADS_URL):
                tail = url.rsplit("/", 1)[-1]
                names = tail.split(",")
                if len(names) == 1:
                    # Live single-name shape is FLAT, not nested.
                    single_urls.append(url)
                    if "%2F" in tail:
                        return json.dumps(
                            {"downloads": 222, "package": "@vscode/web-custom-data"}
                        ).encode()
                    return json.dumps(
                        {"downloads": 111, "package": names[0]}
                    ).encode()
                bulk_urls.append(url)
                return json.dumps(
                    {n: {"downloads": 111} for n in names}
                ).encode()
            raise AssertionError(f"unrouted URL: {url}")

        harvester.set_transport(router)
        results = harvester.harvest_npm(2)
        self.assertEqual(len(results), 2)

        by_name = {r["package"]: r for r in results}
        self.assertEqual(by_name["plain-pkg"]["downloads_week"], 111)
        self.assertEqual(by_name["@vscode/web-custom-data"]["downloads_week"], 222)

        # Scoped name must never appear inside a comma-joined bulk URL.
        for url in bulk_urls:
            self.assertNotIn("@vscode", url)
        # ...and must be percent-encoded in its own call.
        scoped_calls = [u for u in single_urls if "%2F" in u]
        self.assertEqual(len(scoped_calls), 1)
        self.assertIn("%40vscode", scoped_calls[0])

    def test_zero_max_packages_short_circuits(self):
        calls = []

        def router(url, timeout=20, headers=None):
            calls.append(url)
            return json.dumps(npm_page(["alpha"])).encode()

        harvester.set_transport(router)
        self.assertEqual(harvester.harvest_npm(0), [])
        self.assertEqual(calls, [])


class TestPypiHarvest(TransportCase):
    def _seed(self):
        return {
            "rows": [{"download_count": 500, "project": "requests"}],
            "total_rows": 1,
        }

    def test_seed_then_packument_email_regex(self):
        seed = self._seed()
        packument = {
            "info": {
                "maintainer_email": (
                    "Ian Stapleton Cordasco <graffatcolmingov@gmail.com>, "
                    "Nate Prewitt <nate.prewitt@gmail.com>"
                ),
                "author_email": "Kenneth Reitz <me@kennethreitz.org>",
                "downloads": {"last_day": -1, "last_month": -1, "last_week": -1},
            }
        }

        def router(url, timeout=20, headers=None):
            if url.startswith(harvester.PYPI_TOP_URL):
                return json.dumps(seed).encode()
            if url.startswith("https://pypi.org/pypi/"):
                return json.dumps(packument).encode()
            raise AssertionError(f"unrouted URL: {url}")

        harvester.set_transport(router)
        results = harvester.harvest_pypi(5)

        self.assertEqual(len(results), 1)
        item = results[0]
        self.assertEqual(item["package"], "requests")
        self.assertEqual(
            item["maintainer_emails"],
            [
                "graffatcolmingov@gmail.com",
                "nate.prewitt@gmail.com",
                "me@kennethreitz.org",
            ],
        )
        self.assertEqual(item["downloads"], 500)

    def test_download_count_none_when_negative(self):
        seed = {"rows": [{"download_count": -1, "project": "flask"}], "total_rows": 1}
        packument = {
            "info": {"maintainer_email": "Pallets <contact@palletsprojects.com>"}
        }

        def router(url, timeout=20, headers=None):
            if url.startswith(harvester.PYPI_TOP_URL):
                return json.dumps(seed).encode()
            return json.dumps(packument).encode()

        harvester.set_transport(router)
        results = harvester.harvest_pypi(5)
        self.assertIsNone(results[0]["downloads"])
        self.assertEqual(results[0]["maintainer_emails"], ["contact@palletsprojects.com"])

    def test_packument_404_skipped_not_raise(self):
        seed = {
            "rows": [
                {"download_count": 10, "project": "gone"},
                {"download_count": 20, "project": "six"},
            ],
            "total_rows": 2,
        }

        def router(url, timeout=20, headers=None):
            if url.startswith(harvester.PYPI_TOP_URL):
                return json.dumps(seed).encode()
            if "pypi.org/pypi/gone" in url:
                raise AssertionError("should not be requested via json path")
            return json.dumps(
                {"info": {"author_email": "benjamin@python.org"}}
            ).encode()

        # Gone package raises inside _pypi_item and is dropped.
        def router2(url, timeout=20, headers=None):
            if url.startswith(harvester.PYPI_TOP_URL):
                return json.dumps(seed).encode()
            if "pypi.org/pypi/gone" in url:
                raise OSError("404 Not Found")
            return json.dumps(
                {"info": {"author_email": "benjamin@python.org"}}
            ).encode()

        harvester.set_transport(router2)
        results = harvester.harvest_pypi(5)
        self.assertEqual([r["package"] for r in results], ["six"])
        self.assertEqual(results[0]["maintainer_emails"], ["benjamin@python.org"])

    def test_seed_failure_returns_empty(self):
        def boom(url, timeout=20, headers=None):
            raise OSError("dns failure")

        harvester.set_transport(boom)
        self.assertEqual(harvester.harvest_pypi(10), [])


class TestExtractDomains(TransportCase):
    def test_splits_lowercases_dedupes(self):
        emails = ["Alice@Vision-Media.ca", "tj@vision-media.ca", "x@Karpov.IO"]
        self.assertEqual(
            harvester.extract_domains(emails),
            ["vision-media.ca", "karpov.io"],
        )

    def test_free_mail_excluded(self):
        emails = [
            "a@gmail.com",
            "b@outlook.com",
            "c@yahoo.com",
            "d@proton.me",
            "e@protonmail.com",
            "f@icloud.com",
            "g@hotmail.com",
            "h@live.com",
            "i@gmx.de",
            "j@mail.ru",
            "k@qq.com",
            "l@163.com",
            "m@yandex.ru",
        ]
        self.assertEqual(harvester.extract_domains(emails), [])

    def test_free_mail_excluded_but_custom_domain_kept(self):
        emails = ["a@gmail.com", "b@karpov.io"]
        self.assertEqual(harvester.extract_domains(emails), ["karpov.io"])

    def test_free_mail_case_insensitive(self):
        self.assertEqual(harvester.extract_domains(["a@GMAIL.COM"]), [])
        self.assertEqual(harvester.extract_domains(["a@Proton.ME"]), [])

    def test_subdomains_are_distinct(self):
        self.assertEqual(
            harvester.extract_domains(["a@mail.karpov.io", "b@karpov.io"]),
            ["mail.karpov.io", "karpov.io"],
        )

    def test_malformed_input_ignored(self):
        self.assertEqual(harvester.extract_domains(["nope", "", None, "x@", "@y"]), [])


class TestExtractEmails(TransportCase):
    def test_regex_pulls_addresses_from_free_text(self):
        text = (
            "Ian Stapleton Cordasco <graffatcolmingov@gmail.com>, "
            "Nate Prewitt <nate.prewitt@gmail.com>"
        )
        self.assertEqual(
            harvester.extract_emails(text),
            ["graffatcolmingov@gmail.com", "nate.prewitt@gmail.com"],
        )

    def test_bare_address(self):
        self.assertEqual(
            harvester.extract_emails("benjamin@python.org"), ["benjamin@python.org"]
        )

    def test_deduped_and_lowercased(self):
        self.assertEqual(
            harvester.extract_emails("A@B.COM a@b.com"), ["a@b.com"]
        )

    def test_none_and_empty(self):
        self.assertEqual(harvester.extract_emails(None), [])
        self.assertEqual(harvester.extract_emails(""), [])
        self.assertEqual(harvester.extract_emails("no emails here"), [])


class TestParseInt(unittest.TestCase):
    def test_npm_dependents_string(self):
        self.assertEqual(harvester._parse_int("20705"), 20705)
        self.assertEqual(harvester._parse_int("1,234"), 1234)
        self.assertEqual(harvester._parse_int("0"), 0)

    def test_none_and_junk(self):
        self.assertEqual(harvester._parse_int(None), 0)
        self.assertEqual(harvester._parse_int("abc"), 0)
        self.assertEqual(harvester._parse_int(""), 0)

    def test_int_passthrough(self):
        self.assertEqual(harvester._parse_int(42), 42)
        self.assertEqual(harvester._parse_int(True), 1)
        self.assertEqual(harvester._parse_int(3.9), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
