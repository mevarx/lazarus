"""Harvest output is deterministic metadata and contains no addresses."""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import harvest_all  # noqa: E402


class HarvestOutputCase(unittest.TestCase):
    def test_committed_harvest_has_no_addresses_or_maintainer_fields(self):
        path = Path(__file__).resolve().parents[1] / "data" / "harvest.json"
        encoded = path.read_text(encoding="utf-8")
        payload = json.loads(encoded)
        self.assertIsNone(re.search(r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", encoded))

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key.lower()
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        forbidden = {"maintainers", "maintainer_emails", "email", "handle"}
        self.assertTrue(forbidden.isdisjoint(keys(payload)))

    def test_build_and_payload_remove_all_maintainer_fields(self):
        item = {
            "package": "safe-package",
            "maintainers": [{"email": "redacted"}],
            "dependents": 10,
            "downloads_week": 20,
        }
        rdap_result = {
            "domain": "safe.example", "registered": True, "created": None,
            "expires": None, "status": [], "error": None,
            "bootstrap_status": "present", "primary_url": "https://rdap.test/",
            "alternate_urls": [], "related_urls": [],
        }
        with patch.object(harvest_all.harvester, "extract_domains", return_value=["safe.example"]), \
             patch.object(harvest_all.rdap, "resolve_domains", return_value=[rdap_result]):
            findings = harvest_all.build_findings([item])
        findings[0]["verification"] = {
            "status": "not_applicable", "reasons": [],
        }
        args = SimpleNamespace(npm=1, budget=30)
        payload = harvest_all._payload(1, findings, args, [])
        encoded = json.dumps(payload)
        self.assertIsNone(re.search(r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", encoded))
        for finding in payload["findings"]:
            self.assertNotIn("maintainers", finding)
            self.assertNotIn("maintainer_emails", finding)
            self.assertNotIn("handle", finding)
        self.assertEqual(payload["counts"]["packages_scanned"], 1)
        self.assertEqual(payload["counts"]["maintainer_domains_found"], 1)

    def test_empty_payload_has_explicit_zero_verification_counts(self):
        payload = harvest_all._payload(
            0, [], SimpleNamespace(npm=300, budget=540), ["unverified empty run"]
        )
        self.assertEqual(payload["verification"]["confirmed"], 0)
        self.assertEqual(payload["verification"]["uncertain"], 0)
        self.assertEqual(payload["verification"]["not_applicable"], 0)
        self.assertEqual(payload["notes"][0], "unverified empty run")

    def test_public_payload_withholds_domains_and_packages(self):
        rows = [{
            "domain": "personal-site.example", "ecosystem": "npm", "packages": ["widely-used"],
            "risk": 65, "severity": "HIGH", "signals": ["16071 dependents", "expiring soon"],
            "rdap": {"error": None}, "verified_severity": "HIGH", "needs_manual_check": False,
            "verification": {"status": "confirmed", "reasons": []},
        }]
        args = SimpleNamespace(npm=1, budget=30)
        public = json.dumps(harvest_all._payload(1, rows, args, []))
        private = json.dumps(harvest_all._payload(1, rows, args, [], private=True))
        for secret in ("personal-site", "widely-used", "16071"):
            self.assertNotIn(secret, public)
        self.assertIn("personal-site.example", private)
        self.assertIn('"tld": "example"', public)

    def test_committed_harvest_is_redacted_and_consistent(self):
        path = Path(__file__).resolve().parents[1] / "data" / "harvest.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(payload["redacted"])
        for finding in payload["findings"]:
            self.assertNotIn("domain", finding)
            self.assertNotIn("packages", finding)
        counts = payload["counts"]["severity"]
        self.assertEqual(sum(counts.values()), len(payload["findings"]))
        ver = payload["verification"]
        flagged = [f for f in payload["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
        self.assertEqual(ver["confirmed"] + ver["uncertain"], len(flagged))


if __name__ == "__main__":
    unittest.main()
