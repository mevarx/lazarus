"""Harvest output is deterministic metadata and contains no addresses."""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import harvest_all  # noqa: E402


class HarvestOutputCase(unittest.TestCase):
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
        self.assertEqual(payload["notes"], ["unverified empty run"])


if __name__ == "__main__":
    unittest.main()
