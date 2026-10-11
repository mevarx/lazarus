"""Verification rule tests use fakes and never perform network lookups."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verify  # noqa: E402


def finding(**rdap_overrides):
    data = {
        "registered": True,
        "created": "2020-01-01T00:00:00Z",
        "error": None,
        "bootstrap_status": "present",
        "primary_url": "https://rdap.primary.test/",
        "alternate_urls": [],
        "related_urls": [],
    }
    data.update(rdap_overrides)
    return {"domain": "sample.example", "severity": "HIGH", "rdap": data}


def dns_agrees(domain, qtype):
    return {"status": "NOERROR", "answers": ["ns.sample.example"] if qtype == "NS" else []}


class VerifyCase(unittest.TestCase):
    def test_rdap_error_requires_manual_check(self):
        result = verify.verify_findings(
            [finding(error="timeout")], dns_lookup=dns_agrees
        )[0]
        self.assertEqual(result["verification"]["status"], "needs_manual_check")
        self.assertIn("rdap_error", result["verification"]["reasons"])
        self.assertTrue(result["needs_manual_check"])

    def test_missing_bootstrap_entry_requires_manual_check(self):
        result = verify.verify_findings(
            [finding(bootstrap_status="missing")], dns_lookup=dns_agrees
        )[0]
        self.assertIn("tld_bootstrap_missing", result["verification"]["reasons"])

    def test_not_found_with_dns_delegation_is_uncertain(self):
        result = verify.verify_findings(
            [finding(registered=False, created=None)], dns_lookup=dns_agrees
        )[0]
        self.assertEqual(result["verification"]["status"], "needs_manual_check")
        self.assertIn("rdap_not_found_dns_present", result["verification"]["reasons"])

    def test_registered_and_dns_agree_confirms(self):
        result = verify.verify_findings([finding()], dns_lookup=dns_agrees)[0]
        self.assertEqual(result["verification"]["status"], "confirmed")
        self.assertEqual(result["verified_severity"], "HIGH")
        self.assertFalse(result["needs_manual_check"])

    def test_second_rdap_disagreement_requires_manual_check(self):
        result = verify.verify_findings(
            [finding(alternate_urls=["https://rdap.secondary.test/"])],
            dns_lookup=dns_agrees,
            second_rdap_lookup=lambda domain, url: {
                "registered": False, "created": None, "error": None,
            },
        )[0]
        self.assertIn("second_rdap_disagreement", result["verification"]["reasons"])

    def test_dns_failure_requires_manual_check(self):
        failed = lambda domain, qtype: {"status": "ERROR", "answers": []}
        result = verify.verify_findings([finding()], dns_lookup=failed)[0]
        self.assertIn("dns_lookup_failed", result["verification"]["reasons"])
        self.assertEqual(result["verified_severity"], "UNVERIFIED")

    def test_below_high_is_not_applicable_without_network(self):
        calls = []
        result = verify.verify_findings(
            [{"domain": "sample.example", "severity": "MEDIUM"}],
            dns_lookup=lambda *args: calls.append(args),
        )[0]
        self.assertEqual(result["verification"]["status"], "not_applicable")
        self.assertEqual(result["verified_severity"], "MEDIUM")
        self.assertFalse(calls)

    def test_domain_memoization_and_no_private_fields_in_verification(self):
        calls = []

        def dns(domain, qtype):
            calls.append((domain, qtype))
            return dns_agrees(domain, qtype)

        rows = [finding(), finding()]
        result = verify.verify_findings(rows, dns_lookup=dns)
        self.assertEqual(len(calls), 3)
        text = json.dumps(result[0]["verification"]).lower()
        self.assertNotIn("email", text)
        self.assertNotIn("handle", text)
        self.assertNotIn("@", text)


if __name__ == "__main__":
    unittest.main()
