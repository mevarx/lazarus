"""Blast radius counts CRITICAL and HIGH domains only — never MEDIUM or LOW."""

import itertools
import unittest

import app


def _f(domain, severity, downloads=1000, dependents=10, packages=None):
    return {
        "domain": domain,
        "severity": severity,
        "downloads_week": downloads,
        "dependents": dependents,
        "packages": packages or [f"pkg-{domain}"],
    }


class BlastRadiusRuleTests(unittest.TestCase):
    def test_medium_only_contributes_nothing(self):
        br = app.blast_radius([_f("m.example", "MEDIUM", 5_000_000, 900)])
        self.assertEqual(br["at_risk_domains"], 0)
        self.assertEqual(br["at_risk_packages"], 0)
        self.assertEqual(br["combined_weekly_downloads"], 0)
        self.assertEqual(br["combined_dependents"], 0)
        self.assertIsNone(br["largest_single_domain"])
        self.assertEqual(br["largest_single_downloads"], 0)

    def test_adding_medium_or_low_never_changes_result(self):
        base = [_f("a.example", "CRITICAL", 300, 3), _f("b.example", "HIGH", 200, 2)]
        expected = app.blast_radius(base)
        for sev in ("MEDIUM", "LOW", "medium", "Medium", "", None, "UNVERIFIED"):
            extra = base + [_f("x.example", sev, 10**9, 10**6)]
            self.assertEqual(app.blast_radius(extra), expected, f"severity={sev!r} leaked in")

    def test_every_severity_combination(self):
        sevs = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        for combo in itertools.product(sevs, repeat=3):
            findings = [_f(f"d{i}.example", s, 100 * (i + 1)) for i, s in enumerate(combo)]
            br = app.blast_radius(findings)
            counted = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
            self.assertEqual(br["at_risk_domains"], len(counted), combo)
            self.assertEqual(
                br["combined_weekly_downloads"], sum(f["downloads_week"] for f in counted), combo
            )

    def test_severity_is_case_insensitive_for_counted_levels(self):
        br = app.blast_radius([_f("a.example", "critical", 7), _f("b.example", "High", 5)])
        self.assertEqual(br["combined_weekly_downloads"], 12)

    def test_threshold_is_not_configurable(self):
        with self.assertRaises(TypeError):
            app.blast_radius([_f("a.example", "MEDIUM")], min_severity="MEDIUM")
        self.assertEqual(app.AT_RISK_SEVERITIES, frozenset({"CRITICAL", "HIGH"}))

    def test_domain_counted_once(self):
        br = app.blast_radius([_f("a.example", "HIGH", 100), _f("a.example", "HIGH", 100)])
        self.assertEqual(br["at_risk_domains"], 1)
        self.assertEqual(br["combined_weekly_downloads"], 100)

    def test_bad_numbers_do_not_crash(self):
        br = app.blast_radius([_f("a.example", "HIGH", "n/a", None)])
        self.assertEqual(br["combined_weekly_downloads"], 0)
        self.assertEqual(br["at_risk_domains"], 1)


class BlastRadiusPayloadTests(unittest.TestCase):
    def test_cached_payload_matches_critical_high_subset(self):
        payload = app.cached_payload()
        findings = payload["findings"]
        subset = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        self.assertEqual(payload["blast_radius"], app.blast_radius(subset))

    def test_findings_payload_matches_critical_high_subset(self):
        payload = app.findings_payload()
        subset = [f for f in payload["findings"] if f.get("severity") in ("CRITICAL", "HIGH")]
        self.assertEqual(payload["blast_radius"], app.blast_radius(subset))


if __name__ == "__main__":
    unittest.main()
