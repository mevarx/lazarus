"""Tests for scorer.score_finding and scorer.severity_label.

Every rule boundary in the INTERFACES.md contract is covered:
  * unregistered +60 (and error/None cases that must NOT fire)
  * created age: 179d fires, 181d does not (180d exactly does not)
  * expires: 89d fires, 91d does not; <30d extra +15 (29d fires, 31d does not)
  * dependents: 999 -> 0, 1000 -> +20 (tiered, no double-scoring),
    100 -> +10, 99 -> 0
  * downloads: 99999 -> 0, 100000 -> +10
  * dormant maintainer +15
  * MX + re-registered +10 (MX alone, or re-registered alone, do not fire)
  * cap at 100
  * severity bands: 34/35, 59/60, 79/80 boundaries
  * determinism: same input -> identical output
"""

import unittest
from datetime import datetime, timedelta, timezone

from scorer import (
    POINTS_DEPENDENTS_MAJOR,
    POINTS_DEPENDENTS_NOTABLE,
    POINTS_DOWNLOADS_POPULAR,
    POINTS_EXPIRING_IMMINENT,
    POINTS_EXPIRING_SOON,
    POINTS_MAINTAINER_DORMANT,
    POINTS_MX_REREGISTERED,
    POINTS_RECENTLY_REREGISTERED,
    POINTS_UNREGISTERED,
    RISK_CAP,
    score_finding,
    severity_label,
)

# Fixed reference time so "180 days ago" / "90 days" are exact and stable.
NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


def days_ago(days: int) -> str:
    return (NOW - timedelta(days=days)).isoformat()


def days_ahead(days: int) -> str:
    return (NOW + timedelta(days=days)).isoformat()


def make_finding(**overrides) -> dict:
    """A benign baseline finding: nothing scores on it."""
    finding = {
        "domain": "example.com",
        "packages": ["some-pkg"],
        "dependents": 0,
        "downloads_week": 0,
        "rdap": {
            "domain": "example.com",
            "registered": True,
            "created": days_ago(365 * 5),   # 5 years old
            "expires": days_ahead(365),     # a year away
            "status": [],
            "error": None,
        },
        "maintainers": ["alice@example.com"],
        "maintainer_dormant": False,
        "mx_present": False,
    }
    finding.update(overrides)
    return finding


class TestSeverityLabel(unittest.TestCase):
    def test_each_band_and_boundary(self):
        self.assertEqual(severity_label(0), "LOW")
        self.assertEqual(severity_label(34), "LOW")
        self.assertEqual(severity_label(35), "MEDIUM")
        self.assertEqual(severity_label(59), "MEDIUM")
        self.assertEqual(severity_label(60), "HIGH")
        self.assertEqual(severity_label(79), "HIGH")
        self.assertEqual(severity_label(80), "CRITICAL")
        self.assertEqual(severity_label(100), "CRITICAL")


class TestUnregistered(unittest.TestCase):
    def test_unregistered_scores_60(self):
        result = score_finding(
            make_finding(rdap={"registered": False, "created": None,
                               "expires": None, "status": [],
                               "error": None}),
            now=NOW,
        )
        self.assertEqual(result["risk"], POINTS_UNREGISTERED)
        self.assertEqual(result["severity"], "HIGH")
        self.assertIn("domain unregistered", result["signals"])
        self.assertTrue(any("+60" in r for r in result["reasoning"]))

    def test_registered_does_not_score(self):
        self.assertEqual(score_finding(make_finding(), now=NOW)["risk"], 0)

    def test_error_means_unknown_not_unregistered(self):
        # registered=False but an error field set: the lookup failed, so we
        # must not claim the domain is unregistered.
        result = score_finding(
            make_finding(rdap={"registered": False, "created": None,
                               "expires": None, "status": [],
                               "error": "timeout"}),
            now=NOW,
        )
        self.assertEqual(result["risk"], 0)
        self.assertEqual(result["signals"], [])

    def test_missing_registered_key_does_not_score(self):
        result = score_finding(make_finding(rdap={}), now=NOW)
        self.assertEqual(result["risk"], 0)


class TestRecentlyReRegistered(unittest.TestCase):
    def _with_created_age(self, days: int) -> dict:
        rdap = {
            "registered": True,
            "created": days_ago(days),
            "expires": days_ahead(365),
            "status": [],
            "error": None,
        }
        return make_finding(rdap=rdap)

    def test_179_days_fires(self):
        result = score_finding(self._with_created_age(179), now=NOW)
        self.assertEqual(result["risk"], POINTS_RECENTLY_REREGISTERED)
        self.assertIn("recently re-registered", result["signals"])

    def test_180_days_boundary_does_not_fire(self):
        # Strict "< 180 days": exactly 180 must not fire.
        self.assertEqual(
            score_finding(self._with_created_age(180), now=NOW)["risk"], 0
        )

    def test_181_days_does_not_fire(self):
        self.assertEqual(
            score_finding(self._with_created_age(181), now=NOW)["risk"], 0
        )

    def test_created_none_does_not_fire(self):
        rdap = {"registered": True, "created": None,
                "expires": days_ahead(365), "status": [], "error": None}
        self.assertEqual(
            score_finding(make_finding(rdap=rdap), now=NOW)["risk"], 0
        )


class TestExpiry(unittest.TestCase):
    def _with_expires_in(self, days: int) -> dict:
        rdap = {
            "registered": True,
            "created": days_ago(365 * 5),
            "expires": days_ahead(days),
            "status": [],
            "error": None,
        }
        return make_finding(rdap=rdap)

    def test_89_days_fires_35(self):
        result = score_finding(self._with_expires_in(89), now=NOW)
        self.assertEqual(result["risk"], POINTS_EXPIRING_SOON)
        self.assertIn("expiring soon", result["signals"])

    def test_90_days_boundary_does_not_fire(self):
        # Strict "< 90 days": exactly 90 must not fire.
        self.assertEqual(
            score_finding(self._with_expires_in(90), now=NOW)["risk"], 0
        )

    def test_91_days_does_not_fire(self):
        self.assertEqual(
            score_finding(self._with_expires_in(91), now=NOW)["risk"], 0
        )

    def test_29_days_fires_extra_15(self):
        result = score_finding(self._with_expires_in(29), now=NOW)
        self.assertEqual(result["risk"],
                         POINTS_EXPIRING_SOON + POINTS_EXPIRING_IMMINENT)
        self.assertIn("expiring soon", result["signals"])
        self.assertIn("expires within 30 days", result["signals"])

    def test_30_days_boundary_no_extra(self):
        # 30 days out: "expiring soon" (+35) fires, but NOT the extra +15.
        result = score_finding(self._with_expires_in(30), now=NOW)
        self.assertEqual(result["risk"], POINTS_EXPIRING_SOON)
        self.assertNotIn("expires within 30 days", result["signals"])

    def test_31_days_no_extra(self):
        result = score_finding(self._with_expires_in(31), now=NOW)
        self.assertEqual(result["risk"], POINTS_EXPIRING_SOON)
        self.assertNotIn("expires within 30 days", result["signals"])

    def test_already_expired_fires_both(self):
        # Negative days-left (expiry in the past) must fire both rules.
        result = score_finding(self._with_expires_in(-5), now=NOW)
        self.assertEqual(result["risk"],
                         POINTS_EXPIRING_SOON + POINTS_EXPIRING_IMMINENT)

    def test_expires_none_does_not_fire(self):
        rdap = {"registered": True, "created": days_ago(365 * 5),
                "expires": None, "status": [], "error": None}
        self.assertEqual(
            score_finding(make_finding(rdap=rdap), now=NOW)["risk"], 0
        )


class TestDependents(unittest.TestCase):
    def test_999_scores_10_not_20(self):
        # 999 is past the >=100 notable tier but below the >=1000 major tier.
        result = score_finding(make_finding(dependents=999), now=NOW)
        self.assertEqual(result["risk"], POINTS_DEPENDENTS_NOTABLE)
        self.assertIn("999 dependents", result["signals"])
        self.assertNotIn("1000 dependents", result["signals"])

    def test_1000_scores_20_not_30(self):
        # Tiered: >=1000 gets +20 only, never an extra +10 on top.
        result = score_finding(make_finding(dependents=1000), now=NOW)
        self.assertEqual(result["risk"], POINTS_DEPENDENTS_MAJOR)
        self.assertIn("1000 dependents", result["signals"])

    def test_100_scores_10(self):
        result = score_finding(make_finding(dependents=100), now=NOW)
        self.assertEqual(result["risk"], POINTS_DEPENDENTS_NOTABLE)
        self.assertIn("100 dependents", result["signals"])

    def test_99_scores_zero(self):
        self.assertEqual(
            score_finding(make_finding(dependents=99), now=NOW)["risk"], 0
        )

    def test_huge_dependents_score_20(self):
        result = score_finding(make_finding(dependents=500000), now=NOW)
        self.assertEqual(result["risk"], POINTS_DEPENDENTS_MAJOR)

    def test_string_dependents_are_coerced(self):
        # The npm API returns dependents as a string; parsing must not crash.
        result = score_finding(make_finding(dependents="1000"), now=NOW)
        self.assertEqual(result["risk"], POINTS_DEPENDENTS_MAJOR)


class TestDownloads(unittest.TestCase):
    def test_99999_scores_zero(self):
        self.assertEqual(
            score_finding(make_finding(downloads_week=99999), now=NOW)["risk"],
            0,
        )

    def test_100000_scores_10(self):
        result = score_finding(make_finding(downloads_week=100000), now=NOW)
        self.assertEqual(result["risk"], POINTS_DOWNLOADS_POPULAR)
        self.assertIn("100000 weekly downloads", result["signals"])

    def test_above_threshold_scores_10(self):
        self.assertEqual(
            score_finding(make_finding(downloads_week=100001), now=NOW)["risk"],
            POINTS_DOWNLOADS_POPULAR,
        )


class TestDormantMaintainer(unittest.TestCase):
    def test_dormant_scores_15(self):
        result = score_finding(make_finding(maintainer_dormant=True), now=NOW)
        self.assertEqual(result["risk"], POINTS_MAINTAINER_DORMANT)
        self.assertIn("dormant maintainer", result["signals"])

    def test_not_dormant_scores_zero(self):
        self.assertEqual(
            score_finding(make_finding(maintainer_dormant=False), now=NOW)["risk"],
            0,
        )

    def test_flag_missing_scores_zero(self):
        finding = make_finding()
        finding.pop("maintainer_dormant", None)
        self.assertEqual(score_finding(finding, now=NOW)["risk"], 0)


class TestMxReRegistered(unittest.TestCase):
    def _reregistered(self):
        rdap = {"registered": True, "created": days_ago(30),
                "expires": days_ahead(365), "status": [], "error": None}
        return make_finding(rdap=rdap)

    def test_mx_plus_reregistered_scores_10(self):
        finding = self._reregistered()
        finding["mx_present"] = True
        result = score_finding(finding, now=NOW)
        # 50 (re-registered) + 10 (MX) = 60
        self.assertEqual(result["risk"],
                         POINTS_RECENTLY_REREGISTERED
                         + POINTS_MX_REREGISTERED)
        self.assertIn("MX present on re-registered domain", result["signals"])

    def test_mx_without_reregistration_does_not_score(self):
        result = score_finding(
            make_finding(mx_present=True), now=NOW
        )
        self.assertEqual(result["risk"], 0)

    def test_reregistered_without_mx_does_not_score_extra(self):
        result = score_finding(self._reregistered(), now=NOW)
        self.assertEqual(result["risk"], POINTS_RECENTLY_REREGISTERED)

    def test_mx_flag_missing_scores_zero(self):
        finding = self._reregistered()
        finding.pop("mx_present", None)
        self.assertEqual(score_finding(finding, now=NOW)["risk"],
                         POINTS_RECENTLY_REREGISTERED)


class TestCapAt100(unittest.TestCase):
    def test_everything_caps_at_100(self):
        # Unregistered + re-registered is mutually exclusive in practice, so
        # use a max-magnitude realistic finding: unregistered + expiring soon
        # + imminent + major dependents + downloads + dormant.
        rdap = {"registered": False, "created": None,
                "expires": days_ahead(10), "status": [], "error": None}
        result = score_finding(
            make_finding(
                rdap=rdap,
                dependents=5000,
                downloads_week=1_000_000,
                maintainer_dormant=True,
            ),
            now=NOW,
        )
        # 60 + 35 + 15 + 20 + 10 + 15 = 155 raw -> capped to 100
        self.assertEqual(result["risk"], RISK_CAP)
        self.assertEqual(result["severity"], "CRITICAL")

    def test_reregistered_max_case_caps_at_100(self):
        rdap = {"registered": True, "created": days_ago(10),
                "expires": days_ahead(10), "status": [], "error": None}
        result = score_finding(
            make_finding(
                rdap=rdap,
                dependents=5000,
                downloads_week=1_000_000,
                maintainer_dormant=True,
                mx_present=True,
            ),
            now=NOW,
        )
        # 50 + 35 + 15 + 20 + 10 + 15 + 10 = 155 raw -> capped to 100
        self.assertEqual(result["risk"], RISK_CAP)

    def test_cap_never_exceeded_even_with_all_rules(self):
        # Synthesize a finding where every individual rule could fire at once:
        # error-free unregistered report AND a created date in the future-ish
        # past AND expiry imminent AND big numbers AND flags.
        rdap = {"registered": False, "created": days_ago(1),
                "expires": days_ahead(1), "status": [], "error": None}
        result = score_finding(
            make_finding(
                rdap=rdap,
                dependents=10_000,
                downloads_week=10_000_000,
                maintainer_dormant=True,
                mx_present=True,
            ),
            now=NOW,
        )
        self.assertEqual(result["risk"], RISK_CAP)
        self.assertLessEqual(result["risk"], 100)


class TestDeterminism(unittest.TestCase):
    def test_same_input_same_output(self):
        finding = make_finding(
            rdap={"registered": True, "created": days_ago(30),
                  "expires": days_ahead(20), "status": [], "error": None},
            dependents=2000,
            downloads_week=150000,
            maintainer_dormant=True,
            mx_present=True,
        )
        first = score_finding(finding, now=NOW)
        second = score_finding(finding, now=NOW)
        self.assertEqual(first, second)

    def test_now_changes_age_dependent_rules(self):
        # A domain 100 days from expiry: no signal now, but "expiring soon"
        # once 20 more days have passed. (Moving now forward ages the
        # *created* date further, so expiry is the direction that flips.)
        rdap = {"registered": True, "created": days_ago(365 * 5),
                "expires": days_ahead(100), "status": [], "error": None}
        finding = make_finding(rdap=rdap)
        before = score_finding(finding, now=NOW)["risk"]
        later = score_finding(
            finding, now=NOW + timedelta(days=20)
        )["risk"]
        self.assertEqual(before, 0)
        self.assertEqual(later, POINTS_EXPIRING_SOON)

    def test_now_moves_created_out_of_window(self):
        # Same for the re-registration rule, evaluated against an EARLIER now.
        rdap = {"registered": True, "created": days_ago(190),
                "expires": days_ahead(365), "status": [], "error": None}
        finding = make_finding(rdap=rdap)
        now_too_late = score_finding(finding, now=NOW)["risk"]
        now_earlier = score_finding(
            finding, now=NOW - timedelta(days=20)
        )["risk"]
        self.assertEqual(now_too_late, 0)
        self.assertEqual(now_earlier, POINTS_RECENTLY_REREGISTERED)

    def test_naive_now_is_treated_as_utc(self):
        naive_now = NOW.replace(tzinfo=None)
        rdap = {"registered": True, "created": days_ago(30),
                "expires": days_ahead(365), "status": [], "error": None}
        aware = score_finding(make_finding(rdap=rdap), now=NOW)
        naive = score_finding(make_finding(rdap=rdap), now=naive_now)
        self.assertEqual(aware, naive)

    def test_output_shape(self):
        result = score_finding(make_finding(), now=NOW)
        self.assertEqual(
            sorted(result.keys()),
            ["reasoning", "risk", "severity", "signals"],
        )
        self.assertIsInstance(result["risk"], int)
        self.assertIn(result["severity"], {"CRITICAL", "HIGH", "MEDIUM", "LOW"})
        self.assertIsInstance(result["signals"], list)
        self.assertIsInstance(result["reasoning"], list)

    def test_signals_and_reasoning_grow_together(self):
        # Every firing rule must append one signal AND one reasoning entry.
        rdap = {"registered": True, "created": days_ago(10),
                "expires": days_ahead(10), "status": [], "error": None}
        result = score_finding(
            make_finding(
                rdap=rdap,
                dependents=5000,
                downloads_week=1_000_000,
                maintainer_dormant=True,
                mx_present=True,
            ),
            now=NOW,
        )
        self.assertEqual(len(result["signals"]), len(result["reasoning"]))
        self.assertEqual(len(result["signals"]), 7)


class TestAtlantisReference(unittest.TestCase):
    """The real node-ipc attack pattern, pinned to the attack date."""

    def test_atlantis_scores_critical_at_attack_time(self):
        # RDAP: created 2026-05-07 (re-registered), expires 2027-05-07,
        # status ['client transfer prohibited']. Attack published 2026-05-14.
        attack_now = datetime(2026, 5, 14, 0, 0, 0, tzinfo=timezone.utc)
        rdap = {
            "domain": "atlantis-software.net",
            "registered": True,
            "created": "2026-05-07",
            "expires": "2027-05-07",
            "status": ["client transfer prohibited"],
            "error": None,
        }
        result = score_finding(
            {
                "domain": "atlantis-software.net",
                "packages": ["node-ipc"],
                "dependents": 50000,
                "downloads_week": 2_000_000,
                "rdap": rdap,
                "maintainers": ["maintainer@atlantis-software.net"],
                "maintainer_dormant": True,
                "mx_present": True,
            },
            now=attack_now,
        )
        # 50 (re-registered 7d ago) + 10 (MX+re-registered) + 20 (dependents)
        # + 10 (downloads) + 15 (dormant) = 105 -> capped 100
        self.assertEqual(result["risk"], 100)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertIn("recently re-registered", result["signals"])
        self.assertIn("MX present on re-registered domain", result["signals"])


if __name__ == "__main__":
    unittest.main()
