"""Tests for the new modules: lockfile, repo_scan, blast_radius, judge.analyze."""
import unittest

import lockfile
import repo_scan
from judge import Judge, build_analyze_prompt, _parse_analyze_json, _extract_json


class LockfileTests(unittest.TestCase):
    def test_package_json_deps(self):
        text = '{"dependencies":{"express":"^4","mongoose":"^8"},"devDependencies":{"typescript":"^5"}}'
        self.assertEqual(lockfile.parse_dependencies(text),
                         ["express", "mongoose", "typescript"])

    def test_lockfile_v3_packages(self):
        text = '{"lockfileVersion":3,"packages":{"":{},"node_modules/express":{},"node_modules/express/node_modules/qs":{}}}'
        self.assertEqual(lockfile.parse_dependencies(text), ["express", "qs"])

    def test_lockfile_v1_dependencies(self):
        text = '{"lockfileVersion":1,"dependencies":{"lodash":{},"chalk":{}}}'
        self.assertEqual(lockfile.parse_dependencies(text), ["chalk", "lodash"])

    def test_dedup_preserves_sorted(self):
        text = '{"dependencies":{"b":"1","a":"1","b":"2"}}'
        self.assertEqual(lockfile.parse_dependencies(text), ["a", "b"])

    def test_bad_json_raises(self):
        with self.assertRaises(lockfile.LockfileError):
            lockfile.parse_dependencies("not json")

    def test_no_deps_raises(self):
        with self.assertRaises(lockfile.LockfileError):
            lockfile.parse_dependencies('{"name":"x"}')

    def test_empty_raises(self):
        with self.assertRaises(lockfile.LockfileError):
            lockfile.parse_dependencies("")


class MaskEmailTests(unittest.TestCase):
    def test_masks_mailbox_keeps_domain(self):
        self.assertEqual(repo_scan.mask_email("atiertant@atlantis-software.net"),
                         "***@atlantis-software.net")

    def test_short_local(self):
        self.assertEqual(repo_scan.mask_email("a@b.com"), "***@b.com")

    def test_no_at_passthrough(self):
        self.assertEqual(repo_scan.mask_email("atlantis-software.net"),
                         "atlantis-software.net")


class BlastRadiusTests(unittest.TestCase):
    # blast_radius lives in app.py; import lazily so this file has no server dep
    def _br(self):
        import app
        return app.blast_radius

    def test_sums_only_high_and_above(self):
        findings = [
            {"domain": "a.net", "severity": "CRITICAL", "downloads_week": 100, "dependents": 5, "packages": ["p1"]},
            {"domain": "b.io", "severity": "HIGH", "downloads_week": 200, "dependents": 0, "packages": ["p2"]},
            {"domain": "c.dev", "severity": "MEDIUM", "downloads_week": 999999, "dependents": 0, "packages": ["p3"]},
            {"domain": "d.app", "severity": "LOW", "downloads_week": 1, "dependents": 0, "packages": ["p4"]},
        ]
        br = self._br()(findings)
        self.assertEqual(br["at_risk_domains"], 2)
        self.assertEqual(br["combined_weekly_downloads"], 300)
        self.assertEqual(br["combined_dependents"], 5)
        self.assertEqual(br["at_risk_packages"], 2)
        self.assertEqual(br["largest_single_domain"], "b.io")

    def test_empty(self):
        br = self._br()([])
        self.assertEqual(br["combined_weekly_downloads"], 0)
        self.assertIsNone(br["largest_single_domain"])


class AnalyzeParseTests(unittest.TestCase):
    FINDING = {
        "domain": "atlantis-software.net", "packages": ["node-ipc"],
        "maintainers": ["atiertant"], "maintainer_dormant": True,
        "last_publish": "2022-06-01", "mx_present": True,
        "dependents": 424, "downloads_week": 658012,
        "rdap": {"registered": True, "created": "2026-05-07T11:49:33Z",
                 "expires": "2027-05-07T11:49:33Z", "status": [], "error": None},
        "risk": 95, "severity": "CRITICAL", "signals": ["recently re-registered"],
        "reasoning": ["scorer +50"],
    }

    def test_prompt_withholds_scorer_verdict(self):
        prompt = build_analyze_prompt(self.FINDING)
        # the scorer's own outputs must NOT leak into the analyze prompt
        for leak in ["recently re-registered", "CRITICAL", "scorer +50", '"risk": 95']:
            self.assertNotIn(leak, prompt)
        # raw evidence IS present
        self.assertIn("2026-05-07", prompt)
        self.assertIn("424", prompt)

    def test_parse_string_email(self):
        text = '{"evidence":["a","b"],"risk_reasoning":["x"],"confidence":"high","disclosure_email":"Subject: hi\\n\\nbody"}'
        out = _parse_analyze_json(text, self.FINDING)
        self.assertEqual(out["evidence"], ["a", "b"])
        self.assertIn("Subject: hi", out["disclosure_email"])

    def test_parse_object_email(self):
        # Gemma 3 often returns {subject, body}
        text = '{"evidence":["a"],"disclosure_email":{"subject":"S","body":"B"}}'
        out = _parse_analyze_json(text, self.FINDING)
        self.assertEqual(out["disclosure_email"], "Subject: S\n\nB")

    def test_parse_strips_fences(self):
        text = '```json\n{"evidence":["a"],"disclosure_email":"body"}\n```'
        out = _parse_analyze_json(text, self.FINDING)
        self.assertEqual(out["evidence"], ["a"])

    def test_parse_rejects_missing_email(self):
        self.assertIsNone(_parse_analyze_json('{"evidence":["a"]}', self.FINDING))

    def test_parse_rejects_empty_evidence(self):
        self.assertIsNone(_parse_analyze_json('{"evidence":[],"disclosure_email":"x"}', self.FINDING))

    def test_extract_json_embedded(self):
        self.assertEqual(_extract_json('noise {"a":1} tail'), {"a": 1})


class AnalyzeOfflineTests(unittest.TestCase):
    def test_offline_fallback_never_raises_and_labels_template(self):
        j = Judge(backend="offline")
        finding = {"domain": "x.net", "signals": ["expiring soon"],
                   "reasoning": ["expires in 10d"], "maintainers": ["a@x.net"]}
        out = j.analyze(finding)
        self.assertFalse(out["live"])
        self.assertEqual(out["model"], "offline-template")
        self.assertTrue(out["disclosure_email"])
        # must not leak the raw maintainer email into the drafted email
        self.assertNotIn("a@x.net", out["disclosure_email"])


if __name__ == "__main__":
    unittest.main()
