"""Replay data is reproducible and contains only source-backed, anonymized rows."""
import json
import unittest
from pathlib import Path

from tools.seed_run import build_cached_run

ROOT = Path(__file__).resolve().parents[1]


class ReplayDataTests(unittest.TestCase):
    def test_cached_run_rebuilds_from_labeled_snapshot(self):
        cached = json.loads((ROOT / "data/cached_run.json").read_text(encoding="utf-8"))
        self.assertEqual(build_cached_run(), cached)
        self.assertEqual(cached["mode"], "replay")
        self.assertEqual(set(cached["stats"]), {"total", "critical", "high", "medium", "low"})
        self.assertEqual(cached["stats"], {"total": 3, "critical": 0, "high": 1, "medium": 0, "low": 2})

    def test_rows_are_anonymized_and_provenanced(self):
        cached = json.loads((ROOT / "data/cached_run.json").read_text(encoding="utf-8"))
        self.assertEqual({row["domain"] for row in cached["findings"]}, {
            "atlantis-software.net", "npmjs.com", "python.org",
        })
        serialized = json.dumps(cached)
        self.assertNotIn("@", serialized)
        for row in cached["findings"]:
            self.assertTrue(all(value.startswith("maintainer-") for value in row["maintainers"]))
            self.assertIn(row["provenance"]["source"], {"historical-reconstruction", "rdap-live-fetch"})
            self.assertIsInstance(row["unverified"], list)
            self.assertNotIn("narrative", row)
            self.assertNotIn("analysis", row)
        incident = next(row for row in cached["findings"] if row["domain"] == "atlantis-software.net")
        self.assertEqual(incident["severity"], "HIGH")
        self.assertIsNone(incident["dependents"])
        self.assertIn("maintainer account", incident["incident"])


if __name__ == "__main__":
    unittest.main()
