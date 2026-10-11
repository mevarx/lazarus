import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import lazarus
import repo_scan

ROOT = Path(__file__).resolve().parents[1]


class CliExitCodeTests(unittest.TestCase):
    def run_process(self, args, *, input_text=None, env=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "lazarus.py"), *args],
            cwd=ROOT, input=input_text, text=True, capture_output=True,
            env={**os.environ, **(env or {})}, check=False,
        )

    def test_patchable_scanner_exit_codes_and_redaction(self):
        source = '{"dependencies":{"express":"*"}}'
        cases = (
            ([{"severity": "CRITICAL", "maintainers": [
                "private.person@example.net", "@private_handle"], "domain": "example.net"}], 1),
            ([{"severity": "HIGH", "maintainers": [], "domain": "example.net"}], 0),
            ([], 0),
        )
        for findings, expected in cases:
            with self.subTest(expected=expected, findings=findings):
                with patch.object(repo_scan, "scan_dependencies", return_value=findings):
                    with patch.object(sys, "stdin", io.StringIO(source)):
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            actual = lazarus.main(["check", "-", "--json"])
                self.assertEqual(actual, expected)
                rendered = output.getvalue()
                if findings and findings[0].get("maintainers"):
                    report = json.loads(rendered)
                    self.assertEqual(report["findings"][0]["maintainer_count"], 2)
                    self.assertEqual(report["findings"][0]["maintainers"],
                                     ["maintainer-1-1", "maintainer-1-2"])
                    self.assertNotIn("private.person@example.net", rendered)
                    self.assertNotIn("private_handle", rendered)

    def test_human_output_never_prints_maintainer_identity(self):
        finding = {"severity": "HIGH", "domain": "example.net", "risk": 60,
                   "packages": ["express"], "maintainers": ["private@example.net"]}
        with patch.object(repo_scan, "scan_dependencies", return_value=[finding]):
            with patch.object(sys, "stdin", io.StringIO('{"dependencies":{"x":"*"}}')):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(lazarus.main(["check", "-"]), 0)
        self.assertNotIn("private@example.net", output.getvalue())
        self.assertNotIn("maintainer:", output.getvalue())

    def test_lookup_failure_summary_is_not_silent(self):
        def failed_scan(_names):
            repo_scan.last_lookup_failures = 3
            return []

        with patch.object(repo_scan, "scan_dependencies", side_effect=failed_scan):
            with patch.object(sys, "stdin", io.StringIO('{"dependencies":{"x":"*"}}')):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(lazarus.main(["check", "-"]), 0)
        self.assertIn("3 lookups failed (unverified)", errors.getvalue())

    def test_real_cli_usage_and_input_errors_exit_two(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            empty = directory / "empty.json"
            empty.write_bytes(b"")
            binary = directory / "binary.json"
            binary.write_bytes(b"\xff\x00")
            invalid = directory / "invalid.json"
            invalid.write_text("not json")
            unsupported = directory / "unsupported.json"
            unsupported.write_text('{"name":"no-dependencies"}')
            too_large = directory / "large.json"
            too_large.write_text('{"dependencies":{"express":"*"}}')

            commands = [
                ["check"],
                ["check", str(directory / "missing.json")],
                ["check", str(directory)],
                ["check", str(empty)],
                ["check", str(binary)],
                ["check", str(invalid)],
                ["check", str(unsupported)],
            ]
            for args in commands:
                with self.subTest(args=args):
                    result = self.run_process(args)
                    self.assertEqual(result.returncode, 2, result.stderr)
            result = self.run_process(
                ["check", str(too_large)], env={"LAZARUS_MAX_INPUT_BYTES": "10"}
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            result = self.run_process(
                ["check", str(too_large)], env={"LAZARUS_MAX_INPUT_BYTES": "invalid"}
            )
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_real_cli_empty_dependencies_exit_zero_without_network(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "package.json"
            path.write_text('{"name":"fixture","dependencies":{}}')
            result = self.run_process(["check", str(path)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No maintainer email domains", result.stdout)

    def test_dependency_limit_and_invalid_names_are_reported(self):
        names = {f"pkg-{i}": "*" for i in range(501)}
        names["bad/name/extra"] = "*"
        payload = json.dumps({"dependencies": names})
        with patch.object(repo_scan, "scan_dependencies", return_value=[]) as scan:
            with patch.object(sys, "stdin", io.StringIO(payload)):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors):
                    self.assertEqual(lazarus.main(["check", "-"]), 0)
        self.assertEqual(len(scan.call_args.args[0]), 500)
        self.assertIn("1 invalid dependency name(s) skipped", errors.getvalue())
        self.assertIn("scanning first 500 of 501 packages", errors.getvalue())


class RepoScanPrivacyTests(unittest.TestCase):
    def test_live_findings_contain_placeholders_not_registry_identities(self):
        package_data = {"maintainers": [{
            "name": "private-person", "username": "private-handle",
            "email": "secret.person@mail.example.net",
        }]}
        rdap_result = [{"domain": "mail.example.net", "registered": True,
                        "created": "private@example.net", "expires": None,
                        "status": ["active", "private@example.net"], "error": None,
                        "registrant_email": "private@example.net",
                        "primary_url": "https://rdap.example.net/",
                        "private_metadata": "should-not-be-copied"}]
        with patch.object(repo_scan.harvester, "_get_json", return_value=package_data), \
                patch.object(repo_scan.harvester, "_npm_bulk_downloads", return_value={}), \
                patch.object(repo_scan.harvester, "extract_domains",
                             side_effect=lambda emails: [email.split("@", 1)[1]
                                                         for email in emails]), \
                patch.object(repo_scan.rdap, "resolve_domains", return_value=rdap_result):
            findings = repo_scan.scan_dependencies(["express"])
        report = json.dumps(findings)
        self.assertEqual(findings[0]["maintainer_count"], 1)
        self.assertEqual(findings[0]["maintainers"], ["maintainer-1-1"])
        self.assertNotIn("secret.person@mail.example.net", report)
        self.assertNotIn("private-person", report)
        self.assertNotIn("private-handle", report)
        self.assertNotIn("private@example.net", report)
        self.assertNotIn("private@example.net", json.dumps(findings[0]["rdap"]))
        self.assertNotIn("private_metadata", report)
        self.assertNotIn("primary_url", report)

    def test_dependency_lookup_failure_is_counted_without_echoing_exception(self):
        with patch.object(repo_scan.harvester, "_get_json",
                          side_effect=RuntimeError("secret@example.net")), \
                patch.object(repo_scan.harvester, "_npm_bulk_downloads", return_value={}):
            self.assertEqual(repo_scan.scan_dependencies(["express"]), [])
        self.assertEqual(repo_scan.last_lookup_failures, 1)

    def test_invalid_direct_package_name_never_builds_registry_url(self):
        with patch.object(repo_scan.harvester, "_get_json") as get_json:
            result = repo_scan._packument_maintainers("https://evil.example/path")
        self.assertEqual(result["error"], "invalid package name")
        get_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
