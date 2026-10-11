import os
import platform
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/lazarus.yml"


def check_run_block(text):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines)
                 if "- name: Check maintainer email domains" in line)
    run_line = next(i for i in range(start, len(lines))
                    if lines[i].strip() == "run: |")
    indent = len(lines[run_line]) - len(lines[run_line].lstrip()) + 2
    body = []
    for line in lines[run_line + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


class GitHubActionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.run_block = check_run_block(cls.text)

    def test_workflow_structure_and_permissions(self):
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read$")
        self.assertIn("actions/checkout@v4", self.text)
        self.assertIn("actions/setup-python@v5", self.text)
        self.assertIn("actions/upload-artifact@v4", self.text)
        self.assertIn("python -m unittest discover -s tests", self.text)
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn("warn_only:", self.text)
        self.assertIn("$LAZARUS_WARN_ONLY", self.run_block)
        self.assertRegex(self.run_block, r"status=\$\?")
        self.assertRegex(self.run_block, r"elif \[\[ \"\$status\" -eq 2")
        self.assertIn('exit "$status"', self.run_block)
        self.assertNotIn("secrets.", self.text)
        # the run block must be bash (it uses [[ ]]); the shell is declared too
        self.assertIn("shell: bash", self.text)

    def run_shell(self, exit_code, *, warn_only="false", has_lock=True,
                  has_package=True):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bindir = root / "bin"
            bindir.mkdir()
            fake_python = bindir / "python"
            fake_python.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_ARGS"\n'
                'exit "$FAKE_EXIT"\n'
            )
            fake_python.chmod(0o755)
            if has_lock:
                (root / "package-lock.json").write_text("{}")
            if has_package:
                (root / "package.json").write_text("{}")
            args_file = root / "args.txt"
            env = {
                **os.environ,
                # fake 'python' first on PATH so the workflow's default
                # invocation resolves to it (works on Linux CI / macOS).
                "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
                "LAZARUS_WARN_ONLY": warn_only,
                "FAKE_EXIT": str(exit_code),
                "FAKE_ARGS": str(args_file),
            }
            # The workflow uses bash-only syntax ([[ ]]) and declares
            # 'shell: bash', so run the block under bash to match CI exactly.
            bash = shutil.which("bash")
            self.assertIsNotNone(bash, "bash is required to exercise the workflow block")
            result = subprocess.run(
                [bash, "-c", self.run_block], cwd=root, env=env,
                text=True, capture_output=True, check=False,
            )
            logged = args_file.read_text().strip() if args_file.exists() else ""
            return result, logged

    @unittest.skipIf(
        platform.system() == "Windows",
        "Windows App-Execution-Alias layer intercepts 'python' before PATH, "
        "so a PATH-shadowed fake cannot run under bash here; exercised on "
        "Linux/macOS CI where the workflow actually executes.",
    )
    def test_actual_workflow_shell_propagates_critical_and_usage_codes(self):
        critical, args = self.run_shell(1)
        self.assertEqual(critical.returncode, 1, critical.stderr)
        self.assertIn("lazarus.py check package-lock.json --json", args)

        warning, _ = self.run_shell(1, warn_only="true")
        self.assertEqual(warning.returncode, 0, warning.stderr)
        self.assertIn("::warning::", warning.stdout)

        usage, _ = self.run_shell(2)
        self.assertEqual(usage.returncode, 2, usage.stderr)

    @unittest.skipIf(
        platform.system() == "Windows",
        "see test_actual_workflow_shell_propagates_critical_and_usage_codes",
    )
    def test_workflow_selects_package_json_and_errors_if_missing(self):
        fallback, args = self.run_shell(0, has_lock=False, has_package=True)
        self.assertEqual(fallback.returncode, 0, fallback.stderr)
        self.assertIn("lazarus.py check package.json --json", args)

        # No manifest at all: this repo is pure Python, so the check SKIPS
        # (notice + exit 0) rather than failing — the unit tests are the gate.
        missing, _ = self.run_shell(0, has_lock=False, has_package=False)
        self.assertEqual(missing.returncode, 0)
        self.assertIn("::notice::No package-lock.json or package.json", missing.stdout)


if __name__ == "__main__":
    unittest.main()
