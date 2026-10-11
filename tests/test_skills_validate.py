import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
_PATH_REFERENCE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.(?:py|md|json|sh)\b"
)


def skill_folders():
    return sorted(path for path in SKILLS.iterdir()
                  if path.is_dir() and (path / "SKILL.md").is_file())


def parse_frontmatter(path):
    lines = path.read_text().splitlines()
    if not lines or lines[0].strip() != "---":
        raise AssertionError(f"missing frontmatter: {path}")
    try:
        end = next(index for index, line in enumerate(lines[1:], 1)
                   if line.strip() == "---")
    except StopIteration as exc:
        raise AssertionError(f"unterminated frontmatter: {path}") from exc
    fields = {}
    for line in lines[1:end]:
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip().strip("\"'")
    return fields, "\n".join(lines)


class SkillsValidateTests(unittest.TestCase):
    def test_builtin_skill_metadata_and_references(self):
        folders = skill_folders()
        self.assertTrue(folders, "no skill folders found")
        for folder in folders:
            with self.subTest(skill=folder.name):
                metadata, content = parse_frontmatter(folder / "SKILL.md")
                name = metadata.get("name", "")
                description = metadata.get("description", "")
                self.assertEqual(name, folder.name)
                self.assertLessEqual(len(name), 64)
                self.assertRegex(name, r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")
                self.assertTrue(description)
                self.assertLessEqual(len(description), 1024)
                for reference in _PATH_REFERENCE.findall(content):
                    candidates = (ROOT / reference, folder / reference)
                self.assertTrue(any(path.is_file() for path in candidates),
                                    f"missing referenced file: {reference}")

    def test_domain_helper_rejects_urls_emails_and_malformed_domains(self):
        helper = ROOT / "skills/domain-triage/scripts/check_domain.py"
        for invalid in ("person@example.net", "https://example.net", "foo..example.net",
                        "127.0.0.1", "-bad.example.net"):
            with self.subTest(value=invalid):
                command = ["python3", str(helper)]
                if invalid.startswith("-"):
                    command.append("--")
                command.append(invalid)
                result = subprocess.run(
                    command, cwd=ROOT,
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("person@example.net", result.stdout)
                self.assertIn('"domain": null', result.stdout)

    def test_agentskills_validate_each_folder_when_available(self):
        executable = shutil.which("agentskills")
        candidate = Path("/tmp/skillsref-venv/bin/agentskills")
        if not executable and candidate.is_file() and candidate.stat().st_mode & 0o111:
            executable = str(candidate)
        if not executable:
            print("SKIP: agentskills unavailable; built-in skill checks still ran")
            return
        for folder in skill_folders():
            with self.subTest(skill=folder.name):
                result = subprocess.run(
                    [executable, "validate", str(folder)],
                    cwd=ROOT, text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
