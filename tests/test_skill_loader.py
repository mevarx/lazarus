"""Tests for skill_loader.py — valid load, name validation, frontmatter parsing.

Run:  python -m unittest tests.test_skill_loader -v
Stdlib only (unittest), per INTERFACES.md.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from skill_loader import (  # noqa: E402
    SkillValidationError,
    load_skill,
    parse_frontmatter,
    run_script,
    validate_name,
)

VALID_SKILL_MD = """---
name: domain-triage
description: Assess domain-takeover risk for package maintainer email domains and write the plain-English risk narrative. Use when a scored finding has signals such as an unregistered domain, recent re-registration, imminent expiry, or dormant maintainer.
license: MIT
metadata:
  author: lazarus
  version: "1.0"
allowed-tools: Bash(python:*) Read
---

# Domain takeover triage

Body content here.

## Section

More body.
"""


class SkillTreeTestCase(unittest.TestCase):
    """Builds a throwaway skills tree per test."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="lazarus-skills-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def write_skill(self, dirname: str, content: str) -> str:
        path = os.path.join(self.root, dirname)
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def write_script(self, skill_dir: str, name: str, body: str) -> str:
        scripts = os.path.join(skill_dir, "scripts")
        os.makedirs(scripts, exist_ok=True)
        with open(os.path.join(scripts, name), "w", encoding="utf-8") as handle:
            handle.write(body)
        return scripts


class ValidSkillTests(SkillTreeTestCase):

    def test_valid_skill_loads(self):
        path = self.write_skill("domain-triage", VALID_SKILL_MD)
        skill = load_skill(path)

        self.assertEqual(skill["name"], "domain-triage")
        self.assertIn("domain-takeover risk", skill["description"])
        self.assertEqual(skill["license"], "MIT")
        self.assertEqual(skill["metadata"]["author"], "lazarus")
        self.assertEqual(skill["metadata"]["version"], "1.0")
        self.assertEqual(
            skill["allowed_tools"], ["Bash(python:*)", "Read"]
        )
        self.assertIn("Domain takeover triage", skill["body"])
        self.assertIn("More body.", skill["body"])
        self.assertNotIn("---", skill["body"], "frontmatter must be stripped")

    def test_load_accepts_skill_md_path(self):
        path = self.write_skill("domain-triage", VALID_SKILL_MD)
        skill = load_skill(os.path.join(path, "SKILL.md"))
        self.assertEqual(skill["name"], "domain-triage")

    def test_optional_fields_default(self):
        minimal = (
            "---\n"
            "name: domain-triage\n"
            "description: Assess domain takeover risk. Use when a scored finding "
            "has signals such as an unregistered domain.\n"
            "---\n\nBody.\n"
        )
        path = self.write_skill("domain-triage", minimal)
        skill = load_skill(path)
        self.assertIsNone(skill["license"])
        self.assertEqual(skill["metadata"], {})
        self.assertEqual(skill["allowed_tools"], [])
        self.assertIsNone(skill["compatibility"])

    def test_scripts_are_listed(self):
        path = self.write_skill("domain-triage", VALID_SKILL_MD)
        self.write_script(path, "check_domain.py", "print('hi')\n")
        self.write_script(path, "helper.py", "print('x')\n")
        skill = load_skill(path)
        self.assertEqual(skill["scripts"], ["check_domain.py", "helper.py"])

    def test_bundled_skill_in_repo_is_valid(self):
        """The real skills/domain-triage must satisfy the spec it documents."""
        repo = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "skills", "domain-triage")
        )
        if not os.path.isdir(repo):
            self.skipTest("skills/domain-triage not present")
        skill = load_skill(repo)
        self.assertEqual(skill["name"], "domain-triage")
        self.assertLessEqual(len(skill["description"]), 1024)
        self.assertIn("check_domain.py", skill["scripts"])


class NameValidationTests(SkillTreeTestCase):

    def test_valid_names(self):
        for name in ("domain-triage", "pdf-processing", "a", "code-review", "v2"):
            validate_name(name)  # must not raise

    def test_uppercase_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("PDF-Processing")

    def test_underscore_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("domain_triage")

    def test_space_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("domain triage")

    def test_leading_hyphen_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("-domain")

    def test_trailing_hyphen_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("domain-")

    def test_consecutive_hyphens_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("domain--triage")

    def test_empty_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("")

    def test_too_long_rejected(self):
        with self.assertRaises(SkillValidationError):
            validate_name("a" * 65)

    def test_max_length_accepted(self):
        validate_name("a" * 64)

    def test_invalid_name_in_file_rejected(self):
        content = (
            "---\n"
            "name: Domain-Triage\n"
            "description: Assess domain takeover risk. Use when signals appear.\n"
            "---\n\nBody.\n"
        )
        path = self.write_skill("domain-triage", content)
        with self.assertRaises(SkillValidationError) as ctx:
            load_skill(path)
        self.assertIn("lowercase", str(ctx.exception))

    def test_missing_name_rejected(self):
        content = "---\ndescription: Assess domain takeover risk.\n---\n\nBody.\n"
        path = self.write_skill("domain-triage", content)
        with self.assertRaises(SkillValidationError):
            load_skill(path)

    def test_name_dir_mismatch_rejected(self):
        """name must match the parent directory name."""
        path = self.write_skill("domain-triage", VALID_SKILL_MD)
        # Valid name, wrong directory: the dir is domain-triage but name says other.
        content = VALID_SKILL_MD.replace("name: domain-triage", "name: domain-scan")
        other = self.write_skill("domain-triage", content)
        self.assertEqual(path, other)
        with self.assertRaises(SkillValidationError) as ctx:
            load_skill(path)
        self.assertIn("does not match parent directory", str(ctx.exception))

    def test_missing_description_rejected(self):
        content = "---\nname: domain-triage\n---\n\nBody.\n"
        path = self.write_skill("domain-triage", content)
        with self.assertRaises(SkillValidationError):
            load_skill(path)

    def test_overlong_description_rejected(self):
        content = (
            "---\n"
            "name: domain-triage\n"
            f"description: {'x' * 1025}\n"
            "---\n\nBody.\n"
        )
        path = self.write_skill("domain-triage", content)
        with self.assertRaises(SkillValidationError):
            load_skill(path)

    def test_no_frontmatter_rejected(self):
        path = self.write_skill("domain-triage", "# Just markdown\n\nNo frontmatter.\n")
        with self.assertRaises(SkillValidationError):
            load_skill(path)

    def test_missing_skill_md_rejected(self):
        with self.assertRaises(SkillValidationError):
            load_skill(os.path.join(self.root, "nope"))


class FrontmatterFallbackTests(SkillTreeTestCase):
    """The hand-rolled parser must cope with real-world SKILL.md shapes."""

    def test_simple_key_value(self):
        front, body = parse_frontmatter(
            "---\nname: domain-triage\ndescription: Desc here.\n---\n\nBody.\n"
        )
        self.assertEqual(front["name"], "domain-triage")
        self.assertEqual(front["description"], "Desc here.")
        self.assertEqual(body.strip(), "Body.")

    def test_quoted_values_unquoted(self):
        front, _ = parse_frontmatter(
            '---\nname: domain-triage\ndescription: "Quoted desc."\n'
            'license: \'MIT\'\n---\n'
        )
        self.assertEqual(front["description"], "Quoted desc.")
        self.assertEqual(front["license"], "MIT")

    def test_nested_metadata_map(self):
        front, _ = parse_frontmatter(
            "---\nname: domain-triage\ndescription: Desc.\nmetadata:\n"
            "  author: lazarus\n  version: \"1.0\"\n---\n"
        )
        self.assertEqual(front["metadata"], {"author": "lazarus", "version": "1.0"})

    def test_folded_scalar(self):
        front, _ = parse_frontmatter(
            "---\nname: domain-triage\ndescription: >\n"
            "  A long description that is folded\n"
            "  across several source lines.\n---\n"
        )
        self.assertEqual(
            front["description"],
            "A long description that is folded across several source lines.",
        )

    def test_literal_block_scalar(self):
        front, _ = parse_frontmatter(
            "---\nname: domain-triage\ndescription: |\n"
            "  Line one.\n  Line two.\n---\n"
        )
        self.assertEqual(front["description"], "Line one.\nLine two.")

    def test_trailing_comment_stripped(self):
        front, _ = parse_frontmatter(
            "---\nname: domain-triage\ndescription: Desc here. # trailing comment\n---\n"
        )
        self.assertEqual(front["description"], "Desc here.")

    def test_blank_lines_and_comments_ignored(self):
        front, _ = parse_frontmatter(
            "---\n\n# a comment\nname: domain-triage\n\ndescription: Desc.\n---\n"
        )
        self.assertEqual(front["name"], "domain-triage")

    def test_no_frontmatter_returns_empty_dict(self):
        front, body = parse_frontmatter("# Title\n\nBody.\n")
        self.assertEqual(front, {})
        self.assertEqual(body, "# Title\n\nBody.\n")

    def test_unterminated_frontmatter_returns_empty_dict(self):
        front, body = parse_frontmatter("---\nname: domain-triage\nno closing fence\n")
        self.assertEqual(front, {})

    def test_empty_input(self):
        self.assertEqual(parse_frontmatter(""), ({}, ""))
        self.assertEqual(parse_frontmatter(None), ({}, ""))

    def test_body_containing_dashes_after_frontmatter(self):
        front, body = parse_frontmatter(
            "---\nname: domain-triage\ndescription: Desc.\n---\n\nBody.\n\n---\n\nMore.\n"
        )
        self.assertEqual(front["name"], "domain-triage")
        self.assertIn("Body.", body)
        self.assertIn("More.", body)

    def test_folded_description_validates_through_load_skill(self):
        content = (
            "---\n"
            "name: domain-triage\n"
            "description: >\n"
            "  Assess domain-takeover risk for package maintainer email domains.\n"
            "  Use when a finding has signals such as an unregistered domain.\n"
            "---\n\nBody.\n"
        )
        path = self.write_skill("domain-triage", content)
        skill = load_skill(path)
        self.assertIn("Assess domain-takeover risk", skill["description"])


class RunScriptTests(SkillTreeTestCase):

    def _skill_with_script(self):
        path = self.write_skill("domain-triage", VALID_SKILL_MD)
        self.write_script(
            path,
            "echo.py",
            "import sys, json\n"
            "print(json.dumps({'args': sys.argv[1:]}))\n"
            "sys.stderr.write('to stderr\\n')\n",
        )
        return path

    def test_runs_and_returns_contract_keys(self):
        skill = self._skill_with_script()
        out = run_script(skill, "echo.py", ["one", "two"])
        self.assertEqual(set(out), {"stdout", "stderr", "code"})
        self.assertEqual(out["code"], 0)
        self.assertIn("to stderr", out["stderr"])
        import json

        self.assertEqual(json.loads(out["stdout"])["args"], ["one", "two"])

    def test_relative_skill_dir_resolves_correctly(self):
        """cwd=scripts/ must not double-resolve a relative skill_dir."""
        path = self.write_skill("domain-triage", VALID_SKILL_MD)
        self.write_script(
            path,
            "echo.py",
            "import sys, json\nprint(json.dumps({'args': sys.argv[1:]}))\n",
        )
        # Run from inside the skill's parent so "domain-triage" is relative.
        prev = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, prev)
        out = run_script("domain-triage", "echo.py", ["rel"])
        self.assertEqual(out["code"], 0, out["stderr"])
        import json

        self.assertEqual(json.loads(out["stdout"])["args"], ["rel"])

    def test_runs_with_cwd_inside_scripts_dir(self):
        path = self.write_skill("domain-triage", VALID_SKILL_MD)
        self.write_script(
            path,
            "where.py",
            "import os\nprint(os.getcwd())\nprint(os.path.basename(os.getcwd()))\n",
        )
        out = run_script(path, "where.py", [])
        self.assertEqual(out["code"], 0)
        self.assertEqual(out["stdout"].splitlines()[1].strip(), "scripts")

    def test_missing_script_reported_not_raised(self):
        skill = self.write_skill("domain-triage", VALID_SKILL_MD)
        out = run_script(skill, "nope.py", [])
        self.assertEqual(out["code"], 127)
        self.assertIn("not found", out["stderr"])

    def test_no_scripts_dir_reported(self):
        skill = self.write_skill("domain-triage", VALID_SKILL_MD)
        out = run_script(skill, "echo.py", [])
        self.assertNotEqual(out["code"], 0)
        self.assertTrue(out["stderr"])

    def test_failing_script_propagates_exit_code(self):
        skill = self.write_skill("domain-triage", VALID_SKILL_MD)
        self.write_script(skill, "fail.py", "import sys\nsys.exit(3)\n")
        out = run_script(skill, "fail.py", [])
        self.assertEqual(out["code"], 3)

    def test_timeout_is_caught(self):
        skill = self.write_skill("domain-triage", VALID_SKILL_MD)
        self.write_script(
            skill,
            "slow.py",
            "import time\ntime.sleep(60)\n",
        )
        import skill_loader

        original = skill_loader.SCRIPT_TIMEOUT
        skill_loader.SCRIPT_TIMEOUT = 1
        try:
            out = run_script(skill, "slow.py", [])
        finally:
            skill_loader.SCRIPT_TIMEOUT = original
        self.assertEqual(out["code"], 124)
        self.assertIn("timeout", out["stderr"])

    def test_args_default_empty(self):
        skill = self._skill_with_script()
        out = run_script(skill, "echo.py")
        self.assertEqual(out["code"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
