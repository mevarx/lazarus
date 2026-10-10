"""skill_loader.py — load and validate Agent Skill Open Standard directories.

No PyYAML: the frontmatter parser is hand-rolled on purpose (the project is
stdlib-only per INTERFACES.md). It handles the subset of YAML that SKILL.md
files actually use:

  name: domain-triage                 simple key: value
  description: "quoted text"          quoted scalars
  description: >                      folded scalar (indented block joined by spaces)
  notes: |                            literal block scalar (newlines preserved)
  metadata:                           nested map of string -> string
    author: lazarus
  allowed-tools: Bash(git:*) Read     space-separated tool list

Anything it cannot understand is skipped rather than fatal — validation then
catches the fields that actually matter.

Reference: https://agentskills.io/specification

Stdlib only.
"""

from __future__ import annotations

import os
import re
import subprocess

__all__ = [
    "SkillValidationError",
    "load_skill",
    "run_script",
    "parse_frontmatter",
    "validate_name",
]

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
NAME_MAX = 64
DESCRIPTION_MAX = 1024
COMPATIBILITY_MAX = 500
SCRIPT_TIMEOUT = 30


class SkillValidationError(ValueError):
    """Raised when a skill directory violates the Agent Skill Open Standard."""


# --- frontmatter parsing -----------------------------------------------------


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split SKILL.md text into (frontmatter dict, body string).

    Frontmatter is the first ``---`` delimited block. Returns an empty dict and
    the full text as body when no block is present. Never raises.
    """
    if not isinstance(text, str):
        return {}, ""

    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.strip() == "---":
            start = idx
            break
    if start is None:
        return {}, text

    # Find the closing fence.
    end = None
    for idx in range(start + 1, len(lines)):
        if lines[idx].strip() == "---":
            end = idx
            break
    if end is None:
        return {}, text

    raw = lines[start + 1 : end]
    body = "\n".join(lines[end + 1 :]).strip("\n")
    return _parse_scalars(raw), body


def _parse_scalars(raw_lines: list[str]) -> dict:
    """Minimal YAML subset parser over the frontmatter block."""
    out: dict = {}
    idx = 0
    n = len(raw_lines)

    while idx < n:
        line = raw_lines[idx]
        idx += 1
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        # Must be a top-level "key: value" line (no leading whitespace).
        if line[:1].isspace():
            continue  # orphan indented line — ignore, fallback parser is lenient
        if ":" not in stripped:
            continue

        key, _, rest = stripped.partition(":")
        key = key.strip()
        rest = rest.strip()

        # Strip trailing comment when the value is unquoted and '# ' follows space.
        if rest and not rest[0] in "\"'" and " #" in rest:
            rest = rest.split(" #", 1)[0].strip()

        if not key:
            continue

        # --- block scalar: | or > followed by an indented block ---------------
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            block_lines = []
            while idx < n:
                nxt = raw_lines[idx]
                if nxt.strip() == "" or nxt[:1].isspace():
                    block_lines.append(nxt)
                    idx += 1
                else:
                    break
            out[key] = _render_block_scalar(block_lines, rest)
            continue

        # --- nested map: "key:" followed by indented "sub: value" -------------
        if not rest:
            nested = {}
            while idx < n:
                nxt = raw_lines[idx]
                if nxt.strip() == "" or nxt[:1].isspace():
                    if ":" in nxt and not nxt.strip().startswith(("-", "#")):
                        sub_key, _, sub_val = nxt.strip().partition(":")
                        sub_val = _strip_quotes(sub_val.strip())
                        if sub_key.strip():
                            nested[sub_key.strip()] = sub_val
                    idx += 1
                else:
                    break
            out[key] = nested if nested else ""
            continue

        out[key] = _strip_quotes(rest)

    return out


def _render_block_scalar(block_lines: list[str], indicator: str) -> str:
    """Render a YAML ``|``/``>`` block scalar (minimal, dedent-based)."""
    indents = [
        len(ln) - len(ln.lstrip()) for ln in block_lines if ln.strip()
    ]
    pad = min(indents) if indents else 0
    body = [ln[pad:] if len(ln) >= pad else ln.strip() for ln in block_lines]

    # Drop leading/trailing blank lines introduced by the fence.
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()

    if indicator.startswith("|"):
        # Literal: keep the line breaks (strip-then-fence chomping is close enough).
        return "\n".join(body)
    # Folded: join lines, blank lines become paragraph breaks.
    paragraphs: list[str] = []
    current: list[str] = []
    for ln in body:
        if ln.strip():
            current.append(ln.strip())
        else:
            if current:
                paragraphs.append(" ".join(current))
                current = []
    if current:
        paragraphs.append(" ".join(current))
    return "\n".join(paragraphs)


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


# --- validation --------------------------------------------------------------


def validate_name(name: str) -> None:
    """Enforce the spec's name rules. Raises SkillValidationError."""
    if not name or not isinstance(name, str):
        raise SkillValidationError("name is required")
    if len(name) > NAME_MAX:
        raise SkillValidationError(
            f"name {name!r} is {len(name)} chars, max is {NAME_MAX}"
        )
    if not NAME_RE.match(name):
        raise SkillValidationError(
            f"name {name!r} must be lowercase letters, digits and hyphens only, "
            "must not start or end with a hyphen, and must not contain '--'"
        )


def _resolve_skill_path(path: str) -> tuple[str, str]:
    """Return (skill_dir, skill_md_path). Accepts either the dir or the file."""
    if not path:
        raise SkillValidationError("path is required")
    if os.path.isdir(path):
        skill_dir = os.path.abspath(path)
        skill_md = os.path.join(skill_dir, "SKILL.md")
    else:
        skill_md = os.path.abspath(path)
        skill_dir = os.path.dirname(skill_md)
    if not os.path.isfile(skill_md):
        raise SkillValidationError(f"no SKILL.md at {skill_md}")
    return skill_dir, skill_md


# --- public API --------------------------------------------------------------


def load_skill(path: str) -> dict:
    """Load and validate a skill directory.

    ``path`` may be the skill directory or the SKILL.md file itself.
    Returns {name, description, license, metadata, allowed_tools, body, scripts}.
    Raises SkillValidationError on any spec violation.
    """
    skill_dir, skill_md = _resolve_skill_path(path)

    with open(skill_md, "r", encoding="utf-8") as handle:
        text = handle.read()

    front, body = parse_frontmatter(text)
    if not front:
        raise SkillValidationError(
            f"{skill_md} has no YAML frontmatter (expected a leading '---' block)"
        )

    name = str(front.get("name") or "").strip()
    validate_name(name)

    parent_dir = os.path.basename(os.path.normpath(skill_dir))
    if name != parent_dir:
        raise SkillValidationError(
            f"name {name!r} does not match parent directory {parent_dir!r}"
        )

    description = str(front.get("description") or "").strip()
    if not description:
        raise SkillValidationError("description is required")
    if len(description) > DESCRIPTION_MAX:
        raise SkillValidationError(
            f"description is {len(description)} chars, max is {DESCRIPTION_MAX}"
        )

    compatibility = str(front.get("compatibility") or "").strip()
    if compatibility and len(compatibility) > COMPATIBILITY_MAX:
        raise SkillValidationError(
            f"compatibility is {len(compatibility)} chars, max is {COMPATIBILITY_MAX}"
        )

    metadata = front.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    allowed_raw = str(front.get("allowed-tools") or front.get("allowed_tools") or "")
    allowed_tools = allowed_raw.split() if allowed_raw else []

    return {
        "name": name,
        "description": description,
        "license": str(front.get("license") or "").strip() or None,
        "compatibility": compatibility or None,
        "metadata": {str(k): str(v) for k, v in metadata.items()},
        "allowed_tools": allowed_tools,
        "body": body,
        "scripts": _list_scripts(skill_dir),
        "dir": skill_dir,
    }


def _list_scripts(skill_dir: str) -> list[str]:
    """Bare filenames in scripts/, sorted — directly usable as run_script args."""
    scripts_dir = os.path.join(skill_dir, "scripts")
    if not os.path.isdir(scripts_dir):
        return []
    found = []
    for root, _dirs, files in os.walk(scripts_dir):
        for fname in files:
            if fname.startswith(".") or fname.endswith(".pyc"):
                continue
            rel = os.path.relpath(os.path.join(root, fname), scripts_dir)
            found.append(rel.replace(os.sep, "/"))
    return sorted(found)


def run_script(skill_dir: str, script_name: str, args: list[str] | None = None) -> dict:
    """Run a skill script with cwd=<skill_dir>/scripts and a 30s timeout.

    Returns {stdout, stderr, code}. Never raises — a missing script or a
    timeout comes back as a non-zero code with the reason in stderr.
    """
    args = list(args or [])
    scripts_dir = os.path.join(skill_dir, "scripts")

    # Accept both "check_domain.py" and "scripts/check_domain.py".
    if os.sep in script_name or "/" in script_name:
        candidate = os.path.join(skill_dir, script_name)
        workdir = scripts_dir
    else:
        candidate = os.path.join(scripts_dir, script_name)
        workdir = scripts_dir

    # cwd changes resolution, so make both absolute before the subprocess runs —
    # a relative skill_dir would otherwise resolve the script path twice.
    candidate = os.path.abspath(candidate)
    workdir = os.path.abspath(workdir)

    if not os.path.isfile(candidate):
        return {
            "stdout": "",
            "stderr": f"script not found: {script_name}",
            "code": 127,
        }

    if not os.path.isdir(workdir):
        return {
            "stdout": "",
            "stderr": f"no scripts/ directory in {skill_dir}",
            "code": 127,
        }

    if script_name.endswith((".py", ".pyw")):
        cmd = [_python_executable(), candidate] + args
    else:
        cmd = [candidate] + args

    try:
        proc = subprocess.run(
            cmd,
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=SCRIPT_TIMEOUT,
            errors="replace",
        )
        return {
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "code": proc.returncode,
        }
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return {
            "stdout": out,
            "stderr": (err + f"\n[timeout after {SCRIPT_TIMEOUT}s]").strip(),
            "code": 124,
        }
    except OSError as exc:
        return {"stdout": "", "stderr": f"failed to launch: {exc}", "code": 126}


def _python_executable() -> str:
    import sys

    return sys.executable or "python"
