"""lockfile.py — parse package.json / package-lock.json into dependency names.

Pure stdlib. The scanner only needs the set of direct + transitive package
names; it does not resolve versions or fetch anything itself.
"""

from __future__ import annotations

import json
from pathlib import Path


class LockfileError(ValueError):
    """Raised when the input is not a recognizable package.json/lock."""


def _names_from_package_json(data: dict) -> list[str]:
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            names.update(str(k) for k in block.keys())
    return sorted(names)


def _names_from_lock_v1(data: dict) -> list[str]:
    # lockfileVersion 1: {"dependencies": {"<name>": {...}}}
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        return sorted(str(k) for k in deps.keys())
    return []


def _names_from_lock_v2(data: dict) -> list[str]:
    # lockfileVersion 2/3: {"packages": {"": {...}, "node_modules/<name>": {...}}}
    pkgs = data.get("packages")
    names: set[str] = set()
    if isinstance(pkgs, dict):
        for path in pkgs.keys():
            if not isinstance(path, str):
                continue
            if path.startswith("node_modules/"):
                # "node_modules/a/node_modules/b" -> "b"
                name = path.split("node_modules/")[-1]
                if name:
                    names.add(name)
    # v2 also keeps a flat "dependencies" map for back-compat
    names.update(_names_from_lock_v1(data))
    return sorted(names)


def parse_dependencies(text: str) -> list[str]:
    """Parse dependency names from package.json or package-lock.json content.

    Returns a sorted, de-duplicated list of package names. Raises
    LockfileError if the text is not valid JSON or has no recognizable
    dependency structure.
    """
    if not text or not text.strip():
        raise LockfileError("empty input")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockfileError(f"not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LockfileError("expected a JSON object at the top level")

    names: list[str] = []
    # package-lock.json has "packages" (v2/v3) or "lockfileVersion" + "dependencies" (v1)
    if isinstance(data.get("packages"), dict) or "lockfileVersion" in data:
        names = _names_from_lock_v2(data)
    # package.json has dependency blocks
    if not names:
        names = _names_from_package_json(data)

    # de-dupe while keeping sorted order
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    if not out:
        raise LockfileError(
            "no dependencies found — is this a package.json or package-lock.json?"
        )
    return out


def parse_dependencies_file(path: str | Path) -> list[str]:
    p = Path(path)
    if not p.is_file():
        raise LockfileError(f"file not found: {p}")
    return parse_dependencies(p.read_text(encoding="utf-8"))
