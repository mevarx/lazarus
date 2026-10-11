"""Parse package.json / package-lock.json into validated npm package names."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


DEFAULT_MAX_INPUT_BYTES = 5 * 1024 * 1024
_PACKAGE_PART = re.compile(r"[a-z0-9][a-z0-9._~-]*\Z")


class LockfileError(ValueError):
    """Raised when input is too large or is not a supported dependency file."""


def max_input_bytes() -> int:
    value = os.environ.get("LAZARUS_MAX_INPUT_BYTES")
    if value is None:
        return DEFAULT_MAX_INPUT_BYTES
    try:
        limit = int(value)
    except ValueError as exc:
        raise LockfileError("LAZARUS_MAX_INPUT_BYTES must be a positive integer") from exc
    if limit < 1 or limit > sys.maxsize:
        raise LockfileError("LAZARUS_MAX_INPUT_BYTES must be a positive integer")
    return limit


def is_valid_package_name(name: str) -> bool:
    """Accept npm package names, including one optional @scope/ prefix."""
    if not isinstance(name, str) or not name or len(name) > 214 or ".." in name:
        return False
    if name.startswith("@"):
        parts = name[1:].split("/")
        return len(parts) == 2 and all(_PACKAGE_PART.fullmatch(part) for part in parts)
    return (name not in {"node_modules", "favicon.ico"}
            and "/" not in name and bool(_PACKAGE_PART.fullmatch(name)))


def _lock_v1_names(dependencies: dict) -> list[str]:
    names: list[str] = []
    pending = [dependencies]
    while pending:
        block = pending.pop()
        for name, details in block.items():
            names.append(name)
            if isinstance(details, dict) and isinstance(details.get("dependencies"), dict):
                pending.append(details["dependencies"])
    return names


def _candidate_names(data: dict) -> list[str]:
    package_blocks = ("dependencies", "devDependencies", "peerDependencies",
                      "optionalDependencies")
    has_lock_shape = "lockfileVersion" in data or "packages" in data
    if has_lock_shape:
        version = data.get("lockfileVersion")
        if not isinstance(version, int) or isinstance(version, bool) or version not in (1, 2, 3):
            raise LockfileError("unsupported package-lock lockfileVersion")
        packages = data.get("packages")
        dependencies = data.get("dependencies")
        if "packages" in data and not isinstance(packages, dict):
            raise LockfileError("unsupported package-lock packages shape")
        if "dependencies" in data and not isinstance(dependencies, dict):
            raise LockfileError("unsupported package-lock dependencies shape")
        if packages is None and dependencies is None:
            raise LockfileError("package-lock has no packages or dependencies map")
        names = _lock_v1_names(dependencies) if isinstance(dependencies, dict) else []
        if isinstance(packages, dict):
            for path in packages:
                if path.startswith("node_modules/"):
                    names.append(path.rsplit("node_modules/", 1)[-1])
        return names

    present = [key for key in package_blocks if key in data]
    if not present:
        raise LockfileError("unsupported input shape; expected package.json or package-lock.json")
    names: list[str] = []
    for key in present:
        block = data[key]
        if not isinstance(block, dict):
            raise LockfileError(f"unsupported package.json {key} shape")
        names.extend(block.keys())
    return names


def _parse(text: str) -> tuple[list[str], int]:
    if not text or not text.strip():
        raise LockfileError("empty input")
    if any((ord(char) < 32 and char not in "\t\n\r") or ord(char) == 127
           for char in text):
        raise LockfileError("binary or control characters in input")
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LockfileError("not valid or safely nested JSON") from exc
    if not isinstance(data, dict):
        raise LockfileError("expected a JSON object at the top level")

    candidates = _candidate_names(data)
    valid: set[str] = set()
    invalid = 0
    for name in candidates:
        if is_valid_package_name(name):
            valid.add(name)
        else:
            invalid += 1
    return sorted(valid), invalid


def parse_dependencies_with_stats(text: str) -> tuple[list[str], int]:
    """Return sorted valid package names and the number of skipped invalid names."""
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise LockfileError("input is not valid UTF-8 text") from exc
    if size > max_input_bytes():
        raise LockfileError(f"input exceeds the {max_input_bytes()} byte limit")
    return _parse(text)


def parse_dependencies(text: str) -> list[str]:
    """Return sorted, de-duplicated dependency names from supported npm JSON."""
    return parse_dependencies_with_stats(text)[0]


def parse_dependencies_file_with_stats(path: str | Path) -> tuple[list[str], int]:
    p = Path(path)
    try:
        if not p.is_file():
            raise LockfileError(f"not a regular file: {p}")
        limit = max_input_bytes()
        with p.open("rb") as source:
            raw = source.read(limit + 1)
    except LockfileError:
        raise
    except OSError as exc:
        raise LockfileError(f"cannot read input file: {p}") from exc
    if len(raw) > limit:
        raise LockfileError(f"input exceeds the {limit} byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LockfileError("input is not valid UTF-8 text") from exc
    return _parse(text)


def parse_dependencies_file(path: str | Path) -> list[str]:
    return parse_dependencies_file_with_stats(path)[0]
