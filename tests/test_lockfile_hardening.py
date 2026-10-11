import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import lockfile


class LockfileHardeningTests(unittest.TestCase):
    def test_npm_names_and_invalid_name_count(self):
        content = json.dumps({"dependencies": {
            "express": "*", "@scope/package": "*", "Upper": "*",
            "foo..bar": "*", "../escape": "*", "https://evil.test/pkg": "*",
            "bad name": "*", "node_modules": "*", "favicon.ico": "*",
        }})
        names, skipped = lockfile.parse_dependencies_with_stats(content)
        self.assertEqual(names, ["@scope/package", "express"])
        self.assertEqual(skipped, 7)

    def test_nested_v1_and_scoped_v3(self):
        v1 = '{"lockfileVersion":1,"dependencies":{"outer":{"dependencies":{"inner":{}}}}}'
        self.assertEqual(lockfile.parse_dependencies(v1), ["inner", "outer"])
        v3 = '{"lockfileVersion":3,"packages":{"":{},"node_modules/@scope/pkg":{}}}'
        self.assertEqual(lockfile.parse_dependencies(v3), ["@scope/pkg"])

    def test_empty_dependency_block_is_valid_and_empty(self):
        self.assertEqual(lockfile.parse_dependencies('{"dependencies":{}}'), [])

    def test_unsupported_lockfile_version(self):
        with self.assertRaisesRegex(lockfile.LockfileError, "unsupported"):
            lockfile.parse_dependencies('{"lockfileVersion":4,"packages":{}}')

    def test_deep_json_is_rejected_without_recursion_error(self):
        with self.assertRaises(lockfile.LockfileError):
            lockfile.parse_dependencies("[" * 1200 + "0" + "]" * 1200)

    def test_binary_and_control_input_rejected(self):
        for content in ("{\"dependencies\":{\"x\":\"*\"}}\0", "\x7f"):
            with self.subTest(content=repr(content)):
                with self.assertRaisesRegex(lockfile.LockfileError, "binary|control"):
                    lockfile.parse_dependencies(content)

    def test_input_byte_limit_applies_to_text_and_files(self):
        content = '{"dependencies":{"express":"*"}}'
        with patch.dict(os.environ, {"LAZARUS_MAX_INPUT_BYTES": "10"}):
            with self.assertRaisesRegex(lockfile.LockfileError, "byte limit"):
                lockfile.parse_dependencies(content)
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "package.json"
                path.write_text(content)
                with self.assertRaisesRegex(lockfile.LockfileError, "byte limit"):
                    lockfile.parse_dependencies_file(path)

    def test_file_input_requires_regular_utf8_file(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with self.assertRaisesRegex(lockfile.LockfileError, "regular file"):
                lockfile.parse_dependencies_file(directory)
            binary = directory / "package.json"
            binary.write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(lockfile.LockfileError, "UTF-8"):
                lockfile.parse_dependencies_file(binary)


if __name__ == "__main__":
    unittest.main()
