"""Unit tests for mask_secrets_with, run with plain unittest (no pytest
dependency) so they need nothing beyond the standard library -- not even
the built redact_secret extension, matching how
examples/safe-integration/integration.test.mjs tests pure logic with a
fake scanner instead of the real package.

Run directly:
    python3 -B examples/tracing-masking/python/test_mask_secrets.py
or via discovery:
    python3 -B -m unittest discover -s examples/tracing-masking/python -p "test_*.py"
"""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_scanner import fake_scan_and_redact  # noqa: E402
from mask_leaf import BLOCK_MARKER, CYCLE_MARKER, ERROR_MARKER, LIMIT_MARKER  # noqa: E402
from mask_secrets import mask_secrets_with  # noqa: E402

FIXTURES_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "mask-secrets-cases.json"


class SharedFixtureTest(unittest.TestCase):
    """The shared fixture file: nested objects, arrays, chat-message
    arrays, tool-call arguments/results, and Unicode."""

    def test_shared_cases(self) -> None:
        cases = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))["cases"]
        for case in cases:
            with self.subTest(name=case["name"]):
                result = mask_secrets_with(fake_scan_and_redact, case["input"])
                self.assertEqual(result, case["expected"])


class MaskSecretsWithTest(unittest.TestCase):
    def test_large_string_within_limit_is_scanned_in_full(self) -> None:
        data = {"blob": "x" * 3000 + " SECRET_TOKEN_9 " + "y" * 3000}
        expected = {"blob": "x" * 3000 + " <SECRET_1> " + "y" * 3000}
        self.assertEqual(mask_secrets_with(fake_scan_and_redact, data), expected)

    def test_block_finding_replaces_the_whole_leaf(self) -> None:
        result = mask_secrets_with(fake_scan_and_redact, {"key": "prefix BLOCK_ME suffix"})
        self.assertEqual(result["key"], BLOCK_MARKER)
        serialized = json.dumps(result)
        self.assertNotIn("prefix", serialized)
        self.assertNotIn("suffix", serialized)

    def test_core_failure_fails_closed(self) -> None:
        result = mask_secrets_with(fake_scan_and_redact, {"key": "trigger BOOM here"})
        self.assertEqual(result["key"], ERROR_MARKER)
        self.assertNotIn("BOOM", json.dumps(result))

    def test_numbers_booleans_none_and_non_plain_objects_are_unchanged(self) -> None:
        when = datetime(2026, 1, 1, tzinfo=timezone.utc)
        data = {"count": 1, "active": False, "missing": None, "when": when}
        result = mask_secrets_with(fake_scan_and_redact, data)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["active"], False)
        self.assertIsNone(result["missing"])
        self.assertIs(result["when"], when)

    def test_depth_beyond_limit_is_marked_rather_than_walked(self) -> None:
        data = {"a": {"b": {"c": "SECRET_TOKEN_1"}}}
        result = mask_secrets_with(fake_scan_and_redact, data, limits={"max_depth": 1})
        self.assertEqual(result["a"], LIMIT_MARKER)

    def test_array_and_dict_entries_beyond_limit_are_dropped(self) -> None:
        array_result = mask_secrets_with(fake_scan_and_redact, ["a", "b", "c"], limits={"max_array_length": 2})
        self.assertEqual(array_result, ["a", "b"])

        dict_result = mask_secrets_with(fake_scan_and_redact, {"a": "1", "b": "2", "c": "3"}, limits={"max_object_keys": 2})
        self.assertEqual(list(dict_result.keys()), ["a", "b"])

    def test_total_leaf_budget_bounds_the_whole_call(self) -> None:
        data = {"a": "SECRET_TOKEN_1", "b": "SECRET_TOKEN_2", "c": "SECRET_TOKEN_3"}
        result = mask_secrets_with(fake_scan_and_redact, data, limits={"max_total_leaves": 2})
        self.assertEqual(result["a"], "<SECRET_1>")
        self.assertEqual(result["b"], "<SECRET_1>")
        self.assertEqual(result["c"], LIMIT_MARKER)

    def test_cycle_is_marked_rather_than_recursed_into_forever(self) -> None:
        data: dict = {"name": "root"}
        data["self"] = data
        result = mask_secrets_with(fake_scan_and_redact, data)
        self.assertEqual(result["name"], "root")
        self.assertEqual(result["self"], CYCLE_MARKER)

    def test_string_too_long_is_marked_not_scanned(self) -> None:
        data = {"blob": "a" * 50}
        result = mask_secrets_with(fake_scan_and_redact, data, limits={"max_string_length": 10})
        self.assertEqual(result["blob"], LIMIT_MARKER)

    def test_rejects_non_callable_scan_and_redact(self) -> None:
        with self.assertRaises(TypeError):
            mask_secrets_with(None, {})


if __name__ == "__main__":
    unittest.main()
