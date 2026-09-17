"""Unit tests for redact_tool_call, run with plain unittest -- no pytest,
no built ``redact_secret`` extension required, matching
``examples/tracing-masking/python/test_mask_secrets.py``.

Run directly:
    python3 -B examples/mcp-redact/python/test_redact_tool_call.py
or via discovery:
    python3 -B -m unittest discover -s examples/mcp-redact/python -p "test_*.py"
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_scanner import fake_scan_and_redact  # noqa: E402
from redact_tool_call import (  # noqa: E402
    BLOCKED_MESSAGE,
    LIMIT_MARKER,
    build_blocked_result,
    redact_arguments,
    redact_tool_result,
)

FIXTURES_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "mcp-redact-cases.json"


class SharedFixtureTest(unittest.TestCase):
    """The same fixture file ``redact-tool-call.test.mjs`` reads, proving JS
    and Python agree on text, JSON-in-text, multi-block, resource,
    structuredContent, unicode, block, and core-error outcomes."""

    def setUp(self) -> None:
        self.cases = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))

    def test_result_cases(self) -> None:
        for case in self.cases["resultCases"]:
            with self.subTest(name=case["name"]):
                outcome = redact_tool_result(fake_scan_and_redact, case["input"])
                if case["expectedBlocked"]:
                    self.assertEqual(outcome["outcome"], "blocked")
                    self.assertNotIn("result", outcome)
                else:
                    self.assertEqual(outcome["outcome"], "ok")
                    self.assertEqual(outcome["result"], case["expected"])

    def test_argument_cases(self) -> None:
        for case in self.cases["argumentCases"]:
            with self.subTest(name=case["name"]):
                outcome = redact_arguments(fake_scan_and_redact, case["input"])
                if case["expectedBlocked"]:
                    self.assertEqual(outcome["outcome"], "blocked")
                    self.assertNotIn("arguments", outcome)
                else:
                    self.assertEqual(outcome["outcome"], "ok")
                    self.assertEqual(outcome["arguments"], case["expected"])


class RedactToolCallTest(unittest.TestCase):
    def test_build_blocked_result_carries_only_the_fixed_message(self) -> None:
        result = build_blocked_result()
        self.assertEqual(result["isError"], True)
        self.assertEqual(result["content"], [{"type": "text", "text": BLOCKED_MESSAGE}])

    def test_block_finding_never_leaves_plaintext_or_input(self) -> None:
        outcome = redact_tool_result(
            fake_scan_and_redact, {"content": [{"type": "text", "text": "leaked BLOCK_ME right here"}]}
        )
        self.assertEqual(outcome["outcome"], "blocked")
        serialized = str(outcome)
        self.assertNotIn("leaked", serialized)
        self.assertNotIn("right here", serialized)

    def test_findings_reported_even_on_blocked_outcome(self) -> None:
        outcome = redact_tool_result(fake_scan_and_redact, {"content": [{"type": "text", "text": "BLOCK_ME"}]})
        self.assertEqual(len(outcome["findings"]), 1)
        self.assertEqual(outcome["findings"][0].action, "block")
        self.assertIsInstance(outcome["findings"][0].id, str)

    def test_non_text_blocks_pass_through_unchanged(self) -> None:
        data = {
            "content": [
                {"type": "image", "data": "AAAA", "mimeType": "image/png"},
                {"type": "audio", "data": "BBBB", "mimeType": "audio/wav"},
                {"type": "resource_link", "uri": "file:///x", "name": "x"},
            ]
        }
        outcome = redact_tool_result(fake_scan_and_redact, data)
        self.assertEqual(outcome["outcome"], "ok")
        self.assertEqual(outcome["result"], data)

    def test_depth_beyond_limit_is_marked_and_does_not_block(self) -> None:
        outcome = redact_arguments(
            fake_scan_and_redact, {"a": {"b": {"c": "SECRET_TOKEN_1"}}}, limits={"max_depth": 1}
        )
        self.assertEqual(outcome["outcome"], "ok")
        self.assertEqual(outcome["arguments"]["a"], LIMIT_MARKER)

    def test_total_leaf_budget_bounds_the_whole_call(self) -> None:
        outcome = redact_arguments(
            fake_scan_and_redact,
            {"a": "SECRET_TOKEN_1", "b": "SECRET_TOKEN_2"},
            limits={"max_total_leaves": 1},
        )
        self.assertEqual(outcome["outcome"], "ok")
        self.assertEqual(outcome["arguments"]["a"], "<SECRET_1>")
        self.assertEqual(outcome["arguments"]["b"], LIMIT_MARKER)

    def test_rejects_non_callable_scan_and_redact(self) -> None:
        with self.assertRaises(TypeError):
            redact_tool_result(None, {"content": []})
        with self.assertRaises(TypeError):
            redact_arguments(None, {})

    def test_content_beyond_max_content_blocks_is_dropped(self) -> None:
        data = {"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}, {"type": "text", "text": "c"}]}
        outcome = redact_tool_result(fake_scan_and_redact, data, limits={"max_content_blocks": 2})
        self.assertEqual(outcome["outcome"], "ok")
        self.assertEqual(len(outcome["result"]["content"]), 2)


if __name__ == "__main__":
    unittest.main()
