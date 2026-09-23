"""Unit tests for agent_context, run with plain unittest.

Run directly:
    python3 -B examples/mcp-redact/python/test_agent_context.py
or via discovery:
    python3 -B -m unittest discover -s examples/mcp-redact/python -p "test_*.py"
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_context import build_safe_context, redact_user_input  # noqa: E402
from fake_scanner import fake_scan_and_redact  # noqa: E402


class RedactUserInputTest(unittest.TestCase):
    def test_allow_clean_input_passes_through_untouched(self) -> None:
        result = redact_user_input(fake_scan_and_redact, "hello there")
        self.assertEqual(result, {"outcome": "ok", "text": "hello there", "findings": []})

    def test_redact_a_findings_span_is_replaced(self) -> None:
        result = redact_user_input(fake_scan_and_redact, "here is SECRET_TOKEN_1 ok")
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["text"], "here is <SECRET_1> ok")
        self.assertEqual(result["findings"][0].action, "redact")

    def test_warn_text_passes_through_unchanged_finding_still_reported(self) -> None:
        result = redact_user_input(fake_scan_and_redact, "WARN_ME please")
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["text"], "WARN_ME please")
        self.assertEqual(result["findings"][0].action, "warn")

    def test_block_blocks_with_no_text_or_input_retained(self) -> None:
        result = redact_user_input(fake_scan_and_redact, "BLOCK_ME now")
        self.assertEqual(result["outcome"], "blocked")
        self.assertEqual(result["blockReason"], "policy")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0].action, "block")
        self.assertNotIn("text", result)
        self.assertNotIn("BLOCK_ME", json.dumps(str(result)))

    def test_oversized_input_is_rejected_by_length_alone(self) -> None:
        called = {"value": False}

        def scan_and_redact(text, **_kwargs):
            called["value"] = True
            return None

        result = redact_user_input(scan_and_redact, "x" * 10, limits={"max_input_length": 5})
        self.assertEqual(result, {"outcome": "blocked", "blockReason": "input_too_large", "findings": []})
        self.assertFalse(called["value"])

    def test_scan_and_redact_failure_including_before_initialization_fails_closed(self) -> None:
        result = redact_user_input(fake_scan_and_redact, "BOOM here")
        self.assertEqual(result, {"outcome": "blocked", "blockReason": "core_error", "findings": []})

    def test_rejects_non_callable_scan_and_redact_or_non_str_text(self) -> None:
        with self.assertRaises(TypeError):
            redact_user_input(None, "x")
        with self.assertRaises(TypeError):
            redact_user_input(fake_scan_and_redact, 123)


class BuildSafeContextTest(unittest.IsolatedAsyncioTestCase):
    async def test_allow_clean_input_and_no_tool_call(self) -> None:
        result = await build_safe_context(scan_and_redact=fake_scan_and_redact, user_input="hello")
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["context"]["messages"], [{"role": "user", "content": "hello"}])
        self.assertEqual(result["findings"], [])

    async def test_redact_a_secret_in_user_input_before_context_construction(self) -> None:
        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact, user_input="my token is SECRET_TOKEN_1"
        )
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["context"]["messages"], [{"role": "user", "content": "my token is <SECRET_1>"}])

    async def test_warn_passes_through_and_is_still_reported(self) -> None:
        seen = []
        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="WARN_ME",
            on_finding=lambda finding, scope: seen.append((scope, finding.action)),
        )
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["context"]["messages"], [{"role": "user", "content": "WARN_ME"}])
        self.assertEqual(seen, [("input", "warn")])

    async def test_block_at_input_stage_never_dispatches_tool_or_builds_context(self) -> None:
        called = {"value": False}

        async def call_tool(request, **_kwargs):
            called["value"] = True
            return {"content": []}

        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="BLOCK_ME",
            call_tool=call_tool,
            build_tool_request=lambda safe_text: {"name": "x"},
        )
        self.assertEqual(result["outcome"], "blocked")
        self.assertEqual(result["stage"], "input")
        self.assertEqual(result["blockReason"], "policy")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0].action, "block")
        self.assertFalse(called["value"])
        self.assertNotIn("context", result)

    async def test_tool_result_is_scanned_before_entering_context(self) -> None:
        async def call_tool(request, **_kwargs):
            return {"content": [{"type": "text", "text": f"ran {request['name']}: SECRET_TOKEN_1"}]}

        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="run the tool",
            call_tool=call_tool,
            build_tool_request=lambda safe_text: {"name": "read_file"},
        )
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(
            result["context"]["messages"][1],
            {"role": "tool", "content": {"content": [{"type": "text", "text": "ran read_file: <SECRET_1>"}]}},
        )

    async def test_block_at_tool_stage_discards_context_never_retains_leaked_value(self) -> None:
        async def call_tool(request, **_kwargs):
            return {"content": [{"type": "text", "text": "leak BLOCK_ME here"}]}

        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="run the tool",
            call_tool=call_tool,
            build_tool_request=lambda safe_text: {"name": "x"},
        )
        self.assertEqual(result["outcome"], "blocked")
        self.assertEqual(result["stage"], "tool")
        self.assertNotIn("context", result)
        self.assertNotIn("leak", str(result))

    async def test_tool_dispatch_uses_sanitized_input_text_never_raw(self) -> None:
        seen = {}

        async def call_tool(request, **_kwargs):
            seen["text"] = request["text"]
            return {"content": [{"type": "text", "text": "ok"}]}

        await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="carrying SECRET_TOKEN_1 along",
            call_tool=call_tool,
            build_tool_request=lambda safe_text: {"text": safe_text},
        )
        self.assertEqual(seen["text"], "carrying <SECRET_1> along")

    async def test_core_failure_at_input_stage_fails_closed(self) -> None:
        result = await build_safe_context(scan_and_redact=fake_scan_and_redact, user_input="BOOM")
        self.assertEqual(result, {"outcome": "blocked", "stage": "input", "blockReason": "core_error", "findings": []})

    async def test_throwing_on_finding_never_breaks_the_call(self) -> None:
        def failing_audit(finding, scope):
            raise RuntimeError("audit sink is down")

        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact, user_input="SECRET_TOKEN_1", on_finding=failing_audit
        )
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["context"]["messages"], [{"role": "user", "content": "<SECRET_1>"}])

    async def test_cancellation_an_already_set_event_short_circuits_before_scanning(self) -> None:
        cancel_event = threading.Event()
        cancel_event.set()
        called = {"value": False}

        def scan_and_redact(text, **_kwargs):
            called["value"] = True
            return fake_scan_and_redact(text)

        result = await build_safe_context(
            scan_and_redact=scan_and_redact, user_input="SECRET_TOKEN_1", cancel_event=cancel_event
        )
        self.assertEqual(result, {"outcome": "aborted", "findings": []})
        self.assertFalse(called["value"])

    async def test_abort_the_event_firing_during_the_tool_call_discards_the_result(self) -> None:
        cancel_event = threading.Event()

        async def call_tool(request, **_kwargs):
            cancel_event.set()
            return {"content": [{"type": "text", "text": "ok"}]}

        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="hello",
            call_tool=call_tool,
            build_tool_request=lambda safe_text: {},
            cancel_event=cancel_event,
        )
        self.assertEqual(result, {"outcome": "aborted", "findings": []})

    async def test_a_raising_or_aborted_tool_call_blocks_with_nothing_retained(self) -> None:
        async def call_tool(request, **_kwargs):
            raise RuntimeError("CancelledError: the operation was aborted")

        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="hello",
            call_tool=call_tool,
            build_tool_request=lambda safe_text: {},
        )
        self.assertEqual(result["outcome"], "blocked")
        self.assertEqual(result["stage"], "tool")
        self.assertEqual(result["blockReason"], "tool_call_failed")
        self.assertNotIn("CancelledError", str(result))

    async def test_smoke_secrets_in_user_input_and_tool_result_never_reach_safe_context(self) -> None:
        async def call_tool(request, **_kwargs):
            return {
                "content": [
                    {"type": "text", "text": f"looked up {request['query']}: leaked DATABASE_URL=SECRET_TOKEN_2"}
                ]
            }

        result = await build_safe_context(
            scan_and_redact=fake_scan_and_redact,
            user_input="look up my key SECRET_TOKEN_1 please",
            call_tool=call_tool,
            build_tool_request=lambda safe_text: {"query": safe_text},
        )

        self.assertEqual(result["outcome"], "ok")
        serialized = json.dumps(result["context"])
        self.assertNotIn("SECRET_TOKEN_1", serialized)
        self.assertNotIn("SECRET_TOKEN_2", serialized)
        self.assertIn("<SECRET_1>", serialized)

        async def model_call(context):
            return json.dumps(context)

        sent_to_model = await model_call(result["context"])
        self.assertNotIn("SECRET_TOKEN_1", sent_to_model)
        self.assertNotIn("SECRET_TOKEN_2", sent_to_model)


if __name__ == "__main__":
    unittest.main()
