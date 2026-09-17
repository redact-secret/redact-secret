"""Unit tests for wrap_tool_call, run with plain unittest.

Run directly:
    python3 -B examples/mcp-redact/python/test_wrap_tool_call.py
or via discovery:
    python3 -B -m unittest discover -s examples/mcp-redact/python -p "test_*.py"
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_scanner import fake_scan_and_redact  # noqa: E402
from redact_tool_call import BLOCKED_MESSAGE  # noqa: E402
from wrap_tool_call import wrap_client_call_tool, wrap_server_tool_handler  # noqa: E402


class ServerToolHandlerTest(unittest.IsolatedAsyncioTestCase):
    async def test_redacts_handler_result_before_returning(self) -> None:
        async def handler(ctx, params):
            return {"content": [{"type": "text", "text": f"read {params['arguments']['path']}: SECRET_TOKEN_1"}]}

        wrapped = wrap_server_tool_handler(handler, fake_scan_and_redact)
        result = await wrapped(None, {"arguments": {"path": "/tmp/x"}})
        self.assertEqual(result, {"content": [{"type": "text", "text": "read /tmp/x: <SECRET_1>"}]})

    async def test_leaves_arguments_untouched_by_default(self) -> None:
        seen = {}

        async def handler(ctx, params):
            seen["arguments"] = params["arguments"]
            return {"content": [{"type": "text", "text": "ok"}]}

        wrapped = wrap_server_tool_handler(handler, fake_scan_and_redact)
        await wrapped(None, {"arguments": {"token": "SECRET_TOKEN_1"}})
        self.assertEqual(seen["arguments"], {"token": "SECRET_TOKEN_1"})

    async def test_redacts_arguments_before_calling_handler_when_configured(self) -> None:
        seen = {}

        async def handler(ctx, params):
            seen["arguments"] = params["arguments"]
            return {"content": [{"type": "text", "text": "ok"}]}

        wrapped = wrap_server_tool_handler(handler, fake_scan_and_redact, redact_arguments_before_forwarding=True)
        await wrapped(None, {"arguments": {"token": "SECRET_TOKEN_1"}})
        self.assertEqual(seen["arguments"], {"token": "<SECRET_1>"})

    async def test_never_calls_handler_when_argument_is_blocked(self) -> None:
        called = {"value": False}

        async def handler(ctx, params):
            called["value"] = True
            return {"content": []}

        wrapped = wrap_server_tool_handler(handler, fake_scan_and_redact, redact_arguments_before_forwarding=True)
        result = await wrapped(None, {"arguments": {"token": "BLOCK_ME"}})
        self.assertFalse(called["value"])
        self.assertEqual(result["isError"], True)
        self.assertEqual(result["content"], [{"type": "text", "text": BLOCKED_MESSAGE}])

    async def test_blocks_a_handler_result_containing_a_block_finding(self) -> None:
        async def handler(ctx, params):
            return {"content": [{"type": "text", "text": "leak BLOCK_ME here"}]}

        wrapped = wrap_server_tool_handler(handler, fake_scan_and_redact)
        result = await wrapped(None, {"arguments": {}})
        self.assertEqual(result["isError"], True)
        self.assertNotIn("leak", str(result))

    async def test_reports_safe_finding_metadata_for_both_scopes(self) -> None:
        seen = []

        async def handler(ctx, params):
            return {"content": [{"type": "text", "text": "out SECRET_TOKEN_1 here"}]}

        wrapped = wrap_server_tool_handler(
            handler,
            fake_scan_and_redact,
            redact_arguments_before_forwarding=True,
            on_finding=lambda finding, scope: seen.append((scope, finding.action)),
        )
        await wrapped(None, {"arguments": {"in": "SECRET_TOKEN_2"}})
        self.assertEqual(seen, [("argument", "redact"), ("result", "redact")])

    async def test_throwing_on_finding_never_breaks_the_call(self) -> None:
        async def handler(ctx, params):
            return {"content": [{"type": "text", "text": "out SECRET_TOKEN_1 here"}]}

        def failing_audit(finding, scope):
            raise RuntimeError("audit sink is down")

        wrapped = wrap_server_tool_handler(handler, fake_scan_and_redact, on_finding=failing_audit)
        result = await wrapped(None, {"arguments": {}})
        self.assertEqual(result, {"content": [{"type": "text", "text": "out <SECRET_1> here"}]})

    def test_rejects_non_callable_handler(self) -> None:
        with self.assertRaises(TypeError):
            wrap_server_tool_handler(None, fake_scan_and_redact)


class ClientCallToolTest(unittest.IsolatedAsyncioTestCase):
    async def test_redacts_result_before_it_enters_model_context(self) -> None:
        async def call_tool(name, arguments):
            return {"content": [{"type": "text", "text": f"result for {name}: SECRET_TOKEN_1"}]}

        wrapped = wrap_client_call_tool(call_tool, fake_scan_and_redact)
        result = await wrapped("read_file", {})
        self.assertEqual(result, {"content": [{"type": "text", "text": "result for read_file: <SECRET_1>"}]})

    async def test_blocks_a_result_containing_a_block_finding(self) -> None:
        async def call_tool(name, arguments):
            return {"content": [{"type": "text", "text": "BLOCK_ME"}]}

        wrapped = wrap_client_call_tool(call_tool, fake_scan_and_redact)
        result = await wrapped("x", {})
        self.assertEqual(result["isError"], True)
        self.assertEqual(result["content"], [{"type": "text", "text": BLOCKED_MESSAGE}])

    def test_rejects_non_callable_call_tool(self) -> None:
        with self.assertRaises(TypeError):
            wrap_client_call_tool(None, fake_scan_and_redact)


if __name__ == "__main__":
    unittest.main()
