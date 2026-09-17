"""Unit tests for streaming_tool_result, run with plain unittest.

Run directly:
    python3 -B examples/mcp-redact/python/test_streaming_tool_result.py
or via discovery:
    python3 -B -m unittest discover -s examples/mcp-redact/python -p "test_*.py"
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_incremental_sanitizer import create_fake_incremental_sanitizer  # noqa: E402
from streaming_tool_result import create_streaming_tool_result_redactor  # noqa: E402

LIMITS = {
    "max_input_bytes": 10_000,
    "max_buffered_bytes": 200,
    "max_token_bytes": 100,
    "max_multiline_bytes": 200,
}


class StreamingToolResultTest(unittest.TestCase):
    def test_secret_split_across_two_chunks_is_redacted_at_finalize(self) -> None:
        redactor = create_streaming_tool_result_redactor(create_fake_incremental_sanitizer, limits=LIMITS)
        # Neither chunk alone contains the full "SECRET_TOKEN_9" pattern.
        redactor.append("prefix SECRET_TOK")
        redactor.append("EN_9 suffix")
        outcome = redactor.finalize()

        self.assertEqual(outcome["outcome"], "ok")
        self.assertEqual(outcome["result"], {"content": [{"type": "text", "text": "prefix <SECRET_1> suffix"}]})
        self.assertEqual(len(outcome["findings"]), 1)
        self.assertEqual(outcome["findings"][0].action, "redact")

    def test_block_finding_at_finalize_fails_the_whole_session_closed(self) -> None:
        redactor = create_streaming_tool_result_redactor(create_fake_incremental_sanitizer, limits=LIMITS)
        redactor.append("leaked ")
        redactor.append("BLOCK_ME here")
        outcome = redactor.finalize()

        self.assertEqual(outcome["outcome"], "blocked")
        self.assertEqual(outcome["blockReason"], "policy")
        self.assertNotIn("result", outcome)

    def test_exceeding_buffer_limit_fails_closed(self) -> None:
        redactor = create_streaming_tool_result_redactor(
            create_fake_incremental_sanitizer, limits={**LIMITS, "max_buffered_bytes": 10}
        )
        redactor.append("well within the limit for the first chunk, ")
        redactor.append("and this pushes it over the declared bound")
        outcome = redactor.finalize()

        self.assertEqual(outcome["outcome"], "blocked")
        self.assertEqual(outcome["blockReason"], "limit_exceeded")
        self.assertNotIn("result", outcome)

    def test_append_is_a_noop_once_blocked(self) -> None:
        redactor = create_streaming_tool_result_redactor(
            create_fake_incremental_sanitizer, limits={**LIMITS, "max_buffered_bytes": 5}
        )
        redactor.append("way over the five character limit")
        redactor.append("more")  # must not raise
        outcome = redactor.finalize()
        self.assertEqual(outcome["outcome"], "blocked")

    def test_clean_session_returns_assembled_text_untouched(self) -> None:
        redactor = create_streaming_tool_result_redactor(create_fake_incremental_sanitizer, limits=LIMITS)
        redactor.append("nothing ")
        redactor.append("sensitive here")
        outcome = redactor.finalize()
        self.assertEqual(outcome["outcome"], "ok")
        self.assertEqual(outcome["result"], {"content": [{"type": "text", "text": "nothing sensitive here"}]})

    def test_finalize_cannot_be_called_twice(self) -> None:
        redactor = create_streaming_tool_result_redactor(create_fake_incremental_sanitizer, limits=LIMITS)
        redactor.finalize()
        with self.assertRaises(RuntimeError):
            redactor.finalize()

    def test_limits_is_required(self) -> None:
        with self.assertRaises(TypeError):
            create_streaming_tool_result_redactor(create_fake_incremental_sanitizer, limits={})
        with self.assertRaises(TypeError):
            create_streaming_tool_result_redactor(create_fake_incremental_sanitizer)

    def test_rejects_non_callable_create_session(self) -> None:
        with self.assertRaises(TypeError):
            create_streaming_tool_result_redactor(None, limits=LIMITS)


if __name__ == "__main__":
    unittest.main()
