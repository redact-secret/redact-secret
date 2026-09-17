"""Unit tests for RedactingSpanProcessorWith, run with plain unittest --
no opentelemetry-sdk or redact_secret dependency needed, matching how
test_mask_secrets.py tests pure logic with a fake scanner and plain
duck-typed stand-ins for the SDK's Span/ReadableSpan/SpanProcessor types.

Run directly:
    python3 -B examples/tracing-masking/python/test_redact_span_attributes.py
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_scanner import fake_scan_and_redact  # noqa: E402
from redact_span_attributes import RedactingSpanProcessorWith, redact_attributes_with  # noqa: E402


class FakeEvent:
    def __init__(self, attributes: dict) -> None:
        self._attributes = attributes


class FakeSpan:
    """Stands in for `ReadableSpan`: attributes/event attributes live on
    the private `_attributes` field, matching the real SDK's read-only
    `.attributes` property."""

    def __init__(self, attributes: dict, events=()) -> None:
        self._attributes = attributes
        self.events = list(events)


class FakeNextProcessor:
    def __init__(self) -> None:
        self.started: list[tuple] = []
        self.exported: list[FakeSpan] = []

    def on_start(self, span, parent_context=None) -> None:
        self.started.append((span, parent_context))

    def on_end(self, span) -> None:
        self.exported.append(span)

    def shutdown(self) -> str:
        return "shutdown"

    def force_flush(self, timeout_millis: int = 30000) -> str:
        return "flushed"


class RedactingSpanProcessorWithTest(unittest.TestCase):
    def test_redacts_string_and_string_sequence_attributes_before_export(self) -> None:
        next_processor = FakeNextProcessor()
        processor = RedactingSpanProcessorWith(next_processor, fake_scan_and_redact)
        span = FakeSpan(
            attributes={
                "llm.input_messages": "call SECRET_TOKEN_1 now",
                "llm.tags": ["ok", "BLOCK_ME here"],
                "retry.count": 3,
                "retry.ok": True,
            },
            events=[FakeEvent({"tool.args": "value SECRET_TOKEN_2 done"})],
        )

        processor.on_end(span)

        self.assertEqual(len(next_processor.exported), 1)
        exported = next_processor.exported[0]
        self.assertEqual(exported._attributes["llm.input_messages"], "call <SECRET_1> now")
        self.assertEqual(exported._attributes["llm.tags"], ["ok", "[REDACTED:BLOCKED]"])
        self.assertEqual(exported._attributes["retry.count"], 3)
        self.assertEqual(exported._attributes["retry.ok"], True)
        self.assertEqual(exported.events[0]._attributes["tool.args"], "value <SECRET_1> done")

        serialized = json.dumps(
            [{"attributes": s._attributes, "events": [e._attributes for e in s.events]} for s in next_processor.exported]
        )
        self.assertNotIn("SECRET_TOKEN_1", serialized)
        self.assertNotIn("SECRET_TOKEN_2", serialized)
        self.assertNotIn("BLOCK_ME", serialized)

    def test_core_failure_on_one_attribute_fails_closed(self) -> None:
        next_processor = FakeNextProcessor()
        processor = RedactingSpanProcessorWith(next_processor, fake_scan_and_redact)
        span = FakeSpan(attributes={"boom": "trigger BOOM here"})

        processor.on_end(span)

        self.assertEqual(next_processor.exported[0]._attributes["boom"], "[REDACTED:ERROR]")
        self.assertNotIn("BOOM", json.dumps(next_processor.exported[0]._attributes))

    def test_on_start_shutdown_force_flush_delegate(self) -> None:
        next_processor = FakeNextProcessor()
        processor = RedactingSpanProcessorWith(next_processor, fake_scan_and_redact)

        processor.on_start("span-1", "ctx-1")
        self.assertEqual(next_processor.started, [("span-1", "ctx-1")])
        self.assertEqual(processor.shutdown(), None)
        self.assertEqual(processor.force_flush(), "flushed")

    def test_redact_attributes_with_is_a_noop_for_none(self) -> None:
        redact_attributes_with(fake_scan_and_redact, None)  # must not raise

    def test_rejects_next_processor_without_on_end_or_non_callable_scanner(self) -> None:
        with self.assertRaises(TypeError):
            RedactingSpanProcessorWith(object(), fake_scan_and_redact)
        with self.assertRaises(TypeError):
            RedactingSpanProcessorWith(FakeNextProcessor(), None)


if __name__ == "__main__":
    unittest.main()
