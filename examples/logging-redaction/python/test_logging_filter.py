"""Unit tests for RedactSecretFilter and mask_log_value_with, run with
plain unittest (no pytest dependency) so they need nothing beyond the
standard library -- not even the built redact_secret extension, matching
how examples/logging-redaction/pino-hook.test.mjs tests pure logic with a
fake scanner instead of the real package.

Run directly:
    python3 -B examples/logging-redaction/python/test_logging_filter.py
or via discovery:
    python3 -B -m unittest discover -s examples/logging-redaction/python -p "test_*.py"
"""

from __future__ import annotations

import json
import logging
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_scanner import fake_scan_and_redact  # noqa: E402
from logging_filter import RedactSecretFilter  # noqa: E402
from mask_leaf import BLOCK_MARKER, ERROR_MARKER  # noqa: E402
from mask_log_value import mask_log_value_with  # noqa: E402

FIXTURES_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "logging-redaction-cases.json"

# Built from two literals so the full token never appears contiguously in
# this file's source: `fake_scan_and_redact` redacts only the first match
# per call (matching the real core's per-call behavior, not its ability to
# find every occurrence in one string), and `traceback.format_exception`
# echoes each frame's raw source line -- a literal secret in the `raise`
# call or any of its callers would appear a second, unredacted time there.
_SECRET = "SECRET_TOKEN" + "_1"


class SharedFixtureTest(unittest.TestCase):
    """The same fixture file `pino-hook.test.mjs` reads, proving JS and
    Python agree on message strings, merging/extra fields, nesting,
    arrays, and Unicode."""

    def test_shared_cases(self) -> None:
        cases = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))["cases"]
        for case in cases:
            with self.subTest(name=case["name"]):
                result = mask_log_value_with(fake_scan_and_redact, case["input"])
                self.assertEqual(result, case["expected"])


class ListHandler(logging.Handler):
    """Captures fully formatted (`Formatter.format`-ed) lines, so a test
    can assert on exactly what would have reached a real destination."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


def _raise_with_secret(secret: str) -> None:
    # `fake_scan_and_redact` (like every fixture fake in this repo)
    # redacts only the first match per call, matching the real core's
    # per-call behavior but not its ability to find every occurrence in
    # one string; that's irrelevant here as long as the secret literal
    # appears exactly once in the rendered traceback. Building the
    # message from a variable, instead of a literal in the `raise` line,
    # keeps it out of the traceback's source-context line, which would
    # otherwise print the raw literal from this file a second time.
    raise ValueError("db write failed: " + secret)


def make_logger(name: str, *, extra_fields: tuple[str, ...] = ()) -> tuple[logging.Logger, ListHandler]:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    handler = ListHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(RedactSecretFilter(fake_scan_and_redact, extra_fields=list(extra_fields)))
    logger.addHandler(handler)
    return logger, handler


class RedactSecretFilterTest(unittest.TestCase):
    def test_percent_style_args_are_redacted_and_no_plaintext_is_emitted(self) -> None:
        logger, handler = make_logger("logging-redaction.percent")
        logger.info("user %s presented token %s", "alice", "SECRET_TOKEN_1")
        self.assertEqual(handler.lines, ["user alice presented token <SECRET_1>"])

    def test_f_string_message_is_redacted(self) -> None:
        logger, handler = make_logger("logging-redaction.fstring")
        token = "SECRET_TOKEN_1"
        logger.info(f"token was {token}")
        self.assertEqual(handler.lines, ["token was <SECRET_1>"])

    def test_exc_info_traceback_is_redacted_and_exc_info_is_cleared(self) -> None:
        logger, handler = make_logger("logging-redaction.exc")
        try:
            _raise_with_secret(_SECRET)
        except ValueError:
            logger.exception("query failed")
        self.assertEqual(len(handler.lines), 1)
        self.assertIn("query failed", handler.lines[0])
        self.assertIn("<SECRET_1>", handler.lines[0])
        self.assertNotIn("SECRET_TOKEN_1", handler.lines[0])

        captured = []

        def capture(record: logging.LogRecord) -> bool:
            captured.append(record)
            return True

        logger2, handler2 = make_logger("logging-redaction.exc-info-cleared")
        # Added to the handler, after RedactSecretFilter, so it observes
        # the record post-redaction: Handler-level filters run in
        # addFilter order inside Handler.handle, which fires only after
        # Logger-level filtering has already passed the record through.
        handler2.addFilter(capture)
        try:
            _raise_with_secret(_SECRET)
        except ValueError:
            logger2.exception("query failed")
        self.assertIsNone(captured[0].exc_info)
        self.assertIn("<SECRET_1>", captured[0].exc_text)

    def test_configured_extra_string_field_is_redacted(self) -> None:
        logger, handler = make_logger("logging-redaction.extra", extra_fields=("request_id", "auth_header"))
        logger.info("request received", extra={"request_id": "req-1", "auth_header": "Bearer SECRET_TOKEN_1"})

        captured = []
        handler.addFilter(lambda record: captured.append(record) or True)
        logger.info("second call", extra={"request_id": "req-2", "auth_header": "Bearer SECRET_TOKEN_1"})
        self.assertEqual(captured[0].auth_header, "Bearer <SECRET_1>")
        self.assertEqual(captured[0].request_id, "req-2")

    def test_unconfigured_extra_field_is_left_untouched(self) -> None:
        logger, handler = make_logger("logging-redaction.extra-unconfigured", extra_fields=())
        captured = []
        handler.addFilter(lambda record: captured.append(record) or True)
        logger.info("request received", extra={"auth_header": "Bearer SECRET_TOKEN_1"})
        self.assertEqual(captured[0].auth_header, "Bearer SECRET_TOKEN_1")

    def test_block_finding_replaces_the_whole_message(self) -> None:
        logger, handler = make_logger("logging-redaction.block")
        logger.info("prefix BLOCK_ME suffix")
        self.assertEqual(handler.lines, [BLOCK_MARKER])

    def test_core_failure_fails_closed(self) -> None:
        logger, handler = make_logger("logging-redaction.error")
        logger.info("trigger BOOM here")
        self.assertEqual(handler.lines, [ERROR_MARKER])

    def test_rejects_a_non_callable_scan_and_redact(self) -> None:
        with self.assertRaises(TypeError):
            RedactSecretFilter(None)


if __name__ == "__main__":
    unittest.main()
