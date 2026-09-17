"""Redact messages, exceptions, stack text, and configured string extras.

The filter formats ``msg`` with ``args`` before scanning, then clears the
arguments so downstream formatters cannot reconstruct the original message.
It replaces ``exc_info`` with sanitized traceback text and also scans cached
``exc_text`` when the exception tuple is absent.

Attach the filter to each emitting handler. Ancestor logger filters do not
run for propagated child records; mutations to a record are shared by its
handlers. Custom formatters must not add unscanned fields afterward.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Sequence

from mask_leaf import mask_leaf_with
from mask_log_value import mask_log_value_with

import logging

__all__ = ["RedactSecretFilter"]


class RedactSecretFilter(logging.Filter):
    """Redacts a ``LogRecord`` in place and always returns ``True`` (never
    drops a record; a `block` finding replaces the affected text with a
    fixed marker instead, matching the JS `hooks.logMethod` integration's
    ``BLOCK_MARKER`` behavior in ``../mask-leaf.mjs``).

    ``scan_and_redact`` is injected -- pass ``redact_secret.scan_and_redact``
    for the live integration, or a fake for tests (this module is
    testable without the built native extension, matching
    ``../pino-hook.mjs``). ``extra_fields`` names attributes set via a log
    call's ``extra={...}`` kwarg to also redact if their value is a
    ``str``; unlisted attributes, and non-``str`` extras, are left
    untouched, since this filter never assumes a wire format wide enough
    to know every possible extra field.
    """

    def __init__(
        self,
        scan_and_redact: Callable[..., Any],
        *,
        name: str = "",
        policy: Optional[Any] = None,
        extra_fields: Sequence[str] = (),
        limits: Optional[dict[str, int]] = None,
    ) -> None:
        super().__init__(name)
        if not callable(scan_and_redact):
            raise TypeError("RedactSecretFilter: scan_and_redact must be callable")
        self._scan_and_redact = scan_and_redact
        self._policy = policy
        self._extra_fields = tuple(extra_fields)
        self._limits = limits

    def _mask(self, text: str) -> str:
        max_len = (self._limits or {}).get("max_string_length") if self._limits else None
        return mask_leaf_with(self._scan_and_redact, text, policy=self._policy, max_string_length=max_len)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._mask(record.getMessage())
        record.args = None

        if record.exc_info:
            _exc_type, exc_value, _exc_tb = record.exc_info
            if exc_value is not None:
                masked = mask_log_value_with(self._scan_and_redact, exc_value, policy=self._policy, limits=self._limits)
                record.exc_text = masked["stack"] if isinstance(masked, dict) else masked
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self._mask(record.exc_text)

        if record.stack_info:
            record.stack_info = self._mask(record.stack_info)

        for field in self._extra_fields:
            value = getattr(record, field, None)
            if isinstance(value, str):
                setattr(record, field, self._mask(value))

        return True
