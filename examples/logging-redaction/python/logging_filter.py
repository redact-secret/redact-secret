"""``RedactSecretFilter``: a ``logging.Filter`` (pinned against CPython's
``logging`` module semantics, https://docs.python.org/3/library/logging.html
and https://github.com/python/cpython/blob/main/Lib/logging/__init__.py,
confirmed while resolving issue #328) that redacts a secret out of the
formatted message, ``args``, ``exc_info``/traceback text, ``stack_info``,
and configured ``extra`` string attributes on every ``LogRecord`` a logger
or handler processes, before any downstream ``Formatter`` or transport
sees the record.

API details this filter relies on, pinned here because the issue asks
that they be confirmed up front:

- ``LogRecord.getMessage()`` returns ``str(self.msg) % self.args`` (or just
  ``str(self.msg)`` when ``self.args`` is falsy) -- always a ``str``,
  whether the caller used ``%``-style args, an f-string, or a plain
  string. Redacting that return value and writing it back to ``record.msg``
  with ``record.args`` cleared makes every later ``getMessage()`` call
  (a ``Formatter`` calls it again) return the same already-redacted text,
  without reformatting -- and without ever handing ``%`` a redacted
  format string plus stale raw ``args``, which could raise or silently
  produce something unredacted.
- ``record.exc_text`` is *not* populated at record-creation time: CPython's
  ``Formatter.format()`` computes it lazily from ``record.exc_info`` on
  first use, then caches it back onto the record, so a filter that runs
  before formatting (a ``Filter`` always does: filters run in
  ``Logger.handle``/``Handler.handle``, before ``Handler.format``) sees
  ``exc_text is None`` even when ``exc_info`` is set. This filter formats
  the traceback itself with ``traceback.format_exception`` (which also
  expands any exception chain, ``__cause__``/``__context__``, into the
  same text CPython's own formatter would produce), redacts it, and
  writes the result to ``record.exc_text`` -- so ``Formatter.format()``'s
  own lazy step (`if not record.exc_text: record.exc_text =
  self.formatException(...)`) finds it already set and never touches the
  raw traceback.
- ``record.exc_info`` is cleared to ``None`` after its text is captured.
  Some handlers and structured-logging formatters read ``exc_info``
  directly instead of ``exc_text`` (for example to render a traceback with
  their own styling); clearing it trades that convenience for a hard
  guarantee that nothing downstream can re-extract the original exception
  object and print its unredacted message. A handler that only consults
  ``exc_text`` (CPython's own ``Formatter`` does) is unaffected.
- ``record.stack_info`` (set when a caller passes ``stack_info=True``) is,
  unlike ``exc_text``, already a formatted string by the time any filter
  runs -- ``Logger._log`` captures it via ``findCaller`` before the
  record is created -- so it is redacted directly, like any other string
  field.
- Attaching this filter to a ``Handler`` (``handler.addFilter(...)``)
  rather than to a ``Logger`` (``logger.addFilter(...)``) is the safer
  default for multi-handler setups: a per-logger filter runs once no
  matter how many handlers the record reaches, so a second handler added
  later without its own filter would emit the record's ORIGINAL
  ``msg``/``args`` unredacted, because a ``Logger``-level filter mutates
  the record only when that logger's own ``filter()`` call happens to run
  before propagation -- record mutation is shared, but attaching order
  and handler fan-out are not something either scope changes. The
  concrete pitfall: `logging.config.dictConfig` (or manual code) that adds
  a filter to a `Logger` but a **second** logger elsewhere in the
  hierarchy (or a handler on the root logger reached via propagation)
  also emits this same record without ever calling this filter, because
  each logger's filter list is separate and record mutation from a
  parent logger's `callHandlers` happens only for handlers *reachable
  from where the filter itself was attached*. Attaching to every handler
  that could emit a record closes that gap; see the README for the
  worked example.
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
                record.exc_text = masked["stack"]
            record.exc_info = None

        if record.stack_info:
            record.stack_info = self._mask(record.stack_info)

        for field in self._extra_fields:
            value = getattr(record, field, None)
            if isinstance(value, str):
                setattr(record, field, self._mask(value))

        return True
