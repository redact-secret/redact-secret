"""A deterministic stand-in for ``redact_secret.IncrementalSanitizer``,
shaped like it (``append``/``finalize``/``abort``) but with maximal
buffering: ``append`` always returns an empty result and buffers the chunk
internally; ``finalize`` runs ``fake_scan_and_redact`` once over the whole
buffered input. See ``../fixtures/fake-incremental-sanitizer.mjs`` for the
full rationale; both are kept in sync by hand.

``limits["max_buffered_bytes"]`` is enforced: once the buffered length would
exceed it, ``append`` raises a limit-shaped error, matching the real
session's fail-closed ``BufferLimitExceededError``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fake_scanner import fake_scan_and_redact

__all__ = ["create_fake_incremental_sanitizer"]


class _BufferLimitExceededError(Exception):
    pass


@dataclass
class _EmptyResult:
    text: str = ""
    findings: list = field(default_factory=list)


class _FakeIncrementalSanitizer:
    def __init__(self, limits: dict[str, int]) -> None:
        self.limits = limits
        self.buffer = ""
        self.state = "accepting"

    def append(self, chunk: str) -> Any:
        if self.state != "accepting":
            raise RuntimeError(f'fake session: append() called in state "{self.state}"')
        if len(self.buffer) + len(chunk) > self.limits["max_buffered_bytes"]:
            self.state = "failed"
            raise _BufferLimitExceededError("simulated buffer limit exceeded")
        self.buffer += chunk
        return _EmptyResult()

    def finalize(self) -> Any:
        if self.state != "accepting":
            raise RuntimeError(f'fake session: finalize() called in state "{self.state}"')
        self.state = "finalized"
        return fake_scan_and_redact(self.buffer)

    def abort(self) -> None:
        self.state = "aborted"


def create_fake_incremental_sanitizer(limits: dict[str, int], _policy: Any = None) -> _FakeIncrementalSanitizer:
    return _FakeIncrementalSanitizer(limits)
