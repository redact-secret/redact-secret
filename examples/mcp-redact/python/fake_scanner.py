"""A deterministic stand-in for ``scan_and_redact``, shaped exactly like the
real ``ScanResult`` (``.text``, ``.findings``, each finding's ``.action``).
Self-contained rather than imported from
``examples/tracing-masking/python/fake_scanner.py`` -- each example
directory stands on its own -- but implements the same four rules, by
convention, so a reader who has seen one recognizes the other:

- text containing ``BOOM`` raises (a simulated core failure).
- text containing ``BLOCK_ME`` gets a ``block`` finding.
- text matching ``SECRET_TOKEN_\\d+`` gets one ``redact`` finding over that
  span.
- text containing ``WARN_ME`` gets a ``warn`` finding (left untouched).
- anything else has no findings.

Kept in sync by hand with ``../fixtures/fake-scanner.mjs``; both implement
the same four rules so ``../fixtures/mcp-redact-cases.json`` means the same
thing in either language.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = ["fake_scan_and_redact"]

_SECRET_TOKEN_RE = re.compile(r"SECRET_TOKEN_\d+")


@dataclass
class _Finding:
    id: str
    type: str
    detector: str
    confidence: str
    action: str
    start: int
    end: int


@dataclass
class _ScanResult:
    text: str
    findings: list[Any]


def _finding(action: str) -> _Finding:
    return _Finding(
        id="finding-1",
        type="generic_token",
        detector="fake",
        confidence="medium" if action == "warn" else "high",
        action=action,
        start=0,
        end=0,
    )


def fake_scan_and_redact(text: str, **_kwargs: Any) -> _ScanResult:
    if "BOOM" in text:
        raise RuntimeError("simulated core failure - must never surface to a caller")
    if "BLOCK_ME" in text:
        return _ScanResult(text=text.replace("BLOCK_ME", "<SECRET_1>"), findings=[_finding("block")])
    match = _SECRET_TOKEN_RE.search(text)
    if match:
        redacted = text[: match.start()] + "<SECRET_1>" + text[match.end() :]
        return _ScanResult(text=redacted, findings=[_finding("redact")])
    if "WARN_ME" in text:
        return _ScanResult(text=text, findings=[_finding("warn")])
    return _ScanResult(text=text, findings=[])
