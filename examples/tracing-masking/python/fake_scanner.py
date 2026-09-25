"""A deterministic stand-in for ``scan_and_redact``, shaped exactly like
the real ``ScanResult`` (``.text``, ``.findings``, each finding's
``.action``), keyed on magic substrings. The JavaScript side of this
directory now runs the released ``@redact-secret/adapter-otel`` and
``@redact-secret/adapter`` on the real core (``../smoke.mjs``), so this
fake and ``../fixtures/mask-secrets-cases.json`` serve the Python suite
only.

- text containing ``BOOM`` raises (a simulated core failure).
- text containing ``BLOCK_ME`` gets a ``block`` finding.
- text matching ``SECRET_TOKEN_\\d+`` gets one ``redact`` finding over
  that span.
- text containing ``WARN_ME`` gets a ``warn`` finding (core leaves
  ``warn`` text untouched).
- anything else has no findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class FakeFinding:
    action: str
    id: str = "finding-1"
    type: str = "generic_token"
    detector: str = "fake"
    confidence: str = "high"
    start: int = 0
    end: int = 0


@dataclass(frozen=True)
class FakeResult:
    text: str
    findings: list = field(default_factory=list)


_SECRET_TOKEN = re.compile(r"SECRET_TOKEN_\d+")


def fake_scan_and_redact(text: str, policy=None) -> FakeResult:
    if "BOOM" in text:
        raise RuntimeError("simulated core failure - must never surface to a caller")
    if "BLOCK_ME" in text:
        return FakeResult(text.replace("BLOCK_ME", "<SECRET_1>"), [FakeFinding("block")])
    match = _SECRET_TOKEN.search(text)
    if match:
        redacted = text[: match.start()] + "<SECRET_1>" + text[match.end():]
        return FakeResult(redacted, [FakeFinding("redact")])
    if "WARN_ME" in text:
        return FakeResult(text, [FakeFinding("warn", confidence="medium")])
    return FakeResult(text, [])
