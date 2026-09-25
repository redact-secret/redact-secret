"""The single primitive both logging integrations build on: mask one leaf
string with an injected ``scan_and_redact``, and never let a core failure
or a ``block`` finding put text on the wire.

Mirrors ``maskLeafWith`` in the released ``@redact-secret/adapter`` so
the two languages make the same decision given the same finding.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

BLOCK_MARKER = "[REDACTED:BLOCKED]"
ERROR_MARKER = "[REDACTED:ERROR]"
LIMIT_MARKER = "[REDACTED:LIMIT_EXCEEDED]"
CYCLE_MARKER = "[REDACTED:CYCLE]"

# Bounds enforced by mask_log_value.py. A field that exceeds
# max_string_length, or a value reached only after max_depth/
# max_array_length/max_object_keys/max_total_leaves is spent, never
# reaches the core: it becomes LIMIT_MARKER instead. Every log call pays
# the scan cost (see benchmark.py), so these bounds also cap per-call
# latency for a pathological extra mapping.
DEFAULT_LIMITS: dict[str, int] = {
    "max_depth": 8,
    "max_array_length": 1000,
    "max_object_keys": 200,
    "max_string_length": 200_000,
    "max_total_leaves": 5000,
}


def mask_leaf_with(
    scan_and_redact: Callable[..., Any],
    text: str,
    *,
    policy: Optional[Any] = None,
    max_string_length: Optional[int] = None,
) -> str:
    """Masks one leaf string.

    Any exception the core raises (``redact_secret.SecretScanError`` and
    its subclasses, or anything else a misbehaving ``policy`` raises)
    fails closed: the leaf becomes ``ERROR_MARKER``, never the original
    text and never the exception's own message. A ``block`` finding
    replaces the entire leaf with ``BLOCK_MARKER`` -- matching the issue's
    "block findings replace the whole message with a fixed marker": for a
    plain string log call the leaf *is* the message, and for a formatted
    field or an ``exc_text`` the leaf is that field's whole text.
    """
    if not isinstance(text, str):
        raise TypeError("mask_leaf_with: text must be a str")

    limit = max_string_length if max_string_length is not None else DEFAULT_LIMITS["max_string_length"]
    if len(text) > limit:
        return LIMIT_MARKER

    try:
        result = scan_and_redact(text, policy)
    except Exception:
        return ERROR_MARKER

    if any(finding.action == "block" for finding in result.findings):
        return BLOCK_MARKER
    return result.text
