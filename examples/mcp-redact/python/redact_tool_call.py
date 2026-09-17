"""The pure redaction core for MCP tool calls (issue #327): given an
injected ``scan_and_redact``, redacts a ``CallToolResult``'s content blocks
/ structured content, or a tool call's argument dict, and maps the outcome
onto the issue's policy contract:

- ``redact`` findings: the span is replaced, the call continues.
- ``warn`` findings: the text passes through unchanged; still reported.
- ``block`` findings, or a ``scan_and_redact`` failure: the *whole* call
  becomes a fixed, input-free block outcome -- never a partial or per-leaf
  marker. This differs from ``examples/tracing-masking``'s per-leaf
  ``BLOCK_MARKER``: MCP already has a first-class "tool error" outcome
  (``CallToolResult.is_error``), so blocking maps onto that instead of a
  leaf-level placeholder.

No ``mcp``/``fastmcp`` import: ``CallToolResult`` and its content blocks are
a structural (duck-typed) shape here -- a plain dict tree -- the same choice
``examples/tracing-masking/python/redact_span_attributes.py`` makes for
OpenTelemetry's ``SpanProcessor``. This file is testable without the built
native extension or an MCP SDK installed.

Mirrors ``../redact-tool-call.mjs`` field for field; see that file's
docstring for the design rationale.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

__all__ = [
    "DEFAULT_LIMITS",
    "BLOCKED_MESSAGE",
    "LIMIT_MARKER",
    "CYCLE_MARKER",
    "build_blocked_result",
    "redact_arguments",
    "redact_tool_result",
]

# Bounds enforced while walking arguments and JSON-in-text content. Beyond
# these, a subtree is marked with LIMIT_MARKER and dropped rather than
# passed through unmasked -- the call itself is not blocked, since these are
# complexity guards, not secret-detection outcomes.
DEFAULT_LIMITS: dict[str, int] = {
    "max_depth": 8,
    "max_array_length": 1000,
    "max_object_keys": 200,
    "max_string_length": 200_000,
    "max_total_leaves": 5000,
    "max_content_blocks": 200,
}

# Fixed, input-free text for every blocked outcome. Never carries the input,
# a matched value, or the underlying error's own message.
BLOCKED_MESSAGE = (
    "This MCP tool call was blocked by secret-redaction policy. "
    "No content, arguments, or error detail is included."
)

LIMIT_MARKER = "[REDACTED:LIMIT_EXCEEDED]"
CYCLE_MARKER = "[REDACTED:CYCLE]"


def _is_plain_dict(value: Any) -> bool:
    return type(value) is dict


def _is_plain_list(value: Any) -> bool:
    return type(value) is list


class _Context:
    __slots__ = ("policy", "limits", "budget", "blocked", "block_reason", "findings")

    def __init__(self, policy: Any, limits: dict[str, int]) -> None:
        self.policy = policy
        self.limits = limits
        self.budget = {"leaves": limits["max_total_leaves"]}
        self.blocked = False
        self.block_reason: Optional[str] = None
        self.findings: list[Any] = []


def _make_context(scan_and_redact: Callable[..., Any], policy: Any, limits: Optional[dict[str, int]]) -> _Context:
    if not callable(scan_and_redact):
        raise TypeError("scan_and_redact must be callable")
    merged_limits = {**DEFAULT_LIMITS, **(limits or {})}
    return _Context(policy, merged_limits)


def _redact_leaf(scan_and_redact: Callable[..., Any], text: str, ctx: _Context) -> str:
    if len(text) > ctx.limits["max_string_length"]:
        return LIMIT_MARKER
    if ctx.budget["leaves"] <= 0:
        return LIMIT_MARKER
    ctx.budget["leaves"] -= 1

    try:
        result = scan_and_redact(text, policy=ctx.policy)
    except Exception:
        ctx.blocked = True
        ctx.block_reason = "core_error"
        return ""

    ctx.findings.extend(result.findings)
    if any(finding.action == "block" for finding in result.findings):
        ctx.blocked = True
        ctx.block_reason = "policy"
        return ""
    return result.text


def _redact_json_value(scan_and_redact: Callable[..., Any], value: Any, ctx: _Context, depth: int, seen: set) -> Any:
    if ctx.blocked:
        return value

    if isinstance(value, str):
        return _redact_leaf(scan_and_redact, value, ctx)

    if _is_plain_list(value):
        if depth >= ctx.limits["max_depth"]:
            return LIMIT_MARKER
        if id(value) in seen:
            return CYCLE_MARKER
        seen.add(id(value))
        try:
            bounded = value[: ctx.limits["max_array_length"]]
            return [_redact_json_value(scan_and_redact, item, ctx, depth + 1, seen) for item in bounded]
        finally:
            seen.discard(id(value))

    if _is_plain_dict(value):
        if depth >= ctx.limits["max_depth"]:
            return LIMIT_MARKER
        if id(value) in seen:
            return CYCLE_MARKER
        seen.add(id(value))
        try:
            keys = list(value.keys())[: ctx.limits["max_object_keys"]]
            return {key: _redact_json_value(scan_and_redact, value[key], ctx, depth + 1, seen) for key in keys}
        finally:
            seen.discard(id(value))

    # Numbers, booleans, None, and non-plain objects are left unchanged:
    # only plain dicts, lists, and strings are walked.
    return value


def _redact_text_or_json(scan_and_redact: Callable[..., Any], text: str, ctx: _Context) -> str:
    """Redacts one piece of text that may be a JSON-serialized object/array
    (an MCP "JSON-in-text" result). When it parses as a JSON object or
    array, every string leaf inside is redacted and the value is
    re-serialized with JS-compatible compact separators (``","``/``":"``,
    no spaces) so JS and Python produce byte-identical output. Anything
    else is scanned as opaque text.
    """
    if ctx.blocked:
        return text
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None

    if _is_plain_list(parsed) or _is_plain_dict(parsed):
        redacted = _redact_json_value(scan_and_redact, parsed, ctx, 0, set())
        if ctx.blocked:
            return ""
        return json.dumps(redacted, separators=(",", ":"))
    return _redact_leaf(scan_and_redact, text, ctx)


def _redact_content_block(scan_and_redact: Callable[..., Any], block: Any, ctx: _Context) -> Any:
    if ctx.blocked:
        return block
    if not _is_plain_dict(block):
        return block

    if block.get("type") == "text" and isinstance(block.get("text"), str):
        return {**block, "text": _redact_text_or_json(scan_and_redact, block["text"], ctx)}

    # An embedded text resource (`{"type": "resource", "resource": {"text": ...}}`)
    # carries scannable text; a blob resource (`resource.blob`) is base64
    # binary and, like `image`/`audio`/`resource_link` blocks, passes
    # through unchanged -- the documented non-text false-negative boundary.
    resource = block.get("resource")
    if block.get("type") == "resource" and _is_plain_dict(resource) and isinstance(resource.get("text"), str):
        return {
            **block,
            "resource": {**resource, "text": _redact_text_or_json(scan_and_redact, resource["text"], ctx)},
        }

    return block


def build_blocked_result() -> dict[str, Any]:
    """The fixed ``CallToolResult``-shaped tool error every blocked outcome
    maps to: no content, no arguments, no error detail beyond the fixed
    message."""
    return {"content": [{"type": "text", "text": BLOCKED_MESSAGE}], "isError": True}


def redact_arguments(
    scan_and_redact: Callable[..., Any],
    args: dict[str, Any],
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
) -> dict[str, Any]:
    """Redacts a tool call's argument dict. Returns ``{"outcome": "blocked",
    ...}`` -- with no ``"arguments"`` key -- when any argument value
    contains a ``block`` finding or ``scan_and_redact`` fails; the caller
    must not forward the original arguments to the tool in that case.
    """
    ctx = _make_context(scan_and_redact, policy, limits)
    if not _is_plain_dict(args):
        raise TypeError("redact_arguments: args must be a plain dict")
    redacted = _redact_json_value(scan_and_redact, args, ctx, 0, set())
    if ctx.blocked:
        return {"outcome": "blocked", "blockReason": ctx.block_reason, "findings": ctx.findings}
    return {"outcome": "ok", "arguments": redacted, "findings": ctx.findings}


def redact_tool_result(
    scan_and_redact: Callable[..., Any],
    result: dict[str, Any],
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
) -> dict[str, Any]:
    """Redacts a ``CallToolResult``'s ``content`` blocks and
    ``structuredContent`` before it reaches the client or model context.
    Returns ``{"outcome": "blocked", ...}`` -- with no ``"result"`` key --
    on any ``block`` finding or core failure; the caller must return
    ``build_blocked_result()`` instead of the original result in that case.
    """
    ctx = _make_context(scan_and_redact, policy, limits)
    if not _is_plain_dict(result):
        raise TypeError("redact_tool_result: result must be a plain dict")

    content_in = result.get("content") if _is_plain_list(result.get("content")) else []
    bounded = content_in[: ctx.limits["max_content_blocks"]]
    content = [_redact_content_block(scan_and_redact, block, ctx) for block in bounded]

    has_structured_content = "structuredContent" in result
    structured_content = result.get("structuredContent")
    if not ctx.blocked and _is_plain_dict(structured_content):
        structured_content = _redact_json_value(scan_and_redact, structured_content, ctx, 0, set())

    if ctx.blocked:
        return {"outcome": "blocked", "blockReason": ctx.block_reason, "findings": ctx.findings}

    out = {**result, "content": content}
    if has_structured_content:
        out["structuredContent"] = structured_content
    return {"outcome": "ok", "result": out, "findings": ctx.findings}
