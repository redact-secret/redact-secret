"""The AI-context golden path (issue #587): where authoritative redaction
belongs across a whole agent turn, not just inside one MCP tool call.
Composes ``redact_tool_call.py``'s primitives into the flow the issue
requires::

    user input -> scan -> application policy
    tool result -> scan -> context construction
    safe context -> model

``user_input`` is scanned first. A ``block`` finding there ends the call
before a tool is ever dispatched, before anything is logged, and before
``context`` is built -- ``user_input`` itself never appears in this
module's return value on any path. When ``build_tool_request`` is
supplied, it is called with the *sanitized* input text, never the raw
``user_input``, so a tool argument derived from what the user typed is
dispatched from already-scanned text. The tool's result is then scanned
the same way ``wrap_client_call_tool`` does, before either piece is added
to ``context["messages"]`` -- the only value here that is safe to hand to
a model call or a log line.

No ``mcp``/``fastmcp`` import, matching ``redact_tool_call.py`` and
``wrap_tool_call.py``: ``call_tool`` is a plain, duck-typed async
callable. There is no Python equivalent of the DOM's ``AbortSignal``, so
cancellation here is a duck-typed ``cancel_event`` -- anything with an
``is_set()`` method, the interface both ``threading.Event`` and
``asyncio.Event`` already share -- checked the same way
``../agent-context.mjs`` checks ``signal.aborted``.

Mirrors ``../agent-context.mjs`` field for field; see that file's
docstring for the design rationale.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from redact_tool_call import redact_tool_result
from wrap_tool_call import emit_findings

__all__ = ["DEFAULT_INPUT_LIMITS", "redact_user_input", "build_safe_context"]

# ``max_input_length`` mirrors ``DEFAULT_LIMITS["max_string_length"]`` in
# ``redact_tool_call.py``, applied to the whole user turn up front --
# before ``scan_and_redact`` is ever called -- rather than relying on the
# per-leaf ``LIMIT_MARKER`` a huge tool-result leaf would fall back on.
DEFAULT_INPUT_LIMITS: dict[str, int] = {"max_input_length": 200_000}


def _is_cancelled(cancel_event: Optional[Any]) -> bool:
    return cancel_event is not None and cancel_event.is_set()


def _aborted(findings: list[Any]) -> dict[str, Any]:
    return {"outcome": "aborted", "findings": findings}


def redact_user_input(
    scan_and_redact: Callable[..., Any],
    text: str,
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
) -> dict[str, Any]:
    """Scans one plain-text user turn and maps the outcome onto the
    issue's ``redact``/``warn``/``block``/allow contract. Oversized input
    is rejected by length alone, before ``scan_and_redact`` sees any of it
    -- no retained plaintext for that path, by construction.
    """
    if not callable(scan_and_redact):
        raise TypeError("redact_user_input: scan_and_redact must be callable")
    if not isinstance(text, str):
        raise TypeError("redact_user_input: text must be a str")

    max_input_length = (limits or {}).get("max_input_length", DEFAULT_INPUT_LIMITS["max_input_length"])
    if len(text) > max_input_length:
        return {"outcome": "blocked", "blockReason": "input_too_large", "findings": []}

    try:
        result = scan_and_redact(text, policy=policy)
    except Exception:
        # Covers every core failure the same way, including calling this
        # before the extension is loaded/initialized -- it fails closed
        # exactly like any other scanner error rather than needing its own
        # branch.
        return {"outcome": "blocked", "blockReason": "core_error", "findings": []}

    if any(finding.action == "block" for finding in result.findings):
        return {"outcome": "blocked", "blockReason": "policy", "findings": result.findings}
    return {"outcome": "ok", "text": result.text, "findings": result.findings}


async def build_safe_context(
    *,
    scan_and_redact: Callable[..., Any],
    user_input: str,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
    on_finding: Optional[Callable[..., None]] = None,
    call_tool: Optional[Callable[..., Any]] = None,
    build_tool_request: Optional[Any] = None,
    cancel_event: Optional[Any] = None,
) -> dict[str, Any]:
    """Runs one full agent turn through the required flow and returns the
    safe context to hand to the model, or a blocked/aborted outcome with
    no ``"context"`` key at all.

    ``cancel_event`` is checked before scanning starts, before the tool is
    dispatched, and again before the tool result is folded into context --
    covering both cancellation (already set before this call began) and
    abort (the event is set while the tool call is in flight). Either way
    the return is ``{"outcome": "aborted", ...}``: whatever was scanned so
    far is discarded along with everything unscanned, and the caller must
    not reuse a prior ``context``.
    """
    if _is_cancelled(cancel_event):
        return _aborted([])

    input_outcome = redact_user_input(scan_and_redact, user_input, policy=policy, limits=limits)
    emit_findings(input_outcome["findings"], on_finding, "input")
    if input_outcome["outcome"] == "blocked":
        return {
            "outcome": "blocked",
            "stage": "input",
            "blockReason": input_outcome["blockReason"],
            "findings": input_outcome["findings"],
        }

    findings: list[Any] = list(input_outcome["findings"])
    messages: list[Any] = [{"role": "user", "content": input_outcome["text"]}]

    if call_tool is not None:
        if _is_cancelled(cancel_event):
            return _aborted(findings)

        request = build_tool_request(input_outcome["text"]) if callable(build_tool_request) else build_tool_request
        try:
            raw = await call_tool(request, cancel_event=cancel_event)
        except Exception:
            # A raising or aborted call has no result to redact and nothing
            # new was ever captured -- `messages` (holding only the
            # already-sanitized input) is discarded along with this
            # return, since a blocked outcome carries no "context" key for
            # the caller to reuse.
            return {"outcome": "blocked", "stage": "tool", "blockReason": "tool_call_failed", "findings": findings}

        if _is_cancelled(cancel_event):
            return _aborted(findings)

        result_outcome = redact_tool_result(scan_and_redact, raw, policy=policy, limits=limits)
        emit_findings(result_outcome["findings"], on_finding, "result")
        findings.extend(result_outcome["findings"])
        if result_outcome["outcome"] == "blocked":
            return {
                "outcome": "blocked",
                "stage": "tool",
                "blockReason": result_outcome["blockReason"],
                "findings": findings,
            }
        messages.append({"role": "tool", "content": result_outcome["result"]})

    if _is_cancelled(cancel_event):
        return _aborted(findings)

    return {"outcome": "ok", "context": {"messages": messages}, "findings": findings}
