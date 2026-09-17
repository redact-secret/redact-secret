"""Redaction for a tool result assembled progressively -- a server tool
handler piping a subprocess, file, or HTTP response in chunks before
returning one ``CallToolResult`` -- built directly on
``redact_secret.IncrementalSanitizer``, the same bounded session the byte
stream adapters use. See ``../streaming-tool-result.mjs`` for the full
design rationale (why this targets the core's incremental sanitizer rather
than any MCP transport-level streaming); this file mirrors it field for
field.

``create_session`` is injected -- ``(limits, policy) ->
IncrementalSanitizer``-shaped ``{append, finalize, abort}`` -- so this file
is testable without the built native extension, using a fake session
(``fake_incremental_sanitizer.py``) instead of the real one.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

__all__ = ["create_streaming_tool_result_redactor"]


class _State:
    __slots__ = ("session", "blocked", "block_reason", "findings", "text", "finalized")

    def __init__(self, session: Any) -> None:
        self.session = session
        self.blocked = False
        self.block_reason: Optional[str] = None
        self.findings: list[Any] = []
        self.text = ""
        self.finalized = False


def _fail_closed(state: _State, reason: str) -> None:
    state.blocked = True
    state.block_reason = reason
    try:
        state.session.abort()
    except Exception:
        # abort() is cleanup on an already-failed session; a second failure
        # here does not change the outcome.
        pass


def _record(state: _State, result: Any) -> None:
    if any(finding.action == "block" for finding in result.findings):
        state.blocked = True
        state.block_reason = "policy"
    state.findings.extend(result.findings)
    state.text += result.text


class _StreamingToolResultRedactor:
    def __init__(self, state: _State) -> None:
        self._state = state

    def append(self, chunk: str) -> None:
        state = self._state
        if state.blocked or state.finalized:
            return
        try:
            _record(state, state.session.append(chunk))
        except Exception:
            _fail_closed(state, "limit_exceeded")

    def finalize(self) -> dict[str, Any]:
        state = self._state
        if state.finalized:
            raise RuntimeError("create_streaming_tool_result_redactor: finalize() already called")
        state.finalized = True
        if not state.blocked:
            try:
                _record(state, state.session.finalize())
            except Exception:
                _fail_closed(state, "limit_exceeded")

        if state.blocked:
            return {"outcome": "blocked", "blockReason": state.block_reason, "findings": state.findings}
        return {
            "outcome": "ok",
            "result": {"content": [{"type": "text", "text": state.text}]},
            "findings": state.findings,
        }


def create_streaming_tool_result_redactor(
    create_session: Callable[..., Any],
    *,
    limits: dict[str, int],
    policy: Optional[Any] = None,
) -> _StreamingToolResultRedactor:
    """Opens one streaming redaction session. ``limits`` is required --
    mirroring ``IncrementalLimits``, there is no default."""
    if not callable(create_session):
        raise TypeError("create_streaming_tool_result_redactor: create_session must be callable")
    if not limits:
        raise TypeError("create_streaming_tool_result_redactor: limits is required")
    session = create_session(limits, policy)
    return _StreamingToolResultRedactor(_State(session))
