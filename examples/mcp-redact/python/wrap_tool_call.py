"""Server-side and client-side wrappers built on ``redact_tool_call.py``.

Both wrap a plain async callable matching the official Python MCP SDK's
structural shapes, verified while resolving issue #327 against ``mcp==2.2.0``
(``mcp.server.lowlevel.Server``'s ``on_call_tool`` constructor callback,
``mcp/server/lowlevel/server.py``: ``Callable[[ctx, CallToolRequestParams],
Awaitable[CallToolResult]]``; ``mcp.client.session.ClientSession.call_tool``,
``mcp/client/session.py``: ``(name, arguments) -> CallToolResult``) without
importing ``mcp`` itself -- ``CallToolResult`` is a plain dict tree here, the
same duck-typed choice
``examples/tracing-masking/python/redact_span_attributes.py`` makes for
OpenTelemetry's ``SpanProcessor``.

Real wiring:

.. code-block:: python

    import redact_secret
    from mcp.server.lowlevel import Server
    from wrap_tool_call import wrap_server_tool_handler

    async def read_file(ctx, params):
        ...  # returns a CallToolResult-shaped dict

    server = Server(
        "example",
        on_call_tool=wrap_server_tool_handler(
            read_file, redact_secret.scan_and_redact, on_finding=audit,
        ),
    )

.. code-block:: python

    import redact_secret
    from wrap_tool_call import wrap_client_call_tool

    call_tool = wrap_client_call_tool(session.call_tool, redact_secret.scan_and_redact, on_finding=audit)
    result = await call_tool("read_file", {"path": "/tmp/x"})
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from redact_tool_call import build_blocked_result, redact_arguments, redact_tool_result

__all__ = ["emit_findings", "wrap_server_tool_handler", "wrap_client_call_tool"]


def _get_arguments(params: Any) -> dict[str, Any]:
    """Reads `.arguments` from either a plain dict (used by this module's
    own tests) or a pydantic `CallToolRequestParams` (the real SDK)."""
    if isinstance(params, dict):
        return params.get("arguments") or {}
    return getattr(params, "arguments", None) or {}


def _with_arguments(params: Any, arguments: dict[str, Any]) -> Any:
    if isinstance(params, dict):
        return {**params, "arguments": arguments}
    return params.model_copy(update={"arguments": arguments})


def _as_dict(value: Any) -> dict[str, Any]:
    """Normalizes either a plain dict or a pydantic `CallToolResult` to a
    plain dict tree, the shape `redact_tool_result` operates on."""
    if isinstance(value, dict):
        return value
    return value.model_dump(by_alias=True)


def emit_findings(findings: list[Any], on_finding: Optional[Callable[..., None]], scope: str) -> None:
    """Reported for every finding, including on a blocked outcome, as
    exactly the safe metadata ``scan_and_redact`` already returns -- never
    the input or a matched value. A raising ``on_finding`` is swallowed and
    never influences the redaction outcome. Not underscore-prefixed:
    ``agent_context.py`` imports it rather than keeping a second copy in
    this same directory."""
    if on_finding is None:
        return
    for finding in findings:
        try:
            on_finding(finding, scope=scope)
        except Exception:
            # The audit callback is best-effort: it never influences the
            # redaction outcome, so a raising callback is swallowed rather
            # than failing (or, worse, un-blocking) the call.
            pass


def wrap_server_tool_handler(
    handler: Callable[..., Any],
    scan_and_redact: Callable[..., Any],
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
    redact_arguments_before_forwarding: bool = False,
    on_finding: Optional[Callable[..., None]] = None,
):
    """Wraps a server-side ``on_call_tool``-shaped handler,
    ``async def handler(ctx, params) -> CallToolResult`` where
    ``params.arguments`` is the tool's argument dict.

    Arguments are redacted first -- and, on a ``block`` finding there, the
    handler is never called, so a blocked secret never reaches the tool
    implementation -- then the handler's result is redacted before it is
    returned to the client. ``redact_arguments_before_forwarding`` defaults
    to ``False``: most tools need the real argument value to function (an
    API key they must actually send), so argument redaction is opt-in per
    tool, as the issue's false-positive/negative section documents.
    """
    if not callable(handler):
        raise TypeError("wrap_server_tool_handler: handler must be callable")

    async def redacting_tool_handler(ctx: Any, params: Any) -> Any:
        effective_params = params
        if redact_arguments_before_forwarding:
            args = _get_arguments(params)
            arg_outcome = redact_arguments(scan_and_redact, args, policy=policy, limits=limits)
            emit_findings(arg_outcome["findings"], on_finding, "argument")
            if arg_outcome["outcome"] == "blocked":
                return build_blocked_result()
            effective_params = _with_arguments(params, arg_outcome["arguments"])

        raw = await handler(ctx, effective_params)
        result_outcome = redact_tool_result(scan_and_redact, _as_dict(raw), policy=policy, limits=limits)
        emit_findings(result_outcome["findings"], on_finding, "result")
        if result_outcome["outcome"] == "blocked":
            return build_blocked_result()
        return result_outcome["result"]

    return redacting_tool_handler


def wrap_client_call_tool(
    call_tool: Callable[..., Any],
    scan_and_redact: Callable[..., Any],
    *,
    policy: Optional[Any] = None,
    limits: Optional[dict[str, int]] = None,
    on_finding: Optional[Callable[..., None]] = None,
):
    """Wraps a client-side ``call_tool``. Only the result is redacted --
    arguments are already being sent to the server at this point -- before
    it enters model context, matching the issue's client-side scope.
    """
    if not callable(call_tool):
        raise TypeError("wrap_client_call_tool: call_tool must be callable")

    async def redacting_call_tool(*args: Any, **kwargs: Any) -> Any:
        raw = await call_tool(*args, **kwargs)
        result_outcome = redact_tool_result(scan_and_redact, _as_dict(raw), policy=policy, limits=limits)
        emit_findings(result_outcome["findings"], on_finding, "result")
        if result_outcome["outcome"] == "blocked":
            return build_blocked_result()
        return result_outcome["result"]

    return redacting_call_tool
