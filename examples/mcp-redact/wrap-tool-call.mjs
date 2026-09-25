/**
 * Server-side and client-side wrappers over one AI-context boundary, through
 * `@redact-secret/adapter-mcp` (the MCP boundary contract,
 * `docs/reference/mcp-boundary.md`, #612).
 *
 * Both wrap a plain function matching an MCP TypeScript SDK's structural
 * shapes, without importing an SDK. The adapter is tested with real SDK
 * instances of both supported lines (`@modelcontextprotocol/sdk`
 * `>=1.13.0 <=1.30.1`, `@modelcontextprotocol/client` and `/server`
 * `>=2.0.0 <=2.1.0`) over stdio and Streamable HTTP.
 *
 * Real wiring (`EXAMPLE_LIMITS` is in `agent-context.mjs`; limits are
 * mandatory and explicit):
 *
 * ```js
 * import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 * import { createAiContextBoundary } from "@redact-secret/adapter-ai-context";
 * import { EXAMPLE_LIMITS } from "./agent-context.mjs";
 * import { wrapServerToolHandler } from "./wrap-tool-call.mjs";
 *
 * const boundary = await createAiContextBoundary({ ...EXAMPLE_LIMITS, onFinding: audit });
 * const server = new McpServer({ name: "example", version: "1.0.0" });
 * server.registerTool(
 *   "read_file",
 *   { inputSchema: { path: z.string() } },
 *   wrapServerToolHandler(readFileHandler, boundary),
 * );
 * ```
 *
 * ```js
 * import { Client } from "@modelcontextprotocol/sdk/client/index.js";
 * import { createAiContextBoundary } from "@redact-secret/adapter-ai-context";
 * import { EXAMPLE_LIMITS } from "./agent-context.mjs";
 * import { wrapClientCallTool } from "./wrap-tool-call.mjs";
 *
 * const boundary = await createAiContextBoundary({ ...EXAMPLE_LIMITS, onFinding: audit });
 * const callTool = wrapClientCallTool((params, { signal }) => client.callTool(params, undefined, { signal }), boundary);
 * const result = await callTool({ name: "read_file", arguments: { path: "/tmp/x" } });
 * ```
 *
 * The client side is the authoritative placement: the host applies the
 * boundary to every result it receives, including `isError: true` results,
 * before logging, persistence, or model context. A server-side wrapper is
 * preventive.
 *
 * Audit telemetry is the boundary's `onFinding(finding, { boundary })`,
 * called once per finding with the allowlisted safe metadata, labelled
 * `tool-result` or `tool-arguments`. A throwing callback is swallowed and
 * never changes an outcome.
 */

import { toCallToolResult } from "@redact-secret/adapter-mcp";

import { mcpBoundaryFor } from "./redact-tool-call.mjs";

function requireFunction(value, caller, name) {
  if (typeof value !== "function") throw new TypeError(`${caller}: ${name} must be a function`);
}

/**
 * Wraps a server-side tool handler with the adapter's `wrapToolHandler`.
 * With `redactArguments`, arguments are sanitized first and, on any non-`ok`
 * outcome, the handler is never called. The handler's result is sanitized
 * before it is returned. A handler that throws becomes the fixed tool-error
 * result, so the SDK never turns its `error.message` into result text.
 * Both steps use the request's signal (`extra.signal` on SDK 1.x,
 * `ctx.mcpReq.signal` on 2.x). `redactArguments` defaults to `false`: most
 * tools need the real argument value to function (an API key they must
 * actually send), so argument redaction is opt-in per tool.
 *
 * @param {(args: object, extra: unknown) => unknown | Promise<unknown>} handler
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {{ redactArguments?: boolean, binaryContent?: "block" | "pass" }} [options]
 */
export function wrapServerToolHandler(handler, boundary, options = {}) {
  requireFunction(handler, "wrapServerToolHandler", "handler");
  return mcpBoundaryFor(boundary, { binaryContent: options.binaryContent }).wrapToolHandler(handler, {
    sanitizeArguments: options.redactArguments === true,
  });
}

/**
 * Wraps a client-side `callTool` with the adapter's `sanitizeToolCall`. The
 * result is sanitized before it enters model context. A rejected call (an
 * `McpError` or a transport error) becomes the fixed tool-error result, its
 * message never read. A cancelled call resolves to `null`: nothing is
 * delivered.
 *
 * @param {(params: unknown, options: { signal?: AbortSignal }) => unknown | Promise<unknown>} callTool
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {{ binaryContent?: "block" | "pass" }} [options]
 */
export function wrapClientCallTool(callTool, boundary, options = {}) {
  requireFunction(callTool, "wrapClientCallTool", "callTool");
  const mcp = mcpBoundaryFor(boundary, { binaryContent: options.binaryContent });
  return async function redactingCallTool(params, { signal } = {}) {
    const outcome = await mcp.sanitizeToolCall((context) => callTool(params, { signal: context.signal }), { signal });
    return toCallToolResult(outcome);
  };
}
