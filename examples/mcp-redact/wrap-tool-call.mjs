/**
 * Server-side and client-side wrappers built on `redact-tool-call.mjs`,
 * over one `@redact-secret/adapter-ai-context` boundary.
 *
 * Both wrap a plain function matching the MCP TypeScript SDK's structural
 * shapes — a tool handler (`ToolCallback`, `(args, extra) => CallToolResult`)
 * and a client call (`(params) => CallToolResult`) — without importing
 * `@modelcontextprotocol/sdk`. Verified while resolving issue #327 against
 * `@modelcontextprotocol/sdk@1.30.0`'s type declarations
 * (`server/mcp.d.ts`'s `ToolCallback`, `client/index.d.ts`'s `callTool`,
 * `types.d.ts`'s `CallToolResultSchema`): a tool handler receives
 * `(args: Record<string, unknown>, extra)` and returns a `CallToolResult`;
 * `Client#callTool` is called with `CallToolRequest['params']` and resolves
 * to the same `CallToolResult` shape.
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
 * const callTool = wrapClientCallTool(client.callTool.bind(client), boundary);
 * const result = await callTool({ name: "read_file", arguments: { path: "/tmp/x" } });
 * ```
 *
 * Audit telemetry is the boundary's `onFinding(finding, { boundary })`,
 * called once per finding with the allowlisted safe metadata, including for
 * a call that ends up blocked. A throwing callback is swallowed by the
 * boundary and never changes an outcome.
 */

import { buildBlockedResult, redactArguments, redactToolResult } from "./redact-tool-call.mjs";

function requireFunction(value, caller, name) {
  if (typeof value !== "function") throw new TypeError(`${caller}: ${name} must be a function`);
}

function requireBoundary(boundary, caller) {
  if (typeof boundary?.sanitizeValue !== "function") {
    throw new TypeError(`${caller}: boundary must be an @redact-secret/adapter-ai-context boundary`);
  }
}

/**
 * Wraps a server-side tool handler. With `redactArguments`, arguments are
 * sanitized first and, on any non-`ok` outcome, the handler is never
 * called, so a blocked secret never reaches the tool implementation. The
 * handler's result is then sanitized before it is returned. Both use the
 * request's `extra.signal`, so a cancelled request fails closed.
 * `redactArguments` defaults to `false`: most tools need the real argument
 * value to function (an API key they must actually send), so argument
 * redaction is opt-in per tool.
 *
 * @param {(args: object, extra: unknown) => unknown | Promise<unknown>} handler
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {{ redactArguments?: boolean, maxContentBlocks?: number }} [options]
 */
export function wrapServerToolHandler(handler, boundary, options = {}) {
  requireFunction(handler, "wrapServerToolHandler", "handler");
  requireBoundary(boundary, "wrapServerToolHandler");
  return async function redactingToolHandler(args, extra) {
    const signal = extra?.signal;
    let effectiveArgs = args;
    if (options.redactArguments) {
      const argOutcome = redactArguments(boundary, args, { signal });
      if (argOutcome.outcome !== "ok") return buildBlockedResult();
      effectiveArgs = argOutcome.value;
    }

    const raw = await handler(effectiveArgs, extra);
    const resultOutcome = redactToolResult(boundary, raw, { signal, maxContentBlocks: options.maxContentBlocks });
    return resultOutcome.outcome === "ok" ? resultOutcome.value : buildBlockedResult();
  };
}

/**
 * Wraps a client-side `callTool`. Only the result is sanitized (the
 * arguments are already on their way to the server) before it enters model
 * context.
 *
 * @param {(...args: unknown[]) => unknown | Promise<unknown>} callTool
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {{ maxContentBlocks?: number }} [options]
 */
export function wrapClientCallTool(callTool, boundary, options = {}) {
  requireFunction(callTool, "wrapClientCallTool", "callTool");
  requireBoundary(boundary, "wrapClientCallTool");
  return async function redactingCallTool(...args) {
    const raw = await callTool(...args);
    const resultOutcome = redactToolResult(boundary, raw, { maxContentBlocks: options.maxContentBlocks });
    return resultOutcome.outcome === "ok" ? resultOutcome.value : buildBlockedResult();
  };
}
