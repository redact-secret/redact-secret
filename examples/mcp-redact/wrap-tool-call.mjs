/**
 * Server-side and client-side wrappers built on `redact-tool-call.mjs`.
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
 * to the same `CallToolResult` shape. Neither surface changed in a way that
 * affects this file between 1.x releases checked during that work.
 *
 * Real wiring:
 *
 * ```js
 * import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 * import { initialize, scanAndRedact } from "@redact-secret/core";
 * import { wrapServerToolHandler } from "./wrap-tool-call.mjs";
 *
 * await initialize();
 * const server = new McpServer({ name: "example", version: "1.0.0" });
 * server.registerTool(
 *   "read_file",
 *   { inputSchema: { path: z.string() } },
 *   wrapServerToolHandler(readFileHandler, scanAndRedact, { onFinding: audit }),
 * );
 * ```
 *
 * ```js
 * import { Client } from "@modelcontextprotocol/sdk/client/index.js";
 * import { initialize, scanAndRedact } from "@redact-secret/core";
 * import { wrapClientCallTool } from "./wrap-tool-call.mjs";
 *
 * await initialize();
 * const callTool = wrapClientCallTool(client.callTool.bind(client), scanAndRedact, { onFinding: audit });
 * const result = await callTool({ name: "read_file", arguments: { path: "/tmp/x" } });
 * ```
 */

import { buildBlockedResult, redactArguments, redactToolResult } from "./redact-tool-call.mjs";

/** Reported for every finding, including on a blocked outcome, as exactly
 * the safe metadata `scanAndRedact` already returns — never the input or a
 * matched value. A throwing `onFinding` is swallowed and never influences
 * the redaction outcome. Exported so `agent-context.mjs` shares this one
 * implementation instead of a second copy in the same directory. */
export function emitFindings(findings, onFinding, scope) {
  if (typeof onFinding !== "function") return;
  for (const finding of findings) {
    try {
      onFinding(finding, { scope });
    } catch {
      // The audit callback is best-effort: it never influences the
      // redaction outcome, so a throwing callback is swallowed rather than
      // failing (or, worse, un-blocking) the call.
    }
  }
}

/**
 * Wraps a server-side tool handler. Arguments are redacted first — and, on
 * a `block` finding there, the handler is never called, so a blocked secret
 * never reaches the tool implementation — then the handler's result is
 * redacted before it is returned to the client. `options.redactArguments`
 * defaults to `false`: most tools need the real argument value to function
 * (an API key they must actually send), so argument redaction is opt-in per
 * tool, as the issue's false-positive/negative section documents.
 *
 * @param {(args: object, extra: unknown) => unknown | Promise<unknown>} handler
 * @param {Function} scanAndRedact
 * @param {{ policy?: unknown, limits?: object, redactArguments?: boolean, onFinding?: (finding: object, context: { scope: "argument" | "result" }) => void }} [options]
 */
export function wrapServerToolHandler(handler, scanAndRedact, options = {}) {
  if (typeof handler !== "function") {
    throw new TypeError("wrapServerToolHandler: handler must be a function");
  }
  return async function redactingToolHandler(args, extra) {
    let effectiveArgs = args;
    if (options.redactArguments) {
      const argOutcome = redactArguments(scanAndRedact, args, options);
      emitFindings(argOutcome.findings, options.onFinding, "argument");
      if (argOutcome.outcome === "blocked") return buildBlockedResult();
      effectiveArgs = argOutcome.arguments;
    }

    const raw = await handler(effectiveArgs, extra);
    const resultOutcome = redactToolResult(scanAndRedact, raw, options);
    emitFindings(resultOutcome.findings, options.onFinding, "result");
    if (resultOutcome.outcome === "blocked") return buildBlockedResult();
    return resultOutcome.result;
  };
}

/**
 * Wraps a client-side `callTool`. Only the result is redacted — arguments
 * are already being sent to the server at this point — before it enters
 * model context, matching the issue's client-side scope.
 *
 * @param {(...args: unknown[]) => unknown | Promise<unknown>} callTool
 * @param {Function} scanAndRedact
 * @param {{ policy?: unknown, limits?: object, onFinding?: (finding: object, context: { scope: "result" }) => void }} [options]
 */
export function wrapClientCallTool(callTool, scanAndRedact, options = {}) {
  if (typeof callTool !== "function") {
    throw new TypeError("wrapClientCallTool: callTool must be a function");
  }
  return async function redactingCallTool(...args) {
    const raw = await callTool(...args);
    const resultOutcome = redactToolResult(scanAndRedact, raw, options);
    emitFindings(resultOutcome.findings, options.onFinding, "result");
    if (resultOutcome.outcome === "blocked") return buildBlockedResult();
    return resultOutcome.result;
  };
}
