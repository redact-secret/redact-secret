/**
 * MCP tool calls through the supported MCP boundary
 * (`docs/reference/mcp-boundary.md`, #612), as implemented by
 * `@redact-secret/adapter-mcp` (redact-secret-adapters#13) over the
 * AI-context boundary (`@redact-secret/adapter-ai-context`, #610).
 *
 * Every function here takes the host's AI-context boundary (its limits, its
 * policy, its `onFinding`) and returns the MCP boundary's own outcome:
 *
 * - `{ outcome: "ok", value, findings }`: `value` is the only safe thing to
 *   log, store, or place into model context.
 * - `{ outcome: "blocked", reason, code? }`: nothing derived from input. The
 *   caller returns {@link buildBlockedResult}, the contract's fixed
 *   `isError: true` result, instead.
 * - `{ outcome: "aborted" }`: the signal fired. Nothing is delivered.
 *
 * This file adds nothing to the adapter: no scan, no traversal, no block
 * type rule. The whole `CallToolResult` (text, `structuredContent`, `_meta`,
 * resources, resource links, unknown fields) is one bounded value, text is
 * scanned as text, binary payloads block unless the host opts in with
 * `binaryContent: "pass"`, and the key-context check runs after the leaf
 * pass. Those are the contract's rules, and the adapter implements them.
 *
 * No `@modelcontextprotocol/sdk` import: `CallToolResult` is a structural
 * shape here, as it is in the adapter.
 */

import { createMcpBoundaryWith, MCP_BLOCKED_TEXT, mcpBlockedResult } from "@redact-secret/adapter-mcp";

/** The contract's fixed, input-free text for every blocked outcome. */
export const BLOCKED_MESSAGE = MCP_BLOCKED_TEXT;

const MCP_BOUNDARIES = { block: new WeakMap(), pass: new WeakMap() };

/**
 * The MCP boundary over a host's AI-context boundary, created once per
 * boundary and binary setting.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {{ binaryContent?: "block" | "pass" }} [options]
 * @returns {import("@redact-secret/adapter-mcp").McpBoundary}
 */
export function mcpBoundaryFor(boundary, { binaryContent = "block" } = {}) {
  if (boundary === null || typeof boundary !== "object") {
    throw new TypeError("mcpBoundaryFor: boundary must be an @redact-secret/adapter-ai-context boundary");
  }
  const cache = MCP_BOUNDARIES[binaryContent];
  if (cache === undefined) throw new TypeError('mcpBoundaryFor: binaryContent must be "block" or "pass"');
  let mcp = cache.get(boundary);
  if (mcp === undefined) {
    mcp = createMcpBoundaryWith(boundary, { binaryContent });
    cache.set(boundary, mcp);
  }
  return mcp;
}

/** The contract's fixed `isError: true` result for every blocked outcome. A new object on every call. */
export function buildBlockedResult() {
  return mcpBlockedResult();
}

/**
 * Opt-in: sanitizes a tool call's argument object (MCP
 * `CallToolRequest.params.arguments`) under the `tool-arguments` label,
 * with the key-context check. Absent arguments are `ok` with no value. On a
 * non-`ok` outcome the caller must not dispatch the tool or forward the
 * original arguments.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {unknown} args
 * @param {{ signal?: AbortSignal }} [options]
 */
export function redactArguments(boundary, args, { signal } = {}) {
  return mcpBoundaryFor(boundary).sanitizeToolArguments(args, { signal });
}

/**
 * Sanitizes a whole `CallToolResult` before it reaches a log, a store, or
 * model context. All or nothing.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {unknown} result
 * @param {{ signal?: AbortSignal, binaryContent?: "block" | "pass" }} [options]
 */
export function redactToolResult(boundary, result, { signal, binaryContent } = {}) {
  return mcpBoundaryFor(boundary, { binaryContent }).sanitizeToolResult(result, { signal });
}
