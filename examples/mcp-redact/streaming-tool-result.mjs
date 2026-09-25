/**
 * A tool result that arrives in chunks, through the MCP boundary's streamed
 * tool output (`docs/reference/mcp-boundary.md`, #612), as implemented by
 * `@redact-secret/adapter-mcp`'s `sanitizeStreamedToolResult` over the
 * AI-context boundary's staged stream. This is what `buildSafeContext`'s
 * `streamTool` option runs (issue #721).
 *
 * The case is a tool whose output is produced progressively (a subprocess's
 * stdout, a file, an HTTP body) and assembled into one `CallToolResult`
 * before it joins model context. It is deliberately not wired to an MCP
 * streaming transport: the base MCP protocol resolves one `CallToolResult`
 * per call, and the SDK's chunked delivery (`experimental.tasks`) is not
 * claimed by the contract.
 *
 * What the adapter guarantees, and this file relies on:
 *
 * - **Staging.** Nothing is released before a successful finalize.
 * - **Early stop.** After every chunk it reads the stream's `accepting`
 *   flag. Once the stream fails (a `block` finding, a limit, a core
 *   failure) or is cancelled, it pulls no further chunk and closes the
 *   producer (`return()`, and `destroy()` on a Node `Readable`), so an
 *   upstream subprocess or request can be cancelled.
 * - **Producer failure.** A throwing or rejecting producer is
 *   `tool_error`, its error never read.
 */

import { mcpBoundaryFor } from "./redact-tool-call.mjs";

/**
 * The host's own outcome when the producer fails: the MCP boundary's
 * `tool_error`. Producing the chunks is the host's job, and the error,
 * which may carry input, is never read.
 */
export const TOOL_ERROR = Object.freeze({ outcome: "tool_error" });

/**
 * Sanitizes a tool result delivered as chunks of one logical text, and
 * returns one of:
 *
 * - `{ outcome: "ok", value: { content: [{ type: "text", text }] }, findings }`:
 *   a one-block `CallToolResult` with every `redact` finding replaced.
 *   Finding offsets are absolute in the joined text.
 * - the boundary's `{ outcome: "blocked", reason, code? }` or
 *   `{ outcome: "aborted" }`;
 * - `{ outcome: "tool_error" }`, when iterating `chunks` throws or rejects.
 *
 * `chunks` is an `AsyncIterable<string>` or `Iterable<string>`: a Node
 * `Readable` after `setEncoding("utf8")`, a `ReadableStream` piped through
 * `TextDecoderStream`, or an async generator. A non-string chunk blocks the
 * result as `unsupported_value`.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {AsyncIterable<string> | Iterable<string>} chunks
 * @param {{ signal?: AbortSignal }} [options]
 */
export async function redactStreamedToolResult(boundary, chunks, { signal } = {}) {
  if (boundary === null || typeof boundary !== "object" || typeof boundary.openStream !== "function") {
    throw new TypeError("redactStreamedToolResult: boundary must be an @redact-secret/adapter-ai-context boundary");
  }
  return mcpBoundaryFor(boundary).sanitizeStreamedToolResult(chunks, { signal });
}
