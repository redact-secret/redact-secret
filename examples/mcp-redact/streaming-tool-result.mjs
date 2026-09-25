/**
 * A tool result that arrives in chunks, through the AI-context boundary's
 * staged stream (`openStream`, `docs/reference/ai-context-boundary.md`,
 * #610) as implemented by `@redact-secret/adapter-ai-context`. This is what
 * `buildSafeContext`'s `streamTool` option runs (issue #721).
 *
 * The case is a tool whose output is produced progressively (a subprocess's
 * stdout, a file, an HTTP body) and assembled into one `CallToolResult`
 * before it joins model context. It is deliberately not wired to an MCP
 * streaming transport: the base MCP protocol resolves one `CallToolResult`
 * per call, and the SDK's chunked delivery (`experimental.tasks`) is marked
 * unstable in `@modelcontextprotocol/sdk@1.30.0`. The chunks go through one
 * core `IncrementalSanitizer` session, so a secret split across two chunks
 * is detected as one secret, and the session's mandatory limits bound what
 * it retains.
 *
 * What the boundary guarantees, and this file relies on:
 *
 * - **Staging.** Nothing is released before a successful `finalize`, even
 *   text the core has already sanitized. A `block` finding or a limit
 *   failure mid-stream aborts the core session at once; later chunks are
 *   discarded unscanned, and `finalize` returns the failure.
 * - **Cancellation.** A fired `signal` aborts the core session (which drops
 *   its retained plaintext) and discards the staged text. This file also
 *   stops pulling chunks and closes the producer, so an upstream subprocess
 *   or request can be cancelled.
 * - **Single release.** `finalize` is called exactly once, here.
 *
 * What this file adds: the loop, the producer's own failure (a rejected
 * iterator becomes `tool_error`, its error never read), and the MCP shape
 * of the released value.
 */

const UNSUPPORTED = Object.freeze({ outcome: "blocked", reason: "unsupported_value" });
const ABORTED = Object.freeze({ outcome: "aborted" });

/**
 * The host's own outcome when the producer fails. It is outside the
 * contract's outcome set, like `buildSafeContext`'s `tool_error` for a
 * rejected `callTool`: producing the chunks is the host's job, and the
 * error, which may carry input, is never read.
 */
export const TOOL_ERROR = Object.freeze({ outcome: "tool_error" });

function isIterable(value) {
  return (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    (typeof value[Symbol.asyncIterator] === "function" || typeof value[Symbol.iterator] === "function")
  );
}

function isAborted(signal) {
  return signal?.aborted === true;
}

/**
 * Sanitizes a tool result delivered as chunks of one logical text, and
 * returns one of:
 *
 * - `{ outcome: "ok", value: { content: [{ type: "text", text }] }, findings }`:
 *   a one-block `CallToolResult` with every `redact` finding replaced.
 *   Finding offsets are absolute in the joined text.
 * - the boundary's `{ outcome: "blocked", reason, code? }` or
 *   `{ outcome: "aborted" }`;
 * - {@link TOOL_ERROR}, when iterating `chunks` throws or rejects.
 *
 * A non-`ok` outcome carries no value, no findings, and nothing derived
 * from a chunk. The caller must not keep any chunk it saw itself.
 *
 * `chunks` is an `AsyncIterable<string>` or `Iterable<string>`: a Node
 * `Readable` after `setEncoding("utf8")`, a `ReadableStream` piped through
 * `TextDecoderStream`, or an async generator. Bytes must be decoded by the
 * producer with a streaming decoder, so a multi-byte character split across
 * two reads is not mangled; a non-string chunk blocks the result as
 * `unsupported_value`.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {AsyncIterable<string> | Iterable<string>} chunks
 * @param {{ signal?: AbortSignal }} [options]
 */
export async function redactStreamedToolResult(boundary, chunks, { signal } = {}) {
  if (boundary === null || typeof boundary !== "object" || typeof boundary.openStream !== "function") {
    throw new TypeError("redactStreamedToolResult: boundary must be an @redact-secret/adapter-ai-context boundary");
  }
  if (isAborted(signal)) return ABORTED;
  if (!isIterable(chunks)) return UNSUPPORTED;

  const stream = boundary.openStream({ boundary: "tool-result", signal });
  try {
    // `break` and a throw both close the iterator (`return()`), which is how
    // cancellation reaches the producer.
    for await (const chunk of chunks) {
      if (isAborted(signal)) break;
      stream.append(chunk);
    }
  } catch {
    // The producer failed. Discard everything staged and abort the core
    // session; the error is never read. A signal that fired while the
    // producer was being closed is still reported as a cancellation.
    stream.abort();
    return isAborted(signal) ? ABORTED : TOOL_ERROR;
  }

  const outcome = stream.finalize();
  if (outcome.outcome !== "ok") return outcome;
  return Object.freeze({
    outcome: "ok",
    value: Object.freeze({ content: Object.freeze([Object.freeze({ type: "text", text: outcome.value })]) }),
    findings: outcome.findings,
  });
}
