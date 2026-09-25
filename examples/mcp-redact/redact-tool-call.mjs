/**
 * MCP tool calls through the AI-context boundary (issue #327, migrated onto
 * `@redact-secret/adapter-ai-context` by redact-secret-adapters#12): given a
 * boundary, sanitizes a `CallToolResult`'s content blocks and
 * `structuredContent`, or a tool call's argument object, and returns the
 * boundary's own outcome shape (`docs/reference/ai-context-boundary.md`):
 *
 * - `{ outcome: "ok", value, findings }`: `redact` findings replaced,
 *   `warn`/`allow` text unchanged; `value` is the only safe thing to return.
 * - `{ outcome: "blocked", reason, code? }`: any `block` finding, a key that
 *   would be redacted, a limit, a non-JSON value, or a core failure, anywhere
 *   in the call. No value, no findings, nothing derived from input. The caller
 *   returns {@link buildBlockedResult} instead: MCP has a first-class "tool
 *   error" outcome (`CallToolResult.isError`), so a blocked call maps onto
 *   that rather than a partial result.
 * - `{ outcome: "aborted" }`: the signal fired.
 *
 * This file owns only the MCP shape: which content blocks carry text, and
 * JSON-in-text. Every scan, every traversal, every limit and every failure
 * mapping is the adapter's. There is no walker, marker or leaf budget here.
 *
 * No `@modelcontextprotocol/sdk` import: `CallToolResult` and its content
 * blocks are a structural (duck-typed) shape here.
 */

/**
 * The most content blocks one result may carry. Past it the whole result is
 * blocked as `limit_exceeded`; blocks are never dropped or passed on unscanned.
 */
export const DEFAULT_MAX_CONTENT_BLOCKS = 200;

/** Fixed, input-free text for every blocked outcome. Never carries the
 * input, a matched value, or the underlying error's own message. */
export const BLOCKED_MESSAGE =
  "This MCP tool call was blocked by secret-redaction policy. No content, arguments, or error detail is included.";

function isPlainObject(value) {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function requireBoundary(boundary, caller) {
  if (boundary === null || typeof boundary !== "object" || typeof boundary.sanitizeValue !== "function") {
    throw new TypeError(`${caller}: boundary must be an @redact-secret/adapter-ai-context boundary`);
  }
}

const UNSUPPORTED = Object.freeze({ outcome: "blocked", reason: "unsupported_value" });
const OVER_LIMIT = Object.freeze({ outcome: "blocked", reason: "limit_exceeded" });

/**
 * One piece of text that may be a JSON-serialized object or array (an MCP
 * "JSON-in-text" result, such as a stringified API response). When it
 * parses as one, the parsed value goes through `sanitizeValue` and is
 * re-serialized, which, unlike scanning the raw JSON text as one opaque
 * string, can never place a placeholder outside a quoted string and corrupt
 * the JSON. Anything else is scanned as text.
 */
function sanitizeTextOrJson(boundary, text, options) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (Array.isArray(parsed) || isPlainObject(parsed)) {
    const outcome = boundary.sanitizeValue(parsed, options);
    return outcome.outcome === "ok" ? { ...outcome, value: JSON.stringify(outcome.value) } : outcome;
  }
  return boundary.sanitizeText(text, options);
}

/**
 * Text blocks and embedded text resources are scanned. `image`, `audio`,
 * `resource_link`, and embedded blob resources (base64 binary) pass through
 * unchanged: non-text content is outside the boundary contract, a documented
 * false negative.
 */
function sanitizeContentBlock(boundary, block, options) {
  if (!isPlainObject(block)) return UNSUPPORTED;
  if (block.type === "text" && typeof block.text === "string") {
    const outcome = sanitizeTextOrJson(boundary, block.text, options);
    return outcome.outcome === "ok" ? { ...outcome, value: { ...block, text: outcome.value } } : outcome;
  }
  if (block.type === "resource" && isPlainObject(block.resource) && typeof block.resource.text === "string") {
    const outcome = sanitizeTextOrJson(boundary, block.resource.text, options);
    return outcome.outcome === "ok"
      ? { ...outcome, value: { ...block, resource: { ...block.resource, text: outcome.value } } }
      : outcome;
  }
  return { outcome: "ok", value: block, findings: [] };
}

/** The fixed `CallToolResult`-shaped tool error every blocked or aborted outcome maps
 * to: no content, no arguments, no error detail beyond the fixed message. */
export function buildBlockedResult() {
  return { content: [{ type: "text", text: BLOCKED_MESSAGE }], isError: true };
}

/**
 * Sanitizes a tool call's argument object (MCP
 * `CallToolRequest.params.arguments`, a plain object tree) with
 * `sanitizeValue`: every string value and every key is scanned. On a
 * non-`ok` outcome the caller must not forward the original arguments.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {unknown} args
 * @param {{ signal?: AbortSignal }} [options]
 */
export function redactArguments(boundary, args, { signal } = {}) {
  requireBoundary(boundary, "redactArguments");
  if (!isPlainObject(args)) return UNSUPPORTED;
  // The contract has no label for tool arguments yet (#612 defines the MCP
  // boundary); they cross into a tool, so they are labelled `context`.
  return boundary.sanitizeValue(args, { boundary: "context", signal });
}

/**
 * Sanitizes a `CallToolResult`'s `content` blocks and `structuredContent`
 * before it reaches the client, a log, or model context. All or nothing:
 * the first non-`ok` block, or a non-`ok` `structuredContent`, is the
 * outcome for the whole result. Other top-level fields (`isError`, `_meta`)
 * are copied unchanged.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextBoundary} boundary
 * @param {unknown} result
 * @param {{ signal?: AbortSignal, maxContentBlocks?: number }} [options]
 */
export function redactToolResult(boundary, result, { signal, maxContentBlocks = DEFAULT_MAX_CONTENT_BLOCKS } = {}) {
  requireBoundary(boundary, "redactToolResult");
  if (signal?.aborted === true) return Object.freeze({ outcome: "aborted" });
  if (!isPlainObject(result)) return UNSUPPORTED;
  if (result.content !== undefined && !Array.isArray(result.content)) return UNSUPPORTED;
  const contentIn = result.content ?? [];
  if (contentIn.length > maxContentBlocks) return OVER_LIMIT;

  const options = { boundary: "tool-result", signal };
  const findings = [];
  const content = [];
  for (const block of contentIn) {
    const outcome = sanitizeContentBlock(boundary, block, options);
    if (outcome.outcome !== "ok") return outcome;
    findings.push(...outcome.findings);
    content.push(outcome.value);
  }

  const out = { ...result, content };
  if (result.structuredContent !== undefined) {
    const outcome = boundary.sanitizeValue(result.structuredContent, options);
    if (outcome.outcome !== "ok") return outcome;
    findings.push(...outcome.findings);
    out.structuredContent = outcome.value;
  }
  return Object.freeze({ outcome: "ok", value: out, findings: Object.freeze(findings) });
}
