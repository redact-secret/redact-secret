/**
 * The pure redaction core for MCP tool calls (issue #327): given an injected
 * `scanAndRedact`, redacts a `CallToolResult`'s content blocks / structured
 * content, or a tool call's argument object, and maps the outcome onto the
 * issue's policy contract:
 *
 * - `redact` findings: the span is replaced, the call continues.
 * - `warn` findings: the text passes through unchanged; still reported.
 * - `block` findings, or a `scanAndRedact` failure: the *whole* call becomes
 *   a fixed, input-free block outcome — never a partial or per-leaf marker.
 *   This differs from `examples/tracing-masking`'s per-leaf `BLOCK_MARKER`:
 *   MCP already has a first-class "tool error" outcome
 *   (`CallToolResult.isError`), so blocking maps onto that instead of a
 *   leaf-level placeholder.
 *
 * No `@modelcontextprotocol/sdk` import: `CallToolResult` and its content
 * blocks are a structural (duck-typed) shape here, the same choice
 * `examples/tracing-masking/redact-span-attributes.mjs` makes for
 * OpenTelemetry's `SpanProcessor`. This file is testable without the built
 * native addon or the MCP SDK installed.
 */

/** Bounds enforced while walking arguments and JSON-in-text content. Beyond
 * these, a subtree is marked with {@link LIMIT_MARKER} and dropped rather
 * than passed through unmasked — the call itself is not blocked, since these
 * are complexity guards, not secret-detection outcomes. */
export const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 8,
  maxArrayLength: 1000,
  maxObjectKeys: 200,
  maxStringLength: 200_000,
  maxTotalLeaves: 5000,
  maxContentBlocks: 200,
});

/** Fixed, input-free text for every blocked outcome. Never carries the
 * input, a matched value, or the underlying error's own message. */
export const BLOCKED_MESSAGE =
  "This MCP tool call was blocked by secret-redaction policy. No content, arguments, or error detail is included.";

export const LIMIT_MARKER = "[REDACTED:LIMIT_EXCEEDED]";
export const CYCLE_MARKER = "[REDACTED:CYCLE]";

function isPlainObject(value) {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Scans and redacts one leaf string, recording findings and flipping
 * `ctx.blocked` on a `block` finding or a core failure. Never throws. */
function redactLeaf(scanAndRedact, text, ctx) {
  if (text.length > ctx.limits.maxStringLength) return LIMIT_MARKER;
  if (ctx.budget.leaves <= 0) return LIMIT_MARKER;
  ctx.budget.leaves -= 1;

  let result;
  try {
    result = scanAndRedact(text, { policy: ctx.policy });
  } catch {
    ctx.blocked = true;
    ctx.blockReason = "core_error";
    return "";
  }
  ctx.findings.push(...result.findings);
  if (result.findings.some((finding) => finding.action === "block")) {
    ctx.blocked = true;
    ctx.blockReason = "policy";
    return "";
  }
  return result.text;
}

function redactJsonValue(scanAndRedact, value, ctx, depth, seen) {
  if (ctx.blocked) return value;

  if (typeof value === "string") {
    return redactLeaf(scanAndRedact, value, ctx);
  }

  if (Array.isArray(value)) {
    if (depth >= ctx.limits.maxDepth) return LIMIT_MARKER;
    if (seen.has(value)) return CYCLE_MARKER;
    seen.add(value);
    const bounded = value.slice(0, ctx.limits.maxArrayLength);
    const out = bounded.map((item) => redactJsonValue(scanAndRedact, item, ctx, depth + 1, seen));
    seen.delete(value);
    return out;
  }

  if (isPlainObject(value)) {
    if (depth >= ctx.limits.maxDepth) return LIMIT_MARKER;
    if (seen.has(value)) return CYCLE_MARKER;
    seen.add(value);
    const keys = Object.keys(value).slice(0, ctx.limits.maxObjectKeys);
    const out = {};
    for (const key of keys) {
      out[key] = redactJsonValue(scanAndRedact, value[key], ctx, depth + 1, seen);
    }
    seen.delete(value);
    return out;
  }

  // Numbers, booleans, null, undefined, and non-plain objects are left
  // unchanged: only plain objects, arrays, and strings are walked.
  return value;
}

/**
 * Redacts one piece of text that may be a JSON-serialized object/array (an
 * MCP "JSON-in-text" result, e.g. a stringified API response). When it
 * parses as a JSON object or array, every string leaf inside is redacted and
 * the value is re-serialized, which — unlike scanning the raw JSON text as
 * one opaque string — can never place a placeholder outside a quoted string
 * and corrupt the JSON. Anything else (plain text, or JSON scalars like a
 * bare number or boolean) is scanned as opaque text.
 */
function redactTextOrJson(scanAndRedact, text, ctx) {
  if (ctx.blocked) return text;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (Array.isArray(parsed) || isPlainObject(parsed)) {
    const redacted = redactJsonValue(scanAndRedact, parsed, ctx, 0, new Set());
    if (ctx.blocked) return "";
    return JSON.stringify(redacted);
  }
  return redactLeaf(scanAndRedact, text, ctx);
}

function redactContentBlock(scanAndRedact, block, ctx) {
  if (ctx.blocked) return block;
  if (!isPlainObject(block)) return block;

  if (block.type === "text" && typeof block.text === "string") {
    return { ...block, text: redactTextOrJson(scanAndRedact, block.text, ctx) };
  }

  // An embedded text resource (`{ type: "resource", resource: { text } }`)
  // carries scannable text; a blob resource (`resource.blob`) is base64
  // binary and, like `image`/`audio`/`resource_link` blocks, passes through
  // unchanged — the documented non-text false-negative boundary.
  if (block.type === "resource" && isPlainObject(block.resource) && typeof block.resource.text === "string") {
    return {
      ...block,
      resource: { ...block.resource, text: redactTextOrJson(scanAndRedact, block.resource.text, ctx) },
    };
  }

  return block;
}

function makeContext(scanAndRedact, options) {
  if (typeof scanAndRedact !== "function") {
    throw new TypeError("scanAndRedact must be a function");
  }
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  return {
    policy: options.policy,
    limits,
    budget: { leaves: limits.maxTotalLeaves },
    blocked: false,
    blockReason: undefined,
    findings: [],
  };
}

/** The fixed `CallToolResult`-shaped tool error every blocked outcome maps
 * to: no content, no arguments, no error detail beyond the fixed message. */
export function buildBlockedResult() {
  return { content: [{ type: "text", text: BLOCKED_MESSAGE }], isError: true };
}

/**
 * Redacts a tool call's argument object in place (a plain object tree, as
 * MCP `CallToolRequest.params.arguments` always is). Returns `outcome:
 * "blocked"` — with no `arguments` field — when any argument value contains
 * a `block` finding or `scanAndRedact` fails; the caller must not forward
 * the original arguments to the tool in that case.
 */
export function redactArguments(scanAndRedact, args, options = {}) {
  const ctx = makeContext(scanAndRedact, options);
  if (!isPlainObject(args)) {
    throw new TypeError("redactArguments: args must be a plain object");
  }
  const redacted = redactJsonValue(scanAndRedact, args, ctx, 0, new Set());
  if (ctx.blocked) {
    return { outcome: "blocked", blockReason: ctx.blockReason, findings: ctx.findings };
  }
  return { outcome: "ok", arguments: redacted, findings: ctx.findings };
}

/**
 * Redacts a `CallToolResult`'s `content` blocks and `structuredContent`
 * before it reaches the client or model context. Returns `outcome:
 * "blocked"` — with no `result` field — on any `block` finding or core
 * failure; the caller must return {@link buildBlockedResult} instead of the
 * original result in that case.
 */
export function redactToolResult(scanAndRedact, result, options = {}) {
  const ctx = makeContext(scanAndRedact, options);
  if (!isPlainObject(result)) {
    throw new TypeError("redactToolResult: result must be a plain object");
  }

  const contentIn = Array.isArray(result.content) ? result.content : [];
  const bounded = contentIn.slice(0, ctx.limits.maxContentBlocks);
  const content = bounded.map((block) => redactContentBlock(scanAndRedact, block, ctx));

  let structuredContent = result.structuredContent;
  if (!ctx.blocked && isPlainObject(structuredContent)) {
    structuredContent = redactJsonValue(scanAndRedact, structuredContent, ctx, 0, new Set());
  }

  if (ctx.blocked) {
    return { outcome: "blocked", blockReason: ctx.blockReason, findings: ctx.findings };
  }

  const out = { ...result, content };
  if ("structuredContent" in result) out.structuredContent = structuredContent;
  return { outcome: "ok", result: out, findings: ctx.findings };
}
