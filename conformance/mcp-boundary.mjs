/**
 * JavaScript reference model and conformance runner for the supported MCP
 * redaction boundary (issue #612, `docs/reference/mcp-boundary.md`,
 * `decision-define-the-supported-mcp-redaction-boundary`).
 *
 * The MCP boundary is a thin specialization of the framework-neutral
 * AI-context boundary (#610, `conformance/ai-context-boundary.mjs`). This
 * file never scans, never walks a nested value, never evaluates policy, and
 * never maps a core error: every one of those is the AI-context boundary's.
 * What it adds is the MCP shape only:
 *
 * - which parts of a `CallToolResult` are scanned, which binary payloads are
 *   blocked (or, on explicit opt-in, passed unscanned), and which content
 *   block types exist;
 * - a key-context check: the sanitized structured parts are serialized and
 *   scanned once more as text, so a secret identified only by its key blocks
 *   the result instead of reaching context from `structuredContent`;
 * - the `tool-arguments` label for opted-in argument sanitation;
 * - a streamed tool result that stops pulling from its producer as soon as
 *   the stream stops accepting chunks;
 * - the fixed, input-free `CallToolResult` every non-`ok` outcome maps to,
 *   and an input-free audit record.
 *
 * `createMcpBoundary(aiContextBoundary, options)` is that specialization
 * written as the smallest code that satisfies the contract. It is not a
 * package export and not the adapter: `@redact-secret/adapter-mcp` is
 * redact-secret/redact-secret-adapters#13. The runner accepts any
 * implementation through `options.createBoundary`, so the adapter can replay
 * this fixture through its own public API.
 *
 * `runMcpBoundaryConformance(api, fixture, { phase })` replays
 * `conformance/fixtures/mcp-boundary.json`. `scripts/consumer-harness.mjs`
 * runs it against the packed, clean-installed `@redact-secret/core`, and
 * `conformance/mcp-boundary.test.mjs` runs it against a fake core.
 *
 * No `@modelcontextprotocol/sdk` import: a `CallToolResult` is a structural
 * shape here, as it is on the wire. Plain ESM, no Node.js import, so the same
 * file runs in the browser lane. Failure messages name a case ID and a field
 * only, never an input, a value, or a matched secret.
 */

import { BLOCK_REASONS, SAFE_FINDING_FIELDS, createAiContextBoundary } from "./ai-context-boundary.mjs";

/** The AI-context boundary labels this specialization uses. */
export const MCP_BOUNDARY_LABELS = Object.freeze({
  arguments: "tool-arguments",
  result: "tool-result",
});

/**
 * The content block types of MCP protocol revisions 2025-06-18 and
 * 2025-11-25. A block of any other type is blocked as `unsupported_value`:
 * a future type may carry content this contract does not know how to scan.
 */
export const MCP_CONTENT_TYPES = Object.freeze(["text", "image", "audio", "resource_link", "resource"]);

/** The MCP boundary's outcomes: the AI-context three, plus the host's own `tool_error`. */
export const MCP_OUTCOMES = Object.freeze(["ok", "blocked", "aborted", "tool_error"]);

/** Fixed text of the `CallToolResult` a `blocked` outcome maps to. */
export const MCP_BLOCKED_TEXT =
  "This MCP tool call was blocked by secret-redaction policy. No content, arguments, or error detail is included.";

/** Fixed text of the `CallToolResult` a `tool_error` outcome maps to. */
export const MCP_TOOL_ERROR_TEXT =
  "This MCP tool call failed. No content, arguments, or error detail is included.";

/** The only keys an audit record may carry. */
export const MCP_AUDIT_FIELDS = Object.freeze(["stage", "outcome", "reason", "code"]);

const ABORTED = Object.freeze({ outcome: "aborted" });
const UNSUPPORTED = Object.freeze({ outcome: "blocked", reason: "unsupported_value" });
const TOOL_ERROR = Object.freeze({ outcome: "tool_error" });

function isAborted(signal) {
  return signal != null && signal.aborted === true;
}

function isPlainObject(value) {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isIterable(value) {
  return (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    (typeof value[Symbol.asyncIterator] === "function" || typeof value[Symbol.iterator] === "function")
  );
}

function define(target, key, value) {
  Object.defineProperty(target, key, { value, enumerable: true, configurable: true, writable: true });
}

/** A copy of `object` without `omit`, in the original key order. */
function without(object, omit) {
  const copy = {};
  for (const key of Object.keys(object)) if (key !== omit) define(copy, key, object[key]);
  return copy;
}

/** `sanitized` with `key` put back at its original position in `original`. */
function restore(original, sanitized, key) {
  const out = {};
  for (const name of Object.keys(original)) define(out, name, name === key ? original[key] : sanitized[name]);
  return out;
}

/** Fixed, input-free `CallToolResult` for a `blocked` outcome. A new object each call. */
export function mcpBlockedResult() {
  return { content: [{ type: "text", text: MCP_BLOCKED_TEXT }], isError: true };
}

/** Fixed, input-free `CallToolResult` for a `tool_error` outcome. A new object each call. */
export function mcpToolErrorResult() {
  return { content: [{ type: "text", text: MCP_TOOL_ERROR_TEXT }], isError: true };
}

/**
 * What an outcome may put on the wire or into model context:
 *
 * - `ok`: the sanitized value, and nothing else;
 * - `blocked` (every reason, `core_error` included): {@link mcpBlockedResult};
 * - `tool_error`: {@link mcpToolErrorResult};
 * - `aborted`: `null`, meaning nothing is sent. A cancelled MCP request gets
 *   no response, and a cancelled client call's result is discarded.
 *
 * Never a JSON-RPC error: an error's `message` and `data` are free text that
 * SDKs and hosts log verbatim.
 */
export function toCallToolResult(outcome) {
  switch (outcome?.outcome) {
    case "ok":
      return outcome.value;
    case "blocked":
      return mcpBlockedResult();
    case "tool_error":
      return mcpToolErrorResult();
    case "aborted":
      return null;
    default:
      throw new TypeError("toCallToolResult: not an MCP boundary outcome");
  }
}

/**
 * The input-free audit record of one boundary crossing: the stage, the
 * outcome, and for `blocked` the fixed reason and registry code. Findings
 * reach auditing only through the AI-context boundary's `onFinding`.
 *
 * @param {"arguments" | "result"} stage
 */
export function mcpAuditRecord(outcome, stage) {
  if (stage !== "arguments" && stage !== "result") throw new TypeError("mcpAuditRecord: unknown stage");
  const record = { stage, outcome: outcome.outcome };
  if (outcome.outcome === "blocked") {
    record.reason = outcome.reason;
    if (outcome.code !== undefined) record.code = outcome.code;
  }
  return Object.freeze(record);
}

/**
 * @param {{ sanitizeText: Function, sanitizeValue: Function, openStream: Function }} boundary an AI-context boundary
 * @param {{ binaryContent?: "block" | "pass" }} [options]
 */
export function createMcpBoundary(boundary, { binaryContent = "block" } = {}) {
  if (
    boundary === null ||
    typeof boundary !== "object" ||
    typeof boundary.sanitizeValue !== "function" ||
    typeof boundary.sanitizeText !== "function" ||
    typeof boundary.openStream !== "function"
  ) {
    throw new TypeError("createMcpBoundary: an AI-context boundary is required");
  }
  if (binaryContent !== "block" && binaryContent !== "pass") {
    throw new TypeError('createMcpBoundary: binaryContent must be "block" or "pass"');
  }

  /**
   * A base64 payload (`image.data`, `audio.data`, `resource.blob`) cannot be
   * scanned. By default it blocks the result; on opt-in it is removed from
   * the scan view and restored unscanned afterwards.
   * Returns `{ failure }` or `{ view, binary }`.
   */
  function detachBinary(object, key) {
    if (!(key in object)) return { view: object, binary: false };
    if (binaryContent === "block" || typeof object[key] !== "string") return { failure: UNSUPPORTED };
    return { view: without(object, key), binary: true };
  }

  function prepareBlock(block) {
    if (!isPlainObject(block) || !MCP_CONTENT_TYPES.includes(block.type)) return { failure: UNSUPPORTED };
    if (block.type === "image" || block.type === "audio") {
      const detached = detachBinary(block, "data");
      if (detached.failure) return detached;
      return { view: detached.view, reassemble: detached.binary ? (clean) => restore(block, clean, "data") : null };
    }
    if (block.type === "resource") {
      if (!isPlainObject(block.resource)) return { failure: UNSUPPORTED };
      const detached = detachBinary(block.resource, "blob");
      if (detached.failure) return detached;
      if (!detached.binary) return { view: block, reassemble: null };
      const view = {};
      for (const key of Object.keys(block)) define(view, key, key === "resource" ? detached.view : block[key]);
      return {
        view,
        reassemble: (clean) => {
          const out = {};
          for (const key of Object.keys(block)) {
            define(out, key, key === "resource" ? restore(block.resource, clean.resource, "blob") : clean[key]);
          }
          return out;
        },
      };
    }
    return { view: block, reassemble: null };
  }

  /**
   * The key-context check. The per-leaf scan sees a string leaf without the
   * key it sits under, so `{"password": "<value>"}` is missed when the value
   * is not self-identifying, while the same pair in text is caught. MCP makes
   * this acute: a tool that returns `structuredContent` should also return
   * its serialization as text, so the text copy would be redacted and the
   * structured copy delivered as is. After the per-leaf pass, each
   * value-shaped part of the SANITIZED value is serialized with
   * `JSON.stringify` and scanned once more as text. A `redact` or `block`
   * finding there cannot be mapped back onto a leaf, so it blocks the whole
   * operation as `policy`. Placeholders the first pass wrote are not
   * detected again. Returns a non-`ok` outcome, or `undefined` to continue.
   */
  function checkKeyContext(parts, label, signal) {
    for (const part of parts) {
      const outcome = boundary.sanitizeText(JSON.stringify(part), { boundary: label, signal });
      if (outcome.outcome !== "ok") return outcome;
      if (outcome.findings.some((finding) => finding.action === "redact" || finding.action === "block")) {
        return Object.freeze({ outcome: "blocked", reason: "policy" });
      }
    }
    return undefined;
  }

  /**
   * The value-shaped parts of a sanitized result: the result without its
   * `content` array (so `structuredContent`, `_meta`, and any other field),
   * and every block without its scanned `text` (a text block's or an
   * embedded resource's), which already carried its own context. Binary
   * payloads are not in the sanitized view.
   */
  function keyContextParts(result) {
    const parts = [without(result, "content")];
    for (const block of Array.isArray(result.content) ? result.content : []) {
      if (block.type === "text") parts.push(without(block, "text"));
      else if (block.type === "resource") parts.push({ ...block, resource: without(block.resource, "text") });
      else parts.push(block);
    }
    return parts;
  }

  /**
   * Sanitizes one `CallToolResult` before it is logged, persisted, or placed
   * into model context: the whole result, `content`, `structuredContent`,
   * `_meta`, and any other field, as ONE bounded value through the
   * AI-context `sanitizeValue` (every string leaf and every key scanned,
   * traversal limits counted from the result root). All or nothing.
   */
  function sanitizeToolResult(result, { signal } = {}) {
    if (isAborted(signal)) return ABORTED;
    if (!isPlainObject(result)) return UNSUPPORTED;
    if (result.content !== undefined && !Array.isArray(result.content)) return UNSUPPORTED;

    const reassembly = [];
    let view = result;
    if (Array.isArray(result.content)) {
      const content = [];
      for (const block of result.content) {
        const prepared = prepareBlock(block);
        if (prepared.failure) return prepared.failure;
        content.push(prepared.view);
        reassembly.push(prepared.reassemble);
      }
      view = {};
      for (const key of Object.keys(result)) define(view, key, key === "content" ? content : result[key]);
    }

    const outcome = boundary.sanitizeValue(view, { boundary: MCP_BOUNDARY_LABELS.result, signal });
    if (outcome.outcome !== "ok") return outcome;
    const context = checkKeyContext(keyContextParts(outcome.value), MCP_BOUNDARY_LABELS.result, signal);
    if (context !== undefined) return context;
    if (!reassembly.some(Boolean)) return outcome;
    const value = {};
    for (const key of Object.keys(outcome.value)) {
      define(
        value,
        key,
        key === "content"
          ? outcome.value.content.map((block, index) => (reassembly[index] ? reassembly[index](block) : block))
          : outcome.value[key],
      );
    }
    return Object.freeze({ outcome: "ok", value, findings: outcome.findings });
  }

  /**
   * Opt-in: sanitizes `CallToolRequest.params.arguments` before the tool is
   * dispatched (client side) or before the handler reads it (server side).
   * Absent arguments are `ok` with no value. A non-`ok` outcome means the
   * tool is not dispatched and the original arguments are not forwarded.
   */
  function sanitizeToolArguments(args, { signal } = {}) {
    if (isAborted(signal)) return ABORTED;
    if (args === undefined) return Object.freeze({ outcome: "ok", value: undefined, findings: Object.freeze([]) });
    if (!isPlainObject(args)) return UNSUPPORTED;
    const outcome = boundary.sanitizeValue(args, { boundary: MCP_BOUNDARY_LABELS.arguments, signal });
    if (outcome.outcome !== "ok") return outcome;
    return checkKeyContext([outcome.value], MCP_BOUNDARY_LABELS.arguments, signal) ?? outcome;
  }

  /**
   * Runs the host's tool (a server handler, or a client's `callTool`) and
   * sanitizes what it returns. A throw or rejection becomes `tool_error`,
   * its error never read: the SDK's own conversion of a thrown handler error
   * into `isError` text, and a client's `McpError` message, never run on
   * this path.
   */
  async function sanitizeToolCall(invoke, { signal } = {}) {
    if (isAborted(signal)) return ABORTED;
    let raw;
    try {
      raw = await invoke({ signal });
    } catch {
      return isAborted(signal) ? ABORTED : TOOL_ERROR;
    }
    return sanitizeToolResult(raw, { signal });
  }

  /**
   * A tool result produced as chunks of one logical text, through one staged
   * AI-context stream, released as a one-block `CallToolResult` only by a
   * successful finalize. As soon as the stream stops accepting (a `block`,
   * a limit, a lifecycle or core failure, or an abort), no further chunk is
   * pulled and the producer is closed.
   */
  async function sanitizeStreamedToolResult(chunks, { signal } = {}) {
    if (isAborted(signal)) return ABORTED;
    if (!isIterable(chunks)) return UNSUPPORTED;
    const stream = boundary.openStream({ boundary: MCP_BOUNDARY_LABELS.result, signal });
    if (stream.accepting === true) {
      try {
        // `break` closes the iterator (`return()`), which is how an early
        // failure or a cancellation reaches the producer.
        for await (const chunk of chunks) {
          stream.append(chunk);
          if (stream.accepting !== true) break;
        }
      } catch {
        stream.abort();
        return isAborted(signal) ? ABORTED : TOOL_ERROR;
      }
    }
    const outcome = stream.finalize();
    if (outcome.outcome !== "ok") return outcome;
    return Object.freeze({
      outcome: "ok",
      value: { content: [{ type: "text", text: outcome.value }] },
      findings: outcome.findings,
    });
  }

  return Object.freeze({ sanitizeToolResult, sanitizeToolArguments, sanitizeToolCall, sanitizeStreamedToolResult });
}

// ---------------------------------------------------------------------
// Conformance runner
// ---------------------------------------------------------------------

const POLICIES = {
  default: () => undefined,
  "block-all": () => ({ evaluate: () => "block" }),
  throwing: () => ({
    evaluate: () => {
      throw new Error("synthetic policy failure");
    },
  }),
};

function fail(caseId, field) {
  throw new Error(`mcp-boundary ${caseId}: ${field}`);
}

function sameJson(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function observable(outcome) {
  return JSON.parse(JSON.stringify(outcome));
}

function materializeChunk(chunk) {
  if (typeof chunk === "string") return chunk;
  if (chunk && typeof chunk.repeat === "string") return chunk.repeat.repeat(chunk.count);
  throw new Error("mcp-boundary fixture: unsupported chunk form");
}

function incrementalLimitsFrom(fixture) {
  const limits = fixture.limits.incremental;
  return {
    maxInputCodeUnits: limits.maxInputBytes,
    maxBufferedCodeUnits: limits.maxBufferedBytes,
    maxTokenCodeUnits: limits.maxTokenBytes,
    maxMultilineCodeUnits: limits.maxMultilineBytes,
  };
}

/**
 * A synchronous producer that records how many chunks were pulled and
 * whether it was closed. It can fire the signal, or throw an error carrying
 * a secret, before yielding chunk `index`.
 */
function producer(chunks, { abortBefore, throwBefore, secret }, signal) {
  const state = { pulled: 0, closed: false };
  let index = 0;
  const iterator = {
    [Symbol.iterator]() {
      return iterator;
    },
    next() {
      if (throwBefore !== undefined && index === throwBefore) {
        throw new Error(`synthetic producer failure ${secret ?? ""}`);
      }
      if (abortBefore !== undefined && index === abortBefore) signal.aborted = true;
      if (index >= chunks.length) {
        state.closed = true;
        return { done: true, value: undefined };
      }
      state.pulled += 1;
      const value = chunks[index];
      index += 1;
      return { done: false, value };
    },
    return() {
      state.closed = true;
      return { done: true, value: undefined };
    },
  };
  return { iterator, state };
}

function checkNoLeak(caseId, testCase, outcome, delivered, audit, events) {
  const secrets = testCase.secrets ?? [];
  const metadata = JSON.stringify({ ...outcome, value: undefined }) + JSON.stringify(events) + JSON.stringify(audit);
  const value = outcome.outcome === "ok" ? JSON.stringify(outcome.value) : JSON.stringify(delivered);
  for (const secret of secrets) {
    if (metadata.includes(secret)) fail(caseId, "a secret reached outcome metadata, audit, or telemetry");
    if (!testCase.valueMayContainSecrets && value !== undefined && value.includes(secret)) {
      fail(caseId, "a secret reached the delivered result");
    }
  }
  for (const event of events) {
    if (!sameJson(Object.keys(event.finding).sort(), [...SAFE_FINDING_FIELDS].sort())) {
      fail(caseId, "telemetry finding carries non-contract fields");
    }
    if (!sameJson(Object.keys(event.context), ["boundary"])) fail(caseId, "telemetry context carries non-contract fields");
    if (!Object.values(MCP_BOUNDARY_LABELS).includes(event.context.boundary)) fail(caseId, "telemetry label");
  }
  if (!MCP_OUTCOMES.includes(outcome.outcome)) fail(caseId, "unknown outcome");
  if (outcome.outcome !== "ok" && ("value" in outcome || "findings" in outcome)) {
    fail(caseId, "a non-ok outcome carries a value or findings");
  }
  if (outcome.outcome === "blocked" && !BLOCK_REASONS.includes(outcome.reason)) fail(caseId, "unknown block reason");
  if (Object.keys(audit).some((key) => !MCP_AUDIT_FIELDS.includes(key))) fail(caseId, "audit record carries non-contract fields");
}

/** Every non-`ok` outcome maps onto exactly the fixture's fixed result, or onto nothing. */
function checkMapping(caseId, fixture, outcome, delivered) {
  if (outcome.outcome === "ok") {
    if (!sameJson(delivered, outcome.value)) fail(caseId, "an ok outcome must deliver exactly its value");
  } else if (outcome.outcome === "aborted") {
    if (delivered !== null) fail(caseId, "an aborted outcome must deliver nothing");
  } else {
    const expected = outcome.outcome === "blocked" ? fixture.fixedResults.blocked : fixture.fixedResults.toolError;
    if (!sameJson(delivered, expected)) fail(caseId, "a non-ok outcome must deliver the fixed result");
  }
}

function defaultCreateBoundary(api, options) {
  return createMcpBoundary(createAiContextBoundary(api, options), { binaryContent: options.binaryContent });
}

/**
 * Replays every fixture case for `phase` and returns a count-only summary.
 * Throws on the first divergence. `createBoundary(api, options)` builds the
 * implementation under test (default: this reference model); `options`
 * carries the fixture's limits, `policy`, `onFinding`, and `binaryContent`.
 */
export async function runMcpBoundaryConformance(
  api,
  fixture,
  { phase = "initialized", createBoundary = defaultCreateBoundary } = {},
) {
  if (fixture.schemaVersion !== 1) throw new Error("mcp-boundary fixture: unsupported schema");
  if (!sameJson(fixture.safeFindingFields, SAFE_FINDING_FIELDS)) {
    throw new Error("mcp-boundary fixture: safe finding fields diverge from the runner");
  }
  if (
    !sameJson(fixture.fixedResults.blocked, mcpBlockedResult()) ||
    !sameJson(fixture.fixedResults.toolError, mcpToolErrorResult())
  ) {
    throw new Error("mcp-boundary fixture: fixed results diverge from the runner");
  }
  if (!sameJson(fixture.contentTypes, MCP_CONTENT_TYPES)) {
    throw new Error("mcp-boundary fixture: content types diverge from the runner");
  }
  const summary = { cases: 0, pulledChunks: 0, telemetryEvents: 0 };

  for (const testCase of fixture.cases) {
    if ((testCase.phase ?? "initialized") !== phase) continue;
    const events = [];
    const boundary = createBoundary(api, {
      wholeInputLimits: fixture.limits.wholeInput,
      incrementalLimits: incrementalLimitsFrom(fixture),
      traversalLimits: fixture.limits.traversal,
      policy: POLICIES[testCase.policy ?? "default"](),
      binaryContent: testCase.binaryContent ?? "block",
      onFinding: (finding, context) => {
        events.push({ finding: { ...finding }, context: { ...context } });
      },
    });
    const signal = { aborted: testCase.signal === "aborted-before" };
    let outcome;
    let stage = "result";

    if (testCase.operation === "toolResult") {
      outcome = boundary.sanitizeToolResult(testCase.result, { signal });
    } else if (testCase.operation === "toolArguments") {
      stage = "arguments";
      outcome = boundary.sanitizeToolArguments(testCase.arguments, { signal });
    } else if (testCase.operation === "toolCall") {
      const secret = (testCase.secrets ?? [])[0] ?? "";
      outcome = await boundary.sanitizeToolCall(
        async () => {
          if (testCase.toolThrows) throw new Error(`synthetic tool failure ${secret}`);
          return testCase.result;
        },
        { signal },
      );
    } else if (testCase.operation === "streamedToolResult") {
      const chunks = testCase.chunks.map(materializeChunk);
      const { iterator, state } = producer(
        chunks,
        { ...testCase.producer, secret: (testCase.secrets ?? [])[0] },
        signal,
      );
      outcome = await boundary.sanitizeStreamedToolResult(iterator, { signal });
      if (testCase.expectedPulled !== undefined && state.pulled !== testCase.expectedPulled) {
        fail(testCase.id, "chunks pulled from the producer");
      }
      if (testCase.expectedClosed !== undefined && state.closed !== testCase.expectedClosed) {
        fail(testCase.id, "producer closed");
      }
      summary.pulledChunks += state.pulled;
    } else {
      fail(testCase.id, "unknown operation");
    }

    if (!sameJson(observable(outcome), testCase.expected)) fail(testCase.id, "outcome");
    const delivered = toCallToolResult(outcome);
    const audit = mcpAuditRecord(outcome, stage);
    checkMapping(testCase.id, fixture, outcome, delivered);
    checkNoLeak(testCase.id, testCase, outcome, delivered, audit, events);
    if (testCase.expectedLabels !== undefined) {
      const labels = [...new Set(events.map((event) => event.context.boundary))];
      if (!sameJson(labels, testCase.expectedLabels)) fail(testCase.id, "telemetry labels");
    }
    summary.cases += 1;
    summary.telemetryEvents += events.length;
  }
  return summary;
}
