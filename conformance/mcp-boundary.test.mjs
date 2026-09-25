/**
 * Unit tests for the MCP boundary reference model and runner (issue #612)
 * against a fake core, so they run in `npm run ci` without a built
 * artifact. The real-artifact replay of `fixtures/mcp-boundary.json` runs in
 * `scripts/consumer-harness.mjs` against the packed, clean-installed
 * `@redact-secret/core` on the Node addon lane and in every browser engine.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { BLOCK_REASONS, SAFE_FINDING_FIELDS, createAiContextBoundary } from "./ai-context-boundary.mjs";
import {
  MCP_AUDIT_FIELDS,
  MCP_BLOCKED_TEXT,
  MCP_BOUNDARY_LABELS,
  MCP_CONTENT_TYPES,
  MCP_OUTCOMES,
  MCP_TOOL_ERROR_TEXT,
  createMcpBoundary,
  mcpAuditRecord,
  mcpBlockedResult,
  runMcpBoundaryConformance,
  toCallToolResult,
} from "./mcp-boundary.mjs";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/mcp-boundary.json", import.meta.url), "utf8"));

const SYNTHETIC = "SYNTHETIC_MCP_BOUNDARY_VALUE_0000";
/** The fake core's "key context" secret: detected only after `password":"`. */
const CONTEXTUAL = "synthetic-contextual-0000";

const LIMITS = {
  wholeInputLimits: { maxInputBytes: 4096, maxFindings: 16 },
  incrementalLimits: {
    maxInputCodeUnits: 64,
    maxBufferedCodeUnits: 64,
    maxTokenCodeUnits: 64,
    maxMultilineCodeUnits: 64,
  },
  traversalLimits: { maxDepth: 6, maxNodes: 64 },
};

class FakeScanError extends Error {
  constructor(code, message = "fixed message") {
    super(message);
    this.code = code;
  }
}

function finding(action, start, end) {
  return { id: "finding-1", type: "synthetic", detector: "fake", confidence: "high", action, obfuscation: "none", start, end, score: 0.9 };
}

/**
 * A fake core: redacts SYNTHETIC anywhere, and redacts CONTEXTUAL only when
 * it follows `password":"` (the way key-context detection behaves), so the
 * key-context check has something to catch. Its incremental session enforces
 * `maxInputCodeUnits` like the real core.
 */
function fakeApi() {
  function scan(text) {
    let index = text.indexOf(SYNTHETIC);
    if (index !== -1) {
      return { text: text.replace(SYNTHETIC, "<SECRET_1>"), findings: [finding("redact", index, index + SYNTHETIC.length)] };
    }
    index = text.indexOf(`password":"${CONTEXTUAL}`);
    if (index !== -1) {
      const start = index + 'password":"'.length;
      return { text: text.replace(CONTEXTUAL, "<SECRET_1>"), findings: [finding("redact", start, start + CONTEXTUAL.length)] };
    }
    return { text, findings: [] };
  }
  const api = {
    aborts: 0,
    scanAndRedact: (text) => scan(text),
    createIncrementalSanitizer({ limits }) {
      let buffer = "";
      return {
        append(chunk) {
          buffer += chunk;
          if (buffer.length > limits.maxInputCodeUnits) throw new FakeScanError("INPUT_LIMIT_EXCEEDED");
          return { text: "", findings: [] };
        },
        finalize: () => scan(buffer),
        abort() {
          api.aborts += 1;
          buffer = "";
        },
      };
    },
  };
  return api;
}

function setup({ binaryContent, api = fakeApi() } = {}) {
  const events = [];
  const base = createAiContextBoundary(api, { ...LIMITS, onFinding: (f, context) => events.push({ finding: f, context }) });
  return { api, events, mcp: createMcpBoundary(base, { binaryContent }) };
}

/** A producer that counts pulls and records whether it was closed. */
function countingProducer(chunks) {
  const state = { pulled: 0, closed: false };
  async function* generate() {
    try {
      for (const chunk of chunks) {
        state.pulled += 1;
        yield chunk;
      }
    } finally {
      state.closed = true;
    }
  }
  return { chunks: generate(), state };
}

test("the fixture is well formed and names only contract outcomes, reasons, labels, and block types", () => {
  assert.equal(fixture.schemaVersion, 1);
  assert.deepEqual(fixture.safeFindingFields, SAFE_FINDING_FIELDS);
  assert.deepEqual(fixture.contentTypes, MCP_CONTENT_TYPES);
  assert.deepEqual(fixture.fixedResults.blocked.content[0].text, MCP_BLOCKED_TEXT);
  assert.deepEqual(fixture.fixedResults.toolError.content[0].text, MCP_TOOL_ERROR_TEXT);
  const ids = fixture.cases.map((testCase) => testCase.id);
  assert.equal(new Set(ids).size, ids.length, "case IDs are unique");
  const operations = new Set(["toolResult", "toolArguments", "toolCall", "streamedToolResult"]);
  const outcomesSeen = new Set();
  const reasonsSeen = new Set();
  for (const testCase of fixture.cases) {
    assert.ok(operations.has(testCase.operation), testCase.id);
    assert.ok(Array.isArray(testCase.secrets), `${testCase.id}: secrets list`);
    const outcome = testCase.expected;
    assert.ok(MCP_OUTCOMES.includes(outcome.outcome), testCase.id);
    outcomesSeen.add(outcome.outcome);
    if (outcome.outcome === "blocked") {
      assert.ok(BLOCK_REASONS.includes(outcome.reason), testCase.id);
      reasonsSeen.add(outcome.reason);
    }
    if (outcome.outcome !== "ok") {
      assert.equal("value" in outcome || "findings" in outcome, false, `${testCase.id}: non-ok outcome carries data`);
    }
    for (const found of outcome.findings ?? []) {
      assert.deepEqual(Object.keys(found), SAFE_FINDING_FIELDS, `${testCase.id}: finding field order`);
    }
  }
  assert.deepEqual([...outcomesSeen].sort(), [...MCP_OUTCOMES].sort(), "every outcome has a case");
  assert.deepEqual(
    [...reasonsSeen].sort(),
    ["core_error", "limit_exceeded", "policy", "unsupported_value"],
    "every reachable block reason has a case (lifecycle is the AI-context fixture's)",
  );
  // The acceptance criteria's five coverage areas each have at least one case.
  const has = (predicate) => fixture.cases.some(predicate);
  assert.ok(has((c) => c.operation === "toolResult" && c.result?.content?.some?.((b) => b.type === "text")), "text");
  assert.ok(has((c) => c.result?.structuredContent !== undefined), "nested structured content");
  assert.ok(has((c) => c.operation === "streamedToolResult" && c.chunks.length > 1 && c.expected.outcome === "ok"), "streaming split");
  assert.ok(has((c) => c.producer?.abortBefore !== undefined), "cancellation");
  assert.ok(has((c) => c.expected.outcome === "blocked"), "blocked results");
});

test("a whole result is one value: content, structuredContent, and _meta are all scanned", () => {
  const { mcp, events } = setup();
  const outcome = mcp.sanitizeToolResult({
    content: [{ type: "text", text: `a ${SYNTHETIC}` }],
    structuredContent: { deep: [{ value: `b ${SYNTHETIC}` }] },
    _meta: { trace: `c ${SYNTHETIC}` },
    isError: false,
  });
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(outcome.value, {
    content: [{ type: "text", text: "a <SECRET_1>" }],
    structuredContent: { deep: [{ value: "b <SECRET_1>" }] },
    _meta: { trace: "c <SECRET_1>" },
    isError: false,
  });
  assert.equal(JSON.stringify({ outcome, events }).includes(SYNTHETIC), false);
  assert.deepEqual(new Set(events.map((event) => event.context.boundary)), new Set([MCP_BOUNDARY_LABELS.result]));
  for (const event of events) assert.deepEqual(Object.keys(event.finding), SAFE_FINDING_FIELDS);
});

test("the key-context check blocks a structured secret that only its key identifies", () => {
  const { mcp } = setup();
  const text = JSON.stringify({ password: CONTEXTUAL });
  // The text copy alone is redacted in place: its key context is in the text.
  assert.equal(mcp.sanitizeToolResult({ content: [{ type: "text", text }] }).value.content[0].text, '{"password":"<SECRET_1>"}');
  // The structured copy cannot be mapped back onto its leaf, so the result blocks.
  const outcome = mcp.sanitizeToolResult({ content: [{ type: "text", text }], structuredContent: { password: CONTEXTUAL } });
  assert.deepEqual(outcome, { outcome: "blocked", reason: "policy" });
  assert.deepEqual(mcp.sanitizeToolArguments({ password: CONTEXTUAL }), { outcome: "blocked", reason: "policy" });
});

test("binary payloads block by default and pass unscanned, in place, only on opt-in", () => {
  const image = { type: "image", mimeType: "image/png", data: "U1lOVEhFVElD", annotations: { priority: 1 } };
  const blob = { type: "resource", resource: { uri: "file:///x.bin", blob: "U1lOVEhFVElD", mimeType: "application/octet-stream" } };
  for (const block of [image, { type: "audio", data: "U1lOVEhFVElD", mimeType: "audio/wav" }, blob]) {
    assert.deepEqual(setup().mcp.sanitizeToolResult({ content: [block] }), { outcome: "blocked", reason: "unsupported_value" });
  }
  const { mcp } = setup({ binaryContent: "pass" });
  const outcome = mcp.sanitizeToolResult({ content: [image, blob, { type: "text", text: SYNTHETIC }] });
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(outcome.value.content[0], image);
  assert.deepEqual(Object.keys(outcome.value.content[0]), Object.keys(image), "key order is preserved");
  assert.deepEqual(outcome.value.content[1], blob);
  assert.deepEqual(Object.keys(outcome.value.content[1].resource), Object.keys(blob.resource));
  assert.equal(outcome.value.content[2].text, "<SECRET_1>");
  // Opting in never passes a non-string payload.
  assert.deepEqual(mcp.sanitizeToolResult({ content: [{ type: "image", data: { nested: SYNTHETIC } }] }), {
    outcome: "blocked",
    reason: "unsupported_value",
  });
  assert.throws(() => createMcpBoundary(createAiContextBoundary(fakeApi(), LIMITS), { binaryContent: "scan" }), TypeError);
});

test("a block type outside the protocol revisions blocks the whole result", () => {
  const { mcp } = setup();
  assert.deepEqual(mcp.sanitizeToolResult({ content: [{ type: "text", text: "ok" }, { type: "video", uri: "x" }] }), {
    outcome: "blocked",
    reason: "unsupported_value",
  });
});

test("arguments are opt-in, labelled tool-arguments, and never forwarded on a non-ok outcome", () => {
  const { mcp, events } = setup();
  const outcome = mcp.sanitizeToolArguments({ query: SYNTHETIC });
  assert.deepEqual(outcome.value, { query: "<SECRET_1>" });
  assert.deepEqual(events.map((event) => event.context), [{ boundary: MCP_BOUNDARY_LABELS.arguments }]);
  assert.deepEqual(mcp.sanitizeToolArguments(undefined), { outcome: "ok", value: undefined, findings: [] });
  assert.deepEqual(mcp.sanitizeToolArguments([SYNTHETIC]), { outcome: "blocked", reason: "unsupported_value" });
});

test("a failing tool becomes tool_error and its error is never read", async () => {
  const { mcp } = setup();
  let read = false;
  const error = {
    get message() {
      read = true;
      return SYNTHETIC;
    },
  };
  const outcome = await mcp.sanitizeToolCall(async () => {
    throw error;
  });
  assert.deepEqual(outcome, { outcome: "tool_error" });
  assert.equal(read, false);
  assert.deepEqual(toCallToolResult(outcome), { content: [{ type: "text", text: MCP_TOOL_ERROR_TEXT }], isError: true });
});

test("a stream stops pulling and closes the producer as soon as it stops accepting", async () => {
  const { mcp, api } = setup();
  const { chunks, state } = countingProducer(Array.from({ length: 10 }, () => "0123456789abcdef"));
  const outcome = await mcp.sanitizeStreamedToolResult(chunks);
  assert.deepEqual(outcome, { outcome: "blocked", reason: "limit_exceeded", code: "INPUT_LIMIT_EXCEEDED" });
  assert.equal(state.pulled, 5, "the chunk that crossed the limit is the last one pulled");
  assert.equal(state.closed, true);
  assert.equal(api.aborts, 1);
});

test("a stream split is redacted as one secret, and released as one text block", async () => {
  const { mcp } = setup();
  const { chunks, state } = countingProducer([SYNTHETIC.slice(0, 9), SYNTHETIC.slice(9)]);
  const outcome = await mcp.sanitizeStreamedToolResult(chunks);
  assert.deepEqual(outcome.value, { content: [{ type: "text", text: "<SECRET_1>" }] });
  assert.equal(state.closed, true);
});

test("an AbortSignal mid-stream stops pulling and delivers nothing", async () => {
  const { mcp } = setup();
  const controller = new AbortController();
  const state = { pulled: 0, closed: false };
  async function* chunks() {
    try {
      state.pulled += 1;
      yield "ordinary ";
      controller.abort();
      state.pulled += 1;
      yield SYNTHETIC;
      state.pulled += 1;
      yield "never pulled";
    } finally {
      state.closed = true;
    }
  }
  const outcome = await mcp.sanitizeStreamedToolResult(chunks(), { signal: controller.signal });
  assert.deepEqual(outcome, { outcome: "aborted" });
  assert.equal(state.pulled, 2);
  assert.equal(state.closed, true);
  assert.equal(toCallToolResult(outcome), null);
});

test("every non-ok outcome maps onto a fixed, input-free result and audit record", () => {
  assert.deepEqual(toCallToolResult({ outcome: "blocked", reason: "core_error", code: "POLICY_FAILURE" }), mcpBlockedResult());
  assert.notEqual(mcpBlockedResult(), mcpBlockedResult(), "a fresh object each call, so a host cannot mutate the constant");
  assert.throws(() => toCallToolResult({ outcome: "partial" }), TypeError);
  const record = mcpAuditRecord({ outcome: "blocked", reason: "limit_exceeded", code: "INPUT_LIMIT_EXCEEDED" }, "result");
  assert.deepEqual(record, { stage: "result", outcome: "blocked", reason: "limit_exceeded", code: "INPUT_LIMIT_EXCEEDED" });
  assert.ok(Object.keys(record).every((key) => MCP_AUDIT_FIELDS.includes(key)));
  assert.deepEqual(mcpAuditRecord({ outcome: "ok", value: SYNTHETIC, findings: [] }, "arguments"), { stage: "arguments", outcome: "ok" });
});

test("the runner rejects a core that lets a secret through, naming only the case", async () => {
  const passthrough = {
    scanAndRedact: (text) => ({ text, findings: [] }),
    createIncrementalSanitizer: () => ({
      append: () => ({ text: "", findings: [] }),
      finalize: () => ({ text: "", findings: [] }),
      abort: () => {},
    }),
  };
  await assert.rejects(runMcpBoundaryConformance(passthrough, fixture), (error) => {
    assert.match(error.message, /^mcp-boundary [a-z0-9-]+: /);
    for (const testCase of fixture.cases) {
      for (const secret of testCase.secrets) assert.equal(error.message.includes(secret), false);
    }
    return true;
  });
});

test("the runner rejects an implementation that forwards binary content unscanned by default", async () => {
  const leaky = (api, options) => {
    const real = createMcpBoundary(createAiContextBoundary(api, options), { binaryContent: "pass" });
    return real;
  };
  const onlyBinary = { ...fixture, cases: fixture.cases.filter((c) => c.id === "result-image-blocked-by-default") };
  await assert.rejects(
    runMcpBoundaryConformance(fakeApi(), onlyBinary, { createBoundary: leaky }),
    /^Error: mcp-boundary result-image-blocked-by-default: outcome$/,
  );
});
