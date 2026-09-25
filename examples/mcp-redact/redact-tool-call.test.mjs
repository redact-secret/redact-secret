import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createGoldenPathBoundaryWith, EXAMPLE_LIMITS } from "./agent-context.mjs";
import { fakeCore } from "./fixtures/fake-core.mjs";
import { BLOCKED_MESSAGE, buildBlockedResult, redactArguments, redactToolResult } from "./redact-tool-call.mjs";

const fixturesPath = fileURLToPath(new URL("./fixtures/mcp-redact-cases.json", import.meta.url));
const { resultCases, argumentCases } = JSON.parse(readFileSync(fixturesPath, "utf-8"));

function boundaryWithEvents(overrides = {}) {
  const events = [];
  const boundary = createGoldenPathBoundaryWith(fakeCore, {
    onFinding: (finding, context) => events.push({ action: finding.action, boundary: context.boundary }),
    ...overrides,
  });
  return { boundary, events };
}

const { boundary } = boundaryWithEvents();

test("shared fixture: result cases — text, JSON-in-text, multi-block, resource, structuredContent, unicode, block, core error", () => {
  for (const { name, input, expectedBlocked, expected } of resultCases) {
    const outcome = redactToolResult(boundary, input);
    assert.equal(outcome.outcome, expectedBlocked ? "blocked" : "ok", `case: ${name}`);
    if (!expectedBlocked) {
      assert.deepEqual(outcome.value, expected, `case: ${name}`);
    } else {
      assert.deepEqual(Object.keys(outcome).sort(), ["outcome", "reason"], `case: ${name} carries nothing else`);
    }
  }
});

test("shared fixture: argument cases — nested, array, unicode, block, core error", () => {
  for (const { name, input, expectedBlocked, expected } of argumentCases) {
    const outcome = redactArguments(boundary, input);
    assert.equal(outcome.outcome, expectedBlocked ? "blocked" : "ok", `case: ${name}`);
    if (!expectedBlocked) {
      assert.deepEqual(outcome.value, expected, `case: ${name}`);
    } else {
      assert.deepEqual(Object.keys(outcome).sort(), ["outcome", "reason"], `case: ${name} carries nothing else`);
    }
  }
});

test("block and core-failure outcomes carry the contract's fixed reasons", () => {
  assert.deepEqual(redactToolResult(boundary, { content: [{ type: "text", text: "BLOCK_ME" }] }), {
    outcome: "blocked",
    reason: "policy",
  });
  assert.deepEqual(redactToolResult(boundary, { content: [{ type: "text", text: "BOOM" }] }), {
    outcome: "blocked",
    reason: "core_error",
  });
});

test("buildBlockedResult carries only the fixed message, marked as a tool error", () => {
  const result = buildBlockedResult();
  assert.equal(result.isError, true);
  assert.deepEqual(result.content, [{ type: "text", text: BLOCKED_MESSAGE }]);
});

test("a block finding never leaves plaintext, the matched value, the input, or findings in the outcome", () => {
  const outcome = redactToolResult(boundary, { content: [{ type: "text", text: "leaked BLOCK_ME right here" }] });
  assert.equal(outcome.outcome, "blocked");
  const serialized = JSON.stringify(outcome);
  assert.equal(serialized.includes("leaked"), false);
  assert.equal(serialized.includes("right here"), false);
  assert.equal("findings" in outcome, false);
});

test("findings reach auditing through the boundary's telemetry, including on a blocked outcome", () => {
  const { boundary: audited, events } = boundaryWithEvents();
  redactToolResult(audited, { content: [{ type: "text", text: "BLOCK_ME" }] });
  redactArguments(audited, { token: "SECRET_TOKEN_1" });
  assert.deepEqual(events, [
    { action: "block", boundary: "tool-result" },
    { action: "redact", boundary: "context" },
  ]);
});

test("non-text content blocks (image, audio, resource_link) pass through unchanged", () => {
  const input = {
    content: [
      { type: "image", data: "AAAA", mimeType: "image/png" },
      { type: "audio", data: "BBBB", mimeType: "audio/wav" },
      { type: "resource_link", uri: "file:///x", name: "x" },
    ],
  };
  const outcome = redactToolResult(boundary, input);
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(outcome.value, input);
});

test("#610: depth beyond traversalLimits.maxDepth blocks the whole call; nothing is marked and passed on", () => {
  // Nine nested objects, the root included, one past maxDepth 8.
  const nested = { a: { b: { c: { d: { e: { f: { g: { h: { i: "SECRET_TOKEN_1" } } } } } } } } };
  assert.equal(EXAMPLE_LIMITS.traversalLimits.maxDepth, 8);
  assert.equal(redactArguments(boundary, nested.a).outcome, "ok");
  assert.deepEqual(redactArguments(boundary, nested), { outcome: "blocked", reason: "limit_exceeded" });
  assert.deepEqual(redactToolResult(boundary, { content: [], structuredContent: nested }), {
    outcome: "blocked",
    reason: "limit_exceeded",
  });
});

test("#610: more values than traversalLimits.maxNodes block the whole call", () => {
  const tight = createGoldenPathBoundaryWith(fakeCore, { traversalLimits: { maxDepth: 8, maxNodes: 2 } });
  assert.deepEqual(redactArguments(tight, { a: "SECRET_TOKEN_1", b: "SECRET_TOKEN_2" }), {
    outcome: "blocked",
    reason: "limit_exceeded",
  });
});

test("#610: content beyond maxContentBlocks blocks the whole result instead of being dropped", () => {
  const input = { content: [{ type: "text", text: "a" }, { type: "text", text: "b" }, { type: "text", text: "c" }] };
  assert.deepEqual(redactToolResult(boundary, input, { maxContentBlocks: 2 }), {
    outcome: "blocked",
    reason: "limit_exceeded",
  });
});

test("#610: a text leaf over wholeInputLimits.maxInputBytes blocks with the core's INPUT_LIMIT_EXCEEDED", () => {
  const huge = "x".repeat(EXAMPLE_LIMITS.wholeInputLimits.maxInputBytes + 1);
  assert.deepEqual(redactToolResult(boundary, { content: [{ type: "text", text: huge }] }), {
    outcome: "blocked",
    reason: "limit_exceeded",
    code: "INPUT_LIMIT_EXCEEDED",
  });
});

test("#610: object keys are scanned; a key that would be redacted blocks the value", () => {
  assert.deepEqual(redactArguments(boundary, { SECRET_TOKEN_1: "x" }), { outcome: "blocked", reason: "policy" });
  assert.deepEqual(
    redactToolResult(boundary, { content: [{ type: "text", text: '{"SECRET_TOKEN_1":"x"}' }] }),
    { outcome: "blocked", reason: "policy" },
  );
});

test("#610: a non-JSON value, a cycle, or a non-object result is unsupported_value", () => {
  const cyclic = { a: "x" };
  cyclic.self = cyclic;
  for (const args of [{ when: new Date(0) }, cyclic, { missing: undefined }]) {
    assert.deepEqual(redactArguments(boundary, args), { outcome: "blocked", reason: "unsupported_value" });
  }
  assert.deepEqual(redactToolResult(boundary, { content: [], structuredContent: { when: new Date(0) } }), {
    outcome: "blocked",
    reason: "unsupported_value",
  });
  for (const result of [null, "text", [], { content: "not an array" }, { content: [null] }]) {
    assert.deepEqual(redactToolResult(boundary, result), { outcome: "blocked", reason: "unsupported_value" });
  }
  assert.deepEqual(redactArguments(boundary, ["not", "an", "object"]), {
    outcome: "blocked",
    reason: "unsupported_value",
  });
});

test("an aborted signal ends the call before any scan", () => {
  const signal = AbortSignal.abort();
  assert.deepEqual(redactToolResult(boundary, { content: [{ type: "text", text: "x" }] }, { signal }), {
    outcome: "aborted",
  });
  assert.deepEqual(redactArguments(boundary, { a: "x" }, { signal }), { outcome: "aborted" });
});

test("rejects a missing boundary", () => {
  assert.throws(() => redactToolResult(null, { content: [] }), TypeError);
  assert.throws(() => redactArguments(() => {}, {}), TypeError);
});

test("preserves prototype-named JSON keys as redacted own data", () => {
  const input = JSON.parse(
    '{"__proto__":{"value":"SECRET_TOKEN_1"},"constructor":"SECRET_TOKEN_2","toString":"SECRET_TOKEN_3"}',
  );
  const result = redactArguments(boundary, input).value;
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(Object.hasOwn(result, "__proto__"), true);
  assert.deepEqual(
    JSON.parse(JSON.stringify(result)),
    JSON.parse('{"__proto__":{"value":"<SECRET_1>"},"constructor":"<SECRET_1>","toString":"<SECRET_1>"}'),
  );
  assert.equal(input.__proto__.value, "SECRET_TOKEN_1");
});
