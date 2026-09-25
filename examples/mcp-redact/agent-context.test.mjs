import assert from "node:assert/strict";
import test from "node:test";

import { buildSafeContext, createGoldenPathBoundary, createGoldenPathBoundaryWith, EXAMPLE_LIMITS } from "./agent-context.mjs";
import { fakeCore, uninitializedCore } from "./fixtures/fake-core.mjs";

function setup(overrides = {}) {
  const events = [];
  const boundary = createGoldenPathBoundaryWith(fakeCore, {
    onFinding: (finding, context) => events.push({ boundary: context.boundary, action: finding.action }),
    ...overrides,
  });
  return { boundary, events };
}

const { boundary } = setup();

// --- the four policy actions -------------------------------------------------

test("allow — clean input and no tool call produce a one-message safe context", async () => {
  const result = await buildSafeContext({ boundary, userInput: "hello" });
  assert.deepEqual(result, { outcome: "ok", value: [{ role: "user", content: "hello" }], findings: [] });
});

test("redact — a secret in user input is redacted before context construction", async () => {
  const result = await buildSafeContext({ boundary, userInput: "my token is SECRET_TOKEN_1" });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.value, [{ role: "user", content: "my token is <SECRET_1>" }]);
  assert.equal(result.findings[0].action, "redact");
});

test("warn — a warning in user input passes through and is still reported", async () => {
  const { boundary: audited, events } = setup();
  const result = await buildSafeContext({ boundary: audited, userInput: "WARN_ME" });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.value, [{ role: "user", content: "WARN_ME" }]);
  assert.deepEqual(events, [{ boundary: "user-input", action: "warn" }]);
});

test("block at the input stage never dispatches a tool, never builds context, and carries no findings", async () => {
  let called = false;
  const { boundary: audited, events } = setup();
  const result = await buildSafeContext({
    boundary: audited,
    userInput: "BLOCK_ME",
    callTool: async () => {
      called = true;
      return { content: [] };
    },
    buildToolRequest: () => ({ name: "x" }),
  });
  assert.deepEqual(result, { outcome: "blocked", reason: "policy", stage: "input" });
  assert.equal(called, false);
  // Auditing still sees the finding, through telemetry only.
  assert.deepEqual(events, [{ boundary: "user-input", action: "block" }]);
});

// --- tool result -> scan -> context construction -----------------------------

test("a tool result is sanitized before it enters context", async () => {
  const result = await buildSafeContext({
    boundary,
    userInput: "run the tool",
    callTool: async (request) => ({ content: [{ type: "text", text: `ran ${request.name}: SECRET_TOKEN_1` }] }),
    buildToolRequest: () => ({ name: "read_file" }),
  });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.value[1], {
    role: "tool",
    content: { content: [{ type: "text", text: "ran read_file: <SECRET_1>" }] },
  });
});

test("block at the tool stage discards the context and never retains the leaked value", async () => {
  const result = await buildSafeContext({
    boundary,
    userInput: "run the tool",
    callTool: async () => ({ content: [{ type: "text", text: "leak BLOCK_ME here" }] }),
    buildToolRequest: () => ({ name: "x" }),
  });
  assert.deepEqual(result, { outcome: "blocked", reason: "policy", stage: "tool" });
});

test("#610: a structured tool result with a secret in a key, a non-JSON value, or past a limit blocks the turn", async () => {
  for (const [structuredContent, reason] of [
    [{ SECRET_TOKEN_1: "value" }, "policy"],
    [{ when: new Date(0) }, "unsupported_value"],
    [JSON.parse(`${"[".repeat(9)}"x"${"]".repeat(9)}`), "limit_exceeded"],
  ]) {
    const result = await buildSafeContext({
      boundary,
      userInput: "run the tool",
      callTool: async () => ({ content: [], structuredContent }),
    });
    assert.deepEqual(result, { outcome: "blocked", reason, stage: "tool" });
  }
});

test("tool dispatch is built from the sanitized input text, never the raw one", async () => {
  let seenText;
  await buildSafeContext({
    boundary,
    userInput: "carrying SECRET_TOKEN_1 along",
    callTool: async (request) => {
      seenText = request.text;
      return { content: [{ type: "text", text: "ok" }] };
    },
    buildToolRequest: (safeText) => ({ text: safeText }),
  });
  assert.equal(seenText, "carrying <SECRET_1> along");
});

// --- fixed, input-free failures ----------------------------------------------

test("#610: oversized input is refused by the core's whole-input limit before any detection", async () => {
  const userInput = "x".repeat(EXAMPLE_LIMITS.wholeInputLimits.maxInputBytes + 1);
  const result = await buildSafeContext({ boundary, userInput });
  assert.deepEqual(result, { outcome: "blocked", reason: "limit_exceeded", code: "INPUT_LIMIT_EXCEEDED", stage: "input" });
});

test("calling before initialize() fails closed with the core's own NOT_INITIALIZED", async () => {
  const result = await buildSafeContext({
    boundary: createGoldenPathBoundaryWith(uninitializedCore),
    userInput: "SECRET_TOKEN_1",
  });
  assert.deepEqual(result, { outcome: "blocked", reason: "core_error", code: "NOT_INITIALIZED", stage: "input" });
});

test("the live boundary fails closed when the core cannot be loaded, and never returns input", async () => {
  // This example project installs no core (its tests inject one), so the
  // live factory's core import fails: every operation is core_error.
  const live = await createGoldenPathBoundary();
  const result = await buildSafeContext({ boundary: live, userInput: "SECRET_TOKEN_1" });
  assert.deepEqual(result, { outcome: "blocked", reason: "core_error", stage: "input" });
});

test("any other core failure fails closed as core_error, with nothing derived from input", async () => {
  const result = await buildSafeContext({ boundary, userInput: "BOOM" });
  assert.deepEqual(result, { outcome: "blocked", reason: "core_error", stage: "input" });
});

test("a throwing onFinding never breaks the call", async () => {
  const { boundary: audited } = setup({
    onFinding: () => {
      throw new Error("audit sink is down");
    },
  });
  const result = await buildSafeContext({ boundary: audited, userInput: "SECRET_TOKEN_1" });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.value, [{ role: "user", content: "<SECRET_1>" }]);
});

test("a rejecting tool call is a host tool_error with no detail and nothing retained", async () => {
  const result = await buildSafeContext({
    boundary,
    userInput: "hello",
    callTool: async () => {
      throw new Error("AbortError: the operation was aborted near SECRET_TOKEN_1");
    },
    buildToolRequest: () => ({}),
  });
  assert.deepEqual(result, { outcome: "tool_error", stage: "tool" });
});

// --- cancellation and abort --------------------------------------------------

test("cancellation — an already-aborted signal short-circuits before scanning starts", async () => {
  let scanned = false;
  const counting = createGoldenPathBoundaryWith({
    ...fakeCore,
    scanAndRedact(text, options) {
      scanned = true;
      return fakeCore.scanAndRedact(text, options);
    },
  });
  const result = await buildSafeContext({ boundary: counting, userInput: "SECRET_TOKEN_1", signal: AbortSignal.abort() });
  assert.deepEqual(result, { outcome: "aborted", stage: "input" });
  assert.equal(scanned, false);
});

test("abort — the signal firing during the tool call discards the already-sanitized input", async () => {
  const controller = new AbortController();
  const result = await buildSafeContext({
    boundary,
    userInput: "hello SECRET_TOKEN_1",
    callTool: async () => {
      controller.abort();
      return { content: [{ type: "text", text: "ok" }] };
    },
    buildToolRequest: () => ({}),
    signal: controller.signal,
  });
  assert.deepEqual(result, { outcome: "aborted", stage: "tool" });
});

test("rejects a missing boundary", async () => {
  await assert.rejects(buildSafeContext({ userInput: "x" }), TypeError);
});

// --- end-to-end smoke test ---------------------------------------------------

test("smoke: a secret in user input and a secret in the tool result never reach the model-facing safe context", async () => {
  const result = await buildSafeContext({
    boundary,
    userInput: "look up my key SECRET_TOKEN_1 please",
    callTool: async (request) => ({
      content: [{ type: "text", text: `looked up ${request.query}: leaked DATABASE_URL=SECRET_TOKEN_2` }],
    }),
    buildToolRequest: (safeText) => ({ query: safeText }),
  });

  assert.equal(result.outcome, "ok");
  const serialized = JSON.stringify(result.value);
  assert.equal(serialized.includes("SECRET_TOKEN_1"), false);
  assert.equal(serialized.includes("SECRET_TOKEN_2"), false);
  assert.equal(serialized.includes("<SECRET_1>"), true);

  // What actually reaches "the model": the composed value, not each piece
  // in isolation, is what a caller forwards.
  const modelCall = async (messages) => JSON.stringify(messages);
  const sentToModel = await modelCall(result.value);
  assert.equal(sentToModel.includes("SECRET_TOKEN_1"), false);
  assert.equal(sentToModel.includes("SECRET_TOKEN_2"), false);
});
