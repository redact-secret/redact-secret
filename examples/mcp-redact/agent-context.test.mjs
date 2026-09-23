import assert from "node:assert/strict";
import test from "node:test";

import { buildSafeContext, redactUserInput } from "./agent-context.mjs";
import { fakeScanAndRedact } from "./fixtures/fake-scanner.mjs";

// --- redactUserInput -------------------------------------------------------

test("redactUserInput: allow — clean input passes through untouched, no findings", () => {
  const result = redactUserInput(fakeScanAndRedact, "hello there");
  assert.deepEqual(result, { outcome: "ok", text: "hello there", findings: [] });
});

test("redactUserInput: redact — a finding's span is replaced, the call continues", () => {
  const result = redactUserInput(fakeScanAndRedact, "here is SECRET_TOKEN_1 ok");
  assert.equal(result.outcome, "ok");
  assert.equal(result.text, "here is <SECRET_1> ok");
  assert.equal(result.findings[0].action, "redact");
});

test("redactUserInput: warn — text passes through unchanged, finding still reported", () => {
  const result = redactUserInput(fakeScanAndRedact, "WARN_ME please");
  assert.equal(result.outcome, "ok");
  assert.equal(result.text, "WARN_ME please");
  assert.equal(result.findings[0].action, "warn");
});

test("redactUserInput: block — a block finding blocks with no text or input retained", () => {
  const result = redactUserInput(fakeScanAndRedact, "BLOCK_ME now");
  assert.equal(result.outcome, "blocked");
  assert.equal(result.blockReason, "policy");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].action, "block");
  assert.equal("text" in result, false);
  assert.equal(JSON.stringify(result).includes("BLOCK_ME"), false);
});

test("redactUserInput: oversized input is rejected by length alone, scanAndRedact is never called", () => {
  let called = false;
  const scanAndRedact = () => {
    called = true;
    return { text: "", findings: [] };
  };
  const result = redactUserInput(scanAndRedact, "x".repeat(10), { limits: { maxInputLength: 5 } });
  assert.deepEqual(result, { outcome: "blocked", blockReason: "input_too_large", findings: [] });
  assert.equal(called, false);
});

test("redactUserInput: a scanAndRedact failure (including calling before initialize()) fails closed", () => {
  const result = redactUserInput(fakeScanAndRedact, "BOOM here");
  assert.deepEqual(result, { outcome: "blocked", blockReason: "core_error", findings: [] });
});

test("redactUserInput: rejects a non-function scanAndRedact or non-string text", () => {
  assert.throws(() => redactUserInput(null, "x"), TypeError);
  assert.throws(() => redactUserInput(fakeScanAndRedact, 123), TypeError);
});

// --- buildSafeContext --------------------------------------------------------

test("buildSafeContext: allow — clean input and no tool call produce a one-message safe context", async () => {
  const result = await buildSafeContext({ scanAndRedact: fakeScanAndRedact, userInput: "hello" });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.context.messages, [{ role: "user", content: "hello" }]);
  assert.deepEqual(result.findings, []);
});

test("buildSafeContext: redact — a secret in user input is redacted before context construction", async () => {
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "my token is SECRET_TOKEN_1",
  });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.context.messages, [{ role: "user", content: "my token is <SECRET_1>" }]);
});

test("buildSafeContext: warn — a warning in user input passes through and is still reported", async () => {
  const seen = [];
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "WARN_ME",
    onFinding: (finding, ctx) => seen.push({ scope: ctx.scope, action: finding.action }),
  });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.context.messages, [{ role: "user", content: "WARN_ME" }]);
  assert.deepEqual(seen, [{ scope: "input", action: "warn" }]);
});

test("buildSafeContext: block at the input stage never dispatches a tool and never builds context", async () => {
  let called = false;
  const callTool = async () => {
    called = true;
    return { content: [] };
  };
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "BLOCK_ME",
    callTool,
    buildToolRequest: () => ({ name: "x" }),
  });
  assert.equal(result.outcome, "blocked");
  assert.equal(result.stage, "input");
  assert.equal(result.blockReason, "policy");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].action, "block");
  assert.equal(called, false);
  assert.equal("context" in result, false);
});

test("buildSafeContext: a tool result is scanned before entering context (tool result -> scan -> context construction)", async () => {
  const callTool = async (request) => ({
    content: [{ type: "text", text: `ran ${request.name}: SECRET_TOKEN_1` }],
  });
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "run the tool",
    callTool,
    buildToolRequest: () => ({ name: "read_file" }),
  });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.context.messages[1], {
    role: "tool",
    content: { content: [{ type: "text", text: "ran read_file: <SECRET_1>" }] },
  });
});

test("buildSafeContext: block at the tool stage discards context, never retains the leaked value", async () => {
  const callTool = async () => ({ content: [{ type: "text", text: "leak BLOCK_ME here" }] });
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "run the tool",
    callTool,
    buildToolRequest: () => ({ name: "x" }),
  });
  assert.equal(result.outcome, "blocked");
  assert.equal(result.stage, "tool");
  assert.equal("context" in result, false);
  assert.equal(JSON.stringify(result).includes("leak"), false);
});

test("buildSafeContext: tool dispatch is built from the sanitized input text, never the raw one", async () => {
  let seenText;
  const callTool = async (request) => {
    seenText = request.text;
    return { content: [{ type: "text", text: "ok" }] };
  };
  await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "carrying SECRET_TOKEN_1 along",
    callTool,
    buildToolRequest: (safeText) => ({ text: safeText }),
  });
  assert.equal(seenText, "carrying <SECRET_1> along");
});

test("buildSafeContext: initialization/core failure at the input stage fails closed like any other scanner error", async () => {
  const result = await buildSafeContext({ scanAndRedact: fakeScanAndRedact, userInput: "BOOM" });
  assert.deepEqual(result, { outcome: "blocked", stage: "input", blockReason: "core_error", findings: [] });
});

test("buildSafeContext: a throwing onFinding never breaks the call", async () => {
  const onFinding = () => {
    throw new Error("audit sink is down");
  };
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "SECRET_TOKEN_1",
    onFinding,
  });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.context.messages, [{ role: "user", content: "<SECRET_1>" }]);
});

test("buildSafeContext: cancellation — an already-aborted signal short-circuits before scanning starts", async () => {
  const controller = new AbortController();
  controller.abort();
  let scanCalled = false;
  const scanAndRedact = (text) => {
    scanCalled = true;
    return fakeScanAndRedact(text);
  };
  const result = await buildSafeContext({
    scanAndRedact,
    userInput: "SECRET_TOKEN_1",
    signal: controller.signal,
  });
  assert.deepEqual(result, { outcome: "aborted", findings: [] });
  assert.equal(scanCalled, false);
});

test("buildSafeContext: abort — the signal firing during the tool call discards the (already-sanitized) result", async () => {
  const controller = new AbortController();
  const callTool = async () => {
    controller.abort();
    return { content: [{ type: "text", text: "ok" }] };
  };
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "hello",
    callTool,
    buildToolRequest: () => ({}),
    signal: controller.signal,
  });
  assert.deepEqual(result, { outcome: "aborted", findings: [] });
});

test("buildSafeContext: a rejecting/aborted tool call blocks with no leaked detail, nothing retained", async () => {
  const callTool = async () => {
    throw new Error("AbortError: the operation was aborted");
  };
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "hello",
    callTool,
    buildToolRequest: () => ({}),
  });
  assert.equal(result.outcome, "blocked");
  assert.equal(result.stage, "tool");
  assert.equal(result.blockReason, "tool_call_failed");
  assert.equal(JSON.stringify(result).includes("AbortError"), false);
});

// --- end-to-end smoke test ---------------------------------------------------

test("smoke: a secret in user input and a secret in the tool result never reach the model-facing safe context", async () => {
  const callTool = async (request) => ({
    content: [{ type: "text", text: `looked up ${request.query}: leaked DATABASE_URL=SECRET_TOKEN_2` }],
  });
  const result = await buildSafeContext({
    scanAndRedact: fakeScanAndRedact,
    userInput: "look up my key SECRET_TOKEN_1 please",
    callTool,
    buildToolRequest: (safeText) => ({ query: safeText }),
  });

  assert.equal(result.outcome, "ok");
  const serialized = JSON.stringify(result.context);
  assert.equal(serialized.includes("SECRET_TOKEN_1"), false);
  assert.equal(serialized.includes("SECRET_TOKEN_2"), false);
  assert.equal(serialized.includes("<SECRET_1>"), true);

  // What actually reaches "the model" — proving the composed value, not
  // just each piece in isolation, is what a caller would forward.
  const modelCall = async (context) => JSON.stringify(context);
  const sentToModel = await modelCall(result.context);
  assert.equal(sentToModel.includes("SECRET_TOKEN_1"), false);
  assert.equal(sentToModel.includes("SECRET_TOKEN_2"), false);
});
