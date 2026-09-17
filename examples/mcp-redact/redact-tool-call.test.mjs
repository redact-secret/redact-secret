import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { fakeScanAndRedact } from "./fixtures/fake-scanner.mjs";
import {
  BLOCKED_MESSAGE,
  LIMIT_MARKER,
  buildBlockedResult,
  redactArguments,
  redactToolResult,
} from "./redact-tool-call.mjs";

const fixturesPath = fileURLToPath(new URL("./fixtures/mcp-redact-cases.json", import.meta.url));
const { resultCases, argumentCases } = JSON.parse(readFileSync(fixturesPath, "utf-8"));

test("shared fixture: result cases — text, JSON-in-text, multi-block, resource, structuredContent, unicode, block, core error", () => {
  for (const { name, input, expectedBlocked, expected } of resultCases) {
    const outcome = redactToolResult(fakeScanAndRedact, input);
    assert.equal(outcome.outcome, expectedBlocked ? "blocked" : "ok", `case: ${name}`);
    if (!expectedBlocked) {
      assert.deepEqual(outcome.result, expected, `case: ${name}`);
    } else {
      assert.equal("result" in outcome, false, `case: ${name} must not carry a result`);
    }
  }
});

test("shared fixture: argument cases — nested, array, unicode, block, core error", () => {
  for (const { name, input, expectedBlocked, expected } of argumentCases) {
    const outcome = redactArguments(fakeScanAndRedact, input);
    assert.equal(outcome.outcome, expectedBlocked ? "blocked" : "ok", `case: ${name}`);
    if (!expectedBlocked) {
      assert.deepEqual(outcome.arguments, expected, `case: ${name}`);
    } else {
      assert.equal("arguments" in outcome, false, `case: ${name} must not carry arguments`);
    }
  }
});

test("buildBlockedResult carries only the fixed message, marked as a tool error", () => {
  const result = buildBlockedResult();
  assert.equal(result.isError, true);
  assert.deepEqual(result.content, [{ type: "text", text: BLOCKED_MESSAGE }]);
});

test("a block finding never leaves plaintext, the matched value, or the input in the outcome", () => {
  const outcome = redactToolResult(fakeScanAndRedact, {
    content: [{ type: "text", text: "leaked BLOCK_ME right here" }],
  });
  assert.equal(outcome.outcome, "blocked");
  const serialized = JSON.stringify(outcome);
  assert.equal(serialized.includes("leaked"), false);
  assert.equal(serialized.includes("right here"), false);
});

test("findings are reported even on a blocked outcome, as safe metadata only", () => {
  const outcome = redactToolResult(fakeScanAndRedact, {
    content: [{ type: "text", text: "BLOCK_ME" }],
  });
  assert.equal(outcome.findings.length, 1);
  assert.equal(outcome.findings[0].action, "block");
  assert.equal(typeof outcome.findings[0].id, "string");
});

test("non-text content blocks (image, audio, resource_link) pass through unchanged", () => {
  const input = {
    content: [
      { type: "image", data: "AAAA", mimeType: "image/png" },
      { type: "audio", data: "BBBB", mimeType: "audio/wav" },
      { type: "resource_link", uri: "file:///x", name: "x" },
    ],
  };
  const outcome = redactToolResult(fakeScanAndRedact, input);
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(outcome.result, input);
});

test("depth beyond the limit is marked, not walked, and does not block the call", () => {
  const outcome = redactArguments(fakeScanAndRedact, { a: { b: { c: "SECRET_TOKEN_1" } } }, { limits: { maxDepth: 1 } });
  assert.equal(outcome.outcome, "ok");
  assert.equal(outcome.arguments.a, LIMIT_MARKER);
});

test("the total-leaf budget bounds a whole call, not per branch", () => {
  const outcome = redactArguments(
    fakeScanAndRedact,
    { a: "SECRET_TOKEN_1", b: "SECRET_TOKEN_2" },
    { limits: { maxTotalLeaves: 1 } },
  );
  assert.equal(outcome.outcome, "ok");
  assert.equal(outcome.arguments.a, "<SECRET_1>");
  assert.equal(outcome.arguments.b, LIMIT_MARKER);
});

test("rejects a non-function scanAndRedact", () => {
  assert.throws(() => redactToolResult(null, { content: [] }), TypeError);
  assert.throws(() => redactArguments(null, {}), TypeError);
});

test("content beyond maxContentBlocks is dropped, never passed through unscanned", () => {
  const input = { content: [{ type: "text", text: "a" }, { type: "text", text: "b" }, { type: "text", text: "c" }] };
  const outcome = redactToolResult(fakeScanAndRedact, input, { limits: { maxContentBlocks: 2 } });
  assert.equal(outcome.outcome, "ok");
  assert.equal(outcome.result.content.length, 2);
});
