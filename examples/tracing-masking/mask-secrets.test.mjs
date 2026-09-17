import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { fakeScanAndRedact } from "./fixtures/fake-scanner.mjs";
import { BLOCK_MARKER, CYCLE_MARKER, ERROR_MARKER, LIMIT_MARKER, maskSecretsWith } from "./mask-secrets.mjs";

const fixturesPath = fileURLToPath(new URL("./fixtures/mask-secrets-cases.json", import.meta.url));
const { cases } = JSON.parse(readFileSync(fixturesPath, "utf-8"));

test("shared fixture set: nested objects, arrays, chat messages, tool calls, unicode", () => {
  for (const { name, input, expected } of cases) {
    assert.deepEqual(maskSecretsWith(fakeScanAndRedact, input), expected, `case: ${name}`);
  }
});

test("large strings are scanned in full when within the size limit", () => {
  const input = { blob: "x".repeat(3000) + " SECRET_TOKEN_9 " + "y".repeat(3000) };
  const expected = { blob: "x".repeat(3000) + " <SECRET_1> " + "y".repeat(3000) };
  assert.deepEqual(maskSecretsWith(fakeScanAndRedact, input), expected);
});

test("a block finding replaces the whole leaf, never a partial value", () => {
  const result = maskSecretsWith(fakeScanAndRedact, { key: "prefix BLOCK_ME suffix" });
  assert.equal(result.key, BLOCK_MARKER);
  assert.equal(JSON.stringify(result).includes("prefix"), false);
  assert.equal(JSON.stringify(result).includes("suffix"), false);
});

test("a core failure fails closed and never surfaces the error or the input", () => {
  const result = maskSecretsWith(fakeScanAndRedact, { key: "trigger BOOM here" });
  assert.equal(result.key, ERROR_MARKER);
  assert.equal(JSON.stringify(result).includes("BOOM"), false);
});

test("a scanAndRedact that throws NOT_INITIALIZED-shaped errors fails closed", () => {
  const uninitialized = () => {
    const error = new Error("redact-secret is not initialized; await initialize() before this call.");
    error.code = "NOT_INITIALIZED";
    throw error;
  };
  const result = maskSecretsWith(uninitialized, { key: "any input" });
  assert.equal(result.key, ERROR_MARKER);
});

test("numbers, booleans, null, and non-plain objects are left unchanged", () => {
  const when = new Date("2026-01-01T00:00:00.000Z");
  const input = { count: 1, active: false, missing: null, when };
  const result = maskSecretsWith(fakeScanAndRedact, input);
  assert.equal(result.count, 1);
  assert.equal(result.active, false);
  assert.equal(result.missing, null);
  assert.equal(result.when, when);
});

test("depth beyond the limit is marked rather than walked", () => {
  const input = { a: { b: { c: "SECRET_TOKEN_1" } } };
  const result = maskSecretsWith(fakeScanAndRedact, input, { limits: { maxDepth: 1 } });
  assert.equal(result.a, LIMIT_MARKER);
});

test("array and object entries beyond the size limit are dropped, never passed through", () => {
  const arrayResult = maskSecretsWith(fakeScanAndRedact, ["a", "b", "c"], { limits: { maxArrayLength: 2 } });
  assert.deepEqual(arrayResult, ["a", "b"]);

  const objectResult = maskSecretsWith(fakeScanAndRedact, { a: "1", b: "2", c: "3" }, { limits: { maxObjectKeys: 2 } });
  assert.deepEqual(Object.keys(objectResult), ["a", "b"]);
});

test("the total-leaf budget bounds work across the whole call, not per branch", () => {
  const input = { a: "SECRET_TOKEN_1", b: "SECRET_TOKEN_2", c: "SECRET_TOKEN_3" };
  const result = maskSecretsWith(fakeScanAndRedact, input, { limits: { maxTotalLeaves: 2 } });
  assert.equal(result.a, "<SECRET_1>");
  assert.equal(result.b, "<SECRET_1>");
  assert.equal(result.c, LIMIT_MARKER);
});

test("a cycle is marked rather than recursed into forever", () => {
  const input = { name: "root" };
  input.self = input;
  const result = maskSecretsWith(fakeScanAndRedact, input);
  assert.equal(result.name, "root");
  assert.equal(result.self, CYCLE_MARKER);
});

test("a string too long for the size limit is marked, not scanned", () => {
  const input = { blob: "a".repeat(50) };
  const result = maskSecretsWith(fakeScanAndRedact, input, { limits: { maxStringLength: 10 } });
  assert.equal(result.blob, LIMIT_MARKER);
});

test("rejects a non-function scanAndRedact", () => {
  assert.throws(() => maskSecretsWith(null, {}), TypeError);
});

test("preserves prototype-named JSON keys as redacted own data", () => {
  const input = JSON.parse('{"__proto__":{"value":"SECRET_TOKEN_1"},"constructor":"SECRET_TOKEN_2","toString":"SECRET_TOKEN_3"}');
  const result = maskSecretsWith(fakeScanAndRedact, input);
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(Object.hasOwn(result, "__proto__"), true);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), JSON.parse('{"__proto__":{"value":"<SECRET_1>"},"constructor":"<SECRET_1>","toString":"<SECRET_1>"}'));
  assert.equal(input.__proto__.value, "SECRET_TOKEN_1");
});
