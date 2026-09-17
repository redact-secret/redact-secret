import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { fakeScanAndRedact } from "./fixtures/fake-scanner.mjs";
import { BLOCK_MARKER, ERROR_MARKER, maskLogValueWith } from "./mask-log-value.mjs";
import { createRedactingLogMethodWith } from "./pino-hook.mjs";

const fixturesPath = fileURLToPath(new URL("./fixtures/logging-redaction-cases.json", import.meta.url));
const { cases } = JSON.parse(readFileSync(fixturesPath, "utf-8"));

test("shared fixture set: message strings, merging-object fields, nesting, arrays, unicode", () => {
  for (const { name, input, expected } of cases) {
    assert.deepEqual(maskLogValueWith(fakeScanAndRedact, input), expected, `case: ${name}`);
  }
});

function spyMethod() {
  const calls = [];
  function method(...args) {
    calls.push({ receiver: this, args });
  }
  return { method, calls };
}

test("a secret in a plain string message is redacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  const logger = { name: "logger" };
  hook.call(logger, ["token is SECRET_TOKEN_1 here"], method, 30);
  assert.deepEqual(calls, [{ receiver: logger, args: ["token is <SECRET_1> here"] }]);
});

test("a secret in a merging-object string field is redacted alongside the message", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, [{ authHeader: "Bearer SECRET_TOKEN_1" }, "request received"], method, 30);
  assert.deepEqual(calls[0].args, [{ authHeader: "Bearer <SECRET_1>" }, "request received"]);
});

test("a secret in a printf-style interpolation value is redacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["user %s presented %s", "alice", "SECRET_TOKEN_1"], method, 30);
  assert.deepEqual(calls[0].args, ["user %s presented %s", "alice", "<SECRET_1>"]);
});

test("a bare leading Error is normalized to { err }, message, ...rest -- and both are redacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  const err = new Error("failed with SECRET_TOKEN_1");
  hook.call({}, [err], method, 50);
  const [mergingObject, msg] = calls[0].args;
  assert.equal(msg, "failed with <SECRET_1>");
  assert.equal(mergingObject.err.message, "failed with <SECRET_1>");
  assert.equal(typeof mergingObject.err.stack, "string");
  assert.equal(JSON.stringify(calls[0].args).includes("SECRET_TOKEN_1"), false);
});

test("an Error nested inside a merging object is redacted before pino's own serializer sees it", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  const err = new Error("db write failed: SECRET_TOKEN_1");
  hook.call({}, [{ err }, "query failed"], method, 50);
  const [mergingObject] = calls[0].args;
  assert.equal(mergingObject.err.message, "db write failed: <SECRET_1>");
  assert.equal(JSON.stringify(calls[0].args).includes("SECRET_TOKEN_1"), false);
});

test("a block finding replaces the whole message, not a partial value", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["prefix BLOCK_ME suffix"], method, 30);
  assert.equal(calls[0].args[0], BLOCK_MARKER);
});

test("a core scan failure fails closed and never surfaces the raw text or the error", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["trigger BOOM here"], method, 30);
  assert.equal(calls[0].args[0], ERROR_MARKER);
});

test("method is invoked exactly once via apply, with the logger as receiver", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  const logger = { name: "receiver-check" };
  hook.call(logger, ["plain message, no secret"], method, 30);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].receiver, logger);
});

test("numbers, booleans, and non-string interpolation values pass through unchanged", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["count is %d, active is %s", 3, true], method, 30);
  assert.deepEqual(calls[0].args, ["count is %d, active is %s", 3, true]);
});

test("rejects a non-function scanAndRedact", () => {
  assert.throws(() => createRedactingLogMethodWith(null), TypeError);
});

test("preserves prototype-named JSON keys as redacted own data", () => {
  const input = JSON.parse('{"__proto__":{"value":"SECRET_TOKEN_1"},"constructor":"SECRET_TOKEN_2","toString":"SECRET_TOKEN_3"}');
  const result = maskLogValueWith(fakeScanAndRedact, input);
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(Object.hasOwn(result, "__proto__"), true);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), JSON.parse('{"__proto__":{"value":"<SECRET_1>"},"constructor":"<SECRET_1>","toString":"<SECRET_1>"}'));
  assert.equal(input.__proto__.value, "SECRET_TOKEN_1");
});

test("preserves an Error's own __proto__ data without changing the output prototype", () => {
  const error = new Error("ordinary message");
  Object.defineProperty(error, "__proto__", { value: { detail: "SECRET_TOKEN_1" }, enumerable: true });
  const result = maskLogValueWith(fakeScanAndRedact, error);
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(Object.hasOwn(result, "__proto__"), true);
  assert.deepEqual(result.__proto__, { detail: "<SECRET_1>" });
});
