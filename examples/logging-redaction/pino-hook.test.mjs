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

test("a secret in a printf-style interpolation value is redacted -- msg and values joined into one scanned leaf, matching what pino itself would format", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["user %s presented %s", "alice", "SECRET_TOKEN_1"], method, 30);
  assert.deepEqual(calls[0].args, ["user alice presented <SECRET_1>"]);
});

test("issue #361: a secret split across the format string and an interpolation value is redacted -- neither leaf alone matches", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["token is SECRET_TOKEN_%s", "1"], method, 30);
  assert.deepEqual(calls[0].args, ["token is <SECRET_1>"]);
});

test("issue #361: a secret split across two interpolation values is redacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["token is %s%s", "SECRET_TOKEN_", "1"], method, 30);
  assert.deepEqual(calls[0].args, ["token is <SECRET_1>"]);
});

test("issue #361: a contextual assignment split from its value across msg and an interpolation value is redacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["api_key=%s", "SECRET_TOKEN_1"], method, 30);
  assert.deepEqual(calls[0].args, ["api_key=<SECRET_1>"]);
});

test("issue #361: a joined message that trips a block finding replaces the whole message, not a partial value", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["prefix %s suffix", "BLOCK_ME"], method, 30);
  assert.deepEqual(calls[0].args, [BLOCK_MARKER]);
});

test("issue #361: a scanner failure on the joined message fails closed", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["trigger %s here", "BOOM"], method, 30);
  assert.deepEqual(calls[0].args, [ERROR_MARKER]);
});

test("issue #361: a merging object plus a split interpolated message are both redacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, [{ authHeader: "Bearer SECRET_TOKEN_1" }, "token is SECRET_TOKEN_%s", "2"], method, 30);
  assert.deepEqual(calls[0].args, [{ authHeader: "Bearer <SECRET_1>" }, "token is <SECRET_1>"]);
});

test("issue #361: an unused trailing interpolation value is dropped from the joined message, matching pino's own quick-format-unescaped, and its secret is still redacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["no placeholders here", "SECRET_TOKEN_1"], method, 30);
  assert.deepEqual(calls[0].args, ["no placeholders here"]);
});

test("issue #361: ordinary formatting with no secret is unaffected", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["user %s logged in from %s", "alice", "10.0.0.1"], method, 30);
  assert.deepEqual(calls[0].args, ["user alice logged in from 10.0.0.1"]);
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

test("numbers and booleans are formatted into the joined message, matching pino's own quick-format-unescaped, and pass through unredacted", () => {
  const { method, calls } = spyMethod();
  const hook = createRedactingLogMethodWith(fakeScanAndRedact);
  hook.call({}, ["count is %d, active is %s", 3, true], method, 30);
  assert.deepEqual(calls[0].args, ["count is 3, active is true"]);
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
