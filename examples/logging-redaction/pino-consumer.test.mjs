/**
 * Issue #361's required regression: an actual, pinned pino `10.3.1`
 * consumer -- not a spy `method` standing in for pino -- wired through
 * `createRedactingLogMethodWith` (`./pino-hook.mjs`) to a captured
 * destination, asserting on the exact bytes pino writes. `pino` is now an
 * explicit devDependency, pinned to the same `10.3.1` `pino-hook.mjs`'s
 * module docstring documents and `README.md` describes as verified; adding
 * it here replaces that prior one-off, uncommitted verification with a real
 * regression test, per issue #361.
 *
 * `scanAndRedact` is the same deterministic fake `pino-hook.test.mjs` uses
 * (`fixtures/fake-scanner.mjs`) -- this test is about the pino integration
 * boundary (call-shape handling, message formatting, serializer ordering),
 * not the Rust core's detection accuracy, which the fake stands in for by
 * design (issue #361: "This is an example integration defect, not evidence
 * that the canonical detector misses the joined input. Keep detection in
 * the Rust core."). `base: null` and `timestamp: false` keep every line
 * deterministic (no pid/hostname/time fields) so full lines can be asserted
 * exactly, not just substrings.
 */

import assert from "node:assert/strict";
import test from "node:test";

import pino from "pino";

import { fakeScanAndRedact } from "./fixtures/fake-scanner.mjs";
import { createRedactingLogMethodWith } from "./pino-hook.mjs";

function capturingLogger(options = {}) {
  const chunks = [];
  const destination = {
    write(chunk) {
      chunks.push(chunk);
      return true;
    },
  };
  const logMethod = createRedactingLogMethodWith(fakeScanAndRedact, options);
  const logger = pino({ base: null, timestamp: false, hooks: { logMethod } }, destination);
  return {
    logger,
    lines: () => chunks.join("").trimEnd().split("\n").filter(Boolean).map((line) => JSON.parse(line)),
    raw: () => chunks.join(""),
  };
}

test("ordinary formatting with no secret reaches the destination unchanged", () => {
  const { logger, lines } = capturingLogger();
  logger.info("user %s logged in from %s", "alice", "10.0.0.1");
  assert.deepEqual(lines(), [{ level: 30, msg: "user alice logged in from 10.0.0.1" }]);
});

test("issue #361: a contextual assignment split across msg and an interpolation value is redacted before pino ever formats it", () => {
  const { logger, lines, raw } = capturingLogger();
  logger.info("api_key=%s", "SECRET_TOKEN_1");
  assert.deepEqual(lines(), [{ level: 30, msg: "api_key=<SECRET_1>" }]);
  assert.equal(raw().includes("SECRET_TOKEN_1"), false);
});

test("issue #361: a provider token split across two interpolation values is redacted", () => {
  const { logger, lines, raw } = capturingLogger();
  logger.info("token is %s%s", "SECRET_TOKEN_", "1");
  assert.deepEqual(lines(), [{ level: 30, msg: "token is <SECRET_1>" }]);
  assert.equal(raw().includes("SECRET_TOKEN_1"), false);
});

test("a secret confined to a merging-object field is redacted alongside an ordinary message", () => {
  const { logger, lines, raw } = capturingLogger();
  logger.info({ authHeader: "Bearer SECRET_TOKEN_1" }, "request received");
  assert.deepEqual(lines(), [{ level: 30, authHeader: "Bearer <SECRET_1>", msg: "request received" }]);
  assert.equal(raw().includes("SECRET_TOKEN_1"), false);
});

test("a merging object and a split interpolated message are both redacted in the same line", () => {
  const { logger, lines, raw } = capturingLogger();
  logger.info({ authHeader: "Bearer SECRET_TOKEN_1" }, "token is SECRET_TOKEN_%s", "2");
  assert.deepEqual(lines(), [{ level: 30, authHeader: "Bearer <SECRET_1>", msg: "token is <SECRET_1>" }]);
  assert.equal(raw().includes("SECRET_TOKEN_1"), false);
  assert.equal(raw().includes("SECRET_TOKEN_2"), false);
});

test("a bare Error's message and stack are redacted before pino's default err serializer runs", () => {
  const { logger, lines, raw } = capturingLogger();
  logger.error(new Error("failed with SECRET_TOKEN_1"));
  const [line] = lines();
  assert.equal(line.level, 50);
  assert.equal(line.msg, "failed with <SECRET_1>");
  assert.equal(line.err.message, "failed with <SECRET_1>");
  assert.equal(typeof line.err.stack, "string");
  assert.equal(raw().includes("SECRET_TOKEN_1"), false);
});

test("issue #361: a block finding on the joined message replaces the whole message pino writes", () => {
  const { logger, lines, raw } = capturingLogger();
  logger.info("prefix %s suffix", "BLOCK_ME");
  assert.deepEqual(lines(), [{ level: 30, msg: "[REDACTED:BLOCKED]" }]);
  assert.equal(raw().includes("BLOCK_ME"), false);
});

test("issue #361: a scanner failure on the joined message fails closed in the destination bytes", () => {
  const { logger, lines, raw } = capturingLogger();
  logger.info("trigger %s here", "BOOM");
  assert.deepEqual(lines(), [{ level: 30, msg: "[REDACTED:ERROR]" }]);
  assert.equal(raw().includes("BOOM"), false);
});

test("pino's own path-based redact still applies on top, to a field the value-based hook left untouched", () => {
  const chunks = [];
  const destination = { write: (chunk) => (chunks.push(chunk), true) };
  const logMethod = createRedactingLogMethodWith(fakeScanAndRedact);
  const logger = pino({ base: null, timestamp: false, hooks: { logMethod }, redact: ["req.headers.authorization"] }, destination);
  logger.info({ req: { headers: { authorization: "Bearer plain-not-a-detected-secret" } } }, "request received");
  const [line] = chunks.join("").trimEnd().split("\n").map((entry) => JSON.parse(entry));
  assert.deepEqual(line, {
    level: 30,
    req: { headers: { authorization: "[Redacted]" } },
    msg: "request received",
  });
});
