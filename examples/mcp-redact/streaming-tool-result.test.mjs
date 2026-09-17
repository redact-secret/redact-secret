import assert from "node:assert/strict";
import test from "node:test";

import { createFakeIncrementalSanitizer } from "./fixtures/fake-incremental-sanitizer.mjs";
import { createStreamingToolResultRedactor } from "./streaming-tool-result.mjs";

const LIMITS = Object.freeze({
  maxInputCodeUnits: 10_000,
  maxBufferedCodeUnits: 200,
  maxTokenCodeUnits: 100,
  maxMultilineCodeUnits: 200,
});

test("a secret split across two chunks is redacted once the session finalizes", () => {
  const redactor = createStreamingToolResultRedactor(createFakeIncrementalSanitizer, { limits: LIMITS });
  // Neither chunk alone contains the full "SECRET_TOKEN_9" pattern.
  redactor.append("prefix SECRET_TOK");
  redactor.append("EN_9 suffix");
  const outcome = redactor.finalize();

  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(outcome.result, { content: [{ type: "text", text: "prefix <SECRET_1> suffix" }] });
  assert.equal(outcome.findings.length, 1);
  assert.equal(outcome.findings[0].action, "redact");
});

test("a block finding at finalize fails the whole session closed", () => {
  const redactor = createStreamingToolResultRedactor(createFakeIncrementalSanitizer, { limits: LIMITS });
  redactor.append("leaked ");
  redactor.append("BLOCK_ME here");
  const outcome = redactor.finalize();

  assert.equal(outcome.outcome, "blocked");
  assert.equal(outcome.blockReason, "policy");
  assert.equal("result" in outcome, false);
});

test("exceeding the declared buffer limit fails closed, never returning the accumulated text", () => {
  const redactor = createStreamingToolResultRedactor(createFakeIncrementalSanitizer, {
    limits: { ...LIMITS, maxBufferedCodeUnits: 10 },
  });
  redactor.append("well within the limit for the first chunk, ");
  redactor.append("and this pushes it over the declared bound");
  const outcome = redactor.finalize();

  assert.equal(outcome.outcome, "blocked");
  assert.equal(outcome.blockReason, "limit_exceeded");
  assert.equal("result" in outcome, false);
});

test("append is a no-op once the session is already blocked", () => {
  const redactor = createStreamingToolResultRedactor(createFakeIncrementalSanitizer, {
    limits: { ...LIMITS, maxBufferedCodeUnits: 5 },
  });
  redactor.append("way over the five character limit");
  // The session already threw and aborted; further appends must not throw
  // or resurrect it.
  assert.doesNotThrow(() => redactor.append("more"));
  const outcome = redactor.finalize();
  assert.equal(outcome.outcome, "blocked");
});

test("a clean session with no findings returns the assembled text untouched", () => {
  const redactor = createStreamingToolResultRedactor(createFakeIncrementalSanitizer, { limits: LIMITS });
  redactor.append("nothing ");
  redactor.append("sensitive here");
  const outcome = redactor.finalize();
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(outcome.result, { content: [{ type: "text", text: "nothing sensitive here" }] });
});

test("finalize() cannot be called twice", () => {
  const redactor = createStreamingToolResultRedactor(createFakeIncrementalSanitizer, { limits: LIMITS });
  redactor.finalize();
  assert.throws(() => redactor.finalize(), /already called/);
});

test("options.limits is required, matching IncrementalSanitizerOptions' no-defaults contract", () => {
  assert.throws(() => createStreamingToolResultRedactor(createFakeIncrementalSanitizer, {}), TypeError);
  assert.throws(() => createStreamingToolResultRedactor(createFakeIncrementalSanitizer), TypeError);
});

test("rejects a non-function createSession", () => {
  assert.throws(() => createStreamingToolResultRedactor(null, { limits: LIMITS }), TypeError);
});
