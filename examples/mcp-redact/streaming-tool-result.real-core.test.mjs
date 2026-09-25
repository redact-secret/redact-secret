/**
 * Streamed tool output through the golden path's boundary (#721), against
 * the real `@redact-secret/core` and its real `IncrementalSanitizer`, not a
 * fake. Run with `npm run examples:real-core:test` once a built core is
 * resolvable from this directory (README § Running the tests). Without one
 * this file fails: it never skips, because a skipped real-core test proves
 * nothing.
 *
 * Every secret here is synthetic: `AKIA` + `SYNTHETICEXAMPLE` is this
 * repository's synthetic AWS access key ID (also used by
 * `crates/secret-scan-core/src/detectors/aws.rs`'s tests and `demo.mjs`),
 * assembled at runtime so no chunk of source holds it whole.
 */

import assert from "node:assert/strict";
import test from "node:test";

import * as core from "@redact-secret/core";

import {
  buildSafeContext,
  createGoldenPathBoundary,
  createGoldenPathBoundaryWith,
  EXAMPLE_LIMITS,
} from "./agent-context.mjs";
import { redactStreamedToolResult } from "./streaming-tool-result.mjs";

await core.initialize();

const HEAD = "AKIA";
const TAIL = "SYNTHETICEXAMPLE";
const SECRET = HEAD + TAIL;
const TEXT = `deploy log: AWS_ACCESS_KEY_ID=${SECRET} region=us-east-1\n`;
const SPLIT_AT = TEXT.indexOf(SECRET) + HEAD.length + 3;
const FRAGMENTS = [SECRET, HEAD + TAIL.slice(0, 3), TAIL.slice(3), TAIL];

function assertNoPlaintext(value, label) {
  const text = typeof value === "string" ? value : JSON.stringify(value) ?? "";
  for (const fragment of FRAGMENTS) {
    assert.equal(text.includes(fragment), false, `${label}: a secret fragment crossed the boundary`);
  }
}

/**
 * The real core, with every incremental session it creates recorded, so a
 * test can check the boundary aborted the core session (which drops its
 * retained plaintext) and that the session really stopped accepting input.
 */
function recordingCore() {
  const sessions = [];
  return {
    sessions,
    core: {
      scanAndRedact: (text, options) => core.scanAndRedact(text, options),
      createIncrementalSanitizer(options) {
        const session = core.createIncrementalSanitizer(options);
        const record = { session, calls: [] };
        sessions.push(record);
        return {
          append(chunk) {
            record.calls.push("append");
            return session.append(chunk);
          },
          finalize() {
            record.calls.push("finalize");
            return session.finalize();
          },
          abort() {
            record.calls.push("abort");
            return session.abort();
          },
        };
      },
    },
  };
}

function setup(options = {}) {
  const events = [];
  const recorder = recordingCore();
  const boundary = createGoldenPathBoundaryWith(recorder.core, {
    onFinding: (finding, context) => events.push({ finding, context }),
    ...options,
  });
  return { boundary, events, sessions: recorder.sessions };
}

/** The real session drops its retained input on abort: it refuses any further call. */
function assertSessionDiscarded(record) {
  assert.ok(record.calls.includes("abort"), "the core session was not aborted");
  assert.throws(() => record.session.append("x"), (error) => error.code === "INVALID_STATE");
  assert.throws(() => record.session.finalize(), (error) => error.code === "INVALID_STATE");
}

async function* chunked(parts, hooks = {}) {
  try {
    for (const [index, part] of parts.entries()) {
      yield part;
      hooks.afterYield?.(index);
    }
  } finally {
    hooks.onClose?.();
  }
}

test("the real core is loaded: the live golden-path boundary scans", async () => {
  const live = await createGoldenPathBoundary();
  const outcome = live.sanitizeText(TEXT, { boundary: "tool-result" });
  assert.equal(outcome.outcome, "ok");
  assert.equal(outcome.findings[0].detector, "aws-access-key");
  assertNoPlaintext(outcome.value, "whole-input value");
});

test("a synthetic secret split across chunks is redacted in the model-facing context", async () => {
  const { boundary, events, sessions } = setup();
  const log = [];
  const result = await buildSafeContext({
    boundary,
    userInput: "show me the deploy log",
    streamTool: () => chunked([TEXT.slice(0, SPLIT_AT), TEXT.slice(SPLIT_AT)]),
  });
  log.push(JSON.stringify(result));

  assert.equal(result.outcome, "ok");
  const [tool] = result.value.filter((message) => message.role === "tool");
  const text = tool.content.content[0].text;
  assert.equal(text, "deploy log: AWS_ACCESS_KEY_ID=<SECRET_1> region=us-east-1\n");
  assert.deepEqual(
    result.findings.map(({ detector, action, start, end }) => ({ detector, action, start, end })),
    [{ detector: "aws-access-key", action: "redact", start: TEXT.indexOf(SECRET), end: TEXT.indexOf(SECRET) + SECRET.length }],
  );
  assert.deepEqual(sessions[0].calls, ["append", "append", "finalize"]);
  assertNoPlaintext(result, "context");
  assertNoPlaintext(events, "telemetry");
  assertNoPlaintext(log, "log");
});

test("the staged stream equals a whole-input scan of the joined text at every two-way split", async () => {
  const { boundary } = setup();
  const whole = boundary.sanitizeText(TEXT, { boundary: "tool-result" });
  for (let at = 0; at <= TEXT.length; at += 1) {
    const streamed = await redactStreamedToolResult(boundary, [TEXT.slice(0, at), TEXT.slice(at)]);
    assert.equal(streamed.outcome, "ok", `split ${at}`);
    assert.equal(streamed.value.content[0].text, whole.value, `split ${at}`);
    assert.deepEqual(streamed.findings, whole.findings, `split ${at}`);
  }
  const perChar = await redactStreamedToolResult(boundary, [...TEXT]);
  assert.equal(perChar.value.content[0].text, whole.value);
});

test("cancellation mid-secret aborts the real session, closes the producer, and releases nothing", async () => {
  const { boundary, events, sessions } = setup();
  const controller = new AbortController();
  let closed = false;
  const result = await buildSafeContext({
    boundary,
    userInput: "tail it",
    signal: controller.signal,
    streamTool: (_request, { signal }) =>
      chunked([TEXT.slice(0, SPLIT_AT), TEXT.slice(SPLIT_AT), "never pulled"], {
        afterYield: (index) => {
          assert.equal(signal, controller.signal);
          if (index === 0) controller.abort();
        },
        onClose: () => {
          closed = true;
        },
      }),
  });

  assert.deepEqual(result, { outcome: "aborted", stage: "tool" });
  assert.equal(closed, true, "the producer was not closed");
  assert.equal(sessions.length, 1);
  // The signal's listener aborts the session the moment it fires, and the
  // MCP adapter aborts the stream again when it stops pulling; a second
  // abort of a discarded session is a no-op. What matters is that nothing
  // was appended after the first abort.
  const calls = sessions[0].calls;
  assert.deepEqual(calls.slice(0, 2), ["append", "abort"]);
  assert.equal(calls.slice(calls.indexOf("abort")).includes("append"), false, "a chunk was scanned after cancellation");
  assertSessionDiscarded(sessions[0]);
  assert.deepEqual(events, []);
  assertNoPlaintext(result, "outcome");
});

test("a producer failure mid-secret aborts the real session; the outcome is input-free", async () => {
  const { boundary, sessions } = setup();
  const result = await buildSafeContext({
    boundary,
    userInput: "tail it",
    streamTool: async function* () {
      yield TEXT.slice(0, SPLIT_AT);
      throw new Error(`read failed after ${TEXT}`);
    },
  });
  assert.deepEqual(result, { outcome: "tool_error", stage: "tool" });
  assertSessionDiscarded(sessions[0]);
  assertNoPlaintext(result, "outcome");
});

test("an already-aborted signal creates no core session and never calls the tool", async () => {
  const { boundary, sessions } = setup();
  let called = false;
  const outcome = await redactStreamedToolResult(
    boundary,
    {
      [Symbol.asyncIterator]() {
        called = true;
        return chunked([TEXT]);
      },
    },
    { signal: AbortSignal.abort() },
  );
  assert.deepEqual(outcome, { outcome: "aborted" });
  assert.equal(called, false);
  assert.equal(sessions.length, 0);
});

test("a block decision on a split secret blocks the turn and aborts the real session", async () => {
  const { boundary, events, sessions } = setup({ policy: { evaluate: () => "block" } });
  const result = await buildSafeContext({
    boundary,
    userInput: "tail it",
    streamTool: () => chunked([TEXT.slice(0, SPLIT_AT), TEXT.slice(SPLIT_AT), " trailing"]),
  });
  assert.deepEqual(result, { outcome: "blocked", reason: "policy", stage: "tool" });
  // The block is decided mid-stream: the trailing chunk is discarded unscanned.
  assert.deepEqual(sessions[0].calls, ["append", "append", "abort"]);
  assertSessionDiscarded(sessions[0]);
  assert.equal(events[0].finding.action, "block");
  assertNoPlaintext(events, "telemetry");
});

test("a token past the real session's token limit blocks as limit_exceeded with no text", async () => {
  const { boundary, sessions } = setup({
    incrementalLimits: { ...EXAMPLE_LIMITS.incrementalLimits, maxTokenCodeUnits: 16 },
  });
  const outcome = await redactStreamedToolResult(boundary, chunked([TEXT.slice(0, SPLIT_AT), TEXT.slice(SPLIT_AT)]));
  assert.equal(outcome.outcome, "blocked");
  assert.equal(outcome.reason, "limit_exceeded");
  assert.equal("value" in outcome, false);
  assertSessionDiscarded(sessions[0]);
});

// --- the #610 lifecycle rules, on the golden path's own boundary --------------

test("a second finalize is blocked / lifecycle and never releases the value again", () => {
  const { boundary } = setup();
  const stream = boundary.openStream({ boundary: "tool-result" });
  stream.append(TEXT.slice(0, SPLIT_AT));
  stream.append(TEXT.slice(SPLIT_AT));
  const first = stream.finalize();
  assert.equal(first.outcome, "ok");
  assertNoPlaintext(first, "first finalize");
  assert.deepEqual(stream.finalize(), { outcome: "blocked", reason: "lifecycle" });
  // Append after finalize is discarded unscanned; abort after a successful
  // finalize does nothing.
  stream.append(SECRET);
  stream.abort();
  assert.deepEqual(stream.finalize(), { outcome: "blocked", reason: "lifecycle" });
});

test("append after abort is discarded and finalize returns aborted", () => {
  const { boundary, events, sessions } = setup();
  const stream = boundary.openStream({ boundary: "tool-result" });
  stream.append(TEXT.slice(0, SPLIT_AT));
  stream.abort();
  stream.append(TEXT.slice(SPLIT_AT));
  assert.deepEqual(stream.finalize(), { outcome: "aborted" });
  assert.deepEqual(stream.finalize(), { outcome: "blocked", reason: "lifecycle" });
  assert.deepEqual(sessions[0].calls, ["append", "abort"]);
  assertSessionDiscarded(sessions[0]);
  assert.deepEqual(events, []);
});
