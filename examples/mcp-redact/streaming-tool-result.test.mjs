/**
 * Streamed tool output through the golden path's boundary (#721), over the
 * injected fake core (`fixtures/fake-core.mjs`), so it runs without a built
 * native addon. The same behavior against the real core's
 * `IncrementalSanitizer` is in `streaming-tool-result.real-core.test.mjs`.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { buildSafeContext, createGoldenPathBoundaryWith } from "./agent-context.mjs";
import { fakeCore } from "./fixtures/fake-core.mjs";
import { redactStreamedToolResult, TOOL_ERROR } from "./streaming-tool-result.mjs";

/** A producer that yields `chunks` and records whether it was closed early. */
function producer(chunks, { throwAfter } = {}) {
  const state = { pulled: 0, closed: false };
  async function* generate() {
    try {
      for (const chunk of chunks) {
        if (throwAfter !== undefined && state.pulled === throwAfter) {
          throw new Error(`upstream failed while reading ${chunk}`);
        }
        state.pulled += 1;
        yield chunk;
      }
    } finally {
      state.closed = true;
    }
  }
  return { state, chunks: generate() };
}

function setup(overrides = {}) {
  const events = [];
  const boundary = createGoldenPathBoundaryWith(fakeCore, {
    onFinding: (finding, context) => events.push({ ...finding, boundary: context.boundary }),
    ...overrides,
  });
  return { boundary, events };
}

const FRAGMENTS = ["SECRET_TOK", "EN_9"];

function assertNoFragment(value) {
  const text = JSON.stringify(value) ?? "";
  for (const fragment of [...FRAGMENTS, "SECRET_TOKEN_9", "BLOCK_ME"]) {
    assert.equal(text.includes(fragment), false, "an input fragment crossed the boundary");
  }
}

test("a secret split across chunks is redacted and joins the context as a one-block CallToolResult", async () => {
  const { boundary, events } = setup();
  const result = await buildSafeContext({
    boundary,
    userInput: "tail the build log",
    streamTool: () => producer(["build ok, token ", FRAGMENTS[0], FRAGMENTS[1], " done"]).chunks,
  });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(result.value[1], {
    role: "tool",
    content: { content: [{ type: "text", text: "build ok, token <SECRET_1> done" }] },
  });
  assert.equal(result.findings.length, 1);
  assert.equal(events[0].boundary, "tool-result");
  assertNoFragment(result);
  assertNoFragment(events);
});

test("a sync iterable of chunks works too", async () => {
  const { boundary } = setup();
  const outcome = await redactStreamedToolResult(boundary, ["a ", "b"]);
  assert.deepEqual(outcome, { outcome: "ok", value: { content: [{ type: "text", text: "a b" }] }, findings: [] });
});

test("a block finding in a streamed result blocks the turn with no value and no findings", async () => {
  const { boundary } = setup();
  const result = await buildSafeContext({
    boundary,
    userInput: "go",
    streamTool: () => producer(["leak BLO", "CK_ME here"]).chunks,
  });
  assert.deepEqual(result, { outcome: "blocked", reason: "policy", stage: "tool" });
});

test("a limit failure mid-stream blocks the whole result and releases no staged text", async () => {
  const { boundary } = setup({
    incrementalLimits: { maxInputCodeUnits: 1000, maxBufferedCodeUnits: 16, maxTokenCodeUnits: 16, maxMultilineCodeUnits: 16 },
  });
  const outcome = await redactStreamedToolResult(boundary, ["safe chunk ", "and one that goes over the buffer"]);
  assert.deepEqual(outcome, { outcome: "blocked", reason: "limit_exceeded", code: "BUFFER_LIMIT_EXCEEDED" });
});

test("cancellation mid-stream stops pulling chunks, closes the producer, and discards staged text", async () => {
  const { boundary, events } = setup();
  const controller = new AbortController();
  const source = producer(["staged ", FRAGMENTS[0], FRAGMENTS[1], " never read"]);
  let seenSignal;
  const result = await buildSafeContext({
    boundary,
    userInput: "go",
    signal: controller.signal,
    streamTool: (_request, { signal }) => {
      seenSignal = signal;
      return (async function* () {
        for await (const chunk of source.chunks) {
          yield chunk;
          if (chunk === FRAGMENTS[0]) controller.abort();
        }
      })();
    },
  });
  assert.deepEqual(result, { outcome: "aborted", stage: "tool" });
  assert.equal(seenSignal, controller.signal);
  assert.equal(source.state.closed, true);
  assert.ok(source.state.pulled < 4, "chunks were pulled after cancellation");
  assert.deepEqual(events, []);
  assertNoFragment(result);
});

test("an already-aborted signal never calls streamTool", async () => {
  const { boundary } = setup();
  let called = false;
  const result = await buildSafeContext({
    boundary,
    userInput: "go",
    signal: AbortSignal.abort(),
    streamTool: () => {
      called = true;
      return [];
    },
  });
  assert.deepEqual(result, { outcome: "aborted", stage: "input" });
  assert.equal(called, false);
});

test("a producer that fails mid-stream is a tool_error whose error is never read", async () => {
  const { boundary } = setup();
  const source = producer(["partial ", FRAGMENTS[0], FRAGMENTS[1]], { throwAfter: 2 });
  const result = await buildSafeContext({ boundary, userInput: "go", streamTool: () => source.chunks });
  assert.deepEqual(result, { outcome: "tool_error", stage: "tool" });
  assertNoFragment(result);
});

test("a streamTool that throws synchronously is a tool_error", async () => {
  const { boundary } = setup();
  const result = await buildSafeContext({
    boundary,
    userInput: "go",
    streamTool: () => {
      throw new Error(`cannot start: ${FRAGMENTS.join("")}`);
    },
  });
  assert.deepEqual(result, { outcome: "tool_error", stage: "tool" });
});

test("a non-string chunk or a non-iterable result blocks as unsupported_value", async () => {
  const { boundary } = setup();
  assert.deepEqual(await redactStreamedToolResult(boundary, ["text", new Uint8Array([65])]), {
    outcome: "blocked",
    reason: "unsupported_value",
  });
  assert.deepEqual(await redactStreamedToolResult(boundary, 42), { outcome: "blocked", reason: "unsupported_value" });
  // A bare string is refused rather than iterated character by character.
  const result = await buildSafeContext({ boundary, userInput: "go", streamTool: () => "not a chunk list" });
  assert.deepEqual(result, { outcome: "blocked", reason: "unsupported_value", stage: "tool" });
});

test("callTool and streamTool together are rejected", async () => {
  const { boundary } = setup();
  await assert.rejects(
    buildSafeContext({ boundary, userInput: "go", callTool: async () => ({}), streamTool: () => [] }),
    TypeError,
  );
});

test("the tool request is built from the sanitized input, as for callTool", async () => {
  const { boundary } = setup();
  let request;
  const result = await buildSafeContext({
    boundary,
    userInput: "fetch SECRET_TOKEN_1",
    buildToolRequest: (safe) => ({ query: safe }),
    streamTool: (r) => {
      request = r;
      return ["ok"];
    },
  });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(request, { query: "fetch <SECRET_1>" });
});

test("redactStreamedToolResult rejects a non-boundary", async () => {
  await assert.rejects(redactStreamedToolResult({}, []), TypeError);
  assert.equal(TOOL_ERROR.outcome, "tool_error");
});
