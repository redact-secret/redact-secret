import assert from "node:assert/strict";
import test from "node:test";

import { createGoldenPathBoundaryWith } from "./agent-context.mjs";
import { fakeCore } from "./fixtures/fake-core.mjs";
import { BLOCKED_MESSAGE } from "./redact-tool-call.mjs";
import { wrapClientCallTool, wrapServerToolHandler } from "./wrap-tool-call.mjs";

const boundary = createGoldenPathBoundaryWith(fakeCore);

test("server wrapper redacts a handler's result before returning it", async () => {
  const handler = async (args) => ({ content: [{ type: "text", text: `read ${args.path}: SECRET_TOKEN_1` }] });
  const wrapped = wrapServerToolHandler(handler, boundary);
  const result = await wrapped({ path: "/tmp/x" }, {});
  assert.deepEqual(result, { content: [{ type: "text", text: "read /tmp/x: <SECRET_1>" }] });
});

test("server wrapper leaves arguments untouched by default (redactArguments off)", async () => {
  let seenArgs;
  const handler = async (args) => {
    seenArgs = args;
    return { content: [{ type: "text", text: "ok" }] };
  };
  const wrapped = wrapServerToolHandler(handler, boundary);
  await wrapped({ token: "SECRET_TOKEN_1" }, {});
  assert.deepEqual(seenArgs, { token: "SECRET_TOKEN_1" });
});

test("server wrapper redacts arguments before calling the handler when configured", async () => {
  let seenArgs;
  const handler = async (args) => {
    seenArgs = args;
    return { content: [{ type: "text", text: "ok" }] };
  };
  const wrapped = wrapServerToolHandler(handler, boundary, { redactArguments: true });
  await wrapped({ token: "SECRET_TOKEN_1" }, {});
  assert.deepEqual(seenArgs, { token: "<SECRET_1>" });
});

test("server wrapper never calls the handler when an argument is blocked", async () => {
  let called = false;
  const handler = async () => {
    called = true;
    return { content: [] };
  };
  const wrapped = wrapServerToolHandler(handler, boundary, { redactArguments: true });
  for (const args of [{ token: "BLOCK_ME" }, { SECRET_TOKEN_1: "key finding" }, { when: new Date(0) }]) {
    const result = await wrapped(args, {});
    assert.equal(result.isError, true);
    assert.deepEqual(result.content, [{ type: "text", text: BLOCKED_MESSAGE }]);
  }
  assert.equal(called, false);
});

test("server wrapper blocks a handler result containing a block finding", async () => {
  const handler = async () => ({ content: [{ type: "text", text: "leak BLOCK_ME here" }] });
  const wrapped = wrapServerToolHandler(handler, boundary);
  const result = await wrapped({}, {});
  assert.equal(result.isError, true);
  assert.equal(JSON.stringify(result).includes("leak"), false);
});

test("server wrapper fails closed when the request's extra.signal is aborted", async () => {
  let called = false;
  const handler = async () => {
    called = true;
    return { content: [{ type: "text", text: "SECRET_TOKEN_1" }] };
  };
  const wrapped = wrapServerToolHandler(handler, boundary, { redactArguments: true });
  const result = await wrapped({ a: "x" }, { signal: AbortSignal.abort() });
  assert.equal(called, false);
  assert.equal(result.isError, true);
});

test("the boundary reports safe finding metadata for arguments and results to onFinding", async () => {
  const seen = [];
  const audited = createGoldenPathBoundaryWith(fakeCore, {
    onFinding: (finding, context) => seen.push({ boundary: context.boundary, action: finding.action }),
  });
  const handler = async () => ({ content: [{ type: "text", text: "out SECRET_TOKEN_1 here" }] });
  const wrapped = wrapServerToolHandler(handler, audited, { redactArguments: true });
  await wrapped({ in: "SECRET_TOKEN_2" }, {});
  assert.deepEqual(seen, [
    { boundary: "context", action: "redact" },
    { boundary: "tool-result", action: "redact" },
  ]);
});

test("a throwing onFinding never breaks the call", async () => {
  const audited = createGoldenPathBoundaryWith(fakeCore, {
    onFinding: () => {
      throw new Error("audit sink is down");
    },
  });
  const handler = async () => ({ content: [{ type: "text", text: "out SECRET_TOKEN_1 here" }] });
  const result = await wrapServerToolHandler(handler, audited)({}, {});
  assert.deepEqual(result, { content: [{ type: "text", text: "out <SECRET_1> here" }] });
});

test("client wrapper redacts a callTool result before it enters model context", async () => {
  const callTool = async (params) => ({
    content: [{ type: "text", text: `result for ${params.name}: SECRET_TOKEN_1` }],
  });
  const wrapped = wrapClientCallTool(callTool, boundary);
  const result = await wrapped({ name: "read_file", arguments: {} });
  assert.deepEqual(result, { content: [{ type: "text", text: "result for read_file: <SECRET_1>" }] });
});

test("client wrapper blocks a result containing a block finding", async () => {
  const callTool = async () => ({ content: [{ type: "text", text: "BLOCK_ME" }] });
  const wrapped = wrapClientCallTool(callTool, boundary);
  const result = await wrapped({ name: "x" });
  assert.equal(result.isError, true);
  assert.deepEqual(result.content, [{ type: "text", text: BLOCKED_MESSAGE }]);
});

test("rejects a non-function handler/callTool, or a missing boundary", () => {
  assert.throws(() => wrapServerToolHandler(null, boundary), TypeError);
  assert.throws(() => wrapClientCallTool(null, boundary), TypeError);
  assert.throws(() => wrapServerToolHandler(async () => ({}), undefined), TypeError);
  assert.throws(() => wrapClientCallTool(async () => ({}), {}), TypeError);
});
