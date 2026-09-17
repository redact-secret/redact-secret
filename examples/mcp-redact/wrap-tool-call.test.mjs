import assert from "node:assert/strict";
import test from "node:test";

import { fakeScanAndRedact } from "./fixtures/fake-scanner.mjs";
import { BLOCKED_MESSAGE } from "./redact-tool-call.mjs";
import { wrapClientCallTool, wrapServerToolHandler } from "./wrap-tool-call.mjs";

test("server wrapper redacts a handler's result before returning it", async () => {
  const handler = async (args) => ({ content: [{ type: "text", text: `read ${args.path}: SECRET_TOKEN_1` }] });
  const wrapped = wrapServerToolHandler(handler, fakeScanAndRedact);
  const result = await wrapped({ path: "/tmp/x" }, {});
  assert.deepEqual(result, { content: [{ type: "text", text: "read /tmp/x: <SECRET_1>" }] });
});

test("server wrapper leaves arguments untouched by default (redactArguments off)", async () => {
  let seenArgs;
  const handler = async (args) => {
    seenArgs = args;
    return { content: [{ type: "text", text: "ok" }] };
  };
  const wrapped = wrapServerToolHandler(handler, fakeScanAndRedact);
  await wrapped({ token: "SECRET_TOKEN_1" }, {});
  assert.deepEqual(seenArgs, { token: "SECRET_TOKEN_1" });
});

test("server wrapper redacts arguments before calling the handler when configured", async () => {
  let seenArgs;
  const handler = async (args) => {
    seenArgs = args;
    return { content: [{ type: "text", text: "ok" }] };
  };
  const wrapped = wrapServerToolHandler(handler, fakeScanAndRedact, { redactArguments: true });
  await wrapped({ token: "SECRET_TOKEN_1" }, {});
  assert.deepEqual(seenArgs, { token: "<SECRET_1>" });
});

test("server wrapper never calls the handler when a blocked argument is present", async () => {
  let called = false;
  const handler = async () => {
    called = true;
    return { content: [] };
  };
  const wrapped = wrapServerToolHandler(handler, fakeScanAndRedact, { redactArguments: true });
  const result = await wrapped({ token: "BLOCK_ME" }, {});
  assert.equal(called, false);
  assert.equal(result.isError, true);
  assert.deepEqual(result.content, [{ type: "text", text: BLOCKED_MESSAGE }]);
});

test("server wrapper blocks a handler result containing a block finding", async () => {
  const handler = async () => ({ content: [{ type: "text", text: "leak BLOCK_ME here" }] });
  const wrapped = wrapServerToolHandler(handler, fakeScanAndRedact);
  const result = await wrapped({}, {});
  assert.equal(result.isError, true);
  assert.equal(JSON.stringify(result).includes("leak"), false);
});

test("server wrapper reports safe finding metadata for both scopes to onFinding", async () => {
  const seen = [];
  const handler = async () => ({ content: [{ type: "text", text: "out SECRET_TOKEN_1 here" }] });
  const wrapped = wrapServerToolHandler(handler, fakeScanAndRedact, {
    redactArguments: true,
    onFinding: (finding, context) => seen.push({ scope: context.scope, action: finding.action }),
  });
  await wrapped({ in: "SECRET_TOKEN_2" }, {});
  assert.deepEqual(seen, [
    { scope: "argument", action: "redact" },
    { scope: "result", action: "redact" },
  ]);
});

test("a throwing onFinding never breaks the call", async () => {
  const handler = async () => ({ content: [{ type: "text", text: "out SECRET_TOKEN_1 here" }] });
  const wrapped = wrapServerToolHandler(handler, fakeScanAndRedact, {
    onFinding: () => {
      throw new Error("audit sink is down");
    },
  });
  const result = await wrapped({}, {});
  assert.deepEqual(result, { content: [{ type: "text", text: "out <SECRET_1> here" }] });
});

test("client wrapper redacts a callTool result before it enters model context", async () => {
  const callTool = async (params) => ({
    content: [{ type: "text", text: `result for ${params.name}: SECRET_TOKEN_1` }],
  });
  const wrapped = wrapClientCallTool(callTool, fakeScanAndRedact);
  const result = await wrapped({ name: "read_file", arguments: {} });
  assert.deepEqual(result, { content: [{ type: "text", text: "result for read_file: <SECRET_1>" }] });
});

test("client wrapper blocks a result containing a block finding", async () => {
  const callTool = async () => ({ content: [{ type: "text", text: "BLOCK_ME" }] });
  const wrapped = wrapClientCallTool(callTool, fakeScanAndRedact);
  const result = await wrapped({ name: "x" });
  assert.equal(result.isError, true);
  assert.deepEqual(result.content, [{ type: "text", text: BLOCKED_MESSAGE }]);
});

test("rejects a non-function handler/callTool", () => {
  assert.throws(() => wrapServerToolHandler(null, fakeScanAndRedact), TypeError);
  assert.throws(() => wrapClientCallTool(null, fakeScanAndRedact), TypeError);
});
