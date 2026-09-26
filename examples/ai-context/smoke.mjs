#!/usr/bin/env node
/**
 * End-to-end smoke test for the AI-context reference (issue #611):
 * `npm run reference:ai-context` from the repository root.
 *
 * The released `@redact-secret/core` from the registry, the released
 * `@redact-secret/adapter-ai-context` and `@redact-secret/adapter-mcp`, and the
 * `examples/mcp-redact` golden path, with no fake anywhere. Every value
 * below is synthetic. Everything that would reach the model, the tool, or
 * the audit callback is checked for every synthetic value before anything
 * is printed, so a failure never prints plaintext, and nothing is written
 * to disk.
 */

import assert from "node:assert/strict";

import { buildSafeContext, createAppBoundary, readSafeResource } from "./app.mjs";

// Unmistakably synthetic: AKIA + SYNTHETICEXAMPLE is this repository's
// synthetic AWS access key ID; the others say what they are.
const SYNTHETIC = Object.freeze({
  awsKeyId: "AKIASYNTHETICEXAMPLE",
  apiKey: "synthetic-example-value-0000",
  bearer: "synthetic.example.token",
  password: "synthetic-not-a-secret",
});

function assertNoSynthetic(name, value) {
  const serialized = JSON.stringify(value) ?? "";
  for (const secret of Object.values(SYNTHETIC)) {
    // A fixed message: the assertion must not echo what was captured.
    assert.ok(!serialized.includes(secret), `${name}: a synthetic secret crossed the boundary`);
  }
  return serialized;
}

const blockAwsKeys = Object.freeze({
  evaluate: (finding) => (finding.type === "aws_access_key_id" ? "block" : "redact"),
});
const failingPolicy = Object.freeze({
  evaluate: () => {
    throw new Error("policy failure (synthetic)");
  },
});

const userInput = `Deploy with ${SYNTHETIC.awsKeyId} and summarize the logs`;
const toolResult = Object.freeze({
  content: [
    { type: "text", text: `deploy log: login ok with password=${SYNTHETIC.password}` },
    // JSON-in-text is scanned as text (#612), so `"env":"API_KEY=..."` keeps
    // its own context inside the string.
    { type: "text", text: JSON.stringify({ config: { env: `API_KEY=${SYNTHETIC.apiKey}`, region: "eu-west-1" } }) },
  ],
  structuredContent: { upstream: `Authorization: Bearer ${SYNTHETIC.bearer}` },
});

const checks = [];
async function scenario(name, { policy, turn }, expect) {
  const audit = [];
  const toolRequests = [];
  const boundary = await createAppBoundary({ policy, onFinding: (finding, context) => audit.push({ finding, context }) });
  const result = await buildSafeContext({
    boundary,
    callTool: async (request) => {
      toolRequests.push(request);
      return toolResult;
    },
    buildToolRequest: (safeInputText) => ({ name: "summarize_logs", arguments: { query: safeInputText } }),
    userInput,
    ...turn,
  });
  // What reaches the model, the tool, and the audit path: all of it checked.
  const serialized = assertNoSynthetic(name, { result, toolRequests, audit });
  expect(result, { audit, toolRequests });
  checks.push({ name, serialized: JSON.stringify(result) });
}

await scenario("allow / redact: a whole turn", {}, (result, { audit, toolRequests }) => {
  assert.equal(result.outcome, "ok");
  assert.equal(result.value[0].content, "Deploy with <SECRET_1> and summarize the logs");
  assert.equal(toolRequests.length, 1, "the tool is dispatched from sanitized input");
  assert.equal(toolRequests[0].arguments.query, "Deploy with <SECRET_1> and summarize the logs");
  assert.ok(audit.length >= 4, "every finding is audited, as metadata only");
  assert.deepEqual(new Set(audit.map(({ context }) => context.boundary)), new Set(["user-input", "tool-result"]));
});
await scenario("block at the input stage", { policy: blockAwsKeys }, (result, { toolRequests }) => {
  assert.deepEqual({ ...result }, { outcome: "blocked", reason: "policy", stage: "input" });
  assert.equal(toolRequests.length, 0, "a blocked input never dispatches the tool");
});
await scenario(
  "block at the tool stage",
  {
    policy: blockAwsKeys,
    turn: {
      userInput: "Summarize the deploy logs",
      callTool: async () => ({ content: [{ type: "text", text: `AWS_ACCESS_KEY_ID=${SYNTHETIC.awsKeyId}` }] }),
    },
  },
  (result) => assert.deepEqual({ ...result }, { outcome: "blocked", reason: "policy", stage: "tool" }),
);
await scenario(
  "whole-input limit",
  { turn: { userInput: `${"x".repeat(300_000)} ${SYNTHETIC.awsKeyId}` } },
  (result) => assert.deepEqual({ ...result }, { outcome: "blocked", reason: "limit_exceeded", code: "INPUT_LIMIT_EXCEEDED", stage: "input" }),
);
await scenario("core failure fails closed", { policy: failingPolicy }, (result) => {
  assert.equal(result.outcome, "blocked");
  assert.equal(result.reason, "core_error");
  assert.equal(result.stage, "input");
});
await scenario(
  "tool failure never reads the error",
  {
    turn: {
      callTool: async () => {
        throw new Error(`upstream echoed password=${SYNTHETIC.password}`);
      },
    },
  },
  (result) => assert.deepEqual({ ...result }, { outcome: "tool_error", stage: "tool" }),
);
{
  const controller = new AbortController();
  await scenario(
    "abort mid-turn discards sanitized text",
    {
      turn: {
        signal: controller.signal,
        callTool: async () => {
          controller.abort();
          return toolResult;
        },
      },
    },
    (result) => assert.equal(result.outcome, "aborted"),
  );
}

// A tool result streamed in chunks, through the golden path's staged
// stream (#721). The secret is split across chunk boundaries.
const streamedText = `subprocess stdout: exported AWS_ACCESS_KEY_ID=${SYNTHETIC.awsKeyId} done`;
function* chunksOf(text, size = 7) {
  for (let i = 0; i < text.length; i += size) yield text.slice(i, i + size);
}
await scenario(
  "streamed tool result split across chunks",
  { turn: { callTool: undefined, streamTool: () => chunksOf(streamedText) } },
  (result) => {
    assert.equal(result.outcome, "ok");
    assert.deepEqual(result.value[1].content.content, [
      { type: "text", text: "subprocess stdout: exported AWS_ACCESS_KEY_ID=<SECRET_1> done" },
    ]);
  },
);
{
  const controller = new AbortController();
  await scenario(
    "abort mid-stream releases nothing",
    {
      turn: {
        signal: controller.signal,
        callTool: undefined,
        streamTool: function* () {
          yield `partial ${SYNTHETIC.awsKeyId.slice(0, 10)}`;
          controller.abort();
          yield SYNTHETIC.awsKeyId.slice(10);
        },
      },
    },
    (result) => assert.equal(result.outcome, "aborted"),
  );
}

// An MCP-shaped result (#612): secrets in a text block, an embedded text
// resource, and nested `structuredContent`. The host's own sinks, a log line
// and a conversation store, receive only what `buildSafeContext` returned,
// and the returned turn shares no object with the raw result, so nothing the
// tool or SDK still holds can reach context, the log, or the store later.
{
  const mcpResult = {
    content: [
      { type: "text", text: `stdout: exported AWS_ACCESS_KEY_ID=${SYNTHETIC.awsKeyId}` },
      { type: "resource", resource: { uri: "file:///synthetic/.env", mimeType: "text/plain", text: `API_KEY=${SYNTHETIC.apiKey}` } },
    ],
    structuredContent: { deploy: { steps: [{ env: [`Authorization: Bearer ${SYNTHETIC.bearer}`] }] } },
  };
  const rawObjects = new Set();
  (function collect(node) {
    if (node === null || typeof node !== "object") return;
    rawObjects.add(node);
    for (const child of Object.values(node)) collect(child);
  })(mcpResult);
  const log = [];
  const store = [];
  await scenario(
    "MCP-shaped result reaches the model, the log, and the store only sanitized",
    { turn: { userInput: "Deploy and report", callTool: async () => mcpResult } },
    (result) => {
      assert.equal(result.outcome, "ok");
      log.push(`turn ${JSON.stringify(result.value)}`);
      store.push(structuredClone(result.value));
      assertNoSynthetic("log", log);
      assertNoSynthetic("store", store);
      const tool = result.value[1].content;
      assert.equal(tool.content[0].text, "stdout: exported AWS_ACCESS_KEY_ID=<SECRET_1>");
      assert.equal(tool.content[1].resource.text, "API_KEY=<SECRET_1>");
      let shared = 0;
      (function walk(node) {
        if (node === null || typeof node !== "object") return;
        if (rawObjects.has(node)) shared += 1;
        for (const child of Object.values(node)) walk(child);
      })(result.value);
      assert.equal(shared, 0, "the sanitized turn shares no object with the raw tool result");
    },
  );
}

// `resources/read` has no `isError` result, so the same host boundary maps a
// successful read to `{ result }` and a blocked read to one fixed JSON-RPC
// `{ error }`. Only that mapped response may reach model context or a sink.
{
  const boundary = await createAppBoundary();
  const model = [];
  const log = [];
  const store = [];
  const deliver = (name, response) => {
    model.push(response);
    log.push(JSON.stringify(response));
    store.push(structuredClone(response));
    assertNoSynthetic(`${name} model`, model);
    assertNoSynthetic(`${name} log`, log);
    assertNoSynthetic(`${name} store`, store);
  };

  const safe = await readSafeResource(boundary, async () => ({
    contents: [
      {
        uri: "file:///synthetic/deploy.log",
        mimeType: "text/plain",
        text: `exported AWS_ACCESS_KEY_ID=${SYNTHETIC.awsKeyId}`,
      },
      {
        uri: "file:///synthetic/config.json",
        mimeType: "application/json",
        text: JSON.stringify({ password: SYNTHETIC.password, region: "eu-west-1" }),
      },
    ],
    _meta: { password: SYNTHETIC.password },
  }));
  assert.ok(safe && "result" in safe);
  assert.equal(safe.result.contents[0].text, "exported AWS_ACCESS_KEY_ID=<SECRET_1>");
  assert.equal(safe.result.contents[1].text, JSON.stringify({ password: "<SECRET_1>", region: "eu-west-1" }));
  assert.equal(safe.result._meta.password, "<SECRET_1>");
  deliver("resources/read", safe);

  const blocked = await readSafeResource(boundary, async () => ({
    contents: [{ uri: "file:///synthetic/image.bin", blob: SYNTHETIC.bearer }],
  }));
  assert.deepEqual(blocked, {
    error: {
      code: -32603,
      message: "This MCP resource read was blocked by secret-redaction policy. No content, URI, or error detail is included.",
    },
  });
  deliver("resources/read blob", blocked);
  checks.push({ name: "resources/read reaches model, log, and store only after the boundary", serialized: JSON.stringify({ safe, blocked }) });
}

for (const { name, serialized } of checks) console.log(`ok - ${name}: ${serialized.slice(0, 160)}`);
console.log(`\nAI-context reference: ${checks.length} scenarios passed, no synthetic secret crossed the boundary`);
