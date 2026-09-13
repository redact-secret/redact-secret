import assert from "node:assert/strict";
import test from "node:test";

import {
  createServerHandlerWith,
  prepareBrowserSubmissionWith,
} from "./integration.mjs";

const encoder = new TextEncoder();
const body = (content) => encoder.encode(JSON.stringify({ content }));
const finding = (action, overrides = {}) => ({
  id: "finding-1",
  type: "contextual_secret",
  detector: "generic-token",
  confidence: action === "warn" ? "medium" : "high",
  action,
  start: 8,
  end: 33,
  ...overrides,
});

function scanner(input) {
  if (input === "trigger scan failure") throw new Error("unsafe callback detail");
  if (input === "block input") return { text: "<SECRET_1>", findings: [finding("block")] };
  if (input === "warn input") return { text: input, findings: [finding("warn")] };
  if (input === "many findings") {
    return { text: "<SECRET_1> <SECRET_2>", findings: [finding("redact"), finding("redact", { id: "finding-2", start: 34, end: 59 })] };
  }
  if (input === "expand output") return { text: "sanitized output is deliberately long", findings: [] };
  if (input === "redact input") return { text: "<SECRET_1>", findings: [finding("redact")] };
  return { text: input, findings: [] };
}

test("browser prevention omits requests for warn and block decisions", () => {
  assert.equal(prepareBrowserSubmissionWith(scanner, "block input").request, undefined);
  assert.equal(prepareBrowserSubmissionWith(scanner, "warn input").request, undefined);
  const ready = prepareBrowserSubmissionWith(scanner, "redact input");
  assert.equal(ready.state, "ready");
  assert.equal(JSON.parse(ready.request.body).content, "<SECRET_1>");
  assert.equal(ready.request.body.includes("redact input"), false);
});

test("server enforcement forwards only clean or redacted text", async () => {
  const forwarded = [];
  const events = [];
  const handle = createServerHandlerWith({
    scanAndRedact: scanner,
    forward: async (request) => forwarded.push(request.content),
    record: (event) => events.push(event),
  });

  assert.equal((await handle(body("ordinary input"))).code, "OK");
  assert.equal((await handle(body("redact input"))).code, "OK");
  assert.equal((await handle(body("block input"))).code, "SECRET_BLOCKED");
  assert.equal((await handle(body("warn input"))).code, "SECRET_WARNING");
  assert.equal((await handle(body("trigger scan failure"))).code, "SCAN_FAILED");
  assert.deepEqual(forwarded, ["ordinary input", "<SECRET_1>"]);
  assert.equal(JSON.stringify(events).includes("block input"), false);
  assert.equal(JSON.stringify(events).includes("unsafe callback detail"), false);
});

test("server rejects each declared limit before downstream use", async () => {
  const forwarded = [];
  const base = { scanAndRedact: scanner, forward: async (request) => forwarded.push(request) };

  const transport = createServerHandlerWith({ ...base, limits: { maxTransportBytes: 4 } });
  assert.equal((await transport(body("ordinary input"))).code, "TRANSPORT_LIMIT_EXCEEDED");

  const input = createServerHandlerWith({ ...base, limits: { maxInputBytes: 4 } });
  assert.equal((await input(body("ordinary input"))).code, "INPUT_LIMIT_EXCEEDED");

  const output = createServerHandlerWith({ ...base, limits: { maxOutputBytes: 4 } });
  assert.equal((await output(body("expand output"))).code, "OUTPUT_LIMIT_EXCEEDED");

  const findings = createServerHandlerWith({ ...base, limits: { maxFindings: 1 } });
  assert.equal((await findings(body("many findings"))).code, "RESOURCE_LIMIT_EXCEEDED");

  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const concurrent = createServerHandlerWith({
    scanAndRedact: scanner,
    forward: async () => held,
    limits: { maxConcurrentRequests: 1 },
  });
  const first = concurrent(body("ordinary input"));
  assert.equal((await concurrent(body("ordinary input"))).code, "RESOURCE_LIMIT_EXCEEDED");
  release();
  assert.equal((await first).code, "OK");

  assert.equal(forwarded.length, 0);
});
