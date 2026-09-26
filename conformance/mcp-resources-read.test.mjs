/**
 * Unit tests for the MCP `resources/read` reference model and runner
 * (issue #843) against a fake core, so they run in `npm run ci` without a
 * built artifact. The real-artifact replay of
 * `fixtures/mcp-resources-read.json` runs in `scripts/consumer-harness.mjs`
 * against the packed, clean-installed `@redact-secret/core` on the Node addon
 * lane and in every browser engine.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { BLOCK_REASONS, SAFE_FINDING_FIELDS, createAiContextBoundary } from "./ai-context-boundary.mjs";
import { MCP_AUDIT_FIELDS, MCP_BOUNDARY_LABELS, createMcpBoundary, mcpAuditRecord } from "./mcp-boundary.mjs";
import {
  MCP_RESOURCE_BLOCKED_MESSAGE,
  MCP_RESOURCE_ERROR_CODE,
  MCP_RESOURCE_OUTCOMES,
  MCP_RESOURCE_READ_ERROR_MESSAGE,
  mcpResourceBlockedError,
  mcpResourceReadError,
  runMcpResourcesReadConformance,
  toReadResourceResponse,
} from "./mcp-resources-read.mjs";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/mcp-resources-read.json", import.meta.url), "utf8"));

const SYNTHETIC = "SYNTHETIC_MCP_RESOURCE_VALUE_0000";
/** Detected only after `password":"`, the way key-context detection behaves. */
const CONTEXTUAL = "synthetic-contextual-0000";
/** Detected only after `"provider":"fake","value":"`: sibling context. */
const SIBLING = "synthetic-sibling-0000";
const SIBLING_CONTEXT = '"provider":"fake","value":"';

const LIMITS = {
  wholeInputLimits: { maxInputBytes: 4096, maxFindings: 16 },
  incrementalLimits: { maxInputCodeUnits: 64, maxBufferedCodeUnits: 64, maxTokenCodeUnits: 64, maxMultilineCodeUnits: 64 },
  traversalLimits: { maxDepth: 6, maxNodes: 64 },
};

function finding(start, end) {
  return { id: "finding-1", type: "synthetic", detector: "fake", confidence: "high", action: "redact", obfuscation: "none", start, end, score: 0.9 };
}

function fakeApi() {
  function scan(text) {
    for (const [needle, prefix] of [
      [SYNTHETIC, ""],
      [CONTEXTUAL, 'password":"'],
      [SIBLING, SIBLING_CONTEXT],
    ]) {
      const index = text.indexOf(prefix + needle);
      if (index !== -1) {
        const start = index + prefix.length;
        return { text: text.replace(needle, "<SECRET_1>"), findings: [finding(start, start + needle.length)] };
      }
    }
    return { text, findings: [] };
  }
  return {
    scanAndRedact: (text) => scan(text),
    createIncrementalSanitizer: () => ({ append: () => ({ text: "", findings: [] }), finalize: () => ({ text: "", findings: [] }), abort() {} }),
  };
}

function setup({ binaryContent } = {}) {
  const events = [];
  const base = createAiContextBoundary(fakeApi(), { ...LIMITS, onFinding: (f, context) => events.push({ finding: f, context }) });
  return { events, mcp: createMcpBoundary(base, { binaryContent }) };
}

const entry = (text, extra = {}) => ({ uri: "file:///synthetic/readme.txt", mimeType: "text/plain", text, ...extra });

test("the fixture is well formed and names only contract outcomes, reasons, and the resource label", () => {
  assert.equal(fixture.schemaVersion, 1);
  assert.deepEqual(fixture.safeFindingFields, SAFE_FINDING_FIELDS);
  assert.equal(fixture.label, MCP_BOUNDARY_LABELS.resource);
  assert.deepEqual(fixture.fixedErrors, { blocked: mcpResourceBlockedError(), readError: mcpResourceReadError() });
  const ids = fixture.cases.map((testCase) => testCase.id);
  assert.equal(new Set(ids).size, ids.length, "case IDs are unique");
  const covered = new Set();
  for (const testCase of fixture.cases) {
    assert.ok(["resourceResult", "resourceRead"].includes(testCase.operation), testCase.id);
    assert.ok(Array.isArray(testCase.secrets), `${testCase.id}: secrets list`);
    assert.ok(MCP_RESOURCE_OUTCOMES.includes(testCase.expected.outcome), testCase.id);
    if (testCase.expected.outcome === "blocked") assert.ok(BLOCK_REASONS.includes(testCase.expected.reason), testCase.id);
    for (const found of testCase.expected.findings ?? []) {
      assert.deepEqual(Object.keys(found), SAFE_FINDING_FIELDS, `${testCase.id}: finding field order`);
    }
    covered.add(testCase.expected.outcome === "blocked" ? `blocked:${testCase.expected.reason}` : testCase.expected.outcome);
  }
  // The issue's acceptance list: text, JSON-in-text, key-identified leaves,
  // blob under both settings, _meta, several entries, unknown fields, blocked.
  for (const id of [
    "text-redacts-provider-token",
    "json-text-stays-text-and-keeps-key-context",
    "meta-key-identified-leaf-redacts-in-place",
    "entry-meta-nested-key-identified-leaf-redacts-in-place",
    "blob-blocked-by-default",
    "blob-passes-unscanned-only-on-opt-in",
    "result-meta-is-scanned",
    "entry-meta-is-scanned",
    "multiple-contents-mixed-siblings",
    "unknown-fields-are-scanned",
    "text-block-finding-blocks",
    "read-failure-is-never-read",
  ]) {
    assert.ok(ids.includes(id), `fixture covers ${id}`);
  }
  for (const outcome of ["ok", "aborted", "read_error", "blocked:policy", "blocked:limit_exceeded", "blocked:unsupported_value", "blocked:core_error"]) {
    assert.ok(covered.has(outcome), `fixture covers ${outcome}`);
  }
});

test("the whole ReadResourceResult is one value: text, uri, mimeType, _meta, and unknown fields", () => {
  const { mcp, events } = setup();
  const outcome = mcp.sanitizeResourceResult({
    contents: [
      entry(`a ${SYNTHETIC}`, { uri: `https://example.test/?t=${SYNTHETIC}`, _meta: { up: SYNTHETIC } }),
      entry("ordinary text", { mimeType: `text/plain; t=${SYNTHETIC}`, later: SYNTHETIC }),
    ],
    _meta: { trace: SYNTHETIC },
    later: SYNTHETIC,
  });
  assert.equal(outcome.outcome, "ok");
  assert.equal(JSON.stringify(outcome.value).includes(SYNTHETIC), false);
  assert.equal(JSON.stringify(events).includes(SYNTHETIC), false);
  assert.deepEqual(new Set(events.map((event) => event.context.boundary)), new Set([MCP_BOUNDARY_LABELS.resource]));
  for (const event of events) assert.deepEqual(Object.keys(event.finding), SAFE_FINDING_FIELDS);
});

test("text is scanned as text whatever its mimeType, and a key-identified leaf in _meta is redacted in place", () => {
  const { mcp } = setup();
  const text = JSON.stringify({ password: CONTEXTUAL });
  const outcome = mcp.sanitizeResourceResult({
    contents: [entry(text, { mimeType: "application/json" })],
    _meta: { password: CONTEXTUAL },
  });
  assert.equal(outcome.outcome, "ok");
  assert.equal(outcome.value.contents[0].text, '{"password":"<SECRET_1>"}', "JSON-in-text stays text");
  assert.deepEqual(outcome.value._meta, { password: "<SECRET_1>" });
  // Sibling context is still caught only by the backstop, which blocks.
  assert.deepEqual(mcp.sanitizeResourceResult({ contents: [], _meta: { provider: "fake", value: SIBLING } }), {
    outcome: "blocked",
    reason: "policy",
  });
});

test("a blob blocks by default and passes unscanned, in place, only on opt-in", () => {
  const blob = { uri: "file:///synthetic.bin", blob: "U1lOVEhFVElD", mimeType: "application/octet-stream" };
  assert.deepEqual(setup().mcp.sanitizeResourceResult({ contents: [blob] }), { outcome: "blocked", reason: "unsupported_value" });
  const { mcp } = setup({ binaryContent: "pass" });
  const outcome = mcp.sanitizeResourceResult({ contents: [{ ...blob, uri: `file:///${SYNTHETIC}.bin` }, entry(SYNTHETIC)] });
  assert.equal(outcome.outcome, "ok");
  assert.deepEqual(outcome.value.contents[0], { ...blob, uri: "file:///<SECRET_1>.bin" }, "the blob is unchanged; its uri is scanned");
  assert.deepEqual(Object.keys(outcome.value.contents[0]), Object.keys(blob), "key order is preserved");
  assert.equal(outcome.value.contents[1].text, "<SECRET_1>");
  assert.deepEqual(mcp.sanitizeResourceResult({ contents: [{ uri: "x", blob: { nested: SYNTHETIC } }] }), {
    outcome: "blocked",
    reason: "unsupported_value",
  });
});

test("an entry must be exactly one of text or blob, and the result must carry a contents array", () => {
  const { mcp } = setup({ binaryContent: "pass" });
  for (const result of [
    { contents: [{ uri: "x", text: "a", blob: "YQ==" }] },
    { contents: [{ uri: "x" }] },
    { contents: [{ uri: "x", text: { password: CONTEXTUAL } }] },
    { contents: ["ordinary text"] },
    { contents: entry("ordinary text") },
    { _meta: {} },
    "ordinary text",
    null,
    [],
  ]) {
    assert.deepEqual(mcp.sanitizeResourceResult(result), { outcome: "blocked", reason: "unsupported_value" });
  }
});

test("traversal limits count from the result root", () => {
  const { mcp } = setup();
  // Four levels under an entry's _meta is seven from the root: over maxDepth 6.
  const deep = { contents: [entry("ordinary text", { _meta: { a: { b: { c: { d: "x" } } } } })] };
  assert.deepEqual(mcp.sanitizeResourceResult(deep), { outcome: "blocked", reason: "limit_exceeded" });
  const many = { contents: Array.from({ length: 16 }, () => entry("ordinary text")) };
  assert.deepEqual(mcp.sanitizeResourceResult(many), { outcome: "blocked", reason: "limit_exceeded" });
});

test("a failing read becomes read_error and its error is never read", async () => {
  const { mcp } = setup();
  let read = false;
  const error = {
    get message() {
      read = true;
      return SYNTHETIC;
    },
  };
  const outcome = await mcp.sanitizeResourceRead(async () => {
    throw error;
  });
  assert.deepEqual(outcome, { outcome: "read_error" });
  assert.equal(read, false);
  assert.deepEqual(toReadResourceResponse(outcome), { error: { code: -32603, message: MCP_RESOURCE_READ_ERROR_MESSAGE } });
});

test("cancellation before or during a read delivers nothing", async () => {
  const { mcp } = setup();
  const controller = new AbortController();
  controller.abort();
  let reads = 0;
  const before = await mcp.sanitizeResourceRead(async () => {
    reads += 1;
    return { contents: [] };
  }, { signal: controller.signal });
  assert.deepEqual(before, { outcome: "aborted" });
  assert.equal(reads, 0);
  const during = new AbortController();
  const outcome = await mcp.sanitizeResourceRead(async () => {
    during.abort();
    return { contents: [entry(SYNTHETIC)] };
  }, { signal: during.signal });
  assert.deepEqual(outcome, { outcome: "aborted" });
  assert.equal(toReadResourceResponse(outcome), null);
  const rejected = await mcp.sanitizeResourceRead(async () => {
    during.abort();
    throw new Error(SYNTHETIC);
  }, { signal: during.signal });
  assert.deepEqual(rejected, { outcome: "aborted" });
});

test("every non-ok outcome maps onto a fixed, input-free JSON-RPC error and audit record", () => {
  assert.equal(MCP_RESOURCE_ERROR_CODE, -32603);
  assert.deepEqual(toReadResourceResponse({ outcome: "blocked", reason: "core_error", code: "POLICY_FAILURE" }), {
    error: { code: -32603, message: MCP_RESOURCE_BLOCKED_MESSAGE },
  });
  assert.equal("data" in mcpResourceBlockedError(), false, "no data member");
  assert.notEqual(mcpResourceBlockedError(), mcpResourceBlockedError(), "a fresh object each call");
  assert.deepEqual(toReadResourceResponse({ outcome: "ok", value: { contents: [] }, findings: [] }), { result: { contents: [] } });
  assert.throws(() => toReadResourceResponse({ outcome: "tool_error" }), TypeError);
  const record = mcpAuditRecord({ outcome: "blocked", reason: "unsupported_value" }, "resource");
  assert.deepEqual(record, { stage: "resource", outcome: "blocked", reason: "unsupported_value" });
  assert.ok(Object.keys(record).every((key) => MCP_AUDIT_FIELDS.includes(key)));
  assert.deepEqual(mcpAuditRecord({ outcome: "read_error" }, "resource"), { stage: "resource", outcome: "read_error" });
});

test("the runner rejects a core that lets a secret through, naming only the case", async () => {
  const passthrough = {
    scanAndRedact: (text) => ({ text, findings: [] }),
    createIncrementalSanitizer: () => ({ append: () => ({ text: "", findings: [] }), finalize: () => ({ text: "", findings: [] }), abort() {} }),
  };
  await assert.rejects(runMcpResourcesReadConformance(passthrough, fixture), (error) => {
    assert.match(error.message, /^mcp-resources-read [a-z0-9-]+: /);
    for (const testCase of fixture.cases) {
      for (const secret of testCase.secrets) assert.equal(error.message.includes(secret), false);
    }
    return true;
  });
});

test("the runner rejects an implementation that passes blobs by default", async () => {
  const leaky = (api, options) => createMcpBoundary(createAiContextBoundary(api, options), { binaryContent: "pass" });
  const onlyBlob = { ...fixture, cases: fixture.cases.filter((c) => c.id === "blob-blocked-by-default") };
  await assert.rejects(
    runMcpResourcesReadConformance(fakeApi(), onlyBlob, { createBoundary: leaky }),
    /^Error: mcp-resources-read blob-blocked-by-default: outcome$/,
  );
});

test("the runner rejects an implementation that forwards the failure message", async () => {
  const onlyFailure = { ...fixture, cases: fixture.cases.filter((c) => c.id === "read-failure-is-never-read") };
  assert.deepEqual(await runMcpResourcesReadConformance(fakeApi(), onlyFailure), { cases: 1, reads: 1, telemetryEvents: 0 });
  const leaking = (api, options) => ({
    ...createMcpBoundary(createAiContextBoundary(api, options)),
    async sanitizeResourceRead(invoke) {
      try {
        return await invoke({});
      } catch (error) {
        return { outcome: "ok", value: { contents: [{ uri: "x", text: String(error.message) }] }, findings: [] };
      }
    },
  });
  await assert.rejects(runMcpResourcesReadConformance(fakeApi(), onlyFailure, { createBoundary: leaking }), /: outcome$/);
});
