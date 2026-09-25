/**
 * Unit tests for the AI-context boundary reference model and runner
 * (issue #610) against a fake core, so they run without a built artifact.
 * The real-artifact replay runs in `scripts/consumer-harness.mjs` (packed,
 * clean-installed `@redact-secret/core`) and
 * `bindings/python/tests/test_ai_context_boundary.py` (installed wheel).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  BLOCK_REASONS,
  SAFE_FINDING_FIELDS,
  createAiContextBoundary,
  runAiContextBoundaryConformance,
} from "./ai-context-boundary.mjs";

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/ai-context-boundary.json", import.meta.url), "utf8"),
);

const SYNTHETIC = "SYNTHETIC_BOUNDARY_VALUE_0000";

const LIMITS = {
  wholeInputLimits: { maxInputBytes: 4096, maxFindings: 16 },
  incrementalLimits: {
    maxInputCodeUnits: 4096,
    maxBufferedCodeUnits: 2176,
    maxTokenCodeUnits: 1024,
    maxMultilineCodeUnits: 2048,
  },
  traversalLimits: { maxDepth: 4, maxNodes: 64 },
};

class FakeScanError extends Error {
  constructor(code, message = "fixed message") {
    super(message);
    this.code = code;
  }
}

/** A fake core that "redacts" SYNTHETIC and, like a future core might,
 * attaches fields outside the contract to every finding. */
function fakeApi({ action = "redact", extraFields = true } = {}) {
  function scan(text, offset = 0) {
    const index = text.indexOf(SYNTHETIC);
    if (index === -1) return { text, findings: [] };
    const finding = {
      id: "finding-1",
      type: "synthetic",
      detector: "fake",
      confidence: "high",
      action,
      obfuscation: "none",
      start: offset + index,
      end: offset + index + SYNTHETIC.length,
      ...(extraFields ? { score: 0.97, match: SYNTHETIC } : {}),
    };
    const replaced = action === "redact" || action === "block" ? text.replace(SYNTHETIC, "<SECRET_1>") : text;
    return { text: replaced, findings: [finding] };
  }
  return {
    aborts: 0,
    scanAndRedact: (text) => scan(text),
    createIncrementalSanitizer() {
      const api = this;
      let buffer = "";
      return {
        append(chunk) {
          buffer += chunk;
          return { text: "", findings: [] };
        },
        finalize() {
          return scan(buffer);
        },
        abort() {
          api.aborts += 1;
          buffer = "";
        },
      };
    },
  };
}

test("the fixture is well formed and names only contract reasons and operations", () => {
  assert.equal(fixture.schemaVersion, 1);
  assert.deepEqual(fixture.safeFindingFields, SAFE_FINDING_FIELDS);
  assert.deepEqual(fixture.blockReasons, BLOCK_REASONS);
  const ids = fixture.cases.map((testCase) => testCase.id);
  assert.equal(new Set(ids).size, ids.length, "case IDs are unique");
  const operations = new Set(["sanitizeText", "sanitizeValue", "buildContext", "stream"]);
  const reasonsSeen = new Set();
  for (const testCase of fixture.cases) {
    assert.ok(operations.has(testCase.operation), testCase.id);
    assert.ok(Array.isArray(testCase.secrets), `${testCase.id}: secrets list`);
    const outcomes = testCase.operation === "stream" ? testCase.expected : [testCase.expected];
    for (const outcome of outcomes) {
      assert.ok(["ok", "blocked", "aborted"].includes(outcome.outcome), testCase.id);
      if (outcome.outcome === "blocked") {
        assert.ok(BLOCK_REASONS.includes(outcome.reason), testCase.id);
        reasonsSeen.add(outcome.reason);
      }
      if (outcome.outcome !== "ok") {
        assert.equal("value" in outcome || "findings" in outcome, false, `${testCase.id}: non-ok outcome carries data`);
      }
      for (const finding of outcome.findings ?? []) {
        assert.deepEqual(Object.keys(finding), SAFE_FINDING_FIELDS, `${testCase.id}: finding field order`);
      }
    }
  }
  assert.deepEqual([...reasonsSeen].sort(), [...BLOCK_REASONS].sort(), "every block reason has a case");
});

test("findings and telemetry carry only the contract fields, never a score or a match", () => {
  const events = [];
  const boundary = createAiContextBoundary(fakeApi(), {
    ...LIMITS,
    onFinding: (finding, context) => events.push({ finding, context }),
  });
  const outcome = boundary.sanitizeText(`key ${SYNTHETIC}`, { boundary: "user-input" });
  assert.equal(outcome.outcome, "ok");
  assert.equal(outcome.value, "key <SECRET_1>");
  assert.deepEqual(Object.keys(outcome.findings[0]), SAFE_FINDING_FIELDS);
  assert.deepEqual(Object.keys(events[0].finding), SAFE_FINDING_FIELDS);
  assert.deepEqual(events[0].context, { boundary: "user-input" });
  assert.equal(JSON.stringify({ outcome, events }).includes(SYNTHETIC), false);
  assert.ok(Object.isFrozen(outcome) && Object.isFrozen(outcome.findings[0]));
});

test("a thrown error's message and a non-registry code never cross the boundary", () => {
  const api = fakeApi();
  api.scanAndRedact = () => {
    throw new FakeScanError("NOT_A_REGISTRY_CODE", `leaked ${SYNTHETIC}`);
  };
  const boundary = createAiContextBoundary(api, LIMITS);
  assert.deepEqual(boundary.sanitizeText(SYNTHETIC, { boundary: "user-input" }), {
    outcome: "blocked",
    reason: "core_error",
  });
  api.scanAndRedact = () => {
    throw new FakeScanError("TOKEN_LIMIT_EXCEEDED", `leaked ${SYNTHETIC}`);
  };
  assert.deepEqual(boundary.sanitizeText(SYNTHETIC, { boundary: "user-input" }), {
    outcome: "blocked",
    reason: "limit_exceeded",
    code: "TOKEN_LIMIT_EXCEEDED",
  });
});

test("a block finding in a stream aborts the core session and discards staged text", () => {
  const api = fakeApi({ action: "block", extraFields: false });
  const stream = createAiContextBoundary(api, LIMITS).openStream({ boundary: "tool-result" });
  stream.append("ordinary ");
  stream.append(SYNTHETIC);
  assert.deepEqual(stream.finalize(), { outcome: "blocked", reason: "policy" });
  assert.equal(api.aborts, 1);
  assert.deepEqual(stream.finalize(), { outcome: "blocked", reason: "lifecycle" });
});

test("abort after a successful finalize changes nothing; abort before it discards everything", () => {
  const api = fakeApi({ extraFields: false });
  const boundary = createAiContextBoundary(api, LIMITS);
  const finished = boundary.openStream({ boundary: "tool-result" });
  finished.append("ordinary text");
  assert.equal(finished.finalize().value, "ordinary text");
  finished.abort();
  assert.equal(api.aborts, 0);

  const aborted = boundary.openStream({ boundary: "tool-result" });
  aborted.append(SYNTHETIC);
  aborted.abort();
  assert.deepEqual(aborted.finalize(), { outcome: "aborted" });
  assert.equal(api.aborts, 1);
});

test("the runner rejects a core that lets a secret through, naming only the case", () => {
  const passthrough = {
    scanAndRedact: (text) => ({ text, findings: [] }),
    createIncrementalSanitizer: () => ({
      append: (chunk) => ({ text: chunk, findings: [] }),
      finalize: () => ({ text: "", findings: [] }),
      abort: () => {},
    }),
  };
  assert.throws(
    () => runAiContextBoundaryConformance(passthrough, fixture),
    (error) => {
      assert.match(error.message, /^ai-context-boundary [a-z0-9-]+: /);
      for (const testCase of fixture.cases) {
        for (const secret of testCase.secrets) assert.equal(error.message.includes(secret), false);
      }
      return true;
    },
  );
});
