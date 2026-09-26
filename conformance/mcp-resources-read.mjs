/**
 * Fixed failure mapping and conformance runner for the supported MCP
 * `resources/read` boundary (issue #843,
 * `docs/reference/mcp-resources-read.md`,
 * `decision-define-the-supported-mcp-resources-read-boundary`).
 *
 * `resources/read` is a thin specialization of the MCP boundary, which is a
 * thin specialization of the AI-context boundary. The two operations,
 * `sanitizeResourceResult` and `sanitizeResourceRead`, are methods of the
 * MCP reference model (`createMcpBoundary` in `./mcp-boundary.mjs`), where
 * they share its binary-content rule and key-context backstop. This file adds
 * only what differs from `tools/call`:
 *
 * - a `ReadResourceResult` has no `isError`, so a non-`ok` outcome maps to a
 *   fixed, input-free JSON-RPC error (`code` -32603, a fixed `message`, and
 *   no `data`), the error shape the MCP specification gives `resources/read`;
 * - the host's own failure outcome is `read_error`, not `tool_error`;
 * - the runner that replays `conformance/fixtures/mcp-resources-read.json`.
 *
 * Like `./mcp-boundary.mjs`: no MCP SDK import, plain ESM, no Node.js import,
 * so the same file runs in the browser lane. Failure messages name a case ID
 * and a field only, never an input, a value, or a matched secret.
 */

import { BLOCK_REASONS, SAFE_FINDING_FIELDS, createAiContextBoundary } from "./ai-context-boundary.mjs";
import { MCP_AUDIT_FIELDS, MCP_BOUNDARY_LABELS, createMcpBoundary, mcpAuditRecord } from "./mcp-boundary.mjs";

/** The `resources/read` outcomes: the AI-context three, plus the host's own `read_error`. */
export const MCP_RESOURCE_OUTCOMES = Object.freeze(["ok", "blocked", "aborted", "read_error"]);

/**
 * JSON-RPC "Internal error". The MCP specification lists it, with -32002
 * "Resource not found", as the errors a server returns for `resources/read`.
 * -32002 is not used: a blocked resource exists, and a host that treats it
 * as missing may cache or report that.
 */
export const MCP_RESOURCE_ERROR_CODE = -32603;

/** Fixed `message` of the JSON-RPC error a `blocked` outcome maps to. */
export const MCP_RESOURCE_BLOCKED_MESSAGE =
  "This MCP resource read was blocked by secret-redaction policy. No content, URI, or error detail is included.";

/** Fixed `message` of the JSON-RPC error a `read_error` outcome maps to. */
export const MCP_RESOURCE_READ_ERROR_MESSAGE =
  "This MCP resource read failed. No content, URI, or error detail is included.";

/** Fixed, input-free JSON-RPC error object for a `blocked` outcome. A new object each call; never a `data` member. */
export function mcpResourceBlockedError() {
  return { code: MCP_RESOURCE_ERROR_CODE, message: MCP_RESOURCE_BLOCKED_MESSAGE };
}

/** Fixed, input-free JSON-RPC error object for a `read_error` outcome. A new object each call; never a `data` member. */
export function mcpResourceReadError() {
  return { code: MCP_RESOURCE_ERROR_CODE, message: MCP_RESOURCE_READ_ERROR_MESSAGE };
}

/**
 * What a `resources/read` outcome may put on the wire or into the host's
 * context, logs, or store:
 *
 * - `ok`: `{ result }`, the sanitized `ReadResourceResult`, and nothing else;
 * - `blocked` (every reason, `core_error` included): `{ error }`,
 *   {@link mcpResourceBlockedError};
 * - `read_error`: `{ error }`, {@link mcpResourceReadError};
 * - `aborted`: `null`. A cancelled request gets no response, and a
 *   cancelled client read is discarded.
 *
 * A server sends `error` as the JSON-RPC error of the request; a client
 * host records or shows it in place of the resource.
 */
export function toReadResourceResponse(outcome) {
  switch (outcome?.outcome) {
    case "ok":
      return { result: outcome.value };
    case "blocked":
      return { error: mcpResourceBlockedError() };
    case "read_error":
      return { error: mcpResourceReadError() };
    case "aborted":
      return null;
    default:
      throw new TypeError("toReadResourceResponse: not an MCP resources/read outcome");
  }
}

// ---------------------------------------------------------------------
// Conformance runner
// ---------------------------------------------------------------------

const POLICIES = {
  default: () => undefined,
  "block-all": () => ({ evaluate: () => "block" }),
  throwing: () => ({
    evaluate: () => {
      throw new Error("synthetic policy failure");
    },
  }),
};

function fail(caseId, field) {
  throw new Error(`mcp-resources-read ${caseId}: ${field}`);
}

function sameJson(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

function observable(outcome) {
  return JSON.parse(JSON.stringify(outcome));
}

function incrementalLimitsFrom(fixture) {
  const limits = fixture.limits.incremental;
  return {
    maxInputCodeUnits: limits.maxInputBytes,
    maxBufferedCodeUnits: limits.maxBufferedBytes,
    maxTokenCodeUnits: limits.maxTokenBytes,
    maxMultilineCodeUnits: limits.maxMultilineBytes,
  };
}

/** A fixture text entry may be `{ repeat, count }` so a large resource stays readable. */
function materialize(value) {
  if (Array.isArray(value)) return value.map(materialize);
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 2 && typeof value.repeat === "string" && Number.isInteger(value.count)) {
      return value.repeat.repeat(value.count);
    }
    const out = {};
    for (const key of keys) out[key] = materialize(value[key]);
    return out;
  }
  return value;
}

function checkNoLeak(caseId, testCase, outcome, delivered, audit, events) {
  const secrets = testCase.secrets ?? [];
  const metadata = JSON.stringify({ ...outcome, value: undefined }) + JSON.stringify(events) + JSON.stringify(audit);
  const value = outcome.outcome === "ok" ? JSON.stringify(outcome.value) : JSON.stringify(delivered);
  for (const secret of secrets) {
    if (metadata.includes(secret)) fail(caseId, "a secret reached outcome metadata, audit, or telemetry");
    if (!testCase.valueMayContainSecrets && value !== undefined && value.includes(secret)) {
      fail(caseId, "a secret reached the delivered response");
    }
  }
  for (const event of events) {
    if (!sameJson(Object.keys(event.finding).sort(), [...SAFE_FINDING_FIELDS].sort())) {
      fail(caseId, "telemetry finding carries non-contract fields");
    }
    if (!sameJson(Object.keys(event.context), ["boundary"])) fail(caseId, "telemetry context carries non-contract fields");
    if (event.context.boundary !== MCP_BOUNDARY_LABELS.resource) fail(caseId, "telemetry label");
  }
  if (!MCP_RESOURCE_OUTCOMES.includes(outcome.outcome)) fail(caseId, "unknown outcome");
  if (outcome.outcome !== "ok" && ("value" in outcome || "findings" in outcome)) {
    fail(caseId, "a non-ok outcome carries a value or findings");
  }
  if (outcome.outcome === "blocked" && !BLOCK_REASONS.includes(outcome.reason)) fail(caseId, "unknown block reason");
  if (Object.keys(audit).some((key) => !MCP_AUDIT_FIELDS.includes(key))) fail(caseId, "audit record carries non-contract fields");
  if (audit.stage !== "resource") fail(caseId, "audit stage");
}

/** Every non-`ok` outcome maps onto exactly the fixture's fixed error, or onto nothing. */
function checkMapping(caseId, fixture, outcome, delivered) {
  if (outcome.outcome === "ok") {
    if (!sameJson(delivered, { result: outcome.value })) fail(caseId, "an ok outcome must deliver exactly its value");
  } else if (outcome.outcome === "aborted") {
    if (delivered !== null) fail(caseId, "an aborted outcome must deliver nothing");
  } else {
    const expected = outcome.outcome === "blocked" ? fixture.fixedErrors.blocked : fixture.fixedErrors.readError;
    if (!sameJson(delivered, { error: expected })) fail(caseId, "a non-ok outcome must deliver the fixed error");
  }
}

function defaultCreateBoundary(api, options) {
  return createMcpBoundary(createAiContextBoundary(api, options), { binaryContent: options.binaryContent });
}

/**
 * Replays every `resources/read` fixture case for `phase` and returns a
 * count-only summary. Throws on the first divergence. `createBoundary(api,
 * options)` builds the implementation under test (default: the MCP
 * reference model); it must expose `sanitizeResourceResult` and
 * `sanitizeResourceRead`. `options` carries the fixture's limits, `policy`,
 * `onFinding`, and `binaryContent`.
 */
export async function runMcpResourcesReadConformance(
  api,
  fixture,
  { phase = "initialized", createBoundary = defaultCreateBoundary } = {},
) {
  if (fixture.schemaVersion !== 1) throw new Error("mcp-resources-read fixture: unsupported schema");
  if (!sameJson(fixture.safeFindingFields, SAFE_FINDING_FIELDS)) {
    throw new Error("mcp-resources-read fixture: safe finding fields diverge from the runner");
  }
  if (
    !sameJson(fixture.fixedErrors.blocked, mcpResourceBlockedError()) ||
    !sameJson(fixture.fixedErrors.readError, mcpResourceReadError())
  ) {
    throw new Error("mcp-resources-read fixture: fixed errors diverge from the runner");
  }
  if (fixture.label !== MCP_BOUNDARY_LABELS.resource) {
    throw new Error("mcp-resources-read fixture: label diverges from the runner");
  }
  const summary = { cases: 0, reads: 0, telemetryEvents: 0 };

  for (const testCase of fixture.cases) {
    if ((testCase.phase ?? "initialized") !== phase) continue;
    const events = [];
    const boundary = createBoundary(api, {
      wholeInputLimits: fixture.limits.wholeInput,
      incrementalLimits: incrementalLimitsFrom(fixture),
      traversalLimits: fixture.limits.traversal,
      policy: POLICIES[testCase.policy ?? "default"](),
      binaryContent: testCase.binaryContent ?? "block",
      onFinding: (finding, context) => {
        events.push({ finding: { ...finding }, context: { ...context } });
      },
    });
    const signal = { aborted: testCase.signal === "aborted-before" };
    const result = materialize(testCase.result);
    let outcome;

    if (testCase.operation === "resourceResult") {
      outcome = boundary.sanitizeResourceResult(result, { signal });
    } else if (testCase.operation === "resourceRead") {
      const secret = (testCase.secrets ?? [])[0] ?? "";
      let reads = 0;
      outcome = await boundary.sanitizeResourceRead(
        async () => {
          reads += 1;
          if (testCase.readThrows) throw new Error(`synthetic read failure ${secret}`);
          if (testCase.signal === "aborted-during") signal.aborted = true;
          return result;
        },
        { signal },
      );
      if (testCase.expectedReads !== undefined && reads !== testCase.expectedReads) fail(testCase.id, "reads");
      summary.reads += reads;
    } else {
      fail(testCase.id, "unknown operation");
    }

    if (!sameJson(observable(outcome), materialize(testCase.expected))) fail(testCase.id, "outcome");
    const delivered = toReadResourceResponse(outcome);
    const audit = mcpAuditRecord(outcome, "resource");
    checkMapping(testCase.id, fixture, outcome, delivered);
    checkNoLeak(testCase.id, testCase, outcome, delivered, audit, events);
    if (testCase.expectedLabels !== undefined) {
      const labels = [...new Set(events.map((event) => event.context.boundary))];
      if (!sameJson(labels, testCase.expectedLabels)) fail(testCase.id, "telemetry labels");
    }
    summary.cases += 1;
    summary.telemetryEvents += events.length;
  }
  return summary;
}
