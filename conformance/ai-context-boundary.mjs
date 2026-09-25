/**
 * JavaScript reference model and conformance runner for the framework-neutral
 * AI-context boundary contract (issue #610,
 * `docs/reference/ai-context-boundary.md`,
 * `decision-define-the-framework-neutral-ai-context-boundary-contract`).
 *
 * `createAiContextBoundary(api, options)` is the contract written as the
 * smallest code that satisfies it. It exists to prove that the contract can
 * be implemented from documented `@redact-secret/core` exports alone --
 * `scanAndRedact`, `createIncrementalSanitizer`, and `SecretScanError.code`
 * -- and to give `redact-secret-adapters` an executable oracle. It is not a
 * package export, and it is not the adapter: the adapters repository owns the
 * installable implementation (redact-secret/redact-secret-adapters#12).
 *
 * `runAiContextBoundaryConformance(api, fixture, { phase })` replays
 * `conformance/fixtures/ai-context-boundary.json` through that model. It is
 * run against the packed, clean-installed package by
 * `scripts/consumer-harness.mjs` (publish-shaped artifacts) and against a
 * fake core by `conformance/ai-context-boundary.test.mjs`.
 *
 * Plain ESM, no Node.js import: the same file runs in the browser lane.
 * Failure messages name a case ID and a field only, never an input, a value,
 * or a matched secret.
 */

export const SAFE_FINDING_FIELDS = Object.freeze([
  "id",
  "type",
  "detector",
  "confidence",
  "action",
  "obfuscation",
  "start",
  "end",
]);

export const BLOCK_REASONS = Object.freeze([
  "policy",
  "limit_exceeded",
  "unsupported_value",
  "lifecycle",
  "core_error",
]);

const LIMIT_CODES = new Set([
  "INPUT_LIMIT_EXCEEDED",
  "FINDING_LIMIT_EXCEEDED",
  "BUFFER_LIMIT_EXCEEDED",
  "TOKEN_LIMIT_EXCEEDED",
  "MULTILINE_LIMIT_EXCEEDED",
]);

/** Only a code from the core's fixed registry may cross the boundary. */
const CORE_CODES = new Set([
  "INVALID_INPUT",
  "INVALID_OPTIONS",
  "INVALID_DETECTOR",
  "DETECTOR_FAILURE",
  "INVALID_CANDIDATE",
  "POLICY_FAILURE",
  "INVALID_POLICY_ACTION",
  "INVALID_FINDINGS",
  "PLACEHOLDER_FAILURE",
  "INVALID_PLACEHOLDER",
  "INVALID_LIMITS",
  "INPUT_LIMIT_EXCEEDED",
  "FINDING_LIMIT_EXCEEDED",
  "BUFFER_LIMIT_EXCEEDED",
  "TOKEN_LIMIT_EXCEEDED",
  "MULTILINE_LIMIT_EXCEEDED",
  "INVALID_STATE",
  "INVALID_RULESET",
  "NOT_INITIALIZED",
  "INITIALIZATION_FAILED",
  "INVALID_CHUNK",
  "INVALID_UTF8",
  "UNPAIRED_SURROGATE",
]);

function isAborted(signal) {
  return signal != null && signal.aborted === true;
}

function safeFinding(finding) {
  const copy = {};
  for (const field of SAFE_FINDING_FIELDS) copy[field] = finding[field];
  return Object.freeze(copy);
}

function blocked(reason, code) {
  return code === undefined
    ? Object.freeze({ outcome: "blocked", reason })
    : Object.freeze({ outcome: "blocked", reason, code });
}

const ABORTED = Object.freeze({ outcome: "aborted" });

function ok(value, findings) {
  return Object.freeze({ outcome: "ok", value, findings: Object.freeze(findings) });
}

/** Maps any thrown value to a fixed failure. Never reads `error.message`. */
function failureFrom(error) {
  const code =
    error !== null && typeof error === "object" && CORE_CODES.has(error.code) ? error.code : undefined;
  if (code !== undefined && LIMIT_CODES.has(code)) return blocked("limit_exceeded", code);
  if (code === "INVALID_STATE") return blocked("lifecycle", code);
  return blocked("core_error", code);
}

function isPlainObject(value) {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * @param {{ scanAndRedact: Function, createIncrementalSanitizer: Function }} api
 * @param {{
 *   wholeInputLimits: { maxInputBytes: number, maxFindings: number },
 *   incrementalLimits: { maxInputCodeUnits: number, maxBufferedCodeUnits: number, maxTokenCodeUnits: number, maxMultilineCodeUnits: number },
 *   traversalLimits: { maxDepth: number, maxNodes: number },
 *   policy?: { evaluate: Function },
 *   onFinding?: (finding: object, context: { boundary: string }) => void,
 * }} options
 */
export function createAiContextBoundary(api, options) {
  const { wholeInputLimits, incrementalLimits, traversalLimits, policy, onFinding } = options;
  if (!wholeInputLimits || !incrementalLimits || !traversalLimits) {
    throw new TypeError("createAiContextBoundary: every limit set is required");
  }

  function emit(findings, boundary) {
    if (typeof onFinding !== "function") return;
    for (const finding of findings) {
      try {
        onFinding(finding, Object.freeze({ boundary }));
      } catch {
        // Telemetry is observational: a throwing callback never changes
        // the outcome and its error is never read or rethrown.
      }
    }
  }

  /** One whole-input scan; `null` result means a fixed failure. */
  function scanText(text) {
    if (typeof text !== "string") return { failure: blocked("unsupported_value") };
    try {
      const result = api.scanAndRedact(text, { policy, limits: wholeInputLimits });
      return { text: result.text, findings: result.findings.map(safeFinding) };
    } catch (error) {
      return { failure: failureFrom(error) };
    }
  }

  function sanitizeText(text, { boundary, signal } = {}) {
    if (isAborted(signal)) return ABORTED;
    const scanned = scanText(text);
    if (scanned.failure) return scanned.failure;
    emit(scanned.findings, boundary);
    if (scanned.findings.some((finding) => finding.action === "block")) return blocked("policy");
    if (isAborted(signal)) return ABORTED;
    return ok(scanned.text, scanned.findings);
  }

  function sanitizeValue(value, { boundary, signal } = {}) {
    if (isAborted(signal)) return ABORTED;
    const findings = [];
    let nodes = 0;
    const seen = new Set();

    // Returns { value } or { failure }.
    function walk(node, depth) {
      nodes += 1;
      if (nodes > traversalLimits.maxNodes) return { failure: blocked("limit_exceeded") };
      if (typeof node === "string") {
        const scanned = scanText(node);
        if (scanned.failure) return scanned;
        emit(scanned.findings, boundary);
        findings.push(...scanned.findings);
        if (scanned.findings.some((finding) => finding.action === "block")) return { failure: blocked("policy") };
        return { value: scanned.text };
      }
      if (node === null || typeof node === "boolean" || (typeof node === "number" && Number.isFinite(node))) {
        return { value: node };
      }
      const container = Array.isArray(node) || isPlainObject(node);
      if (!container) return { failure: blocked("unsupported_value") };
      if (seen.has(node)) return { failure: blocked("unsupported_value") };
      if (depth + 1 > traversalLimits.maxDepth) return { failure: blocked("limit_exceeded") };
      seen.add(node);
      try {
        if (Array.isArray(node)) {
          const out = [];
          for (const item of node) {
            const child = walk(item, depth + 1);
            if (child.failure) return child;
            out.push(child.value);
          }
          return { value: out };
        }
        const out = {};
        for (const key of Object.keys(node)) {
          // Keys are scanned too. A key cannot be rewritten without changing
          // the value's shape, so any non-passing key finding blocks.
          const scannedKey = scanText(key);
          if (scannedKey.failure) return scannedKey;
          emit(scannedKey.findings, boundary);
          if (scannedKey.findings.some((finding) => finding.action === "block" || finding.action === "redact")) {
            return { failure: blocked("policy") };
          }
          const child = walk(node[key], depth + 1);
          if (child.failure) return child;
          Object.defineProperty(out, key, { value: child.value, enumerable: true, configurable: true, writable: true });
        }
        return { value: out };
      } finally {
        seen.delete(node);
      }
    }

    const walked = walk(value, 0);
    if (walked.failure) return walked.failure;
    if (isAborted(signal)) return ABORTED;
    return ok(walked.value, findings);
  }

  function buildContext(parts, { signal } = {}) {
    if (isAborted(signal)) return ABORTED;
    const messages = [];
    const findings = [];
    for (const part of parts) {
      const outcome =
        "text" in part
          ? sanitizeText(part.text, { boundary: part.boundary, signal })
          : sanitizeValue(part.value, { boundary: part.boundary, signal });
      if (outcome.outcome !== "ok") return outcome;
      findings.push(...outcome.findings);
      messages.push(Object.freeze({ role: part.role, content: outcome.value }));
    }
    if (isAborted(signal)) return ABORTED;
    return ok(Object.freeze(messages), findings);
  }

  /** A staged (all-or-nothing) incremental boundary. */
  function openStream({ boundary, signal } = {}) {
    let session;
    let terminal; // the outcome the first finalize reports, once decided
    let finalized = false;
    let staged = "";
    let findings = [];

    function fail(outcome) {
      if (terminal === undefined) terminal = outcome;
      staged = "";
      findings = [];
      if (session !== undefined) {
        try {
          session.abort();
        } catch {
          // Cleanup on an already-failed session; the outcome is decided.
        }
      }
    }

    if (isAborted(signal)) {
      fail(ABORTED);
    } else {
      try {
        session = api.createIncrementalSanitizer({ limits: incrementalLimits, policy });
      } catch (error) {
        fail(failureFrom(error));
      }
    }

    function record(result) {
      const safe = result.findings.map(safeFinding);
      emit(safe, boundary);
      findings.push(...safe);
      staged += result.text;
      if (safe.some((finding) => finding.action === "block")) fail(blocked("policy"));
    }

    return {
      append(chunk) {
        if (finalized || terminal !== undefined) return;
        if (isAborted(signal)) return fail(ABORTED);
        if (typeof chunk !== "string") return fail(blocked("unsupported_value"));
        try {
          record(session.append(chunk));
        } catch (error) {
          fail(failureFrom(error));
        }
      },
      finalize() {
        if (finalized) return blocked("lifecycle");
        finalized = true;
        if (terminal === undefined && isAborted(signal)) fail(ABORTED);
        if (terminal === undefined) {
          try {
            record(session.finalize());
          } catch (error) {
            fail(failureFrom(error));
          }
        }
        if (terminal !== undefined) return terminal;
        const outcome = ok(staged, findings);
        staged = "";
        findings = [];
        return outcome;
      },
      abort() {
        if (finalized) return;
        fail(ABORTED);
      },
    };
  }

  return Object.freeze({ sanitizeText, sanitizeValue, buildContext, openStream });
}

// ---------------------------------------------------------------------
// Conformance runner
// ---------------------------------------------------------------------

function materialize(input) {
  if (typeof input === "string") return input;
  if (input && typeof input.repeat === "string") return input.repeat.repeat(input.count);
  throw new Error("ai-context-boundary fixture: unsupported input form");
}

function materializeValue(value) {
  if (isPlainObject(value) && typeof value.construct === "string") {
    if (value.construct === "array-of-strings") return Array.from({ length: value.count }, () => value.item);
    if (value.construct === "non-plain-object") return { when: new Date(0) };
    if (value.construct === "cycle") {
      const node = { label: "ordinary text" };
      node.self = node;
      return node;
    }
    throw new Error("ai-context-boundary fixture: unsupported construct");
  }
  return value;
}

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
  throw new Error(`ai-context-boundary ${caseId}: ${field}`);
}

function sameJson(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

/** Observable outcome, in fixture shape (frozen objects serialize as-is). */
function observable(outcome) {
  return JSON.parse(JSON.stringify(outcome));
}

function checkNoLeak(caseId, testCase, outcome, events) {
  const secrets = testCase.secrets ?? [];
  const metadata = JSON.stringify({ ...outcome, value: undefined }) + JSON.stringify(events);
  const value = outcome.outcome === "ok" ? JSON.stringify(outcome.value) : "";
  for (const secret of secrets) {
    if (metadata.includes(secret)) fail(caseId, "a secret reached outcome metadata or telemetry");
    if (!testCase.valueMayContainSecrets && value.includes(secret)) fail(caseId, "a secret reached the safe value");
  }
  for (const event of events) {
    const keys = Object.keys(event.finding).sort();
    if (!sameJson(keys, [...SAFE_FINDING_FIELDS].sort())) fail(caseId, "telemetry finding carries non-contract fields");
    if (!sameJson(Object.keys(event.context), ["boundary"])) fail(caseId, "telemetry context carries non-contract fields");
  }
  if (outcome.outcome !== "ok" && ("value" in outcome || "findings" in outcome)) {
    fail(caseId, "a non-ok outcome carries a value or findings");
  }
  if (outcome.outcome === "blocked" && !BLOCK_REASONS.includes(outcome.reason)) fail(caseId, "unknown block reason");
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

function isValidStringBoundary(input, index) {
  if (index <= 0 || index >= input.length) return true;
  const before = input.charCodeAt(index - 1);
  const after = input.charCodeAt(index);
  return !(before >= 0xd800 && before <= 0xdbff && after >= 0xdc00 && after <= 0xdfff);
}

/**
 * Replays every fixture case for `phase` ("uninitialized" runs only the
 * cases that must be observed before `initialize()`; "initialized" runs the
 * rest) and returns a count-only summary. Throws on the first divergence.
 */
export function runAiContextBoundaryConformance(api, fixture, { phase = "initialized", runtime = "javascript" } = {}) {
  if (fixture.schemaVersion !== 1) throw new Error("ai-context-boundary fixture: unsupported schema");
  if (!sameJson(fixture.safeFindingFields, SAFE_FINDING_FIELDS)) {
    throw new Error("ai-context-boundary fixture: safe finding fields diverge from the runner");
  }
  const summary = { cases: 0, partitions: 0, telemetryEvents: 0 };

  for (const testCase of fixture.cases) {
    if (testCase.runtimes && !testCase.runtimes.includes(runtime)) continue;
    if ((testCase.phase ?? "initialized") !== phase) continue;
    const events = [];
    const throwingTelemetry = testCase.telemetry === "throwing";
    const makeBoundary = () =>
      createAiContextBoundary(api, {
        wholeInputLimits: fixture.limits.wholeInput,
        incrementalLimits: incrementalLimitsFrom(fixture),
        traversalLimits: fixture.limits.traversal,
        policy: POLICIES[testCase.policy ?? "default"](),
        onFinding: (finding, context) => {
          events.push({ finding: { ...finding }, context: { ...context } });
          if (throwingTelemetry) throw new Error("synthetic telemetry failure");
        },
      });
    const boundary = makeBoundary();
    const signal = { aborted: testCase.signal === "aborted-before" };

    if (testCase.operation === "stream") {
      const stream = boundary.openStream({ boundary: testCase.boundary, signal });
      const outcomes = [];
      for (const step of testCase.steps) {
        if (step.op === "append") stream.append(materialize(step.chunk));
        else if (step.op === "abort") stream.abort();
        else if (step.op === "signal") signal.aborted = true;
        else if (step.op === "finalize") outcomes.push(stream.finalize());
        else fail(testCase.id, "unknown step");
      }
      if (!sameJson(outcomes.map(observable), testCase.expected)) fail(testCase.id, "stream outcomes");
      for (const outcome of outcomes) checkNoLeak(testCase.id, testCase, outcome, events);
    } else {
      let outcome;
      if (testCase.operation === "sanitizeText") {
        outcome = boundary.sanitizeText(materialize(testCase.input), { boundary: testCase.boundary, signal });
      } else if (testCase.operation === "sanitizeValue") {
        outcome = boundary.sanitizeValue(materializeValue(testCase.value), { boundary: testCase.boundary, signal });
      } else if (testCase.operation === "buildContext") {
        outcome = boundary.buildContext(testCase.parts, { signal });
      } else {
        fail(testCase.id, "unknown operation");
      }
      if (!sameJson(observable(outcome), testCase.expected)) fail(testCase.id, "outcome");
      checkNoLeak(testCase.id, testCase, outcome, events);

      // Whole-input / incremental equivalence: the staged stream outcome for
      // every two-chunk partition, and one chunk per UTF-16 segment, equals
      // the whole-input outcome.
      if (testCase.operation === "sanitizeText" && testCase.incrementalEquivalence !== false && testCase.signal === undefined) {
        const input = materialize(testCase.input);
        const partitions = [];
        // Every boundary of a short input; a deterministic, evenly spaced
        // sample (plus both edges) of a long one, so an oversized-input case
        // stays cheap on the slowest browser lane.
        const step = input.length <= 256 ? 1 : Math.ceil(input.length / 64);
        for (let index = 0; index <= input.length; index += 1) {
          const sampled = index % step === 0 || index === input.length;
          if (sampled && isValidStringBoundary(input, index)) partitions.push([input.slice(0, index), input.slice(index)]);
        }
        if (input.length <= 256) partitions.push(Array.from(input));
        for (const chunks of partitions) {
          const stream = makeBoundary().openStream({ boundary: testCase.boundary, signal: { aborted: false } });
          for (const chunk of chunks) stream.append(chunk);
          const streamed = stream.finalize();
          if (!sameJson(observable(streamed), testCase.expected)) fail(testCase.id, "incremental outcome diverges from whole-input");
          checkNoLeak(testCase.id, testCase, streamed, events);
          summary.partitions += 1;
        }
      }
    }
    summary.cases += 1;
    summary.telemetryEvents += events.length;
  }
  return summary;
}
