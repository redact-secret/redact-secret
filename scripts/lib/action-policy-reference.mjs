/**
 * Runs the shared declarative action policy fixture
 * (`conformance/fixtures/action-policy-v1.json`, issues #1217 and #1219,
 * `decision-define-the-versioned-declarative-action-policy-and-default-overlay`)
 * against one JavaScript surface, so the Node addon, the WebAssembly artifact
 * and the published package on top of each are held to the same accepted
 * documents, the same rejection code (and, where the surface reports them,
 * class and rule index), the same actions and the same host obligations as the
 * Rust core and the CLI, which have their own consumers of the same file.
 *
 * Division of labour with the Rust core. The core runs `evaluations` for
 * semantics. A JavaScript surface cannot construct a finding without
 * scanning, so it runs the part of `evaluations` whose finding a synthetic
 * input can produce (`SCANNABLE`), and `endToEnd` for the rest of the
 * plumbing. The findings no synthetic input here produces (`jwt-medium`,
 * `contextual-low`, the unknown and not-yet-emitted names) are counted as
 * `unscannableEvaluations`, never silently dropped; their `base` is still
 * reached through `defaultAction` for the anchors the fixture freezes. The
 * core does not expose which rule matched (that is #1220), so `expectedRule`
 * is not observable here and only the resulting action is compared.
 *
 * A surface is described by an object, so this file carries no process,
 * environment or network access of its own:
 *
 * - `profile`: `"full"` or `"common"`. A case whose no-policy scan does not
 *   reproduce the fixture's finding on this profile is skipped and counted
 *   (`common` links fewer detectors), never failed.
 * - `scan(document, input, ruleset)`: the surface's findings for `input`
 *   under the document bytes (a `Buffer`, or `undefined` for none), each with
 *   `type`, `detector`, `confidence`, `obfuscation`, `action`, `start` and
 *   `end` in UTF-16 code units.
 * - `scanAndRedact(document, input)`: `{ text, findings }`.
 * - `incremental(document, chunks)`: the findings a session over `chunks`
 *   releases, in order, with absolute UTF-16 offsets.
 * - `reject(document)`: `undefined` when the surface loads the document, else
 *   `{ code, message, class, ruleIndex }`. `class` and `ruleIndex` are
 *   `undefined` on a surface that carries only the code (the public package,
 *   by design) and are compared when present.
 * - `defaultAction(finding)`: the surface's default evaluation of one
 *   finding's metadata.
 * - `callback`: `scan(document, input, evaluate)` and
 *   `incremental(document, chunks, evaluate)` with a legacy callback, each
 *   returning `{ findings }` or `{ code }`.
 *
 * Every document and input in the fixture is synthetic. The failures this
 * returns name a case id, a class and a count, never a document or an input.
 */

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FIXTURE_PATH = join(REPO_ROOT, "conformance", "fixtures", "action-policy-v1.json");

/** Counts the fixture's own totals, so a truncated or edited fixture fails loudly. */
const EXPECTED = {
  evaluations: 37,
  rejections: 17,
  additionalRejections: 41,
  accepted: 7,
  endToEnd: 5,
  obligations: 7,
};

/** Large enough that no partition of any fixture input reaches a limit. */
export const SESSION_LIMITS = Object.freeze({
  maxInputBytes: 1 << 20,
  maxBufferedBytes: 16_512,
  maxTokenBytes: 8_192,
  maxMultilineBytes: 16_384,
});

/**
 * Synthetic inputs whose one finding carries the metadata of a fixture
 * finding. Each is checked against the fixture's metadata before it is used,
 * so a detector change that moves one fails the case instead of passing it.
 */
const SCANNABLE = Object.freeze({
  "private-key-high": "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRURfRklYVFVSRQ==\n-----END PRIVATE KEY-----\n",
  "github-high": "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000",
  "github-high-invisible": "API_KEY=ghp_SYNTHE\u200bTICREVOKED00000000000000000000",
  "bearer-high": ["Authorization: Bear", "er fedcba9876543210fedcba9876543210"].join(""),
  "contextual-high": ["API_KEY=Zq8Rk3Lm9Xp2", "Vw7Tn4Yb6Hc1Js5Df0Ga"].join(""),
  "contextual-medium": "api_key = abcdefghij1234",
});

const RULESET_INPUT = "ACME_AN_aB1cD2eF3gH4iJ5kL6mN";

export function loadActionPolicyFixture() {
  const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));
  const counts = {
    evaluations: fixture.evaluations.length,
    rejections: fixture.rejections.length,
    additionalRejections: fixture.additionalRejections.length,
    accepted: fixture.acceptedDocuments.length,
    endToEnd: fixture.endToEnd.cases.length,
    obligations: fixture.hostObligations.length,
  };
  for (const [name, expected] of Object.entries(EXPECTED)) {
    if (counts[name] !== expected) {
      throw new Error(`action-policy-v1.json: expected ${expected} ${name}, found ${counts[name]}`);
    }
  }
  return fixture;
}

/** The document bytes of one fixture entry: raw text, compact JSON, or a synthesized bound. */
export function documentBytes(entry) {
  if (entry.documentText !== undefined) return Buffer.from(entry.documentText, "utf8");
  if (entry.document !== undefined) return Buffer.from(JSON.stringify(entry.document), "utf8");
  const synthesis = entry.synthesis;
  if (synthesis === undefined) throw new Error(`fixture entry ${entry.id} carries no document`);
  if (synthesis.kind === "padded") {
    const bytes = Buffer.from(synthesis.base, "utf8");
    if (bytes.length > synthesis.totalBytes) throw new Error(`${entry.id}: base longer than totalBytes`);
    return Buffer.concat([bytes, Buffer.alloc(synthesis.totalBytes - bytes.length, 0x20)]);
  }
  if (synthesis.kind === "rule-count") {
    const rules = Array.from(
      { length: synthesis.count },
      (_, index) => `{"id":"r${index}","match":{"type":["jwt"]},"action":"warn"}`,
    );
    return Buffer.from(`{"actionPolicyRevision":1,"base":"default","rules":[${rules.join(",")}]}`, "utf8");
  }
  if (synthesis.kind === "set-size") {
    const members = Array.from({ length: synthesis.count }, (_, index) => `"t${index}"`);
    return Buffer.from(
      `{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":[${members.join(",")}]},"action":"warn"}]}`,
      "utf8",
    );
  }
  throw new Error(`unknown synthesis kind ${synthesis.kind}`);
}

function namedPolicy(fixture, id) {
  const policy = fixture.policies.find((entry) => entry.id === id);
  if (policy === undefined) throw new Error(`fixture has no policy ${id}`);
  return policy;
}

/** The bytes of a policy reference: a policy id or an inline document. */
export function policyBytes(fixture, reference) {
  return typeof reference === "string"
    ? documentBytes(namedPolicy(fixture, reference))
    : Buffer.from(JSON.stringify(reference), "utf8");
}

/** UTF-8 byte offset to UTF-16 code-unit offset, independent of any binding. */
function utf16Offset(text, byteOffset) {
  return Buffer.from(text, "utf8").subarray(0, byteOffset).toString("utf8").length;
}

function describe(finding) {
  return [
    finding.type,
    finding.detector,
    finding.confidence,
    finding.obfuscation,
    finding.action,
    finding.start,
    finding.end,
  ].join("|");
}

function describeAll(findings) {
  return `[${findings.map(describe).join(",")}]`;
}

/** Every split of `input` into two, three (a sample) and single-code-unit chunks. */
function partitions(input) {
  const result = [[input]];
  for (let at = 1; at < input.length; at += 1) result.push([input.slice(0, at), input.slice(at)]);
  const third = Math.max(1, Math.floor(input.length / 3));
  for (let first = 1; first + 1 < input.length; first += third) {
    result.push([input.slice(0, first), input.slice(first, first + third), input.slice(first + third)]);
  }
  result.push([...input]);
  // A surrogate pair split across chunks is not a valid chunk; the fixture inputs are BMP.
  return result.filter((chunks) => chunks.every((chunk) => chunk.length > 0));
}

/** The text a whole-input `scanAndRedact` must give: redact and block spans become `<SECRET_n>`. */
function expectedRedaction(input, findings) {
  let text = "";
  let cursor = 0;
  let index = 0;
  for (const finding of findings) {
    if (finding.action !== "redact" && finding.action !== "block") continue;
    index += 1;
    text += `${input.slice(cursor, finding.start)}<SECRET_${index}>`;
    cursor = finding.end;
  }
  return text + input.slice(cursor);
}

/**
 * Runs the fixture through `surface`. Returns `{ checks, failures, skipped,
 * unscannableEvaluations }`: the number of checks run, one fixed-form string
 * per disagreement, the cases skipped because the profile does not link the
 * detector, and the evaluations no synthetic input reaches.
 */
export function runActionPolicyReference(fixture, surface) {
  const failures = [];
  const skipped = [];
  let checks = 0;
  let unscannableEvaluations = 0;

  const expect = (id, condition, message) => {
    checks += 1;
    if (!condition) failures.push(`${id}: ${message}`);
  };
  const guard = (id, run) => {
    try {
      return run();
    } catch (error) {
      checks += 1;
      failures.push(`${id}: unexpected ${error?.code ?? error?.name ?? "failure"}`);
      return undefined;
    }
  };

  // ------------------------------------------------------------------ anchors
  for (const anchor of fixture.baseAnchors.cases) {
    const finding = { id: "finding-1", ...fixture.findings[anchor.finding], start: 0, end: 1 };
    const actual = guard(`baseAnchors/${anchor.finding}`, () => surface.defaultAction(finding));
    expect(
      `baseAnchors/${anchor.finding}`,
      actual === anchor.expectedAction,
      `expected ${anchor.expectedAction}, got ${actual}`,
    );
  }

  // -------------------------------------------------------------- evaluations
  const noPolicyCache = new Map();
  const noPolicy = (input, ruleset) => {
    const key = `${ruleset === undefined ? "-" : "r"}:${input}`;
    if (!noPolicyCache.has(key)) noPolicyCache.set(key, surface.scan(undefined, input, ruleset));
    return noPolicyCache.get(key);
  };
  const sameMetadata = (finding, wanted) =>
    finding.type === wanted.type &&
    finding.detector === wanted.detector &&
    finding.confidence === wanted.confidence &&
    finding.obfuscation === wanted.obfuscation;

  for (const evaluation of fixture.evaluations) {
    const id = `evaluations/${evaluation.id}`;
    const wanted = fixture.findings[evaluation.finding];
    const scannable = evaluation.finding === "ruleset-medium" ? RULESET_INPUT : SCANNABLE[evaluation.finding];
    if (scannable === undefined) {
      unscannableEvaluations += 1;
      continue;
    }
    const ruleset = evaluation.finding === "ruleset-medium" ? Buffer.from(fixture.endToEnd.ruleset, "utf8") : undefined;
    const base = guard(id, () => noPolicy(scannable, ruleset));
    if (base === undefined) continue;
    if (base.length !== 1 || !sameMetadata(base[0], wanted)) {
      if (surface.profile === "common") {
        skipped.push(id);
        continue;
      }
      expect(id, false, `the synthetic input no longer yields exactly the fixture finding (${describeAll(base)})`);
      continue;
    }
    const expected = evaluation.expectedAction === "base" ? base[0].action : evaluation.expectedAction;
    const observed = guard(id, () => surface.scan(policyBytes(fixture, evaluation.policy), scannable, ruleset));
    if (observed === undefined) continue;
    expect(
      id,
      observed.length === 1 && observed[0].action === expected,
      `expected ${expected}, got ${describeAll(observed)}`,
    );
  }

  // --------------------------------------------------- accepted and rejected
  for (const policy of fixture.policies) {
    const id = `policies/${policy.id}`;
    const rejected = guard(id, () => surface.reject(documentBytes(policy)));
    expect(id, rejected === undefined, `a named policy was rejected (${rejected?.code})`);
  }
  for (const accepted of fixture.acceptedDocuments) {
    const id = `acceptedDocuments/${accepted.id}`;
    const rejected = guard(id, () => surface.reject(documentBytes(accepted)));
    expect(id, rejected === undefined, `an accepted edge document was rejected (${rejected?.code})`);
  }
  for (const [section, entries] of [
    ["rejections", fixture.rejections],
    ["additionalRejections", fixture.additionalRejections],
  ]) {
    for (const entry of entries) {
      const id = `${section}/${entry.id}`;
      const rejected = guard(id, () => surface.reject(documentBytes(entry)));
      expect(id, rejected !== undefined, `expected ${entry.class}, but the document was accepted`);
      if (rejected === undefined) continue;
      expect(id, rejected.code === fixture.errorCode, `expected code ${fixture.errorCode}, got ${rejected.code}`);
      if (rejected.message !== undefined && rejected.class === undefined) {
        expect(id, rejected.message === fixture.errorMessage, "the public message is not the one fixed message");
      }
      if (rejected.class !== undefined) {
        expect(id, rejected.class === entry.class, `expected class ${entry.class}, got ${rejected.class}`);
        const wantedIndex = entry.ruleIndex ?? undefined;
        expect(id, rejected.ruleIndex === wantedIndex, `expected rule index ${wantedIndex}, got ${rejected.ruleIndex}`);
      }
    }
  }

  // --------------------------------------------------------------- end to end
  const rulesetBytes = Buffer.from(fixture.endToEnd.ruleset, "utf8");
  for (const testCase of fixture.endToEnd.cases) {
    const id = `endToEnd/${testCase.id}`;
    const ruleset = testCase.useRuleset === true ? rulesetBytes : undefined;
    const document = policyBytes(fixture, testCase.policy);
    const base = guard(id, () => noPolicy(testCase.input, ruleset));
    if (base === undefined) continue;

    const expected = testCase.expectedFindings.map((wanted, index) => ({
      type: wanted.type,
      detector: wanted.detector,
      confidence: wanted.confidence,
      obfuscation: wanted.obfuscation,
      action: wanted.expectedAction === "base" ? base[index]?.action : wanted.expectedAction,
      start: utf16Offset(testCase.input, wanted.start),
      end: utf16Offset(testCase.input, wanted.end),
    }));
    const baseMatches =
      base.length === expected.length &&
      base.every(
        (finding, index) =>
          sameMetadata(finding, expected[index]) &&
          finding.start === expected[index].start &&
          finding.end === expected[index].end,
      );
    if (!baseMatches) {
      if (surface.profile === "common") {
        skipped.push(id);
        continue;
      }
      expect(id, false, `the no-policy scan differs from the fixture (${describeAll(base)})`);
      continue;
    }

    const whole = guard(id, () => surface.scan(document, testCase.input, ruleset));
    if (whole !== undefined) {
      expect(
        id,
        describeAll(whole) === describeAll(expected),
        `whole input: expected ${describeAll(expected)}, got ${describeAll(whole)}`,
      );
    }
    if (surface.scanAndRedact !== undefined && ruleset === undefined) {
      const combined = guard(id, () => surface.scanAndRedact(document, testCase.input));
      if (combined !== undefined) {
        expect(id, describeAll(combined.findings) === describeAll(expected), "scanAndRedact findings differ from scan");
        expect(
          id,
          combined.text === expectedRedaction(testCase.input, expected),
          "scanAndRedact text differs from the reference redaction",
        );
      }
    }
    if (testCase.alsoIncremental === true) {
      for (const chunks of partitions(testCase.input)) {
        const released = guard(id, () => surface.incremental(document, chunks));
        if (released === undefined) continue;
        expect(
          id,
          describeAll(released) === describeAll(expected),
          `${chunks.length} chunk(s) split at ${chunks.map((chunk) => chunk.length).join("+")}: expected ${describeAll(expected)}, got ${describeAll(released)}`,
        );
      }
    }
  }

  // --------------------------------------------------------- host obligations
  const obligation = (name) => fixture.hostObligations.find((entry) => entry.id === name);
  // One input every profile detects: a `contextual_secret` at high confidence.
  const probeInput = SCANNABLE["contextual-high"];
  const allowProbe = policyBytes(fixture, {
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "allow-contextual", match: { type: ["contextual_secret"] }, action: "allow" }],
  });
  const warnProbe = policyBytes(fixture, {
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "warn-contextual", match: { type: ["contextual_secret"] }, action: "warn" }],
  });
  const brokenDocument = Buffer.from("{}", "utf8");
  if (surface.callback !== undefined) {
    {
      const id = `hostObligations/${obligation("legacy-callback-replaces-the-default").id}`;
      const replaced = guard(id, () => surface.callback.scan(undefined, probeInput, () => "allow"));
      expect(
        id,
        replaced?.findings?.length === 1 && replaced.findings[0].action === "allow",
        "the callback did not replace the default",
      );
      const seen = guard(id, () => surface.callback.scan(undefined, probeInput, () => "warn"));
      expect(id, seen?.findings?.[0]?.action === "warn", "the callback's action was not the result");
    }
    {
      const id = `hostObligations/${obligation("legacy-callback-throws").id}`;
      const result = guard(id, () =>
        surface.callback.scan(undefined, probeInput, () => {
          throw new Error("SYNTHETIC_REVOKED_CALLBACK_FAILURE");
        }),
      );
      expect(
        id,
        result?.code === obligation("legacy-callback-throws").expectedCode,
        `expected POLICY_FAILURE, got ${result?.code}`,
      );
      const inSession = guard(id, () =>
        surface.callback.incremental(undefined, [probeInput], () => {
          throw new Error("SYNTHETIC_REVOKED_CALLBACK_FAILURE");
        }),
      );
      expect(id, inSession?.code === "POLICY_FAILURE", `session: expected POLICY_FAILURE, got ${inSession?.code}`);
    }
    {
      const id = `hostObligations/${obligation("legacy-callback-invalid-action").id}`;
      // A non-string return is `POLICY_FAILURE` on every surface, as before; only a string outside the four names is this code.
      for (const bad of ["mask", "", "REDACT", "allow "]) {
        const result = guard(id, () => surface.callback.scan(undefined, probeInput, () => bad));
        expect(
          id,
          result?.code === obligation("legacy-callback-invalid-action").expectedCode,
          `expected INVALID_POLICY_ACTION for ${JSON.stringify(bad)}, got ${result?.code}`,
        );
      }
      const inSession = guard(id, () => surface.callback.incremental(undefined, [probeInput], () => "mask"));
      expect(
        id,
        inSession?.code === "INVALID_POLICY_ACTION",
        `session: expected INVALID_POLICY_ACTION, got ${inSession?.code}`,
      );
    }
    {
      const id = `hostObligations/${obligation("callback-and-action-policy-together").id}`;
      const expectedCode = obligation("callback-and-action-policy-together").expectedCode;
      for (const document of [allowProbe, brokenDocument]) {
        const whole = guard(id, () => surface.callback.scan(document, probeInput, () => "redact"));
        expect(
          id,
          whole?.code === expectedCode,
          `whole input: expected ${expectedCode}, got ${whole?.code ?? "a result"}`,
        );
        const session = guard(id, () => surface.callback.incremental(document, [probeInput], () => "redact"));
        expect(
          id,
          session?.code === expectedCode,
          `session: expected ${expectedCode}, got ${session?.code ?? "a result"}`,
        );
      }
    }
  }

  {
    const id = `hostObligations/${obligation("invalid-document-fails-before-scanning").id}`;
    const rejected = guard(id, () => surface.reject(brokenDocument));
    expect(
      id,
      rejected?.code === obligation("invalid-document-fails-before-scanning").expectedCode,
      `expected INVALID_ACTION_POLICY, got ${rejected?.code}`,
    );
    // The whole call fails; nothing partial and no default result comes back.
    const outcome = (() => {
      try {
        return { findings: surface.scan(brokenDocument, probeInput) };
      } catch (error) {
        return { code: error?.code };
      }
    })();
    expect(id, outcome.code === "INVALID_ACTION_POLICY", "a rejected document produced a result");
  }

  if (surface.profile !== "common") {
    {
      const id = `hostObligations/${obligation("session-binds-policy-at-construction").id}`;
      for (const [first, second] of [
        [allowProbe, warnProbe],
        [warnProbe, allowProbe],
      ]) {
        const chunks = [probeInput.slice(0, 12), probeInput.slice(12)];
        const sessions = guard(id, () => surface.sessions([first, second]));
        if (sessions === undefined) continue;
        const [one, two] = sessions;
        // Interleave appends so neither session can finish before the other builds output.
        const heads = [one.append(chunks[0]), two.append(chunks[0])];
        const tails = [one.append(chunks[1]), two.append(chunks[1])];
        const ends = [one.finalize(), two.finalize()];
        const actionOf = (index) => [...heads[index], ...tails[index], ...ends[index]].map((finding) => finding.action);
        const wantedOne = first === allowProbe ? "allow" : "warn";
        const wantedTwo = second === allowProbe ? "allow" : "warn";
        expect(
          id,
          actionOf(0).join() === wantedOne,
          `the first session gave ${actionOf(0).join()} instead of ${wantedOne}`,
        );
        expect(
          id,
          actionOf(1).join() === wantedTwo,
          `the second session gave ${actionOf(1).join()} instead of ${wantedTwo}`,
        );
      }
    }
    {
      const id = `hostObligations/${obligation("no-process-global-policy-slot").id}`;
      const run = (document) => guard(id, () => surface.scan(document, probeInput))?.[0]?.action;
      for (const order of [
        [allowProbe, warnProbe, allowProbe, warnProbe],
        [warnProbe, allowProbe, warnProbe, allowProbe],
      ]) {
        const actions = order.map(run);
        const wanted = order.map((document) => (document === allowProbe ? "allow" : "warn"));
        expect(id, actions.join() === wanted.join(), `expected ${wanted.join()}, got ${actions.join()}`);
      }
      // A rejected document leaves the previously loaded one untouched.
      try {
        surface.scan(brokenDocument, probeInput);
      } catch {
        // Expected: the document is rejected whole.
      }
      expect(id, run(allowProbe) === "allow", "a document is not independent of an earlier failure");
    }
  }

  return { checks, failures, skipped, unscannableEvaluations };
}

/**
 * Throws when `result` (from {@link runActionPolicyReference} or
 * {@link runPublicInputForms}) shows a disagreement, or when too few checks
 * ran for the profile for the run to mean anything (`common` links fewer
 * detectors, so fewer end-to-end cases apply).
 */
export function assertActionPolicyResult(label, result, profile) {
  const minimum = profile === "common" ? 380 : 500;
  if (result.skipped !== undefined && result.checks < minimum) {
    throw new Error(`${label}: only ${result.checks} action policy checks ran (expected at least ${minimum})`);
  }
  if (result.failures.length > 0) {
    throw new Error(
      `${label}: ${result.failures.length} action policy case(s) disagreed: ${result.failures.slice(0, 5).join("; ")}`,
    );
  }
}

// --------------------------------------------------------------------------
// Surface builders. Each wraps one JavaScript entry point; none interprets a
// document, so a disagreement is the surface's, never this file's.
// --------------------------------------------------------------------------

function parseRawRejection(error) {
  const match = /\(([A-Z_]+)(?:, rule (\d+))?\)$/.exec(String(error?.message));
  return {
    code: error?.code,
    message: String(error?.message),
    class: match === null ? "(no class)" : match[1],
    ruleIndex: match?.[2] === undefined ? undefined : Number(match[2]),
  };
}

const findingFields = (finding) => ({
  type: finding.type,
  detector: finding.detector,
  confidence: finding.confidence,
  obfuscation: finding.obfuscation,
  action: finding.action,
  start: finding.start,
  end: finding.end,
});

function callbackFor(evaluate) {
  // The raw addon and the public package call a function and an object
  // respectively; this is the function form the raw bindings take.
  return (finding, context) => evaluate(finding, context);
}

/**
 * The published package's public API (`@redact-secret/core` or
 * `@redact-secret/core/common`, already initialized): the code only, as the
 * 0.1.x contract decides, so no class or rule index is compared.
 */
export function publicPackageSurface(api, profile) {
  const options = (document, ruleset) => ({
    ...(document === undefined ? {} : { actionPolicy: document }),
    ...(ruleset === undefined ? {} : { ruleset }),
  });
  const session = (document, extra = {}) =>
    api.createIncrementalSanitizer({
      limits: SESSION_LIMITS,
      ...(document === undefined ? {} : { actionPolicy: document }),
      ...extra,
    });
  const incremental = (document, chunks, extra) => {
    const open = session(document, extra);
    const released = [];
    for (const chunk of chunks) released.push(...open.append(chunk).findings);
    released.push(...open.finalize().findings);
    return released.map(findingFields);
  };
  const code = (run) => {
    try {
      return run();
    } catch (error) {
      return { code: error?.code };
    }
  };
  return {
    profile,
    scan: (document, input, ruleset) => api.scan(input, options(document, ruleset)).map(findingFields),
    scanAndRedact: (document, input) => {
      const result = api.scanAndRedact(input, options(document));
      return { text: result.text, findings: result.findings.map(findingFields) };
    },
    incremental: (document, chunks) => incremental(document, chunks),
    sessions: (documents) =>
      documents.map((document) => {
        const open = session(document);
        return {
          append: (chunk) => open.append(chunk).findings.map(findingFields),
          finalize: () => open.finalize().findings.map(findingFields),
        };
      }),
    reject: (document) => {
      const results = [];
      for (const probe of [() => api.scan("irrelevant", options(document)), () => session(document)]) {
        try {
          probe();
          results.push(undefined);
        } catch (error) {
          results.push({ code: error?.code, message: String(error?.message), class: undefined, ruleIndex: undefined });
        }
      }
      const [whole, incrementalResult] = results;
      if (whole === undefined && incrementalResult === undefined) return undefined;
      if (whole === undefined || incrementalResult === undefined)
        return { ...(whole ?? incrementalResult), code: "(whole input and session disagree)" };
      if (whole.code !== incrementalResult.code || whole.message !== incrementalResult.message) {
        return { ...whole, code: "(whole input and session disagree)" };
      }
      return whole;
    },
    defaultAction: (finding) => api.defaultPolicy.evaluate(finding),
    callback: {
      scan: (document, input, evaluate) =>
        code(() => ({
          findings: api
            .scan(input, { policy: { evaluate: callbackFor(evaluate) }, ...options(document) })
            .map(findingFields),
        })),
      incremental: (document, chunks, evaluate) =>
        code(() => ({ findings: incremental(document, chunks, { policy: { evaluate: callbackFor(evaluate) } }) })),
    },
  };
}

/**
 * The raw Node addon (`index.js` of `bindings/node`): UTF-16 offsets, the
 * document as a trailing `Buffer`, and the fixed class and rule index
 * appended to the `INVALID_ACTION_POLICY` message.
 */
export function addonSurface(addon, profile) {
  const common = profile === "common";
  const scan = common ? addon.scanCommon : addon.scan;
  const scanAndRedact = common ? addon.scanAndRedactCommon : addon.scanAndRedact;
  const open = common ? addon.createIncrementalSanitizerCommon : addon.createIncrementalSanitizer;
  const limits = {
    maxInputCodeUnits: SESSION_LIMITS.maxInputBytes,
    maxBufferedCodeUnits: SESSION_LIMITS.maxBufferedBytes,
    maxTokenCodeUnits: SESSION_LIMITS.maxTokenBytes,
    maxMultilineCodeUnits: SESSION_LIMITS.maxMultilineBytes,
  };
  const session = (document, extra = {}) =>
    open({ limits, ...(document === undefined ? {} : { actionPolicy: document }), ...extra });
  const incremental = (document, chunks, extra) => {
    const opened = session(document, extra);
    const released = [];
    for (const chunk of chunks) released.push(...opened.append(chunk).findings);
    released.push(...opened.finalize().findings);
    return released.map(findingFields);
  };
  const code = (run) => {
    try {
      return run();
    } catch (error) {
      return { code: error?.code };
    }
  };
  return {
    profile,
    scan: (document, input, ruleset) => scan(input, undefined, undefined, ruleset, document).map(findingFields),
    scanAndRedact: (document, input) => {
      const result = scanAndRedact(input, undefined, undefined, undefined, undefined, document);
      return { text: result.redacted, findings: result.findings.map(findingFields) };
    },
    incremental: (document, chunks) => incremental(document, chunks),
    sessions: (documents) =>
      documents.map((document) => {
        const opened = session(document);
        return {
          append: (chunk) => opened.append(chunk).findings.map(findingFields),
          finalize: () => opened.finalize().findings.map(findingFields),
        };
      }),
    reject: (document) => {
      const results = [];
      for (const probe of [
        () => scan("irrelevant", undefined, undefined, undefined, document),
        () => session(document),
      ]) {
        try {
          probe();
          results.push(undefined);
        } catch (error) {
          results.push(parseRawRejection(error));
        }
      }
      const [whole, incrementalResult] = results;
      if (whole === undefined && incrementalResult === undefined) return undefined;
      if (whole === undefined || incrementalResult === undefined)
        return { ...(whole ?? incrementalResult), code: "(whole input and session disagree)" };
      if (whole.message !== incrementalResult.message) return { ...whole, code: "(whole input and session disagree)" };
      return whole;
    },
    defaultAction: (finding) => addon.defaultPolicy(finding),
    callback: {
      scan: (document, input, evaluate) =>
        code(() => ({
          findings: scan(input, callbackFor(evaluate), undefined, undefined, document).map(findingFields),
        })),
      incremental: (document, chunks, evaluate) =>
        code(() => ({ findings: incremental(document, chunks, { policy: callbackFor(evaluate) }) })),
    },
  };
}

/**
 * The generated WebAssembly glue (already `default()`-initialized and
 * `initialize([])`d): UTF-16 offsets, positional trailing arguments, handle
 * results freed after reading, and the same appended class and rule index.
 */
export function wasmGlueSurface(glue, profile) {
  const limits = [
    SESSION_LIMITS.maxInputBytes,
    SESSION_LIMITS.maxBufferedBytes,
    SESSION_LIMITS.maxTokenBytes,
    SESSION_LIMITS.maxMultilineBytes,
  ];
  const readFindings = (result) => {
    try {
      return result.takeFindings().map(findingFields);
    } finally {
      result.free();
    }
  };
  const open = (document, policy) => glue.createIncrementalSanitizer(...limits, policy, undefined, document);
  const incremental = (document, chunks, policy) => {
    const opened = open(document, policy);
    const released = [];
    for (const chunk of chunks) released.push(...readFindings(opened.append(chunk)));
    released.push(...readFindings(opened.finalize()));
    return released;
  };
  const code = (run) => {
    try {
      return run();
    } catch (error) {
      return { code: error?.code };
    }
  };
  return {
    profile,
    scan: (document, input, ruleset) =>
      glue.scan(input, undefined, undefined, undefined, ruleset, document).map(findingFields),
    scanAndRedact: (document, input) => {
      const result = glue.scanAndRedact(input, undefined, undefined, undefined, undefined, undefined, document);
      try {
        return { text: result.takeText(), findings: result.takeFindings().map(findingFields) };
      } finally {
        result.free();
      }
    },
    incremental: (document, chunks) => incremental(document, chunks, undefined),
    sessions: (documents) =>
      documents.map((document) => {
        const opened = open(document, undefined);
        return {
          append: (chunk) => readFindings(opened.append(chunk)),
          finalize: () => readFindings(opened.finalize()),
        };
      }),
    reject: (document) => {
      const results = [];
      for (const probe of [
        () => glue.scan("irrelevant", undefined, undefined, undefined, undefined, document),
        () => open(document, undefined),
      ]) {
        try {
          probe();
          results.push(undefined);
        } catch (error) {
          results.push(parseRawRejection(error));
        }
      }
      const [whole, incrementalResult] = results;
      if (whole === undefined && incrementalResult === undefined) return undefined;
      if (whole === undefined || incrementalResult === undefined)
        return { ...(whole ?? incrementalResult), code: "(whole input and session disagree)" };
      if (whole.message !== incrementalResult.message) return { ...whole, code: "(whole input and session disagree)" };
      return whole;
    },
    defaultAction: (finding) =>
      glue.defaultPolicy(
        finding.id,
        finding.type,
        finding.detector,
        finding.confidence,
        finding.obfuscation,
        finding.start,
        finding.end,
      ),
    callback: {
      scan: (document, input, evaluate) =>
        code(() => ({
          findings: glue
            .scan(input, callbackFor(evaluate), undefined, undefined, undefined, document)
            .map(findingFields),
        })),
      incremental: (document, chunks, evaluate) =>
        code(() => ({ findings: incremental(document, chunks, callbackFor(evaluate)) })),
    },
  };
}

/**
 * Checks the public package's three document forms (object, text, bytes)
 * give the same findings as the bytes route, that a mutation of the object
 * after a session was built changes nothing, and that the rejection a
 * serializer failure gives is the document-level `INVALID_ACTION_POLICY`.
 * Returns `{ checks, failures }`.
 */
export function runPublicInputForms(fixture, api) {
  const failures = [];
  let checks = 0;
  const expect = (id, condition, message) => {
    checks += 1;
    if (!condition) failures.push(`publicInputForms/${id}: ${message}`);
  };
  const input = SCANNABLE["contextual-high"];
  const document = namedPolicy(fixture, "exact-type");
  const object = document.document;
  const text = JSON.stringify(object);
  const bytes = Buffer.from(text, "utf8");
  const run = (actionPolicy) => api.scan(input, { actionPolicy }).map(findingFields);
  const viaBytes = describeAll(run(bytes));
  expect("object", describeAll(run(object)) === viaBytes, "an object differs from its bytes");
  expect("text", describeAll(run(text)) === viaBytes, "text differs from its bytes");

  // The fixture's exact-type document names `jwt`; one naming the probe's type shows an effect.
  const allow = {
    actionPolicyRevision: 1,
    base: "default",
    rules: [{ id: "allow-contextual", match: { type: ["contextual_secret"] }, action: "allow" }],
  };
  const allowed = run(allow);
  expect("effect", allowed.length === 1 && allowed[0].action === "allow", "the object form had no effect");

  const mutable = { actionPolicyRevision: 1, base: "default", rules: [{ ...allow.rules[0] }] };
  const session = api.createIncrementalSanitizer({ limits: SESSION_LIMITS, actionPolicy: mutable });
  mutable.rules[0].action = "warn";
  mutable.rules.push({ id: "extra", match: { type: ["contextual_secret"] }, action: "block" });
  const released = [...session.append(input).findings, ...session.finalize().findings];
  expect(
    "snapshot",
    released.length === 1 && released[0].action === "allow",
    "a later mutation changed a bound session",
  );

  // Key order is the object's own: the revision must come first.
  let code;
  try {
    run({ base: "default", actionPolicyRevision: 1, rules: [] });
  } catch (error) {
    code = error?.code;
  }
  expect("revision-first", code === "INVALID_ACTION_POLICY", `revision-last gave ${code}`);

  const cyclic = {};
  cyclic.self = cyclic;
  try {
    run(cyclic);
    code = undefined;
  } catch (error) {
    code = error?.code;
  }
  expect("serializer-failure", code === "INVALID_ACTION_POLICY", `a cyclic object gave ${code}`);
  return { checks, failures };
}
