/**
 * Runs the shared explain-and-compare fixture
 * (`conformance/fixtures/action-policy-compare-v1.json`, issue #1220,
 * `decision-explain-and-compare-action-policies-over-one-detection-pass`)
 * against one JavaScript surface, so the Node addon, the WebAssembly artifact
 * and the published package on top of each are held to the same per-finding
 * actions, bases, rule ids and indexes, the same `differs` flags and counts,
 * the same callback call sequences, the same errors and the same digests as
 * the Rust core and the CLI, which have their own consumers of the same file.
 * It also asserts what the fixture describes in prose: enforcement parity
 * (each declarative side's action equals what `scan` with that document
 * yields), that the comparison leaves enforcement outputs and callback logs
 * unchanged, that the result carries no byte of the input, and that no
 * incremental or stream comparison exists.
 *
 * Division of labour with the Rust core. The core runs every case for
 * semantics, including that detection runs once; a JavaScript surface cannot
 * observe that, so `detection-runs-once` is reported as not observable here
 * (counted, never silently dropped) while the rest of the obligations run.
 *
 * A surface is described by an object, so this file carries no process,
 * environment or network access of its own:
 *
 * - `profile`: `"full"` or `"common"`. A case whose no-policy scan does not
 *   reproduce the fixture's findings on this profile is skipped and counted
 *   (`common` links fewer detectors), never failed.
 * - `scan(document, input, ruleset, evaluate)`: the surface's `scan`
 *   findings (`type`, `detector`, `confidence`, `obfuscation`, `action`,
 *   `start`, `end` in UTF-16 code units, plus `id`), under the document bytes
 *   (or none) or an `evaluate(finding, context)` callback.
 * - `scanAndRedact(document, input, ruleset)`: `{ text, findings }`.
 * - `compare(input, sides, { limits, ruleset })`: the comparison, as the
 *   canonical shape below, or `{ code }` when it throws. A side is
 *   `{ kind: "default" }`, `{ kind: "action-policy", document }` (a
 *   `Buffer`) or `{ kind: "callback", evaluate }`.
 * - `exports`: the names on the surface that mention comparison, so a
 *   session or stream comparison cannot appear unnoticed.
 *
 * The canonical comparison shape is `{ detection: { activationIdentity,
 * profile, detectorCount }, policies: [{ kind, documentSha256, counts }],
 * changedCount, findings: [{ id, type, detector, confidence, obfuscation,
 * start, end, differs, decisions: [{ action, basis, ruleId, ruleIndex }] }] }`
 * with `null` for every absent value. A surface adapter below maps its own
 * shape to it and does nothing else.
 *
 * Every document and input in the fixture is synthetic. The failures this
 * returns name a case id and a count, never a document or an input.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FIXTURE_PATH = join(REPO_ROOT, "conformance", "fixtures", "action-policy-compare-v1.json");

/** The fixture's own totals, so a truncated or edited fixture fails loudly. */
const EXPECTED = { policies: 8, digests: 4, cases: 8, errors: 7, obligations: 8 };

export function loadCompareFixture() {
  const fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));
  const counts = {
    policies: fixture.policies.length,
    digests: fixture.digests.length,
    cases: fixture.cases.length,
    errors: fixture.errors.length,
    obligations: fixture.hostObligations.length,
  };
  for (const [name, expected] of Object.entries(EXPECTED)) {
    if (counts[name] !== expected) {
      throw new Error(`action-policy-compare-v1.json: expected ${expected} ${name}, found ${counts[name]}`);
    }
  }
  return fixture;
}

/** UTF-8 byte offset to UTF-16 code-unit offset, independent of any binding. */
function utf16Offset(text, byteOffset) {
  return Buffer.from(text, "utf8").subarray(0, byteOffset).toString("utf8").length;
}

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

function policyDocument(fixture, id) {
  const policy = fixture.policies.find((entry) => entry.id === id);
  if (policy === undefined) throw new Error(`fixture has no policy ${id}`);
  return Buffer.from(policy.documentText, "utf8");
}

const findingKey = (finding) =>
  [finding.type, finding.detector, finding.confidence, finding.obfuscation, finding.start, finding.end].join("|");

/**
 * A callback side for one fixture entry: `returns[findingIndex]` for each
 * call, a thrown error at `failAtFindingIndex`, and every call recorded as
 * `<label><findingIndex>` in `log`.
 */
function callbackSide(entry, log) {
  return {
    kind: "callback",
    evaluate: (_finding, context) => {
      log.push(`${entry.label}${context.findingIndex}`);
      if (entry.failAtFindingIndex === context.findingIndex) throw new Error("synthetic callback failure");
      return entry.returns[context.findingIndex];
    },
  };
}

function buildSides(fixture, entries, log) {
  return entries.map((entry) => {
    if (entry.kind === "default") return { kind: "default" };
    if (entry.kind === "policy") return { kind: "action-policy", document: policyDocument(fixture, entry.policy) };
    if (entry.kind === "callback") return callbackSide(entry, log);
    throw new Error(`unknown side kind ${entry.kind}`);
  });
}

function countsOf(decisions) {
  const counts = { redact: 0, block: 0, warn: 0, allow: 0 };
  for (const decision of decisions) counts[decision.action] += 1;
  return counts;
}

/** Whether `serialized` holds any 12-code-unit window of a finding's matched span. */
function leaksSpan(serialized, input, findings) {
  for (const finding of findings) {
    const span = input.slice(finding.start, finding.end);
    for (let at = 0; at + 12 <= span.length; at += 1) {
      if (serialized.includes(span.slice(at, at + 12))) return true;
    }
  }
  return false;
}

/** Whether `value` is frozen all the way down. */
function deepFrozen(value) {
  if (typeof value !== "object" || value === null) return true;
  return Object.isFrozen(value) && Object.values(value).every(deepFrozen);
}

/**
 * Runs the fixture through `surface`. Returns `{ checks, failures, skipped,
 * notObservable, resultDigest }`: the number of checks run, one fixed-form
 * string per disagreement, the cases skipped because the profile does not
 * link the detector they need, the obligations this surface cannot observe,
 * and a SHA-256 over the canonical result of every case (so the addon and the
 * WebAssembly artifact can be shown to produce identical results).
 */
export function runCompareReference(fixture, surface) {
  const failures = [];
  const skipped = [];
  const notObservable = [];
  let checks = 0;
  let compared = 0;
  const digest = createHash("sha256");

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
  const rulesetBytes = Buffer.from(fixture.ruleset, "utf8");

  // ------------------------------------------------------------------- cases
  for (const testCase of fixture.cases) {
    const id = `cases/${testCase.id}`;
    const ruleset = testCase.useRuleset === true ? rulesetBytes : undefined;
    const base = guard(id, () => surface.scan(undefined, testCase.input, ruleset));
    if (base === undefined) continue;

    const expectedFindings = testCase.expectedFindings.map((wanted) => ({
      ...wanted,
      start: utf16Offset(testCase.input, wanted.start),
      end: utf16Offset(testCase.input, wanted.end),
    }));
    const reproduces =
      base.length === expectedFindings.length &&
      base.every((finding, index) => findingKey(finding) === findingKey(expectedFindings[index]));
    // `common` links fewer detectors, so a case whose input does not yield the
    // fixture's findings there keeps the checks that do not depend on them
    // (parity with `scan`, counts, digests, call order, no plaintext) and
    // skips only the fixture's own expectations, which are counted.
    if (!reproduces) {
      if (surface.profile !== "common") {
        expect(id, false, `the synthetic input no longer yields the fixture findings (${base.length} found)`);
        continue;
      }
      skipped.push(id);
    }

    const log = [];
    const sides = buildSides(fixture, testCase.sides, log);
    const result = guard(id, () => surface.compare(testCase.input, sides, { ruleset }));
    if (result === undefined) continue;
    if (result.code !== undefined) {
      expect(id, false, `the comparison failed with ${result.code}`);
      continue;
    }
    digest.update(`${testCase.id}\n${JSON.stringify(result)}\n`);
    compared += 1;

    expect(id, result.findings.length === base.length, `${result.findings.length} compared findings`);
    expect(id, result.policies.length === testCase.sides.length, `${result.policies.length} compared sides`);
    expect(
      id,
      result.changedCount === result.findings.filter((finding) => finding.differs).length,
      `changed count ${result.changedCount} does not count the differing findings`,
    );
    // Each callback side runs alone over every finding, in order, in side order.
    const wantedSequence = reproduces
      ? (testCase.expectedCallSequence ?? [])
      : testCase.sides
          .filter((entry) => entry.kind === "callback")
          .flatMap((entry) => base.map((_, index) => `${entry.label}${index}`));
    expect(id, JSON.stringify(log) === JSON.stringify(wantedSequence), `call sequence ${log.join(",")}`);
    if (reproduces) {
      expect(id, result.changedCount === testCase.expectedChangedCount, `changed ${result.changedCount}`);
    }

    // Finalized findings only: the same findings, in the same order, with the
    // same ids and ranges, that `scan` returns.
    result.findings.forEach((compared, index) => {
      const fid = `${id}/finding-${index}`;
      expect(fid, compared.id === base[index]?.id, `id ${compared.id} is not scan's ${base[index]?.id}`);
      expect(fid, findingKey(compared) === findingKey(base[index] ?? {}), "metadata or range differs from scan's");
      expect(fid, compared.decisions.length === testCase.sides.length, `${compared.decisions.length} decisions`);
      expect(
        fid,
        compared.differs === new Set(compared.decisions.map((decision) => decision.action)).size > 1,
        `differs ${compared.differs} does not follow the decisions`,
      );
      if (!reproduces) return;
      const wanted = expectedFindings[index];
      expect(fid, findingKey(compared) === findingKey(wanted), "metadata or range differs from the fixture");
      expect(fid, compared.differs === wanted.expectedDiffers, `differs ${compared.differs}`);
      wanted.expectedDecisions.forEach((decision, side) => {
        const got = compared.decisions[side];
        const action = decision.action === fixture.baseSentinel ? base[index]?.action : decision.action;
        expect(fid, got?.action === action, `side ${side} action ${got?.action}, expected ${action}`);
        expect(fid, got?.basis === decision.basis, `side ${side} basis ${got?.basis}, expected ${decision.basis}`);
        expect(fid, got?.ruleId === decision.ruleId, `side ${side} rule id ${got?.ruleId}`);
        expect(fid, got?.ruleIndex === decision.ruleIndex, `side ${side} rule index ${got?.ruleIndex}`);
      });
    });

    // Per-side counts follow the decisions; kinds and digests follow the sides.
    testCase.sides.forEach((entry, side) => {
      const sid = `${id}/side-${side}`;
      const summary = result.policies[side];
      const column = result.findings.map((compared) => compared.decisions[side]);
      expect(
        sid,
        JSON.stringify(summary?.counts) === JSON.stringify(countsOf(column)),
        "counts do not follow decisions",
      );
      const kind = entry.kind === "policy" ? "action-policy" : entry.kind;
      expect(sid, summary?.kind === kind, `kind ${summary?.kind}, expected ${kind}`);
      const document = sides[side].document;
      const wantedDigest = document === undefined ? null : sha256Hex(document);
      expect(sid, summary?.documentSha256 === wantedDigest, "the document digest is not the SHA-256 of its bytes");
    });

    // Enforcement parity: each declarative side's action equals what `scan`
    // with that document yields for the same finding.
    testCase.sides.forEach((entry, side) => {
      if (entry.kind !== "policy") return;
      const pid = `${id}/parity-${side}`;
      const enforced = guard(pid, () => surface.scan(sides[side].document, testCase.input, ruleset));
      if (enforced === undefined) return;
      expect(pid, enforced.length === result.findings.length, "scan and comparison disagree on the finding count");
      enforced.forEach((finding, index) => {
        expect(
          pid,
          finding.action === result.findings[index]?.decisions[side]?.action,
          `finding ${index}: scan ${finding.action}, comparison ${result.findings[index]?.decisions[side]?.action}`,
        );
      });
    });

    // The default side is `scan`'s own default evaluation; the base sentinel
    // resolved above is that, so it must agree with the comparison's default.
    testCase.sides.forEach((entry, side) => {
      if (entry.kind !== "default") return;
      result.findings.forEach((compared, index) => {
        expect(
          `${id}/default-${side}`,
          compared.decisions[side]?.action === base[index]?.action,
          `finding ${index}: the default side differs from scan`,
        );
      });
    });

    // No plaintext: no matched value and no window of one in the result.
    const serialized = JSON.stringify(result);
    expect(id, !leaksSpan(serialized, testCase.input, base), "the result holds a window of a matched value");
    expect(id, !serialized.includes(testCase.input), "the result holds the input");
  }

  // ------------------------------------------------------------------ errors
  for (const entry of fixture.errors) {
    const id = `errors/${entry.id}`;
    const ruleset = entry.useRuleset === true ? rulesetBytes : undefined;
    const log = [];
    const sides = buildSides(fixture, entry.sides, log);
    const result = guard(id, () => surface.compare(entry.input, sides, { limits: entry.limits, ruleset }));
    if (result === undefined) continue;
    expect(id, result.code === entry.expectedCode, `expected ${entry.expectedCode}, got ${result.code ?? "a result"}`);
    expect(
      id,
      JSON.stringify(log) === JSON.stringify(entry.expectedCallSequence),
      `call sequence ${log.join(",")}, expected ${entry.expectedCallSequence.join(",")}`,
    );
    expect(id, result.findings === undefined && result.policies === undefined, "a failed comparison returned a result");
    digest.update(`${entry.id}\n${result.code}\n`);
  }

  // --------------------------------------------------------------- additional
  // A bad return fails the whole comparison exactly as it does in `scan`, and
  // the same on every runtime: a string outside the four action names is
  // `INVALID_POLICY_ACTION`, a throw or a non-string is `POLICY_FAILURE`.
  const probeInput = "ACME_AN_aB1cD2eF3gH4iJ5kL6mN\nAPI_KEY=ghp_SYNTHETICREVOKED00000000000000000000\n";
  const probeRuleset = rulesetBytes;
  const probeBase = guard("additional/probe", () => surface.scan(undefined, probeInput, probeRuleset));
  if (probeBase !== undefined && probeBase.length >= 1) {
    for (const [name, returned, code] of [
      ["unknown-action", "mask", "INVALID_POLICY_ACTION"],
      ["non-string", 7, "POLICY_FAILURE"],
      ["undefined", undefined, "POLICY_FAILURE"],
    ]) {
      const id = `additional/callback-${name}`;
      const calls = [];
      const side = {
        kind: "callback",
        evaluate: (_finding, context) => {
          calls.push(context.findingIndex);
          return context.findingIndex === 0 ? "allow" : returned;
        },
      };
      const viaCompare = guard(id, () =>
        surface.compare(probeInput, [{ kind: "default" }, side], { ruleset: probeRuleset }),
      );
      const viaScan = guard(id, () =>
        surface.scanFails(probeInput, probeRuleset, (_finding, context) =>
          context.findingIndex === 0 ? "allow" : returned,
        ),
      );
      if (viaCompare === undefined || viaScan === undefined) continue;
      if (probeBase.length >= 2) {
        expect(id, viaCompare.code === code, `comparison gave ${viaCompare.code ?? "a result"}, expected ${code}`);
        expect(id, viaScan.code === code, `scan gave ${viaScan.code ?? "findings"}, expected ${code}`);
        expect(id, calls.join(",") === "0,1", `calls ${calls.join(",")}, expected 0,1`);
      }
    }
    // The callback sequence of a one-side comparison equals `scan`'s.
    const scanCalls = [];
    const compareCalls = [];
    guard("additional/sequence", () =>
      surface.scan(undefined, probeInput, probeRuleset, (_finding, context) => {
        scanCalls.push(`${context.findingIndex}/${context.findingCount}`);
        return "warn";
      }),
    );
    guard("additional/sequence", () =>
      surface.compare(
        probeInput,
        [
          {
            kind: "callback",
            evaluate: (_finding, context) => {
              compareCalls.push(`${context.findingIndex}/${context.findingCount}`);
              return "warn";
            },
          },
        ],
        { ruleset: probeRuleset },
      ),
    );
    expect(
      "additional/sequence",
      scanCalls.length > 0 && scanCalls.join(",") === compareCalls.join(","),
      `scan ${scanCalls.join(",")} against comparison ${compareCalls.join(",")}`,
    );
  } else {
    skipped.push("additional/callbacks");
  }

  // ----------------------------------------------------------------- digests
  const digestBy = new Map();
  for (const entry of fixture.digests) {
    const id = `digests/${entry.policy}`;
    const document = policyDocument(fixture, entry.policy);
    const result = guard(id, () => surface.compare("nothing to see here\n", [{ kind: "action-policy", document }], {}));
    if (result === undefined) continue;
    const got = result.policies?.[0]?.documentSha256;
    expect(id, got === entry.documentSha256, `digest ${got}, expected ${entry.documentSha256}`);
    expect(id, got === sha256Hex(document), "the digest is not this runtime's SHA-256 of the document bytes");
    digestBy.set(entry.policy, got);
    digest.update(`${entry.policy}\n${got}\n`);
  }
  expect(
    "digests/whitespace",
    digestBy.get("empty-rules") !== undefined && digestBy.get("empty-rules") !== digestBy.get("empty-rules-spaced"),
    "insignificant whitespace did not change the digest",
  );

  // ------------------------------------------------------------ obligations
  const probeCase = fixture.cases.find((entry) => entry.id === "three-findings-four-policies");
  const probeRulesetFor = (entry) => (entry.useRuleset === true ? rulesetBytes : undefined);
  const probeReproduces = guard("obligations/probe", () => {
    const base = surface.scan(undefined, probeCase.input, probeRulesetFor(probeCase));
    return base.length === probeCase.expectedFindings.length;
  });

  for (const obligation of fixture.hostObligations) {
    const id = `obligations/${obligation.id}`;
    switch (obligation.id) {
      case "preview-is-not-enforcement": {
        if (!probeReproduces) {
          skipped.push(id);
          break;
        }
        const ruleset = probeRulesetFor(probeCase);
        const before = guard(id, () => surface.scanAndRedact(undefined, probeCase.input, ruleset));
        const result = guard(id, () =>
          surface.compare(probeCase.input, buildSides(fixture, probeCase.sides, []), { ruleset }),
        );
        const after = guard(id, () => surface.scanAndRedact(undefined, probeCase.input, ruleset));
        if (before === undefined || after === undefined || result === undefined) break;
        expect(id, before.text === after.text, "enforcement output changed after a comparison");
        expect(
          id,
          JSON.stringify(before.findings) === JSON.stringify(after.findings),
          "enforcement findings changed after a comparison",
        );
        expect(id, result.text === undefined && result.redacted === undefined, "a comparison returned text");
        // A callback's log under enforcement is unchanged by an interleaved comparison.
        const first = [];
        const second = [];
        const evaluate = (log) => (_finding, context) => {
          log.push(`${context.findingIndex}/${context.findingCount}`);
          return "warn";
        };
        guard(id, () => surface.scan(undefined, probeCase.input, ruleset, evaluate(first)));
        guard(id, () => surface.compare(probeCase.input, [{ kind: "callback", evaluate: evaluate([]) }], { ruleset }));
        guard(id, () => surface.scan(undefined, probeCase.input, ruleset, evaluate(second)));
        expect(id, first.length > 0 && first.join(",") === second.join(","), "an enforcement callback log changed");
        break;
      }
      case "detection-runs-once":
        // Not observable through a public JavaScript surface: a callback
        // sees findings, never detector calls. The Rust core's tests prove it.
        notObservable.push(obligation.id);
        break;
      case "finalized-findings-only": {
        // Covered per case above (ids, order, ranges, metadata against scan);
        // asserted again here on the overlap case, whose loser must be absent.
        const overlap = fixture.cases.find((entry) => entry.id === "overlap-loser-is-never-compared");
        const scanned = guard(id, () => surface.scan(undefined, overlap.input, undefined));
        const result = guard(id, () => surface.compare(overlap.input, buildSides(fixture, overlap.sides, []), {}));
        if (scanned === undefined || result === undefined) break;
        if (scanned.length !== overlap.expectedFindings.length) {
          skipped.push(id);
          break;
        }
        expect(id, result.findings.length === scanned.length, "the finding count differs from scan");
        expect(
          id,
          result.findings.every(
            (compared, index) =>
              compared.id === scanned[index].id && findingKey(compared) === findingKey(scanned[index]),
          ),
          "a compared finding differs from scan's",
        );
        break;
      }
      case "no-plaintext":
        // Asserted on every compared case above; this makes sure one ran.
        expect(id, compared > 0 || surface.profile === "common", "no case was compared, so nothing was checked");
        break;
      case "detection-identified-separately": {
        const input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000\n";
        const swapPolicy = guard(id, () =>
          [{ kind: "default" }, { kind: "action-policy", document: policyDocument(fixture, "four-actions") }].map(
            (side) => surface.compare(input, [side], {}),
          ),
        );
        const swapRuleset = guard(id, () =>
          [undefined, rulesetBytes].map((ruleset) =>
            surface.compare(input, [{ kind: "action-policy", document: policyDocument(fixture, "four-actions") }], {
              ruleset,
            }),
          ),
        );
        if (swapPolicy === undefined || swapRuleset === undefined) break;
        expect(
          id,
          JSON.stringify(swapPolicy[0].detection) === JSON.stringify(swapPolicy[1].detection),
          "swapping a policy changed the detection identity",
        );
        expect(
          id,
          swapRuleset[0].policies[0].documentSha256 === swapRuleset[1].policies[0].documentSha256,
          "swapping the ruleset changed a policy binding",
        );
        expect(
          id,
          swapRuleset[1].detection.detectorCount === swapRuleset[0].detection.detectorCount + 1,
          "a ruleset detector is not counted in the detection identity",
        );
        expect(
          id,
          typeof swapPolicy[0].detection.activationIdentity === "string" &&
            swapPolicy[0].detection.profile === surface.profile &&
            Object.keys(swapPolicy[0].detection).sort().join() === "activationIdentity,detectorCount,profile",
          "the detection identity is not {activationIdentity, profile, detectorCount}",
        );
        break;
      }
      case "callback-bindings-have-no-identity": {
        const result = guard(id, () =>
          surface.compare("nothing to see here\n", [{ kind: "callback", evaluate: () => "allow" }], {}),
        );
        if (result === undefined) break;
        expect(
          id,
          result.policies[0].kind === "callback" && result.policies[0].documentSha256 === null,
          "a callback side reports an identity",
        );
        break;
      }
      case "incremental-comparison-is-unsupported": {
        const names = surface.exports.slice().sort().join(",");
        expect(id, names === surface.expectedExports.slice().sort().join(","), `comparison-named exports: ${names}`);
        for (const probe of surface.unsupportedProbes?.() ?? []) {
          expect(id, probe.ok, probe.message);
        }
        break;
      }
      case "digest-is-over-the-exact-document-bytes": {
        const text = policyDocument(fixture, "four-actions").toString("utf8");
        const forms = guard(id, () => (surface.digestForms === undefined ? undefined : surface.digestForms(text)));
        if (forms === undefined) {
          notObservable.push(`${obligation.id} (object form: package only)`);
          break;
        }
        expect(id, forms.text === sha256Hex(Buffer.from(text, "utf8")), "the text digest is not over its UTF-8 bytes");
        expect(id, forms.bytes === forms.text, "bytes and text of one document digest differently");
        expect(
          id,
          forms.object === sha256Hex(Buffer.from(JSON.stringify(JSON.parse(text)), "utf8")),
          "an object's digest is not over its compact JSON bytes",
        );
        break;
      }
      default:
        expect(id, false, "an obligation this runner does not know");
    }
  }

  return { checks, failures, skipped, notObservable, resultDigest: digest.digest("hex") };
}

/**
 * Throws when `result` shows a disagreement, or when too few checks ran for
 * the profile for the run to mean anything (`common` links fewer detectors).
 */
export function assertCompareResult(label, result, profile) {
  const minimum = profile === "common" ? 40 : 150;
  if (result.checks < minimum) {
    throw new Error(`${label}: only ${result.checks} comparison checks ran (expected at least ${minimum})`);
  }
  if (result.failures.length > 0) {
    throw new Error(
      `${label}: ${result.failures.length} comparison case(s) disagreed: ${result.failures.slice(0, 5).join("; ")}`,
    );
  }
}

// --------------------------------------------------------------------------
// Surface builders. Each wraps one JavaScript entry point and maps its shape
// to the canonical one; none interprets a policy, so a disagreement is the
// surface's, never this file's.
// --------------------------------------------------------------------------

const findingFields = (finding) => ({
  id: finding.id,
  type: finding.type,
  detector: finding.detector,
  confidence: finding.confidence,
  obfuscation: finding.obfuscation,
  action: finding.action,
  start: finding.start,
  end: finding.end,
});

/** Maps a raw binding result (null or missing for an absent value) to the canonical shape. */
function canonicalRaw(result) {
  return {
    detection: {
      activationIdentity: result.detection.activationIdentity,
      profile: result.detection.profile ?? null,
      detectorCount: result.detection.detectorCount,
    },
    policies: result.sides.map((side) => ({
      kind: side.kind,
      documentSha256: side.documentSha256 ?? null,
      counts: { redact: side.redact, block: side.block, warn: side.warn, allow: side.allow },
    })),
    changedCount: result.changedCount,
    findings: result.findings.map((finding) => ({
      id: finding.id,
      type: finding.type,
      detector: finding.detector,
      confidence: finding.confidence,
      obfuscation: finding.obfuscation,
      start: finding.start,
      end: finding.end,
      differs: finding.differs,
      decisions: finding.decisions.map((decision) => ({
        action: decision.action,
        basis: decision.basis,
        ruleId: decision.ruleId ?? null,
        ruleIndex: decision.ruleIndex ?? null,
      })),
    })),
  };
}

/**
 * Maps the WebAssembly artifact's flat array
 * (`bindings/wasm/src/compare.rs` documents the layout) to the canonical
 * shape. A second, independent decoder of that layout next to the package's
 * own, so a drift in either shows as a disagreement.
 */
function canonicalFlat(flat) {
  if (!Array.isArray(flat)) throw new Error("the artifact did not return an array");
  let cursor = 0;
  const next = () => {
    if (cursor >= flat.length) throw new Error("the flat comparison is too short");
    return flat[cursor++];
  };
  const detection = { activationIdentity: next(), profile: next(), detectorCount: next() };
  const sideCount = next();
  const policies = [];
  for (let side = 0; side < sideCount; side += 1) {
    const kind = next();
    const documentSha256 = next();
    policies.push({ kind, documentSha256, counts: { redact: next(), block: next(), warn: next(), allow: next() } });
  }
  const changedCount = next();
  const findingCount = next();
  const findings = [];
  for (let index = 0; index < findingCount; index += 1) {
    const finding = {
      id: next(),
      type: next(),
      detector: next(),
      confidence: next(),
      obfuscation: next(),
      start: next(),
      end: next(),
      differs: next(),
      decisions: [],
    };
    for (let side = 0; side < sideCount; side += 1) {
      finding.decisions.push({ action: next(), basis: next(), ruleId: next(), ruleIndex: next() });
    }
    findings.push(finding);
  }
  if (cursor !== flat.length) throw new Error("the flat comparison has trailing values");
  return { detection, policies, changedCount, findings };
}

/** Splits sides into the parallel `kinds`/`documents`/`callbacks` the raw bindings take. */
function splitRaw(sides) {
  const kinds = [];
  const documents = [];
  const callbacks = [];
  for (const side of sides) {
    kinds.push(side.kind);
    if (side.kind === "action-policy") documents.push(side.document);
    if (side.kind === "callback") callbacks.push((finding, context) => side.evaluate(finding, context));
  }
  return { kinds, documents, callbacks };
}

const codeOnly = (run) => {
  try {
    return run();
  } catch (error) {
    return { code: error?.code };
  }
};

/** The comparison-named properties of an object, own and inherited methods included. */
function comparisonNames(object) {
  const names = new Set();
  for (let target = object; target !== null && target !== Object.prototype; target = Object.getPrototypeOf(target)) {
    for (const name of Object.getOwnPropertyNames(target)) if (/compar/i.test(name)) names.add(name);
  }
  return [...names];
}

/**
 * The raw Node addon (`index.js` of `bindings/node`): UTF-16 offsets, the
 * parallel `kinds`/`documents`/`callbacks` arguments, camelCase result fields.
 */
export function addonCompareSurface(addon, profile) {
  const common = profile === "common";
  const scan = common ? addon.scanCommon : addon.scan;
  const scanAndRedact = common ? addon.scanAndRedactCommon : addon.scanAndRedact;
  const compare = common ? addon.compareActionPoliciesCommon : addon.compareActionPolicies;
  const open = common ? addon.createIncrementalSanitizerCommon : addon.createIncrementalSanitizer;
  const callbackFor = (evaluate) =>
    evaluate === undefined ? undefined : (finding, context) => evaluate(finding, context);
  const scanWith = (document, input, ruleset, evaluate) =>
    scan(input, callbackFor(evaluate), undefined, ruleset, document).map(findingFields);
  return {
    profile,
    scan: scanWith,
    scanFails: (input, ruleset, evaluate) =>
      codeOnly(() => ({ findings: scanWith(undefined, input, ruleset, evaluate) })),
    scanAndRedact: (document, input, ruleset) => {
      const result = scanAndRedact(input, undefined, undefined, undefined, ruleset, document);
      return { text: result.redacted, findings: result.findings.map(findingFields) };
    },
    compare: (input, sides, { limits, ruleset } = {}) =>
      codeOnly(() => {
        const { kinds, documents, callbacks } = splitRaw(sides);
        return canonicalRaw(compare(input, kinds, documents, callbacks, limits, ruleset));
      }),
    exports: comparisonNames(addon),
    expectedExports: ["compareActionPolicies", "compareActionPoliciesCommon"],
    unsupportedProbes: () => {
      const session = open({
        limits: {
          maxInputCodeUnits: 1 << 20,
          maxBufferedCodeUnits: 16_512,
          maxTokenCodeUnits: 8_192,
          maxMultilineCodeUnits: 16_384,
        },
      });
      return [
        {
          ok: comparisonNames(session).length === 0,
          message: "an incremental session exposes a comparison-named member",
        },
      ];
    },
  };
}

/**
 * The generated WebAssembly glue (already `default()`-initialized and
 * `initialize([])`d): UTF-16 offsets, positional trailing arguments, a plain
 * result object, handle results freed after reading.
 */
export function wasmGlueCompareSurface(glue, profile) {
  const callbackFor = (evaluate) =>
    evaluate === undefined
      ? undefined
      : (finding, context) => evaluate({ ...finding, start: finding.range.start, end: finding.range.end }, context);
  const scanWith = (document, input, ruleset, evaluate) =>
    glue.scan(input, callbackFor(evaluate), undefined, undefined, ruleset, document).map(findingFields);
  return {
    profile,
    scan: scanWith,
    scanFails: (input, ruleset, evaluate) =>
      codeOnly(() => ({ findings: scanWith(undefined, input, ruleset, evaluate) })),
    scanAndRedact: (document, input, ruleset) => {
      const result = glue.scanAndRedact(input, undefined, undefined, undefined, undefined, ruleset, document);
      try {
        return { text: result.takeText(), findings: result.takeFindings().map(findingFields) };
      } finally {
        result.free();
      }
    },
    compare: (input, sides, { limits, ruleset } = {}) =>
      codeOnly(() => {
        const { kinds, documents, callbacks } = splitRaw(sides);
        const wrapped = callbacks.map(
          (callback) => (finding, context) =>
            callback({ ...finding, start: finding.range.start, end: finding.range.end }, context),
        );
        return canonicalFlat(
          glue.compareActionPolicies(
            input,
            kinds,
            documents,
            wrapped,
            limits?.maxInputBytes,
            limits?.maxFindings,
            ruleset,
          ),
        );
      }),
    exports: comparisonNames(glue),
    expectedExports: ["compareActionPolicies"],
    unsupportedProbes: () => {
      const session = glue.createIncrementalSanitizer(1 << 20, 16_512, 8_192, 16_384);
      return [
        {
          ok: comparisonNames(session).length === 0,
          message: "an incremental session exposes a comparison-named member",
        },
      ];
    },
  };
}

/**
 * The published package's public API (`@redact-secret/core` or
 * `@redact-secret/core/common`, already initialized). The adapter also checks
 * the public contract the raw surfaces cannot: the result is frozen,
 * self-describing and plain, and anything that could be mistaken for an
 * incremental or stream comparison is refused.
 */
export function publicPackageCompareSurface(api, profile) {
  const policyFor = (side) => {
    if (side.kind === "default") return { kind: "default" };
    if (side.kind === "action-policy") return { kind: "action-policy", actionPolicy: side.document };
    return { kind: "callback", policy: { evaluate: (finding, context) => side.evaluate(finding, context) } };
  };
  const scanWith = (document, input, ruleset, evaluate) =>
    api
      .scan(input, {
        ...(document === undefined ? {} : { actionPolicy: document }),
        ...(ruleset === undefined ? {} : { ruleset }),
        ...(evaluate === undefined ? {} : { policy: { evaluate: (finding, context) => evaluate(finding, context) } }),
      })
      .map(findingFields);
  const compare = (input, sides, { limits, ruleset } = {}) =>
    api.compareActionPolicies(input, {
      policies: sides.map(policyFor),
      ...(limits === undefined ? {} : { limits }),
      ...(ruleset === undefined ? {} : { ruleset }),
    });
  const code = (run) => codeOnly(run);
  return {
    profile,
    scan: scanWith,
    scanFails: (input, ruleset, evaluate) => code(() => ({ findings: scanWith(undefined, input, ruleset, evaluate) })),
    scanAndRedact: (document, input, ruleset) => {
      const result = api.scanAndRedact(input, {
        ...(document === undefined ? {} : { actionPolicy: document }),
        ...(ruleset === undefined ? {} : { ruleset }),
      });
      return { text: result.text, findings: result.findings.map(findingFields) };
    },
    compare: (input, sides, options) =>
      code(() => {
        const result = compare(input, sides, options);
        // The public shape adds self-description to the canonical one.
        const own = {
          detection: result.detection,
          policies: result.policies.map(({ kind, documentSha256, counts }) => ({ kind, documentSha256, counts })),
          changedCount: result.changedCount,
          findings: result.findings.map((finding) => ({
            id: finding.id,
            type: finding.type,
            detector: finding.detector,
            confidence: finding.confidence,
            obfuscation: finding.obfuscation,
            start: finding.start,
            end: finding.end,
            differs: finding.differs,
            decisions: finding.decisions.map((decision) => ({ ...decision })),
          })),
        };
        const frozen = deepFrozen(result);
        const labels = result.policies.map((policy) => policy.label).join(",");
        const wantedLabels = result.policies
          .map((_, index) => (index === 0 ? "baseline" : `candidate-${index}`))
          .join(",");
        const selfDescribing =
          result.mode === "preview" &&
          result.enforced === false &&
          result.rangeUnit === "utf16-code-units" &&
          result.version === api.VERSION &&
          result.findingCount === result.findings.length &&
          labels === wantedLabels;
        const roundTrip = JSON.stringify(structuredClone(result)) === JSON.stringify(result);
        if (!frozen || !selfDescribing || !roundTrip) {
          return { code: `(public shape: frozen=${frozen} selfDescribing=${selfDescribing} plain=${roundTrip})` };
        }
        return own;
      }),
    exports: Object.keys(api).filter((name) => /compar/i.test(name)),
    expectedExports: ["compareActionPolicies"],
    digestForms: (text) => {
      const document = JSON.parse(text);
      const onlyPolicy = (actionPolicy) =>
        api.compareActionPolicies("nothing to see here\n", { policies: [{ kind: "action-policy", actionPolicy }] })
          .policies[0].documentSha256;
      return {
        text: onlyPolicy(text),
        bytes: onlyPolicy(Buffer.from(text, "utf8")),
        object: onlyPolicy(document),
      };
    },
    unsupportedProbes: () => {
      const probes = [];
      const throws = (run, wanted) => {
        try {
          run();
        } catch (error) {
          return error?.code === wanted;
        }
        return false;
      };
      const input = "nothing to see here\n";
      const one = [{ kind: "default" }];
      probes.push({
        ok: throws(() => api.compareActionPolicies(["a", "b"], { policies: one }), "INVALID_INPUT"),
        message: "an array of chunks was accepted as comparison input",
      });
      probes.push({
        ok: throws(() => api.compareActionPolicies(Buffer.from(input), { policies: one }), "INVALID_INPUT"),
        message: "bytes were accepted as comparison input",
      });
      probes.push({
        ok: throws(
          () =>
            api.compareActionPolicies(
              (async function* () {
                yield input;
              })(),
              { policies: one },
            ),
          "INVALID_INPUT",
        ),
        message: "an async iterable was accepted as comparison input",
      });
      for (const extra of [
        { incremental: true },
        { stream: true },
        { chunks: [input] },
        { limits: { maxInputBytes: 100, maxFindings: 10, maxBufferedBytes: 10 } },
      ]) {
        probes.push({
          ok: throws(() => api.compareActionPolicies(input, { policies: one, ...extra }), "INVALID_OPTIONS"),
          message: `the key ${Object.keys(extra)[0]} was silently accepted`,
        });
      }
      probes.push({
        ok: throws(
          () => api.compareActionPolicies(input, { policies: [{ kind: "default", incremental: true }] }),
          "INVALID_OPTIONS",
        ),
        message: "a side accepted a key of another kind",
      });
      probes.push({
        ok: throws(() => api.compareActionPolicies(input, { policies: [{ kind: "session" }] }), "INVALID_OPTIONS"),
        message: "a side accepted an unknown kind",
      });
      const session = api.createIncrementalSanitizer({
        limits: { maxInputBytes: 1 << 20, maxBufferedBytes: 16_512, maxTokenBytes: 8_192, maxMultilineBytes: 16_384 },
      });
      probes.push({
        ok: comparisonNames(session).length === 0,
        message: "an incremental session exposes a comparison-named member",
      });
      return probes;
    },
  };
}
