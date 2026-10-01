/**
 * Bounded, deterministic property-based fuzz of the core's security
 * invariants (issue #1143; `.agents/skills/invariant-fuzz/SKILL.md`).
 *
 * The properties drive the *built* `@redact-secret/core` package through its
 * public API only (resolved by its own `exports` map, never a `src/` path),
 * against the real engine. A source checkout has neither the N-API addon nor
 * the WebAssembly artifact (the other tests use doubles for that reason), so
 * when `initialize()` cannot load one the whole suite is skipped with an
 * explicit marker rather than passing vacuously. Set
 * `REDACT_SECRET_FUZZ_REQUIRE_ARTIFACT=1` (CI, release qualification) to turn
 * that skip into a failure.
 *
 * Environment overrides, for manual large runs:
 *
 *     REDACT_SECRET_FUZZ_SEED=<int>   fast-check seed (default 1143)
 *     REDACT_SECRET_FUZZ_RUNS=<int>   runs per property (default 2000)
 *
 * Every generated value is synthetic or revoked. A failure message names
 * fixtures and indices, never plaintext; fast-check's own report is replaced
 * by {@link report}, which prints the seed, path and shrunk structure only.
 */

import * as fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";

type Core = typeof import("@redact-secret/core");
type Finding = import("@redact-secret/core").SecretFinding;
type Action = import("@redact-secret/core").SecretAction;

const SEED = Number.parseInt(process.env.REDACT_SECRET_FUZZ_SEED ?? "1143", 10);
const RUNS = Number.parseInt(process.env.REDACT_SECRET_FUZZ_RUNS ?? "2000", 10);
/** Generous, and proportional to the run count so a manual large run is not cut off. */
const TIMEOUT_MS = Math.max(60_000, RUNS * 40);
const REQUIRE_ARTIFACT = process.env.REDACT_SECRET_FUZZ_REQUIRE_ARTIFACT === "1";

// Conformance-style synthetic / revoked values. Never real credentials.
const GITHUB = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const AWS = "AKIASYNTHETIC0TEST00";
const PASSWORD_VALUE = "SYNTH_REVOKED_42";
const SECRETS = [GITHUB, AWS, `password=${PASSWORD_VALUE}`] as const;
const SECRET_VALUES = [GITHUB, AWS, PASSWORD_VALUE] as const;

const NAMES = ["GITHUB", "AWS", "PASSWORD_VALUE"] as const;

/** Fixture names for a leaked plaintext, so a failure never prints it. */
function nameOf(leak: string): string {
  const index = SECRET_VALUES.findIndex((value) => leak.includes(value));
  return index >= 0 ? `fixture:${NAMES[index]}` : "matched-text";
}

const ADVERSARIAL = [
  "\u{1F600}",
  "\u{1F468}‍\u{1F469}‍\u{1F467}", // ZWJ family emoji
  "‮",
  "‪",
  "⁧",
  "‏", // bidi controls
  "ẹ́",
  "क्ष", // combining marks / conjunct
  "​",
  "﻿",
  " ",
  "\r\n",
  "\n",
  "\t",
  "$&",
  "$1",
  "$`",
  "$'",
  "$$",
  "${x}",
  "%s",
  "\\",
  '"',
  "=",
  ": ",
] as const;

/** A synthetic secret, sometimes with an invisible character spliced in. */
const secretPiece = fc
  .tuple(fc.constantFrom(...SECRETS), fc.option(fc.constantFrom("​", "‍", "⁠"), { nil: undefined }), fc.nat(60))
  .map(([secret, invisible, at]) =>
    invisible === undefined
      ? secret
      : secret.slice(0, at % secret.length) + invisible + secret.slice(at % secret.length),
  );

const piece = fc.oneof(
  { weight: 4, arbitrary: secretPiece },
  { weight: 4, arbitrary: fc.constantFrom(...ADVERSARIAL) },
  { weight: 3, arbitrary: fc.stringMatching(/^[A-Za-z0-9_ ]{0,24}$/) },
  { weight: 1, arbitrary: fc.string({ unit: "grapheme", maxLength: 12 }) },
  { weight: 1, arbitrary: fc.constantFrom(" ", "\n", " ", "　") },
);

/** True when `value` has no lone surrogate. */
function isWellFormed(value: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value);
}

/** Well-formed (no lone surrogate) text assembled from the pieces above. */
const wellFormedText = fc
  .array(piece, { maxLength: 24 })
  .map((parts) => parts.join(""))
  .filter((text) => isWellFormed(text));

/** The same, plus one large many-candidate input now and then. */
const text = fc.oneof(
  { weight: 9, arbitrary: wellFormedText },
  {
    weight: 1,
    arbitrary: fc
      .tuple(fc.constantFrom(...SECRETS), fc.integer({ min: 20, max: 60 }))
      .map(([secret, n]) => Array.from({ length: n }, (_, i) => `${secret} ${i}\n`).join("")),
  },
);

type ActionTable = Readonly<Record<string, Action>>;
const ACTIONS: readonly Action[] = ["redact", "warn", "allow"];
/** A per-finding-type action table, so policy selection varies per family. */
const actionTable: fc.Arbitrary<ActionTable> = fc.record({
  github_token: fc.constantFrom(...ACTIONS),
  aws_access_key_id: fc.constantFrom(...ACTIONS),
  contextual_secret: fc.constantFrom(...ACTIONS),
});

function policyFor(table: ActionTable) {
  return { evaluate: (finding: { type: string }): Action => table[finding.type] ?? "redact" };
}

/** `⟦n⟧`: a formatter whose placeholders can be predicted exactly. */
const formatter = (_f: unknown, { placeholderIndex }: { placeholderIndex: number }) => `⟦${placeholderIndex}⟧`;

/** Cut points at code point boundaries (a lone surrogate chunk is rejected). */
function partition(input: string, cuts: readonly number[]): string[] {
  const points = [...new Set(cuts.map((c) => (input.length === 0 ? 0 : c % (input.length + 1))))]
    .map((c) => {
      let cut = c;
      const code = input.charCodeAt(cut);
      const previous = input.charCodeAt(cut - 1);
      if (
        cut > 0 &&
        cut < input.length &&
        code >= 0xdc00 &&
        code <= 0xdfff &&
        previous >= 0xd800 &&
        previous <= 0xdbff
      ) {
        cut -= 1;
      }
      return cut;
    })
    .sort((a, b) => a - b);
  const chunks: string[] = [];
  let last = 0;
  for (const cut of [...points, input.length]) {
    chunks.push(input.slice(last, cut));
    last = cut;
  }
  return chunks;
}

/** Everything reachable from a thrown value, serialized for a leak check. */
function serializeError(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  const own = Object.getOwnPropertyNames(error).map((key) => {
    const value = (error as unknown as Record<string, unknown>)[key];
    return `${key}=${typeof value === "string" ? value : JSON.stringify(value)}`;
  });
  return [error.message, error.stack ?? "", String(error), JSON.stringify(error), ...own].join("\n");
}

/** Never print counterexample plaintext: seed, path and a structural summary. */
function report(details: fc.RunDetails<any>): void {
  if (!details.failed) return;
  const summary = {
    seed: details.seed,
    path: details.counterexamplePath,
    numRuns: details.numRuns,
    numShrinks: details.numShrinks,
    counterexampleShape: (details.counterexample ?? []).map((value: unknown) =>
      typeof value === "string" ? `string(len ${value.length})` : typeof value,
    ),
    error: details.errorInstance instanceof Error ? details.errorInstance.message.split("\n")[0] : undefined,
  };
  throw new Error(`invariant violated: ${JSON.stringify(summary)}`);
}

function property<T extends unknown[]>(
  arbitraries: { [K in keyof T]: fc.Arbitrary<T[K]> },
  predicate: (...args: T) => void,
): void {
  const details = fc.check(
    (fc.property as unknown as (...args: unknown[]) => fc.IProperty<unknown[]>)(...arbitraries, predicate),
    { seed: SEED, numRuns: RUNS, verbose: 0 },
  );
  report(details);
}

let core: Core | undefined;
let skipReason: string | undefined;

beforeAll(async () => {
  try {
    const loaded = await import("@redact-secret/core");
    await loaded.initialize();
    core = loaded;
  } catch {
    skipReason = "no usable native addon or WebAssembly artifact in this checkout";
    if (REQUIRE_ARTIFACT) {
      throw new Error(`invariant fuzz requires a real artifact: ${skipReason}`);
    }
  }
});

function run(name: string, body: (api: Core) => void): void {
  it(
    name,
    (context) => {
      if (core === undefined) {
        context.skip();
        return;
      }
      body(core);
    },
    TIMEOUT_MS,
  );
}

describe(`invariant fuzz (seed ${SEED}, ${RUNS} runs per property)`, () => {
  run("1. no plaintext in findings, output of redact-selected ranges, or thrown errors", (api) => {
    property([text, actionTable], (input, table) => {
      const result = api.scanAndRedact(input, { policy: policyFor(table), placeholderFormatter: formatter });
      for (const finding of result.findings) {
        const matched = input.slice(finding.start, finding.end);
        const serialized = JSON.stringify(finding);
        if (matched.length >= 8) {
          expect(serialized.includes(matched), `finding leaks ${nameOf(matched)}`).toBe(false);
        }
        expect(Object.keys(finding).sort()).toEqual([
          "action",
          "confidence",
          "detector",
          "end",
          "id",
          "obfuscation",
          "start",
          "type",
        ]);
      }
    });

    // Thrown errors: an unpaired surrogate beside a secret, a forged finding.
    property([fc.constantFrom(...SECRETS), fc.constantFrom("\ud800", "\udc00")], (secret, lone) => {
      for (const attempt of [
        () => api.scan(`${lone} ${secret}`),
        () => api.scanAndRedact(`${secret} ${lone}`),
        () =>
          api.redact(`${secret} tail`, [
            {
              id: "finding-1",
              type: "t",
              detector: "d",
              confidence: "high",
              obfuscation: "none",
              action: "redact",
              start: 0,
              end: 10_000,
            },
          ]),
      ]) {
        let thrown: unknown;
        try {
          attempt();
        } catch (error) {
          thrown = error;
        }
        expect(thrown).toBeInstanceOf(api.SecretScanError);
        const serialized = serializeError(thrown);
        for (const value of SECRET_VALUES) {
          expect(serialized.includes(value), `error leaks ${nameOf(value)}`).toBe(false);
        }
      }
    });
  });

  run("2. placeholder boundary: at most 256 UTF-8 bytes and never contains a replaced range", (api) => {
    property([text, fc.integer({ min: 0, max: 300 })], (input, size) => {
      const found = api.scan(input);
      const placeholder = "é".repeat(Math.floor(size / 2)) + (size % 2 === 1 ? "x" : "");
      const bytes = new TextEncoder().encode(placeholder).length;
      let result: ReturnType<Core["scanAndRedact"]> | undefined;
      try {
        result = api.scanAndRedact(input, { placeholderFormatter: () => placeholder });
      } catch (error) {
        expect((error as { code?: string }).code).toBe("INVALID_PLACEHOLDER");
      }
      const redacting = found.filter((f) => f.action === "redact" || f.action === "block");
      if (redacting.length > 0) {
        // Oversized or empty placeholders are rejected with the fixed code;
        // accepted ones are within the documented bound.
        if (result === undefined) expect(bytes > 256 || bytes === 0).toBe(true);
        else expect(bytes).toBeLessThanOrEqual(256);
      }
    });

    // A placeholder equal to (or embedding) the matched text must be refused.
    property([fc.constantFrom(...SECRET_VALUES), fc.string({ maxLength: 4 })], (value, noise) => {
      const input = `key ${value === PASSWORD_VALUE ? `password=${value}` : value} end`;
      const found = api.scan(input).filter((f) => f.action === "redact");
      for (const finding of found) {
        const matched = input.slice(finding.start, finding.end);
        let thrown: unknown;
        try {
          api.scanAndRedact(input, { placeholderFormatter: () => `${noise}${matched}${noise}` });
        } catch (error) {
          thrown = error;
        }
        expect(thrown, "placeholder embedding the matched text must be rejected").toBeInstanceOf(api.SecretScanError);
      }
    });
  });

  run("3. action gate: redact removes matched text, warn/allow preserves it byte-for-byte", (api) => {
    property([text, actionTable], (input, table) => {
      const result = api.scanAndRedact(input, { policy: policyFor(table), placeholderFormatter: formatter });
      // Rebuild the expected output from the original text and the findings.
      let expected = "";
      let cursor = 0;
      let placeholder = 0;
      for (const finding of result.findings) {
        expected += input.slice(cursor, finding.start);
        if (finding.action === "redact" || finding.action === "block") {
          placeholder += 1;
          expected += `⟦${placeholder}⟧`;
        } else {
          expected += input.slice(finding.start, finding.end);
        }
        cursor = finding.end;
        expect(finding.action).toBe(table[finding.type] ?? "redact");
      }
      expected += input.slice(cursor);
      expect(result.text === expected, "output differs from the action-derived reconstruction").toBe(true);
    });
  });

  run("4. determinism: repeated calls give identical findings and output", (api) => {
    property([text, actionTable], (input, table) => {
      const options = { policy: policyFor(table), placeholderFormatter: formatter };
      const first = api.scanAndRedact(input, options);
      for (let i = 0; i < 3; i += 1) {
        expect(api.scanAndRedact(input, options)).toEqual(first);
        expect(api.scan(input, { policy: policyFor(table) })).toEqual(first.findings);
      }
    });
  });

  run("5. incremental sanitizer over any chunk partition equals whole-input scanAndRedact", (api) => {
    const limits = {
      maxInputCodeUnits: 32_768,
      maxBufferedCodeUnits: 16_512,
      maxTokenCodeUnits: 8_192,
      maxMultilineCodeUnits: 16_384,
    };
    property([text, fc.array(fc.nat(), { maxLength: 12 }), actionTable], (input, cuts, table) => {
      const whole = api.scanAndRedact(input, { policy: policyFor(table), placeholderFormatter: formatter });
      const session = api.createIncrementalSanitizer({
        limits,
        policy: policyFor(table),
        placeholderFormatter: formatter,
      });
      let output = "";
      const findings: Finding[] = [];
      for (const chunk of partition(input, cuts)) {
        const step = session.append(chunk);
        output += step.text;
        findings.push(...step.findings);
      }
      const last = session.finalize();
      output += last.text;
      findings.push(...last.findings);
      expect(output === whole.text, "incremental output differs from whole-input output").toBe(true);
      expect(findings).toEqual(whole.findings);
    });
  });

  run("6. ranges are in bounds, ordered, non-overlapping, and never split a surrogate pair", (api) => {
    property([text], (input) => {
      expect(api.RANGE_UNIT).toBe("utf16-code-units");
      let previousEnd = 0;
      for (const finding of api.scan(input)) {
        expect(Number.isInteger(finding.start) && Number.isInteger(finding.end)).toBe(true);
        expect(finding.start).toBeGreaterThanOrEqual(previousEnd);
        expect(finding.end).toBeGreaterThan(finding.start);
        expect(finding.end).toBeLessThanOrEqual(input.length);
        expect(isWellFormed(input.slice(finding.start, finding.end))).toBe(true);
        previousEnd = finding.end;
      }
    });
  });

  const forgedFinding = (start: number, end: number): Finding => ({
    id: "finding-1",
    type: "github_token",
    detector: "github-token",
    confidence: "high",
    obfuscation: "none",
    action: "redact",
    start,
    end,
  });

  /**
   * Shared body for invariant 7: `redact` must either apply a well-formed
   * range exactly there or reject with the fixed INVALID_FINDINGS error.
   */
  function forgedRangesAreRejected(api: Core, ranges: fc.Arbitrary<{ start: number; end: number }>): void {
    property([text, ranges, fc.boolean()], (input, range, duplicate) => {
      const base = forgedFinding(range.start, range.end);
      const findings = duplicate ? [base, base] : [base];
      const validRange =
        Number.isInteger(range.start) &&
        Number.isInteger(range.end) &&
        range.start >= 0 &&
        range.start < range.end &&
        range.end <= input.length;
      let result: string | undefined;
      let thrown: unknown;
      try {
        result = api.redact(input, findings);
      } catch (error) {
        thrown = error;
      }
      if (!validRange || duplicate) {
        expect(thrown, "invalid finding set must be rejected").toBeInstanceOf(api.SecretScanError);
        expect((thrown as { code?: string }).code).toBe("INVALID_FINDINGS");
        expect((thrown as Error).message).toBe("Redaction findings are invalid.");
      } else if (thrown === undefined) {
        // A well-formed range is applied exactly there, never elsewhere.
        expect((result as string).startsWith(input.slice(0, range.start))).toBe(true);
        expect((result as string).endsWith(input.slice(range.end))).toBe(true);
      } else {
        // An in-bounds range is refused only for a mid-code-point boundary
        // (INVALID_FINDINGS) or because the default placeholder would itself
        // contain the replaced text (INVALID_PLACEHOLDER, invariant 2).
        const code = (thrown as { code?: string }).code;
        const swallowed = input.slice(range.start, range.end);
        if (code === "INVALID_PLACEHOLDER") expect("<SECRET_1>".includes(swallowed)).toBe(true);
        else expect(code).toBe("INVALID_FINDINGS");
      }
    });
  }

  run(
    "7a. integer ranges that are out of bounds, inverted, empty, infinite, or overlapping are rejected with a fixed error",
    (api) => {
      forgedRangesAreRejected(
        api,
        fc.record({
          start: fc.integer({ min: -5, max: 200 }),
          end: fc.oneof(fc.integer({ min: -5, max: 200 }), fc.constant(Number.POSITIVE_INFINITY)),
        }),
      );
    },
  );

  // KNOWN VIOLATION (see the issue #1143 report): `redact` silently accepts a
  // NaN or fractional `start`/`end` and redacts at a coerced range (NaN -> 0,
  // 1.5 -> 1) instead of rejecting with INVALID_FINDINGS, contradicting
  // invariant 7 ("never ... a silent redaction at the wrong range"). `it.fails`
  // keeps the property enforced: this test passes while the violation exists
  // and goes red as soon as the core is fixed, which is the cue to drop the
  // `.fails` and promote it to a plain assertion. Do not weaken the property.
  it.fails("7b. KNOWN VIOLATION: NaN or fractional range bounds are rejected, not coerced", (context) => {
    if (core === undefined) {
      context.skip();
      return;
    }
    forgedRangesAreRejected(
      core,
      fc.record({
        start: fc.oneof(fc.constant(Number.NaN), fc.double({ min: 0, max: 50, noInteger: true })),
        end: fc.integer({ min: 1, max: 50 }),
      }),
    );
  });
});
