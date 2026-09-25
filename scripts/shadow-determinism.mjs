#!/usr/bin/env node
/**
 * Cross-runtime determinism of the shadow evidence scorer (issue #772,
 * `decision-freeze-the-shadow-evidence-score-and-confidence-contract`
 * section 7, `docs/specs/engine.md` "Shadow scorer qualification").
 *
 *     node scripts/shadow-determinism.mjs inputs > inputs.jsonl
 *     node scripts/shadow-determinism.mjs compare <label>=<shadow.jsonl> ...
 *
 * `inputs` writes the qualification input set as the JSON Lines
 * `crates/secret-scan-core/examples/shadow_evaluation.rs` reads: every
 * fixture of the canonical synchronous, incremental and Unicode-conversion
 * corpora under `conformance/fixtures/`, then a generated battery of hostile
 * maximum-length and repeated or periodic values (`hostileBattery`). The
 * output is a pure function of the committed corpora and this file.
 *
 * `compare` takes the example's output from two or more hosts, requires
 * every file to be byte-for-byte identical, and prints one JSON summary:
 * each file's SHA-256 and record counts, and, over the statistical records,
 * the band distribution. It exits 1 on any difference, naming the first
 * differing line number and the two labels. It never prints a record: the
 * records hold identifiers and integers only (contract section 8), but the
 * summary has no need of them.
 *
 * Every generated value is synthetic: repetitions of fixed blocks, a
 * de Bruijn sequence, and a fixed-seed linear congruential generator over
 * `[0-9A-Za-z]`. None is a credential, and none is committed as a literal.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = join(REPO_ROOT, "conformance", "fixtures");

/** `generic-token`'s longest contextual value, `MAX_CONTEXT_VALUE_LENGTH`. */
export const MAX_CONTEXT_VALUE_BYTES = 4096;
/** The scorer's analysis bound, `MAX_ANALYSED_CHARS`. */
export const MAX_ANALYSED_CHARS = 256;

const ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/** The 32-symbol synthetic block the core's own evidence tests use. */
const BLOCK_32 = "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa";

/** `length` symbols from a fixed-seed LCG over `[0-9A-Za-z]`. */
export function lcgValue(seed, length) {
  let state = seed >>> 0;
  let out = "";
  for (let i = 0; i < length; i += 1) {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    out += ALPHANUMERIC[(state >>> 16) % ALPHANUMERIC.length];
  }
  return out;
}

/**
 * The de Bruijn sequence B(k, 2) over the first `k` symbols of
 * `[0-9A-Za-z]`: every ordered pair of symbols occurs exactly once, so no
 * bigram repeats (the worst case of `repeated_bigram_permille`).
 */
export function deBruijnPairs(k) {
  const a = new Array(2 * k).fill(0);
  const sequence = [];
  const db = (t, p) => {
    if (t > 2) {
      if (2 % p === 0) for (let j = 1; j <= p; j += 1) sequence.push(a[j]);
    } else {
      a[t] = a[t - p];
      db(t + 1, p);
      for (let j = a[t - p] + 1; j < k; j += 1) {
        a[t] = j;
        db(t + 1, t);
      }
    }
  };
  db(1, 1);
  return sequence.map((index) => ALPHANUMERIC[index]).join("");
}

/** `unit` repeated and cut to exactly `bytes` UTF-8 bytes (ASCII `unit`). */
function fill(unit, bytes) {
  return unit.repeat(Math.ceil(bytes / unit.length)).slice(0, bytes);
}

/**
 * Hostile values for the scorer's feature functions, each at most one
 * contextual value long unless its name says otherwise:
 *
 * - `period-32`: a 32-symbol block repeated, the largest autocorrelation
 *   lag the features scan;
 * - `period-33`: one symbol past that window;
 * - `late-period-break`: 255 equal symbols then a different one, where the
 *   smallest-period search fails as late as possible for every period;
 * - `distinct-bigrams`: no repeated bigram, the full quadratic bigram scan;
 * - `single-symbol`: one symbol repeated;
 * - `max-length` and `over-max-length`: fixed-seed random values of exactly
 *   `MAX_CONTEXT_VALUE_BYTES` and one byte more;
 * - `astral-distinct`: 256 distinct astral symbols, the longest histogram
 *   scan, followed by random ASCII;
 * - `invisible-interleaved`: a zero-width space after every fourth symbol;
 * - `template-long`, `environment-long`, `placeholder-long`, `mask-long`:
 *   whole-value exclusion shapes at the maximum length, for the grammar
 *   checks that read the whole value.
 */
export function hostileValues() {
  const random = lcgValue(0x772, MAX_CONTEXT_VALUE_BYTES);
  const astral = Array.from({ length: MAX_ANALYSED_CHARS }, (_, i) =>
    String.fromCodePoint(0x20000 + i),
  ).join("");
  const invisible = Array.from(fill(BLOCK_32, 3200), (ch, i) =>
    i % 4 === 3 ? `${ch}​` : ch,
  ).join("");
  return [
    ["period-32", fill(BLOCK_32, MAX_CONTEXT_VALUE_BYTES)],
    ["period-33", fill(`${BLOCK_32}X`, MAX_CONTEXT_VALUE_BYTES)],
    ["late-period-break", `${"a".repeat(255)}b${random.slice(256)}`],
    ["distinct-bigrams", fill(deBruijnPairs(62), MAX_CONTEXT_VALUE_BYTES)],
    ["single-symbol", "a".repeat(MAX_CONTEXT_VALUE_BYTES)],
    ["max-length", random],
    ["over-max-length", `${random}Z`],
    ["astral-distinct", `${astral}${random.slice(0, MAX_CONTEXT_VALUE_BYTES - 4 * MAX_ANALYSED_CHARS)}`],
    ["invisible-interleaved", invisible],
    ["template-long", `{{${random.slice(4)}}}`],
    ["environment-long", `\${SYNTHETIC_NAME:-${random.slice(20)}}`],
    ["placeholder-long", fill("example_token_", MAX_CONTEXT_VALUE_BYTES)],
    ["mask-long", "*".repeat(MAX_CONTEXT_VALUE_BYTES)],
  ];
}

/** Credential-bearing contexts `generic-token` scores, around each value. */
const CONTEXTS = [
  ["assign", (value) => `API_KEY=${value}`],
  ["yaml-quoted", (value) => `password: "${value}"\n`],
  ["json", (value) => `{"auth_token": "${value}"}`],
  // The bare `sk-` policy candidate has an exact 48-symbol body.
  ["bare-vendor", (value) => `sk-${value.slice(0, 48)}`],
];

/** Two lowercase letters naming `i`: `generic-token` rejects digit suffixes. */
function letters(i) {
  return String.fromCharCode(97 + Math.floor(i / 26) % 26, 97 + (i % 26));
}

/** The generated hostile battery, as `[id, text]` pairs. */
export function hostileBattery() {
  const cases = [];
  for (const [valueName, value] of hostileValues()) {
    for (const [contextName, wrap] of CONTEXTS) {
      cases.push([`hostile/${valueName}/${contextName}`, wrap(value)]);
    }
  }
  // Many maximum-length contextual candidates in one input.
  const many = [];
  for (let i = 0; i < 64; i += 1) many.push(`service_${letters(i)}_api_key=${lcgValue(i + 1, MAX_CONTEXT_VALUE_BYTES)}`);
  cases.push(["hostile/many-max-length", `${many.join("\n")}\n`]);
  // Many short periodic candidates in one input.
  const periodic = [];
  for (let i = 0; i < 1024; i += 1) {
    periodic.push(`app_${letters(i)}_secret = ${fill(BLOCK_32.slice(i % 16) + BLOCK_32.slice(0, i % 16), 32 + (i % 97))}`);
  }
  cases.push(["hostile/many-periodic", `${periodic.join("\n")}\n`]);
  return cases;
}

function corpusCases() {
  const cases = [];
  const read = (name) => JSON.parse(readFileSync(join(FIXTURES, name), "utf8")).fixtures;
  for (const fixture of read("synchronous-corpus.json")) cases.push([`synchronous/${fixture.id}`, fixture.input]);
  for (const fixture of read("incremental-corpus.json")) cases.push([`incremental/${fixture.id}`, fixture.input]);
  for (const fixture of read("unicode-conversion-corpus.json")) cases.push([`unicode/${fixture.id}`, fixture.input]);
  return cases;
}

/** The whole qualification input set, in output order. */
export function qualificationInputs() {
  return [...corpusCases(), ...hostileBattery()];
}

/** A summary of one shadow-evaluation output: counts only, no record. */
export function summarize(text) {
  const summary = {
    sha256: createHash("sha256").update(text).digest("hex"),
    lines: 0,
    comparisons: 0,
    statistical: 0,
    deterministic: 0,
    errors: 0,
    statisticalBands: { none: 0, low: 0, medium: 0, high: 0 },
    promotions: { promote: 0, demote: 0, preserve: 0 },
    header: null,
  };
  for (const line of text.split("\n")) {
    if (line === "") continue;
    summary.lines += 1;
    const record = JSON.parse(line);
    if (record.record === "shadow-evaluation") {
      const { productVersion, model, featureSchema, artifactRevision, modelFingerprint, profile } = record;
      summary.header = { productVersion, model, featureSchema, artifactRevision, modelFingerprint, profile };
    } else if (record.record === "shadow-error") {
      summary.errors += 1;
    } else if (record.record === "shadow-comparison") {
      summary.comparisons += 1;
      summary.promotions[record.promotion] += 1;
      if (record.authority === "statistical") {
        summary.statistical += 1;
        summary.statisticalBands[record.band] += 1;
      } else {
        summary.deterministic += 1;
      }
    }
  }
  return summary;
}

/** The first 1-based line number at which `a` and `b` differ, or 0. */
export function firstDifference(a, b) {
  const left = a.split("\n");
  const right = b.split("\n");
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return i + 1;
  }
  return 0;
}

function main(argv) {
  const [command, ...rest] = argv;
  if (command === "inputs") {
    const lines = qualificationInputs().map(([id, text]) => JSON.stringify({ id, text }));
    process.stdout.write(`${lines.join("\n")}\n`);
    return 0;
  }
  if (command === "compare") {
    if (rest.length < 2) {
      console.error("compare needs at least two <label>=<file> arguments");
      return 2;
    }
    const outputs = rest.map((argument) => {
      const at = argument.indexOf("=");
      if (at <= 0) throw new Error(`expected <label>=<file>, got ${argument}`);
      return { label: argument.slice(0, at), text: readFileSync(argument.slice(at + 1), "utf8") };
    });
    const [reference, ...others] = outputs;
    const mismatches = others
      .map((other) => ({ label: other.label, line: firstDifference(reference.text, other.text) }))
      .filter((mismatch) => mismatch.line !== 0)
      .map((mismatch) => ({ reference: reference.label, ...mismatch }));
    const report = {
      identical: mismatches.length === 0,
      crossRuntimeMismatches: mismatches.length,
      mismatches,
      outputs: Object.fromEntries(outputs.map(({ label, text }) => [label, summarize(text)])),
    };
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report.identical ? 0 : 1;
  }
  console.error("usage: shadow-determinism.mjs inputs | compare <label>=<file> <label>=<file> ...");
  return 2;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
