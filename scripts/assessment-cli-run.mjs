/**
 * Evaluates the real, built `redact-secret` CLI binary against
 * `assessment/fixtures/accuracy-corpus.json` — the same reviewed synthetic
 * accuracy corpus every other surface's runner scores — and emits a
 * conforming `AssessmentResult` for the `"cli"` surface, plus a Markdown
 * report.
 *
 * This drives only the CLI's public host contract
 * (`crates/secret-scan-cli/src/main.rs`): standard input, `--json` check
 * mode, `--redact` mode, file arguments, and documented exit codes. It never
 * inspects detector or policy logic directly. Every fixture is scored by
 * `assessment/adapters/scoring.ts`'s `scoreFixture`/`aggregateAccuracyMetrics`
 * — the same corpus-scoring rules every surface shares — after converting the
 * CLI's canonical UTF-8 byte ranges to UTF-16 code units.
 *
 * Beyond accuracy scoring, one run also exercises and validates:
 *
 * - the documented exit codes (0 clean, 1 findings, 2 usage/decoding failure)
 * - a malformed standard-input decode failure, which must fail closed rather
 *   than silently reporting a zero-finding success
 * - a multi-file `--` run, checked byte-for-byte against the same fixtures'
 *   standard-input results, so the file and standard-input paths agree
 * - `--redact` mode against every fixture with a `redact`/`block` finding,
 *   checked byte-for-byte against the placeholder text its own reported
 *   findings imply
 *
 * A CLI exit code outside {0, 1}, a reported source failure, or a file/redact
 * mismatch aborts the run before any `AssessmentResult` is emitted.
 *
 * Usage:
 *
 *     cargo build --release -p redact-secret-cli
 *     node scripts/assessment-cli-run.mjs
 *     node scripts/assessment-cli-run.mjs --binary target/release/redact-secret
 *     node scripts/assessment-cli-run.mjs --json-out out/cli.json --markdown-out out/cli.md
 *     node scripts/assessment-cli-run.mjs --self-test
 *
 * Every fixture is synthetic or explicitly revoked, and nothing this script
 * prints or writes carries a fixture's `input` or a matched value.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildAndEmitAccuracyResult, loadAssessmentSchema, loadAssessmentScoring } from "./lib/assessment-emit.mjs";
import {
  accuracyCorpusHash, gitCommit, hostCpu, hostOs, loadAccuracyCorpus,
} from "./lib/assessment-provenance.mjs";
import { cliVersion, resolveCliBinary, runCliProcess, rustcVersion, scanStdinJson } from "./lib/assessment-cli.mjs";

const PROFILE_ID = "accuracy-corpus";
const REDACTED_ACTIONS = new Set(["redact", "block"]);

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = {
    binary: undefined, jsonOut: "-", markdownOut: undefined, mismatchesOut: undefined,
    strict: false, selfTest: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--self-test") options.selfTest = true;
    else if (argument === "--binary") options.binary = argv[(index += 1)];
    else if (argument === "--json-out") options.jsonOut = argv[(index += 1)];
    else if (argument === "--markdown-out") options.markdownOut = argv[(index += 1)];
    else if (argument === "--mismatches-out") options.mismatchesOut = argv[(index += 1)];
    else if (argument === "--strict") options.strict = true;
    else fail(`unknown argument: ${argument}`);
  }
  return options;
}

function normalizeFinding(finding) {
  return {
    type: finding.type, detector: finding.detector, confidence: finding.confidence,
    action: finding.action, start: finding.start, end: finding.end,
  };
}

function verifyUsageErrorExitCode(invoke) {
  const result = invoke(["--not-an-option"], Buffer.alloc(0));
  if (result.status !== 2) fail(`a usage error exited ${result.status}, expected 2`);
  if (result.stdout.toString("utf8") !== "") fail("a usage error wrote to stdout");
  if (!result.stderr.toString("utf8").includes("usage: redact-secret")) {
    fail("a usage error printed no usage block on stderr");
  }
}

function verifyMalformedInputFailsClosed(invoke) {
  const malformed = Buffer.from([0xff, 0xfe, 0x00]);
  let failedClosed = false;
  try {
    scanStdinJson(invoke, malformed);
  } catch {
    failedClosed = true;
  }
  if (!failedClosed) fail("malformed standard input did not fail the evaluation closed");

  const result = invoke(["--json"], malformed);
  if (result.status !== 2) fail(`malformed standard input exited ${result.status}, expected 2`);
  const report = JSON.parse(result.stdout.toString("utf8"));
  if (report.failures.length !== 1 || report.failures[0].code !== "NOT_UTF8") {
    fail("malformed standard input did not report NOT_UTF8");
  }
}

/** One multi-file `--json` run, checked against the standard-input results already scored. */
function verifyFilePathParity(invoke, fixtures, rawFindingsByFixture) {
  const directory = mkdtempSync(join(tmpdir(), "redact-secret-cli-assessment-"));
  try {
    const paths = fixtures.map((fixture, index) => {
      const path = join(directory, `fixture-${String(index).padStart(4, "0")}.txt`);
      writeFileSync(path, Buffer.from(fixture.input, "utf8"));
      return path;
    });
    const result = invoke(["--json", "--", ...paths], Buffer.alloc(0));
    if (![0, 1].includes(result.status)) fail(`the file-path run exited ${result.status} unexpectedly`);
    const report = JSON.parse(result.stdout.toString("utf8"));
    if (report.failures.length > 0) fail("the file-path run reported source failure(s)");
    if (report.sources.length !== fixtures.length) fail("the file-path run reported an unexpected source count");
    fixtures.forEach((fixture, index) => {
      const expected = rawFindingsByFixture.get(fixture.id).map(normalizeFinding);
      const actual = report.sources[index].findings.map(normalizeFinding);
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        fail(`${fixture.id}: the file-path result diverged from the standard-input result`);
      }
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/** `--redact` against every fixture with a redacted finding, on the shared accuracy corpus. */
function verifyRedactMode(invoke, fixtures, rawFindingsByFixture) {
  let checked = 0;
  for (const fixture of fixtures) {
    const findings = rawFindingsByFixture.get(fixture.id);
    const redacted = findings.filter((finding) => REDACTED_ACTIONS.has(finding.action));
    if (redacted.length === 0) continue;
    checked += 1;

    const result = invoke(["--redact"], Buffer.from(fixture.input, "utf8"));
    if (result.status !== 0) fail(`${fixture.id}: --redact exited ${result.status}`);

    const source = Buffer.from(fixture.input, "utf8");
    const pieces = [];
    let cursor = 0;
    redacted.forEach((finding, placeholder) => {
      pieces.push(source.subarray(cursor, finding.start));
      pieces.push(Buffer.from(`<SECRET_${placeholder + 1}>`, "utf8"));
      cursor = finding.end;
    });
    pieces.push(source.subarray(cursor));
    if (result.stdout.toString("base64") !== Buffer.concat(pieces).toString("base64")) {
      fail(`${fixture.id}: --redact output diverged from the expected redaction`);
    }
  }
  if (checked === 0) fail("no accuracy-corpus fixture exercised redaction");
}

function cargoInvoke(args, stdinBuffer) {
  return runCliProcess("cargo", ["run", "-p", "redact-secret-cli", "--", ...args], stdinBuffer);
}

/**
 * Tiny known-answer checks that need no prebuilt binary — `cargo run` builds
 * a debug binary on demand, the same way
 * `assessment/adapters/rust-adapter.test.ts` drives the Rust adapter's own
 * `self-test` mode. Exercises check mode, redact mode, JSON reporting, a
 * UTF-8 byte range spanning an astral character, a decode failure, and a
 * usage failure — the small known-answer surface `AGENTS.md`'s issue
 * verification asks for, distinct from the real accuracy/performance runs
 * above, which require a real release artifact.
 */
function runSelfTest() {
  const unicodeInput = "\u{1F511} API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
  const findings = scanStdinJson(cargoInvoke, Buffer.from(unicodeInput, "utf8"));
  if (findings.length !== 1) fail("self-test: unicode known-answer scan produced no finding");
  const expectedStart = Buffer.byteLength("\u{1F511} API_KEY=", "utf8");
  if (findings[0].start !== expectedStart) fail("self-test: unicode known-answer range was not a UTF-8 byte range");

  const redacted = cargoInvoke(["--redact"], Buffer.from(unicodeInput, "utf8"));
  if (redacted.status !== 0) fail("self-test: redact mode did not exit cleanly");
  if (redacted.stdout.toString("utf8").includes("SYNTHETICREVOKED")) {
    fail("self-test: redact mode left the matched value in its output");
  }

  let failedClosed = false;
  try {
    scanStdinJson(cargoInvoke, Buffer.from([0xff, 0xfe, 0x00]));
  } catch {
    failedClosed = true;
  }
  if (!failedClosed) fail("self-test: malformed standard input did not fail the evaluation");

  const usageError = cargoInvoke(["--not-an-option"], Buffer.alloc(0));
  if (usageError.status !== 2) fail("self-test: a usage error did not exit 2");
  if (!usageError.stderr.toString("utf8").includes("usage: redact-secret")) {
    fail("self-test: a usage error printed no usage block");
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.selfTest) {
    runSelfTest();
    return;
  }

  const binary = resolveCliBinary(options.binary);
  const invoke = (args, stdinBuffer) => runCliProcess(binary, args, stdinBuffer);
  const version = cliVersion(invoke);

  const schema = await loadAssessmentSchema();
  const scoring = await loadAssessmentScoring();
  const corpus = loadAccuracyCorpus();
  if (corpus.offsetUnit !== "utf8-byte") fail(`accuracy-corpus.json: unexpected offsetUnit ${corpus.offsetUnit}`);
  const fixtures = schema.validateAssessmentFixtures(corpus.fixtures);
  if (fixtures.length !== corpus.fixtureCount || fixtures.length === 0) {
    fail(`accuracy-corpus.json: expected ${corpus.fixtureCount} fixture(s), found ${fixtures.length}`);
  }

  verifyUsageErrorExitCode(invoke);
  verifyMalformedInputFailsClosed(invoke);

  const rawFindingsByFixture = new Map();
  const perFixtureScores = [];
  for (const fixture of fixtures) {
    let rawFindings;
    try {
      rawFindings = scanStdinJson(invoke, Buffer.from(fixture.input, "utf8"));
    } catch (error) {
      fail(`accuracy evaluation FAILED before completing — ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    rawFindingsByFixture.set(fixture.id, rawFindings);
    const actual = rawFindings.map((finding) => ({
      detector: finding.detector,
      type: finding.type,
      start: scoring.byteOffsetToUtf16CodeUnit(fixture.input, finding.start),
      end: scoring.byteOffsetToUtf16CodeUnit(fixture.input, finding.end),
      action: finding.action,
    }));
    perFixtureScores.push(scoring.scoreFixture(fixture, actual));
  }
  const metrics = scoring.aggregateAccuracyMetrics(perFixtureScores);
  const mismatches = perFixtureScores.flatMap((entry) => entry.mismatches);

  verifyFilePathParity(invoke, fixtures, rawFindingsByFixture);
  verifyRedactMode(invoke, fixtures, rawFindingsByFixture);

  const provenance = {
    commit: gitCommit(),
    artifactIdentity: `redact-secret@${version.version}`,
    corpusVersion: String(corpus.corpusVersion),
    corpusHash: accuracyCorpusHash(),
    os: hostOs(), cpu: hostCpu(), runtime: rustcVersion(),
    command: `node scripts/assessment-cli-run.mjs ${process.argv.slice(2).join(" ")}`.trim(),
  };

  const result = await buildAndEmitAccuracyResult({
    surface: "cli", profileId: PROFILE_ID, metrics, mismatches, provenance,
    jsonOut: options.jsonOut, markdownOut: options.markdownOut, mismatchesOut: options.mismatchesOut,
  });

  const { accuracy } = result;
  console.error(
    `cli accuracy: ${accuracy.truePositives} true positive(s), ${accuracy.falsePositives} false positive(s), ` +
      `${accuracy.falseNegatives} false negative(s), ${accuracy.policyMismatches} policy mismatch(es) across ${fixtures.length} fixture(s)`,
  );

  if (
    options.strict &&
    (accuracy.falsePositives > 0 || accuracy.falseNegatives > 0 || accuracy.policyMismatches > 0)
  ) {
    fail("--strict: at least one mismatch was found");
  }
}

await main();
