/**
 * Qualifies a built CLI binary on the architecture it targets.
 *
 * Five passes:
 *
 * 1. **Inspect** — the artifact exists, is executable, carries the file name
 *    its target implies, and its size and SHA-256 are printed, so a release
 *    run records the artifact's contents and not only its name.
 * 2. **Identity** — `--version` reports the shared product version
 *    (`decision-release-bindings-in-lockstep`) and `--help` leads with the
 *    same identity and prints the usage block.
 * 3. **Contract** — the documented exit codes: 0 clean, 1 findings, 2 usage
 *    error, with the usage block on stderr and nothing on stdout.
 * 4. **Conform** — every canonical synchronous fixture
 *    (`decision-govern-cross-language-conformance`) through bounded,
 *    multi-source `--json` runs. Batching keeps the complete Windows command
 *    line below its platform limit as the corpus grows. The CLI reports UTF-8
 *    byte ranges, which are the corpus's own canonical unit, so the comparison
 *    needs no conversion.
 * 5. **Redact** — every fixture with a redacted finding through `--redact`,
 *    compared byte for byte against the text that run's own findings and the
 *    documented default placeholder imply, and checked for any surviving
 *    match.
 *
 * Every fixture input is synthetic or explicitly revoked, and nothing this
 * script prints carries an input, a matched value, or a placeholder body.
 * Node rather than Python because this has to run on every runner in the
 * matrix, including Windows on Arm. Usage:
 *
 *     node scripts/qualify-cli-binary.mjs --target aarch64-apple-darwin
 *     node scripts/qualify-cli-binary.mjs --binary target/release/redact-secret
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  constants,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { batchArguments } from "./lib/cli-qualification-batches.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES_DIR = join(REPO_ROOT, "conformance", "fixtures");

/**
 * Every target the CLI is released for, and the suffix its executable
 * carries. `scripts/check-artifact-matrix.py` requires every triple in
 * `cli-release-targets` to appear here. The CLI ships no musl variant, so
 * this is the six triples the addon shares with the wheels, not the addon's
 * own eight.
 */
const TARGET_SUFFIXES = {
  "aarch64-apple-darwin": "",
  "aarch64-pc-windows-msvc": ".exe",
  "aarch64-unknown-linux-gnu": "",
  "x86_64-apple-darwin": "",
  "x86_64-pc-windows-msvc": ".exe",
  "x86_64-unknown-linux-gnu": "",
};

const BINARY_NAME = "redact-secret";
const USAGE_PREFIX = "usage: redact-secret";
/** Actions the default policy resolves to a placeholder in the output. */
const REDACTED_ACTIONS = new Set(["redact", "block"]);

const failures = [];

function report(name, run) {
  try {
    run();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures.push(name);
    console.log(`not ok - ${name}`);
    console.error(`    ${error instanceof Error ? error.message : String(error)}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  const left = JSON.stringify(actual);
  const right = JSON.stringify(expected);
  if (left !== right) throw new Error(`${message}: expected ${right}, got ${left}`);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = { target: undefined, binary: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--target") {
      index += 1;
      const value = argv[index];
      if (value === undefined || !(value in TARGET_SUFFIXES)) {
        fail(`--target must be one of ${Object.keys(TARGET_SUFFIXES).join(", ")}`);
      }
      options.target = value;
    } else if (argument === "--binary") {
      index += 1;
      const value = argv[index];
      if (value === undefined) fail("--binary requires a path");
      options.binary = resolve(REPO_ROOT, value);
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }
  if (options.binary === undefined) {
    if (options.target === undefined) fail("one of --binary or --target is required");
    options.binary = join(
      REPO_ROOT,
      "target",
      options.target,
      "release",
      BINARY_NAME + TARGET_SUFFIXES[options.target],
    );
  }
  return options;
}

function productVersion() {
  return JSON.parse(
    readFileSync(join(REPO_ROOT, "packages/javascript/package.json"), "utf8"),
  ).version;
}

function loadFixtures() {
  const corpus = JSON.parse(
    readFileSync(join(FIXTURES_DIR, "synchronous-corpus.json"), "utf8"),
  );
  assert(
    corpus.offsetUnit === "utf8-byte",
    `synchronous-corpus.json: offsetUnit is ${corpus.offsetUnit}`,
  );
  // "not-yet-evaluated" fixtures carry no expectation and document a future
  // gap, not a current behavioral contract.
  return corpus.fixtures.filter(
    (fixture) => fixture.support !== "not-yet-evaluated",
  );
}

function runCli(binary, args, stdin = Buffer.alloc(0)) {
  const result = spawnSync(binary, args, { input: stdin, maxBuffer: 64 * 1024 * 1024 });
  if (result.error !== undefined) throw result.error;
  return result;
}

function inspect(binary, target) {
  const { size } = statSync(binary);
  const sha256 = createHash("sha256").update(readFileSync(binary)).digest("hex");
  console.log(`# ${binary} ${size} bytes sha256:${sha256}`);
  if (target !== undefined) {
    assertEqual(
      binary.split(/[\\/]/).at(-1),
      BINARY_NAME + TARGET_SUFFIXES[target],
      "binary name",
    );
  }
  if (process.platform !== "win32") {
    accessSync(binary, constants.X_OK);
  }
}

function identity(binary) {
  const version = runCli(binary, ["--version"]);
  assertEqual(version.status, 0, "--version exit code");
  assertEqual(
    version.stdout.toString().trim(),
    `${BINARY_NAME} ${productVersion()}`,
    "--version output",
  );

  const help = runCli(binary, ["--help"]);
  assertEqual(help.status, 0, "--help exit code");
  const printed = help.stdout.toString();
  assert(
    printed.startsWith(`${BINARY_NAME} ${productVersion()}`),
    "--help did not lead with the product identity",
  );
  assert(printed.includes(USAGE_PREFIX), "--help printed no usage block on stdout");
}

function exitCodes(binary, positive) {
  const clean = runCli(binary, ["--json"], Buffer.from("nothing to see here\n"));
  assertEqual(clean.status, 0, "clean input exit code");
  assertEqual(JSON.parse(clean.stdout).findingCount, 0, "clean finding count");

  const found = runCli(binary, ["--json"], Buffer.from(positive, "utf8"));
  assertEqual(found.status, 1, "finding exit code");
  assert(JSON.parse(found.stdout).findingCount > 0, "no finding was reported");

  const rejected = runCli(binary, ["--not-an-option"]);
  assertEqual(rejected.status, 2, "usage error exit code");
  assertEqual(rejected.stdout.toString(), "", "a usage error wrote to stdout");
  assert(
    rejected.stderr.toString().includes(USAGE_PREFIX),
    "a usage error printed no usage block on stderr",
  );
}

/**
 * One file per fixture, holding its exact UTF-8 bytes and nothing more: a
 * trailing newline would move every end-of-input span.
 */
function writeSources(directory, fixtures) {
  return fixtures.map((fixture, index) => {
    const path = join(directory, `fixture-${String(index).padStart(4, "0")}.txt`);
    writeFileSync(path, Buffer.from(fixture.input, "utf8"));
    return path;
  });
}

/** Bounded multi-source `--json` runs; returns each fixture's reported findings. */
function conform(binary, fixtures, paths) {
  const reported = new Map();
  const mismatched = [];
  let fixtureIndex = 0;
  for (const pathBatch of batchArguments(paths)) {
    const result = runCli(binary, ["--json", "--", ...pathBatch]);
    assert([0, 1].includes(result.status), `unexpected exit code ${result.status}`);
    const report = JSON.parse(result.stdout);
    assertEqual(report.rangeUnit, "utf8-bytes", "reported range unit");
    assertEqual(report.version, productVersion(), "reported version");
    assertEqual(report.failures, [], "the run reported source failures");
    assertEqual(report.sources.length, pathBatch.length, "reported source count");

    report.sources.forEach((source) => {
      const fixture = fixtures[fixtureIndex];
      const findings = source.findings;
      reported.set(fixture.id, findings);
      const actual = findings.map((finding) => [
        finding.detector,
        finding.type,
        finding.confidence,
        finding.start,
        finding.end,
      ]);
      const expected = fixture.expected.map((item) => [
        item.detector,
        item.type,
        item.confidence,
        item.start,
        item.end,
      ]);
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        mismatched.push({ id: fixture.id, expected, actual });
      }
      fixtureIndex += 1;
    });
  }
  assertEqual(fixtureIndex, fixtures.length, "qualified fixture count");
  assert(
    mismatched.length === 0,
    `${mismatched.length} fixture(s) disagreed: ${JSON.stringify(mismatched.slice(0, 5))}`,
  );
  return reported;
}

function redact(binary, fixtures, paths, reported) {
  let checked = 0;
  fixtures.forEach((fixture, index) => {
    const findings = reported.get(fixture.id);
    const redacted = findings.filter((finding) => REDACTED_ACTIONS.has(finding.action));
    if (redacted.length === 0) return;
    checked += 1;

    const result = runCli(binary, ["--redact", "--", paths[index]]);
    assertEqual(result.status, 0, `${fixture.id}: --redact exit code`);

    const source = Buffer.from(fixture.input, "utf8");
    const pieces = [];
    let cursor = 0;
    redacted.forEach((finding, placeholder) => {
      pieces.push(source.subarray(cursor, finding.start));
      pieces.push(Buffer.from(`<SECRET_${placeholder + 1}>`, "utf8"));
      cursor = finding.end;
    });
    pieces.push(source.subarray(cursor));
    // The byte-exact comparison above already pins every replaced span to
    // its placeholder and leaves everything else untouched, so it is a
    // stronger check than searching the output for leftover matched text.
    // That search would also be wrong on its own: some fixtures (e.g.
    // `contextual-positive-remaining-declared-names`) legitimately repeat
    // the same synthetic value across findings that resolve to different
    // actions, so a `warn`/`allow` finding can leave a byte-identical copy
    // of a `redact`/`block` finding's value elsewhere in the output.
    assertEqual(
      result.stdout.toString("base64"),
      Buffer.concat(pieces).toString("base64"),
      `${fixture.id}: redacted output`,
    );
  });
  assert(checked >= 50, `only ${checked} fixture(s) exercised redaction`);
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const fixtures = loadFixtures();
  assert(fixtures.length >= 100, `only ${fixtures.length} corpus fixtures`);
  const positive = fixtures.find((fixture) => fixture.expected.length > 0);
  assert(positive !== undefined, "no positive fixture");

  console.log(`# ${process.platform}-${process.arch}`);
  report("the CLI artifact is an executable with the expected name", () =>
    inspect(options.binary, options.target),
  );
  if (failures.length > 0) {
    console.error("\nCLI qualification FAILED: the artifact is unusable");
    process.exit(1);
  }

  report("--version and --help report the product identity", () =>
    identity(options.binary),
  );
  report("the documented exit codes hold", () =>
    exitCodes(options.binary, positive.input),
  );

  const directory = mkdtempSync(join(tmpdir(), "redact-secret-cli-"));
  try {
    const paths = writeSources(directory, fixtures);
    let reported;
    report("the CLI matches the canonical synchronous corpus", () => {
      reported = conform(options.binary, fixtures, paths);
    });
    if (reported !== undefined) {
      report("--redact removes every match and matches the default placeholder", () =>
        redact(options.binary, fixtures, paths, reported),
      );
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    console.error(`\nCLI qualification FAILED: ${failures.join(", ")}`);
    process.exit(1);
  }
  console.log("\nCLI qualification passed");
}

main();
