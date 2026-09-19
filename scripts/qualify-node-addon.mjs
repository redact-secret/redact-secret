/**
 * Qualifies a built N-API addon on the architecture it targets
 * (`decision-define-runtime-bindings`).
 *
 * Five passes, in order:
 *
 * 1. **Inspect** — the addon directory must hold the generated loader, its
 *    type declarations, and exactly one compiled `.node` file, and that file
 *    must carry the platform name the requested target maps to. Everything
 *    found is printed, so a release run records the artifact's contents
 *    rather than only its name.
 * 2. **Smoke** — `bindings/node/smoke-test.mjs`, the addon's own consumer
 *    test, run against the real artifact rather than a double.
 * 3. **Conform** — every canonical synchronous fixture
 *    (`decision-govern-cross-language-conformance`) through the addon's
 *    `scan`, with each expectation's UTF-8 byte offsets converted to UTF-16
 *    code units by an independent reference conversion.
 * 4. **Integrate** — the published JavaScript package's public API driven
 *    against the same addon, resolved the way an installed consumer resolves
 *    it, so the package's own binding glue is covered end to end.
 * 5. **Stream** — the Node `Transform` stream adapter
 *    (`packages/javascript/src/adapters/node-stream.ts`) driven over the same
 *    real addon: every UTF-8 byte-partition point of a Unicode-bearing
 *    fixture, backpressure, `destroy()`, a downstream pipeline failure, and
 *    malformed UTF-8. `test/adapters/node-stream.test.ts` exercises this same
 *    surface only against the deterministic double
 *    (`test/sanitizing-binding.ts`), because the real addon is not present in
 *    a source checkout.
 *
 * Every corpus input is synthetic or explicitly revoked, and no diagnostic
 * printed here carries an input, a matched value, or a placeholder. Usage:
 *
 *     node scripts/qualify-node-addon.mjs --target aarch64-apple-darwin
 *
 * `--detector-profile common` qualifies the addon's `common` exports
 * (`scanCommon`, `initializeCommon`, ...) instead of its default `full`
 * ones (`decision-define-detector-profile-and-pack-contract`), mirroring
 * `scripts/qualify-browser-artifact.mjs`'s own `--detector-profile` flag:
 * pass 3 (Conform) checks the addon's `common` findings against the
 * reviewed `conformance/fixtures/common-profile-expectations.json`
 * expectations instead of the canonical corpus's own `full` ones, and
 * asserts every finding comes from a detector inside the `common`
 * membership list. Passes 4 (Integrate) and 5 (Stream) also run for
 * `common`, against `@redact-secret/core/common` and the same
 * `common-profile-expectations.json`, on `COMMON_REDACT_FIXTURE_ID` instead
 * of `CANONICAL_FIXTURE_ID` (see its own comment). One compiled addon links
 * both profiles' exports, so `--detector-profile` only changes which
 * exports, expectations, and fixtures every pass uses.
 */

import { execFileSync } from "node:child_process";
import { once } from "node:events";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  CANONICAL_FIXTURE_ID,
  assertMatchesFixture,
  loadCanonicalFixture,
  packageVersion,
} from "./qualify-runtime-fixture.mjs";
import { fullDetectorIds } from "./lib/full-detector-ids.mjs";

/**
 * The package-integration and stream-adapter fixture for `common`
 * (`decision-define-detector-profile-and-pack-contract`). `CANONICAL_FIXTURE_ID` (`host-dotenv-github`) is a
 * `github-token` (provider-pack) finding under `full`; `common` falls back to
 * `generic-token` at `warn`, which leaves the input text unredacted and would
 * make this file's redaction checks vacuous. `jwt-positive-structured` is a
 * `common`-pack (`jwt`) finding that is `redact` and identical — same
 * detector, type, confidence, and range — in both `full` and `common`
 * (per-detector invariance), single-finding, and pure ASCII, the same
 * constraints `CANONICAL_FIXTURE_ID` satisfies.
 */
const COMMON_REDACT_FIXTURE_ID = "jwt-positive-structured";

import { qualifyIncrementalInput } from "./qualify-incremental-input.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ADDON_DIR = join(REPO_ROOT, "bindings", "node");
const JS_PACKAGE_DIR = join(REPO_ROOT, "packages", "javascript");
const FIXTURES_DIR = join(REPO_ROOT, "conformance", "fixtures");

/**
 * The `<platform>-<arch>[-<abi>]` name `@napi-rs/cli` gives the compiled
 * file for each declared target. `scripts/check-artifact-matrix.py`
 * requires every target in the declared matrix to appear here.
 */
const TARGET_PLATFORM_NAMES = {
  "x86_64-unknown-linux-gnu": "linux-x64-gnu",
  "aarch64-unknown-linux-gnu": "linux-arm64-gnu",
  "x86_64-unknown-linux-musl": "linux-x64-musl",
  "aarch64-unknown-linux-musl": "linux-arm64-musl",
  "x86_64-apple-darwin": "darwin-x64",
  "aarch64-apple-darwin": "darwin-arm64",
  "x86_64-pc-windows-msvc": "win32-x64-msvc",
  "aarch64-pc-windows-msvc": "win32-arm64-msvc",
};

/**
 * Limits generous enough that no canonical fixture reaches one. They only
 * have to be structurally valid: the Node runtime rejects the call before
 * any of them is consulted.
 */
const GENEROUS_LIMITS = Object.freeze({
  maxInputCodeUnits: 1_000_000,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
});

/**
 * Per detector profile: which of the addon's exports pass 3 (Conform) uses
 * (`decision-define-detector-profile-and-pack-contract`). N-API's camelCase
 * conversion turns `bindings/node/src/lib.rs`'s `scan_common`/
 * `initialize_common` into these names. The profile check call below asserts
 * both `profile()` and `profileCommon()` unconditionally, regardless of
 * `detectorProfile` — one compiled addon always exposes both, so there is
 * nothing per-profile to select there.
 */
const DETECTOR_PROFILES = {
  full: { initialize: "initialize", scan: "scan" },
  common: {
    initialize: "initializeCommon",
    scan: "scanCommon",
  },
};
const COMMON_EXPECTATIONS_FILE = "common-profile-expectations.json";

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

async function reportAsync(name, run) {
  try {
    await run();
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

/**
 * The exact text `redact()`'s default formatter produces from `input` and
 * `findings`: `<SECRET_N>` (`N` one-based among `redact`/`block` findings,
 * `crates/secret-scan-core/src/redact.rs`) in place of each such finding's
 * span, everything else — including a `warn`/`allow` finding's own span —
 * passed through unchanged. An independent reconstruction from the
 * fixture's own findings, not a search over the output: a fixture can
 * reuse one literal secret value across findings with different actions or
 * lengths (`slack-positive-all-prefixes` has one finding's matched text as
 * a literal substring of another's), which makes "does this value still
 * appear anywhere" and "how many times does it appear" both unsound.
 */
function expectedRedaction(input, findings) {
  const redacted = findings
    .filter((finding) => finding.action === "redact" || finding.action === "block")
    .sort((a, b) => a.start - b.start);
  const pieces = [];
  let cursor = 0;
  redacted.forEach((finding, index) => {
    pieces.push(input.slice(cursor, finding.start));
    pieces.push(`<SECRET_${index + 1}>`);
    cursor = finding.end;
  });
  pieces.push(input.slice(cursor));
  return pieces.join("");
}

function parseArguments(argv) {
  const options = { target: undefined, detectorProfile: "full" };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--target") {
      index += 1;
      const value = argv[index];
      if (value === undefined || !(value in TARGET_PLATFORM_NAMES)) {
        console.error(
          `--target must be one of ${Object.keys(TARGET_PLATFORM_NAMES).join(", ")}`,
        );
        process.exit(1);
      }
      options.target = value;
    } else if (argument === "--detector-profile") {
      index += 1;
      const value = argv[index];
      if (!Object.hasOwn(DETECTOR_PROFILES, value ?? "")) {
        console.error(
          `--detector-profile must be one of ${Object.keys(DETECTOR_PROFILES).join(", ")}`,
        );
        process.exit(1);
      }
      options.detectorProfile = value;
    } else {
      console.error(`unknown argument: ${argument}`);
      process.exit(1);
    }
  }
  return options;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Converts a canonical UTF-8 byte offset to a UTF-16 code-unit offset
 * without using the addon under test, so a conformance assertion cannot
 * validate the binding against its own conversion.
 */
function byteOffsetToCodeUnitOffset(text, byteOffset) {
  return decoder.decode(encoder.encode(text).slice(0, byteOffset)).length;
}

function loadSynchronousCorpus() {
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

/**
 * The reviewed `common`-profile expectations for every canonical synchronous
 * fixture (`decision-define-detector-profile-and-pack-contract`): the same
 * file `scripts/qualify-browser-artifact.mjs` qualifies the browser
 * artifact's `common` build against, so the two artifacts are held to one
 * reviewed set of expected findings rather than two.
 */
function loadCommonExpectations() {
  const common = JSON.parse(
    readFileSync(join(FIXTURES_DIR, COMMON_EXPECTATIONS_FILE), "utf8"),
  );
  assert(
    common.profile === "common" && common.offsetUnit === "utf8-byte",
    `${COMMON_EXPECTATIONS_FILE}: not a utf8-byte common expectation set`,
  );
  return common;
}

function inspectAddon(target) {
  const entries = readdirSync(ADDON_DIR).filter(
    (name) => name !== "node_modules" && name !== "src",
  );
  console.log(`# ${ADDON_DIR}`);
  for (const name of entries.sort()) {
    const { size } = statSync(join(ADDON_DIR, name));
    console.log(`#   ${String(size).padStart(9)}  ${name}`);
  }

  const compiled = entries.filter((name) => name.endsWith(".node"));
  assert(
    compiled.length === 1,
    `expected exactly one compiled addon, found ${compiled.length}: ${compiled.join(", ")}`,
  );
  for (const required of ["index.js", "index.d.ts", "package.json"]) {
    assert(entries.includes(required), `${required}: missing from the addon`);
  }
  if (target !== undefined) {
    const expected = `redact-secret.${TARGET_PLATFORM_NAMES[target]}.node`;
    assertEqual(compiled[0], expected, "compiled addon name");
  }
  return compiled[0];
}

function runSmokeTest() {
  execFileSync(process.execPath, ["smoke-test.mjs"], {
    cwd: ADDON_DIR,
    stdio: "inherit",
  });
}

/**
 * Pass 3 (Conform): drives the addon's `scan`/`scanCommon` export over
 * every canonical fixture and checks both its findings and their detector
 * membership.
 *
 * For `full`, `expected` comes from the fixture itself and `allowed` is
 * `fullDetectorIds()`. For `common`
 * (`decision-define-detector-profile-and-pack-contract`), `expected` comes
 * from `commonExpectations` (matched by fixture id — the corpus's own
 * fixtures carry only the `full` expectation) and `allowed` is
 * `commonExpectations.detectors`; a `common` addon that linked or ran a
 * `provider` detector would report a finding under an id outside that list.
 */
function conformAddon(fixtures, detectorProfile, commonExpectations) {
  const exports = DETECTOR_PROFILES[detectorProfile];
  const addon = createRequire(join(ADDON_DIR, "index.js"))("./index.js");
  addon[exports.initialize]();

  const expectationsById =
    commonExpectations === undefined
      ? undefined
      : new Map(commonExpectations.fixtures.map(({ id, expected }) => [id, expected]));
  const allowed = new Set(
    commonExpectations === undefined ? fullDetectorIds() : commonExpectations.detectors,
  );

  const mismatched = [];
  const foreign = new Set();
  for (const fixture of fixtures) {
    const expectedSource = expectationsById?.get(fixture.id) ?? fixture.expected;
    if (expectationsById !== undefined) {
      assert(
        expectationsById.has(fixture.id),
        `${COMMON_EXPECTATIONS_FILE}: no entry for ${fixture.id}`,
      );
    }
    const actual = addon[exports.scan](fixture.input).map((finding) => [
      finding.detector,
      finding.type,
      finding.confidence,
      finding.start,
      finding.end,
    ]);
    for (const [detector] of actual) {
      if (!allowed.has(detector)) foreign.add(detector);
    }
    const expected = expectedSource.map((item) => [
      item.detector,
      item.type,
      item.confidence,
      byteOffsetToCodeUnitOffset(fixture.input, item.start),
      byteOffsetToCodeUnitOffset(fixture.input, item.end),
    ]);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      mismatched.push({ id: fixture.id, expected, actual });
    }
  }
  assert(
    mismatched.length === 0,
    `${mismatched.length} fixture(s) disagreed: ${JSON.stringify(mismatched.slice(0, 5))}`,
  );
  assert(
    foreign.size === 0,
    `finding(s) from detector(s) outside the ${detectorProfile} profile: ${[...foreign].join(", ")}`,
  );
}

/**
 * Resolves the addon under the specifier the package actually requires, by
 * linking it into the package's own `node_modules`.
 *
 * `packages/javascript` declares one per-platform addon package per
 * supported host (issue #79) and `runtime/node.js` picks between them; the
 * name is asked of that module rather than restated here, so this links
 * exactly what a consumer install would resolve. Nothing publishes those
 * packages during a qualification run, so the local build stands in for the
 * one npm would have fetched.
 */
async function linkAddon() {
  const { resolveAddonSpecifier } = await import(
    pathToFileURL(join(JS_PACKAGE_DIR, "dist", "runtime", "node.js")).href
  );
  const specifier = resolveAddonSpecifier();
  assert(
    specifier !== undefined,
    `no platform package is mapped for ${process.platform}/${process.arch}`,
  );
  const scope = join(JS_PACKAGE_DIR, "node_modules", "@redact-secret");
  const link = join(scope, specifier.split("/")[1]);
  mkdirSync(scope, { recursive: true });
  rmSync(link, { recursive: true, force: true });
  symlinkSync(ADDON_DIR, link, "junction");
  return link;
}

/**
 * The finding shape `commonExpectations` (a `common-profile-expectations.json`
 * entry) records for `fixtureId`, compared against `assertMatchesFixture`'s
 * exact field set (detector, type, confidence, start, end — offsets already
 * UTF-16 for this file's pure-ASCII fixtures, the same reasoning
 * `qualify-runtime-fixture.mjs` documents for `CANONICAL_FIXTURE_ID`).
 */
function assertMatchesCommonExpectation(finding, commonExpectations, fixtureId) {
  const entry = commonExpectations.fixtures.find(({ id }) => id === fixtureId);
  assert(entry !== undefined, `${COMMON_EXPECTATIONS_FILE}: no entry for ${fixtureId}`);
  assert(
    entry.expected.length === 1,
    `fixture ${fixtureId} common expectation must have exactly one finding, found ${entry.expected.length}`,
  );
  const expected = entry.expected[0];
  const mismatches = ["detector", "type", "confidence", "start", "end"]
    .filter((key) => finding?.[key] !== expected[key])
    .map((key) => `${key}: expected ${JSON.stringify(expected[key])}, got ${JSON.stringify(finding?.[key])}`);
  if (mismatches.length > 0) {
    throw new Error(`fixture ${fixtureId} common mismatch:\n${mismatches.join("\n")}`);
  }
}

/**
 * Drives the published package's public API against the real addon,
 * resolved under the specifier an installed consumer resolves.
 *
 * This is the one layer no other check reaches: the package's own binding
 * glue, on a real artifact. `bindings/node` builds a real incremental
 * session (`decision-define-runtime-bindings`), so `initialize()` succeeds
 * and both the synchronous surface and `createIncrementalSanitizer` are
 * exercised here; `qualify-browser-artifact.mjs` exercises the same session
 * on the browser's WebAssembly artifact.
 *
 * The single-fixture assertion goes through `qualify-runtime-fixture.mjs`,
 * so this script embeds no fixture input of its own beyond a fixed synthetic
 * marker for the incremental session; the whole-corpus pass above already
 * covers the addon's own `scan`/`scanCommon`. For `common`, `entry` is
 * `@redact-secret/core/common` and the finding is checked against
 * `commonExpectations` instead of `fixture`'s own `full` expectation.
 */
async function integrateWithPackage(detectorProfile, commonExpectations) {
  const entry = join(
    JS_PACKAGE_DIR,
    "dist",
    detectorProfile === "common" ? "common.js" : "index.js",
  );
  assert(
    existsSync(entry),
    `${entry}: missing; build the package with \`npm run js:build\``,
  );

  const fixture = await loadCanonicalFixture(
    detectorProfile === "common" ? COMMON_REDACT_FIXTURE_ID : CANONICAL_FIXTURE_ID,
  );
  const expectedVersion = await packageVersion();

  const link = await linkAddon();
  try {
    const api = await import(pathToFileURL(entry).href);

    // Idempotent, and it must succeed: a rejection here means the addon no
    // longer satisfies the binding contract the package declares.
    await api.initialize();
    await api.initialize();
    qualifyIncrementalInput(api.createIncrementalSanitizer, api.SecretScanError);
    assertEqual(api.VERSION, expectedVersion, "the package's reported version");
    assertEqual(api.RANGE_UNIT, "utf16-code-units", "RANGE_UNIT");
    assertEqual(api.PROFILE, detectorProfile, "the package's reported PROFILE");

    const findings = api.scan(fixture.input);
    assertEqual(findings.length, 1, `fixture ${fixture.id} finding count`);
    if (detectorProfile === "common") {
      assertMatchesCommonExpectation(findings[0], commonExpectations, fixture.id);
    } else {
      assertMatchesFixture(findings[0], fixture);
    }
    assert(Object.isFrozen(findings[0]), "the package returned a mutable finding");

    const { text, findings: combined } = api.scanAndRedact(fixture.input);
    assertEqual(
      text,
      api.redact(fixture.input, api.scan(fixture.input)),
      `fixture ${fixture.id} scanAndRedact disagreed with scan + redact`,
    );
    assertEqual(
      text,
      expectedRedaction(fixture.input, combined),
      `fixture ${fixture.id} left a redacted span in the output`,
    );

    // `bindings/node` builds a real session on the real addon: a value
    // split across chunks, including one that only closes on the next
    // chunk, must sanitize the same way the whole-input API does and never
    // leave the marker in its output.
    const MARKER = "SYNTHETIC_REVOKED_NODE_QUALIFICATION_MARKER";
    const session = api.createIncrementalSanitizer({ limits: GENEROUS_LIMITS });
    assertEqual(session.state, "accepting", "a fresh session's state");
    let sanitized = "";
    for (const chunk of [
      `api_key=${MARKER.slice(0, 10)}`,
      `${MARKER.slice(10)}\n`,
      "tail",
    ]) {
      sanitized += session.append(chunk).text;
    }
    sanitized += session.finalize().text;
    assertEqual(session.state, "finalized", "a finalized session's state");
    assert(!sanitized.includes(MARKER), "the session left the marker in its output");
    assert(sanitized.endsWith("tail"), "the session dropped trailing plaintext");

    // A session outside `accepting` rejects every further operation with a
    // fixed, input-free code rather than silently accepting it.
    let thrown;
    try {
      session.append("ignored");
    } catch (error) {
      thrown = error;
    }
    assert(thrown !== undefined, "a finalized session accepted another append");
    assert(
      thrown instanceof api.SecretScanError,
      "a foreign error escaped the package",
    );
    assertEqual(thrown.code, "INVALID_STATE", "post-finalize append code");
  } finally {
    rmSync(link, { recursive: true, force: true });
  }
}

/**
 * Drives the Node `Transform` stream adapter over the real addon.
 *
 * `fixture` is one canonical, single-finding corpus entry: real enough that
 * an actual detector must decide it, synthetic enough to publish. It is
 * wrapped in astral-plane padding on its own lines so byte-partitioning also
 * exercises a decoder split mid-character without disturbing the fixture's
 * own line-start context.
 *
 * Every expectation is self-consistent — computed from one whole-input pass
 * of the same real session (`oracle`) rather than a hardcoded string — so
 * this does not encode the addon's redaction format a second time. For
 * `common`, `createIncrementalSanitizer`/`initialize`/`scanAndRedact` come
 * from `@redact-secret/core/common` instead of the root entry — `oracle`
 * then reflects `common`'s own findings, not `full`'s, so no fixed expected
 * shape needs to change here. `NodeStreamSanitizer` itself is always
 * imported from the one `dist/adapters/node-stream.js` (there is no
 * `common` variant — see this script's module comment): its class wraps
 * whichever session object it is given and never reads the module-level
 * `runtime` `node-stream.ts` also exports, which stays `full`-bound.
 */
async function qualifyNodeStreamAdapter(fixture, detectorProfile) {
  const entry = join(JS_PACKAGE_DIR, "dist", "adapters", "node-stream.js");
  assert(
    existsSync(entry),
    `${entry}: missing; build the package with \`npm run js:build\``,
  );

  const link = await linkAddon();
  try {
    const packageEntry = join(
      JS_PACKAGE_DIR,
      "dist",
      detectorProfile === "common" ? "common.js" : "index.js",
    );
    const { createIncrementalSanitizer, initialize, scanAndRedact } = await import(
      pathToFileURL(packageEntry).href
    );
    const { NodeStreamSanitizer } = await import(pathToFileURL(entry).href);
    await initialize();

    const FULL = fixture.input;
    const FINALIZED = `${FULL}\n`;
    // Deliberately short of a complete match: this construct can never close
    // in these checks, so it stays retained/undecided the whole time.
    const UNRESOLVED = FULL.slice(0, -5);

    function openStreamSession() {
      return createIncrementalSanitizer({ limits: GENEROUS_LIMITS });
    }

    function oracle(text) {
      return scanAndRedact(text);
    }

    async function sanitize(chunks) {
      const transform = new NodeStreamSanitizer(openStreamSession());
      const output = [];
      for await (const chunk of Readable.from(chunks).pipe(transform)) {
        output.push(chunk);
      }
      return {
        text: Buffer.concat(output).toString("utf8"),
        findings: transform.findings,
      };
    }

    const wrapped = `🔑 lead\n${FINALIZED}🔒 tail`;
    const encoded = Buffer.from(wrapped, "utf8");
    const expected = oracle(wrapped);
    assert(expected.text !== wrapped, "the real addon left a known secret unredacted");

    const diverged = [];
    for (let boundary = 0; boundary <= encoded.length; boundary += 1) {
      const actual = await sanitize([
        encoded.subarray(0, boundary),
        encoded.subarray(boundary),
      ]);
      if (
        actual.text !== expected.text ||
        JSON.stringify(actual.findings) !== JSON.stringify(expected.findings)
      ) {
        diverged.push(boundary);
      }
    }
    assert(
      diverged.length === 0,
      `${diverged.length} byte boundary(ies) had output or findings diverge from the whole-input result: ${diverged
        .slice(0, 5)
        .join(", ")}`,
    );

    const finalizedOracle = oracle(FINALIZED).text;

    {
      const bomCases = [
        "\uFEFF",
        `\uFEFF${FINALIZED}`,
        `ordinary prefix \uFEFF ${FINALIZED}`,
      ];
      for (const bomCase of bomCases) {
        const bomBytes = Buffer.from(bomCase, "utf8");
        const bomExpected = oracle(bomCase);
        const bomDiverged = [];
        for (let boundary = 0; boundary <= bomBytes.length; boundary += 1) {
          const actual = await sanitize([
            bomBytes.subarray(0, boundary),
            bomBytes.subarray(boundary),
          ]);
          if (
            actual.text !== bomExpected.text ||
            JSON.stringify(actual.findings) !== JSON.stringify(bomExpected.findings)
          ) {
            bomDiverged.push(boundary);
          }
        }
        assert(
          bomDiverged.length === 0,
          `${bomDiverged.length} BOM byte boundary(ies) had output or findings diverge from the whole-input result: ${bomDiverged
            .slice(0, 5)
            .join(", ")}`,
        );
      }
    }

    {
      const { findings } = await sanitize([encoded]);
      assert(
        Object.isFrozen(findings),
        "the real addon returned a mutable findings array through the stream adapter",
      );
      assert(findings.length > 0, "expected at least one finding from the wrapped fixture");
      assert(
        Object.isFrozen(findings[0]),
        "the real addon returned a mutable finding through the stream adapter",
      );
    }

    {
      const transform = new NodeStreamSanitizer(openStreamSession());
      const output = [];
      transform.on("data", (chunk) => output.push(chunk));
      transform.write(Buffer.from(FINALIZED + UNRESOLVED));
      transform.end(Uint8Array.of(0xc3, 0x28));
      const [error] = await once(transform, "error");
      assertEqual(error?.code, "INVALID_UTF8", "malformed UTF-8 error code");
      const flushed = Buffer.concat(output).toString("utf8");
      assertEqual(
        flushed,
        finalizedOracle,
        "output flushed before malformed UTF-8 diverged from the oracle",
      );
      assert(
        !flushed.includes(UNRESOLVED),
        "malformed UTF-8 leaked retained plaintext",
      );
    }

    {
      const transform = new NodeStreamSanitizer(openStreamSession());
      transform.end(Buffer.from("🔑", "utf8").subarray(0, 2));
      const [error] = await once(transform, "error");
      assertEqual(error?.code, "INVALID_UTF8", "truncated UTF-8 error code");
    }

    {
      const session = openStreamSession();
      const transform = new NodeStreamSanitizer(session);
      const output = [];
      transform.on("data", (chunk) => output.push(chunk));
      transform.write(Buffer.from(UNRESOLVED));
      transform.destroy();
      await once(transform, "close");
      assert(
        Buffer.concat(output).length === 0,
        "destroy() flushed retained plaintext",
      );
      assertEqual(
        transform.findings,
        [],
        "destroy() reported a finding that was never finalized",
      );
      assertEqual(session.state, "aborted", "destroy() did not abort the real addon's session");
    }

    {
      const transform = new NodeStreamSanitizer(openStreamSession());
      const written = [];
      let stalled = false;
      for (let index = 0; index < 512 && !stalled; index += 1) {
        const chunk = Buffer.from(`line-${index}-${"x".repeat(1_000)}\n`);
        written.push(chunk);
        if (!transform.write(chunk)) stalled = true;
      }
      assert(stalled, "512 large writes never produced backpressure");
      const output = [];
      const drained = once(transform, "drain");
      transform.on("data", (chunk) => output.push(chunk));
      await drained;
      const ended = once(transform, "end");
      transform.end();
      await ended;
      assert(
        Buffer.concat(output).equals(Buffer.concat(written)),
        "output diverged from input after backpressure drained",
      );
    }

    {
      const session = openStreamSession();
      const transform = new NodeStreamSanitizer(session);
      const output = [];
      let supplied = false;
      // Never signals end: the only way this pipeline settles is the
      // downstream failure below, not `transform` reaching `_flush` on its
      // own. `Readable.from([...])` would end the source right after the one
      // chunk and let `_flush` run to completion first, which finalizes the
      // session before the downstream failure has a chance to abort it.
      const source = new Readable({
        read() {
          if (supplied) return;
          supplied = true;
          this.push(Buffer.from(FINALIZED + UNRESOLVED));
        },
      });
      const downstreamError = new Error("Synthetic downstream failure.");
      const sink = new Writable({
        write(chunk, _encoding, callback) {
          output.push(chunk);
          callback(downstreamError);
        },
      });
      let rejected;
      try {
        await pipeline(source, transform, sink);
      } catch (error) {
        rejected = error;
      }
      assert(
        rejected === downstreamError,
        "pipeline() did not propagate the downstream failure",
      );
      assertEqual(
        Buffer.concat(output).toString("utf8"),
        finalizedOracle,
        "finalized output was not preserved on downstream failure",
      );
      assertEqual(
        session.state,
        "aborted",
        "downstream failure did not abort the real addon's session",
      );
    }
  } finally {
    rmSync(link, { recursive: true, force: true });
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const { detectorProfile } = options;
  const fixtures = loadSynchronousCorpus();
  assert(fixtures.length >= 100, `only ${fixtures.length} corpus fixtures`);

  const commonExpectations =
    detectorProfile === "common" ? loadCommonExpectations() : undefined;
  if (commonExpectations !== undefined) {
    assert(
      commonExpectations.fixtures.length === fixtures.length,
      `${COMMON_EXPECTATIONS_FILE} covers ${commonExpectations.fixtures.length} ` +
        `fixtures, the corpus evaluates ${fixtures.length}; regenerate it (see its Rust test)`,
    );
  }

  console.log(
    `# node ${process.version} on ${process.platform}-${process.arch} ` +
      `(detector profile: ${detectorProfile})`,
  );
  report("the addon directory holds exactly one compiled artifact", () =>
    inspectAddon(options.target),
  );
  report("the addon passes its own consumer smoke test", runSmokeTest);
  report(`the addon matches the canonical synchronous corpus (${detectorProfile})`, () =>
    conformAddon(fixtures, detectorProfile, commonExpectations),
  );
  report(`profile()/profileCommon() report the ${detectorProfile} contract`, () => {
    const addon = createRequire(join(ADDON_DIR, "index.js"))("./index.js");
    assertEqual(addon.profile(), "full", "addon.profile()");
    assertEqual(addon.profileCommon(), "common", "addon.profileCommon()");
  });

  await reportAsync(
    `the JavaScript package's public API runs on the real addon (${detectorProfile})`,
    () => integrateWithPackage(detectorProfile, commonExpectations),
  );

  const streamFixtureId =
    detectorProfile === "common" ? COMMON_REDACT_FIXTURE_ID : CANONICAL_FIXTURE_ID;
  const streamFixture = fixtures.find((fixture) => fixture.id === streamFixtureId);
  assert(streamFixture !== undefined, `no ${streamFixtureId} fixture in the synchronous corpus`);
  await reportAsync(
    `the Node stream adapter runs on the real addon (${detectorProfile})`,
    () => qualifyNodeStreamAdapter(streamFixture, detectorProfile),
  );

  if (failures.length > 0) {
    console.error(`\naddon qualification FAILED: ${failures.join(", ")}`);
    process.exit(1);
  }
  console.log("\naddon qualification passed");
}

await main();
