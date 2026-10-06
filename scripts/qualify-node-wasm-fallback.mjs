#!/usr/bin/env node

/**
 * Qualifies the Node WebAssembly fallback (`decision-add-node-wasm-fallback`)
 * against the real published artifact, the way `qualify-node-addon.mjs`
 * qualifies the addon and `qualify-browser-artifact.mjs` qualifies the
 * browser build.
 *
 * The fallback engages only once the native addon path has already failed,
 * so this script forces that by never linking an addon and instead linking
 * the built WebAssembly artifact into `packages/javascript`'s own
 * `node_modules`, at the exact specifier `runtime/node.ts`'s fallback loader
 * resolves (`@redact-secret/wasm`) — the same substitution
 * `qualify-node-addon.mjs`'s `linkAddon` performs for the addon, and the
 * same package assembly `qualify-package-consumer.mjs`'s `assembleWasmPackage`
 * performs for a real install. It then drives the published package's public
 * API exactly as an application would: `initialize()`, a synchronous scan,
 * an incremental session, and the Node `Transform` stream adapter, and
 * asserts `artifact()` reports `"wasm"` so a false pass (the addon loading
 * anyway) cannot go unnoticed.
 *
 * It also runs the reference declarative ruleset fixture
 * (`conformance/fixtures/ruleset-reference.json`, #1183) through the artifact's
 * own generated glue, loaded the way the fallback loads it: the accepted cases
 * with their default action, and every rejection as `INVALID_RULESET` with the
 * fixed class the glue appends to its error message. The public package hides
 * the class by design, so the class comparison needs the glue itself.
 *
 * It runs the shared action policy fixture
 * (`conformance/fixtures/action-policy-v1.json`, #1219) the same two ways: through
 * the artifact's own glue (the fixed class and rule index the raw error appends
 * to its message) and through the published package on the fallback, which
 * reports the code only (`scripts/lib/action-policy-reference.mjs`).
 *
 * It runs the shared explain-and-compare fixture
 * (`conformance/fixtures/action-policy-compare-v1.json`, #1220) the same two
 * ways (`scripts/lib/action-policy-compare-reference.mjs`), and requires the
 * package's canonical result digest to equal the glue's; the addon
 * qualification prints the same digest for the same profile.
 *
 * This does not exhaustively fuzz every byte boundary the way
 * `qualify-node-addon.mjs`'s own stream pass does: the stream adapter and
 * incremental session are unmodified, already-qualified code shared with the
 * addon and browser paths (`packages/javascript/src/adapters/node-stream-core.ts`,
 * `runtime/wasm-binding.ts`'s `createBindingFromWasmModule`); what this
 * script exists to prove is specific to the fallback itself — that it loads
 * at all, from this exact package layout, and that the shared code behaves
 * the same way once it does.
 *
 * Preconditions:
 * - `npm run wasm:build` (`--detector-profile common` for the `common`
 *   profile) has produced the browser build in some directory (`--wasm-dir`).
 * - `npm run js:build` has produced `packages/javascript/dist`.
 *
 * Usage:
 *
 *     node scripts/qualify-node-wasm-fallback.mjs --wasm-dir dist/wasm-web
 *     node scripts/qualify-node-wasm-fallback.mjs --wasm-dir dist/wasm-web-common --detector-profile common
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import {
  assertCompareResult,
  loadCompareFixture,
  publicPackageCompareSurface,
  runCompareReference,
  wasmGlueCompareSurface,
} from "./lib/action-policy-compare-reference.mjs";
import {
  assertActionPolicyResult,
  loadActionPolicyFixture,
  publicPackageSurface,
  runActionPolicyReference,
  runPublicInputForms,
  wasmGlueSurface,
} from "./lib/action-policy-reference.mjs";
import { loadRulesetReference, runRulesetReference } from "./lib/ruleset-reference.mjs";
import {
  assertMatchesFixture,
  CANONICAL_FIXTURE_ID,
  loadCanonicalFixture,
  packageVersion,
  REPO_ROOT_PATH,
} from "./qualify-runtime-fixture.mjs";

const JS_PACKAGE_DIR = join(REPO_ROOT_PATH, "packages", "javascript");
const WASM_PACKAGE_ROOT = join(REPO_ROOT_PATH, "bindings", "wasm", "npm");
const COMMON_REDACT_FIXTURE_ID = "jwt-positive-structured";

/**
 * Limits generous enough that no fixture used here reaches one, mirroring
 * `qualify-node-addon.mjs`'s own `GENEROUS_LIMITS`.
 */
const GENEROUS_LIMITS = Object.freeze({
  maxInputCodeUnits: 1_000_000,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  assert(actual === expected, `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function parseArguments(argv) {
  const options = { wasmDir: undefined, detectorProfile: "full", phoneSelector: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--wasm-dir") {
      index += 1;
      options.wasmDir = argv[index];
    } else if (argument === "--detector-profile") {
      index += 1;
      options.detectorProfile = argv[index];
    } else if (argument === "--phone-selector") {
      index += 1;
      options.phoneSelector = argv[index];
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  if (options.wasmDir === undefined) {
    throw new Error("usage: qualify-node-wasm-fallback.mjs --wasm-dir <dir> [--detector-profile full|common]");
  }
  if (options.detectorProfile !== "full" && options.detectorProfile !== "common") {
    throw new Error("--detector-profile must be full or common");
  }
  if (options.phoneSelector !== undefined && !["exact", "global", "off"].includes(options.phoneSelector)) {
    throw new Error("--phone-selector must be exact, global, or off");
  }
  return options;
}

function utf16OffsetFromUtf8(input, byteOffset) {
  return Buffer.from(input, "utf8").subarray(0, byteOffset).toString("utf8").length;
}

function observable(finding) {
  return {
    detector: finding.detector,
    type: finding.type,
    confidence: finding.confidence,
    action: finding.action,
    start: finding.start,
    end: finding.end,
  };
}

async function qualifyPhone(api, selectorKind) {
  const fixture = JSON.parse(
    await readFile(join(REPO_ROOT_PATH, "conformance", "fixtures", "pii-phone-v1.json"), "utf8"),
  );
  const selectors = selectorKind === "exact" ? [fixture.selector] : selectorKind === "global" ? ["pii:global"] : [];
  await api.initialize({ pii: selectors });
  assertEqual(api.artifact(), "wasm", `${selectorKind} phone artifact`);
  const globals =
    "pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone";
  const activation =
    selectorKind === "exact"
      ? "credentials=full;selectors=pii:family:global:phone;families=pii:global:phone;vocabulary=pii-context/v2"
      : selectorKind === "global"
        ? `credentials=full;selectors=pii:global;families=${globals};vocabulary=pii-context/v2`
        : "credentials=full;selectors=off;families=;vocabulary=pii-context/v2";
  assertEqual(api.piiActivation(), activation, `${selectorKind} phone activation`);

  for (const testCase of fixture.cases) {
    const expected =
      selectorKind === "off"
        ? []
        : testCase.expected.map((finding) => ({
            ...finding,
            start: utf16OffsetFromUtf8(testCase.input, finding.start),
            end: utf16OffsetFromUtf8(testCase.input, finding.end),
          }));
    const whole = api.scanAndRedact(testCase.input);
    assertEqual(
      JSON.stringify(whole.findings.map(observable)),
      JSON.stringify(expected),
      `${selectorKind} phone ${testCase.id} whole findings`,
    );
    for (let split = 0; split <= testCase.input.length; split += 1) {
      const unit = testCase.input.charCodeAt(split);
      if (unit >= 0xdc00 && unit <= 0xdfff) continue;
      const session = api.createIncrementalSanitizer({ limits: GENEROUS_LIMITS });
      const results = [
        session.append(testCase.input.slice(0, split)),
        session.append(testCase.input.slice(split)),
        session.finalize(),
      ];
      assertEqual(
        results.map((result) => result.text).join(""),
        whole.text,
        `${selectorKind} phone ${testCase.id} partition ${split} text`,
      );
      assertEqual(
        JSON.stringify(results.flatMap((result) => result.findings).map(observable)),
        JSON.stringify(expected),
        `${selectorKind} phone ${testCase.id} partition ${split} findings`,
      );
    }
  }
}

/**
 * Copies the built WebAssembly artifact next to its published manifest
 * (`bindings/wasm/npm/package.json`), then links that directory into
 * `packages/javascript/node_modules/@redact-secret/wasm` — the exact
 * specifier the fallback loader resolves. Removing any addon link for this
 * host first forces `loadAddon()` to fail, the same failure an unsupported
 * platform or a missing optional dependency produces, so `initialize()`
 * cannot reach the fallback by anything other than its own documented
 * trigger.
 */
async function linkWasmFallback(wasmDir) {
  await cp(resolve(wasmDir), WASM_PACKAGE_ROOT, { recursive: true });
  const scope = join(JS_PACKAGE_DIR, "node_modules", "@redact-secret");
  await mkdir(scope, { recursive: true });
  const link = join(scope, "wasm");
  rmSync(link, { recursive: true, force: true });
  symlinkSync(WASM_PACKAGE_ROOT, link, "junction");

  const { resolveAddonSpecifier } = await import(
    pathToFileURL(join(JS_PACKAGE_DIR, "dist", "runtime", "node.js")).href
  );
  const addonSpecifier = resolveAddonSpecifier();
  if (addonSpecifier !== undefined) {
    rmSync(join(scope, addonSpecifier.split("/")[1]), {
      recursive: true,
      force: true,
    });
  }
  return link;
}

/**
 * The reference ruleset fixture through the WebAssembly artifact's generated
 * glue (#1183). The glue reports UTF-16 offsets, like every JavaScript surface.
 */
async function conformRuleset(detectorProfile) {
  const name = detectorProfile === "common" ? "redact_secret_wasm_common" : "redact_secret_wasm";
  // A query string makes this a module instance of its own, so initializing
  // it cannot disturb the one the package's fallback loader imports.
  const glue = await import(`${pathToFileURL(join(WASM_PACKAGE_ROOT, `${name}.js`)).href}?ruleset-reference`);
  await glue.default({ module_or_path: readFileSync(join(WASM_PACKAGE_ROOT, `${name}_bg.wasm`)) });
  assertEqual(glue.profile(), detectorProfile, "the glue's reported profile");
  glue.initialize([]);

  const { checks, failures } = runRulesetReference(loadRulesetReference(), {
    offsetUnit: "utf16",
    scan: (ruleset, input) => glue.scan(input, undefined, undefined, undefined, ruleset),
    reject: (ruleset) => {
      try {
        glue.scan("irrelevant", undefined, undefined, undefined, ruleset);
      } catch (error) {
        assertEqual(error.code, "INVALID_RULESET", "rejected ruleset error code");
        const match = /\(([A-Z_]+)\)$/.exec(String(error.message));
        return match === null ? "(no class)" : match[1];
      }
      return undefined;
    },
  });
  assert(checks >= 40, `only ${checks} ruleset reference checks ran`);
  assert(failures.length === 0, `${failures.length} ruleset case(s) disagreed: ${failures.slice(0, 5).join("; ")}`);
  return checks;
}

/**
 * The shared action policy fixture (`conformance/fixtures/action-policy-v1.json`,
 * #1219) through the artifact's generated glue, loaded the way the fallback
 * loads it: every rejection with the fixed class and rule index the glue
 * appends to its error message, the accepted and boundary documents, the
 * end-to-end cases (whole input and incremental sessions over several
 * partitions) and the host obligations.
 */
async function conformActionPolicy(detectorProfile) {
  const name = detectorProfile === "common" ? "redact_secret_wasm_common" : "redact_secret_wasm";
  const glue = await import(`${pathToFileURL(join(WASM_PACKAGE_ROOT, `${name}.js`)).href}?action-policy`);
  await glue.default({ module_or_path: readFileSync(join(WASM_PACKAGE_ROOT, `${name}_bg.wasm`)) });
  assertEqual(glue.profile(), detectorProfile, "the glue's reported profile");
  glue.initialize([]);

  const result = runActionPolicyReference(loadActionPolicyFixture(), wasmGlueSurface(glue, detectorProfile));
  assertActionPolicyResult("wasm glue", result, detectorProfile);
  return result;
}

/**
 * The shared explain-and-compare fixture
 * (`conformance/fixtures/action-policy-compare-v1.json`, #1220) through the
 * artifact's generated glue, loaded the way the fallback loads it: every case,
 * error, digest and host obligation, enforcement parity against the glue's own
 * `scan`, and the callback call sequences.
 */
async function conformCompare(detectorProfile) {
  const name = detectorProfile === "common" ? "redact_secret_wasm_common" : "redact_secret_wasm";
  const glue = await import(`${pathToFileURL(join(WASM_PACKAGE_ROOT, `${name}.js`)).href}?action-policy-compare`);
  await glue.default({ module_or_path: readFileSync(join(WASM_PACKAGE_ROOT, `${name}_bg.wasm`)) });
  assertEqual(glue.profile(), detectorProfile, "the glue's reported profile");
  glue.initialize([]);

  const result = runCompareReference(loadCompareFixture(), wasmGlueCompareSurface(glue, detectorProfile));
  assertCompareResult("wasm glue", result, detectorProfile);
  return result;
}

async function main() {
  const { wasmDir, detectorProfile, phoneSelector } = parseArguments(process.argv.slice(2));
  const packageEntry = join(JS_PACKAGE_DIR, "dist", detectorProfile === "common" ? "common.js" : "index.js");
  const streamEntry = join(
    JS_PACKAGE_DIR,
    "dist",
    "adapters",
    detectorProfile === "common" ? "node-stream-common.js" : "node-stream.js",
  );
  for (const entry of [packageEntry, streamEntry]) {
    assert(existsSync(entry), `${entry}: missing; build the package with \`npm run js:build\``);
  }

  const fixtureId = detectorProfile === "common" ? COMMON_REDACT_FIXTURE_ID : CANONICAL_FIXTURE_ID;
  const fixture = await loadCanonicalFixture(fixtureId);
  const expectedVersion = await packageVersion();

  const link = await linkWasmFallback(wasmDir);
  try {
    const api = await import(pathToFileURL(packageEntry).href);
    const { NodeStreamSanitizer } = await import(pathToFileURL(streamEntry).href);

    if (phoneSelector !== undefined) {
      await qualifyPhone(api, phoneSelector);
      console.log(`qualified Node WebAssembly fallback phone matrix: ${phoneSelector}`);
      return;
    }

    const rulesetChecks = await conformRuleset(detectorProfile);
    console.log(`the WebAssembly artifact matches the reference ruleset fixture (${rulesetChecks} checks)`);

    const actionPolicy = await conformActionPolicy(detectorProfile);
    console.log(
      `the WebAssembly artifact matches the shared action policy fixture ` +
        `(${actionPolicy.checks} checks, ${actionPolicy.skipped.length} skipped on this profile, ` +
        `${actionPolicy.unscannableEvaluations} evaluations no synthetic input reaches)`,
    );

    const compare = await conformCompare(detectorProfile);
    console.log(
      `the WebAssembly artifact matches the explain-and-compare fixture ` +
        `(${compare.checks} checks, ${compare.skipped.length} fixture expectations skipped on this profile, ` +
        `${compare.notObservable.length} obligations not observable here, result digest ${compare.resultDigest})`,
    );

    await api.initialize();
    assertEqual(api.artifact(), "wasm", "the fallback's reported artifact");
    const publicCompare = runCompareReference(loadCompareFixture(), publicPackageCompareSurface(api, detectorProfile));
    assertCompareResult("package comparison", publicCompare, detectorProfile);
    assertEqual(
      publicCompare.resultDigest,
      compare.resultDigest,
      "the package's comparison results against the glue's",
    );
    console.log(
      `the package's comparison matches the glue's on the WebAssembly fallback ` +
        `(${publicCompare.checks} checks, result digest ${publicCompare.resultDigest})`,
    );
    const actionPolicyFixture = loadActionPolicyFixture();
    assertActionPolicyResult(
      "package",
      runActionPolicyReference(actionPolicyFixture, publicPackageSurface(api, detectorProfile)),
      detectorProfile,
    );
    assertActionPolicyResult("package input forms", runPublicInputForms(actionPolicyFixture, api), detectorProfile);
    console.log("the package's public API matches the shared action policy fixture on the WebAssembly fallback");
    assertEqual(api.VERSION, expectedVersion, "the package's reported version");
    assertEqual(api.PROFILE, detectorProfile, "the package's reported PROFILE");

    const findings = api.scan(fixture.input);
    assertEqual(findings.length, 1, `fixture ${fixture.id} finding count`);
    if (detectorProfile !== "common") assertMatchesFixture(findings[0], fixture);

    const { text } = api.scanAndRedact(fixture.input);
    assertEqual(
      text,
      api.redact(fixture.input, api.scan(fixture.input)),
      `fixture ${fixture.id} scanAndRedact disagreed with scan + redact`,
    );

    const MARKER = "SYNTHETIC_REVOKED_WASM_FALLBACK_QUALIFICATION_MARKER";
    const session = api.createIncrementalSanitizer({ limits: GENEROUS_LIMITS });
    assertEqual(session.state, "accepting", "a fresh session's state");
    let sanitized = "";
    for (const chunk of [`api_key=${MARKER.slice(0, 10)}`, `${MARKER.slice(10)}\n`, "tail"]) {
      sanitized += session.append(chunk).text;
    }
    sanitized += session.finalize().text;
    assertEqual(session.state, "finalized", "a finalized session's state");
    assert(!sanitized.includes(MARKER), "the fallback left the marker in its output");
    assert(sanitized.endsWith("tail"), "the fallback dropped trailing plaintext");

    // The Node `Transform` adapter, chunked across a byte boundary that
    // splits the marker, compared against a whole-input oracle from the same
    // artifact — proving the shared adapter code behaves identically over
    // the fallback binding, not merely that it constructs without error.
    const WRAPPED = `lead\napi_key=${MARKER}\ntail`;
    const encoded = Buffer.from(WRAPPED, "utf8");
    const oracle = api.scanAndRedact(WRAPPED);
    assert(oracle.text !== WRAPPED, "the fallback left a known secret unredacted");

    const boundary = Math.floor(encoded.length / 2);
    const transform = new NodeStreamSanitizer(api.createIncrementalSanitizer({ limits: GENEROUS_LIMITS }));
    const output = [];
    for await (const chunk of Readable.from([encoded.subarray(0, boundary), encoded.subarray(boundary)]).pipe(
      transform,
    )) {
      output.push(chunk);
    }
    assertEqual(
      Buffer.concat(output).toString("utf8"),
      oracle.text,
      "the stream adapter diverged from the whole-input oracle over the fallback",
    );
    assertEqual(
      JSON.stringify(transform.findings),
      JSON.stringify(oracle.findings),
      "the stream adapter's findings diverged from the whole-input oracle over the fallback",
    );

    console.log(
      `qualified the Node WebAssembly fallback (${detectorProfile} profile): artifact() reported "wasm", scan/redact/scanAndRedact, an incremental session, and the Node stream adapter all matched the real artifact.`,
    );
  } finally {
    await rm(link, { recursive: true, force: true });
  }

  if (detectorProfile === "full") {
    for (const selector of ["exact", "global", "off"]) {
      const child = spawnSync(
        process.execPath,
        [process.argv[1], "--wasm-dir", wasmDir, "--phone-selector", selector],
        { stdio: "inherit" },
      );
      assertEqual(child.status, 0, `phone ${selector} fallback child exit`);
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
