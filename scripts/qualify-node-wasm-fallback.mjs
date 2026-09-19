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

import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { existsSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { Readable } from "node:stream";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  CANONICAL_FIXTURE_ID,
  REPO_ROOT_PATH,
  assertMatchesFixture,
  loadCanonicalFixture,
  packageVersion,
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
  assert(
    actual === expected,
    `${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
  );
}

function parseArguments(argv) {
  const options = { wasmDir: undefined, detectorProfile: "full" };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--wasm-dir") {
      index += 1;
      options.wasmDir = argv[index];
    } else if (argument === "--detector-profile") {
      index += 1;
      options.detectorProfile = argv[index];
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  if (options.wasmDir === undefined) {
    throw new Error(
      "usage: qualify-node-wasm-fallback.mjs --wasm-dir <dir> [--detector-profile full|common]",
    );
  }
  if (options.detectorProfile !== "full" && options.detectorProfile !== "common") {
    throw new Error("--detector-profile must be full or common");
  }
  return options;
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

async function main() {
  const { wasmDir, detectorProfile } = parseArguments(process.argv.slice(2));
  const packageEntry = join(
    JS_PACKAGE_DIR,
    "dist",
    detectorProfile === "common" ? "common.js" : "index.js",
  );
  const streamEntry = join(
    JS_PACKAGE_DIR,
    "dist",
    "adapters",
    detectorProfile === "common" ? "node-stream-common.js" : "node-stream.js",
  );
  for (const entry of [packageEntry, streamEntry]) {
    assert(existsSync(entry), `${entry}: missing; build the package with \`npm run js:build\``);
  }

  const fixtureId =
    detectorProfile === "common" ? COMMON_REDACT_FIXTURE_ID : CANONICAL_FIXTURE_ID;
  const fixture = await loadCanonicalFixture(fixtureId);
  const expectedVersion = await packageVersion();

  const link = await linkWasmFallback(wasmDir);
  try {
    const api = await import(pathToFileURL(packageEntry).href);
    const { NodeStreamSanitizer } = await import(pathToFileURL(streamEntry).href);

    await api.initialize();
    assertEqual(api.artifact(), "wasm", "the fallback's reported artifact");
    assertEqual(api.VERSION, expectedVersion, "the package's reported version");
    assertEqual(api.PROFILE, detectorProfile, "the package's reported PROFILE");

    const findings = api.scan(fixture.input);
    assertEqual(findings.length, 1, `fixture ${fixture.id} finding count`);
    if (detectorProfile !== "common") assertMatchesFixture(findings[0], fixture);

    const { text, findings: combined } = api.scanAndRedact(fixture.input);
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
    const transform = new NodeStreamSanitizer(
      api.createIncrementalSanitizer({ limits: GENEROUS_LIMITS }),
    );
    const output = [];
    for await (const chunk of Readable.from([
      encoded.subarray(0, boundary),
      encoded.subarray(boundary),
    ]).pipe(transform)) {
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
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
