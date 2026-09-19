#!/usr/bin/env node
/**
 * Qualifies the Cloudflare Workers runtime path (`decision-verify-edge-runtimes`)
 * against a real `workerd` sandbox, the way `qualify-node-wasm-fallback.mjs`
 * qualifies the Node fallback and `qualify-browser-artifact.mjs` qualifies the
 * browser build.
 *
 * `wrangler dev` starts a real local `workerd` server — the exact engine that
 * runs Cloudflare Workers in production, not a synthetic sandbox — from a
 * worker script that imports the published `@redact-secret/core` package
 * exactly as a Worker deployment would. Resolving that import is what
 * exercises the real thing under test: `wrangler`'s bundler selects the
 * package's `workerd` condition (`packages/javascript/package.json`'s
 * `#native` map), landing on `runtime/workerd.js`, and applies its own
 * `CompiledWasm` module rule to the `.wasm` binary that loader imports by
 * literal specifier — producing a real compiled `WebAssembly.Module`, which
 * `runtime/workerd.ts` hands straight to the real generated glue. Nothing
 * here stubs the loader, the bundler's module rule, or the artifact.
 *
 * This does not re-qualify `createBindingFromWasmModule`'s normalization —
 * already exercised against the real artifact by
 * `qualify-browser-artifact.mjs` — or the Web `TransformStream` adapter,
 * which runs unmodified over the same binding that pass already qualifies.
 * What this script exists to prove is specific to this loader: that it
 * actually loads, from this exact package-resolution and bundling shape, on
 * the real `workerd` engine.
 *
 * Preconditions:
 * - `npm run wasm:build` (`--detector-profile common` for the `common`
 *   profile) has produced the browser build in some directory (`--wasm-dir`).
 * - `npm run js:build` has produced `packages/javascript/dist`.
 * - `wrangler` is installed (`npm ci`; a devDependency).
 *
 * Usage:
 *
 *     node scripts/qualify-workerd-artifact.mjs --wasm-dir bindings/wasm/pkg
 *     node scripts/qualify-workerd-artifact.mjs --wasm-dir bindings/wasm/pkg-common --detector-profile common
 */

import { spawn } from "node:child_process";
import { existsSync, rmSync, symlinkSync } from "node:fs";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  CANONICAL_FIXTURE_ID,
  REPO_ROOT_PATH,
  assertMatchesFixture,
  loadCanonicalFixture,
  packageVersion,
} from "./qualify-runtime-fixture.mjs";

const JS_PACKAGE_DIR = join(REPO_ROOT_PATH, "packages", "javascript");
const WASM_PACKAGE_ROOT = join(REPO_ROOT_PATH, "bindings", "wasm", "npm");
/** A fixture whose default policy resolves to `redact`, for the `common`
 * profile's narrower registry, mirroring `qualify-node-wasm-fallback.mjs`'s
 * own choice for the same reason. */
const COMMON_REDACT_FIXTURE_ID = "jwt-positive-structured";
/** Long enough for `wrangler dev` to bundle and start a fresh `workerd`
 * instance on a slow CI runner, short enough to fail fast otherwise. */
const READY_TIMEOUT_MS = 60_000;

function assert(condition, message) {
  if (!condition) throw new Error(message);
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
      "usage: qualify-workerd-artifact.mjs --wasm-dir <dir> [--detector-profile full|common]",
    );
  }
  if (options.detectorProfile !== "full" && options.detectorProfile !== "common") {
    throw new Error("--detector-profile must be full or common");
  }
  return options;
}

/**
 * Links the built WebAssembly artifact into `packages/javascript`'s own
 * `node_modules`, at the exact specifier `runtime/workerd.ts`/
 * `workerd-common.ts` resolve — the same substitution
 * `qualify-node-wasm-fallback.mjs`'s `linkWasmFallback` performs for the Node
 * fallback loader, needed for the same reason: `import()` inside
 * `packages/javascript/dist/runtime/workerd.js` resolves starting from that
 * file's own real location (through the symlink `stageWorkerProject` below
 * makes for `@redact-secret/core`), not from the temporary worker project.
 */
async function linkWasmPackage(wasmDir) {
  await cp(resolve(wasmDir), WASM_PACKAGE_ROOT, { recursive: true });
  const scope = join(JS_PACKAGE_DIR, "node_modules", "@redact-secret");
  await mkdir(scope, { recursive: true });
  const link = join(scope, "wasm");
  rmSync(link, { recursive: true, force: true });
  symlinkSync(WASM_PACKAGE_ROOT, link, "junction");
  return link;
}

/**
 * The worker script under test: imports the public package exactly as a
 * Workers deployment would, then drives `initialize()`, `artifact()`, a
 * synchronous scan, `redact`, `scanAndRedact`, and one incremental session —
 * the same operations `qualify-node-wasm-fallback.mjs` drives against its own
 * fallback — against one canonical fixture, and reports the outcome as JSON
 * rather than throwing, so a real assertion failure is visible in the
 * response body instead of an opaque `workerd` 500.
 */
function renderWorkerSource(detectorProfile, fixture, expectedVersion) {
  const entry =
    detectorProfile === "common" ? "@redact-secret/core/common" : "@redact-secret/core";
  return `
    import { initialize, artifact, scan, redact, scanAndRedact, createIncrementalSanitizer, VERSION, PROFILE } from ${JSON.stringify(entry)};

    const FIXTURE = ${JSON.stringify(fixture.input)};
    const EXPECTED_FINDING_COUNT = ${fixture.expected.length};
    const EXPECTED_VERSION = ${JSON.stringify(expectedVersion)};
    const EXPECTED_PROFILE = ${JSON.stringify(detectorProfile)};
    const GENEROUS_LIMITS = {
      maxInputCodeUnits: 1_000_000,
      maxBufferedCodeUnits: 16_512,
      maxTokenCodeUnits: 8_192,
      maxMultilineCodeUnits: 16_384,
    };

    function check(name, run) {
      try {
        run();
        return { name, ok: true };
      } catch (error) {
        return { name, ok: false, detail: error instanceof Error ? error.message : String(error) };
      }
    }

    export default {
      async fetch(request) {
        const checks = [];
        let findings = [];
        try {
          await initialize();
          checks.push(check("artifact() reports wasm", () => {
            if (artifact() !== "wasm") throw new Error("artifact() was " + artifact());
          }));
          checks.push(check("VERSION/PROFILE match the built package", () => {
            if (VERSION !== EXPECTED_VERSION) throw new Error("VERSION " + VERSION);
            if (PROFILE !== EXPECTED_PROFILE) throw new Error("PROFILE " + PROFILE);
          }));
          checks.push(check("scan matches the canonical fixture's finding count", () => {
            findings = scan(FIXTURE);
            if (findings.length !== EXPECTED_FINDING_COUNT) {
              throw new Error("found " + findings.length + " finding(s)");
            }
          }));
          checks.push(check("scanAndRedact agrees with scan then redact", () => {
            const combined = scanAndRedact(FIXTURE);
            const separate = redact(FIXTURE, scan(FIXTURE));
            if (combined.text !== separate) throw new Error("scanAndRedact disagreed with scan + redact");
          }));
          checks.push(check("an incremental session matches the whole-input result", () => {
            const whole = scanAndRedact(FIXTURE);
            const session = createIncrementalSanitizer({ limits: GENEROUS_LIMITS });
            const half = Math.floor(FIXTURE.length / 2);
            const parts = [
              session.append(FIXTURE.slice(0, half)),
              session.append(FIXTURE.slice(half)),
              session.finalize(),
            ];
            const text = parts.map((part) => part.text).join("");
            if (text !== whole.text) throw new Error("incremental text diverged from the whole-input result");
          }));
        } catch (error) {
          checks.push({ name: "initialize", ok: false, detail: error instanceof Error ? error.stack : String(error) });
        }
        const ok = checks.every((entry) => entry.ok);
        return new Response(
          JSON.stringify(
            {
              ok,
              checks,
              findings: findings.map((finding) => ({
                detector: finding.detector,
                type: finding.type,
                confidence: finding.confidence,
                start: finding.start,
                end: finding.end,
              })),
            },
            null,
            2,
          ),
          {
            status: ok ? 200 : 500,
            headers: { "content-type": "application/json" },
          },
        );
      },
    };
  `;
}

async function stageWorkerProject(detectorProfile, fixture, expectedVersion) {
  const directory = await mkdtemp(join(tmpdir(), "redact-secret-workerd-"));
  const scope = join(directory, "node_modules", "@redact-secret");
  await mkdir(scope, { recursive: true });
  symlinkSync(JS_PACKAGE_DIR, join(scope, "core"), "junction");
  await writeFile(
    join(directory, "worker.mjs"),
    renderWorkerSource(detectorProfile, fixture, expectedVersion),
  );
  await writeFile(
    join(directory, "wrangler.toml"),
    [
      'name = "redact-secret-workerd-qualification"',
      'main = "worker.mjs"',
      `compatibility_date = "${new Date().toISOString().slice(0, 10)}"`,
      "",
      "[[rules]]",
      'type = "CompiledWasm"',
      'globs = ["**/*.wasm"]',
      "fallthrough = true",
      "",
    ].join("\n"),
  );
  return directory;
}

/** Starts `wrangler dev` in `directory` and resolves once it answers requests,
 * polling rather than parsing its stdout so this does not depend on the
 * exact banner text of whatever `wrangler` version is installed. */
async function startWrangler(directory, port) {
  const child = spawn(
    process.platform === "win32" ? "npx.cmd" : "npx",
    ["wrangler", "dev", "--port", String(port), "--local", "--ip", "127.0.0.1"],
    { cwd: directory, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));
  let exited = false;
  child.once("exit", () => {
    exited = true;
  });

  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (exited) {
      throw new Error(`wrangler dev exited before it was ready:\n${output}`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
      await response.text();
      return child;
    } catch {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 500));
    }
  }
  child.kill();
  throw new Error(`wrangler dev did not become ready within ${READY_TIMEOUT_MS}ms:\n${output}`);
}

async function stopWrangler(child) {
  child.kill();
  await new Promise((resolveExit) => child.once("exit", resolveExit));
}

async function main() {
  const { wasmDir, detectorProfile } = parseArguments(process.argv.slice(2));
  const packageEntry = join(
    JS_PACKAGE_DIR,
    "dist",
    detectorProfile === "common" ? "common.js" : "index.js",
  );
  assert(
    existsSync(packageEntry),
    `${packageEntry}: missing; build the package with \`npm run js:build\``,
  );

  const fixtureId =
    detectorProfile === "common" ? COMMON_REDACT_FIXTURE_ID : CANONICAL_FIXTURE_ID;
  const fixture = await loadCanonicalFixture(fixtureId);
  const expectedVersion = await packageVersion();

  const link = await linkWasmPackage(wasmDir);
  let directory;
  try {
    directory = await stageWorkerProject(detectorProfile, fixture, expectedVersion);
    const port = 8700 + Math.floor(Math.random() * 300);
    const child = await startWrangler(directory, port);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
      const body = await response.json();
      for (const entry of body.checks ?? []) {
        console.log(`${entry.ok ? "ok" : "not ok"} - workerd (${detectorProfile}) · ${entry.name}`);
        if (!entry.ok) console.error(`    ${entry.detail}`);
      }
      assert(body.ok === true, `workerd qualification (${detectorProfile}) reported failures`);
      if (detectorProfile !== "common") {
        // The `common` registry resolves this fixture to a different action;
        // only the `full` profile's finding shape is asserted exactly.
        assert(body.findings.length === 1, `expected exactly one finding, got ${body.findings.length}`);
        assertMatchesFixture(body.findings[0], fixture);
      }
      console.log(
        `qualified the Cloudflare Workers runtime path (${detectorProfile} profile) against a real workerd sandbox.`,
      );
    } finally {
      await stopWrangler(child);
    }
  } finally {
    if (directory !== undefined) await rm(directory, { recursive: true, force: true });
    await rm(link, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
