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
 * Shared binding normalization is covered by `qualify-browser-artifact.mjs`.
 * This pass also exercises Web Streams over the selected Workers binding.
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
 *     node scripts/qualify-workerd-artifact.mjs --wasm-dir bindings/wasm/pkg --pii
 *
 * For immutable consumer qualification use `--candidate-dir` and `--report`;
 * the directory must contain the packed core and complete wasm package only.
 * Legacy `--wasm-dir` runs loader smoke without a durable receipt.
 *
 * `--pii` (issue #937) initializes with a PII selection, so the worker
 * instantiates the profile's `pii` build instead of the default one, and
 * checks the activation identity and a synthetic phone finding.
 */

import { execFileSync, spawn } from "node:child_process";
import { existsSync, rmSync, symlinkSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import {
  cleanEnvironment,
  fileDigests,
  loadNpmCandidate,
  runShell,
  sha256,
  sourceCommit,
  startCandidateRegistry,
} from "./lib/candidate-install.mjs";
import {
  assertMatchesFixture,
  CANONICAL_FIXTURE_ID,
  loadCanonicalFixture,
  packageVersion,
  REPO_ROOT_PATH,
} from "./qualify-runtime-fixture.mjs";

const COMPATIBILITY_DATE = "2026-10-01";
const WRANGLER_BIN =
  process.env.REDACT_SECRET_WRANGLER_BIN ?? join(REPO_ROOT_PATH, "node_modules/wrangler/bin/wrangler.js");
const JS_PACKAGE_DIR = join(REPO_ROOT_PATH, "packages", "javascript");
const WASM_PACKAGE_ROOT = join(REPO_ROOT_PATH, "bindings", "wasm", "npm");
/** A fixture whose default policy resolves to `redact`, for the `common`
 * profile's narrower registry, mirroring `qualify-node-wasm-fallback.mjs`'s
 * own choice for the same reason. */
const COMMON_REDACT_FIXTURE_ID = "jwt-positive-structured";
/** Long enough for `wrangler dev` to bundle and start a fresh `workerd`
 * instance on a slow CI runner, short enough to fail fast otherwise. */
const READY_TIMEOUT_MS = 60_000;
/** How long the process group gets to exit on `SIGTERM` before `SIGKILL`. */
const STOP_TIMEOUT_MS = 5_000;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export function parseArguments(argv) {
  const options = { wasmDir: undefined, detectorProfile: "full", pii: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--candidate-dir" || argument === "--report") {
      options[argument === "--candidate-dir" ? "candidateDir" : "report"] = argv[++index];
      if (!options[argument === "--candidate-dir" ? "candidateDir" : "report"])
        throw new Error(`missing value for ${argument}`);
    } else if (argument === "--wasm-dir") {
      index += 1;
      options.wasmDir = argv[index];
    } else if (argument === "--detector-profile") {
      index += 1;
      options.detectorProfile = argv[index];
    } else if (argument === "--pii") {
      options.pii = true;
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  if ((options.wasmDir === undefined) === (options.candidateDir === undefined)) {
    throw new Error(
      "usage: qualify-workerd-artifact.mjs (--wasm-dir <dir> | --candidate-dir <dir>) [--detector-profile full|common] [--pii] [--report <path>]",
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
function renderWorkerSource(detectorProfile, fixture, expectedVersion, pii) {
  const entry = detectorProfile === "common" ? "@redact-secret/core/common" : "@redact-secret/core";
  return `
    import { createWebStreamSanitizer } from ${JSON.stringify(`${entry}/web-stream`)};
    import { initialize, artifact, piiActivation, artifactManifest, scan, redact, scanAndRedact, compareActionPolicies, createIncrementalSanitizer, VERSION, PROFILE } from ${JSON.stringify(entry)};

    const FIXTURE = ${JSON.stringify(fixture.input)};
    const EXPECTED_FINDING_COUNT = ${fixture.expected.length};
    const EXPECTED_VERSION = ${JSON.stringify(expectedVersion)};
    const EXPECTED_PROFILE = ${JSON.stringify(detectorProfile)};
    const INITIALIZE_OPTIONS = ${JSON.stringify(pii === undefined ? {} : { pii: [pii.selector] })};
    const EXPECTED_ACTIVATION = ${JSON.stringify(
      pii === undefined
        ? `credentials=${detectorProfile};selectors=off;families=;vocabulary=pii-context/v2`
        : `credentials=${detectorProfile};selectors=${pii.selector};families=${pii.family};vocabulary=pii-context/v2`,
    )};
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

    let initializationMs;
    export default {
      async fetch(request) {
        const checks = [];
        let findings = [];
        try {
          const initStart = performance.now();
          await initialize(INITIALIZE_OPTIONS);
          if (initializationMs === undefined) initializationMs = performance.now() - initStart;
          checks.push(check("artifact() reports wasm", () => {
            if (artifact() !== "wasm") throw new Error("artifact() was " + artifact());
          }));
          checks.push(check("piiActivation() reports the requested activation", () => {
            if (piiActivation() !== EXPECTED_ACTIVATION) throw new Error("activation identity disagreed");
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
          checks.push(check("compareActionPolicies compares sides over one detection pass (#1220)", () => {
            const scanned = scan(FIXTURE);
            const calls = [];
            const comparison = compareActionPolicies(FIXTURE, {
              policies: [
                { kind: "default" },
                { kind: "action-policy", actionPolicy: { actionPolicyRevision: 1, base: "default", rules: [] } },
                { kind: "callback", policy: { evaluate: (finding, context) => { calls.push(context.findingIndex); return "warn"; } } },
              ],
            });
            if (comparison.findings.length !== scanned.length) throw new Error("the finding count differs from scan");
            comparison.findings.forEach((compared, index) => {
              if (compared.id !== scanned[index].id || compared.start !== scanned[index].start) {
                throw new Error("a compared finding differs from scan's");
              }
              if (compared.decisions[0].action !== scanned[index].action) throw new Error("the default side differs from scan");
              if (compared.decisions[1].basis !== "no-rule-matched") throw new Error("an empty policy had a rule basis");
              if (compared.decisions[2].basis !== "callback") throw new Error("a callback side had a rule basis");
            });
            if (calls.join() !== scanned.map((_, index) => index).join()) throw new Error("callback order differs");
            if (!/^[0-9a-f]{64}$/.test(comparison.policies[1].documentSha256)) throw new Error("no document digest");
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
        try {
          const whole = scanAndRedact(FIXTURE);
          const bytes = new TextEncoder().encode(FIXTURE);
          const source = new ReadableStream({ start(controller) {
            const half = Math.floor(bytes.length / 2);
            controller.enqueue(bytes.slice(0, half));
            controller.enqueue(bytes.slice(half));
            controller.close();
          }});
          const reader = source.pipeThrough(createWebStreamSanitizer({ limits: GENEROUS_LIMITS })).getReader();
          let actual = "";
          for (;;) {
            const part = await reader.read();
            if (part.done) break;
            actual += part.value;
          }
          if (actual !== whole.text) throw new Error("Web Streams result diverged");
          checks.push({ name: "Web Streams matches whole-input result", ok: true });
        } catch { checks.push({ name: "Web Streams matches whole-input result", ok: false }); }
        const scanTimes = [];
        const scanBatchTimes = [];
        for (let index = 0; index < 21; index++) {
          const start = performance.now();
          for (let call = 0; call < 100; call++) scanAndRedact(FIXTURE);
          const batchMs = performance.now() - start;
          scanBatchTimes.push(batchMs);
          scanTimes.push(batchMs / 100);
        }
        const ok = checks.every((entry) => entry.ok);
        return new Response(
          JSON.stringify(
            {
              ok,
              checks,
              measurements: { initializeMs: initializationMs, scanAndRedactMs: scanTimes, scanBatchMs: scanBatchTimes, callsPerSample: 100, repetitions: 21, inputBytes: new TextEncoder().encode(FIXTURE).length, inputCodeUnits: FIXTURE.length, memory: { status: "unavailable", reason: "workerd does not expose process or isolate memory counters to the worker" } },
              artifactSourceRevision: artifactManifest().sourceRevision,
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

export async function stageWorkerProject(detectorProfile, fixture, expectedVersion, pii, candidateDir) {
  const directory = await mkdtemp(join(tmpdir(), "redact-secret-workerd-"));
  try {
    const scope = join(directory, "node_modules", "@redact-secret");
    await mkdir(scope, { recursive: true });
    let packages;
    if (candidateDir) {
      packages = await loadNpmCandidate(resolve(candidateDir), directory, "workerd candidate");
      assert(
        packages.size === 2 && packages.has("@redact-secret/wasm"),
        "edge candidate must contain exactly core and wasm tarballs",
      );
      const registry = await startCandidateRegistry(packages);
      try {
        await writeFile(
          join(directory, "package.json"),
          JSON.stringify({ private: true, type: "module", dependencies: { "@redact-secret/core": expectedVersion } }),
        );
        await writeFile(join(directory, ".npmrc"), `@redact-secret:registry=${registry.url}\n`);
        const install = await runShell(
          "npm install --ignore-scripts --omit=optional --no-audit --no-fund",
          directory,
          cleanEnvironment(),
        );
        assert(install.code === 0, "edge candidate install failed");
        for (const [name, candidate] of packages) {
          assert(candidate.manifest.version === expectedVersion, "edge candidate version differs");
          const installed = await fileDigests(join(scope, name.split("/")[1]));
          assert(
            installed.size === candidate.contents.size &&
              [...candidate.contents].every(([file, digest]) => installed.get(file) === digest),
            "installed edge package differs from tarball",
          );
        }
      } finally {
        await registry.close();
      }
    } else symlinkSync(JS_PACKAGE_DIR, join(scope, "core"), "junction");
    await writeFile(join(directory, "worker.mjs"), renderWorkerSource(detectorProfile, fixture, expectedVersion, pii));
    await writeFile(
      join(directory, "wrangler.toml"),
      [
        'name = "redact-secret-workerd-qualification"',
        'main = "worker.mjs"',
        `compatibility_date = "${COMPATIBILITY_DATE}"`,
        "",
        "[[rules]]",
        'type = "CompiledWasm"',
        'globs = ["**/*.wasm"]',
        "fallthrough = true",
        "",
      ].join("\n"),
    );
    return { directory, packages };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

/** Starts `wrangler dev` in `directory` and resolves once it answers requests,
 * polling rather than parsing its stdout so this does not depend on the
 * exact banner text of whatever `wrangler` version is installed. */
export async function startWrangler(directory, port) {
  const child = spawn(process.execPath, [WRANGLER_BIN, "dev", "--port", String(port), "--local", "--ip", "127.0.0.1"], {
    cwd: directory,
    stdio: ["ignore", "pipe", "pipe"],
    env: cleanEnvironment({ WRANGLER_SEND_METRICS: "false" }),
    // Wrangler starts workerd, so signalling only the direct child can
    // leave its runtime running. A detached child leads its own process
    // group, which `stopWrangler` can signal as a whole.
    detached: process.platform !== "win32",
  });
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
  await stopWrangler(child);
  throw new Error(`wrangler dev did not become ready within ${READY_TIMEOUT_MS}ms:\n${output}`);
}

/** Stops the whole `wrangler` → `workerd` group and releases its
 * pipes. A surviving grandchild holds the write end of this child's `stdout`
 * and `stderr`, which keeps this process's event loop alive after the last
 * check has already passed: the script hangs until CI cancels the job at its
 * timeout, leaving orphan `workerd` processes behind. */
export async function stopWrangler(child) {
  const exited = new Promise((resolveExit) => child.once("exit", resolveExit));
  const signal = (name) => {
    try {
      if (process.platform === "win32") child.kill(name);
      else process.kill(-child.pid, name);
    } catch {
      // Already gone, or never started: nothing left to signal.
    }
  };
  signal("SIGTERM");
  let timer;
  await Promise.race([
    exited,
    new Promise((resolveTimeout) => {
      timer = setTimeout(resolveTimeout, STOP_TIMEOUT_MS);
    }),
  ]);
  clearTimeout(timer);
  signal("SIGKILL");
  child.stdout?.destroy();
  child.stderr?.destroy();
}

async function main() {
  const { wasmDir, candidateDir, report, detectorProfile, pii: piiMode } = parseArguments(process.argv.slice(2));
  const packageEntry = join(JS_PACKAGE_DIR, "dist", detectorProfile === "common" ? "common.js" : "index.js");
  assert(
    candidateDir || existsSync(packageEntry),
    `${packageEntry}: missing; build the package with \`npm run js:build\``,
  );

  const lock = JSON.parse(await readFile(join(REPO_ROOT_PATH, "package-lock.json"), "utf8"));
  const wrangler = JSON.parse(await readFile(resolve(WRANGLER_BIN, "../../package.json"), "utf8"));
  assert(wrangler.version === lock.packages["node_modules/wrangler"].version, "Wrangler differs from lockfile");
  const workerd = JSON.parse(await readFile(resolve(WRANGLER_BIN, "../../../workerd/package.json"), "utf8"));
  assert(workerd.version === lock.packages["node_modules/workerd"].version, "workerd differs from lockfile");
  const fixtureId = detectorProfile === "common" ? COMMON_REDACT_FIXTURE_ID : CANONICAL_FIXTURE_ID;
  const expectedVersion = await packageVersion();
  // With `--pii`, a synthetic phone fixture replaces the canonical one: its
  // one expected finding comes from the PII runtime only the `pii` build
  // links, so a worker that instantiated the default build fails here.
  let fixture = await loadCanonicalFixture(fixtureId);
  let pii;
  if (piiMode) {
    const phone = JSON.parse(
      await readFile(join(REPO_ROOT_PATH, "conformance", "fixtures", "pii-phone-v1.json"), "utf8"),
    );
    const positive = phone.cases.find(({ id }) => id === "phone-sensitive-national-hyphen-exact-selector");
    assert(positive !== undefined, "pii-phone-v1.json: representative positive is missing");
    fixture = positive;
    pii = { selector: phone.selector, family: phone.family };
  }
  const label = piiMode ? `${detectorProfile}, pii` : detectorProfile;

  assert(!report || candidateDir, "a durable report requires packed candidate artifacts");
  const link = candidateDir ? undefined : await linkWasmPackage(wasmDir);
  let directory;
  try {
    const staged = await stageWorkerProject(detectorProfile, fixture, expectedVersion, pii, candidateDir);
    directory = staged.directory;
    const port = 8700 + Math.floor(Math.random() * 300);
    const child = await startWrangler(directory, port);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
      const body = await response.json();
      for (const entry of body.checks ?? []) {
        console.log(`${entry.ok ? "ok" : "not ok"} - workerd (${label}) · ${entry.name}`);
        if (!entry.ok) console.error(`    ${entry.detail}`);
      }
      assert(body.ok === true, `workerd qualification (${label}) reported failures`);
      if (piiMode) {
        assert(body.findings.length === 1, `expected exactly one PII finding, got ${body.findings.length}`);
        assert(body.findings[0].detector === "pii-domain", "the PII finding came from another detector");
      } else if (detectorProfile !== "common") {
        // The `common` registry resolves this fixture to a different action;
        // only the `full` profile's finding shape is asserted exactly.
        assert(body.findings.length === 1, `expected exactly one finding, got ${body.findings.length}`);
        assertMatchesFixture(body.findings[0], fixture);
      }
      if (report) {
        assert(
          body.artifactSourceRevision === null || body.artifactSourceRevision === sourceCommit(),
          "loaded artifact source revision differs",
        );
        const binary = `redact_secret_wasm${detectorProfile === "common" ? "_common" : ""}${piiMode ? "_pii" : ""}_bg.wasm`;
        const digest = staged.packages.get("@redact-secret/wasm").contents.get(binary);
        const wasmBytes = await readFile(join(directory, "node_modules/@redact-secret/wasm", binary));
        assert(digest, "candidate has no selected WASM binary");
        let bundle;
        const bundleDir = join(directory, "deployment-bundle");
        try {
          execFileSync(process.execPath, [WRANGLER_BIN, "deploy", "--dry-run", "--outdir", bundleDir], {
            cwd: directory,
            env: cleanEnvironment({ WRANGLER_SEND_METRICS: "false" }),
            timeout: 30000,
            stdio: "pipe",
          });
          const modules = [];
          for (const [file, moduleSha256] of await fileDigests(bundleDir)) {
            if (!/\.(?:m?js|wasm)$/.test(file)) continue;
            const bytes = await readFile(join(bundleDir, file));
            modules.push({ file, sha256: moduleSha256, bytes: bytes.length, gzipBytes: gzipSync(bytes).length });
          }
          assert(
            modules.some(({ file }) => file.endsWith(".wasm")),
            "dry-run bundle has no WASM module",
          );
          bundle = {
            status: "measured",
            kind: "Wrangler deploy --dry-run qualification worker JS/WASM modules, including smoke checks; sum of independent per-module gzip, no transport overhead",
            modules,
            bytes: modules.reduce((sum, module) => sum + module.bytes, 0),
            gzipBytes: modules.reduce((sum, module) => sum + module.gzipBytes, 0),
          };
        } catch {
          bundle = {
            status: "unavailable",
            reason: "Wrangler offline deployment dry-run did not produce qualified bundle modules",
          };
        }
        await mkdir(resolve(report, ".."), { recursive: true });
        await writeFile(
          report,
          `${JSON.stringify(
            {
              schemaVersion: 1,
              sourceCommit: sourceCommit(),
              artifactSourceRevision: body.artifactSourceRevision,
              productVersion: expectedVersion,
              published: false,
              runtime: {
                name: "cloudflare-workers",
                engine: "workerd",
                wranglerVersion: wrangler.version,
                workerdVersion: lock.packages["node_modules/workerd"].version,
                compatibilityDate: COMPATIBILITY_DATE,
              },
              detectorProfile,
              pii: piiMode,
              status: "qualified",
              checks: body.checks.map(({ name, ok }) => ({ name, ok })),
              fixture: {
                id: piiMode ? "phone-sensitive-national-hyphen-exact-selector" : fixtureId,
                path: `conformance/fixtures/${piiMode ? "pii-phone-v1.json" : "synchronous-corpus.json"}`,
                sha256: sha256(
                  await readFile(
                    join(
                      REPO_ROOT_PATH,
                      "conformance/fixtures",
                      piiMode ? "pii-phone-v1.json" : "synchronous-corpus.json",
                    ),
                  ),
                ),
              },
              packageArtifacts: [...staged.packages].map(([name, pkg]) => ({
                name,
                version: pkg.manifest.version,
                file: pkg.file,
                sha256: pkg.sha256,
                packedBytes: pkg.bytes.length,
              })),
              binaries: [{ package: "@redact-secret/wasm", file: binary, sha256: digest }],
              measurements: {
                ...body.measurements,
                wasmBytes: wasmBytes.length,
                wasmGzipBytes: gzipSync(wasmBytes).length,
                timingKind:
                  "first worker initialization and 21 warm batches of 100 scanAndRedact calls; per-call samples divide batch by 100; excludes bundler and process startup",
                clock: "performance.now wall clock; quantized zero samples are below clock resolution, not zero cost",
                bundle,
              },
              limits: {
                qualification: "local workerd, not an account deployment",
                maxInputCodeUnits: 1000000,
                maxBufferedCodeUnits: 16512,
                maxTokenCodeUnits: 8192,
                maxMultilineCodeUnits: 16384,
              },
            },
            null,
            2,
          )}\n`,
        );
      }
      console.log(`qualified the Cloudflare Workers runtime path (${label} profile) against a real workerd sandbox.`);
    } finally {
      await stopWrangler(child);
    }
  } finally {
    if (directory !== undefined) await rm(directory, { recursive: true, force: true });
    if (link) await rm(link, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
  });
}
