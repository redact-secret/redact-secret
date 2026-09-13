#!/usr/bin/env node
/**
 * Qualifies `packages/javascript` as an actual npm consumer would install
 * it: packs it and its native/WebAssembly dependencies into tarballs, installs
 * the packed `@redact-secret/core` tarball into a clean directory outside
 * the repository (nothing under it resolves back into this checkout), and
 * exercises the installed public scan, incremental, and stream APIs on the
 * requested Node or browser runtime.
 *
 * `optionalDependencies`/`dependencies` in `packages/javascript/package.json`
 * name registry versions of `@redact-secret/node-<platform>` and
 * `@redact-secret/wasm` (issue #79) that are not published yet
 * (RB-2, issue #72, is what starts publishing `packages/javascript` at
 * all). This script substitutes local tarballs for exactly those two
 * dependency kinds via npm's `overrides`, which is the standard way to
 * exercise a real install shape without a real registry; everything else
 * about the install — `optionalDependencies` resolution, `os`/`cpu`/`libc`
 * matching, the resulting `node_modules` layout — is the real npm installer,
 * not a simulation of it.
 *
 * Preconditions (the same artifacts `qualify-node-addon.mjs` and
 * `qualify-browser-artifact.mjs` require):
 * - `napi build --platform --release` has produced this host's addon in
 *   `bindings/node`.
 * - `wasm-bindgen --target web --out-name redact_secret_wasm` has produced the
 *   browser build in some directory (`--wasm-dir`).
 * - `npm run js:build` has produced `packages/javascript/dist`.
 * - The requested Playwright engine is installed for the browser lane.
 *
 * Usage: node scripts/qualify-package-consumer.mjs --lane node|browser
 *   --wasm-dir <dir> [--engine chromium|firefox|webkit] --report <path>
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  CANONICAL_FIXTURE_ID,
  REPO_ROOT_PATH,
  loadCanonicalFixture,
  packageVersion,
} from "./qualify-runtime-fixture.mjs";
import { WASM_SPECIFIER, qualifyBrowser, qualifyNode } from "./consumer-harness.mjs";

const JS_PACKAGE_ROOT = join(REPO_ROOT_PATH, "packages/javascript");
const NODE_PLATFORM_ROOT = join(REPO_ROOT_PATH, "bindings/node");
const WASM_PACKAGE_ROOT = join(REPO_ROOT_PATH, "bindings/wasm/npm");
const SAFE_INTEGRATION_ROOT = join(REPO_ROOT_PATH, "examples/safe-integration");
const INCREMENTAL_CORPUS_PATH = join(
  REPO_ROOT_PATH,
  "conformance",
  "fixtures",
  "incremental-corpus.json",
);
const INTEGRATION_FIXTURE_IDS = Object.freeze({
  redact: CANONICAL_FIXTURE_ID,
  warn: "contextual-positive-minimum-length-is-medium-confidence",
  block: "private-key-positive",
});

function parseArgs(argv) {
  function value(name) {
    const index = argv.indexOf(name);
    return index === -1 ? undefined : argv[index + 1];
  }
  const lane = value("--lane");
  const wasmDir = value("--wasm-dir");
  const report = value("--report");
  const engine = value("--engine");
  if (
    (lane !== "node" && lane !== "browser") ||
    wasmDir === undefined ||
    report === undefined ||
    (lane === "browser" && engine === undefined)
  ) {
    throw new Error(
      "usage: qualify-package-consumer.mjs --lane node|browser " +
        "--wasm-dir <dir> [--engine chromium|firefox|webkit] --report <path>",
    );
  }
  return { lane, wasmDir, report, engine };
}

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function loadIncrementalCorpus() {
  const bytes = await readFile(INCREMENTAL_CORPUS_PATH);
  const corpus = JSON.parse(bytes.toString("utf8"));
  return {
    path: "conformance/fixtures/incremental-corpus.json",
    sha256: createHash("sha256").update(bytes).digest("hex"),
    offsetUnit: corpus.offsetUnit,
    fixtureCount: corpus.fixtures.length,
    corpus,
  };
}

function sourceCommit() {
  if (process.env.SOURCE_COMMIT?.trim()) return process.env.SOURCE_COMMIT.trim();
  return execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: REPO_ROOT_PATH,
    encoding: "utf8",
  }).trim();
}

function npmPack(cwd) {
  const output = execFileSync(
    process.platform === "win32" ? "npm.cmd" : "npm",
    ["pack", "--json"],
    { cwd, encoding: "utf8" },
  );
  const [result] = JSON.parse(output);
  if (result === undefined) throw new Error(`npm pack produced no result in ${cwd}`);
  return join(cwd, result.filename);
}

/** This host's platform package directory, with the built addon copied in. */
async function assembleNodePlatformPackage() {
  const { resolveAddonSpecifier } = await import(
    pathToFileURL(join(JS_PACKAGE_ROOT, "dist/runtime/node.js")).href
  );
  const specifier = resolveAddonSpecifier();
  if (specifier === undefined) {
    throw new Error(
      `no platform package is mapped for ${process.platform}/${process.arch}`,
    );
  }
  const suffix = specifier.split("/")[1].replace("node-", "");
  const dir = join(NODE_PLATFORM_ROOT, "npm", suffix);
  const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
  await cp(
    join(NODE_PLATFORM_ROOT, manifest.main),
    join(dir, manifest.main),
  );
  return { specifier, dir };
}

/** The wasm package directory, with the wasm-bindgen web build copied in. */
async function assembleWasmPackage(wasmDir) {
  await cp(wasmDir, WASM_PACKAGE_ROOT, { recursive: true });
  return WASM_PACKAGE_ROOT;
}

/**
 * A package.json outside the repository whose only path back into it is
 * three absolute `file:` tarball references, resolved once by `npm install`
 * and never again.
 */
async function buildConsumerProject(tarballs) {
  const root = await mkdtemp(join(tmpdir(), "redact-secret-consumer-"));
  const manifest = {
    name: "redact-secret-consumer-qualification",
    private: true,
    type: "module",
    dependencies: {
      "@redact-secret/core": `file:${tarballs.js}`,
    },
    overrides: {
      [WASM_SPECIFIER]: `file:${tarballs.wasm}`,
      [tarballs.nodeSpecifier]: `file:${tarballs.node}`,
    },
  };
  await writeFile(join(root, "package.json"), JSON.stringify(manifest, null, 2));
  execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", [
    "install",
    "--no-audit",
    "--no-fund",
  ], { cwd: root, stdio: "inherit" });
  await cp(SAFE_INTEGRATION_ROOT, join(root, "safe-integration"), {
    recursive: true,
  });
  return root;
}

async function main() {
  const { lane, wasmDir, report, engine } = parseArgs(process.argv.slice(2));
  const fixture = await loadCanonicalFixture(CANONICAL_FIXTURE_ID);
  const integrationFixtures = Object.fromEntries(
    await Promise.all(
      Object.entries(INTEGRATION_FIXTURE_IDS).map(async ([kind, id]) => [
        kind,
        await loadCanonicalFixture(id),
      ]),
    ),
  );
  const expectedVersion = await packageVersion();
  const incrementalCorpus = await loadIncrementalCorpus();

  const { specifier: nodeSpecifier, dir: nodePlatformDir } =
    await assembleNodePlatformPackage();
  const wasmPackageDir = await assembleWasmPackage(wasmDir);

  const tarballs = {
    js: npmPack(JS_PACKAGE_ROOT),
    node: npmPack(nodePlatformDir),
    wasm: npmPack(wasmPackageDir),
    nodeSpecifier,
  };

  let consumerRoot;
  try {
    consumerRoot = await buildConsumerProject(tarballs);
    const results =
      lane === "node"
        ? qualifyNode(
            consumerRoot,
            fixture,
            expectedVersion,
            integrationFixtures,
            incrementalCorpus.corpus,
          )
        : await qualifyBrowser(
            consumerRoot,
            fixture,
            expectedVersion,
            engine,
            integrationFixtures,
            incrementalCorpus.corpus,
          );
    const packageArtifacts = await Promise.all(
      [
        ["@redact-secret/core", tarballs.js],
        [nodeSpecifier, tarballs.node],
        [WASM_SPECIFIER, tarballs.wasm],
      ].map(async ([name, path]) => ({
        name,
        version: expectedVersion,
        file: path.split(/[\\/]/).at(-1),
        sha256: await sha256(path),
      })),
    );
    await writeFile(
      report,
      `${JSON.stringify(
        {
          schemaVersion: 1,
          sourceCommit: sourceCommit(),
          published: false,
          lane,
          runtime:
            lane === "node"
              ? { name: "node", version: process.version }
              : { name: engine, version: results.engineVersion },
          productVersion: expectedVersion,
          fixture: fixture.id,
          integrationFixtures: Object.fromEntries(
            Object.entries(integrationFixtures).map(([kind, entry]) => [kind, entry.id]),
          ),
          incrementalCorpus: {
            path: incrementalCorpus.path,
            sha256: incrementalCorpus.sha256,
            offsetUnit: incrementalCorpus.offsetUnit,
            fixtureCount: incrementalCorpus.fixtureCount,
          },
          packageArtifacts,
          commands: [
            "npm install --no-audit --no-fund",
            `node scripts/qualify-package-consumer.mjs --lane ${lane}` +
              (engine ? ` --engine ${engine}` : "") +
              " --wasm-dir <candidate-wasm-dir> --report <evidence-path>",
          ],
          operations:
            lane === "node"
              ? [
                  "initialize",
                  "scan",
                  "createIncrementalSanitizer",
                  "createNodeStreamSanitizer",
                  "safeIntegration",
                ]
              : [
                  "initialize",
                  "scan",
                  "createIncrementalSanitizer",
                  "createWebStreamSanitizer",
                  "safeIntegration",
                ],
          results,
        },
        null,
        2,
      )}\n`,
    );
  } finally {
    await rm(tarballs.js, { force: true });
    await rm(tarballs.node, { force: true });
    await rm(tarballs.wasm, { force: true });
    await mkdir(nodePlatformDir, { recursive: true });
    await rm(join(nodePlatformDir, JSON.parse(await readFile(join(nodePlatformDir, "package.json"), "utf8")).main), { force: true });
    await rm(join(wasmPackageDir, "redact_secret_wasm.js"), { force: true });
    await rm(join(wasmPackageDir, "redact_secret_wasm.d.ts"), { force: true });
    await rm(join(wasmPackageDir, "redact_secret_wasm_bg.wasm"), { force: true });
    await rm(join(wasmPackageDir, "redact_secret_wasm_bg.wasm.d.ts"), { force: true });
    if (consumerRoot) await rm(consumerRoot, { recursive: true, force: true });
  }

  console.log(
    `Package consumer qualification passed (${lane}${engine ? `/${engine}` : ""}, ` +
      `fixture ${fixture.id}, version ${expectedVersion}): the packed package was ` +
      "installed into a clean directory and its public scan, incremental, and stream APIs passed.",
  );
}

await main();
