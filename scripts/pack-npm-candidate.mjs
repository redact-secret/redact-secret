#!/usr/bin/env node
/**
 * Issue #586: packs the npm packages a release would publish for this host --
 * `@redact-secret/core`, `@redact-secret/wasm` (both detector profiles), and
 * this host's `@redact-secret/node-<platform>` -- from already-built,
 * already-qualified binaries, into one candidate directory that
 * `scripts/qualify-clean-install.mjs --candidate-dir` installs from.
 *
 * Nothing is compiled here. The addon and both WebAssembly builds are the
 * artifacts the `node-addon` and `browser` jobs of
 * `.github/workflows/artifact-qualification.yml` uploaded (the same ones
 * `release.yml` publishes and `record-artifact-inventory.py` hashes); this
 * script copies them into the package directories exactly the way
 * `release.yml`'s publish jobs do, runs `npm pack`, and restores the tree.
 *
 * Preconditions:
 * - `npm run js:build` has produced `packages/javascript/dist`.
 * - The host's addon sits in `--addon-dir` under the file name its platform
 *   package's `main` declares.
 * - `--wasm-dir` / `--wasm-common-dir` hold the `full` and `common`
 *   wasm-bindgen web builds.
 *
 * Usage: node scripts/pack-npm-candidate.mjs --addon-dir <dir> --wasm-dir <dir>
 *   --wasm-common-dir <dir> --out-dir <dir>
 */

import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO_ROOT = fileURLToPath(new URL("../", import.meta.url));
const JS_PACKAGE_ROOT = join(REPO_ROOT, "packages/javascript");
const NODE_PLATFORM_ROOT = join(REPO_ROOT, "bindings/node/npm");
const WASM_PACKAGE_ROOT = join(REPO_ROOT, "bindings/wasm/npm");
const NPM = process.platform === "win32" ? "npm.cmd" : "npm";

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) values.invalid = true;
    else values[key.slice(2)] = value;
  }
  const required = ["addon-dir", "wasm-dir", "wasm-common-dir", "out-dir"];
  if (values.invalid || required.some((key) => values[key] === undefined)) {
    throw new Error(
      "usage: pack-npm-candidate.mjs --addon-dir <dir> --wasm-dir <dir> " +
        "--wasm-common-dir <dir> --out-dir <dir>",
    );
  }
  return Object.fromEntries(required.map((key) => [key, resolve(values[key])]));
}

function npmPack(packageDir, outDir) {
  const output = execFileSync(NPM, ["pack", "--json", "--pack-destination", outDir], {
    cwd: packageDir,
    encoding: "utf8",
  });
  const [result] = JSON.parse(output);
  if (result === undefined) throw new Error(`npm pack produced no result in ${packageDir}`);
  return result.filename;
}

/** Copies `files` from `sourceDir` into `packageDir`, failing on any gap. */
async function stage(sourceDir, packageDir, files) {
  const present = new Set(await readdir(sourceDir));
  for (const file of files) {
    if (!present.has(file)) throw new Error(`${sourceDir} has no ${file}`);
    await cp(join(sourceDir, file), join(packageDir, file));
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const { resolveAddonSpecifier } = await import(
    pathToFileURL(join(JS_PACKAGE_ROOT, "dist/runtime/node.js")).href
  );
  const specifier = resolveAddonSpecifier();
  if (specifier === undefined) {
    throw new Error(`no platform package is mapped for ${process.platform}/${process.arch}`);
  }
  const platformDir = join(NODE_PLATFORM_ROOT, specifier.split("/")[1].replace("node-", ""));
  const platformManifest = JSON.parse(await readFile(join(platformDir, "package.json"), "utf8"));
  const wasmManifest = JSON.parse(await readFile(join(WASM_PACKAGE_ROOT, "package.json"), "utf8"));
  const wasmFiles = wasmManifest.files.filter((file) => file !== "package.json");
  const fullFiles = wasmFiles.filter((file) => !file.includes("_common"));
  const commonFiles = wasmFiles.filter((file) => file.includes("_common"));

  await mkdir(options["out-dir"], { recursive: true });
  const staged = [
    ...platformManifest.files.map((file) => join(platformDir, file)),
    ...wasmFiles.map((file) => join(WASM_PACKAGE_ROOT, file)),
  ];
  try {
    await stage(options["addon-dir"], platformDir, platformManifest.files);
    await stage(options["wasm-dir"], WASM_PACKAGE_ROOT, fullFiles);
    await stage(options["wasm-common-dir"], WASM_PACKAGE_ROOT, commonFiles);
    const packed = [
      npmPack(JS_PACKAGE_ROOT, options["out-dir"]),
      npmPack(WASM_PACKAGE_ROOT, options["out-dir"]),
      npmPack(platformDir, options["out-dir"]),
    ];
    console.log(`Packed npm candidate into ${options["out-dir"]}: ${packed.join(", ")}`);
  } finally {
    await Promise.all(staged.map((path) => rm(path, { force: true })));
  }
}

await main();
