#!/usr/bin/env node
/**
 * Packs, content-checks, publishes, and verifies one runtime dependency
 * package of `@redact-secret/core` -- a native platform package under
 * `bindings/node/npm/<platform>` or the WebAssembly package under
 * `bindings/wasm/npm` -- at its declared, immutable version. Issue #141
 * requires every such package to clear this gate before the public wrapper
 * becomes eligible to publish; `.github/workflows/release.yml` wires that
 * ordering through `needs:`, not through anything in this script.
 *
 * `npm run rust:check` (`scripts/check-rust-workspace.py`) already holds
 * every dependency package's `version` and `engines.node` in lockstep with
 * `packages/javascript`, and `npm run artifacts:check`
 * (`scripts/check-artifact-matrix.py`) already holds its `name`/`os`/`cpu`
 * declarations in lockstep with the platform matrix. Both run inside the
 * `ci` gate this workflow requires before this script runs, so this script
 * does not re-derive those facts -- it packs the tree those checks already
 * approved and verifies the one thing they cannot: that the artifact this
 * revision qualified was actually assembled into the package directory, and
 * that the registry agrees with what is about to be published.
 *
 * This is idempotent by registry state rather than by a first-cutover vs.
 * routine-release switch: a declared version already on the registry with
 * matching content is treated as already satisfied (skip, not republish --
 * npm versions are immutable); a declared version already on the registry
 * with *different* content is a conflict this script fails on with a
 * diagnostic naming both shasums, rather than letting `npm publish` reject it
 * with a less specific error. So the exact same invocation handles the first
 * cutover (nothing published yet) and every routine release after it
 * (already published, verified, skipped) without a separate mode -- issue
 * #141's "cannot accidentally publish only the wrapper" requirement, because
 * there is only ever one path, and the wrapper's own publish job structurally
 * depends on it succeeding.
 *
 * Usage:
 *   node scripts/publish-dependency-package.mjs --package-dir <dir> [--tag <tag>] [--dry-run]
 *
 * `--dry-run` packs and content-checks, reports what would happen against
 * the current registry state, and publishes nothing -- the no-publication
 * rehearsal `package-release-rehearsal.yml` runs.
 */

import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { describePublication, viewPublished, waitForPublished } from "./npm-registry-metadata.mjs";

const NPM = process.platform === "win32" ? "npm.cmd" : "npm";

function parseArgs(argv) {
  const options = { packageDir: undefined, tag: "latest", dryRun: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--package-dir") {
      options.packageDir = argv[(index += 1)];
    } else if (argument === "--tag") {
      options.tag = argv[(index += 1)];
    } else if (argument === "--dry-run") {
      options.dryRun = true;
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  if (!options.packageDir) {
    throw new Error(
      "usage: publish-dependency-package.mjs --package-dir <dir> [--tag <tag>] [--dry-run]",
    );
  }
  options.packageDir = resolve(options.packageDir);
  return options;
}

function readManifest(dir) {
  const path = join(dir, "package.json");
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Error(`${path}: missing -- has the artifact for this package been assembled?`);
  }
  return JSON.parse(text);
}

function npmPackJson(dir) {
  const output = execFileSync(NPM, ["pack", "--json"], { cwd: dir, encoding: "utf8" });
  const [result] = JSON.parse(output);
  if (!result) throw new Error(`npm pack produced no result in ${dir}`);
  return result;
}

/**
 * The tarball must contain everything the manifest declares in `files` --
 * nothing declared can be silently dropped -- and, for these dependency
 * packages, its own `main` entry point: that is the compiled native addon or
 * the wasm-bindgen build this qualified revision produced, and its absence
 * means the assembly step before this script ran did not actually copy the
 * qualified artifact in, i.e. issue #141's "missing dependency package" case.
 */
function checkPackedContents(manifest, packResult) {
  const packedPaths = new Set(packResult.files.map((entry) => entry.path));
  const declared = manifest.files ?? [];
  const missingDeclared = declared.filter((path) => !packedPaths.has(path));
  if (missingDeclared.length > 0) {
    throw new Error(
      `${manifest.name}: packed tarball is missing declared "files" entries: ${missingDeclared.join(", ")}`,
    );
  }
  if (manifest.main && !packedPaths.has(manifest.main)) {
    throw new Error(
      `${manifest.name}: packed tarball does not contain its own "main" (${manifest.main}) -- ` +
        "the qualified artifact was not assembled into this package directory",
    );
  }
}

async function main() {
  const { packageDir, tag, dryRun } = parseArgs(process.argv.slice(2));
  const manifest = readManifest(packageDir);
  const { name, version } = manifest;
  if (!name || !version) {
    throw new Error(`${join(packageDir, "package.json")}: missing "name" or "version"`);
  }

  const packResult = npmPackJson(packageDir);
  const tarball = join(packageDir, packResult.filename);
  try {
    checkPackedContents(manifest, packResult);

    const published = await viewPublished(name, version);
    if (published !== undefined) {
      if (published.dist.shasum !== packResult.shasum) {
        throw new Error(
          `${name}@${version} is already published with different content than this revision ` +
            `would produce (published shasum ${published.dist.shasum}, this revision's shasum ` +
            `${packResult.shasum}). Versions are immutable: this is a conflicting publish, not ` +
            "a re-publish -- bump the version to ship new content.",
        );
      }
      console.log(
        `${name}@${version} is already published and matches this revision's content ` +
          `(shasum ${packResult.shasum}); nothing to publish.`,
      );
      return;
    }

    if (dryRun) {
      console.log(
        `${name}@${version} is not yet published; dry run would publish ` +
          `${packResult.filename} (shasum ${packResult.shasum}, tag ${tag}).`,
      );
      return;
    }

    execFileSync(NPM, ["publish", "--access", "public", "--tag", tag, tarball], {
      stdio: "inherit",
    });
    // `npm publish` exited 0 for exactly this tarball, so npm has accepted
    // this shasum: a registry still serving 404 after the window is
    // propagation lag, not a failure (issue #614). A visible, different
    // checksum still fails.
    const verified = await waitForPublished(name, version, {
      expectedShasum: packResult.shasum,
      publishAccepted: true,
    });
    console.log(describePublication(name, version, verified));
  } finally {
    rmSync(tarball, { force: true });
  }
}

await main();
