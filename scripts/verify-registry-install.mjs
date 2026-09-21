#!/usr/bin/env node
/**
 * Issue #141, "registry-backed clean install" criterion: installs the real,
 * published `@redact-secret/core` from the npm registry -- no local
 * tarball, no `overrides` -- into a clean directory outside this repository,
 * and exercises initialization, scan, incremental sanitization, and the
 * runtime's stream adapter on the requested runtime.
 *
 * This runs only after `publish`, `publish-native-dependencies`, and
 * `publish-wasm-dependency` have all succeeded (`.github/workflows/release.yml`'s
 * `needs:`), so `npm install` resolves every dependency from the registry
 * exactly the way an actual consumer's install would: `optionalDependencies`
 * platform matching on the node lane, and the wasm package as an ordinary
 * dependency on both. `scripts/qualify-package-consumer.mjs` proves the same
 * contract before those packages exist, with packed local tarballs standing
 * in for the registry; this proves it once they do, against the registry
 * itself, which is the one thing a pre-publish check cannot do.
 *
 * Usage: node scripts/verify-registry-install.mjs --lane node|browser
 */

import { execFileSync } from "node:child_process";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CANONICAL_FIXTURE_ID,
  REPO_ROOT_PATH,
  loadCanonicalFixture,
  packageVersion,
} from "./qualify-runtime-fixture.mjs";
import { qualifyBrowser, qualifyNode } from "./consumer-harness.mjs";
import { waitForVisible } from "./npm-registry-metadata.mjs";

const WRAPPER_PACKAGE_NAME = "@redact-secret/core";

const INTEGRATION_FIXTURE_IDS = Object.freeze({
  redact: CANONICAL_FIXTURE_ID,
  warn: "contextual-positive-minimum-length-is-medium-confidence",
  block: "private-key-positive",
});
const INCREMENTAL_CORPUS_PATH = join(
  REPO_ROOT_PATH,
  "conformance",
  "fixtures",
  "incremental-corpus.json",
);

function parseArgs(argv) {
  const index = argv.indexOf("--lane");
  const lane = index === -1 ? undefined : argv[index + 1];
  if (lane !== "node" && lane !== "browser") {
    throw new Error("usage: verify-registry-install.mjs --lane node|browser");
  }
  return { lane };
}

/**
 * A package.json outside the repository whose only dependency is the real,
 * published wrapper at its exact version -- nothing here resolves back into
 * this checkout, and nothing overrides what the registry serves.
 */
async function buildConsumerProject(version) {
  const root = await mkdtemp(join(tmpdir(), "redact-secret-registry-consumer-"));
  const manifest = {
    name: "redact-secret-registry-install-verification",
    private: true,
    type: "module",
    dependencies: {
      [WRAPPER_PACKAGE_NAME]: version,
    },
  };
  await writeFile(join(root, "package.json"), JSON.stringify(manifest, null, 2));
  execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", [
    "install",
    "--no-audit",
    "--no-fund",
  ], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  await cp(
    join(REPO_ROOT_PATH, "examples/safe-integration"),
    join(root, "safe-integration"),
    { recursive: true },
  );
  return root;
}

async function loadIncrementalCorpus() {
  return JSON.parse(await readFile(INCREMENTAL_CORPUS_PATH, "utf8"));
}

async function main() {
  const { lane } = parseArgs(process.argv.slice(2));
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

  // `npm install` below reads the registry too, but its own error for "not
  // there yet" is indistinguishable from "never published" -- so name that
  // read explicitly here first, with the same bounded wait and the same
  // clear "still propagating" vs. "not visible" distinction every other
  // registry-state read in the release pipeline gets.
  await waitForVisible(WRAPPER_PACKAGE_NAME, expectedVersion);

  let consumerRoot;
  try {
    consumerRoot = await buildConsumerProject(expectedVersion);
    if (lane === "node") {
      qualifyNode(
        consumerRoot,
        fixture,
        expectedVersion,
        integrationFixtures,
        incrementalCorpus,
      );
    } else {
      await qualifyBrowser(
        consumerRoot,
        fixture,
        expectedVersion,
        "chromium",
        integrationFixtures,
        incrementalCorpus,
      );
    }
  } finally {
    if (consumerRoot) await rm(consumerRoot, { recursive: true, force: true });
  }

  console.log(
    `Registry install verification passed (${lane} lane, fixture ${fixture.id}, ` +
      `version ${expectedVersion}): the published package installed from the ` +
      "registry into a clean directory and initialized.",
  );
}

await main();
