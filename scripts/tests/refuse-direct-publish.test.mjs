import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = new URL("../../", import.meta.url);
const script = fileURLToPath(new URL("scripts/refuse-direct-publish.mjs", root));
const manifest = JSON.parse(readFileSync(new URL("package.json", root), "utf8"));

test("the release script refuses, exits non-zero and points to the workflow", () => {
  const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /Nothing was published/);
  assert.match(result.stderr, /docs\/releasing\.md/);
  assert.match(result.stderr, /release\.yml/);
});

test("`npm run release` is the refusal, never a publish", () => {
  assert.equal(manifest.scripts.release, "node scripts/refuse-direct-publish.mjs");
});

test("the refusal script cannot publish: it imports nothing and spawns nothing", () => {
  const source = readFileSync(script, "utf8");
  assert.doesNotMatch(source, /^\s*import\s/m);
  assert.doesNotMatch(source, /\brequire\s*\(|\bimport\s*\(/);
  for (const forbidden of [
    "child_process",
    "node:fs",
    "node:http",
    "fetch(",
    "execFile",
    "spawn(",
    "NODE_AUTH_TOKEN",
  ]) {
    assert.ok(!source.includes(forbidden), forbidden);
  }
});

test("no package script publishes to a registry outside the workflows", () => {
  for (const [name, command] of Object.entries(manifest.scripts)) {
    assert.doesNotMatch(command, /\b(npm|pnpm|yarn)\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b/, name);
  }
});

test("only the workflow-run dependency publisher invokes `npm publish` under scripts/", () => {
  const directory = new URL("scripts/", root);
  const publishers = readdirSync(directory)
    .filter((name) => /\.(mjs|js|py|sh)$/.test(name))
    .filter((name) =>
      /\[\s*(?:[A-Za-z_"'.]+\s*,\s*)?["']publish["']|twine\s+upload|["']upload["']/.test(
        readFileSync(new URL(name, directory), "utf8"),
      ),
    )
    .sort();
  // The one script that publishes is run by release.yml and reconcile-release.yml
  // (a dry run in the rehearsal); a script that invokes a registry publish as a command
  // list is a publish path. A new entry here is a new publish path and needs review.
  assert.deepEqual(publishers, ["publish-dependency-package.mjs"]);
});
