import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

// The recipes in docs/guides/configuration-ownership.md are these files,
// verbatim. They need a built addon, artifact or wheel to run, so CI cannot run
// them here; this test keeps the guide and the files that were run from drifting.
// The Rust recipes are run by crates/secret-scan-core/tests/configuration_ownership_1222.rs.
const here = new URL("./", import.meta.url);
const guide = readFileSync(new URL("../../docs/guides/configuration-ownership.md", import.meta.url), "utf8");
const files = readdirSync(fileURLToPath(here)).filter(
  (name) => /\.(mjs|py)$/.test(name) && !name.endsWith(".test.mjs"),
);

test("the example set is the one the guide shows", () => {
  assert.deepEqual(files.sort(), [
    "node-policy-per-call.mjs",
    "node-singleton-conflict.mjs",
    "node-worker-tenants.mjs",
    "python_policy_per_call.py",
    "python_process_tenants.py",
    "wasm-instance-tenants.mjs",
  ]);
});

for (const name of files) {
  test(`the guide contains ${name} verbatim`, () => {
    const source = readFileSync(new URL(name, here), "utf8").trimEnd();
    assert.ok(guide.includes(`\`\`\`${name.endsWith(".py") ? "python" : "js"}\n${source}\n\`\`\``), name);
  });
}
