import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// The fallback recipe in docs/guides/javascript.md is this file, verbatim. It
// needs a built addon or WebAssembly artifact to run, so CI cannot run it here;
// this test keeps the guide and the file that was run from drifting.
const guide = readFileSync(new URL("../../docs/guides/javascript.md", import.meta.url), "utf8");
const source = readFileSync(new URL("node-feature-detection.mjs", import.meta.url), "utf8").trimEnd();

test("the guide contains node-feature-detection.mjs verbatim", () => {
  assert.ok(guide.includes(`\`\`\`js\n${source}\n\`\`\``));
});
