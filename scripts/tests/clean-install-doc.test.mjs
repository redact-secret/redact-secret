import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  LANES,
  SYNTHETIC_INPUT,
  parseQuickstart,
  requirePinnedVersion,
  scenarioCommands,
  versionSpellings,
} from "../clean-install-doc.mjs";

const root = new URL("../../", import.meta.url);
const read = async (path) => readFile(new URL(path, root), "utf8");
const quickstart = await read("docs/quickstart.md");
const version = JSON.parse(await read("packages/javascript/package.json")).version;

const fence = (info, body) => `\`\`\`${info}\n${body}\n\`\`\`\n`;
const lane = (name, { serve = name === "browser", input = SYNTHETIC_INPUT } = {}) =>
  [
    fence(`sh qualify=${name}:setup`, "npm install @redact-secret/core@0.1.0-beta.1"),
    fence(`js qualify=${name}:file:main.js`, `scan(${JSON.stringify(input)});`),
    fence(`sh qualify=${name}:run`, "node main.js"),
    serve ? fence(`sh qualify=${name}:serve`, "npx vite preview --port 4173") : "",
    fence(`text qualify=${name}:expect`, "redact-secret 0.1.0-beta.1 loaded addon"),
  ].join("\n");
const minimal = (overrides = {}) => LANES.map((name) => overrides[name] ?? lane(name)).join("\n");

test("the published quickstart declares every lane and pins the product version", () => {
  const scenarios = parseQuickstart(quickstart);
  assert.deepEqual(Object.keys(scenarios), LANES);
  assert.deepEqual(requirePinnedVersion(scenarios, version), []);
  for (const name of LANES) {
    assert.ok(scenarioCommands(scenarios[name]).length >= 2, name);
    assert.match(scenarios[name].expect, /^API_KEY=<SECRET_1>$/m, name);
  }
  assert.equal(scenarios.node.expect.split("\n")[0], `redact-secret ${version} loaded addon`);
  assert.equal(scenarios.browser.expect.split("\n")[0], `redact-secret ${version} loaded wasm`);
});

test("the quickstart uses only the synthetic input and never installs from a path", () => {
  const scenarios = parseQuickstart(quickstart);
  for (const name of LANES) {
    for (const command of scenarioCommands(scenarios[name])) {
      assert.doesNotMatch(command, /file:|link:|\.\.\/|\/packages\/|\/bindings\//, command);
    }
    const literals = scenarios[name].files.flatMap((file) => file.content.match(/"API_KEY=[^"]*"/g) ?? []);
    assert.deepEqual([...new Set(literals)], [JSON.stringify(SYNTHETIC_INPUT)], name);
  }
});

test("CI runs the quickstart driver for every lane and the qualification guide names the same command", async () => {
  const workflow = await read(".github/workflows/artifact-qualification.yml");
  const start = workflow.indexOf("\n  clean-install:\n");
  const next = workflow.slice(start + 1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
  const job = workflow.slice(start, start + 1 + next);
  assert.deepEqual([...job.matchAll(/^ {10}- (node|python|browser)$/gm)].map((match) => match[1]), LANES);
  assert.match(job, /node scripts\/qualify-clean-install\.mjs \\\n\s+--lane "\$\{\{ matrix\.lane \}\}" \\\n\s+--candidate-dir candidate/);
  assert.match(workflow, /\n {6}- clean-install\n/);
  const guide = await read("docs/qualification.md");
  assert.match(guide, /node scripts\/qualify-clean-install\.mjs --lane <node\|python\|browser> --candidate-dir <dir>/);
});

test("a minimal three-lane page parses", () => {
  const scenarios = parseQuickstart(minimal());
  assert.deepEqual(scenarios.node.files, [{ name: "main.js", content: `scan(${JSON.stringify(SYNTHETIC_INPUT)});\n` }]);
  assert.deepEqual(scenarioCommands(scenarios.browser), [
    "npm install @redact-secret/core@0.1.0-beta.1",
    "node main.js",
    "npx vite preview --port 4173",
  ]);
});

test("a page a reader could not follow literally is rejected", () => {
  assert.throws(() => parseQuickstart(minimal({ python: "" })), /python has no setup block/);
  assert.throws(() => parseQuickstart(minimal({ node: lane("node", { serve: true }) })), /only the browser lane has a serve block/);
  assert.throws(() => parseQuickstart(minimal({ node: lane("node", { input: "API_KEY=abc" }) })), /does not redact the synthetic input/);
  assert.throws(() => parseQuickstart(minimal() + fence("sh qualify=node:run", "node other.js")), /node declares run twice/);
  assert.throws(() => parseQuickstart(minimal() + fence("sh qualify=ruby:run", "ruby x.rb")), /unknown lane ruby/);
  assert.throws(() => parseQuickstart(minimal() + fence("js qualify=node:file:../escape.js", "x")), /plain file name/);
});

test("a stale version pin or expected version is reported per lane", () => {
  const scenarios = parseQuickstart(minimal());
  assert.deepEqual(requirePinnedVersion(scenarios, "0.1.0-beta.1").filter((error) => !error.startsWith("python")), []);
  const errors = requirePinnedVersion(scenarios, "0.1.0-beta.2");
  assert.ok(errors.some((error) => error.startsWith("node: setup must install exactly @redact-secret/core@0.1.0-beta.2")));
  assert.ok(errors.some((error) => error.startsWith("python: setup must install exactly redact-secret==0.1.0b2")));
  assert.ok(errors.some((error) => error.startsWith('browser: expected output must start with "redact-secret 0.1.0-beta.2"')));
});

test("npm and PyPI version spellings", () => {
  assert.deepEqual(versionSpellings("0.1.0-beta.7"), { npm: "0.1.0-beta.7", python: "0.1.0b7" });
  assert.deepEqual(versionSpellings("1.2.3"), { npm: "1.2.3", python: "1.2.3" });
  assert.throws(() => versionSpellings("1.2.3-rc.1"), /unsupported product version/);
});
