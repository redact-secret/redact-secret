import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  ENTRY,
  EXAMPLE_DIR,
  TOOL_PREFIX,
  TOOL_SECRET,
  USER_INPUT,
  USER_SECRET,
  importClosure,
  localImports,
  realCoreTests,
  requireSanitized,
} from "../qualify-golden-path.mjs";

const exampleRoot = fileURLToPath(new URL(`../../${EXAMPLE_DIR}/`, import.meta.url));

test("the Node closure is the golden path and the modules it imports, never tests or fakes", async () => {
  const closure = await importClosure(exampleRoot, ENTRY.node);
  const paths = [...closure.keys()].sort();
  assert.ok(paths.includes("agent-context.mjs") && paths.includes("redact-tool-call.mjs"));
  assert.ok(paths.every((path) => !path.includes(".test.") && !path.startsWith("fixtures/")));
});

test("the Python closure is the twin and the sibling modules it imports, never tests or fakes", async () => {
  const closure = await importClosure(exampleRoot, ENTRY.python);
  const paths = [...closure.keys()].sort();
  assert.ok(paths.includes("python/agent_context.py") && paths.includes("python/redact_tool_call.py"));
  assert.ok(paths.every((path) => path.startsWith("python/") && !/\/(test_|fake_)/.test(path)));
});

test("localImports follows relative ESM specifiers and sibling Python modules only", () => {
  const esm = [
    'import { a } from "./a.mjs";',
    "import {\n  b,\n  c,\n} from '../b.mjs';",
    'import "./side-effect.mjs";',
    'export { d } from "./d.mjs";',
    'import pkg from "@redact-secret/core";',
    ' * @param {import("./not-an-import.mjs").T} x',
  ].join("\n");
  assert.deepEqual(localImports("sub/entry.mjs", esm, new Set()).sort(), ["b.mjs", "sub/a.mjs", "sub/d.mjs", "sub/side-effect.mjs"]);

  const python = "from __future__ import annotations\nimport json\nfrom helper import x\nimport other\n";
  const siblings = new Set(["python/helper.py", "python/other.py"]);
  assert.deepEqual(localImports("python/entry.py", python, siblings).sort(), ["python/helper.py", "python/other.py"]);
});

test("importClosure fails closed on an import that is not in the example", async () => {
  const root = await mkdtemp(join(tmpdir(), "golden-path-closure-"));
  try {
    await mkdir(join(root, "python"));
    await writeFile(join(root, "entry.mjs"), 'import { x } from "./missing.mjs";\n');
    await assert.rejects(importClosure(root, "entry.mjs"), /missing\.mjs is imported but does not exist/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

const sanitized = () => ({
  outcome: "ok",
  stage: null,
  roles: ["user", "tool"],
  findings: 2,
  toolSawRawInput: false,
  modelFacing: JSON.stringify([
    { role: "user", content: USER_INPUT.replace(USER_SECRET, "<SECRET_1>") },
    { role: "tool", content: { content: [{ type: "text", text: `${TOOL_PREFIX} x: <SECRET_2>` }] } },
  ]),
});

test("requireSanitized accepts a sanitized two-message turn", () => {
  assert.doesNotThrow(() => requireSanitized(sanitized()));
});

test("requireSanitized rejects every way the model-facing value can be unsafe or empty", () => {
  const cases = [
    [{ outcome: "blocked", stage: "input" }, /ended blocked at the input stage/],
    [{ roles: ["user"] }, /one user and one tool message/],
    [{ toolSawRawInput: true }, /unsanitized user input/],
    [{ modelFacing: sanitized().modelFacing.replace("<SECRET_1>", USER_SECRET) }, /user-input credential/],
    [{ modelFacing: sanitized().modelFacing.replace("<SECRET_2>", TOOL_SECRET) }, /tool-result credential/],
    [{ modelFacing: sanitized().modelFacing.replaceAll(/<SECRET_\d>/g, "[x]") }, /no placeholder/],
    [{ modelFacing: '"<SECRET_1>"' }, /lost its non-secret text/],
    [{ findings: 1 }, /a finding per credential/],
  ];
  for (const [override, pattern] of cases) {
    assert.throws(() => requireSanitized({ ...sanitized(), ...override }), pattern);
  }
});

const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

test("artifact qualification runs the golden-path driver for both lanes, and the inventory requires it", async () => {
  const workflow = await read(".github/workflows/artifact-qualification.yml");
  const start = workflow.indexOf("\n  golden-path:\n");
  assert.ok(start >= 0, "no golden-path job");
  const next = workflow.slice(start + 1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
  const job = workflow.slice(start, start + 1 + next);
  assert.deepEqual([...job.matchAll(/^ {10}- (node|python)$/gm)].map((match) => match[1]), ["node", "python"]);
  assert.match(job, /needs: \[plan, node-addon, browser, python\]/);
  assert.match(job, /node scripts\/qualify-golden-path\.mjs \\\n\s+--lane "\$\{\{ matrix\.lane \}\}" \\\n\s+--candidate-dir candidate/);
  assert.match(job, /name: golden-path-\$\{\{ matrix\.lane \}\}/);
  assert.match(workflow, /\n {6}- golden-path\n/);
  assert.match(workflow, /"\$GOLDEN_PATH_RESULT"/);
});

test("the example README and the qualification guide document the same command", async () => {
  for (const path of [`${EXAMPLE_DIR}/README.md`, "docs/qualification.md"]) {
    assert.match(
      await read(path),
      /npm run golden-path:qualify -- --lane <node\|python> --candidate-dir <dir>/,
      `${path} does not document the golden-path command`,
    );
  }
  const scripts = JSON.parse(await read("package.json")).scripts;
  assert.equal(scripts["golden-path:qualify"], "node scripts/qualify-golden-path.mjs");
});

test("the Node lane runs exactly the real-core tests the documented script names", async () => {
  const scripts = JSON.parse(await read("package.json")).scripts;
  const tests = realCoreTests(scripts);
  assert.ok(tests.includes("streaming-tool-result.real-core.test.mjs"));
  const closure = await importClosure(exampleRoot, tests[0]);
  assert.ok(closure.has("agent-context.mjs") && closure.has("streaming-tool-result.mjs"));
  assert.throws(() => realCoreTests({}), /names no examples\/mcp-redact test file/);
  assert.throws(
    () => realCoreTests({ "examples:real-core:test": "node --test examples/mcp-redact/sub/x.test.mjs" }),
    /must sit in examples\/mcp-redact/,
  );
});
