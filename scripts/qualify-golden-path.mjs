#!/usr/bin/env node
/**
 * Issue #720: runs the MCP AI-context golden path (`examples/mcp-redact`,
 * issue #587) end to end against an *installed* release candidate, and
 * asserts that the value it would hand a model is sanitized.
 *
 * The example's own tests inject a fake core. This driver is the other half:
 * the real engine, installed the way an outside consumer installs it.
 *
 * - `--lane node` copies `agent-context.mjs` and every module it imports
 *   (followed from the file, not listed here) into an empty directory outside
 *   the checkout, and installs `@redact-secret/core` plus the example's
 *   pinned adapter packages from a local registry that serves only the
 *   candidate tarballs (`scripts/pack-npm-candidate.mjs`) and the pinned
 *   adapter tarballs (`adapters/pin-source.json`, verified against their
 *   content digests). Nothing comes from a public registry.
 *   `createGoldenPathBoundary()` then loads that installed core.
 * - `--lane python` does the same for the Python twin
 *   (`python/agent_context.py` and its imports), installing the candidate
 *   wheel into a fresh virtual environment with `PIP_NO_INDEX` and
 *   `PIP_FIND_LINKS`, and passes the installed `redact_secret.scan_and_redact`
 *   to `build_safe_context`.
 *
 * One turn carries a synthetic credential in the user input and another in
 * the tool result. The lane passes only if the turn is `ok`, the tool was
 * dispatched from already-sanitized input, and the serialized model-facing
 * value contains neither credential but does contain a placeholder and the
 * surrounding non-secret text. The installed packages are verified byte for
 * byte against the candidate files, and every `.node`, `.wasm`, and `.whl`
 * they carried is reported by SHA-256, so the `inventory` job of
 * `.github/workflows/artifact-qualification.yml` can require each to be an
 * artifact that same run recorded.
 *
 * The report records outcomes, versions, digests, and the example files'
 * digests -- never the model-facing value or any command output.
 *
 * Usage: node scripts/qualify-golden-path.mjs --lane node|python
 *   --candidate-dir <dir> [--report <path>]
 */

import { readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, join, posix, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { versionSpellings } from "./clean-install-doc.mjs";
import {
  REPO_ROOT,
  cleanEnvironment,
  freshWorkspace,
  loadNpmCandidate,
  loadNpmTarballs,
  makeAssert,
  runShell,
  sha256,
  sourceCommit,
  startCandidateRegistry,
  verifyNpmInstall,
  wheelProbeSource,
} from "./lib/candidate-install.mjs";

const LABEL = "golden path";
const assert = makeAssert(LABEL);
export const LANES = ["node", "python"];
export const EXAMPLE_DIR = "examples/mcp-redact";
export const ENTRY = { node: "agent-context.mjs", python: "python/agent_context.py" };
const PIN_SOURCE = "adapters/pin-source.json";

// Synthetic values already used elsewhere in this repository: the
// quickstart's revoked-context value and the AWS detector tests' example key
// ID. Neither is a real credential.
export const USER_SECRET = "SYNTHETIC_REVOKED_CONTEXT_VALUE";
export const TOOL_SECRET = "AKIASYNTHETICEXAMPLE";
export const USER_INPUT = `look up the owner of API_KEY=${USER_SECRET} please`;
export const TOOL_PREFIX = "looked up";

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const [key, value] = [argv[index], argv[index + 1]];
    if (value === undefined) throw new Error(`missing value for ${key}`);
    if (key === "--lane") options.lane = value;
    else if (key === "--candidate-dir") options.candidateDir = resolve(value);
    else if (key === "--report") options.report = resolve(value);
    else throw new Error(`unknown argument ${key}`);
  }
  if (!LANES.includes(options.lane) || options.candidateDir === undefined) {
    throw new Error("usage: qualify-golden-path.mjs --lane node|python --candidate-dir <dir> [--report <path>]");
  }
  return options;
}

/**
 * The local modules `source` (at `path`, relative to the example directory)
 * imports: relative ESM specifiers, or Python modules that exist as a
 * sibling `.py` file. Anything else is a package the install must provide.
 */
export function localImports(path, source, siblings) {
  if (path.endsWith(".mjs")) {
    const specifiers = [...source.matchAll(/^\s*(?:import|export)\s[^;]*?from\s+["'](\.{1,2}\/[^"']+)["']/gm)].map(
      (match) => match[1],
    );
    specifiers.push(...[...source.matchAll(/^\s*import\s+["'](\.{1,2}\/[^"']+)["']/gm)].map((match) => match[1]));
    return specifiers.map((specifier) => posix.normalize(posix.join(posix.dirname(path), specifier)));
  }
  const modules = [...source.matchAll(/^\s*(?:from\s+([A-Za-z_]\w*)\s+import|import\s+([A-Za-z_]\w*))/gm)].map(
    (match) => match[1] ?? match[2],
  );
  return modules
    .map((module) => posix.join(posix.dirname(path), `${module}.py`))
    .filter((candidate) => siblings.has(candidate));
}

/** `entry` and every example module it transitively imports, each with its bytes. */
export async function importClosure(exampleRoot, entry) {
  const siblings = new Set();
  for (const dir of ["", "python"]) {
    for (const name of await readdir(join(exampleRoot, dir))) siblings.add(posix.join(dir, name));
  }
  const files = new Map();
  const pending = [entry];
  while (pending.length > 0) {
    const path = pending.pop();
    if (files.has(path)) continue;
    assert(!path.startsWith("..") && siblings.has(path), `${EXAMPLE_DIR}/${path} is imported but does not exist`);
    const bytes = await readFile(join(exampleRoot, path));
    files.set(path, bytes);
    pending.push(...localImports(path, bytes.toString("utf8"), siblings));
  }
  return files;
}

/** Writes the closure into `project`, flattened to the entry's directory. */
async function copyClosure(project, closure, entry) {
  const base = posix.dirname(entry);
  const copied = [];
  for (const [path, bytes] of [...closure].sort()) {
    const target = posix.relative(base, path);
    assert(!target.startsWith(".."), `${path} is outside ${base}`);
    await writeFile(join(project, target), bytes);
    copied.push({ path: `${EXAMPLE_DIR}/${path}`, sha256: sha256(bytes) });
  }
  return copied;
}

/**
 * The content digest `scripts/adapter-pins.py` pins: SHA-256 over the sorted
 * `path NUL sha256 LF` lines of the tarball's regular files.
 */
function contentDigest(contents) {
  const lines = [...contents].map(([file, digest]) => `package/${file}\0${digest}\n`).sort();
  return `sha256:${sha256(Buffer.from(lines.join(""), "utf8"))}`;
}

/**
 * The example's pinned adapter tarballs, loaded from the paths its
 * `package.json` names (which `npm run adapter-pins:check` requires to be
 * exactly the pinned ones) and each verified against the pin's digest.
 */
async function loadPinnedAdapters(scratch) {
  const pin = JSON.parse(await readFile(join(REPO_ROOT, PIN_SOURCE), "utf8"));
  const manifest = JSON.parse(await readFile(join(REPO_ROOT, EXAMPLE_DIR, "package.json"), "utf8"));
  const dependencies = Object.entries(manifest.dependencies ?? {});
  const paths = dependencies.map(([name, spec]) => {
    assert(String(spec).startsWith("file:"), `${EXAMPLE_DIR} depends on ${name} from outside the pin`);
    return resolve(REPO_ROOT, EXAMPLE_DIR, spec.slice("file:".length));
  });
  let tarballs;
  try {
    tarballs = await loadNpmTarballs(paths, scratch, LABEL);
  } catch (error) {
    throw new Error(`${LABEL}: the pinned adapter tarballs are missing; run \`npm run adapter-pins:install\``, {
      cause: error,
    });
  }
  const pinned = new Map(pin.packages.map((entry) => [entry.name, entry]));
  for (const [name, entry] of tarballs) {
    const record = pinned.get(name);
    assert(record !== undefined, `${name} is not pinned in ${PIN_SOURCE}`);
    assert(entry.manifest.version === record.version, `${name} is not the pinned ${record.version}`);
    assert(contentDigest(entry.contents) === record.contentDigest, `${name} does not match its pinned content digest`);
  }
  return {
    tarballs,
    dependencies: Object.fromEntries([...tarballs].map(([name, entry]) => [name, entry.manifest.version])),
    record: {
      repository: pin.repository,
      commit: pin.commit,
      packages: [...tarballs.keys()].sort().map((name) => {
        const { version, contentDigest: digest } = pinned.get(name);
        return { name, version, contentDigest: digest };
      }),
    },
  };
}

/** The checks every lane makes on what the driver printed. */
export function requireSanitized(printed) {
  assert(printed.outcome === "ok", `the turn ended ${printed.outcome}${printed.stage ? ` at the ${printed.stage} stage` : ""}`);
  assert(JSON.stringify(printed.roles) === JSON.stringify(["user", "tool"]), "the safe context is not one user and one tool message");
  assert(printed.toolSawRawInput === false, "the tool was dispatched with unsanitized user input");
  const value = printed.modelFacing;
  assert(typeof value === "string" && value.length > 0, "the driver reported no model-facing value");
  assert(!value.includes(USER_SECRET), "the model-facing value carries the user-input credential");
  assert(!value.includes(TOOL_SECRET), "the model-facing value carries the tool-result credential");
  assert(value.includes("<SECRET_"), "the model-facing value carries no placeholder");
  assert(value.includes("look up the owner of") && value.includes(TOOL_PREFIX), "the model-facing value lost its non-secret text");
  assert(Number.isInteger(printed.findings) && printed.findings >= 2, `expected a finding per credential, got ${printed.findings}`);
}

async function runDriver(command, project, env) {
  const result = await runShell(command, project, env);
  // The printed value is sanitized by the time it is printed, or the lane
  // fails; neither case writes it anywhere but this process's memory.
  assert(result.code === 0, `the golden-path driver exited ${result.code}`);
  const printed = JSON.parse(result.stdout.trim().split("\n").at(-1));
  return printed;
}

const nodeDriver = () => `import { artifact } from "@redact-secret/core";
import { buildSafeContext, createGoldenPathBoundary } from "./agent-context.mjs";

const USER_SECRET = ${JSON.stringify(USER_SECRET)};
const boundary = await createGoldenPathBoundary();
let toolSawRawInput;
const result = await buildSafeContext({
  boundary,
  userInput: ${JSON.stringify(USER_INPUT)},
  buildToolRequest: (safeText) => ({ name: "lookup", query: safeText }),
  callTool: async (request) => {
    toolSawRawInput = JSON.stringify(request).includes(USER_SECRET);
    return { content: [{ type: "text", text: \`${TOOL_PREFIX} \${request.query}: leaked AWS_ACCESS_KEY_ID=${TOOL_SECRET}\` }] };
  },
});
console.log(JSON.stringify({
  outcome: result.outcome,
  stage: result.stage ?? null,
  roles: result.outcome === "ok" ? result.value.map((message) => message.role) : [],
  findings: result.outcome === "ok" ? result.findings.length : null,
  toolSawRawInput,
  modelFacing: result.outcome === "ok" ? JSON.stringify(result.value) : "",
  artifact: artifact(),
  core: import.meta.resolve("@redact-secret/core"),
}));
`;

const pythonDriver = () => `import asyncio
import json
import pathlib

import redact_secret
import redact_secret._native as native

from agent_context import build_safe_context

USER_SECRET = ${JSON.stringify(USER_SECRET)}


async def main():
    seen = {}

    async def call_tool(request, **_kwargs):
        seen["raw"] = USER_SECRET in json.dumps(request)
        return {"content": [{"type": "text", "text": f"${TOOL_PREFIX} {request['query']}: leaked AWS_ACCESS_KEY_ID=${TOOL_SECRET}"}]}

    result = await build_safe_context(
        scan_and_redact=redact_secret.scan_and_redact,
        user_input=${JSON.stringify(USER_INPUT)},
        call_tool=call_tool,
        build_tool_request=lambda safe_text: {"name": "lookup", "query": safe_text},
    )
    ok = result["outcome"] == "ok"
    print(json.dumps({
        "outcome": result["outcome"],
        "stage": result.get("stage"),
        "roles": [message["role"] for message in result["context"]["messages"]] if ok else [],
        "findings": len(result["findings"]) if ok else None,
        "toolSawRawInput": seen.get("raw"),
        "modelFacing": json.dumps(result["context"]) if ok else "",
        "module": str(pathlib.Path(redact_secret.__file__).resolve()),
        "native": str(pathlib.Path(native.__file__).resolve()),
    }))


asyncio.run(main())
`;

async function nodeLane(context) {
  const { project, parent, version, candidateDir } = context;
  const scratch = join(parent, "tarballs");
  const candidate = await loadNpmCandidate(candidateDir, scratch, LABEL);
  for (const entry of candidate.values()) {
    assert(entry.manifest.version === version, `${entry.file} is ${entry.manifest.version}, not ${version}`);
  }
  const adapters = await loadPinnedAdapters(scratch);
  const served = new Map([...candidate, ...adapters.tarballs]);
  const registry = await startCandidateRegistry(served);
  try {
    // Every registry lookup, scoped or not, goes to the local registry: the
    // install needs nothing else, and anything else would be a 404.
    const npmrc = join(parent, "npmrc");
    await writeFile(npmrc, `registry=${registry.url}\n@redact-secret:registry=${registry.url}\n`);
    const env = cleanEnvironment({
      npm_config_cache: join(parent, "npm-cache"),
      npm_config_update_notifier: "false",
      NPM_CONFIG_USERCONFIG: npmrc,
    });

    const files = await copyClosure(project, context.closure, ENTRY.node);
    const manifest = {
      name: "golden-path-candidate",
      private: true,
      type: "module",
      dependencies: { "@redact-secret/core": version, ...adapters.dependencies },
    };
    await writeFile(join(project, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    const install = await runShell("npm install --no-audit --no-fund", project, env);
    if (install.code !== 0) process.stderr.write(install.stdout + install.stderr);
    assert(install.code === 0, `npm install exited ${install.code}`);
    const installed = await verifyNpmInstall(project, version, served, registry.url, {
      label: LABEL,
      additional: Object.keys(adapters.dependencies),
    });

    await writeFile(join(project, "golden-path.mjs"), nodeDriver());
    const printed = await runDriver("node golden-path.mjs", project, env);
    requireSanitized(printed);
    assert(
      fileURLToPath(printed.core).startsWith(join(project, "node_modules") + sep),
      "@redact-secret/core does not resolve inside the clean project",
    );
    assert(printed.artifact === "addon", `the installed core loaded ${printed.artifact}, not the addon`);

    return {
      runtime: { name: "node", version: process.version },
      artifact: printed.artifact,
      files,
      adapters: adapters.record,
      packages: installed.packages,
      binaries: installed.binaries,
    };
  } finally {
    await registry.close();
  }
}

async function pythonLane(context) {
  const { project, parent, version, candidateDir } = context;
  const wheels = (await readdir(candidateDir)).filter((name) => name.endsWith(".whl")).map((name) => join(candidateDir, name));
  assert(wheels.length > 0, `${candidateDir} holds no wheel`);
  const env = cleanEnvironment({
    PIP_DISABLE_PIP_VERSION_CHECK: "1",
    PIP_NO_CACHE_DIR: "1",
    PIP_NO_INDEX: "1",
    PIP_FIND_LINKS: candidateDir,
  });
  const pythonVersion = versionSpellings(version).python;
  const setup = await runShell(
    `python3 -m venv .venv\n.venv/bin/python -m pip install --only-binary=:all: redact-secret==${pythonVersion}`,
    project,
    env,
  );
  if (setup.code !== 0) process.stderr.write(setup.stdout + setup.stderr);
  assert(setup.code === 0, `installing the candidate wheel exited ${setup.code}`);

  const probe = await runShell(
    `.venv/bin/python -c "$WHEEL_CHECK" ${wheels.map((wheel) => `'${wheel}'`).join(" ")}`,
    project,
    { ...env, WHEEL_CHECK: await wheelProbeSource() },
  );
  assert(probe.code === 0, "cannot inspect the installed distribution");
  const installed = JSON.parse(probe.stdout);
  assert(installed.version === pythonVersion, `installed redact-secret ${installed.version}`);
  assert(installed.wheel !== null, "the installed wheel is not one of the candidate wheels");
  assert(installed.files > 0 && installed.mismatched.length === 0, "installed files differ from the wheel");

  const files = await copyClosure(project, context.closure, ENTRY.python);
  await writeFile(join(project, "golden_path.py"), pythonDriver());
  const printed = await runDriver(".venv/bin/python -B golden_path.py", project, env);
  requireSanitized(printed);
  const venv = join(project, ".venv") + sep;
  assert(
    printed.module.startsWith(venv) && printed.native.startsWith(venv) && printed.native === installed.native,
    "redact_secret does not load from the clean virtual environment",
  );

  const wheelPath = wheels.find((wheel) => basename(wheel) === installed.wheel);
  const wheelSha256 = sha256(await readFile(wheelPath));
  return {
    runtime: { name: "python", version: installed.python },
    artifact: "native",
    files,
    adapters: null,
    packages: [{ name: "redact-secret", version: installed.version, file: installed.wheel, sha256: wheelSha256 }],
    binaries: [{ package: "redact-secret", file: installed.wheel, sha256: wheelSha256 }],
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (process.platform === "win32") throw new Error(`${LABEL}: the driver runs POSIX shell commands`);
  const version = JSON.parse(await readFile(join(REPO_ROOT, "packages/javascript/package.json"), "utf8")).version;
  const closure = await importClosure(join(REPO_ROOT, EXAMPLE_DIR), ENTRY[options.lane]);

  const { parent, project } = await freshWorkspace(`redact-secret-golden-path-${options.lane}-`, LABEL);
  try {
    const lane = options.lane === "node" ? nodeLane : pythonLane;
    const outcome = await lane({ project, parent, version, closure, candidateDir: options.candidateDir });
    const report = {
      schemaVersion: 1,
      lane: options.lane,
      sourceCommit: sourceCommit(),
      published: false,
      productVersion: version,
      example: { path: EXAMPLE_DIR, entry: `${EXAMPLE_DIR}/${ENTRY[options.lane]}`, files: outcome.files },
      adapters: outcome.adapters,
      runtime: outcome.runtime,
      platform: `${process.platform}-${process.arch}`,
      loadedArtifact: outcome.artifact,
      packages: outcome.packages,
      binaries: outcome.binaries,
      results: { install: "passed", contents: "passed", artifact: "passed", toolInput: "passed", sanitized: "passed" },
    };
    if (options.report !== undefined) await writeFile(options.report, `${JSON.stringify(report, null, 2)}\n`);
    console.log(
      `Golden-path qualification passed (${options.lane}, ${version}, candidate artifacts): ` +
        `buildSafeContext on the installed ${outcome.artifact} core kept both synthetic credentials out of the model-facing context.`,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
