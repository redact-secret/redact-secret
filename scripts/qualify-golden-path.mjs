#!/usr/bin/env node
/**
 * Issue #720: runs the MCP AI-context golden path (`examples/mcp-redact`,
 * issue #587) end to end against an *installed* release candidate, and
 * asserts that the value it would hand a model is sanitized.
 *
 * The example's own tests inject a fake core. This driver is the other half:
 * the real engine, installed the way an outside consumer installs it.
 *
 * `--lane node` copies `agent-context.mjs` and every module it imports
 * (followed from the file, not listed here) into an empty directory outside
 * the checkout, and installs `@redact-secret/core` plus the example's
 * adapter packages from a local registry that serves only the candidate
 * tarballs (`scripts/pack-npm-candidate.mjs`) and the adapter tarballs the
 * example's `package-lock.json` locks. Those adapter tarballs are the
 * published npm registry bytes: fetched from the `resolved` URL the lockfile
 * records and verified against its `integrity` before they are served, so
 * the clean project installs exactly the versions the example does, next to
 * the candidate core. `createGoldenPathBoundary()` then loads that installed
 * core. The lane also runs the example's real-core tests -- the files
 * `npm run examples:real-core:test` names (#721, streamed tool output on the
 * real `IncrementalSanitizer`) -- in the same project, against the same
 * installed core.
 *
 * There is no Python lane. The Python MCP golden-path twins were retired
 * (#810): no Python AI-context or MCP adapter exists, and the MCP boundary
 * does not support the Python `mcp` SDK (#612).
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
 * Usage: node scripts/qualify-golden-path.mjs --lane node
 *   --candidate-dir <dir> [--report <path>]
 */

import { createHash } from "node:crypto";
import { readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join, posix, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

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
} from "./lib/candidate-install.mjs";

const LABEL = "golden path";
const assert = makeAssert(LABEL);
export const LANES = ["node"];
export const EXAMPLE_DIR = "examples/mcp-redact";
export const ENTRY = { node: "agent-context.mjs" };
export const LOCKFILE = `${EXAMPLE_DIR}/package-lock.json`;
export const NPM_REGISTRY = "https://registry.npmjs.org/";
const REAL_CORE_SCRIPT = "examples:real-core:test";

/**
 * The example test files the `examples:real-core:test` script runs, relative
 * to the example directory. Read from `package.json` so a real-core test
 * added to that script runs here too, with no second list to keep in sync.
 */
export function realCoreTests(scripts) {
  const command = String(scripts?.[REAL_CORE_SCRIPT] ?? "");
  const tests = [...command.matchAll(/(?:^|\s)examples\/mcp-redact\/(\S+\.test\.mjs)(?=\s|$)/g)].map((match) => match[1]);
  assert(tests.length > 0, `the ${REAL_CORE_SCRIPT} script names no ${EXAMPLE_DIR} test file`);
  assert(tests.every((test) => !test.includes("/")), `the ${REAL_CORE_SCRIPT} tests must sit in ${EXAMPLE_DIR}`);
  return tests;
}

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
    throw new Error("usage: qualify-golden-path.mjs --lane node --candidate-dir <dir> [--report <path>]");
  }
  return options;
}

/**
 * The local modules `source` (at `path`, relative to the example directory)
 * imports: relative ESM specifiers. Anything else is a package the install
 * must provide.
 */
export function localImports(path, source) {
  const specifiers = [...source.matchAll(/^\s*(?:import|export)\s[^;]*?from\s+["'](\.{1,2}\/[^"']+)["']/gm)].map(
    (match) => match[1],
  );
  specifiers.push(...[...source.matchAll(/^\s*import\s+["'](\.{1,2}\/[^"']+)["']/gm)].map((match) => match[1]));
  return specifiers.map((specifier) => posix.normalize(posix.join(posix.dirname(path), specifier)));
}

/** `entry` and every example module it transitively imports, each with its bytes. */
export async function importClosure(exampleRoot, entry) {
  const siblings = new Set(await readdir(exampleRoot));
  const files = new Map();
  const pending = [entry];
  while (pending.length > 0) {
    const path = pending.pop();
    if (files.has(path)) continue;
    assert(!path.startsWith("..") && siblings.has(path), `${EXAMPLE_DIR}/${path} is imported but does not exist`);
    const bytes = await readFile(join(exampleRoot, path));
    files.set(path, bytes);
    pending.push(...localImports(path, bytes.toString("utf8")));
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
 * The adapter packages `lock` (the example's `package-lock.json`) locks:
 * every `@redact-secret/*` entry, each installed at the top level from the
 * public registry with an integrity. `@redact-secret/core` must not be one of
 * them -- the candidate supplies it -- and every direct dependency the
 * example's `package.json` declares must be locked at exactly its spec.
 */
export function lockedAdapters(manifest, lock) {
  const locked = [];
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!key.includes("node_modules/@redact-secret/")) continue;
    const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
    assert(key === `node_modules/${name}`, `${LOCKFILE} nests ${name}; every adapter must install at the top level`);
    assert(name !== "@redact-secret/core", `${LOCKFILE} locks @redact-secret/core; the candidate supplies it`);
    assert(entry.link !== true, `${LOCKFILE} links ${name} instead of locking a registry version`);
    assert(
      typeof entry.version === "string" && entry.resolved === `${NPM_REGISTRY}${name}/-/${name.split("/")[1]}-${entry.version}.tgz`,
      `${LOCKFILE} does not resolve ${name} from ${NPM_REGISTRY}`,
    );
    assert(/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(String(entry.integrity)), `${LOCKFILE} has no sha512 integrity for ${name}`);
    locked.push({ name, version: entry.version, resolved: entry.resolved, integrity: entry.integrity });
  }
  assert(locked.length > 0, `${LOCKFILE} locks no @redact-secret adapter`);
  const byName = new Map(locked.map((entry) => [entry.name, entry]));
  for (const [name, spec] of Object.entries(manifest.dependencies ?? {})) {
    assert(byName.get(name)?.version === spec, `${EXAMPLE_DIR} declares ${name} ${spec}, which ${LOCKFILE} does not lock exactly`);
  }
  return locked.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
}

/**
 * The example's adapter tarballs, fetched from the npm registry at exactly
 * the versions its lockfile locks and each verified against the lockfile's
 * integrity before anything serves it.
 */
async function loadRegistryAdapters(scratch) {
  const manifest = JSON.parse(await readFile(join(REPO_ROOT, EXAMPLE_DIR, "package.json"), "utf8"));
  const lock = JSON.parse(await readFile(join(REPO_ROOT, LOCKFILE), "utf8"));
  const locked = lockedAdapters(manifest, lock);
  const paths = [];
  for (const entry of locked) {
    const response = await fetch(entry.resolved);
    assert(response.ok, `fetching ${entry.name}@${entry.version} from ${NPM_REGISTRY} returned ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    assert(integrity === entry.integrity, `${entry.name}@${entry.version} does not match its ${LOCKFILE} integrity`);
    const path = join(scratch, `registry-${entry.name.split("/")[1]}-${entry.version}.tgz`);
    await writeFile(path, bytes);
    paths.push(path);
  }
  const tarballs = await loadNpmTarballs(paths, scratch, LABEL);
  for (const entry of locked) {
    assert(tarballs.get(entry.name)?.manifest.version === entry.version, `${entry.name}'s tarball is not ${entry.version}`);
  }
  return {
    tarballs,
    dependencies: Object.fromEntries(locked.map((entry) => [entry.name, entry.version])),
    record: {
      source: NPM_REGISTRY,
      lockfile: LOCKFILE,
      packages: locked.map(({ name, version, integrity }) => ({ name, version, integrity })),
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

async function nodeLane(context) {
  const { project, parent, version, candidateDir } = context;
  const scratch = join(parent, "tarballs");
  const candidate = await loadNpmCandidate(candidateDir, scratch, LABEL);
  for (const entry of candidate.values()) {
    assert(entry.manifest.version === version, `${entry.file} is ${entry.manifest.version}, not ${version}`);
  }
  const adapters = await loadRegistryAdapters(scratch);
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
    const tests = await runShell(`node --test ${context.realCoreTests.join(" ")}`, project, env);
    if (tests.code !== 0) process.stderr.write(tests.stdout + tests.stderr);
    assert(tests.code === 0, `the example's real-core tests (${context.realCoreTests.join(", ")}) failed on the installed core`);
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
      realCoreTests: context.realCoreTests.map((test) => `${EXAMPLE_DIR}/${test}`),
      packages: installed.packages,
      binaries: installed.binaries,
    };
  } finally {
    await registry.close();
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (process.platform === "win32") throw new Error(`${LABEL}: the driver runs POSIX shell commands`);
  const version = JSON.parse(await readFile(join(REPO_ROOT, "packages/javascript/package.json"), "utf8")).version;
  const exampleRoot = join(REPO_ROOT, EXAMPLE_DIR);
  const closure = await importClosure(exampleRoot, ENTRY[options.lane]);
  const tests = realCoreTests(JSON.parse(await readFile(join(REPO_ROOT, "package.json"), "utf8")).scripts);
  for (const test of tests) for (const [path, bytes] of await importClosure(exampleRoot, test)) closure.set(path, bytes);

  const { parent, project } = await freshWorkspace(`redact-secret-golden-path-${options.lane}-`, LABEL);
  try {
    const outcome = await nodeLane({ project, parent, version, closure, realCoreTests: tests, candidateDir: options.candidateDir });
    const report = {
      // 2: `adapters` records the registry packages the example's lockfile
      // locks (#810 retired the Python lane and the tarball pin).
      schemaVersion: 2,
      lane: options.lane,
      sourceCommit: sourceCommit(),
      published: false,
      productVersion: version,
      example: { path: EXAMPLE_DIR, entry: `${EXAMPLE_DIR}/${ENTRY[options.lane]}`, files: outcome.files },
      adapters: outcome.adapters,
      realCoreTests: outcome.realCoreTests,
      runtime: outcome.runtime,
      platform: `${process.platform}-${process.arch}`,
      loadedArtifact: outcome.artifact,
      packages: outcome.packages,
      binaries: outcome.binaries,
      results: {
        install: "passed",
        contents: "passed",
        artifact: "passed",
        toolInput: "passed",
        sanitized: "passed",
        realCoreTests: "passed",
      },
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
