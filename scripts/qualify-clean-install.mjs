#!/usr/bin/env node
/**
 * Issue #586: the five-minute clean-install qualification. Runs one scenario
 * of `docs/quickstart.md` -- Node.js, Python, or a browser bundler -- exactly
 * as a new user would: in an empty directory outside this repository, with
 * the page's own commands and files, read from the page at run time
 * (`scripts/clean-install-doc.mjs`). Nothing here imports repository source
 * into the scenario, and no command is rewritten.
 *
 * What changes between a reader's run and CI's is only *where packages come
 * from*, set through the environment the same commands already honor:
 *
 * - `--candidate-dir <dir>` holds a release candidate's npm tarballs
 *   (`scripts/pack-npm-candidate.mjs`) and/or wheels. npm resolves the
 *   `@redact-secret` scope from a local registry serving only those tarballs
 *   (everything else, e.g. Vite, from the public registry); pip resolves from
 *   `PIP_FIND_LINKS` with `PIP_NO_INDEX`. The packages installed are verified
 *   byte-for-byte against the candidate files.
 * - Without it, the published packages are installed from the public
 *   registries -- the post-publication check of the same path.
 *
 * Beyond the documented output, each lane verifies what the page cannot show:
 * the directory is outside the repository and starts empty; the installed
 * packages are exactly the expected set and their files (and transitive
 * runtime assets: the addon, both `.wasm` builds, the bundled `.wasm`) match
 * the candidate; the loaded artifact is the one the page claims; the whole
 * documented path finishes inside `--budget-seconds`; and an initialization
 * failure (addon and WebAssembly removed, the extension module removed, or
 * the `.wasm` request failing) surfaces as the fixed, input-free, actionable
 * error the troubleshooting guide names. The report records only those
 * outcomes, versions, digests, and commands -- never command output.
 *
 * Usage: node scripts/qualify-clean-install.mjs --lane node|python|browser
 *   [--candidate-dir <dir>] [--report <path>] [--budget-seconds 300]
 *   [--engine chromium|firefox|webkit]
 */

import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  REPO_ROOT,
  cleanEnvironment,
  fileDigests,
  freshWorkspace as freshCandidateWorkspace,
  loadNpmCandidate as loadCandidateTarballs,
  makeAssert,
  runShell,
  sha256,
  sourceCommit,
  startCandidateRegistry,
  verifyNpmInstall as verifyCandidateInstall,
  wheelProbeSource,
} from "./lib/candidate-install.mjs";
import {
  LANES,
  SYNTHETIC_INPUT,
  parseQuickstart,
  requirePinnedVersion,
  scenarioCommands,
  versionSpellings,
} from "./clean-install-doc.mjs";

const QUICKSTART = "docs/quickstart.md";
const PUBLIC_NPM_REGISTRY = "https://registry.npmjs.org/";
const SECRET_VALUE = SYNTHETIC_INPUT.split("=")[1];

// Where each failure message must send the reader
// (docs/troubleshooting.md, docs/python-packaging.md).
const JS_FAILURE_GUIDE = "docs/troubleshooting.md";
const PYTHON_FAILURE_GUIDE = "docs/python-packaging.md";

function parseArgs(argv) {
  const options = { budgetSeconds: 300, engine: "chromium" };
  for (let index = 0; index < argv.length; index += 2) {
    const [key, value] = [argv[index], argv[index + 1]];
    if (value === undefined) throw new Error(`missing value for ${key}`);
    if (key === "--lane") options.lane = value;
    else if (key === "--candidate-dir") options.candidateDir = resolve(value);
    else if (key === "--report") options.report = resolve(value);
    else if (key === "--budget-seconds") options.budgetSeconds = Number(value);
    else if (key === "--engine") options.engine = value;
    else throw new Error(`unknown argument ${key}`);
  }
  if (!LANES.includes(options.lane) || !(options.budgetSeconds > 0)) {
    throw new Error(
      "usage: qualify-clean-install.mjs --lane node|python|browser [--candidate-dir <dir>] " +
        "[--report <path>] [--budget-seconds <n>] [--engine chromium|firefox|webkit]",
    );
  }
  return options;
}

const assert = makeAssert("clean install");

async function runStep(label, block, cwd, env) {
  const result = await runShell(block, cwd, env);
  if (result.code !== 0) {
    process.stderr.write(result.stdout + result.stderr);
    throw new Error(`clean install: documented ${label} step exited ${result.code}`);
  }
  return result;
}

/** A fresh, empty directory under the OS temp root, never inside this checkout. */
function freshWorkspace(lane) {
  return freshCandidateWorkspace(`redact-secret-clean-${lane}-`, "clean install", "quickstart");
}

async function writeScenarioFiles(project, files) {
  for (const file of files) await writeFile(join(project, file.name), file.content);
}

const loadNpmCandidate = (candidateDir, scratch) => loadCandidateTarballs(candidateDir, scratch, "clean install");

const verifyNpmInstall = (project, version, candidate, registryUrl) =>
  verifyCandidateInstall(project, version, candidate, registryUrl, { label: "clean install" });

/** The installed package's own fixed message for `code`, read from its public API. */
async function fixedJsMessage(project, env, code) {
  const probe = await runShell(
    `node --input-type=module -e 'const m = await import("@redact-secret/core"); console.log(new m.SecretScanError("${code}").message)'`,
    project,
    env,
  );
  assert(probe.code === 0, "cannot read SecretScanError's fixed message from the installed package");
  return probe.stdout.trim();
}

function requireSafeFailure(message, { guide, workspace }) {
  assert(message.length > 0, "the initialization failure carries no message");
  assert(!message.includes(SECRET_VALUE), "the initialization failure exposes input");
  assert(!message.includes(workspace), "the initialization failure exposes a host path");
  assert(message.includes(guide), `the initialization failure does not point to ${guide}`);
}

async function nodeLane(context) {
  const { scenario, project, parent, env, timer } = context;
  await runStep("setup", scenario.setup, project, env);
  await writeScenarioFiles(project, scenario.files);
  const run = await runStep("run", scenario.run, project, env);
  assert(run.stdout.replace(/\n$/, "") === scenario.expect, "node output differs from the documented output");
  const elapsedSeconds = timer();

  const install = await verifyNpmInstall(project, context.version, context.candidate, context.registryUrl);
  const resolved = await runShell(
    `node --input-type=module -e 'console.log(import.meta.resolve("@redact-secret/core"))'`,
    project,
    env,
  );
  assert(
    fileURLToPath(resolved.stdout.trim()).startsWith(join(project, "node_modules") + sep),
    "@redact-secret/core does not resolve inside the clean project",
  );

  // Without the addon the documented program must still work on WebAssembly,
  // as the page says; without both it must fail with the fixed error.
  const fixed = await fixedJsMessage(project, env, "INITIALIZATION_FAILED");
  await rm(join(project, "node_modules", install.hostAddon), { recursive: true, force: true });
  const fallback = await runStep("run (addon removed)", scenario.run, project, env);
  assert(
    fallback.stdout.replace(/\n$/, "") === scenario.expect.replace(/ loaded addon$/m, " loaded wasm"),
    "without the addon, node does not fall back to WebAssembly as documented",
  );
  await rm(join(project, "node_modules", "@redact-secret", "wasm"), { recursive: true, force: true });
  const failed = await runShell(scenario.run, project, env);
  const message = /^SecretScanError: (.*)$/m.exec(failed.stderr)?.[1];
  assert(failed.code !== 0 && message !== undefined, "an unloadable install does not reject with SecretScanError");
  assert(failed.stderr.includes("INITIALIZATION_FAILED"), "the failure does not carry INITIALIZATION_FAILED");
  assert(message === fixed, "the failure message is not the fixed INITIALIZATION_FAILED message");
  assert(!failed.stdout.includes(SECRET_VALUE) && !failed.stderr.includes(SECRET_VALUE), "the failure exposes input");
  requireSafeFailure(message, { guide: JS_FAILURE_GUIDE, workspace: parent });

  return {
    elapsedSeconds,
    runtime: { name: "node", version: process.version },
    artifact: "addon",
    packages: install.packages,
    binaries: install.binaries,
    checks: { install: "passed", contents: "passed", output: "passed", artifact: "passed", fallback: "passed", failure: "passed" },
  };
}

async function pythonLane(context) {
  const { scenario, project, parent, env, timer, candidateDir } = context;
  await runStep("setup", scenario.setup, project, env);
  await writeScenarioFiles(project, scenario.files);
  const run = await runStep("run", scenario.run, project, env);
  assert(run.stdout.replace(/\n$/, "") === scenario.expect, "python output differs from the documented output");
  const elapsedSeconds = timer();

  const wheels = candidateDir === undefined
    ? []
    : (await readdir(candidateDir)).filter((name) => name.endsWith(".whl")).map((name) => join(candidateDir, name));
  assert(candidateDir === undefined || wheels.length > 0, `${candidateDir} holds no wheel`);
  const probe = await runShell(
    `.venv/bin/python -c "$WHEEL_CHECK" ${wheels.map((wheel) => `'${wheel}'`).join(" ")}`,
    project,
    { ...env, WHEEL_CHECK: await wheelProbeSource() },
  );
  assert(probe.code === 0, `cannot inspect the installed distribution: ${probe.stderr.split("\n").at(-2) ?? ""}`);
  const installed = JSON.parse(probe.stdout);
  assert(installed.version === versionSpellings(context.version).python, `installed redact-secret ${installed.version}`);
  assert(candidateDir === undefined || installed.wheel !== null, "the installed wheel is not one of the candidate wheels");
  assert(installed.files > 0 && installed.mismatched.length === 0, `installed files differ from the wheel: ${installed.mismatched.join(", ")}`);
  const venv = join(project, ".venv") + sep;
  assert(installed.module.startsWith(venv) && installed.native.startsWith(venv), "redact_secret does not load from the clean virtual environment");

  // A missing or unloadable extension module must fail the import with the
  // fixed, actionable message, not a loader traceback naming host paths.
  await rm(installed.native);
  const failed = await runShell(scenario.run, project, env);
  const message = /^ImportError: (.*)$/m.exec(failed.stderr)?.[1];
  assert(failed.code !== 0 && message !== undefined, "an unloadable install does not raise ImportError");
  assert(!failed.stderr.includes(SECRET_VALUE), "the failure exposes input");
  assert(!failed.stderr.includes("_native."), "the failure exposes the loader's own diagnostic");
  requireSafeFailure(message, { guide: PYTHON_FAILURE_GUIDE, workspace: parent });

  const wheelPath = wheels.find((wheel) => basename(wheel) === installed.wheel);
  return {
    elapsedSeconds,
    runtime: { name: "python", version: installed.python },
    artifact: "native",
    packages: [
      {
        name: "redact-secret",
        version: installed.version,
        file: installed.wheel,
        sha256: wheelPath === undefined ? null : sha256(await readFile(wheelPath)),
      },
    ],
    binaries: wheelPath === undefined ? [] : [{ package: "redact-secret", file: installed.wheel, sha256: sha256(await readFile(wheelPath)) }],
    checks: { install: "passed", contents: "passed", output: "passed", artifact: "passed", failure: "passed" },
  };
}

async function waitForServer(url, serving) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (serving.exitCode !== null) throw new Error(`clean install: the documented serve step exited ${serving.exitCode}`);
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error(`clean install: ${url} did not come up`);
}

async function browserLane(context) {
  const { scenario, project, parent, env, timer, engine } = context;
  await runStep("setup", scenario.setup, project, env);
  await writeScenarioFiles(project, scenario.files);
  await runStep("build", scenario.run, project, env);

  // The bundle must carry the full-profile WebAssembly binary the package
  // installed, byte for byte, and not the common one.
  const installedWasm = await fileDigests(join(project, "node_modules", "@redact-secret", "wasm"));
  const bundled = [...(await fileDigests(join(project, "dist")))].filter(([file]) => file.endsWith(".wasm"));
  assert(
    bundled.length === 1 && bundled[0][1] === installedWasm.get("redact_secret_wasm_bg.wasm"),
    "the bundle does not carry exactly the installed full-profile .wasm asset",
  );

  const port = /--port\s+(\d+)/.exec(scenario.serve)?.[1];
  assert(port !== undefined, "the serve step names no --port");
  const url = `http://localhost:${port}/`;
  const serving = spawn("sh", ["-e", "-c", scenario.serve], { cwd: project, env, stdio: "ignore", detached: true });
  let browser;
  try {
    await waitForServer(url, serving);
    const playwright = await import("playwright");
    assert(typeof playwright[engine]?.launch === "function", `unsupported engine ${engine}`);
    browser = await playwright[engine].launch();
    const page = await browser.newPage();
    const wasmResponses = [];
    page.on("response", (response) => {
      if (new URL(response.url()).pathname.endsWith(".wasm")) {
        wasmResponses.push({ status: response.status(), type: response.headers()["content-type"] });
      }
    });
    const readOutput = async () => {
      await page.waitForFunction(() => document.querySelector("#output")?.textContent !== "loading", null, { timeout: 30_000 });
      return page.locator("#output").textContent();
    };
    await page.goto(url);
    const output = await readOutput();
    assert(output === scenario.expect, "page text differs from the documented output");
    const elapsedSeconds = timer();
    assert(
      wasmResponses.length === 1 && wasmResponses[0].status === 200 && wasmResponses[0].type?.startsWith("application/wasm"),
      "the page did not load exactly one .wasm asset served as application/wasm",
    );

    const install = await verifyNpmInstall(project, context.version, context.candidate, context.registryUrl);
    const fixed = await fixedJsMessage(project, env, "INITIALIZATION_FAILED");
    const failing = await browser.newPage();
    await failing.route("**/*.wasm", (route) => route.fulfill({ status: 404, body: "" }));
    await failing.goto(url);
    await failing.waitForFunction(() => document.querySelector("#output")?.textContent !== "loading", null, { timeout: 30_000 });
    const failure = await failing.locator("#output").textContent();
    assert(failure === `INITIALIZATION_FAILED: ${fixed}`, "a failed .wasm request does not surface the fixed INITIALIZATION_FAILED error");
    requireSafeFailure(fixed, { guide: JS_FAILURE_GUIDE, workspace: parent });

    return {
      elapsedSeconds,
      runtime: { name: engine, version: browser.version() },
      artifact: "wasm",
      packages: install.packages,
      binaries: install.binaries,
      checks: { install: "passed", contents: "passed", bundle: "passed", output: "passed", artifact: "passed", failure: "passed" },
    };
  } finally {
    await browser?.close();
    try {
      process.kill(-serving.pid, "SIGTERM");
    } catch {
      // already gone
    }
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (process.platform === "win32") throw new Error("clean install: the documented commands are POSIX shell");
  const markdown = await readFile(join(REPO_ROOT, QUICKSTART));
  const scenarios = parseQuickstart(markdown.toString("utf8"));
  const version = JSON.parse(await readFile(join(REPO_ROOT, "packages/javascript/package.json"), "utf8")).version;
  const pinErrors = requirePinnedVersion(scenarios, version);
  assert(pinErrors.length === 0, `${QUICKSTART} does not pin ${version}: ${pinErrors.join("; ")}`);
  const scenario = scenarios[options.lane];

  const { parent, project } = await freshWorkspace(options.lane);
  const scratch = await mkdtemp(join(tmpdir(), "redact-secret-clean-candidate-"));
  let registry;
  try {
    const npmLane = options.lane !== "python";
    const candidate =
      npmLane && options.candidateDir !== undefined ? await loadNpmCandidate(options.candidateDir, scratch) : undefined;
    if (candidate !== undefined) {
      for (const entry of candidate.values()) {
        assert(entry.manifest.version === version, `${entry.file} is ${entry.manifest.version}, not ${version}`);
      }
    }
    const overrides = {
      npm_config_cache: join(parent, "npm-cache"),
      npm_config_update_notifier: "false",
      PIP_DISABLE_PIP_VERSION_CHECK: "1",
      PIP_NO_CACHE_DIR: "1",
    };
    let registryUrl = PUBLIC_NPM_REGISTRY;
    if (candidate !== undefined) {
      registry = await startCandidateRegistry(candidate);
      registryUrl = registry.url;
      const npmrc = join(parent, "npmrc");
      await writeFile(npmrc, `@redact-secret:registry=${registry.url}\n`);
      overrides.NPM_CONFIG_USERCONFIG = npmrc;
    }
    if (!npmLane && options.candidateDir !== undefined) {
      overrides.PIP_NO_INDEX = "1";
      overrides.PIP_FIND_LINKS = options.candidateDir;
    }

    const started = process.hrtime.bigint();
    const context = {
      scenario,
      project,
      parent,
      version,
      candidate,
      candidateDir: options.candidateDir,
      registryUrl,
      engine: options.engine,
      env: cleanEnvironment(overrides),
      timer: () => Number((process.hrtime.bigint() - started) / 1_000_000n) / 1000,
    };
    const lane = { node: nodeLane, python: pythonLane, browser: browserLane }[options.lane];
    const outcome = await lane(context);
    assert(
      outcome.elapsedSeconds <= options.budgetSeconds,
      `the documented ${options.lane} path took ${outcome.elapsedSeconds}s, over the ${options.budgetSeconds}s budget`,
    );

    const report = {
      schemaVersion: 1,
      lane: options.lane,
      sourceCommit: sourceCommit(),
      published: options.candidateDir === undefined,
      productVersion: version,
      document: { path: QUICKSTART, sha256: sha256(markdown) },
      commands: scenarioCommands(scenario),
      files: scenario.files.map((file) => file.name),
      runtime: outcome.runtime,
      platform: `${process.platform}-${process.arch}`,
      loadedArtifact: outcome.artifact,
      budgetSeconds: options.budgetSeconds,
      elapsedSeconds: outcome.elapsedSeconds,
      packages: outcome.packages,
      binaries: outcome.binaries,
      results: outcome.checks,
    };
    if (options.report !== undefined) await writeFile(options.report, `${JSON.stringify(report, null, 2)}\n`);
    console.log(
      `Clean-install qualification passed (${options.lane}, ${version}, ` +
        `${options.candidateDir === undefined ? "published packages" : "candidate artifacts"}): ` +
        `the documented path completed in ${outcome.elapsedSeconds}s of a ${options.budgetSeconds}s budget.`,
    );
  } finally {
    await registry?.close();
    await rm(scratch, { recursive: true, force: true });
    await rm(parent, { recursive: true, force: true });
  }
}

await main();
