/**
 * External, test-only browser/WASM performance runner for scale profiles.
 *
 * `--detector-profile common` measures the `common` artifact
 * (`npm run wasm:build:common`, default directory `bindings/wasm/pkg-common`)
 * through the same `@redact-secret/core` facade and protocol as `full`
 * (`decision-define-detector-profile-and-pack-contract`): only the glue the
 * facade's `@redact-secret/wasm` import resolves to changes.
 */
import { createServer } from "node:http";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAndEmitPerformanceResult, loadAssessmentSchema } from "./lib/assessment-emit.mjs";
import { loadTsModule } from "./lib/load-ts-module.mjs";
import {
  gitCommit, hostCpu, hostOs, loadWorkloadProfiles, readPackageVersion,
  REPO_ROOT, workloadProfilesHash,
} from "./lib/assessment-provenance.mjs";

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ENTRY = join(REPO_ROOT, "packages", "javascript", "dist", "index.js");
/** Per detector profile: the glue and binary to stage, and the default build directory. */
const DETECTOR_PROFILES = {
  full: {
    glue: "redact_secret_wasm.js",
    binary: "redact_secret_wasm_bg.wasm",
    defaultArtifactDir: join(REPO_ROOT, "bindings", "wasm", "pkg"),
    buildCommand: "npm run wasm:build",
  },
  common: {
    glue: "redact_secret_wasm_common.js",
    binary: "redact_secret_wasm_common_bg.wasm",
    defaultArtifactDir: join(REPO_ROOT, "bindings", "wasm", "pkg-common"),
    buildCommand: "npm run wasm:build:common",
  },
};
const WASM_PACKAGE_JSON = join(REPO_ROOT, "bindings", "wasm", "npm", "package.json");
const ENGINES = ["chromium", "firefox", "webkit"];
const CONTENT_TYPES = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json", ".wasm": "application/wasm" };
const BOUNDARY_LIMIT = "Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks.";

function fail(message) { console.error(message); process.exit(1); }

function parseArguments(argv) {
  const options = { engine: "chromium", artifactDir: undefined, detectorProfile: "full", profile: "scale-logs-small-whole", runs: 10, jsonOut: "-", markdownOut: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--engine") { options.engine = value; index += 1; }
    else if (argument === "--artifact-dir") { options.artifactDir = resolve(REPO_ROOT, value); index += 1; }
    else if (argument === "--profile") { options.profile = value; index += 1; }
    else if (argument === "--detector-profile") { options.detectorProfile = value; index += 1; }
    else if (argument === "--runs") { options.runs = Number(value); index += 1; }
    else if (argument === "--json-out") { options.jsonOut = value; index += 1; }
    else if (argument === "--markdown-out") { options.markdownOut = value; index += 1; }
    else fail(`unknown argument: ${argument}`);
  }
  if (!ENGINES.includes(options.engine)) fail(`--engine must be one of ${ENGINES.join(", ")}`);
  if (!Object.hasOwn(DETECTOR_PROFILES, options.detectorProfile ?? "")) fail(`--detector-profile must be one of ${Object.keys(DETECTOR_PROFILES).join(", ")}`);
  options.artifactDir ??= DETECTOR_PROFILES[options.detectorProfile].defaultArtifactDir;
  if (!Number.isSafeInteger(options.runs) || options.runs < 2 || options.runs > 100) fail("--runs must be an integer from 2 through 100");
  return options;
}

function renderPage() {
  return "<script type=\"module\" src=\"./run.js\"></script>";
}

async function stage(artifactDir, detectorProfile, profile) {
  if (!existsSync(PACKAGE_ENTRY)) fail(`${PACKAGE_ENTRY}: missing; run \`npm run js:build\` first`);
  const artifact = DETECTOR_PROFILES[detectorProfile];
  const directory = mkdtempSync(join(tmpdir(), "redact-secret-performance-"));
  for (const name of [artifact.glue, artifact.binary]) {
    try { copyFileSync(join(artifactDir, name), join(directory, name)); }
    catch { rmSync(directory, { recursive: true, force: true }); fail(`${join(artifactDir, name)}: missing; run \`${artifact.buildCommand}\` first`); }
  }
  const { build } = await import("esbuild");
  await build({
    entryPoints: [join(SCRIPTS_DIR, "assessment-browser-performance-harness.mjs")],
    outfile: join(directory, "harness.js"), bundle: true, format: "esm", platform: "browser",
    conditions: ["browser", "import"],
    alias: { "@redact-secret/core": PACKAGE_ENTRY, "@redact-secret/wasm": join(artifactDir, artifact.glue) },
    logLevel: "silent",
  });
  writeFileSync(join(directory, "index.html"), renderPage());
  writeFileSync(join(directory, "profile.json"), JSON.stringify(profile));
  writeFileSync(
    join(directory, "run.js"),
    "import { measure } from './harness.js';\n" +
      "const profile = await (await fetch('./profile.json')).json();\n" +
      "try { globalThis.__result = { ok: true, sample: await measure(profile) }; }\n" +
      "catch (error) { globalThis.__result = { ok: false, error: String(error) }; }\n",
  );
  return directory;
}

async function serve(directory) {
  const server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const name = path === "/" ? "index.html" : path.slice(1);
    if (name.includes("/") || name.includes("\\") || name.includes("..")) { response.writeHead(404).end(); return; }
    try {
      const body = readFileSync(join(directory, name));
      response.writeHead(200, { "content-type": CONTENT_TYPES[extname(name)] ?? "application/octet-stream", "content-length": String(body.byteLength) });
      response.end(body);
    } catch { response.writeHead(404).end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const schema = await loadAssessmentSchema();
  const document = loadWorkloadProfiles();
  const profiles = schema.validateAssessmentWorkloadProfiles(document.profiles);
  if (profiles.length !== document.profileCount) fail("workload profile count does not match");
  const profile = profiles.find((candidate) => candidate.id === options.profile);
  if (profile === undefined || profile.purpose !== "scale") fail(`${options.profile}: unknown scale profile`);

  let playwright;
  try { playwright = await import("playwright"); } catch { fail("playwright is not installed; run `npm ci`"); }
  const directory = await stage(options.artifactDir, options.detectorProfile, profile);
  let server;
  let browser;
  let browserVersion;
  const samples = [];
  try {
    const served = await serve(directory);
    server = served.server;
    browser = await playwright[options.engine].launch();
    browserVersion = browser.version();
    for (let run = 0; run < options.runs; run += 1) {
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        await page.goto(served.origin);
        await page.waitForFunction(() => globalThis.__result !== undefined);
        const outcome = await page.evaluate(() => globalThis.__result);
        if (!outcome.ok) throw new Error("browser performance sample failed");
        samples.push(outcome.sample);
      } finally {
        await context.close();
      }
    }
  } finally {
    if (browser !== undefined) await browser.close();
    if (server !== undefined) await new Promise((resolve) => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  }

  const metrics = await loadTsModule(join(REPO_ROOT, "assessment", "adapters", "performance.ts"));
  const unavailable = (reason) => metrics.unavailableMemory(reason, "No samples were available.");
  const heapSamples = samples.flatMap((sample) => sample.browserHeap === undefined ? [] : [sample.browserHeap]);
  const performanceMetrics = {
    initialization: metrics.summarizeDistribution(samples.map((sample) => sample.initializationMs), "milliseconds"),
    processing: metrics.summarizeDistribution(samples.map((sample) => sample.processingMs), "milliseconds"),
    throughput: metrics.summarizeDistribution(samples.map((sample) => sample.throughputBytesPerSecond), "bytes-per-second"),
    memory: {
      nodeHeap: unavailable("A browser process does not expose Node heapUsed."),
      nodeRss: unavailable("Browser pages do not expose process RSS through a standard API."),
      nodeExternal: unavailable("Browser pages do not expose Node external memory."),
      browserJsHeap: heapSamples.length === samples.length ? metrics.availableMemory(heapSamples, `${BOUNDARY_LIMIT} performance.memory is non-standard, engine-dependent, and may be coarsened.`) : unavailable("This engine does not expose performance.memory.usedJSHeapSize."),
      wasmLinearMemory: unavailable("The package intentionally keeps its WebAssembly.Memory handle private; the test harness cannot read linear-memory size without adding product instrumentation."),
      pythonHeap: unavailable("The browser surface does not run inside a Python allocator."),
      processRss: unavailable("Browser pages do not expose whole-process RSS through a standard API."),
      streamingBuffer: unavailable("The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size."),
    },
  };
  const result = await buildAndEmitPerformanceResult({
    surface: "browser-wasm", profileId: profile.id, performance: performanceMetrics,
    provenance: {
      commit: gitCommit(),
      artifactIdentity: `@redact-secret/wasm@${readPackageVersion(WASM_PACKAGE_JSON)}${options.detectorProfile === "full" ? "" : ` (${options.detectorProfile})`}`,
      corpusVersion: "1", corpusHash: workloadProfilesHash(), os: hostOs(), cpu: hostCpu(),
      runtime: `${options.engine}-${browserVersion}`,
      command: `node scripts/assessment-browser-performance.mjs ${process.argv.slice(2).join(" ")}`.trim(),
    }, jsonOut: options.jsonOut, markdownOut: options.markdownOut,
  });
  console.error(`${options.engine} performance: ${result.performance.processing.samples.length} run(s), median ${result.performance.processing.median} ms`);
}

await main();
