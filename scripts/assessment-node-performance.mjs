/** External, test-only Node performance runner for assessment scale profiles. */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildAndEmitPerformanceResult, loadAssessmentSchema } from "./lib/assessment-emit.mjs";
import { loadTsModule } from "./lib/load-ts-module.mjs";
import {
  agreedResolvedArtifact, gitCommit, hostCpu, hostOs, loadWorkloadProfiles, readPackageVersion,
  REPO_ROOT, workloadProfilesHash,
} from "./lib/assessment-provenance.mjs";

const ENTRY = join(REPO_ROOT, "packages", "javascript", "dist", "index.js");
const PACKAGE_JSON = join(REPO_ROOT, "packages", "javascript", "package.json");
const DEFAULT_ADDON_DIR = join(REPO_ROOT, "bindings", "node");
const DEFAULT_PROFILE = "scale-logs-small-whole";
const BOUNDARY_LIMIT = "Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks.";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = { profile: DEFAULT_PROFILE, runs: 10, jsonOut: "-", markdownOut: undefined, sample: false, addonDir: DEFAULT_ADDON_DIR };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--profile") { options.profile = value; index += 1; }
    else if (argument === "--runs") { options.runs = Number(value); index += 1; }
    else if (argument === "--json-out") { options.jsonOut = value; index += 1; }
    else if (argument === "--markdown-out") { options.markdownOut = value; index += 1; }
    else if (argument === "--addon-dir") { options.addonDir = value; index += 1; }
    else if (argument === "--sample") options.sample = true;
    else fail(`unknown argument: ${argument}`);
  }
  if (typeof options.profile !== "string" || options.profile.length === 0) fail("--profile requires a value");
  if (!Number.isSafeInteger(options.runs) || options.runs < 2 || options.runs > 100) {
    fail("--runs must be an integer from 2 through 100");
  }
  return options;
}

async function linkAddon(addonDir) {
  const runtime = await import(pathToFileURL(join(REPO_ROOT, "packages", "javascript", "dist", "runtime", "node.js")).href);
  const specifier = runtime.resolveAddonSpecifier();
  if (specifier === undefined) fail(`no Node addon package is mapped for ${process.platform}/${process.arch}`);
  const scope = join(REPO_ROOT, "packages", "javascript", "node_modules", "@redact-secret");
  const link = join(scope, specifier.split("/")[1]);
  if (existsSync(link)) return undefined;
  mkdirSync(scope, { recursive: true });
  symlinkSync(addonDir, link, "junction");
  return link;
}

function processInput(api, input, chunks, chunkProfile, inputLimit) {
  if (chunkProfile === "whole") {
    const result = api.scanAndRedact(input);
    return result.text.length + result.findings.length;
  }
  const session = api.createIncrementalSanitizer({
    limits: {
      maxInputCodeUnits: inputLimit,
      maxBufferedCodeUnits: 32_896,
      maxTokenCodeUnits: 8_192,
      maxMultilineCodeUnits: 32_768,
    },
  });
  let sink = 0;
  for (const chunk of chunks) {
    const result = session.append(chunk);
    sink += result.text.length + result.findings.length;
  }
  const final = session.finalize();
  return sink + final.text.length + final.findings.length;
}

async function loadProfile(profileId) {
  const schema = await loadAssessmentSchema();
  const document = loadWorkloadProfiles();
  const profiles = schema.validateAssessmentWorkloadProfiles(document.profiles);
  if (profiles.length !== document.profileCount) fail("workload profile count does not match");
  const profile = profiles.find((candidate) => candidate.id === profileId);
  if (profile === undefined || profile.purpose !== "scale") fail(`${profileId}: unknown scale profile`);
  return profile;
}

async function measureOne(profile) {
  if (!existsSync(ENTRY)) fail(`${ENTRY}: missing; run \`npm run js:build\` first`);
  const generate = await loadTsModule(join(REPO_ROOT, "assessment", "generate.ts"));
  const metrics = await loadTsModule(join(REPO_ROOT, "assessment", "adapters", "performance.ts"));
  const input = generate.generateWorkloadInput(profile);
  const chunks = metrics.partitionInput(input, profile.chunkProfile);
  const inputBytes = Buffer.byteLength(input);
  const inputLimit = inputBytes + 1;
  const api = await import(pathToFileURL(ENTRY).href);

  const initialization = await metrics.measureAsyncOperation(
    () => performance.now(),
    () => api.initialize(),
  );
  // Which artifact served this sample: the loader can fall back from the addon to WebAssembly.
  const artifact = api.artifact();

  processInput(api, input, chunks, profile.chunkProfile, inputLimit);
  const baseline = process.memoryUsage();
  const processing = metrics.measureOperation(
    () => performance.now(),
    () => processInput(api, input, chunks, profile.chunkProfile, inputLimit),
  );
  const after = process.memoryUsage();
  if (!Number.isSafeInteger(processing.value)) fail("processing did not complete");
  if (processing.elapsedMs <= 0) fail("processing duration was not positive");
  return {
    artifact,
    initializationMs: initialization.elapsedMs,
    processingMs: processing.elapsedMs,
    throughputBytesPerSecond: inputBytes / (processing.elapsedMs / 1000),
    memory: {
      nodeHeap: { baselineBytes: baseline.heapUsed, maximumObservedBytes: Math.max(baseline.heapUsed, after.heapUsed) },
      nodeRss: { baselineBytes: baseline.rss, maximumObservedBytes: Math.max(baseline.rss, after.rss) },
      nodeExternal: { baselineBytes: baseline.external, maximumObservedBytes: Math.max(baseline.external, after.external) },
    },
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const profile = await loadProfile(options.profile);
  if (options.sample) {
    process.stdout.write(`${JSON.stringify(await measureOne(profile))}\n`);
    return;
  }

  const samples = [];
  const addonLink = await linkAddon(options.addonDir);
  try {
    for (let run = 0; run < options.runs; run += 1) {
      const output = execFileSync(process.execPath, [fileURLToPath(import.meta.url), "--sample", "--profile", profile.id], {
        cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 1024 * 1024,
      });
      samples.push(JSON.parse(output));
    }
  } finally {
    if (addonLink !== undefined) rmSync(addonLink, { recursive: true, force: true });
  }
  let resolvedArtifact;
  try {
    resolvedArtifact = agreedResolvedArtifact(samples.map((sample) => sample.artifact));
  } catch (error) {
    fail(`node performance: ${error.message}`);
  }
  const metrics = await loadTsModule(join(REPO_ROOT, "assessment", "adapters", "performance.ts"));
  const unavailable = (reason) => metrics.unavailableMemory(reason, "No samples were available.");
  const performanceMetrics = {
    initialization: metrics.summarizeDistribution(samples.map((sample) => sample.initializationMs), "milliseconds"),
    processing: metrics.summarizeDistribution(samples.map((sample) => sample.processingMs), "milliseconds"),
    throughput: metrics.summarizeDistribution(samples.map((sample) => sample.throughputBytesPerSecond), "bytes-per-second"),
    memory: {
      nodeHeap: metrics.availableMemory(samples.map((sample) => sample.memory.nodeHeap), BOUNDARY_LIMIT),
      nodeRss: metrics.availableMemory(samples.map((sample) => sample.memory.nodeRss), BOUNDARY_LIMIT),
      nodeExternal: metrics.availableMemory(samples.map((sample) => sample.memory.nodeExternal), `${BOUNDARY_LIMIT} External memory can overlap RSS and must not be summed with it.`),
      browserJsHeap: unavailable("The Node process does not expose a browser JavaScript heap."),
      wasmLinearMemory: unavailable("The Node N-API surface does not use WebAssembly linear memory."),
      pythonHeap: unavailable("The Node process does not run inside a Python allocator."),
      processRss: unavailable("Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice."),
      streamingBuffer: unavailable("The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size."),
    },
  };
  const result = await buildAndEmitPerformanceResult({
    surface: "node", profileId: profile.id, performance: performanceMetrics,
    provenance: {
      commit: gitCommit(),
      artifactIdentity: `@redact-secret/core@${readPackageVersion(PACKAGE_JSON)}`,
      corpusVersion: "1", corpusHash: workloadProfilesHash(),
      os: hostOs(), cpu: hostCpu(), runtime: `node-${process.version.slice(1)}`,
      command: `node scripts/assessment-node-performance.mjs ${process.argv.slice(2).join(" ")}`.trim(),
      resolvedArtifact,
    },
    jsonOut: options.jsonOut, markdownOut: options.markdownOut,
  });
  console.error(`node performance: ${result.performance.processing.samples.length} run(s), median ${result.performance.processing.median} ms, artifact ${resolvedArtifact}`);
}

await main();
