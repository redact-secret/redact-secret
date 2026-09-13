/**
 * External performance and memory runner for the real, built `redact-secret`
 * CLI binary, using the same generated scale workload profiles as every
 * other surface's performance runner.
 *
 * Every repetition spawns two fresh processes: one running `--version` alone
 * — nothing but process startup, argument parsing, and exit — timed as
 * `initialization`, and one running `--json` against the generated input,
 * timed as `processing`. Unlike the in-process Node, Python, and Rust
 * runners, a CLI `processing` sample is necessarily *process-inclusive*: it
 * still contains the same process-startup cost `initialization` measures on
 * its own, because a subprocess boundary offers no way to time only the
 * library work inside it without the product exposing new instrumentation.
 * `processing` here must not be read as, or compared directly against,
 * another surface's steady-state processing number; `initialization` is
 * reported so a reader can see the startup cost it does *not* subtract out.
 *
 * Process memory is sampled with a separate, untimed `/usr/bin/time`-wrapped
 * repetition of the same `--json` invocation, on the same terms
 * `assessment-python-performance.mjs` samples Python memory in a separate
 * untimed pass so sampling overhead cannot contaminate the processing
 * distribution. It reports the whole child process's maximum resident set
 * size, unavailable where no such portable wrapper exists.
 *
 * Usage:
 *
 *     cargo build --release -p redact-secret-cli
 *     node scripts/assessment-cli-performance.mjs --profile scale-logs-small-whole --runs 10
 *     node scripts/assessment-cli-performance.mjs --binary target/release/redact-secret --json-out out/cli.json --markdown-out out/cli.md
 */
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { buildAndEmitPerformanceResult, loadAssessmentSchema } from "./lib/assessment-emit.mjs";
import { cliVersion, resolveCliBinary, runCliProcess, rustcVersion } from "./lib/assessment-cli.mjs";
import { loadTsModule } from "./lib/load-ts-module.mjs";
import {
  gitCommit, hostCpu, hostOs, loadWorkloadProfiles, REPO_ROOT, workloadProfilesHash,
} from "./lib/assessment-provenance.mjs";

const DEFAULT_PROFILE = "scale-logs-small-whole";
const PROCESS_RSS_LIMIT = "A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory.";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = { binary: undefined, profile: DEFAULT_PROFILE, runs: 10, jsonOut: "-", markdownOut: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--binary") options.binary = argv[(index += 1)];
    else if (argument === "--profile") options.profile = argv[(index += 1)];
    else if (argument === "--runs") options.runs = Number(argv[(index += 1)]);
    else if (argument === "--json-out") options.jsonOut = argv[(index += 1)];
    else if (argument === "--markdown-out") options.markdownOut = argv[(index += 1)];
    else fail(`unknown argument: ${argument}`);
  }
  if (!Number.isSafeInteger(options.runs) || options.runs < 2 || options.runs > 100) {
    fail("--runs must be an integer from 2 through 100");
  }
  return options;
}

/** The `--json`-wrapping process-memory tool for this platform, or `undefined` if none is known. */
function rssWrapper() {
  if (process.platform === "darwin") return { command: "/usr/bin/time", prefixArgs: ["-l"] };
  if (process.platform === "linux") return { command: "/usr/bin/time", prefixArgs: ["-v"] };
  return undefined;
}

function parseMaxRssBytes(stderrText) {
  const macos = stderrText.match(/(\d+)\s+maximum resident set size/);
  if (macos !== null) return Number(macos[1]);
  const linux = stderrText.match(/Maximum resident set size \(kbytes\):\s*(\d+)/);
  if (linux !== null) return Number(linux[1]) * 1024;
  return undefined;
}

function measureRssBytes(wrapper, binary, args, stdinBuffer) {
  if (wrapper === undefined) return undefined;
  const result = spawnSync(wrapper.command, [...wrapper.prefixArgs, binary, ...args], {
    input: stdinBuffer, maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error !== undefined || ![0, 1].includes(result.status)) return undefined;
  return parseMaxRssBytes(result.stderr.toString("utf8"));
}

function measureOne(binary, wrapper, inputBuffer, inputBytes) {
  const initStart = performance.now();
  const initResult = spawnSync(binary, ["--version"]);
  const initializationMs = performance.now() - initStart;
  if (initResult.status !== 0) fail("CLI performance evaluation FAILED before completing (--version)");

  const processStart = performance.now();
  const processResult = spawnSync(binary, ["--json"], { input: inputBuffer, maxBuffer: 64 * 1024 * 1024 });
  const processingMs = performance.now() - processStart;
  if (![0, 1].includes(processResult.status)) fail("CLI performance evaluation FAILED before completing (processing)");
  JSON.parse(processResult.stdout.toString("utf8"));
  if (processingMs <= 0) fail("processing duration was not positive");

  return {
    initializationMs,
    processingMs,
    throughputBytesPerSecond: inputBytes / (processingMs / 1000),
    processRssBytes: measureRssBytes(wrapper, binary, ["--json"], inputBuffer),
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const binary = resolveCliBinary(options.binary);
  const invoke = (args, stdinBuffer) => runCliProcess(binary, args, stdinBuffer);
  const version = cliVersion(invoke);

  const schema = await loadAssessmentSchema();
  const document = loadWorkloadProfiles();
  const profiles = schema.validateAssessmentWorkloadProfiles(document.profiles);
  if (profiles.length !== document.profileCount) fail("workload profile count does not match");
  const profile = profiles.find((candidate) => candidate.id === options.profile);
  if (profile === undefined || profile.purpose !== "scale") fail(`${options.profile}: unknown scale profile`);

  const generate = await loadTsModule(join(REPO_ROOT, "assessment", "generate.ts"));
  const metrics = await loadTsModule(join(REPO_ROOT, "assessment", "adapters", "performance.ts"));
  const input = generate.generateWorkloadInput(profile);
  const inputBuffer = Buffer.from(input, "utf8");
  const inputBytes = inputBuffer.length;

  const wrapper = rssWrapper();
  const samples = [];
  for (let run = 0; run < options.runs; run += 1) {
    samples.push(measureOne(binary, wrapper, inputBuffer, inputBytes));
  }

  const unavailable = (reason) => metrics.unavailableMemory(reason, "No samples were available.");
  const rssSamples = samples.flatMap((sample) => typeof sample.processRssBytes === "number" ? [sample.processRssBytes] : []);
  const memoryMetrics = {
    nodeHeap: unavailable("The CLI is a native process, not a Node.js process."),
    nodeRss: unavailable("The CLI is a native process, not a Node.js process."),
    nodeExternal: unavailable("The CLI is a native process, not a Node.js process."),
    browserJsHeap: unavailable("The CLI is a native process, not a browser JavaScript environment."),
    wasmLinearMemory: unavailable("The CLI is a native process and does not use WebAssembly linear memory."),
    pythonHeap: unavailable("The CLI is a native process, not a Python allocator."),
    processRss: rssSamples.length === samples.length
      ? metrics.availableMemory(
        rssSamples.map((bytes) => ({ baselineBytes: 0, maximumObservedBytes: bytes })),
        PROCESS_RSS_LIMIT,
      )
      : unavailable("No portable whole-process resident-memory sampling tool is available on this platform."),
    streamingBuffer: unavailable(
      "The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.",
    ),
  };
  const performanceMetrics = {
    initialization: metrics.summarizeDistribution(samples.map((sample) => sample.initializationMs), "milliseconds"),
    processing: metrics.summarizeDistribution(samples.map((sample) => sample.processingMs), "milliseconds"),
    throughput: metrics.summarizeDistribution(samples.map((sample) => sample.throughputBytesPerSecond), "bytes-per-second"),
    memory: memoryMetrics,
  };

  const result = await buildAndEmitPerformanceResult({
    surface: "cli", profileId: profile.id, performance: performanceMetrics,
    provenance: {
      commit: gitCommit(), artifactIdentity: `redact-secret@${version.version}`,
      corpusVersion: "1", corpusHash: workloadProfilesHash(), os: hostOs(), cpu: hostCpu(),
      runtime: rustcVersion(),
      command: `node scripts/assessment-cli-performance.mjs ${process.argv.slice(2).join(" ")}`.trim(),
    },
    jsonOut: options.jsonOut, markdownOut: options.markdownOut,
  });
  console.error(
    `cli performance: ${result.performance.processing.samples.length} run(s), ` +
      `process-inclusive processing median ${result.performance.processing.median} ms, ` +
      `process-startup-only initialization median ${result.performance.initialization.median} ms`,
  );
}

await main();
