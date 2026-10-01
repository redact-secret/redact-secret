/** External performance and memory runner for an installed Python package. */
import { join } from "node:path";

import { buildAndEmitPerformanceResult, loadAssessmentSchema } from "./lib/assessment-emit.mjs";
import {
  gitCommit,
  hostCpu,
  hostOs,
  loadWorkloadProfiles,
  REPO_ROOT,
  workloadProfilesHash,
} from "./lib/assessment-provenance.mjs";
import { runPythonWorker } from "./lib/assessment-python.mjs";
import { loadTsModule } from "./lib/load-ts-module.mjs";

const DEFAULT_PROFILE = "scale-logs-small-whole";
const PYTHON_HEAP_LIMIT =
  "Measured by tracemalloc during a separate untimed processing pass; it observes Python allocations made after tracing starts, not the interpreter's pre-existing heap or native Rust allocations.";
const PROCESS_RSS_LIMIT =
  "Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory.";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArguments(argv) {
  const options = { python: "python3", profile: DEFAULT_PROFILE, runs: 10, jsonOut: "-", markdownOut: undefined };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === "--python") {
      options.python = value;
      index += 1;
    } else if (argument === "--profile") {
      options.profile = value;
      index += 1;
    } else if (argument === "--runs") {
      options.runs = Number(value);
      index += 1;
    } else if (argument === "--json-out") {
      options.jsonOut = value;
      index += 1;
    } else if (argument === "--markdown-out") {
      options.markdownOut = value;
      index += 1;
    } else fail(`unknown argument: ${argument}`);
  }
  if (typeof options.python !== "string" || options.python.length === 0) fail("--python requires a value");
  if (!Number.isSafeInteger(options.runs) || options.runs < 2 || options.runs > 100)
    fail("--runs must be an integer from 2 through 100");
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const schema = await loadAssessmentSchema();
  const document = loadWorkloadProfiles();
  const profiles = schema.validateAssessmentWorkloadProfiles(document.profiles);
  if (profiles.length !== document.profileCount) fail("workload profile count does not match");
  const profile = profiles.find((candidate) => candidate.id === options.profile);
  if (profile === undefined || profile.purpose !== "scale") fail(`${options.profile}: unknown scale profile`);

  const generate = await loadTsModule(join(REPO_ROOT, "assessment", "generate.ts"));
  const metrics = await loadTsModule(join(REPO_ROOT, "assessment", "adapters", "performance.ts"));
  const input = generate.generateWorkloadInput(profile);
  const chunks = metrics.partitionInput(input, profile.chunkProfile);
  const samples = [];
  try {
    for (let run = 0; run < options.runs; run += 1) {
      samples.push(
        runPythonWorker(options.python, "performance-sample", {
          input,
          chunks,
          chunkProfile: profile.chunkProfile,
        }),
      );
    }
  } catch {
    fail("Python performance evaluation FAILED before completing");
  }
  if (samples.some((sample) => sample.version !== samples[0]?.version || sample.runtime !== samples[0]?.runtime)) {
    fail("Python performance evaluation changed artifact or runtime between repetitions");
  }
  const unavailable = (reason) => metrics.unavailableMemory(reason, "No samples were available.");
  const rssSamples = samples.flatMap((sample) => (sample.processRss === null ? [] : [sample.processRss]));
  const memory = {
    nodeHeap: unavailable("The Python process does not run inside a Node.js heap."),
    nodeRss: unavailable(
      "The Python process is not a Node.js process; its whole-process RSS is reported as processRss.",
    ),
    nodeExternal: unavailable("The Python process has no Node external-memory category."),
    browserJsHeap: unavailable("The Python process does not run inside a browser JavaScript heap."),
    wasmLinearMemory: unavailable("The Python package uses a native extension, not WebAssembly linear memory."),
    pythonHeap: metrics.availableMemory(
      samples.map((sample) => sample.pythonHeap),
      PYTHON_HEAP_LIMIT,
    ),
    processRss:
      rssSamples.length === samples.length
        ? metrics.availableMemory(rssSamples, PROCESS_RSS_LIMIT)
        : unavailable("Portable process RSS sampling is unavailable on this operating system."),
    streamingBuffer: unavailable(
      "The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.",
    ),
  };
  const performance = {
    initialization: metrics.summarizeDistribution(
      samples.map((sample) => sample.initializationMs),
      "milliseconds",
    ),
    processing: metrics.summarizeDistribution(
      samples.map((sample) => sample.processingMs),
      "milliseconds",
    ),
    throughput: metrics.summarizeDistribution(
      samples.map((sample) => sample.throughputBytesPerSecond),
      "bytes-per-second",
    ),
    memory,
  };
  const first = samples[0];
  const result = await buildAndEmitPerformanceResult({
    surface: "python",
    profileId: profile.id,
    performance,
    provenance: {
      commit: gitCommit(),
      artifactIdentity: `redact-secret==${first.version}`,
      corpusVersion: "1",
      corpusHash: workloadProfilesHash(),
      os: hostOs(),
      cpu: hostCpu(),
      runtime: first.runtime,
      command: `node scripts/assessment-python-performance.mjs ${process.argv.slice(2).join(" ")}`.trim(),
    },
    jsonOut: options.jsonOut,
    markdownOut: options.markdownOut,
  });
  console.error(
    `python performance: ${result.performance.processing.samples.length} run(s), median ${result.performance.processing.median} ms`,
  );
}

await main();
