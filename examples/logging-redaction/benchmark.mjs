/**
 * Measures the per-call overhead `createRedactingLogMethodWith` adds to a
 * pino log call, for a 1 KB and a 64 KB message, against the real,
 * release-built `@redact-secret/core` (issue #328's "measured per-call
 * cost in a release build, not a debug build"). Requires the native addon
 * to be built in release mode first:
 *
 *   cd bindings/node && npm install && npm run build
 *   npm run js:build
 *   node examples/logging-redaction/benchmark.mjs
 *
 * Prints median and p95 milliseconds per call over many iterations, after
 * a warmup phase, so JIT warmup and first-call initialization don't skew
 * the result. Numbers are machine-dependent; this script, not a single
 * frozen number, is the artifact worth trusting.
 */

import { initialize, scanAndRedact } from "@redact-secret/core";

import { createRedactingLogMethodWith } from "./pino-hook.mjs";

function percentile(sortedMs, p) {
  const index = Math.min(sortedMs.length - 1, Math.floor(sortedMs.length * p));
  return sortedMs[index];
}

function benchmark(hook, message, { warmup, iterations }) {
  const method = () => {};
  const args = [message];
  for (let i = 0; i < warmup; i += 1) hook(args, method, 30);

  const samplesMs = new Array(iterations);
  for (let i = 0; i < iterations; i += 1) {
    const start = process.hrtime.bigint();
    hook(args, method, 30);
    const end = process.hrtime.bigint();
    samplesMs[i] = Number(end - start) / 1e6;
  }
  samplesMs.sort((a, b) => a - b);
  return {
    medianMs: percentile(samplesMs, 0.5),
    p95Ms: percentile(samplesMs, 0.95),
  };
}

async function main() {
  await initialize();
  const hook = createRedactingLogMethodWith(scanAndRedact);

  const cases = [
    { label: "1 KB message", bytes: 1024 },
    { label: "64 KB message", bytes: 64 * 1024 },
  ];

  for (const { label, bytes } of cases) {
    // Plain filler text with no findings, matching the issue's request to
    // measure the no-secret-found path most log lines take.
    const message = "the quick brown fox jumps over the lazy dog. ".repeat(Math.ceil(bytes / 46)).slice(0, bytes);
    const { medianMs, p95Ms } = benchmark(hook, message, { warmup: 200, iterations: 2000 });
    console.log(`${label}: median ${medianMs.toFixed(4)} ms/call, p95 ${p95Ms.toFixed(4)} ms/call`);
  }
}

main();
