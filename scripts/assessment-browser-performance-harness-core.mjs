/**
 * The profile-agnostic body of the browser performance measurement harness.
 *
 * `assessment-browser-performance-harness.mjs` and
 * `assessment-browser-performance-harness-common.mjs` are the two thin,
 * per-profile entry points that import their own package entry
 * (`@redact-secret/core` or `@redact-secret/core/common`) with a literal
 * specifier — required so a bundler resolves and includes the right compiled
 * artifact — and hand the resulting bindings to `measure` here
 * (`decision-define-detector-profile-and-pack-contract`).
 */
import { generateWorkloadInput } from "../assessment/generate.js";
import {
  measureAsyncOperation, measureOperation, partitionInput,
} from "../assessment/adapters/performance.js";

function processInput(api, input, chunks, chunkProfile, inputLimit) {
  const { createIncrementalSanitizer, scanAndRedact } = api;
  if (chunkProfile === "whole") {
    const result = scanAndRedact(input);
    return result.text.length + result.findings.length;
  }
  const session = createIncrementalSanitizer({
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

function browserHeapBytes() {
  const value = globalThis.performance.memory?.usedJSHeapSize;
  return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

/** Runs one measurement against `api` (`{ createIncrementalSanitizer, initialize, scanAndRedact }`). */
export async function measure(profile, api) {
  const input = generateWorkloadInput(profile);
  const inputBytes = new TextEncoder().encode(input).length;
  const inputLimit = inputBytes + 1;
  const chunks = partitionInput(input, profile.chunkProfile);

  const initialization = await measureAsyncOperation(
    () => performance.now(),
    () => api.initialize(),
  );
  processInput(api, input, chunks, profile.chunkProfile, inputLimit);

  const baselineHeap = browserHeapBytes();
  const processing = measureOperation(
    () => performance.now(),
    () => processInput(api, input, chunks, profile.chunkProfile, inputLimit),
  );
  const afterHeap = browserHeapBytes();
  if (!Number.isSafeInteger(processing.value)) throw new Error("processing did not complete");
  if (processing.elapsedMs <= 0) throw new Error("processing duration was not positive");
  return {
    initializationMs: initialization.elapsedMs,
    processingMs: processing.elapsedMs,
    throughputBytesPerSecond: inputBytes / (processing.elapsedMs / 1000),
    browserHeap: baselineHeap === undefined || afterHeap === undefined ? undefined : {
      baselineBytes: baselineHeap,
      maximumObservedBytes: Math.max(baselineHeap, afterHeap),
    },
  };
}
