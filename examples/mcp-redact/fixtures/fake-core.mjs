/**
 * The two core operations `@redact-secret/adapter-ai-context` injects,
 * faked for the golden-path tests: `scanAndRedact` is `fakeScanAndRedact`
 * (`fake-scanner.mjs`'s rules) plus the core's whole-input byte limit, which
 * it enforces before scanning with the core's own `INPUT_LIMIT_EXCEEDED`
 * code; `createIncrementalSanitizer` is `fake-incremental-sanitizer.mjs`.
 * A `BOOM` input throws an error with no code, so it maps to `core_error`
 * with no code, as any non-core error does.
 */

import { createFakeIncrementalSanitizer } from "./fake-incremental-sanitizer.mjs";
import { fakeScanAndRedact } from "./fake-scanner.mjs";

function coded(code) {
  return Object.assign(new Error(`fake core failure: ${code}`), { code });
}

export const fakeCore = Object.freeze({
  scanAndRedact(text, options) {
    const limits = options?.limits;
    if (limits !== undefined && new TextEncoder().encode(text).length > limits.maxInputBytes) {
      throw coded("INPUT_LIMIT_EXCEEDED");
    }
    return fakeScanAndRedact(text);
  },
  createIncrementalSanitizer(options) {
    return createFakeIncrementalSanitizer(options.limits);
  },
});

/** A core whose every call fails the way an uninitialized core does. */
export const uninitializedCore = Object.freeze({
  scanAndRedact() {
    throw coded("NOT_INITIALIZED");
  },
  createIncrementalSanitizer() {
    throw coded("NOT_INITIALIZED");
  },
});
