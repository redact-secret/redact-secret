/**
 * `@redact-secret/core/common`: the opt-in `common` detector profile, the
 * same deterministic secret detection and redaction API as
 * `@redact-secret/core` across Node.js and the browser, built from the
 * 6-detector structural/contextual subset instead of the full 42
 * (`decision-define-detector-profile-and-pack-contract`).
 *
 * The package's `exports` map selects the N-API addon on Node and the
 * WebAssembly build in the browser (`decision-define-runtime-bindings`).
 * Every runtime uses the same contract:
 *
 * ```ts
 * import { initialize, scanAndRedact } from "@redact-secret/core/common";
 *
 * await initialize();
 * const { text, findings } = scanAndRedact(input);
 * ```
 *
 * `await initialize()` must succeed exactly once before any synchronous
 * operation; calling it again is free. Node's own loading has nothing to
 * await, but the call stays part of the contract so the usage model does not
 * vary by runtime.
 *
 * Every range this module reports is a `[start, end)` pair of UTF-16
 * code-unit offsets ({@link RANGE_UNIT}), and every finding it returns is
 * frozen. Every failure is a {@link SecretScanError} carrying nothing but a
 * fixed code and message.
 *
 * This entry point's smaller registry trades detection coverage for transfer
 * size: it finds only bare, structurally- or contextually-identifiable
 * secrets and never the vendor-specific findings the full profile's other 36
 * detectors add, so it has a strictly higher false-negative rate on
 * vendor-shaped secrets than `@redact-secret/core`.
 *
 * Built-in detectors all run in Rust; there is no custom detector callback in
 * this API, and no internal module of this package is reachable through its
 * `exports` map.
 *
 * The `createNodeStreamSanitizer` and `createWebStreamSanitizer` factories of
 * `@redact-secret/core/node-stream` and `@redact-secret/core/web-stream`
 * always open a `full` session. For a `common` byte stream, pass a session
 * from this module's `createIncrementalSanitizer` to the `NodeStreamSanitizer`
 * or `WebStreamSanitizer` class instead. This module never resolves a `node:`
 * module.
 */

import { runtime } from "./session-common.js";

/**
 * Loads this runtime's binding and prepares it for use.
 *
 * Idempotent: the artifact is loaded at most once no matter how many callers
 * await it. A rejected attempt is not cached, so a caller may retry. Rejects
 * with `INITIALIZATION_FAILED` when the artifact is missing, unusable, or
 * built from a different product version or detector profile than this
 * package.
 */
export const initialize = runtime.initialize;

/**
 * Which artifact `initialize()` loaded: `"addon"` (the native N-API addon)
 * or `"wasm"` (the WebAssembly fallback engaged when the addon could not
 * produce a usable binding, `decision-add-node-wasm-fallback`; always
 * `"wasm"` in a browser). Requires `initialize()` to have already succeeded,
 * the same as every other operation here.
 */
export const artifact = runtime.artifact;

/** Scans `input` and returns every finding, in input order. */
export const scan = runtime.scan;

/**
 * Replaces the `redact` and `block` findings in `input` with placeholders,
 * leaving `warn` and `allow` findings untouched.
 *
 * `findings` must be the findings {@link scan} returned for this same input.
 */
export const redact = runtime.redact;

/** Scans and redacts in one call, so text and findings cannot disagree. */
export const scanAndRedact = runtime.scanAndRedact;

/** Opens a bounded incremental session over text supplied in chunks. */
export const createIncrementalSanitizer = runtime.createIncrementalSanitizer;

export * from "./entry-core.js";

/**
 * The detector profile this entry point is built from: the 6-detector
 * structural/contextual subset. `@redact-secret/core` exports the same
 * constant as `"full"` (`decision-define-detector-profile-and-pack-contract`).
 */
export const PROFILE = "common" as const;
