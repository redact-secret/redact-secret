/**
 * `@redact-secret/core`: deterministic secret detection and redaction, one
 * API across Node.js and the browser.
 *
 * The package's `exports` map selects the N-API addon on Node and the
 * WebAssembly build in the browser (`decision-define-runtime-bindings`).
 * Every runtime uses the same contract:
 *
 * ```ts
 * import { initialize, scanAndRedact } from "@redact-secret/core";
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
 * On Node, `initialize()` normally loads the native addon; it falls back to
 * a WebAssembly artifact when the addon cannot produce a usable binding
 * (`decision-add-node-wasm-fallback`). {@link artifact} reports which one
 * actually loaded.
 *
 * Built-in detectors all run in Rust; there is no custom detector callback in
 * this API, and no internal module of this package is reachable through its
 * `exports` map.
 *
 * Byte streams are served by the two adapter subpaths,
 * `@redact-secret/core/node-stream` and
 * `@redact-secret/core/web-stream`, each of which drives one incremental
 * session per stream. This root module never resolves a `node:` module.
 */

import { runtime } from "./session.js";

/**
 * Loads this runtime's binding and prepares it for use.
 *
 * Idempotent: the artifact is loaded at most once no matter how many callers
 * await it. A rejected attempt is not cached, so a caller may retry. Rejects
 * with `INITIALIZATION_FAILED` when the artifact is missing, unusable, or
 * built from a different product version than this package.
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
 * The detector profile this entry point is built from: the full 42-detector
 * registry. `@redact-secret/core/common` exports the same constant as
 * `"common"` (`decision-define-detector-profile-and-pack-contract`).
 */
export const PROFILE = "full" as const;
