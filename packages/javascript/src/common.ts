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
 * `await initialize()` must succeed before any synchronous operation.
 * Equivalent PII selections are idempotent; a different later or concurrent
 * selection rejects with `PII_ACTIVATION_CONFLICT`.
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
 * Equivalent calls share one load. A rejected attempt is not cached, so a
 * caller may retry. Invalid or unavailable selectors and conflicting
 * activation use their fixed PII error codes; artifact or profile failures
 * use `INITIALIZATION_FAILED`.
 */
export const initialize = runtime.initialize;
/** Returns the canonical credentials/PII activation identity. */
export const piiActivation = runtime.piiActivation;
/**
 * Reports whether the `common` runtime is initialized and its public
 * activation, without loading, initializing or reconfiguring anything. Takes
 * no input, never throws, and returns fixed values only.
 */
export const status = runtime.status;

/**
 * Which artifact `initialize()` loaded: `"addon"` (the native N-API addon)
 * or `"wasm"` (the WebAssembly fallback engaged when the addon could not
 * produce a usable binding, `decision-add-node-wasm-fallback`; always
 * `"wasm"` in a browser). Requires `initialize()` to have already succeeded,
 * the same as every other operation here.
 */
export const artifact = runtime.artifact;

/**
 * The loaded `common` artifact's `artifact-manifest/v1` document (see
 * `@redact-secret/core`'s `artifactManifest`). Its `variant` is `"common"`
 * and the `full` built-in ids it lacks are listed in `notIncluded`.
 */
export const artifactManifest = runtime.artifactManifest;

/**
 * Resolves a configuration request over the `common` artifact's defaults (see
 * `@redact-secret/core`'s `resolveConfig`). A `provider` detector id is
 * `DETECTOR_NOT_INCLUDED` here, never satisfied by loading `full`.
 */
export const resolveConfig = runtime.resolveConfig;

/**
 * The snapshot of the configuration this `common` runtime is fixed to (see
 * `@redact-secret/core`'s `describeConfig`).
 */
export const describeConfig = runtime.describeConfig;

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

/**
 * Compares what one to four policies would choose for the findings `input`
 * yields, over one detection pass, against the `common` detector set (see
 * `@redact-secret/core`'s `compareActionPolicies`). Whole-input only.
 */
export const compareActionPolicies = runtime.compareActionPolicies;

/**
 * Compares detection configurations over one input against the `common`
 * artifact: each side an independent preview pass over a temporary registry
 * (see `@redact-secret/core`'s `compareConfigurations`). Whole-input only.
 */
export const compareConfigurations = runtime.compareConfigurations;

/** Opens a bounded incremental session over text supplied in chunks. */
export const createIncrementalSanitizer = runtime.createIncrementalSanitizer;

/**
 * The core's default policy, as a policy object (see
 * `@redact-secret/core`'s `defaultPolicy`). The default action does not
 * depend on the detector profile.
 */
export const defaultPolicy = runtime.defaultPolicy;

export * from "./entry-core.js";

/**
 * The detector profile this entry point is built from: the 6-detector
 * structural/contextual subset. `@redact-secret/core` exports the same
 * constant as `"full"` (`decision-define-detector-profile-and-pack-contract`).
 */
export const PROFILE = "common" as const;
