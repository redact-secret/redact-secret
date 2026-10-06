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
 * `await initialize()` must succeed before any synchronous operation.
 * Equivalent PII selections are idempotent; a different later or concurrent
 * selection rejects with `PII_ACTIVATION_CONFLICT`.
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
 * Equivalent calls share one load. A rejected attempt is not cached, so a
 * caller may retry. Invalid or unavailable selectors and conflicting
 * activation use their fixed PII error codes; artifact failures use
 * `INITIALIZATION_FAILED`.
 */
export const initialize = runtime.initialize;
/** Returns the canonical credentials/PII activation identity. */
export const piiActivation = runtime.piiActivation;
/**
 * Reports whether the core is initialized and its public activation, without
 * loading, initializing or reconfiguring anything. Takes no input, never
 * throws, and returns fixed values only (no exception text, path or
 * secret-derived value). Absent in releases before this addition.
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
 * Compares what one to four policies (the default, a declarative action
 * policy, or a legacy callback policy) would choose for the findings `input`
 * yields, over one detection pass, and says why: the deciding rule or the
 * default. A preview, never enforcement: it returns no text and changes no
 * state of `scan`, `redact` or an incremental session.
 *
 * Whole-input only. It takes one string, so a stream, a chunk or an
 * incremental session cannot be compared, and a key that suggests one is
 * `INVALID_OPTIONS`. A callback policy is called once per finding, in order,
 * one side at a time, so a callback with state or side effects advances them.
 * A failing callback fails the whole comparison with `POLICY_FAILURE` (or
 * `INVALID_POLICY_ACTION` for a bad return) and no partial result.
 *
 * The result holds safe finding metadata and decisions, plus each action
 * policy side's `documentSha256`; it holds no input byte or matched value.
 */
export const compareActionPolicies = runtime.compareActionPolicies;

/** Opens a bounded incremental session over text supplied in chunks. */
export const createIncrementalSanitizer = runtime.createIncrementalSanitizer;

/**
 * The core's default policy, as a policy object: `evaluate` returns the
 * action the default evaluation gives that finding, so a callback that wants
 * "mine, else the default" never copies the default table. It works as a
 * whole-input `policy` and as an incremental session `policy`, and it needs a
 * successful `initialize()` like every other operation. A declarative
 * `actionPolicy` with an empty `rules` array is the same behavior as data.
 */
export const defaultPolicy = runtime.defaultPolicy;

export * from "./entry-core.js";

/**
 * The detector profile this entry point is built from: the full 42-detector
 * registry. `@redact-secret/core/common` exports the same constant as
 * `"common"` (`decision-define-detector-profile-and-pack-contract`).
 */
export const PROFILE = "full" as const;
