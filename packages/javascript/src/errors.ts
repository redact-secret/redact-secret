/**
 * The single sanitized error type this package throws.
 *
 * Every code and message below is fixed and input-free: no error carries the
 * scanned input, a matched value, a placeholder, or a failing callback's own
 * message (`decision-define-runtime-bindings`). Seventeen codes come from the
 * Rust core — including `FINDING_LIMIT_EXCEEDED` and the broadened
 * `INPUT_LIMIT_EXCEEDED`/`INVALID_LIMITS`, shared between incremental
 * sessions and whole-input `scan`/`redact`/`scanAndRedact`
 * (`decision-bound-whole-input-operations-by-default`); `NOT_INITIALIZED` and
 * `INITIALIZATION_FAILED` are produced by the
 * binding layer, `INVALID_CHUNK` and `INVALID_UTF8` by the stream adapters,
 * `UNPAIRED_SURROGATE` by this package's own runtime-neutral input check. The
 * package normalizes all of them into the same class so
 * `instanceof SecretScanError` holds on every runtime and every subpath.
 *
 * `UNPAIRED_SURROGATE` resolves `B/F-10`
 * (`docs/audits/deferred-quality-backlog.md`): a JavaScript string may hold a
 * lone UTF-16 surrogate, which has no UTF-8 representation, so it cannot
 * cross into the Rust core's `&str` without either a silent `U+FFFD`
 * substitution (which would make `redact`'s output a transcoded copy, not the
 * caller's input with only findings replaced) or a stable rejection. This
 * package rejects, once, in `runtime.ts`'s `requireString`, before the string
 * reaches either binding — so the error and this check are identical on the
 * Node and browser runtimes by construction rather than by parallel
 * implementation.
 */

export type SecretScanErrorCode =
  | "INVALID_INPUT"
  | "INVALID_OPTIONS"
  | "INVALID_DETECTOR"
  | "DETECTOR_FAILURE"
  | "INVALID_CANDIDATE"
  | "POLICY_FAILURE"
  | "INVALID_POLICY_ACTION"
  | "INVALID_FINDINGS"
  | "PLACEHOLDER_FAILURE"
  | "INVALID_PLACEHOLDER"
  | "INVALID_LIMITS"
  | "INPUT_LIMIT_EXCEEDED"
  | "FINDING_LIMIT_EXCEEDED"
  | "BUFFER_LIMIT_EXCEEDED"
  | "TOKEN_LIMIT_EXCEEDED"
  | "MULTILINE_LIMIT_EXCEEDED"
  | "INVALID_STATE"
  | "INVALID_RULESET"
  | "NOT_INITIALIZED"
  | "INITIALIZATION_FAILED"
  | "INVALID_CHUNK"
  | "INVALID_UTF8"
  | "UNPAIRED_SURROGATE";

/** The fixed message for every code, mirroring the core's own strings. */
const ERROR_MESSAGES: Readonly<Record<SecretScanErrorCode, string>> = {
  INVALID_INPUT: "Secret scan input must be a string.",
  INVALID_OPTIONS: "Secret scan options are invalid.",
  INVALID_DETECTOR: "Invalid detector registration.",
  DETECTOR_FAILURE: "A secret detector failed.",
  INVALID_CANDIDATE: "A secret detector returned an invalid candidate.",
  POLICY_FAILURE: "The secret policy failed.",
  INVALID_POLICY_ACTION: "The secret policy returned an invalid action.",
  INVALID_FINDINGS: "Redaction findings are invalid.",
  PLACEHOLDER_FAILURE: "The placeholder formatter failed.",
  INVALID_PLACEHOLDER: "The placeholder formatter returned an invalid value.",
  INVALID_LIMITS: "Secret scan limits are invalid.",
  INPUT_LIMIT_EXCEEDED: "Secret scan input limit exceeded.",
  FINDING_LIMIT_EXCEEDED: "Secret scan finding limit exceeded.",
  BUFFER_LIMIT_EXCEEDED: "Incremental sanitizer buffer limit exceeded.",
  TOKEN_LIMIT_EXCEEDED: "Incremental sanitizer token limit exceeded.",
  MULTILINE_LIMIT_EXCEEDED: "Incremental sanitizer multiline limit exceeded.",
  INVALID_STATE: "The incremental sanitizer is no longer accepting input.",
  // The raw Node addon and WebAssembly errors append the fixed rejection
  // class in parentheses (`RulesetErrorClass`, issue #495); this package's
  // own `SecretScanError` keeps the same one-fixed-message-per-code
  // invariant every other code already has, rather than special-casing this
  // one code to carry variable content.
  INVALID_RULESET: "The supplied ruleset is invalid.",
  NOT_INITIALIZED:
    "redact-secret is not initialized; await initialize() before this call.",
  INITIALIZATION_FAILED: "redact-secret failed to initialize.",
  INVALID_CHUNK: "Stream sanitizer input must contain bytes.",
  INVALID_UTF8: "Stream sanitizer input is not valid UTF-8.",
  UNPAIRED_SURROGATE: "Secret scan input contains an unpaired UTF-16 surrogate.",
};

const ERROR_CODES = new Set<string>(Object.keys(ERROR_MESSAGES));

/** A sanitized failure. It carries nothing but its fixed code and message. */
export class SecretScanError extends Error {
  readonly code: SecretScanErrorCode;

  constructor(code: SecretScanErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "SecretScanError";
    this.code = code;
  }
}

function nativeErrorCode(value: unknown): SecretScanErrorCode | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const { code } = value as { code?: unknown };
  return typeof code === "string" && ERROR_CODES.has(code)
    ? (code as SecretScanErrorCode)
    : undefined;
}

/**
 * Rewrites whatever a binding threw as a {@link SecretScanError}.
 *
 * The Node addon throws an N-API error whose `code` is the core's fixed code;
 * the WebAssembly binding throws a `js_sys::Error` with the same property. A
 * value that carries no recognized code is replaced by `fallback` rather than
 * surfaced, so a host-specific message can never reach a caller.
 */
export function toSecretScanError(
  thrown: unknown,
  fallback: SecretScanErrorCode,
): SecretScanError {
  if (thrown instanceof SecretScanError) return thrown;
  return new SecretScanError(nativeErrorCode(thrown) ?? fallback);
}
