/**
 * The documented public type contract of `@redact-secret/core`.
 *
 * Every range in this file is a `[start, end)` pair of **UTF-16 code-unit**
 * offsets into the JavaScript string that produced it, so `input.slice(start,
 * end)` selects exactly the matched span (`decision-define-runtime-bindings`).
 * The Rust core reports UTF-8 byte offsets; the Node and browser bindings
 * convert them without changing the selected span.
 *
 * Custom detector callbacks are deliberately absent: every built-in detector
 * runs in Rust, and the first stable extension surface is a policy and a
 * placeholder formatter, both of which receive safe metadata only.
 */

/** The string-index unit every public range in this package uses. */
export type RangeUnit = "utf16-code-units";

/**
 * Which artifact this runtime loaded: the native addon, or the WebAssembly
 * fallback engaged when the addon path could not produce a usable binding
 * (`decision-add-node-wasm-fallback`). Always `"wasm"` in a browser, where
 * WebAssembly is the only artifact.
 */
export type ArtifactKind = "addon" | "wasm";

/** How specific a detector considers a match. */
export type SecretConfidence = "high" | "medium" | "low";

/** What a policy decided to do with a finding. */
export type SecretAction = "redact" | "block" | "warn" | "allow";

/**
 * Whether a finding's reported range shows evidence of invisible-character
 * obfuscation: at least one zero-rendering or format code point was removed
 * from inside it before detection. Carries no value, no offset into the
 * secret, and no plaintext.
 */
export type SecretObfuscation = "none" | "invisible-characters";

/**
 * A finding before policy evaluation: the safe metadata a policy callback
 * receives. It never carries the input or the matched value.
 */
export interface DetectedSecretFinding {
  /** Deterministic finding id (`finding-1`, `finding-2`, ...). */
  readonly id: string;
  /** Finding type, for example `"jwt"` or `"aws_access_key_id"`. */
  readonly type: string;
  /** Id of the detector that produced this finding. */
  readonly detector: string;
  readonly confidence: SecretConfidence;
  readonly obfuscation: SecretObfuscation;
  /** Start offset, in UTF-16 code units. */
  readonly start: number;
  /** End offset (exclusive), in UTF-16 code units. */
  readonly end: number;
}

/** A finding after policy evaluation: the shape {@link scan} returns. */
export interface SecretFinding extends DetectedSecretFinding {
  readonly action: SecretAction;
}

/** Position information passed alongside a finding to a policy. */
export interface PolicyContext {
  /** Zero-based position in the finalized detection list. */
  readonly findingIndex: number;
  /** Total number of finalized findings for the input. */
  readonly findingCount: number;
}

/**
 * A custom policy. It sees safe metadata only, never the input or a matched
 * value. Omit it to use the built-in policy, which runs in Rust.
 */
export interface SecretPolicy {
  evaluate(finding: DetectedSecretFinding, context: PolicyContext): SecretAction;
}

/** Position information passed to a placeholder formatter. */
export interface PlaceholderContext {
  /** One-based position among findings that are actually replaced. */
  readonly placeholderIndex: number;
}

/**
 * A custom placeholder formatter. It sees safe metadata only, and its result
 * is validated: an empty, oversized, or matched-value-reproducing placeholder
 * is rejected.
 */
export type PlaceholderFormatter = (
  finding: SecretFinding,
  context: PlaceholderContext,
) => string;

/**
 * Explicit byte and finding-count bounds for {@link scan}, {@link redact},
 * and {@link scanAndRedact}. Omit to use the core's default — 64 MiB of
 * input and 50,000 findings
 * (`decision-bound-whole-input-operations-by-default`). Exceeding either
 * bound fails with a fixed `INPUT_LIMIT_EXCEEDED`/`FINDING_LIMIT_EXCEEDED`
 * error rather than truncating.
 */
export interface WholeInputLimits {
  /** UTF-8 byte ceiling on the whole input. */
  readonly maxInputBytes: number;
  /** Ceiling on the number of accepted findings. */
  readonly maxFindings: number;
}

export interface ScanOptions {
  readonly policy?: SecretPolicy;
  readonly limits?: WholeInputLimits;
  /**
   * A caller-supplied declarative ruleset
   * (`decision-define-declarative-detector-ruleset-contract`), as raw bytes
   * or a UTF-8 string of its text grammar. Its declared detectors register
   * after every built-in, so a ruleset detector can add detections but
   * never outrank a built-in's resolved finding. Throws
   * `INVALID_RULESET` when it does not parse.
   */
  readonly ruleset?: Uint8Array | string;
}

export interface RedactOptions {
  readonly placeholderFormatter?: PlaceholderFormatter;
  readonly limits?: WholeInputLimits;
}

export interface ScanAndRedactOptions extends ScanOptions, RedactOptions {}

/** Sanitized text alongside every finding that produced it. */
export interface ScanResult {
  readonly text: string;
  readonly findings: readonly SecretFinding[];
}

/** The terminally distinct lifecycle states of an incremental session. */
export type IncrementalSanitizerState =
  | "accepting"
  | "finalized"
  | "aborted"
  | "failed";

/** Position information passed alongside a finding to an incremental policy. */
export interface IncrementalPolicyContext {
  /** Zero-based position among findings finalized by this session. */
  readonly findingIndex: number;
}

/** A custom policy for an incremental session. */
export interface IncrementalSecretPolicy {
  evaluate(
    finding: DetectedSecretFinding,
    context: IncrementalPolicyContext,
  ): SecretAction;
}

/**
 * Explicit, positive UTF-16 code-unit limits every incremental session
 * requires. There are no environment-derived or silent defaults.
 */
export interface IncrementalLimits {
  /** UTF-8 byte ceiling; the legacy field name is retained for compatibility. */
  readonly maxInputCodeUnits: number;
  /** UTF-8 byte ceiling; the legacy field name is retained for compatibility. */
  readonly maxBufferedCodeUnits: number;
  /** UTF-8 byte ceiling; the legacy field name is retained for compatibility. */
  readonly maxTokenCodeUnits: number;
  /** UTF-8 byte ceiling; the legacy field name is retained for compatibility. */
  readonly maxMultilineCodeUnits: number;
}

/**
 * Does not extend {@link RedactOptions}: that interface's `limits` is a
 * whole-input {@link WholeInputLimits}, a different shape from this
 * interface's own required incremental `limits`, so the two field
 * declarations would collide under one property name.
 */
export interface IncrementalSanitizerOptions {
  readonly limits: IncrementalLimits;
  readonly placeholderFormatter?: PlaceholderFormatter;
  readonly policy?: IncrementalSecretPolicy;
}

/** Safe output and final findings produced by one session operation. */
export interface IncrementalSanitizerResult extends ScanResult {}

/**
 * A bounded incremental session. `append` and `finalize` return only text and
 * findings whose detection window is closed; findings carry absolute UTF-16
 * offsets into the logical whole-session input.
 */
export interface IncrementalSanitizer {
  readonly state: IncrementalSanitizerState;
  append(chunk: string): IncrementalSanitizerResult;
  finalize(): IncrementalSanitizerResult;
  abort(): void;
}
