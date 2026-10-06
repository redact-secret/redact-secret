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

/** Options accepted by `initialize`. PII stays off when omitted or empty. */
export interface InitializeOptions {
  readonly pii?: readonly string[];
}

/**
 * What `status()` reports, without initializing or reconfiguring anything.
 *
 * Fixed values and public capability metadata only: no input, exception text,
 * path or secret-derived value.
 */
export interface CoreStatus {
  /** `true` once an `initialize()` call has succeeded and operations are usable. */
  readonly initialized: boolean;
  /** The detector profile of this entry point. */
  readonly profile: "full" | "common";
  /**
   * The canonical credentials/PII activation identity (the `piiActivation()`
   * string) once initialized; `null` before.
   */
  readonly activation: string | null;
}

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
export type PlaceholderFormatter = (finding: SecretFinding, context: PlaceholderContext) => string;

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

/** What a rule of an {@link ActionPolicyDocument} may do: an action, or `"default"` for the base. */
export type ActionPolicyRuleAction = SecretAction | "default";

/**
 * The conditions of one rule. Every key a rule has must hold (AND), and a key
 * holds when the finding's value is a member of its non-empty set (OR). A rule
 * has one to four keys; no key is a wildcard, a pattern, a negation or a
 * number.
 */
export interface ActionPolicyMatch {
  /** Finding types (lowercase identifiers). A type no detector emits is accepted and matches nothing. */
  readonly type?: readonly string[];
  /** Detector ids (lowercase identifiers). */
  readonly detector?: readonly string[];
  readonly confidence?: readonly SecretConfidence[];
  readonly obfuscation?: readonly SecretObfuscation[];
}

/** One rule of an {@link ActionPolicyDocument}. */
export interface ActionPolicyRule {
  /** A lowercase identifier of at most 64 bytes, unique in the document. */
  readonly id: string;
  readonly match: ActionPolicyMatch;
  readonly action: ActionPolicyRuleAction;
}

/**
 * A revision 1 declarative action policy
 * (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`):
 * the first rule that matches a finalized finding decides its action, and a
 * finding no rule matches keeps the default action the running artifact
 * computes. The document is parsed and validated by the Rust core, never by
 * this package.
 */
export interface ActionPolicyDocument {
  readonly actionPolicyRevision: 1;
  readonly base: "default";
  /** 0 to 128 rules, evaluated in order. */
  readonly rules: readonly ActionPolicyRule[];
}

/**
 * The accepted forms of the `actionPolicy` option: a plain object (serialized
 * once, with `JSON.stringify`, at the call or at session construction), or
 * the document as UTF-8 JSON text or bytes. The document is at most 65,536
 * bytes. A rejected document throws `INVALID_ACTION_POLICY`; supplying it
 * together with a callback `policy` throws `INVALID_OPTIONS`.
 */
export type ActionPolicyInput = ActionPolicyDocument | string | Uint8Array;

/**
 * The `defaultPolicy` export: the core's default evaluation as a policy. It is
 * a valid `policy` for a whole-input call and for an incremental session, and
 * its `context` is optional because the default reads neither.
 */
export interface DefaultSecretPolicy extends SecretPolicy, IncrementalSecretPolicy {
  evaluate(finding: DetectedSecretFinding, context?: PolicyContext | IncrementalPolicyContext): SecretAction;
}

export interface ScanOptions {
  readonly policy?: SecretPolicy;
  /**
   * A declarative action policy that replaces the default evaluation: the
   * first matching rule's action, or the default action for an unmatched
   * finding. Mutually exclusive with `policy`. See {@link ActionPolicyInput}.
   */
  readonly actionPolicy?: ActionPolicyInput;
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

/**
 * One policy to compare
 * (`decision-explain-and-compare-action-policies-over-one-detection-pass`):
 * the default evaluation the running artifact computes, a declarative action
 * policy, or a legacy callback policy. Every side names its `kind` and carries
 * only the field of that kind; any other key is `INVALID_OPTIONS`, so nothing
 * is silently ignored.
 */
export type ComparedPolicy =
  | { readonly kind: "default" }
  | {
      readonly kind: "action-policy";
      /** The same forms as {@link ScanOptions.actionPolicy}. */
      readonly actionPolicy: ActionPolicyInput;
    }
  | {
      readonly kind: "callback";
      /**
       * A whole-input policy, called exactly once per finalized finding, in
       * finding order, with the same context `scan` gives it. Sides run one at
       * a time in the order supplied, so two callbacks never interleave.
       */
      readonly policy: SecretPolicy;
    };

/**
 * Options of `compareActionPolicies`. The comparison is whole-input only: it
 * takes one string, never a stream, a chunk or an incremental session, and
 * there is no incremental limit or option here. A key this interface does not
 * name is `INVALID_OPTIONS`.
 */
export interface CompareActionPoliciesOptions {
  /** One to four policies, compared in this order: the first is the baseline. */
  readonly policies: readonly ComparedPolicy[];
  /** Explicit whole-input bounds, exactly as for `scan`. Omit for the core's default. */
  readonly limits?: WholeInputLimits;
  /** A declarative detector ruleset, exactly as for `scan`; it applies to every side. */
  readonly ruleset?: Uint8Array | string;
}

/** What kind of policy one compared side is. */
export type ComparedPolicyKind = "default" | "action-policy" | "callback";

/**
 * Why a side chose its action: `rule` is a fixed-action rule, `rule-default`
 * a rule whose action is `default` (the base action, and evaluation stopped at
 * that rule), `no-rule-matched` the fall back to the base, `default-policy`
 * the default side and `callback` a callback side.
 */
export type DecisionBasis = "rule" | "rule-default" | "no-rule-matched" | "default-policy" | "callback";

/** One side's action for one finding and the reason for it. */
export interface ActionDecision {
  readonly action: SecretAction;
  readonly basis: DecisionBasis;
  /** The deciding rule's id for `rule` and `rule-default`; otherwise `null`. */
  readonly ruleId: string | null;
  /** The deciding rule's zero-based index for `rule` and `rule-default`; otherwise `null`. */
  readonly ruleIndex: number | null;
}

/** How many findings a side redacts, blocks, warns on and allows. */
export interface ActionCounts {
  readonly redact: number;
  readonly block: number;
  readonly warn: number;
  readonly allow: number;
}

/** One compared side: its position label, kind, document digest and counts. */
export interface ComparedPolicySummary {
  /** `"baseline"` for the first side, then `"candidate-1"`, `"candidate-2"`, `"candidate-3"`. */
  readonly label: string;
  readonly kind: ComparedPolicyKind;
  /**
   * The lowercase SHA-256 (64 hex characters) of an action policy document's
   * exact bytes: the text or bytes given, or, for an object, the compact
   * `JSON.stringify` bytes this package serialized. `null` for the default
   * (which evolves with the artifact: key evidence to `version` as well) and
   * for a callback (which has no identity). The only digest in a result.
   */
  readonly documentSha256: string | null;
  readonly counts: ActionCounts;
}

/**
 * What detection saw, apart from every policy. Swapping a policy leaves it
 * unchanged, and swapping the ruleset or PII selection leaves every
 * `documentSha256` unchanged. It does not identify a custom ruleset: key that
 * to your own digest of its bytes.
 */
export interface ComparisonDetection {
  /** The canonical credentials/PII activation identity (`piiActivation()`). */
  readonly activationIdentity: string;
  readonly profile: "full" | "common" | null;
  /** How many detectors ran, ruleset detectors included. */
  readonly detectorCount: number;
}

/** A finalized finding and every side's decision for it, in side order. */
export interface ComparedFinding extends DetectedSecretFinding {
  /** Whether the sides do not all choose the same action. The reason is not compared. */
  readonly differs: boolean;
  readonly decisions: readonly ActionDecision[];
}

/**
 * The result of `compareActionPolicies`: a preview of what each policy would
 * choose for the findings `scan` returns for the same input, never
 * enforcement. It is frozen plain data with no input byte, matched value,
 * snippet or hash of either.
 *
 * It covers finalized findings only: not overlap losers, not candidates that
 * never survived, not suppressed PII alternatives, and it makes no claim about
 * what detection missed. A rule with no match on this input is not proven dead.
 */
export interface ActionComparison {
  /** The package version that produced the result; key `default`-side evidence to it. */
  readonly version: string;
  readonly rangeUnit: RangeUnit;
  readonly mode: "preview";
  readonly enforced: false;
  readonly detection: ComparisonDetection;
  /** One per side, in the order supplied. */
  readonly policies: readonly ComparedPolicySummary[];
  readonly findingCount: number;
  /** How many findings have `differs` set. */
  readonly changedCount: number;
  /** In `scan`'s order, with the same ids, ranges and metadata. */
  readonly findings: readonly ComparedFinding[];
}

/** The terminally distinct lifecycle states of an incremental session. */
export type IncrementalSanitizerState = "accepting" | "finalized" | "aborted" | "failed";

/** Position information passed alongside a finding to an incremental policy. */
export interface IncrementalPolicyContext {
  /** Zero-based position among findings finalized by this session. */
  readonly findingIndex: number;
}

/** A custom policy for an incremental session. */
export interface IncrementalSecretPolicy {
  evaluate(finding: DetectedSecretFinding, context: IncrementalPolicyContext): SecretAction;
}

/** The input limit under its byte name; the deprecated alias is optional. */
interface InputLimitInBytes {
  /** UTF-8 byte ceiling. */
  readonly maxInputBytes: number;
  /** @deprecated Use `maxInputBytes`; same meaning (UTF-8 bytes). */
  readonly maxInputCodeUnits?: number;
}

/** The input limit under its deprecated name; the byte name is optional. */
interface InputLimitInCodeUnits {
  /** @deprecated Use `maxInputBytes`; same meaning (UTF-8 bytes). */
  readonly maxInputCodeUnits: number;
  /** UTF-8 byte ceiling. */
  readonly maxInputBytes?: number;
}

/** The buffered limit under its byte name; the deprecated alias is optional. */
interface BufferedLimitInBytes {
  /** UTF-8 byte ceiling. */
  readonly maxBufferedBytes: number;
  /** @deprecated Use `maxBufferedBytes`; same meaning (UTF-8 bytes). */
  readonly maxBufferedCodeUnits?: number;
}

/** The buffered limit under its deprecated name; the byte name is optional. */
interface BufferedLimitInCodeUnits {
  /** @deprecated Use `maxBufferedBytes`; same meaning (UTF-8 bytes). */
  readonly maxBufferedCodeUnits: number;
  /** UTF-8 byte ceiling. */
  readonly maxBufferedBytes?: number;
}

/** The token limit under its byte name; the deprecated alias is optional. */
interface TokenLimitInBytes {
  /** UTF-8 byte ceiling. */
  readonly maxTokenBytes: number;
  /** @deprecated Use `maxTokenBytes`; same meaning (UTF-8 bytes). */
  readonly maxTokenCodeUnits?: number;
}

/** The token limit under its deprecated name; the byte name is optional. */
interface TokenLimitInCodeUnits {
  /** @deprecated Use `maxTokenBytes`; same meaning (UTF-8 bytes). */
  readonly maxTokenCodeUnits: number;
  /** UTF-8 byte ceiling. */
  readonly maxTokenBytes?: number;
}

/** The multiline limit under its byte name; the deprecated alias is optional. */
interface MultilineLimitInBytes {
  /** UTF-8 byte ceiling. */
  readonly maxMultilineBytes: number;
  /** @deprecated Use `maxMultilineBytes`; same meaning (UTF-8 bytes). */
  readonly maxMultilineCodeUnits?: number;
}

/** The multiline limit under its deprecated name; the byte name is optional. */
interface MultilineLimitInCodeUnits {
  /** @deprecated Use `maxMultilineBytes`; same meaning (UTF-8 bytes). */
  readonly maxMultilineCodeUnits: number;
  /** UTF-8 byte ceiling. */
  readonly maxMultilineBytes?: number;
}

/**
 * Explicit, positive limits every incremental session requires. There are no
 * environment-derived or silent defaults.
 *
 * Every limit is a **UTF-8 byte** ceiling on every artifact, not a UTF-16
 * code-unit count: size non-ASCII input with `TextEncoder` when choosing it.
 * Each limit has two spellings, and each limit must be given under at least
 * one of them (naming both is allowed only when they hold the same value):
 *
 * | Preferred | Deprecated alias |
 * | --- | --- |
 * | `maxInputBytes` | `maxInputCodeUnits` |
 * | `maxBufferedBytes` | `maxBufferedCodeUnits` |
 * | `maxTokenBytes` | `maxTokenCodeUnits` |
 * | `maxMultilineBytes` | `maxMultilineCodeUnits` |
 *
 * The `CodeUnits` names are deprecated, not removed: they keep working with
 * the same meaning. Giving both spellings of one limit with different values
 * throws `INVALID_LIMITS`, as does giving neither. Findings' `start` and `end`
 * ranges are still UTF-16 code units; only these four ceilings count bytes.
 */
export type IncrementalLimits = (InputLimitInBytes | InputLimitInCodeUnits) &
  (BufferedLimitInBytes | BufferedLimitInCodeUnits) &
  (TokenLimitInBytes | TokenLimitInCodeUnits) &
  (MultilineLimitInBytes | MultilineLimitInCodeUnits);

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
  /**
   * A declarative action policy, parsed once when the session is created and
   * bound to it for its whole life. Mutually exclusive with `policy`. See
   * {@link ActionPolicyInput}.
   */
  readonly actionPolicy?: ActionPolicyInput;
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
