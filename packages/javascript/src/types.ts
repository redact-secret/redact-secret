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
 * One built-in detector an artifact includes, as its manifest lists it
 * (`ArtifactManifest.detectors`).
 */
export interface ArtifactManifestDetector {
  /** The `Finding.detector` id, for example `"github-token"`. */
  readonly id: string;
  /** `"common"` ships in every profile; `"provider"` only in `full`. */
  readonly pack: "common" | "provider";
  /**
   * The finding types this detector can emit, sorted: its reviewed
   * declaration, not a guarantee about every finding the engine can return
   * (see {@link ArtifactManifest.typeVocabulary}).
   */
  readonly types: readonly string[];
  /** Alternate spellings of `id`, sorted. Empty today. */
  readonly aliases: readonly string[];
}

/**
 * What the loaded artifact contains and supports: the `artifact-manifest/v1`
 * document the Rust core generates from the detectors the artifact actually
 * links (`decision-define-the-artifact-manifest-and-configuration-data-contracts`).
 *
 * It is the **included** level of the capability ceiling, before any runtime
 * choice. It holds no input, ruleset, literal, path, host name or timestamp.
 * Digests bind exact content and are not stable across versions: `version`
 * is inside `digest`.
 */
export interface ArtifactManifest {
  readonly schema: "artifact-manifest/v1";
  readonly product: "redact-secret";
  /** The lockstep product version. */
  readonly version: string;
  /** The 40-hex source commit of the build, or `null` when the build has none. */
  readonly sourceRevision: string | null;
  readonly artifact: {
    /** The target class of the artifact. */
    readonly kind: "wasm" | "node-addon" | "python-wheel" | "cli" | "rust-registry";
    readonly variant: "full" | "common" | "custom";
    /** Whether the PII runtime is linked into this artifact. */
    readonly pii: boolean;
  };
  readonly composition: {
    readonly kind: "standard" | "custom";
    readonly profile: "full" | "common" | "custom";
    /** `null` for a standard artifact. */
    readonly id: string | null;
  };
  /** Every included built-in detector, in canonical (registration) order. */
  readonly detectors: readonly ArtifactManifestDetector[];
  /** `full` built-in ids this artifact does not include, in canonical order. */
  readonly notIncluded: readonly string[];
  readonly pii: {
    readonly available: boolean;
    /** The PII family ids the artifact supports, sorted; empty when unavailable. */
    readonly families: readonly string[];
  };
  readonly capabilities: {
    readonly detectorSelection: boolean;
    readonly ruleset: { readonly revisions: readonly number[] } | null;
    readonly actionPolicy: { readonly revisions: readonly number[] };
    readonly incremental: boolean;
  };
  /** What the artifact does when runtime input is absent (`build-defaults/v1`). */
  readonly defaults: {
    readonly schema: "build-defaults/v1";
    readonly detection: "all-included";
    readonly pii: { readonly selectors: readonly string[] };
    readonly actionPolicy: "artifact-default";
    readonly limits: "artifact-default";
  };
  /** The artifact defaults of the limits and the document bounds. */
  readonly bounds: {
    readonly limits: { readonly maxInputBytes: number; readonly maxFindings: number };
    readonly actionPolicyBytes: number;
    readonly detectorIdsMax: number;
    readonly diagnosticsMax: number;
  };
  /**
   * Says that `detectors[].types` is not a closed vocabulary: a declarative
   * ruleset, a custom detector and the PII adapter emit types it does not name.
   */
  readonly typeVocabulary: {
    readonly builtInTypes: "declared";
    readonly complete: false;
    readonly dynamicSources: readonly string[];
  };
  /** `sha256:` and 64 hex characters: the SHA-256 of the canonical JSON of this object without `digest`. */
  readonly digest: string;
}

/**
 * Whether a finding's reported range shows evidence of invisible-character
 * obfuscation: at least one zero-rendering or format code point was removed
 * from inside it before detection. Carries no value, no offset into the
 * secret, and no plaintext.
 */
export type SecretObfuscation = "none" | "invisible-characters";

/**
 * The detector-id selection (`detection` of `runtime-config/v1`): which of the
 * artifact's included built-in detectors are enabled. At most one of the two
 * members.
 *
 * - `include`: exactly these, an allowlist. A detector added in a later
 *   release is not enabled. `include: []` enables no built-in detector.
 * - `exclude`: every included detector except these, a denylist. A detector
 *   added later is enabled. `exclude: []` is the same as omitting `detection`.
 *
 * Ids are `Finding.detector` values such as `"github-token"`, not types. They
 * are not case-folded or trimmed, and request order never matters: the enabled
 * set is the artifact's canonical order filtered to the enabled ids. An
 * unknown, not-included or repeated id is rejected, never ignored.
 */
export interface DetectionSelection {
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
}

/**
 * Options accepted by `initialize`. PII stays off and every included detector
 * stays enabled when omitted.
 *
 * `detection` and `pii` are fixed for the thread (and profile) by the first
 * successful call: an equivalent later request is idempotent, a differing one
 * is `DETECTION_CONFIG_CONFLICT` (`PII_ACTIVATION_CONFLICT` for `pii`), and a
 * rejected or conflicting request changes nothing. There is no per-call
 * detection argument and no way to reconfigure after initialization.
 */
export interface InitializeOptions {
  readonly pii?: readonly string[];
  /**
   * The detector-id selection (issue #1251). Applied when the registry is
   * built, before the prefilter and overlap resolution. Rejected with
   * `INVALID_DETECTION_CONFIG` when it names an unknown, not-included or
   * repeated id (no other artifact is ever loaded to satisfy it), and with
   * `EMPTY_DETECTION_SET` when nothing would be enabled.
   */
  readonly detection?: DetectionSelection;
}

/**
 * What a caller asks for, as data (`runtime-config/v1`). Every key is
 * optional and an absent key inherits the artifact default; an explicit empty
 * value disables; an array or a policy document replaces and is never merged
 * with another layer. A callback is not data: pass it as
 * {@link ResolveConfigOptions.policy}.
 */
export interface RuntimeConfig {
  readonly schema?: "runtime-config/v1";
  readonly detection?: DetectionSelection;
  /** PII selectors, as for {@link InitializeOptions.pii}. Absent and `[]` are both off. */
  readonly pii?: readonly string[];
  /** A declarative ruleset, as for {@link ScanOptions.ruleset}. Adds detectors; empty is not expressible. */
  readonly ruleset?: Uint8Array | string;
  /** A declarative action policy, as for {@link ScanOptions.actionPolicy}. Replaces the whole document. */
  readonly actionPolicy?: ActionPolicyInput;
  /** Whole-input limits; each field inherits the artifact default independently. */
  readonly limits?: { readonly maxInputBytes?: number; readonly maxFindings?: number };
}

/** Options of `resolveConfig` that are not configuration data. */
export interface ResolveConfigOptions {
  /**
   * A callback policy that is in force. It is recorded as a dynamic reference
   * (`actionPolicy.source: "callback"`, `explainable: false`) and never
   * called; together with `actionPolicy` it is `INVALID_OPTIONS`.
   */
  readonly policy?: SecretPolicy;
  /**
   * Includes the ruleset's detector ids and byte digest in the snapshot. Off
   * by default: a ruleset's identity can be sensitive, and
   * {@link ConfigSnapshot.detectionDigest} already says whether two
   * detections are the same.
   */
  readonly discloseRulesetIdentity?: boolean;
}

/** One safe finding about a configuration input (`config-diagnostics/v1`). */
export interface ConfigDiagnostic {
  /** A fixed code such as `UNKNOWN_DETECTOR_ID`; an unknown code is handled by its `severity`. */
  readonly code: string;
  readonly severity: "error" | "warning" | "info";
  /**
   * A fixed-syntax pointer such as `detection.include[3]`. An unknown member is
   * addressed by its position (`detection.@1`), never its name.
   */
  readonly path: string;
  /**
   * Only ever a canonical detector id from the catalog or the id of a rule in a
   * validated action policy; `null` otherwise. Never a string the input gave
   * for an unknown name.
   */
  readonly id: string | null;
  /**
   * A second pointer that explains this finding, present only when there is
   * one: for `ACTION_POLICY_SHADOWED_RULE`, the earlier rule that provably
   * matches everything this rule matches. Absent otherwise.
   */
  readonly related?: string;
}

/**
 * The resolved, effective configuration (`config-snapshot/v1`): immutable data
 * that explains what is compiled, enabled, disabled and unavailable, where each
 * value came from, and which identity it has. It is not a handle and cannot
 * scan.
 *
 * It holds ids, counts, digests and fixed words. It never holds an input byte,
 * a ruleset body, a rule's pattern, a matched value or a path, and no scalar
 * sensitivity or probability.
 */
export interface ConfigSnapshot {
  readonly schema: "config-snapshot/v1";
  readonly artifact: {
    readonly compositionId: string | null;
    readonly kind: string;
    /** The digest of the artifact manifest the defaults are bound to. */
    readonly manifestDigest: string;
    readonly profile: string;
    readonly version: string;
  };
  readonly detection: {
    /** Built-in detectors linked into the artifact. */
    readonly compiledCount: number;
    /** Custom detectors a Rust registry holds; they are code, not data. */
    readonly customDetectors: number;
    /** Included but not enabled, in canonical order. */
    readonly disabled: readonly string[];
    /** Enabled, in canonical order. */
    readonly enabled: readonly string[];
    readonly enabledCount: number;
    readonly mode: "all-included" | "include" | "exclude";
    /** `full` built-ins this artifact does not include: unavailable here. */
    readonly unavailable: readonly string[];
  };
  readonly ruleset: {
    readonly detectorCount: number | null;
    /** Withheld (`null`) unless `discloseRulesetIdentity` was set. */
    readonly detectorIds: readonly string[] | null;
    readonly digest: string | null;
    readonly disclosed: boolean;
    readonly present: boolean;
    readonly revision: number | null;
  };
  readonly pii: {
    /** The existing canonical activation identity string, unchanged. */
    readonly activation: string;
    readonly available: boolean;
    readonly families: readonly string[];
    readonly selectors: readonly string[];
  };
  readonly actionPolicy: {
    /** The digest of the exact serialized policy document, or `null`. */
    readonly digest: string | null;
    /** `false` for a callback: its decisions cannot be explained or reproduced. */
    readonly explainable: boolean;
    readonly revision: number | null;
    readonly ruleCount: number | null;
    readonly source: "default" | "document" | "callback";
  };
  readonly limits: { readonly maxFindings: number; readonly maxInputBytes: number };
  /** Who fixes each setting on this surface: `initialize`, `registry`, `call` or `session`. */
  readonly owners: {
    readonly actionPolicy: string;
    readonly detection: string;
    readonly incremental: string;
    readonly limits: string;
    readonly pii: string;
    readonly ruleset: string;
  };
  /** Where each value came from: `artifact-default` or `runtime`. */
  readonly origins: {
    readonly actionPolicy: string;
    readonly detection: string;
    readonly maxFindings: string;
    readonly maxInputBytes: string;
    readonly pii: string;
    readonly ruleset: string;
  };
  readonly effects: {
    /** `true` when a disabled built-in could change which detector wins an overlap. */
    readonly overlapOutcomesMayChange: boolean;
    /** `true` when nothing at all is enabled; binding it to an owner fails. */
    readonly inert: boolean;
  };
  /** `sha256:` over the manifest digest, the enabled ids, the ruleset digest and the PII activation: equal digests mean the same detection. */
  readonly detectionDigest: string;
  /** `sha256:` over the canonical JSON of this object without `digest`. */
  readonly digest: string;
}

/**
 * What `resolveConfig` returns (`config-resolution/v1`). Invalid input is
 * data: `ok` is `false`, `snapshot` is `null` and every problem is listed, so
 * a tool can show them all.
 */
export interface ConfigResolution {
  readonly schema: "config-resolution/v1";
  readonly ok: boolean;
  readonly snapshot: ConfigSnapshot | null;
  readonly diagnostics: {
    readonly schema: "config-diagnostics/v1";
    /** `true` when more than 256 diagnostics were produced and the rest dropped. */
    readonly truncated: boolean;
    /** Errors first, then in document order. */
    readonly items: readonly ConfigDiagnostic[];
  };
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
  /**
   * The detector profile of this entry point: `"full"` or `"common"` for the
   * published entry points, `"custom"` for the generated wrapper of a static
   * custom composition (`scripts/build-custom-artifact.mjs`).
   */
  readonly profile: "full" | "common" | "custom";
  /**
   * The canonical credentials/PII activation identity (the `piiActivation()`
   * string) once initialized; `null` before.
   */
  readonly activation: string | null;
  /**
   * The `digest` of the snapshot of the configuration this runtime is fixed to
   * (`describeConfig().digest`) once initialized; `null` before, and `null`
   * when the loaded artifact reports no configuration. An additive field.
   */
  readonly configuration: string | null;
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

/**
 * Options of `compareConfigurations`
 * (`decision-define-the-artifact-manifest-and-configuration-data-contracts`,
 * `configuration-comparison/v1`). Whole-input only, like
 * {@link CompareActionPoliciesOptions}: one string, never a stream. A key this
 * interface does not name is `INVALID_OPTIONS`.
 */
export interface CompareConfigurationsOptions {
  /**
   * One to four configurations, compared in this order: the first is the
   * baseline. Each side's `detection`, `pii`, `ruleset`, `actionPolicy` and
   * `limits` are honored for that side only. A side that cannot be built or
   * scanned is a failed side in the result, not a thrown error.
   */
  readonly configs: readonly RuntimeConfig[];
  /**
   * A declarative action policy for every side whose own `actionPolicy` is
   * absent. Without either, a side uses the artifact's default evaluation.
   */
  readonly actionPolicy?: ActionPolicyInput;
  /**
   * A callback policy for every side. It may have side effects and has no
   * stable identity: it is called once per finalized finding of each scanned
   * side, side by side in the order supplied, and a failure fails the whole
   * call with no partial result. Together with any `actionPolicy` (this one or
   * a side's) it is `INVALID_OPTIONS`.
   */
  readonly policy?: SecretPolicy;
}

/** Whether a side produced findings, and if not, why not. */
export type ComparedSideStatus = "scanned" | "limited" | "unsupported" | "error";

/** One compared configuration: its identities, origins and diagnostics. */
export interface ComparedConfigurationSummary {
  /** `"baseline"` for the first side, then `"candidate-1"`, `"candidate-2"`, `"candidate-3"`. */
  readonly label: string;
  /** The snapshot digest, or `null` when the configuration did not resolve. */
  readonly digest: string | null;
  /**
   * Equal digests mean the same detection. A different ruleset, selection or
   * PII activation always differs here, whatever the action policy bytes are.
   */
  readonly detectionDigest: string | null;
  /** Where each value came from (`artifact-default` or `runtime`), or `null` when unresolved. */
  readonly origins: ConfigSnapshot["origins"] | null;
  /** The configuration's own diagnostics (`resolveConfig`'s), safe and bounded. */
  readonly diagnostics: readonly ConfigDiagnostic[];
  /** The side's policy: a callback has no identity and may have side effects. */
  readonly policy: {
    readonly kind: ComparedPolicyKind;
    /** The action policy document's SHA-256, as for {@link ComparedPolicySummary.documentSha256}; `null` otherwise. */
    readonly documentSha256: string | null;
  };
}

/** One finalized finding of one side, as safe metadata. There is no per-scan id: it is not a stable identity. */
export interface ConfigurationFinding {
  readonly type: string;
  readonly detector: string;
  readonly confidence: SecretConfidence;
  readonly obfuscation: SecretObfuscation;
  /** Start in {@link ConfigurationComparison.rangeUnit}. */
  readonly start: number;
  /** Exclusive end in {@link ConfigurationComparison.rangeUnit}. */
  readonly end: number;
  readonly action: SecretAction;
  readonly reason: {
    readonly basis: DecisionBasis;
    readonly ruleId: string | null;
    readonly ruleIndex: number | null;
  };
}

/**
 * One side's outcome. A failed side (`status` other than `"scanned"`) has no
 * findings, which is not the same as finding nothing: check `status`.
 */
export interface ConfigurationSideResult {
  readonly status: ComparedSideStatus;
  /** The fixed code of a failed side (a configuration diagnostic or error code); otherwise `null`. */
  readonly failure: string | null;
  readonly counts: ActionCounts;
  /** In input order. */
  readonly findings: readonly ConfigurationFinding[];
}

/** What a changed attribute of a {@link ConfigurationDifference} can be. */
export type ConfigurationChange = "range" | "type" | "detector" | "confidence" | "action" | "reason";

/**
 * One difference between the baseline and another side. `base` and `other`
 * are positions in `results[0].findings` and in the other side's `findings`.
 *
 * - `added` / `removed`: a finding only one side has (one per entry).
 * - `changed`: one finding on each side over overlapping ranges with at least
 *   one attribute changed. A provider detector removed while a contextual one
 *   takes the same span is this kind, with `type` and `detector` changed, not
 *   a removal.
 * - `split` / `merged` / `regrouped`: several findings share the overlap. They
 *   are listed together and are not paired (`correspondence: "ambiguous"`).
 */
export interface ConfigurationDifference {
  readonly kind: "added" | "removed" | "changed" | "split" | "merged" | "regrouped";
  /** `exact`: the same range; `overlap`: one each over different ranges; `ambiguous`: several; `null` for added and removed. */
  readonly correspondence: "exact" | "overlap" | "ambiguous" | null;
  readonly base: readonly number[];
  readonly other: readonly number[];
  /** Only for `changed`. */
  readonly changes: readonly ConfigurationChange[];
}

/** The differences of one side against the baseline, on this input only. */
export interface ConfigurationDifferences {
  /** In input order. */
  readonly entries: readonly ConfigurationDifference[];
  /** Pairs with the same range and every attribute equal. */
  readonly unchanged: number;
}

/**
 * The result of `compareConfigurations` (`configuration-comparison/v1`): what
 * independent detection passes over this one input found under each
 * configuration, and how those findings correspond. A preview, never
 * enforcement; frozen plain data with no input byte, matched value, snippet or
 * hash of either.
 *
 * It reports differences **on this input only** (`scope: "input"`) and covers
 * finalized findings only: not overlap losers, not candidates a gate removed.
 * A side or a pair with no finding says nothing about absence of risk, about
 * other input, or that a detector or rule is ineffective. Findings of
 * different passes have no stable identity; correspondence comes from the
 * declared `rangeUnit` ranges.
 */
export interface ConfigurationComparison {
  readonly schema: "configuration-comparison/v1";
  /** The package version that produced the result. */
  readonly version: string;
  readonly rangeUnit: RangeUnit;
  readonly scope: "input";
  readonly mode: "preview";
  readonly enforced: false;
  /** Positions of callback sides: they may have side effects and have no stable identity. */
  readonly callbackSides: readonly number[];
  /** One per side, in the order supplied. */
  readonly configs: readonly ComparedConfigurationSummary[];
  /** One per side, in the order supplied. */
  readonly results: readonly ConfigurationSideResult[];
  /**
   * One per side: `null` for the baseline, and for a side where it or the
   * baseline did not scan, so a failure is never read as equivalence.
   */
  readonly differences: readonly (ConfigurationDifferences | null)[];
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
