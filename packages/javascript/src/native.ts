/**
 * The internal contract every runtime adapter must satisfy.
 *
 * `runtime/node.ts` builds it from the N-API addon and `runtime/browser.ts`
 * from the WebAssembly build; nothing here is part of the published API, and
 * the package's `exports` map makes this module unreachable from outside
 * (`decision-define-runtime-bindings`).
 *
 * Every offset crossing this boundary is already a UTF-16 code-unit offset:
 * each binding converts from the core's UTF-8 byte offsets on its own side,
 * without changing the selected span.
 */

import type {
  ArtifactKind,
  IncrementalPolicyContext,
  IncrementalSanitizerState,
  PlaceholderContext,
  PolicyContext,
} from "./types.js";

/**
 * Carries a binding-private handle alongside a public finding.
 *
 * The WebAssembly binding returns opaque `Finding` objects that its `redact`
 * must receive back unchanged; the property is a symbol and non-enumerable, so
 * it never appears in `Object.keys`, `JSON.stringify`, or a structural
 * comparison of a public finding.
 */
export const NATIVE_HANDLE: unique symbol = Symbol.for("@redact-secret/core.native-handle");

export interface NativeFinding {
  readonly id: string;
  readonly type: string;
  readonly detector: string;
  readonly confidence: string;
  readonly action: string;
  readonly obfuscation: string;
  readonly start: number;
  readonly end: number;
  readonly [NATIVE_HANDLE]?: unknown;
}

export interface NativeDetectedFinding {
  readonly id: string;
  readonly type: string;
  readonly detector: string;
  readonly confidence: string;
  readonly obfuscation: string;
  readonly start: number;
  readonly end: number;
}

export type NativePolicyCallback = (finding: NativeDetectedFinding, context: PolicyContext) => string;

export type NativeIncrementalPolicyCallback = (
  finding: NativeDetectedFinding,
  context: IncrementalPolicyContext,
) => string;

export type NativeFormatterCallback = (finding: NativeFinding, context: PlaceholderContext) => string;

export interface NativeScanAndRedactResult {
  readonly text: string;
  readonly findings: readonly NativeFinding[];
}

/**
 * Explicit byte and finding-count bounds for `scan`, `redact`, and
 * `scanAndRedact`. Omit to use the core's default
 * (`decision-bound-whole-input-operations-by-default`).
 */
export interface NativeWholeInputLimits {
  readonly maxInputBytes: number;
  readonly maxFindings: number;
}

/**
 * What the bindings receive. The public wrapper resolves the `max*Bytes`
 * aliases to these fields before the call, so a binding never sees (or needs
 * to know) the alias spelling. All four are UTF-8 byte ceilings despite the
 * legacy field names.
 */
export interface NativeIncrementalLimits {
  readonly maxInputCodeUnits: number;
  readonly maxBufferedCodeUnits: number;
  readonly maxTokenCodeUnits: number;
  readonly maxMultilineCodeUnits: number;
}

export interface NativeIncrementalOptions {
  readonly limits: NativeIncrementalLimits;
  readonly policy?: NativeIncrementalPolicyCallback;
  readonly formatter?: NativeFormatterCallback;
  /** The bytes of an action policy document; never together with `policy`. */
  readonly actionPolicy?: Uint8Array;
}

export interface NativeIncrementalResult {
  readonly text: string;
  readonly findings: readonly NativeFinding[];
}

export interface NativeIncrementalSanitizer {
  readonly state: IncrementalSanitizerState;
  append(chunk: string): NativeIncrementalResult;
  finalize(): NativeIncrementalResult;
  abort(): void;
}

/**
 * One side of a comparison as the public wrapper hands it to a binding. A
 * document is already the exact bytes the core will hash and parse; a
 * callback is already adapted to safe metadata.
 */
export type NativeComparedSide =
  | { readonly kind: "default" }
  | { readonly kind: "action-policy"; readonly document: Uint8Array }
  | { readonly kind: "callback"; readonly callback: NativePolicyCallback };

/**
 * What a binding returns for a comparison: the same field names on every
 * runtime, ranges already UTF-16 code units. An absent value may be `null` or
 * missing; the wrapper normalizes it to the one public shape.
 */
export interface NativeActionComparison {
  readonly detection: {
    readonly activationIdentity: string;
    readonly profile?: string | null;
    readonly detectorCount: number;
  };
  readonly sides: readonly {
    readonly kind: string;
    readonly documentSha256?: string | null;
    readonly redact: number;
    readonly block: number;
    readonly warn: number;
    readonly allow: number;
  }[];
  readonly changedCount: number;
  readonly findings: readonly {
    readonly id: string;
    readonly type: string;
    readonly detector: string;
    readonly confidence: string;
    readonly obfuscation: string;
    readonly start: number;
    readonly end: number;
    readonly differs: boolean;
    readonly decisions: readonly {
      readonly action: string;
      readonly basis: string;
      readonly ruleId?: string | null;
      readonly ruleIndex?: number | null;
    }[];
  }[];
}

/**
 * Splits sides into the parallel arrays both bindings take: each side's
 * `kind` in order, the documents in the order their sides appear, and the
 * callbacks in the order theirs do. A binding rebuilds the sides from the
 * three, so neither runtime needs a structured-clone of a callback.
 */
export function splitNativeSides(sides: readonly NativeComparedSide[]): {
  readonly kinds: string[];
  readonly documents: Uint8Array[];
  readonly callbacks: NativePolicyCallback[];
} {
  const kinds: string[] = [];
  const documents: Uint8Array[] = [];
  const callbacks: NativePolicyCallback[] = [];
  for (const side of sides) {
    kinds.push(side.kind);
    if (side.kind === "action-policy") documents.push(side.document);
    else if (side.kind === "callback") callbacks.push(side.callback);
  }
  return { kinds, documents, callbacks };
}

export interface NativeBinding {
  /** The shared product version this artifact was built from. */
  version(): string;
  /** The detector profile this artifact was built from: `"full"` or `"common"`. */
  profile(): string;
  /** Which artifact this binding was built from. */
  artifact(): ArtifactKind;
  /**
   * Idempotent native setup. May be a no-op, as it is on Node.
   *
   * `detection`, when given, is the JSON text of the `detection` object of
   * `runtime-config/v1` (`{"include":[...]}` or `{"exclude":[...]}`): the
   * detector-id selection the owner is fixed to. The binding forwards it to
   * the core, which validates it and applies it when the registry is built.
   * A binding that cannot take one rejects the request (it never ignores it).
   */
  initialize(pii?: readonly string[], detection?: string): void;
  piiActivation?(): string;
  /**
   * The artifact's `artifact-manifest/v1` document as JSON text, generated by
   * the Rust core from the detectors the artifact links. Side-effect free: it
   * builds no registry and reads no PII selection. Absent on an artifact built
   * before the manifest existed.
   */
  artifactManifest?(): string;
  /**
   * Resolves explicit runtime input over the artifact's defaults into the
   * `config-resolution/v1` document as JSON text, in the Rust core. Pure: it
   * builds no registry and changes no owner. `config` is the JSON text of the
   * data members (`schema`, `detection`, `pii`, `limits`); `ruleset` and
   * `actionPolicy` are the exact bytes a call would load. Absent on an
   * artifact built before configuration resolution existed.
   */
  resolveConfig?(
    config: string | undefined,
    ruleset: Uint8Array | undefined,
    actionPolicy: Uint8Array | undefined,
    callback: boolean,
    disclose: boolean,
  ): string;
  scan(
    input: string,
    policy: NativePolicyCallback | undefined,
    limits: NativeWholeInputLimits | undefined,
    ruleset: Uint8Array | undefined,
    actionPolicy: Uint8Array | undefined,
  ): readonly NativeFinding[];
  redact(
    input: string,
    findings: readonly NativeFinding[],
    formatter: NativeFormatterCallback | undefined,
    limits: NativeWholeInputLimits | undefined,
  ): string;
  scanAndRedact(
    input: string,
    policy: NativePolicyCallback | undefined,
    formatter: NativeFormatterCallback | undefined,
    limits: NativeWholeInputLimits | undefined,
    ruleset: Uint8Array | undefined,
    actionPolicy: Uint8Array | undefined,
  ): NativeScanAndRedactResult;
  createIncrementalSanitizer(options: NativeIncrementalOptions): NativeIncrementalSanitizer;
  /**
   * The whole-input comparison primitive: one detection pass, then every
   * side's action and reason per finding
   * (`decision-explain-and-compare-action-policies-over-one-detection-pass`).
   * There is deliberately no session or stream counterpart.
   */
  compareActionPolicies(
    input: string,
    sides: readonly NativeComparedSide[],
    limits: NativeWholeInputLimits | undefined,
    ruleset: Uint8Array | undefined,
  ): NativeActionComparison;
  /**
   * One side of a configuration comparison (`configuration-comparison/v1`,
   * issue #1254): a whole-input pass over a **temporary** registry built from
   * `config` (the `runtime-config/v1` text) and `ruleset` for this call, with
   * one policy evaluated over the finalized findings. It reads and changes no
   * owner and holds nothing. The result is the single-side shape of
   * {@link NativeBinding.compareActionPolicies}; the whole-input limits are the
   * configuration's own. The public wrapper relates the sides; a binding never
   * does. Absent on an artifact built before the comparison existed.
   */
  scanConfigurationSide?(
    input: string,
    config: string | undefined,
    ruleset: Uint8Array | undefined,
    side: NativeComparedSide,
  ): NativeActionComparison;
  /**
   * The core's default evaluation of one finding's safe metadata, as an
   * action name. The default table lives only in the core; nothing here
   * copies it.
   */
  defaultPolicy(finding: NativeDetectedFinding): string;
}

/**
 * What {@link NativeBindingLoader} is asked to load (issue #937).
 *
 * `pii` is `true` when the first `initialize()` carries a non-empty PII
 * selection. A WebAssembly loader then loads its profile's `pii` artifact,
 * the only build that links the PII runtime; otherwise it loads the default
 * artifact, which rejects any PII selection with `PII_SELECTOR_UNAVAILABLE`.
 * The Node addon links the PII runtime in every build and ignores it.
 */
export interface NativeBindingLoadOptions {
  readonly pii: boolean;
}

/** Loads and prepares this runtime's binding. Called at most once per successful load. */
export type NativeBindingLoader = (options: NativeBindingLoadOptions) => Promise<NativeBinding>;
