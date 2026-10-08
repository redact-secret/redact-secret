/**
 * The runtime-neutral half of the package: the initialization contract and
 * the operations it gates.
 *
 * {@link createRedactSecretRuntime} takes the loader for one runtime and returns
 * the public operations bound to it. `index.ts` supplies the loader the
 * package's `imports` map selected; tests supply their own. Nothing here
 * inspects the host, imports a `node:` module, or touches a global.
 */

import { toActionComparison } from "./compare.js";
import { parseConfigResolution } from "./config.js";
import { type SideOutcome, toConfigurationComparison } from "./configuration-compare.js";
import { SecretScanError, type SecretScanErrorCode, toSecretScanError } from "./errors.js";
import { defaultPlaceholderFormatter } from "./formatters.js";
import { assertManifestDigest, parseArtifactManifest } from "./manifest.js";
import {
  NATIVE_HANDLE,
  type NativeBinding,
  type NativeBindingLoader,
  type NativeComparedSide,
  type NativeDetectedFinding,
  type NativeFinding,
  type NativeFormatterCallback,
  type NativeIncrementalOptions,
  type NativeIncrementalPolicyCallback,
  type NativeIncrementalSanitizer,
  type NativePolicyCallback,
  type NativeWholeInputLimits,
} from "./native.js";
import type {
  ActionComparison,
  ArtifactKind,
  ArtifactManifest,
  CompareActionPoliciesOptions,
  CompareConfigurationsOptions,
  ComparedPolicyKind,
  ConfigResolution,
  ConfigSnapshot,
  ConfigurationComparison,
  CoreStatus,
  DefaultSecretPolicy,
  DetectedSecretFinding,
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
  IncrementalSanitizerResult,
  InitializeOptions,
  PlaceholderFormatter,
  RedactOptions,
  ResolveConfigOptions,
  RuntimeConfig,
  ScanAndRedactOptions,
  ScanOptions,
  ScanResult,
  SecretAction,
  SecretFinding,
} from "./types.js";
import { VERSION } from "./version.js";

/** Freezes the six documented fields a policy callback is allowed to see. */
function toDetectedSecretFinding(finding: NativeDetectedFinding): DetectedSecretFinding {
  return Object.freeze({
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence as DetectedSecretFinding["confidence"],
    obfuscation: finding.obfuscation as DetectedSecretFinding["obfuscation"],
    start: finding.start,
    end: finding.end,
  });
}

/** Freezes the eight documented fields, preserving any binding handle. */
function toSecretFinding(finding: NativeFinding): SecretFinding {
  const published: SecretFinding = {
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence as SecretFinding["confidence"],
    action: finding.action as SecretFinding["action"],
    obfuscation: finding.obfuscation as SecretFinding["obfuscation"],
    start: finding.start,
    end: finding.end,
  };
  const handle = finding[NATIVE_HANDLE];
  if (handle !== undefined) {
    Object.defineProperty(published, NATIVE_HANDLE, {
      value: handle,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(published);
}

function toSecretFindings(findings: readonly NativeFinding[]): readonly SecretFinding[] {
  return Object.freeze(findings.map(toSecretFinding));
}

/**
 * Re-presents a public finding to the binding that produced it, carrying the
 * binding handle back across when the finding has one.
 *
 * The WebAssembly binding's `redact` accepts only the opaque findings its own
 * `scan` returned; that adapter rejects a finding that arrives without one
 * rather than reinterpreting it. The Node addon reads the plain fields.
 */
function toNativeFinding(finding: SecretFinding): NativeFinding {
  const handle = (finding as { [NATIVE_HANDLE]?: unknown })[NATIVE_HANDLE];
  if (handle === undefined) return finding;
  return { ...finding, [NATIVE_HANDLE]: handle };
}

/**
 * Matches a JavaScript string containing a lone (unpaired) UTF-16 surrogate:
 * a high surrogate not immediately followed by a low surrogate, or a low
 * surrogate not immediately preceded by a high surrogate. Such a code unit
 * has no UTF-8 representation, so it cannot cross into either binding's Rust
 * `&str` (`errors.ts`'s `UNPAIRED_SURROGATE` documentation).
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function requireString(value: unknown): string {
  if (typeof value !== "string") throw new SecretScanError("INVALID_INPUT");
  if (LONE_SURROGATE.test(value)) {
    throw new SecretScanError("UNPAIRED_SURROGATE");
  }
  return value;
}

/**
 * Detection is fixed by the initialization owner, never by a call: a
 * per-call `detection` argument is rejected rather than ignored, because
 * ignoring it would silently run with a different detector set than the
 * caller asked for.
 */
function rejectPerCallDetection(options: unknown): void {
  if (typeof options === "object" && options !== null && Object.hasOwn(options, "detection")) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
}

function toPolicyCallback(policy: ScanOptions["policy"]): NativePolicyCallback | undefined {
  if (policy === undefined) return undefined;
  if (typeof policy !== "object" || typeof policy.evaluate !== "function") {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  return (finding, context) => policy.evaluate(toDetectedSecretFinding(finding), context);
}

/**
 * Routes the exported default formatter back to the binding's own built-in
 * rather than calling across the boundary for every placeholder, so the
 * default path stays exactly the core's.
 */
function toFormatterCallback(formatter: PlaceholderFormatter | undefined): NativeFormatterCallback | undefined {
  if (formatter === undefined || formatter === defaultPlaceholderFormatter) {
    return undefined;
  }
  if (typeof formatter !== "function") {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  return (finding, context) => formatter(toSecretFinding(finding), context);
}

/** Largest value the native bindings' `u32` limit fields can hold. */
const MAX_NATIVE_LIMIT = 0xffff_ffff;

/**
 * Rejects a limit that the bindings' `u32` conversion would silently wrap or
 * truncate instead of refusing: `-1` would become 4 GiB, `2 ** 32 + 4` would
 * become 4, and `1.5` would become 1. Zero is in range here and left to the
 * binding, which rejects it with the same `INVALID_LIMITS`.
 */
function toNativeLimit(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_NATIVE_LIMIT) {
    throw new SecretScanError("INVALID_LIMITS");
  }
  return value;
}

/**
 * Converts an optional public {@link WholeInputLimits} to its native shape.
 * `undefined` passes through unchanged so the binding applies the core's
 * default (`decision-bound-whole-input-operations-by-default`); a value that
 * is present but malformed throws `INVALID_OPTIONS` here rather than
 * reaching the binding as a nonsensical native call. A well-shaped value
 * outside the native range throws `INVALID_LIMITS` ({@link toNativeLimit});
 * zero is left to the binding, which reports the same `INVALID_LIMITS`.
 */
function toNativeWholeInputLimits(limits: ScanOptions["limits"]): NativeWholeInputLimits | undefined {
  if (limits === undefined) return undefined;
  if (
    typeof limits !== "object" ||
    limits === null ||
    typeof limits.maxInputBytes !== "number" ||
    typeof limits.maxFindings !== "number"
  ) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  return {
    maxInputBytes: toNativeLimit(limits.maxInputBytes),
    maxFindings: toNativeLimit(limits.maxFindings),
  };
}

/**
 * Converts an optional public `ruleset` (raw bytes or a UTF-8 string) to the
 * `Uint8Array` every binding accepts (`decision-define-declarative-detector-
 * ruleset-contract`'s "Surface exposure": "a `Uint8Array`/`string` ruleset
 * argument"). A value that is present but neither shape throws
 * `INVALID_OPTIONS` here rather than reaching the binding as a nonsensical
 * native call; a malformed ruleset's own grammar is rejected by the core with
 * `INVALID_RULESET`.
 */
function toNativeRuleset(ruleset: ScanOptions["ruleset"]): Uint8Array | undefined {
  if (ruleset === undefined) return undefined;
  if (typeof ruleset === "string") return new TextEncoder().encode(ruleset);
  if (ruleset instanceof Uint8Array) return ruleset;
  throw new SecretScanError("INVALID_OPTIONS");
}

/**
 * Converts an optional public `actionPolicy` to the document bytes every
 * binding accepts
 * (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`).
 * This package serializes and forwards; the Rust core parses and validates the
 * document, so no grammar rule is restated here.
 *
 * - Text becomes its UTF-8 bytes, and bytes pass through.
 * - A plain object is serialized once, here, with `JSON.stringify` (the
 *   standard compact encoder), so a later mutation of it changes nothing. A
 *   serializer failure (a cycle, a `BigInt`) or a value with no JSON form is
 *   `INVALID_ACTION_POLICY`, as a malformed document. Member order is the
 *   object's insertion order, and the core requires `actionPolicyRevision`
 *   first.
 * - A value of any other kind is `INVALID_OPTIONS`.
 *
 * A callback `policy` and an action policy together are `INVALID_OPTIONS`,
 * reported before the document is serialized or read.
 */
function toNativeActionPolicy(
  actionPolicy: ScanOptions["actionPolicy"],
  hasCallbackPolicy: boolean,
): Uint8Array | undefined {
  if (actionPolicy === undefined) return undefined;
  if (hasCallbackPolicy) throw new SecretScanError("INVALID_OPTIONS");
  if (typeof actionPolicy === "string") return new TextEncoder().encode(actionPolicy);
  if (actionPolicy instanceof Uint8Array) return actionPolicy;
  if (typeof actionPolicy === "object" && actionPolicy !== null) {
    let serialized: unknown;
    try {
      serialized = JSON.stringify(actionPolicy);
    } catch {
      throw new SecretScanError("INVALID_ACTION_POLICY");
    }
    if (typeof serialized !== "string") throw new SecretScanError("INVALID_ACTION_POLICY");
    return new TextEncoder().encode(serialized);
  }
  throw new SecretScanError("INVALID_OPTIONS");
}

/**
 * Checks the shape of the finding metadata handed to `defaultPolicy.evaluate`
 * before it crosses into a binding, so a malformed value is the same fixed
 * `INVALID_FINDINGS` on every runtime rather than whatever a binding's own
 * argument conversion would do. Identifier and vocabulary checks are the
 * core's.
 */
function toNativeDefaultPolicyFinding(finding: unknown): NativeDetectedFinding {
  if (typeof finding !== "object" || finding === null) {
    throw new SecretScanError("INVALID_FINDINGS");
  }
  const record = finding as Readonly<Record<string, unknown>>;
  const { id, type, detector, confidence, obfuscation, start, end } = record;
  if (
    typeof id !== "string" ||
    typeof type !== "string" ||
    typeof detector !== "string" ||
    typeof confidence !== "string" ||
    typeof obfuscation !== "string" ||
    typeof start !== "number" ||
    typeof end !== "number" ||
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 0 ||
    end < 0 ||
    start > MAX_NATIVE_LIMIT ||
    end > MAX_NATIVE_LIMIT
  ) {
    throw new SecretScanError("INVALID_FINDINGS");
  }
  return { id, type, detector, confidence, obfuscation, start, end };
}

/**
 * Returns `value` as a plain record whose own enumerable keys are all in
 * `allowed`, or throws `INVALID_OPTIONS`. The comparison primitive is strict
 * about what it is given so that nothing is silently ignored: a key that could
 * be mistaken for an incremental or stream option, or a field of the wrong
 * side kind, is refused rather than dropped.
 */
function requireExactKeys(value: unknown, allowed: readonly string[]): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  return value as Readonly<Record<string, unknown>>;
}

/** Whether `value` is a plain object: no array, no class instance. */
function isPlainObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

/** The most sides one comparison takes: a baseline and three candidates. */
const MAX_COMPARED_POLICIES = 4;

/**
 * Converts one public `ComparedPolicy` to the side a binding takes.
 *
 * The kind is closed, every kind carries exactly its own field, and a
 * document is serialized to the exact bytes the core will hash and parse
 * ({@link toNativeActionPolicy}), here, once, so a later mutation of an object
 * policy changes nothing.
 */
function toNativeComparedSide(side: unknown): NativeComparedSide {
  const kind = typeof side === "object" && side !== null ? (side as { kind?: unknown }).kind : undefined;
  if (kind === "default") {
    requireExactKeys(side, ["kind"]);
    return { kind };
  }
  if (kind === "action-policy") {
    const record = requireExactKeys(side, ["kind", "actionPolicy"]);
    const document = toNativeActionPolicy(record.actionPolicy as ScanOptions["actionPolicy"], false);
    if (document === undefined) throw new SecretScanError("INVALID_OPTIONS");
    return { kind, document };
  }
  if (kind === "callback") {
    const record = requireExactKeys(side, ["kind", "policy"]);
    const callback = toPolicyCallback(record.policy as ScanOptions["policy"]);
    if (callback === undefined) throw new SecretScanError("INVALID_OPTIONS");
    return { kind, callback };
  }
  throw new SecretScanError("INVALID_OPTIONS");
}

/**
 * Validates and converts the options of `compareActionPolicies`. The side
 * count and every side's shape are checked before anything crosses into a
 * binding, so a malformed call detects nothing and calls no callback.
 */
function toNativeComparison(options: CompareActionPoliciesOptions): {
  readonly sides: readonly NativeComparedSide[];
  readonly limits: NativeWholeInputLimits | undefined;
  readonly ruleset: Uint8Array | undefined;
} {
  const record = requireExactKeys(options, ["policies", "limits", "ruleset"]);
  const policies = record.policies;
  if (!Array.isArray(policies) || policies.length < 1 || policies.length > MAX_COMPARED_POLICIES) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  for (let index = 0; index < policies.length; index += 1) {
    if (!Object.hasOwn(policies, index)) throw new SecretScanError("INVALID_OPTIONS");
  }
  const sides = (policies as readonly unknown[]).map(toNativeComparedSide);
  if (record.limits !== undefined) requireExactKeys(record.limits, ["maxInputBytes", "maxFindings"]);
  return {
    sides,
    limits: toNativeWholeInputLimits(record.limits as ScanOptions["limits"]),
    ruleset: toNativeRuleset(record.ruleset as ScanOptions["ruleset"]),
  };
}

/**
 * Resolves one incremental limit given under its byte name, its deprecated
 * `CodeUnits` name, or both. Both are validated like any limit
 * ({@link toNativeLimit}); a name that is absent or `undefined` is not
 * given. Both given with different values is ambiguous and throws
 * `INVALID_LIMITS` rather than guessing which one the caller meant; neither
 * given throws the same code, as an omitted limit always did.
 */
function resolveIncrementalLimit(limits: object, bytesName: string, legacyName: string): number {
  const record = limits as Readonly<Record<string, unknown>>;
  const bytes = record[bytesName];
  const legacy = record[legacyName];
  if (bytes === undefined) return toNativeLimit(legacy);
  const resolved = toNativeLimit(bytes);
  if (legacy !== undefined && toNativeLimit(legacy) !== resolved) {
    throw new SecretScanError("INVALID_LIMITS");
  }
  return resolved;
}

function toNativeIncrementalOptions(options: IncrementalSanitizerOptions): NativeIncrementalOptions {
  if (typeof options !== "object" || options === null) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  rejectPerCallDetection(options);
  // A ruleset is a whole-input option (`rulesets in incremental sessions` are outside contract 1): a session
  // that ignored one would silently run without the detectors the caller asked for (issue #1255).
  if ("ruleset" in options) throw new SecretScanError("INVALID_OPTIONS");
  const { limits, policy, placeholderFormatter } = options;
  if (typeof limits !== "object" || limits === null) {
    throw new SecretScanError("INVALID_LIMITS");
  }
  const formatter = toFormatterCallback(placeholderFormatter);
  if (policy !== undefined && (typeof policy !== "object" || typeof policy.evaluate !== "function")) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  const policyCallback: NativeIncrementalPolicyCallback | undefined =
    policy === undefined ? undefined : (finding, context) => policy.evaluate(toDetectedSecretFinding(finding), context);
  const actionPolicy = toNativeActionPolicy(options.actionPolicy, policy !== undefined);
  return {
    limits: {
      maxInputCodeUnits: resolveIncrementalLimit(limits, "maxInputBytes", "maxInputCodeUnits"),
      maxBufferedCodeUnits: resolveIncrementalLimit(limits, "maxBufferedBytes", "maxBufferedCodeUnits"),
      maxTokenCodeUnits: resolveIncrementalLimit(limits, "maxTokenBytes", "maxTokenCodeUnits"),
      maxMultilineCodeUnits: resolveIncrementalLimit(limits, "maxMultilineBytes", "maxMultilineCodeUnits"),
    },
    ...(policyCallback === undefined ? {} : { policy: policyCallback }),
    ...(formatter === undefined ? {} : { formatter }),
    ...(actionPolicy === undefined ? {} : { actionPolicy }),
  };
}

export interface RedactSecretRuntime {
  initialize(options?: InitializeOptions): Promise<void>;
  piiActivation(): string;
  status(): CoreStatus;
  artifact(): ArtifactKind;
  artifactManifest(): ArtifactManifest;
  resolveConfig(config?: RuntimeConfig, options?: ResolveConfigOptions): ConfigResolution;
  describeConfig(): ConfigSnapshot;
  scan(input: string, options?: ScanOptions): readonly SecretFinding[];
  redact(input: string, findings: readonly SecretFinding[], options?: RedactOptions): string;
  scanAndRedact(input: string, options?: ScanAndRedactOptions): ScanResult;
  compareActionPolicies(input: string, options: CompareActionPoliciesOptions): ActionComparison;
  compareConfigurations(input: string, options: CompareConfigurationsOptions): ConfigurationComparison;
  createIncrementalSanitizer(options: IncrementalSanitizerOptions): IncrementalSanitizer;
  readonly defaultPolicy: DefaultSecretPolicy;
}

/**
 * Binds the public operations to one runtime's loader.
 *
 * `initialize` is the whole lifecycle contract: it may be awaited any number
 * of times from any number of call sites and loads at most once, it verifies
 * that the loaded artifact reports this package's version
 * (`decision-release-bindings-in-lockstep`) and the expected detector profile
 * (`decision-define-detector-profile-and-pack-contract`), and every
 * synchronous operation below fails with `NOT_INITIALIZED` until exactly one
 * call has succeeded. A failed attempt is not cached: a caller may retry.
 *
 * The PII selection of the call that loads also picks which artifact a
 * WebAssembly runtime loads (issue #937): the default one without the PII
 * runtime, or the `pii` one. Activation is one-shot on both, so a later,
 * different selection is `PII_ACTIVATION_CONFLICT` exactly as before.
 */
export function createRedactSecretRuntime(
  loadNativeBinding: NativeBindingLoader,
  expectedProfile: "full" | "common" | "custom",
): RedactSecretRuntime {
  let binding: NativeBinding | undefined;
  let manifest: ArtifactManifest | undefined;
  let pending: Promise<void> | undefined;
  let pendingKey: string | undefined;
  let activeKey: string | undefined;
  /**
   * The configuration this runtime is fixed to, captured once from the first
   * successful `initialize()`: the `runtime-config/v1` text of its detection
   * and PII members, and the frozen snapshot the core resolved from it. Later
   * equivalent calls do not replace it, and no call changes it.
   */
  let ownerConfig: string | undefined;
  let ownerSnapshot: ConfigSnapshot | undefined;

  /** The parsed, copied options of one `initialize()` call. */
  interface InitializeRequest {
    readonly pii: readonly string[];
    /** The JSON text of the `detection` object, copied at call time; `undefined` when not given. */
    readonly detection: string | undefined;
  }

  function parseInitializeOptions(options?: InitializeOptions): InitializeRequest {
    if (options === undefined) return { pii: [], detection: undefined };
    if (
      typeof options !== "object" ||
      options === null ||
      Array.isArray(options) ||
      (Object.getPrototypeOf(options) !== Object.prototype && Object.getPrototypeOf(options) !== null) ||
      Object.keys(options).some((key) => key !== "pii" && key !== "detection")
    ) {
      throw new SecretScanError("INVALID_OPTIONS");
    }
    const pii = options.pii;
    let selectors: readonly string[] = [];
    if (pii !== undefined) {
      if (!Array.isArray(pii)) throw new SecretScanError("INVALID_OPTIONS");
      for (let index = 0; index < pii.length; index += 1) {
        if (!Object.hasOwn(pii, index) || typeof pii[index] !== "string") {
          throw new SecretScanError("INVALID_OPTIONS");
        }
      }
      selectors = [...pii];
    }
    return { pii: selectors, detection: serializeDetection(options.detection) };
  }

  /**
   * Copies a `detection` value to JSON text once, at call time, so a later
   * mutation of the caller's arrays changes nothing. Only the host shape is
   * checked here (a plain object); the grammar, the ids and the ceiling are
   * the core's, reported as `INVALID_DETECTION_CONFIG` (or, in
   * `resolveConfig`, as diagnostics), so there is one set of rules.
   */
  function serializeDetection(detection: unknown): string | undefined {
    if (detection === undefined) return undefined;
    if (
      typeof detection !== "object" ||
      detection === null ||
      Array.isArray(detection) ||
      (Object.getPrototypeOf(detection) !== Object.prototype && Object.getPrototypeOf(detection) !== null)
    ) {
      throw new SecretScanError("INVALID_OPTIONS");
    }
    let text: unknown;
    try {
      text = JSON.stringify(detection);
    } catch {
      throw new SecretScanError("INVALID_OPTIONS");
    }
    if (typeof text !== "string") throw new SecretScanError("INVALID_OPTIONS");
    return text;
  }

  function selectorKey(pii: readonly string[]): string {
    return [...new Set(pii.map((value) => (value === "pii" ? "pii:global" : value)))].sort().join(",");
  }

  function requestKey(request: InitializeRequest): string {
    return `${selectorKey(request.pii)}\u0000${request.detection ?? ""}`;
  }

  /** The `runtime-config/v1` text of an initialization request's data members. */
  function ownerConfigText(request: InitializeRequest): string {
    const parts: string[] = [];
    if (request.detection !== undefined) parts.push(`"detection":${request.detection}`);
    if (request.pii.length > 0) parts.push(`"pii":${JSON.stringify(request.pii)}`);
    return `{${parts.join(",")}}`;
  }

  async function load(request: InitializeRequest): Promise<void> {
    const { pii, detection } = request;
    let loaded: NativeBinding;
    try {
      // Issue #937: only a PII selection loads the PII-capable artifact, so
      // a WebAssembly runtime that never enables PII never fetches it. The
      // selectors themselves are still validated by the artifact, so an
      // invalid one reports the same `PII_SELECTOR_*` code as before.
      loaded = await loadNativeBinding({ pii: pii.length > 0 });
      if (loaded.version() !== VERSION) {
        throw new SecretScanError("INITIALIZATION_FAILED");
      }
      if (loaded.profile() !== expectedProfile) {
        throw new SecretScanError("INITIALIZATION_FAILED");
      }
      // The artifact's own manifest, when it reports one, must describe this
      // entry point: another schema, version or variant, or a digest that is
      // not the document's own, is an unusable artifact. It reads no PII
      // selection and builds no registry, so it runs before `initialize`.
      const reported = loaded.artifactManifest?.();
      if (reported !== undefined) {
        const parsed = parseArtifactManifest(reported, expectedProfile);
        await assertManifestDigest(parsed);
        manifest = parsed;
      }
      loaded.initialize(pii, detection);
    } catch (thrown) {
      throw toSecretScanError(thrown, "INITIALIZATION_FAILED");
    }
    binding = loaded;
    activeKey = requestKey(request);
    // What the owner is fixed to, resolved once by the core. A binding that
    // reports no configuration leaves it unset: `status().configuration` is
    // then `null` and `describeConfig()` is `INITIALIZATION_FAILED`.
    ownerConfig = ownerConfigText(request);
    try {
      const resolved = resolveWith(loaded, ownerConfig, undefined, undefined, false, false);
      ownerSnapshot = resolved.ok && resolved.snapshot !== null ? resolved.snapshot : undefined;
    } catch {
      ownerSnapshot = undefined;
    }
  }

  function initialize(options?: InitializeOptions): Promise<void> {
    let request: InitializeRequest;
    try {
      request = parseInitializeOptions(options);
    } catch (thrown) {
      return Promise.reject(toSecretScanError(thrown, "INVALID_OPTIONS"));
    }
    const key = requestKey(request);
    if (binding !== undefined) {
      if (activeKey === key) return Promise.resolve();
      try {
        binding.initialize(request.pii, request.detection);
        activeKey = key;
        return Promise.resolve();
      } catch (thrown) {
        return Promise.reject(toSecretScanError(thrown, "INITIALIZATION_FAILED"));
      }
    }
    if (pending !== undefined) {
      return pendingKey === key ? pending : pending.then(() => initialize(options));
    }
    pendingKey = key;
    pending = load(request).finally(() => {
      pending = undefined;
      pendingKey = undefined;
    });
    return pending;
  }

  function active(): NativeBinding {
    if (binding === undefined) throw new SecretScanError("NOT_INITIALIZED");
    return binding;
  }

  /** Which artifact `initialize()` loaded. Requires initialization, like every other operation here. */
  function artifact(): ArtifactKind {
    return active().artifact();
  }

  /**
   * What the loaded artifact contains and supports (`artifact-manifest/v1`).
   * Reports the artifact `initialize()` loaded, so it needs a successful
   * `initialize()` like every other operation here, but it reads no input,
   * builds no registry and changes no activation. An artifact that reports no
   * manifest fails with `INITIALIZATION_FAILED`.
   */
  function artifactManifest(): ArtifactManifest {
    active();
    if (manifest === undefined) throw new SecretScanError("INITIALIZATION_FAILED");
    return manifest;
  }

  function piiActivation(): string {
    const native = active();
    return (
      native.piiActivation?.() ?? `credentials=${expectedProfile};selectors=off;families=;vocabulary=pii-context/v2`
    );
  }

  /**
   * Reports initialization state and the activation identity without loading,
   * initializing or reconfiguring anything. Never throws and never carries an
   * error: a binding exists only after a successful load, so a failed or
   * pending `initialize()` reads as not initialized.
   */
  function status(): CoreStatus {
    const native = binding;
    if (native === undefined) {
      return Object.freeze({ initialized: false, profile: expectedProfile, activation: null, configuration: null });
    }
    let activation: string | null;
    try {
      activation = piiActivation();
    } catch {
      activation = null;
    }
    return Object.freeze({
      initialized: true,
      profile: expectedProfile,
      activation,
      configuration: ownerSnapshot?.digest ?? null,
    });
  }

  /**
   * Asks `native` to resolve one request and checks the answer is a
   * resolution of this artifact's manifest. The core owns the precedence table
   * and the snapshot; nothing here restates either.
   */
  function resolveWith(
    native: NativeBinding,
    config: string | undefined,
    ruleset: Uint8Array | undefined,
    actionPolicy: Uint8Array | undefined,
    callback: boolean,
    disclose: boolean,
  ): ConfigResolution {
    if (native.resolveConfig === undefined) throw new SecretScanError("INITIALIZATION_FAILED");
    let text: string;
    try {
      text = native.resolveConfig(config, ruleset, actionPolicy, callback, disclose);
    } catch (thrown) {
      throw toSecretScanError(thrown, "INITIALIZATION_FAILED");
    }
    return parseConfigResolution(text, manifest?.digest);
  }

  /**
   * Resolves `config` over the artifact's defaults into a frozen
   * `config-resolution/v1` without scanning, building a registry or touching
   * the runtime: invalid input is data in the result, never a throw. Requires a
   * successful `initialize()` like every other operation here, because the
   * resolver is the loaded artifact's own, but changes nothing.
   *
   * Host-shape mistakes (not a plain object, a ruleset that is neither text nor
   * bytes, a value with no JSON form) are `INVALID_OPTIONS`, as they are for a
   * call. The caller's data is copied and serialized once, here, so mutating it
   * afterwards changes nothing.
   */
  function resolveConfig(config?: RuntimeConfig, options?: ResolveConfigOptions): ConfigResolution {
    const native = active();
    if (config !== undefined && !isPlainObject(config)) throw new SecretScanError("INVALID_OPTIONS");
    if (options !== undefined) {
      if (!isPlainObject(options)) throw new SecretScanError("INVALID_OPTIONS");
      if (Object.keys(options).some((key) => key !== "policy" && key !== "discloseRulesetIdentity")) {
        throw new SecretScanError("INVALID_OPTIONS");
      }
      if (options.discloseRulesetIdentity !== undefined && typeof options.discloseRulesetIdentity !== "boolean") {
        throw new SecretScanError("INVALID_OPTIONS");
      }
    }
    const resolveOptions: ResolveConfigOptions | undefined = options;
    const hasCallback = resolveOptions?.policy !== undefined;
    // Validated like a call's callback, and never called.
    if (hasCallback) toPolicyCallback(resolveOptions?.policy);
    let ruleset: Uint8Array | undefined;
    let actionPolicy: Uint8Array | undefined;
    let text: string | undefined;
    if (config !== undefined) {
      const {
        ruleset: rulesetInput,
        actionPolicy: policyInput,
        ...data
      } = config as RuntimeConfig & {
        readonly [key: string]: unknown;
      };
      ruleset = toNativeRuleset(rulesetInput);
      // A callback and a policy document together are reported as a data
      // diagnostic (`INVALID_OPTIONS`), not thrown: the core owns the row.
      actionPolicy = toNativeActionPolicy(policyInput, false);
      try {
        const serialized: unknown = JSON.stringify(data);
        if (typeof serialized !== "string") throw new SecretScanError("INVALID_OPTIONS");
        text = serialized;
      } catch {
        throw new SecretScanError("INVALID_OPTIONS");
      }
    }
    return resolveWith(
      native,
      text,
      ruleset,
      actionPolicy,
      hasCallback,
      resolveOptions?.discloseRulesetIdentity === true,
    );
  }

  /**
   * The snapshot of the configuration this runtime is fixed to: its detection
   * selection and PII activation, and the artifact defaults for everything a
   * call supplies. Input-free: it takes no argument, scans nothing, builds no
   * registry and changes nothing. Requires a successful `initialize()`, and is
   * `INITIALIZATION_FAILED` for an artifact that reports no configuration.
   */
  function describeConfig(): ConfigSnapshot {
    active();
    if (ownerSnapshot === undefined) throw new SecretScanError("INITIALIZATION_FAILED");
    return ownerSnapshot;
  }

  function scan(input: string, options?: ScanOptions): readonly SecretFinding[] {
    const native = active();
    const text = requireString(input);
    rejectPerCallDetection(options);
    const policy = toPolicyCallback(options?.policy);
    const actionPolicy = toNativeActionPolicy(options?.actionPolicy, policy !== undefined);
    const limits = toNativeWholeInputLimits(options?.limits);
    const ruleset = toNativeRuleset(options?.ruleset);
    try {
      return toSecretFindings(native.scan(text, policy, limits, ruleset, actionPolicy));
    } catch (thrown) {
      throw toSecretScanError(thrown, "DETECTOR_FAILURE");
    }
  }

  function redact(input: string, findings: readonly SecretFinding[], options?: RedactOptions): string {
    const native = active();
    const text = requireString(input);
    rejectPerCallDetection(options);
    if (!Array.isArray(findings)) {
      throw new SecretScanError("INVALID_FINDINGS");
    }
    const formatter = toFormatterCallback(options?.placeholderFormatter);
    const limits = toNativeWholeInputLimits(options?.limits);
    try {
      return native.redact(text, findings.map(toNativeFinding), formatter, limits);
    } catch (thrown) {
      throw toSecretScanError(thrown, "INVALID_FINDINGS");
    }
  }

  function scanAndRedact(input: string, options?: ScanAndRedactOptions): ScanResult {
    const native = active();
    const text = requireString(input);
    rejectPerCallDetection(options);
    const policy = toPolicyCallback(options?.policy);
    const actionPolicy = toNativeActionPolicy(options?.actionPolicy, policy !== undefined);
    const formatter = toFormatterCallback(options?.placeholderFormatter);
    const limits = toNativeWholeInputLimits(options?.limits);
    const ruleset = toNativeRuleset(options?.ruleset);
    let result;
    try {
      result = native.scanAndRedact(text, policy, formatter, limits, ruleset, actionPolicy);
    } catch (thrown) {
      throw toSecretScanError(thrown, "DETECTOR_FAILURE");
    }
    return Object.freeze({
      text: result.text,
      findings: toSecretFindings(result.findings),
    });
  }

  /**
   * The whole-input comparison primitive: one detection pass, then what each
   * policy would choose for every finalized finding and why. A preview, never
   * enforcement: it returns no text, and the sanitizer paths are not involved.
   * It takes one string; there is no session or stream form.
   */
  function compareActionPolicies(input: string, options: CompareActionPoliciesOptions): ActionComparison {
    const native = active();
    const text = requireString(input);
    const { sides, limits, ruleset } = toNativeComparison(options);
    try {
      return toActionComparison(native.compareActionPolicies(text, sides, limits, ruleset));
    } catch (thrown) {
      throw toSecretScanError(thrown, "DETECTOR_FAILURE");
    }
  }

  /**
   * The failure codes of a side that was built but could not be scanned,
   * recorded in the result instead of thrown. Every other code is a malformed
   * call or a callback failure and fails the whole comparison.
   */
  const SIDE_FAILURES: readonly string[] = [
    "INPUT_LIMIT_EXCEEDED",
    "FINDING_LIMIT_EXCEEDED",
    "DETECTOR_FAILURE",
    "INVALID_CANDIDATE",
    "EMPTY_DETECTION_SET",
    "INVALID_DETECTION_CONFIG",
    "INVALID_RULESET",
    "PII_SELECTOR_INVALID",
    "PII_SELECTOR_UNSUPPORTED",
    "PII_SELECTOR_UNAVAILABLE",
  ];

  /**
   * Compares detection configurations over one input (`configuration-comparison/v1`,
   * issue #1254): each side is an independent pass over a temporary registry
   * the artifact builds for that call from the side's own `detection`, `pii`,
   * `ruleset` and `limits`, then the sides' finalized findings are related by
   * their declared-unit ranges. A preview, never enforcement; it returns no
   * text and changes no owner. It reads the loaded artifact's resolver and
   * registry constructors, so it needs a successful `initialize()`, but it
   * neither requires nor changes the owner's `detection` or `pii` (a side the
   * artifact cannot build, such as PII on an artifact without the PII runtime,
   * is a failed side). It takes one string; there is no session or stream form.
   *
   * Every side is validated and resolved before any side is scanned, so a
   * malformed call or an invalid action policy document detects nothing and
   * calls no callback. A configuration problem or a limit is data in the
   * result.
   */
  function compareConfigurations(input: string, options: CompareConfigurationsOptions): ConfigurationComparison {
    const native = active();
    const text = requireString(input);
    const record = requireExactKeys(options, ["configs", "actionPolicy", "policy"]);
    const configs = record.configs;
    if (!Array.isArray(configs) || configs.length < 1 || configs.length > MAX_COMPARED_POLICIES) {
      throw new SecretScanError("INVALID_OPTIONS");
    }
    for (let index = 0; index < configs.length; index += 1) {
      if (!Object.hasOwn(configs, index) || !isPlainObject(configs[index])) {
        throw new SecretScanError("INVALID_OPTIONS");
      }
    }
    const callback = toPolicyCallback(record.policy as CompareConfigurationsOptions["policy"]);
    const shared = toNativeActionPolicy(
      record.actionPolicy as CompareConfigurationsOptions["actionPolicy"],
      callback !== undefined,
    );
    const sides = (configs as readonly RuntimeConfig[]).map((config) => {
      const {
        ruleset: rulesetInput,
        actionPolicy: policyInput,
        ...data
      } = config as RuntimeConfig & Record<string, unknown>;
      const ruleset = toNativeRuleset(rulesetInput);
      const own = toNativeActionPolicy(policyInput, callback !== undefined);
      let configText: string;
      try {
        const serialized: unknown = JSON.stringify(data);
        if (typeof serialized !== "string") throw new SecretScanError("INVALID_OPTIONS");
        configText = serialized;
      } catch {
        throw new SecretScanError("INVALID_OPTIONS");
      }
      const document = own ?? shared;
      const side: NativeComparedSide =
        callback !== undefined
          ? { kind: "callback", callback }
          : document !== undefined
            ? { kind: "action-policy", document }
            : { kind: "default" };
      return {
        configText,
        ruleset,
        side,
        resolution: resolveWith(native, configText, ruleset, document, callback !== undefined, false),
      };
    });
    // A rejected policy document is a malformed call, like for
    // `compareActionPolicies`: it fails before any side is scanned.
    if (sides.some((side) => side.resolution.diagnostics.items.some((item) => item.code === "INVALID_ACTION_POLICY"))) {
      throw new SecretScanError("INVALID_ACTION_POLICY");
    }
    if (native.scanConfigurationSide === undefined) throw new SecretScanError("INITIALIZATION_FAILED");

    const outcomes: SideOutcome[] = sides.map(({ configText, ruleset, side, resolution }, index) => {
      const snapshot = resolution.snapshot;
      const kind: ComparedPolicyKind = side.kind;
      const digest = snapshot?.actionPolicy.digest ?? null;
      const summary = Object.freeze({
        label: index === 0 ? "baseline" : `candidate-${index}`,
        digest: snapshot?.digest ?? null,
        detectionDigest: snapshot?.detectionDigest ?? null,
        origins: snapshot?.origins ?? null,
        diagnostics: resolution.diagnostics.items,
        policy: Object.freeze({
          kind,
          documentSha256: kind === "action-policy" && digest !== null ? digest.replace(/^sha256:/, "") : null,
        }),
      });
      if (snapshot === null) {
        const failure =
          resolution.diagnostics.items.find((item) => item.severity === "error")?.code ?? "INVALID_OPTIONS";
        return { summary, failure, native: null };
      }
      if (snapshot.effects.inert) return { summary, failure: "EMPTY_DETECTION_SET", native: null };
      try {
        return {
          summary,
          failure: null,
          native: native.scanConfigurationSide?.(text, configText, ruleset, side) ?? null,
        };
      } catch (thrown) {
        const error = toSecretScanError(thrown, "DETECTOR_FAILURE");
        if (!SIDE_FAILURES.includes(error.code)) throw error;
        return { summary, failure: error.code, native: null };
      }
    });
    return toConfigurationComparison(outcomes);
  }

  function createIncrementalSanitizer(options: IncrementalSanitizerOptions): IncrementalSanitizer {
    const native = active();
    let session: NativeIncrementalSanitizer;
    try {
      session = native.createIncrementalSanitizer(toNativeIncrementalOptions(options));
    } catch (thrown) {
      throw toSecretScanError(thrown, "INVALID_LIMITS");
    }

    // Host validation cannot reach the core; abort releases its buffer and index.
    let inputFailed = false;

    function requireAccepting(): void {
      if (inputFailed || session.state !== "accepting") {
        throw new SecretScanError("INVALID_STATE");
      }
    }

    function run(
      operation: () => {
        readonly text: string;
        readonly findings: readonly NativeFinding[];
      },
      fallback: SecretScanErrorCode,
    ): IncrementalSanitizerResult {
      let result;
      try {
        result = operation();
      } catch (thrown) {
        throw toSecretScanError(thrown, fallback);
      }
      return Object.freeze({
        text: result.text,
        findings: toSecretFindings(result.findings),
      });
    }

    return Object.freeze({
      get state() {
        return inputFailed ? "failed" : session.state;
      },
      append: (chunk: string) => {
        requireAccepting();
        let text;
        try {
          text = requireString(chunk);
        } catch (thrown) {
          inputFailed = true;
          try {
            session.abort();
          } finally {
            throw toSecretScanError(thrown, "INVALID_INPUT");
          }
        }
        return run(() => session.append(text), "DETECTOR_FAILURE");
      },
      finalize: () => {
        requireAccepting();
        return run(() => session.finalize(), "DETECTOR_FAILURE");
      },
      abort: () => {
        requireAccepting();
        try {
          session.abort();
        } catch (thrown) {
          throw toSecretScanError(thrown, "INVALID_STATE");
        }
      },
    });
  }

  /**
   * The core's default evaluation as a policy, for "mine, else the default"
   * callbacks. The decision runs in the core through the loaded binding; this
   * package holds no copy of the default table. It needs a successful
   * `initialize()` like every other operation, and it is a policy for both
   * whole-input calls and incremental sessions, since the default reads
   * neither context.
   */
  const defaultPolicy: DefaultSecretPolicy = Object.freeze({
    evaluate(finding: DetectedSecretFinding): SecretAction {
      const native = active();
      const metadata = toNativeDefaultPolicyFinding(finding);
      try {
        return native.defaultPolicy(metadata) as SecretAction;
      } catch (thrown) {
        throw toSecretScanError(thrown, "INVALID_FINDINGS");
      }
    },
  });

  return {
    initialize,
    piiActivation,
    status,
    artifact,
    artifactManifest,
    resolveConfig,
    describeConfig,
    scan,
    redact,
    scanAndRedact,
    compareActionPolicies,
    compareConfigurations,
    createIncrementalSanitizer,
    defaultPolicy,
  };
}
