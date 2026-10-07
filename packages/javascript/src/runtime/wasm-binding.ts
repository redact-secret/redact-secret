/**
 * Normalizes a `wasm-bindgen` module's shape to the internal binding contract
 * (`decision-define-runtime-bindings`), independent of which profile compiled
 * it or which literal specifier loaded it.
 *
 * `runtime/browser.ts` (the `full` profile, `@redact-secret/wasm`) and
 * `runtime/browser-common.ts` (the `common` profile,
 * `@redact-secret/wasm/common`,
 * `decision-define-detector-profile-and-pack-contract`) each keep their own
 * `loadWasmModule`/`loadNativeBinding` with their own literal dynamic-import
 * specifier, so a bundler can statically discover and include only the one
 * `.wasm` artifact the entry point a consumer imported actually needs. Both
 * import the shared normalization below instead of duplicating it. Neither
 * file may import the *other* profile's loader module: doing so would give a
 * bundler two literal `import()` specifiers to resolve from one entry point,
 * pulling the unused profile's WebAssembly artifact into a consumer's bundle.
 */

import { SecretScanError } from "../errors.js";
import {
  NATIVE_HANDLE,
  type NativeActionComparison,
  type NativeBinding,
  type NativeDetectedFinding,
  type NativeFinding,
  type NativeFormatterCallback,
  type NativeIncrementalPolicyCallback,
  type NativeIncrementalResult,
  type NativePolicyCallback,
  splitNativeSides,
} from "../native.js";
import type { IncrementalSanitizerState, PlaceholderContext, PolicyContext } from "../types.js";

/** One opaque finding handle, as `scan`/`redact`/`scanAndRedact` return it. */
export interface WasmFinding {
  readonly id: string;
  readonly type: string;
  readonly detector: string;
  readonly confidence: string;
  readonly action: string;
  readonly obfuscation: string;
  readonly range: { readonly start: number; readonly end: number };
  /** Flat twins of `range`: plain numbers, so no `Range` handle is allocated. */
  readonly start: number;
  readonly end: number;
}

/**
 * What `scanAndRedact` returns. The wrapper reads each part once through a
 * consuming accessor (no clone in linear memory) and then frees the handle.
 */
export interface WasmScanAndRedactResult {
  takeText(): string;
  takeFindings(): readonly WasmFinding[];
  free(): void;
}

/**
 * The safe metadata a `policy` callback is actually invoked with
 * (`bindings/wasm/src/metadata.rs`'s `policy_finding`): the same fields as
 * {@link WasmFinding} minus `action`, with the range still nested rather than
 * flattened onto the object.
 */
export interface WasmDetectedFindingMetadata {
  readonly id: string;
  readonly type: string;
  readonly detector: string;
  readonly confidence: string;
  readonly obfuscation: string;
  readonly range: { readonly start: number; readonly end: number };
}

/**
 * The safe metadata a `formatter` callback is actually invoked with
 * (`metadata.rs`'s `formatter_finding`): adds the `action` the policy already
 * chose.
 */
export interface WasmFindingMetadata extends WasmDetectedFindingMetadata {
  readonly action: string;
}

type WasmPolicyCallback = (finding: WasmDetectedFindingMetadata, context: PolicyContext) => string;

type WasmFormatterCallback = (finding: WasmFindingMetadata, context: PlaceholderContext) => string;

/** The position information an incremental policy callback receives. */
export interface WasmIncrementalPolicyContext {
  readonly findingIndex: number;
}

type WasmIncrementalPolicyCallback = (
  finding: WasmDetectedFindingMetadata,
  context: WasmIncrementalPolicyContext,
) => string;

/** The result of one incremental `append`/`finalize` call. */
export interface WasmIncrementalResult {
  takeText(): string;
  takeFindings(): readonly WasmFinding[];
  free(): void;
}

/** The `IncrementalSanitizer` class `createIncrementalSanitizer` returns. */
export interface WasmIncrementalSanitizer {
  readonly state: string;
  append(chunk: string): WasmIncrementalResult;
  finalize(): WasmIncrementalResult;
  abort(): void;
}

export interface WasmModule {
  /**
   * `runtime/browser.ts`/`browser-common.ts` call this with no argument,
   * which `fetch`es the `.wasm` binary relative to the generated glue's own
   * `import.meta.url`. `runtime/node.ts`'s WebAssembly fallback
   * (`decision-add-node-wasm-fallback`) instead passes
   * `{ module_or_path: <bytes already read from disk> }`, instantiating
   * directly rather than through `fetch` — the same generated function, one
   * documented alternate calling convention, not a second build target.
   * `runtime/workerd.ts`/`workerd-common.ts` (`decision-verify-edge-runtimes`)
   * pass a third: an already-compiled module object a bundler's `.wasm`
   * import resolved, typed here as `object` rather than the real
   * `WebAssembly.Module` because this package's `lib.ES2022`-only
   * `tsconfig.json` deliberately excludes `dom`, so no runtime file's
   * type-checking depends on browser-only globals.
   */
  default(source?: { module_or_path: Uint8Array | object }): Promise<unknown>;
  version(): string;
  profile(): string;
  initialize(pii: readonly string[], detection?: string): void;
  piiActivation(): string;
  /** The artifact's `artifact-manifest/v1` document as JSON text (side-effect free). */
  artifactManifest?(): string;
  /** The `config-resolution/v1` document as JSON text (pure; `bindings/wasm/src/lib.rs`). */
  resolveConfig?(
    config: string | undefined,
    ruleset: Uint8Array | undefined,
    actionPolicy: Uint8Array | undefined,
    callback: boolean,
    disclose: boolean,
  ): string;
  scan(
    input: string,
    policy?: WasmPolicyCallback,
    maxInputBytes?: number,
    maxFindings?: number,
    ruleset?: Uint8Array,
    actionPolicy?: Uint8Array,
  ): readonly WasmFinding[];
  redact(
    input: string,
    findings: readonly WasmFinding[],
    formatter?: WasmFormatterCallback,
    maxInputBytes?: number,
    maxFindings?: number,
  ): string;
  scanAndRedact(
    input: string,
    policy?: WasmPolicyCallback,
    formatter?: WasmFormatterCallback,
    maxInputBytes?: number,
    maxFindings?: number,
    ruleset?: Uint8Array,
    actionPolicy?: Uint8Array,
  ): WasmScanAndRedactResult;
  createIncrementalSanitizer(
    maxInputCodeUnits: number,
    maxBufferedCodeUnits: number,
    maxTokenCodeUnits: number,
    maxMultilineCodeUnits: number,
    policy?: WasmIncrementalPolicyCallback,
    formatter?: WasmFormatterCallback,
    actionPolicy?: Uint8Array,
  ): WasmIncrementalSanitizer;
  /**
   * The whole-input comparison (`bindings/wasm/src/compare.rs`): the sides as
   * the parallel `kinds`/`documents`/`callbacks` arrays
   * {@link splitNativeSides} builds, and one flat array that
   * {@link decodeComparison} rebuilds into the nested shape.
   */
  compareActionPolicies(
    input: string,
    kinds: string[],
    documents: Uint8Array[],
    callbacks: WasmPolicyCallback[],
    maxInputBytes?: number,
    maxFindings?: number,
    ruleset?: Uint8Array,
  ): readonly unknown[];
  /**
   * One side of a configuration comparison (`bindings/wasm/src/lib.rs`): a
   * temporary registry from `config` and `ruleset`, one policy side as the
   * parallel arrays above, and the same flat array for one side. Absent on an
   * artifact built before the comparison existed.
   */
  scanConfigurationSide?(
    input: string,
    config: string | undefined,
    ruleset: Uint8Array | undefined,
    kinds: string[],
    documents: Uint8Array[],
    callbacks: WasmPolicyCallback[],
  ): readonly unknown[];
  defaultPolicy(
    id: string,
    type: string,
    detector: string,
    confidence: string,
    obfuscation: string,
    start: number,
    end: number,
  ): string;
}

/**
 * The exports every profile's compiled `wasm-bindgen` module must have.
 * Shared by `runtime/browser.ts` and `runtime/browser-common.ts` so the
 * required-export list has one definition even though each keeps its own
 * literal dynamic-import specifier (see this module's own comment on why).
 */
const REQUIRED_WASM_EXPORTS = [
  "default",
  "version",
  "profile",
  "initialize",
  "scan",
  "redact",
  "scanAndRedact",
  "createIncrementalSanitizer",
  "compareActionPolicies",
  "defaultPolicy",
] as const;

/** Throws `INITIALIZATION_FAILED` unless every required export is present. */
export function assertWasmModuleShape(module: Partial<WasmModule>): asserts module is WasmModule {
  for (const name of REQUIRED_WASM_EXPORTS) {
    if (typeof module[name] !== "function") {
      throw new SecretScanError("INITIALIZATION_FAILED");
    }
  }
}

/**
 * Flattens an opaque handle into the contract's shape while keeping the handle
 * itself, because the WebAssembly `redact` only accepts the objects its own
 * `scan` returned.
 */
function toNativeFinding(finding: WasmFinding): NativeFinding {
  return {
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    action: finding.action,
    obfuscation: finding.obfuscation,
    start: finding.start,
    end: finding.end,
    [NATIVE_HANDLE]: finding,
  };
}

/** Recovers the handle `scan` produced, refusing a foreign finding. */
function toWasmFinding(finding: NativeFinding): WasmFinding {
  const handle = finding[NATIVE_HANDLE];
  if (handle === undefined) throw new SecretScanError("INVALID_FINDINGS");
  return handle as WasmFinding;
}

/**
 * Flattens and freezes the nested-`range` metadata a `policy` callback is
 * actually invoked with, so a callback crossing this boundary sees the same
 * numeric `start`/`end` fields it sees on Node, matching `types.ts`.
 */
function toNativeDetectedFinding(finding: WasmDetectedFindingMetadata): NativeDetectedFinding {
  const { start, end } = finding.range;
  return Object.freeze({
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    obfuscation: finding.obfuscation,
    start,
    end,
  });
}

/** As {@link toNativeDetectedFinding}, plus the `action` a formatter sees. */
function toNativeFormatterMetadata(finding: WasmFindingMetadata): NativeFinding {
  const { start, end } = finding.range;
  return Object.freeze({
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    action: finding.action,
    obfuscation: finding.obfuscation,
    start,
    end,
  });
}

function toWasmPolicyCallback(policy: NativePolicyCallback | undefined): WasmPolicyCallback | undefined {
  if (policy === undefined) return undefined;
  return (finding, context) => policy(toNativeDetectedFinding(finding), context);
}

function toWasmFormatterCallback(formatter: NativeFormatterCallback | undefined): WasmFormatterCallback | undefined {
  if (formatter === undefined) return undefined;
  return (finding, context) => formatter(toNativeFormatterMetadata(finding), context);
}

function toWasmIncrementalPolicyCallback(
  policy: NativeIncrementalPolicyCallback | undefined,
): WasmIncrementalPolicyCallback | undefined {
  if (policy === undefined) return undefined;
  return (finding, context) => policy(toNativeDetectedFinding(finding), context);
}

function toNativeIncrementalResult(result: WasmIncrementalResult): NativeIncrementalResult {
  try {
    return {
      text: result.takeText(),
      findings: result.takeFindings().map(toNativeFinding),
    };
  } finally {
    result.free();
  }
}

/**
 * Rebuilds the nested comparison the Node addon returns from the flat array
 * the WebAssembly artifact returns (`bindings/wasm/src/compare.rs`, which
 * documents the layout). A flat array keeps the artifact small; this is the
 * one place that knows it, and a value that is not the expected kind fails
 * closed as an unusable artifact rather than being passed on.
 *
 * Exported so a test can exercise the layout against a hand-built array.
 */
export function decodeComparison(flat: readonly unknown[]): NativeActionComparison {
  let cursor = 0;
  const fail = (): never => {
    throw new SecretScanError("INITIALIZATION_FAILED");
  };
  const text = (): string => {
    const value = flat[cursor++];
    return typeof value === "string" ? value : fail();
  };
  const nullableText = (): string | null => {
    const value = flat[cursor++];
    return value === null || typeof value === "string" ? value : fail();
  };
  const number = (): number => {
    const value = flat[cursor++];
    return typeof value === "number" ? value : fail();
  };
  const nullableNumber = (): number | null => {
    const value = flat[cursor++];
    return value === null || typeof value === "number" ? value : fail();
  };
  const boolean = (): boolean => {
    const value = flat[cursor++];
    return typeof value === "boolean" ? value : fail();
  };

  const detection = { activationIdentity: text(), profile: nullableText(), detectorCount: number() };
  const sideCount = number();
  const sides = Array.from({ length: sideCount }, () => ({
    kind: text(),
    documentSha256: nullableText(),
    redact: number(),
    block: number(),
    warn: number(),
    allow: number(),
  }));
  const changedCount = number();
  const findingCount = number();
  const findings = Array.from({ length: findingCount }, () => ({
    id: text(),
    type: text(),
    detector: text(),
    confidence: text(),
    obfuscation: text(),
    start: number(),
    end: number(),
    differs: boolean(),
    decisions: Array.from({ length: sideCount }, () => ({
      action: text(),
      basis: text(),
      ruleId: nullableText(),
      ruleIndex: nullableNumber(),
    })),
  }));
  if (cursor !== flat.length) fail();
  return { detection, sides, changedCount, findings };
}

/**
 * Builds the internal binding contract from an already-loaded WebAssembly
 * module.
 *
 * Exported so a test double can exercise this exact normalization — the
 * nested-metadata flattening above and the incremental session wiring below
 * — against a fake module shaped like the real artifact, without loading the
 * artifact itself.
 */
export function createBindingFromWasmModule(wasm: WasmModule): NativeBinding {
  const readManifest = wasm.artifactManifest;
  const resolve = wasm.resolveConfig;
  const scanSide = wasm.scanConfigurationSide;
  return {
    version: () => wasm.version(),
    profile: () => wasm.profile(),
    artifact: () => "wasm",
    initialize: (pii = [], detection) => {
      wasm.initialize(pii, detection);
    },
    piiActivation: () => wasm.piiActivation(),
    ...(readManifest === undefined ? {} : { artifactManifest: () => readManifest.call(wasm) }),
    ...(resolve === undefined
      ? {}
      : {
          resolveConfig: (config, ruleset, actionPolicy, callback, disclose) =>
            resolve.call(wasm, config, ruleset, actionPolicy, callback, disclose),
        }),
    ...(scanSide === undefined
      ? {}
      : {
          scanConfigurationSide: (input, config, ruleset, side) => {
            const { kinds, documents, callbacks } = splitNativeSides([side]);
            return decodeComparison(
              scanSide.call(
                wasm,
                input,
                config,
                ruleset,
                kinds,
                documents,
                callbacks.map((callback) => toWasmPolicyCallback(callback) as WasmPolicyCallback),
              ),
            );
          },
        }),
    scan: (input, policy, limits, ruleset, actionPolicy) =>
      wasm
        .scan(input, toWasmPolicyCallback(policy), limits?.maxInputBytes, limits?.maxFindings, ruleset, actionPolicy)
        .map(toNativeFinding),
    redact: (input, findings, formatter, limits) =>
      wasm.redact(
        input,
        findings.map(toWasmFinding),
        toWasmFormatterCallback(formatter),
        limits?.maxInputBytes,
        limits?.maxFindings,
      ),
    scanAndRedact: (input, policy, formatter, limits, ruleset, actionPolicy) => {
      const result = wasm.scanAndRedact(
        input,
        toWasmPolicyCallback(policy),
        toWasmFormatterCallback(formatter),
        limits?.maxInputBytes,
        limits?.maxFindings,
        ruleset,
        actionPolicy,
      );
      try {
        return {
          text: result.takeText(),
          findings: result.takeFindings().map(toNativeFinding),
        };
      } finally {
        result.free();
      }
    },
    createIncrementalSanitizer: (options) => {
      const session = wasm.createIncrementalSanitizer(
        options.limits.maxInputCodeUnits,
        options.limits.maxBufferedCodeUnits,
        options.limits.maxTokenCodeUnits,
        options.limits.maxMultilineCodeUnits,
        toWasmIncrementalPolicyCallback(options.policy),
        toWasmFormatterCallback(options.formatter),
        options.actionPolicy,
      );
      return {
        get state() {
          return session.state as IncrementalSanitizerState;
        },
        append: (chunk) => toNativeIncrementalResult(session.append(chunk)),
        finalize: () => toNativeIncrementalResult(session.finalize()),
        abort: () => {
          session.abort();
        },
      };
    },
    compareActionPolicies: (input, sides, limits, ruleset) => {
      const { kinds, documents, callbacks } = splitNativeSides(sides);
      return decodeComparison(
        wasm.compareActionPolicies(
          input,
          kinds,
          documents,
          callbacks.map((callback) => toWasmPolicyCallback(callback) as WasmPolicyCallback),
          limits?.maxInputBytes,
          limits?.maxFindings,
          ruleset,
        ),
      );
    },
    defaultPolicy: (finding) =>
      wasm.defaultPolicy(
        finding.id,
        finding.type,
        finding.detector,
        finding.confidence,
        finding.obfuscation,
        finding.start,
        finding.end,
      ),
  };
}
