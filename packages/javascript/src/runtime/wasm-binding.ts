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
  type NativeBinding,
  type NativeDetectedFinding,
  type NativeFinding,
  type NativeFormatterCallback,
  type NativeIncrementalPolicyCallback,
  type NativeIncrementalResult,
  type NativePolicyCallback,
} from "../native.js";
import type {
  IncrementalSanitizerState,
  PlaceholderContext,
  PolicyContext,
} from "../types.js";

/** One opaque finding handle, as `scan`/`redact`/`scanAndRedact` return it. */
export interface WasmFinding {
  readonly id: string;
  readonly type: string;
  readonly detector: string;
  readonly confidence: string;
  readonly action: string;
  readonly range: { readonly start: number; readonly end: number };
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

type WasmPolicyCallback = (
  finding: WasmDetectedFindingMetadata,
  context: PolicyContext,
) => string;

type WasmFormatterCallback = (
  finding: WasmFindingMetadata,
  context: PlaceholderContext,
) => string;

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
  readonly text: string;
  readonly findings: readonly WasmFinding[];
}

/** The `IncrementalSanitizer` class `createIncrementalSanitizer` returns. */
export interface WasmIncrementalSanitizer {
  readonly state: string;
  append(chunk: string): WasmIncrementalResult;
  finalize(): WasmIncrementalResult;
  abort(): void;
}

export interface WasmModule {
  default(): Promise<unknown>;
  version(): string;
  profile(): string;
  initialize(): void;
  scan(
    input: string,
    policy?: WasmPolicyCallback,
    maxInputBytes?: number,
    maxFindings?: number,
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
  ): { readonly text: string; readonly findings: readonly WasmFinding[] };
  createIncrementalSanitizer(
    maxInputCodeUnits: number,
    maxBufferedCodeUnits: number,
    maxTokenCodeUnits: number,
    maxMultilineCodeUnits: number,
    policy?: WasmIncrementalPolicyCallback,
    formatter?: WasmFormatterCallback,
  ): WasmIncrementalSanitizer;
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
] as const;

/** Throws `INITIALIZATION_FAILED` unless every required export is present. */
export function assertWasmModuleShape(
  module: Partial<WasmModule>,
): asserts module is WasmModule {
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
  const { start, end } = finding.range;
  return {
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    action: finding.action,
    start,
    end,
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
function toNativeDetectedFinding(
  finding: WasmDetectedFindingMetadata,
): NativeDetectedFinding {
  const { start, end } = finding.range;
  return Object.freeze({
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    start,
    end,
  });
}

/** As {@link toNativeDetectedFinding}, plus the `action` a formatter sees. */
function toNativeFormatterMetadata(
  finding: WasmFindingMetadata,
): NativeFinding {
  const { start, end } = finding.range;
  return Object.freeze({
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    action: finding.action,
    start,
    end,
  });
}

function toWasmPolicyCallback(
  policy: NativePolicyCallback | undefined,
): WasmPolicyCallback | undefined {
  if (policy === undefined) return undefined;
  return (finding, context) =>
    policy(toNativeDetectedFinding(finding), context);
}

function toWasmFormatterCallback(
  formatter: NativeFormatterCallback | undefined,
): WasmFormatterCallback | undefined {
  if (formatter === undefined) return undefined;
  return (finding, context) =>
    formatter(toNativeFormatterMetadata(finding), context);
}

function toWasmIncrementalPolicyCallback(
  policy: NativeIncrementalPolicyCallback | undefined,
): WasmIncrementalPolicyCallback | undefined {
  if (policy === undefined) return undefined;
  return (finding, context) =>
    policy(toNativeDetectedFinding(finding), context);
}

function toNativeIncrementalResult(
  result: WasmIncrementalResult,
): NativeIncrementalResult {
  return {
    text: result.text,
    findings: result.findings.map(toNativeFinding),
  };
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
  return {
    version: () => wasm.version(),
    profile: () => wasm.profile(),
    initialize: () => {
      wasm.initialize();
    },
    scan: (input, policy, limits) =>
      wasm
        .scan(
          input,
          toWasmPolicyCallback(policy),
          limits?.maxInputBytes,
          limits?.maxFindings,
        )
        .map(toNativeFinding),
    redact: (input, findings, formatter, limits) =>
      wasm.redact(
        input,
        findings.map(toWasmFinding),
        toWasmFormatterCallback(formatter),
        limits?.maxInputBytes,
        limits?.maxFindings,
      ),
    scanAndRedact: (input, policy, formatter, limits) => {
      const result = wasm.scanAndRedact(
        input,
        toWasmPolicyCallback(policy),
        toWasmFormatterCallback(formatter),
        limits?.maxInputBytes,
        limits?.maxFindings,
      );
      return {
        text: result.text,
        findings: result.findings.map(toNativeFinding),
      };
    },
    createIncrementalSanitizer: (options) => {
      const session = wasm.createIncrementalSanitizer(
        options.limits.maxInputCodeUnits,
        options.limits.maxBufferedCodeUnits,
        options.limits.maxTokenCodeUnits,
        options.limits.maxMultilineCodeUnits,
        toWasmIncrementalPolicyCallback(options.policy),
        toWasmFormatterCallback(options.formatter),
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
  };
}
