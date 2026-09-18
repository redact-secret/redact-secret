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
export const NATIVE_HANDLE: unique symbol = Symbol.for(
  "@redact-secret/core.native-handle",
);

export interface NativeFinding {
  readonly id: string;
  readonly type: string;
  readonly detector: string;
  readonly confidence: string;
  readonly action: string;
  readonly start: number;
  readonly end: number;
  readonly [NATIVE_HANDLE]?: unknown;
}

export interface NativeDetectedFinding {
  readonly id: string;
  readonly type: string;
  readonly detector: string;
  readonly confidence: string;
  readonly start: number;
  readonly end: number;
}

export type NativePolicyCallback = (
  finding: NativeDetectedFinding,
  context: PolicyContext,
) => string;

export type NativeIncrementalPolicyCallback = (
  finding: NativeDetectedFinding,
  context: IncrementalPolicyContext,
) => string;

export type NativeFormatterCallback = (
  finding: NativeFinding,
  context: PlaceholderContext,
) => string;

export interface NativeScanAndRedactResult {
  readonly text: string;
  readonly findings: readonly NativeFinding[];
}

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

export interface NativeBinding {
  /** The shared product version this artifact was built from. */
  version(): string;
  /** The detector profile this artifact was built from: `"full"` or `"common"`. */
  profile(): string;
  /** Idempotent native setup. May be a no-op, as it is on Node. */
  initialize(): void;
  scan(
    input: string,
    policy: NativePolicyCallback | undefined,
  ): readonly NativeFinding[];
  redact(
    input: string,
    findings: readonly NativeFinding[],
    formatter: NativeFormatterCallback | undefined,
  ): string;
  scanAndRedact(
    input: string,
    policy: NativePolicyCallback | undefined,
    formatter: NativeFormatterCallback | undefined,
  ): NativeScanAndRedactResult;
  createIncrementalSanitizer(
    options: NativeIncrementalOptions,
  ): NativeIncrementalSanitizer;
}

/** Loads and prepares this runtime's binding. Called at most once. */
export type NativeBindingLoader = () => Promise<NativeBinding>;
