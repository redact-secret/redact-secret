/**
 * A test double shaped exactly like the real artifact `bindings/wasm` builds:
 * opaque `Finding` handles with a nested `range` object
 * (`bindings/wasm/src/finding.rs`), the same nested-`range` metadata a custom
 * `policy`/`formatter` callback is actually invoked with
 * (`bindings/wasm/src/metadata.rs`), and the generated `default()` init step
 * ahead of the binding's own idempotent `initialize()`
 * (`bindings/wasm/src/lib.rs`).
 *
 * It is passed through `createBindingFromWasmModule` — the exact
 * normalization `runtime/browser.ts` applies to the real artifact — rather
 * than reimplementing that flattening here, so a regression in that
 * normalization fails these tests instead of passing silently.
 */

import type { NativeActionComparison, NativeBinding, NativeBindingLoader } from "../src/native.js";
import {
  createBindingFromWasmModule,
  type WasmDetectedFindingMetadata,
  type WasmFinding,
  type WasmIncrementalResult,
  type WasmIncrementalSanitizer,
  type WasmModule,
} from "../src/runtime/browser.js";
import { VERSION } from "../src/version.js";
import { emptyNativeComparison } from "./fake-binding.js";

/**
 * The inverse of `decodeComparison`: lays a nested comparison out as the flat
 * array `bindings/wasm/src/compare.rs` returns, so a test can run the decoder
 * against the artifact's real shape.
 */
export function encodeComparison(comparison: NativeActionComparison): unknown[] {
  const flat: unknown[] = [
    comparison.detection.activationIdentity,
    comparison.detection.profile ?? null,
    comparison.detection.detectorCount,
    comparison.sides.length,
  ];
  for (const side of comparison.sides) {
    flat.push(side.kind, side.documentSha256 ?? null, side.redact, side.block, side.warn, side.allow);
  }
  flat.push(comparison.changedCount, comparison.findings.length);
  for (const finding of comparison.findings) {
    flat.push(
      finding.id,
      finding.type,
      finding.detector,
      finding.confidence,
      finding.obfuscation,
      finding.start,
      finding.end,
      finding.differs,
    );
    for (const decision of finding.decisions) {
      flat.push(decision.action, decision.basis, decision.ruleId ?? null, decision.ruleIndex ?? null);
    }
  }
  return flat;
}

export interface WasmShapedBindingOptions {
  /** What `compareActionPolicies` returns; an empty one-side comparison when omitted. */
  readonly comparison?: NativeActionComparison;
  readonly version?: string;
  readonly profile?: string;
  readonly findings?: readonly WasmFinding[];
  readonly redacted?: string;
  readonly throwOnScan?: unknown;
  readonly throwOnDefault?: unknown;
  /** Findings an incremental session's `finalize()` reports. */
  readonly incrementalFindings?: readonly WasmFinding[];
}

/** Builds the fixed `INVALID_STATE` error the real artifact throws. */
function invalidStateError(): Error {
  const error = new Error("The incremental sanitizer is no longer accepting input.");
  error.name = "SecretScanError";
  Object.assign(error, { code: "INVALID_STATE" });
  return error;
}

export interface WasmShapedBinding {
  readonly calls: string[];
  /** The four positional limits the most recent `createIncrementalSanitizer` call received. */
  readonly lastIncrementalLimits: readonly number[] | undefined;
  /** The `actionPolicy` bytes the most recent `scan`/`scanAndRedact`/session call received. */
  readonly lastActionPolicy: Uint8Array | undefined;
  /** The arguments the most recent `defaultPolicy` call received. */
  readonly lastDefaultPolicyArguments: readonly unknown[] | undefined;
  /**
   * The arguments the most recent `compareActionPolicies` call received, with
   * the callbacks reduced to their count.
   */
  readonly lastCompareArguments: readonly unknown[] | undefined;
  /** Mirrors `runtime/browser.ts`'s own `loadNativeBinding`, against this fake module instead of a real dynamic import. */
  readonly load: NativeBindingLoader;
}

/** Strips `action`, mirroring `metadata.rs`'s `policy_finding`. */
function toDetectedFindingMetadata(finding: WasmFinding): WasmDetectedFindingMetadata {
  return {
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    obfuscation: finding.obfuscation,
    range: finding.range,
  };
}

export function createWasmShapedBinding(options: WasmShapedBindingOptions = {}): WasmShapedBinding {
  const calls: string[] = [];
  let lastIncrementalLimits: readonly number[] | undefined;
  let lastActionPolicy: Uint8Array | undefined;
  let lastDefaultPolicyArguments: readonly unknown[] | undefined;
  let lastCompareArguments: readonly unknown[] | undefined;
  const findings = options.findings ?? [];
  const redacted = options.redacted ?? "<SECRET_1>";
  let activation = `credentials=${options.profile ?? "full"};selectors=off;families=;vocabulary=pii-context/v2`;

  const module: WasmModule = {
    default: async () => {
      calls.push("default");
      if (options.throwOnDefault !== undefined) throw options.throwOnDefault;
    },
    version: () => options.version ?? VERSION,
    piiActivation: () => activation,
    profile: () => options.profile ?? "full",
    initialize: (pii) => {
      calls.push("initialize");
      if (pii.includes("PII")) {
        throw Object.assign(new Error("PII selector is invalid."), { code: "PII_SELECTOR_INVALID" });
      }
      if (pii.includes("pii:kr")) {
        throw Object.assign(new Error("PII jurisdiction or family is unsupported."), {
          code: "PII_SELECTOR_UNSUPPORTED",
        });
      }
      if (pii.includes("pii:family:global:ambiguous-national-id")) {
        throw Object.assign(new Error("PII selection is unavailable in this artifact."), {
          code: "PII_SELECTOR_UNAVAILABLE",
        });
      }
      const selectors = [...new Set(pii.map((value) => (value === "pii" ? "pii:global" : value)))].sort();
      const jurisdiction = selectors.includes("pii:us");
      const global = selectors.includes("pii:global") || jurisdiction;
      const families = [
        ...(global || selectors.includes("pii:family:global:email") ? ["pii:global:email"] : []),
        ...(global || selectors.includes("pii:family:global:iban") ? ["pii:global:iban"] : []),
        ...(global || selectors.includes("pii:family:global:network-address") ? ["pii:global:network-address"] : []),
        ...(global || selectors.includes("pii:family:global:payment-card") ? ["pii:global:payment-card"] : []),
        ...(global || selectors.includes("pii:family:global:phone") ? ["pii:global:phone"] : []),
        ...(jurisdiction || selectors.includes("pii:family:us:ssn") ? ["pii:us:ssn"] : []),
      ].join(",");
      activation = `credentials=${options.profile ?? "full"};selectors=${selectors.length === 0 ? "off" : selectors.join(",")};families=${families};vocabulary=pii-context/v2`;
    },
    scan: (input, policy, _maxInputBytes, _maxFindings, _ruleset, actionPolicy) => {
      lastActionPolicy = actionPolicy;
      calls.push(`scan:${input}:${policy === undefined ? "builtin" : "custom"}`);
      if (options.throwOnScan !== undefined) throw options.throwOnScan;
      if (policy !== undefined) {
        findings.forEach((finding, index) => {
          policy(toDetectedFindingMetadata(finding), {
            findingIndex: index,
            findingCount: findings.length,
          });
        });
      }
      return findings;
    },
    redact: (input, given, formatter) => {
      calls.push(`redact:${input}:${given.length}:${formatter === undefined ? "builtin" : "custom"}`);
      if (formatter !== undefined) {
        given.forEach((finding, index) => {
          formatter(finding, { placeholderIndex: index + 1 });
        });
      }
      return redacted;
    },
    scanAndRedact: (input, policy, formatter, _maxInputBytes, _maxFindings, _ruleset, actionPolicy) => {
      lastActionPolicy = actionPolicy;
      calls.push(
        `scanAndRedact:${input}:${policy === undefined ? "builtin" : "custom"}:${formatter === undefined ? "builtin" : "custom"}`,
      );
      if (policy !== undefined) {
        findings.forEach((finding, index) => {
          policy(toDetectedFindingMetadata(finding), {
            findingIndex: index,
            findingCount: findings.length,
          });
        });
      }
      if (formatter !== undefined) {
        findings.forEach((finding, index) => {
          formatter(finding, { placeholderIndex: index + 1 });
        });
      }
      return {
        takeText: () => redacted,
        takeFindings: () => findings,
        free: () => {
          calls.push("free");
        },
      };
    },
    createIncrementalSanitizer: (
      maxInputCodeUnits,
      maxBufferedCodeUnits,
      maxTokenCodeUnits,
      maxMultilineCodeUnits,
      policy,
      formatter,
      actionPolicy,
    ) => {
      lastActionPolicy = actionPolicy;
      lastIncrementalLimits = [maxInputCodeUnits, maxBufferedCodeUnits, maxTokenCodeUnits, maxMultilineCodeUnits];
      calls.push(`createIncrementalSanitizer:${maxInputCodeUnits}`);
      const incrementalFindings = options.incrementalFindings ?? [];
      let state: WasmIncrementalSanitizer["state"] = "accepting";

      function incrementalResult(text: string, found: readonly WasmFinding[]): WasmIncrementalResult {
        return {
          takeText: () => text,
          takeFindings: () => found,
          free: () => {
            calls.push("free");
          },
        };
      }

      function requireAccepting(): void {
        if (state !== "accepting") throw invalidStateError();
      }

      const session: WasmIncrementalSanitizer = {
        get state() {
          return state;
        },
        append: (chunk): WasmIncrementalResult => {
          requireAccepting();
          calls.push(`append:${chunk.length}`);
          return incrementalResult(chunk, []);
        },
        finalize: (): WasmIncrementalResult => {
          requireAccepting();
          state = "finalized";
          incrementalFindings.forEach((finding, index) => {
            policy?.(toDetectedFindingMetadata(finding), { findingIndex: index });
            formatter?.(finding, { placeholderIndex: index + 1 });
          });
          return incrementalResult("", incrementalFindings);
        },
        abort: () => {
          requireAccepting();
          calls.push("abort");
          state = "aborted";
        },
      };
      return session;
    },
    compareActionPolicies: (input, kinds, documents, callbacks, maxInputBytes, maxFindings, ruleset) => {
      lastCompareArguments = [input, kinds, documents, callbacks.length, maxInputBytes, maxFindings, ruleset];
      calls.push(`compareActionPolicies:${input}:${kinds.join(",")}`);
      // Each callback runs once per finding with the nested-`range` metadata
      // `bindings/wasm/src/compare.rs` adapts through `callbacks.rs`.
      for (const callback of callbacks) {
        findings.forEach((finding, index) => {
          callback(toDetectedFindingMetadata(finding), { findingIndex: index, findingCount: findings.length });
        });
      }
      return encodeComparison(options.comparison ?? emptyNativeComparison);
    },
    defaultPolicy: (...given) => {
      lastDefaultPolicyArguments = given;
      return "redact";
    },
  };

  return {
    calls,
    get lastCompareArguments() {
      return lastCompareArguments;
    },
    get lastIncrementalLimits() {
      return lastIncrementalLimits;
    },
    get lastActionPolicy() {
      return lastActionPolicy;
    },
    get lastDefaultPolicyArguments() {
      return lastDefaultPolicyArguments;
    },
    load: async (): Promise<NativeBinding> => {
      await module.default();
      return createBindingFromWasmModule(module);
    },
  };
}

export const sampleWasmFinding: WasmFinding = Object.freeze({
  id: "finding-1",
  type: "contextual_secret",
  detector: "generic-token",
  confidence: "high",
  action: "redact",
  obfuscation: "none",
  range: Object.freeze({ start: 8, end: 39 }),
  start: 8,
  end: 39,
});
