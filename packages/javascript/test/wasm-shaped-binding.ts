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

import type { NativeBinding, NativeBindingLoader } from "../src/native.js";
import {
  createBindingFromWasmModule,
  type WasmDetectedFindingMetadata,
  type WasmFinding,
  type WasmIncrementalResult,
  type WasmIncrementalSanitizer,
  type WasmModule,
} from "../src/runtime/browser.js";
import { VERSION } from "../src/version.js";

export interface WasmShapedBindingOptions {
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
  const error = new Error(
    "The incremental sanitizer is no longer accepting input.",
  );
  error.name = "SecretScanError";
  Object.assign(error, { code: "INVALID_STATE" });
  return error;
}

export interface WasmShapedBinding {
  readonly calls: string[];
  /** Mirrors `runtime/browser.ts`'s own `loadNativeBinding`, against this fake module instead of a real dynamic import. */
  readonly load: NativeBindingLoader;
}

/** Strips `action`, mirroring `metadata.rs`'s `policy_finding`. */
function toDetectedFindingMetadata(
  finding: WasmFinding,
): WasmDetectedFindingMetadata {
  return {
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence,
    obfuscation: finding.obfuscation,
    range: finding.range,
  };
}

export function createWasmShapedBinding(
  options: WasmShapedBindingOptions = {},
): WasmShapedBinding {
  const calls: string[] = [];
  const findings = options.findings ?? [];
  const redacted = options.redacted ?? "<SECRET_1>";

  const module: WasmModule = {
    default: async () => {
      calls.push("default");
      if (options.throwOnDefault !== undefined) throw options.throwOnDefault;
    },
    version: () => options.version ?? VERSION,
    profile: () => options.profile ?? "full",
    initialize: () => {
      calls.push("initialize");
    },
    scan: (input, policy) => {
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
      calls.push(
        `redact:${input}:${given.length}:${formatter === undefined ? "builtin" : "custom"}`,
      );
      if (formatter !== undefined) {
        given.forEach((finding, index) => {
          formatter(finding, { placeholderIndex: index + 1 });
        });
      }
      return redacted;
    },
    scanAndRedact: (input, policy, formatter) => {
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
      return { text: redacted, findings };
    },
    createIncrementalSanitizer: (
      maxInputCodeUnits,
      _maxBufferedCodeUnits,
      _maxTokenCodeUnits,
      _maxMultilineCodeUnits,
      policy,
      formatter,
    ) => {
      calls.push(`createIncrementalSanitizer:${maxInputCodeUnits}`);
      const incrementalFindings = options.incrementalFindings ?? [];
      let state: WasmIncrementalSanitizer["state"] = "accepting";

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
          return { text: chunk, findings: [] };
        },
        finalize: (): WasmIncrementalResult => {
          requireAccepting();
          state = "finalized";
          incrementalFindings.forEach((finding, index) => {
            policy?.(toDetectedFindingMetadata(finding), { findingIndex: index });
            formatter?.(finding, { placeholderIndex: index + 1 });
          });
          return { text: "", findings: incrementalFindings };
        },
        abort: () => {
          requireAccepting();
          calls.push("abort");
          state = "aborted";
        },
      };
      return session;
    },
  };

  return {
    calls,
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
});
