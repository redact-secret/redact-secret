/**
 * A minimal stand-in for a loaded binding.
 *
 * The N-API addon and the WebAssembly artifact are built and published in
 * lockstep with this package and are not present in a source checkout, so the
 * lifecycle and normalization contracts are exercised against this recorded
 * double instead. It implements the internal binding contract exactly, so a
 * change to that contract breaks these tests rather than passing silently.
 */

import type {
  NativeBinding,
  NativeFinding,
  NativeIncrementalLimits,
  NativeIncrementalOptions,
  NativeIncrementalSanitizer,
  NativeWholeInputLimits,
} from "../src/native.js";
import type { IncrementalSanitizerState } from "../src/types.js";
import { VERSION } from "../src/version.js";

export interface FakeBindingOptions {
  readonly version?: string;
  readonly profile?: string;
  readonly findings?: readonly NativeFinding[];
  readonly redacted?: string;
  readonly throwOnScan?: unknown;
  readonly throwOnInitialize?: unknown;
  /**
   * `false` models a WebAssembly artifact built without the PII runtime
   * (issue #937): after the same selector checks, a non-empty selection
   * that is not an activation conflict fails `PII_SELECTOR_UNAVAILABLE`.
   */
  readonly piiRuntime?: boolean;
}

export interface FakeBinding extends NativeBinding {
  readonly calls: string[];
  /**
   * The `limits` argument the most recent `scan`/`redact`/`scanAndRedact`
   * call received — `undefined` both when no such call has happened yet and
   * when the most recent one omitted `limits` (i.e. used the default), so a
   * test that needs to distinguish those two cases should check `calls`
   * first.
   */
  readonly lastLimits: NativeWholeInputLimits | undefined;
  /** The limits the most recent `createIncrementalSanitizer` call received. */
  readonly lastIncrementalLimits: NativeIncrementalLimits | undefined;
  /**
   * The `ruleset` argument the most recent `scan`/`scanAndRedact` call
   * received, with the same "check `calls` first" caveat as
   * {@link lastLimits}.
   */
  readonly lastRuleset: Uint8Array | undefined;
  /**
   * The `actionPolicy` document bytes the most recent `scan`/`scanAndRedact`
   * call received, with the same "check `calls` first" caveat.
   */
  readonly lastActionPolicy: Uint8Array | undefined;
  /** The options the most recent `createIncrementalSanitizer` call received. */
  readonly lastIncrementalOptions: NativeIncrementalOptions | undefined;
}

export function createFakeBinding(options: FakeBindingOptions = {}): FakeBinding {
  const calls: string[] = [];
  const findings = options.findings ?? [];
  const redacted = options.redacted ?? "<SECRET_1>";
  let lastLimits: NativeWholeInputLimits | undefined;
  let lastIncrementalLimits: NativeIncrementalLimits | undefined;
  let lastRuleset: Uint8Array | undefined;
  let lastActionPolicy: Uint8Array | undefined;
  let lastIncrementalOptions: NativeIncrementalOptions | undefined;
  let activation = "credentials=full;selectors=off;families=;vocabulary=pii-context/v2";

  function session(): NativeIncrementalSanitizer {
    let state: IncrementalSanitizerState = "accepting";
    function requireAccepting(): void {
      if (state !== "accepting") {
        throw Object.assign(new Error("The incremental sanitizer is no longer accepting input."), {
          code: "INVALID_STATE",
        });
      }
    }
    return {
      get state() {
        return state;
      },
      append: (chunk: string) => {
        requireAccepting();
        calls.push(`append:${chunk.length}`);
        return { text: chunk, findings: [] };
      },
      finalize: () => {
        requireAccepting();
        state = "finalized";
        return { text: "", findings };
      },
      abort: () => {
        requireAccepting();
        calls.push("abort");
        state = "aborted";
      },
    };
  }

  return {
    calls,
    version: () => options.version ?? VERSION,
    profile: () => options.profile ?? "full",
    artifact: () => "addon",
    initialize: (pii = []) => {
      calls.push("initialize");
      if (options.throwOnInitialize !== undefined) {
        throw options.throwOnInitialize;
      }
      const rejected = pii.includes("PII")
        ? ["PII_SELECTOR_INVALID", "PII selector is invalid."]
        : pii.includes("pii:kr")
          ? ["PII_SELECTOR_UNSUPPORTED", "PII jurisdiction or family is unsupported."]
          : pii.includes("pii:family:global:ambiguous-national-id")
            ? ["PII_SELECTOR_UNAVAILABLE", "PII selection is unavailable in this artifact."]
            : undefined;
      if (rejected !== undefined) {
        throw Object.assign(new Error(rejected[1]), { code: rejected[0] });
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
      const next = `credentials=${options.profile ?? "full"};selectors=${selectors.length === 0 ? "off" : selectors.join(",")};families=${families};vocabulary=pii-context/v2`;
      if (activation !== next && calls.filter((call) => call === "initialize").length > 1) {
        throw Object.assign(new Error("conflict"), { code: "PII_ACTIVATION_CONFLICT" });
      }
      if (options.piiRuntime === false && selectors.length > 0) {
        throw Object.assign(new Error("PII selection is unavailable in this artifact."), {
          code: "PII_SELECTOR_UNAVAILABLE",
        });
      }
      activation = next;
    },
    piiActivation: () => activation,
    scan: (input, policy, limits, ruleset, actionPolicy) => {
      lastLimits = limits;
      lastRuleset = ruleset;
      lastActionPolicy = actionPolicy;
      calls.push(`scan:${input}:${policy === undefined ? "builtin" : "custom"}`);
      if (options.throwOnScan !== undefined) throw options.throwOnScan;
      return findings;
    },
    redact: (input, given, formatter, limits) => {
      lastLimits = limits;
      calls.push(`redact:${input}:${given.length}:${formatter === undefined ? "builtin" : "custom"}`);
      return redacted;
    },
    scanAndRedact: (input, policy, formatter, limits, ruleset, actionPolicy) => {
      lastLimits = limits;
      lastRuleset = ruleset;
      lastActionPolicy = actionPolicy;
      calls.push(
        `scanAndRedact:${input}:${policy === undefined ? "builtin" : "custom"}:${formatter === undefined ? "builtin" : "custom"}`,
      );
      return { text: redacted, findings };
    },
    createIncrementalSanitizer: (incrementalOptions) => {
      lastIncrementalLimits = incrementalOptions.limits;
      lastIncrementalOptions = incrementalOptions;
      calls.push(`createIncrementalSanitizer:${incrementalOptions.limits.maxInputCodeUnits}`);
      return session();
    },
    get lastIncrementalLimits() {
      return lastIncrementalLimits;
    },
    get lastLimits() {
      return lastLimits;
    },
    get lastRuleset() {
      return lastRuleset;
    },
    get lastActionPolicy() {
      return lastActionPolicy;
    },
    get lastIncrementalOptions() {
      return lastIncrementalOptions;
    },
    defaultPolicy: () => "redact",
  };
}

export const sampleFinding: NativeFinding = Object.freeze({
  id: "finding-1",
  type: "contextual_secret",
  detector: "generic-token",
  confidence: "high",
  action: "redact",
  obfuscation: "none",
  start: 8,
  end: 39,
});
