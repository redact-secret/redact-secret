/**
 * A minimal stand-in for a loaded binding.
 *
 * The N-API addon and the WebAssembly artifact are built and published in
 * lockstep with this package and are not present in a source checkout, so the
 * lifecycle and normalization contracts are exercised against this recorded
 * double instead. It implements the internal binding contract exactly, so a
 * change to that contract breaks these tests rather than passing silently.
 */

import { VERSION } from "../src/version.js";
import type {
  NativeBinding,
  NativeFinding,
  NativeIncrementalSanitizer,
  NativeWholeInputLimits,
} from "../src/native.js";
import type { IncrementalSanitizerState } from "../src/types.js";

export interface FakeBindingOptions {
  readonly version?: string;
  readonly profile?: string;
  readonly findings?: readonly NativeFinding[];
  readonly redacted?: string;
  readonly throwOnScan?: unknown;
  readonly throwOnInitialize?: unknown;
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
  /**
   * The `ruleset` argument the most recent `scan`/`scanAndRedact` call
   * received, with the same "check `calls` first" caveat as
   * {@link lastLimits}.
   */
  readonly lastRuleset: Uint8Array | undefined;
}

export function createFakeBinding(
  options: FakeBindingOptions = {},
): FakeBinding {
  const calls: string[] = [];
  const findings = options.findings ?? [];
  const redacted = options.redacted ?? "<SECRET_1>";
  let lastLimits: NativeWholeInputLimits | undefined;
  let lastRuleset: Uint8Array | undefined;

  function session(): NativeIncrementalSanitizer {
    let state: IncrementalSanitizerState = "accepting";
    function requireAccepting(): void {
      if (state !== "accepting") {
        throw Object.assign(
          new Error("The incremental sanitizer is no longer accepting input."),
          { code: "INVALID_STATE" },
        );
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
    initialize: () => {
      calls.push("initialize");
      if (options.throwOnInitialize !== undefined) {
        throw options.throwOnInitialize;
      }
    },
    scan: (input, policy, limits, ruleset) => {
      lastLimits = limits;
      lastRuleset = ruleset;
      calls.push(`scan:${input}:${policy === undefined ? "builtin" : "custom"}`);
      if (options.throwOnScan !== undefined) throw options.throwOnScan;
      return findings;
    },
    redact: (input, given, formatter, limits) => {
      lastLimits = limits;
      calls.push(
        `redact:${input}:${given.length}:${formatter === undefined ? "builtin" : "custom"}`,
      );
      return redacted;
    },
    scanAndRedact: (input, policy, formatter, limits, ruleset) => {
      lastLimits = limits;
      lastRuleset = ruleset;
      calls.push(
        `scanAndRedact:${input}:${policy === undefined ? "builtin" : "custom"}:${formatter === undefined ? "builtin" : "custom"}`,
      );
      return { text: redacted, findings };
    },
    createIncrementalSanitizer: (incrementalOptions) => {
      calls.push(
        `createIncrementalSanitizer:${incrementalOptions.limits.maxInputCodeUnits}`,
      );
      return session();
    },
    get lastLimits() {
      return lastLimits;
    },
    get lastRuleset() {
      return lastRuleset;
    },
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
