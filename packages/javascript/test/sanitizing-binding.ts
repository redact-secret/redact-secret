/**
 * A deterministic stand-in for a loaded binding that actually sanitizes.
 *
 * The N-API addon and the WebAssembly artifact are not present in a source
 * checkout, and the Rust core's own detection is covered by the crate's
 * partition and conformance suites. What the stream adapters add on top of a
 * session is the part these doubles exist to exercise: a stateful UTF-8
 * decoder across chunk boundaries, hold-back of text whose detection window is
 * still open, absolute finding offsets, and the discard-on-abort contract.
 *
 * So this session implements one deliberately small rule — `api_key=` followed
 * by token characters — with the same hold-back shape the real session has: it
 * emits only text it will not revise, retains the rest, and reports findings
 * with absolute UTF-16 offsets into the logical whole-session input. Every
 * value in every fixture is synthetic.
 */

import { VERSION } from "../src/version.js";
import type {
  NativeBinding,
  NativeFinding,
  NativeIncrementalOptions,
  NativeIncrementalResult,
  NativeIncrementalSanitizer,
} from "../src/native.js";
import type { IncrementalSanitizerState } from "../src/types.js";

const MARKER = "api_key=";
const TOKEN_CHARACTERS = /^[A-Za-z0-9_]*$/;
const COMPLETE_MATCH = /api_key=([A-Za-z0-9_]+)/g;

/** Fails the way the core does: a fixed code the binding layer recognizes. */
function coded(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

/**
 * The first offset in `text` that may still be revised by later input.
 *
 * That is either the start of an unterminated `api_key=` match or the start of
 * a tail that could still grow into the marker.
 */
function settledBoundary(text: string): number {
  const last = text.lastIndexOf(MARKER);
  if (last !== -1 && TOKEN_CHARACTERS.test(text.slice(last + MARKER.length))) {
    return last;
  }
  for (let length = Math.min(MARKER.length - 1, text.length); length > 0; length -= 1) {
    if (text.endsWith(MARKER.slice(0, length))) return text.length - length;
  }
  return text.length;
}

export function createSanitizingBinding(): NativeBinding {
  function session(
    options: NativeIncrementalOptions,
  ): NativeIncrementalSanitizer {
    const { limits, policy, formatter } = options;
    let state: IncrementalSanitizerState = "accepting";
    let pending = "";
    /** Absolute offset of `pending[0]` in the logical whole-session input. */
    let consumed = 0;
    let inputCodeUnits = 0;
    let findingCount = 0;
    let placeholderCount = 0;

    function requireAccepting(): void {
      if (state !== "accepting") {
        throw coded(
          "INVALID_STATE",
          "The incremental sanitizer is no longer accepting input.",
        );
      }
    }

    function fail(code: string, message: string): never {
      state = "failed";
      throw coded(code, message);
    }

    /** Replaces every complete match in `settled`, keeping input offsets. */
    function sanitize(settled: string): NativeIncrementalResult {
      const findings: NativeFinding[] = [];
      let text = "";
      let cursor = 0;
      for (const match of settled.matchAll(COMPLETE_MATCH)) {
        const value = match[1] ?? "";
        const index = match.index ?? 0;
        const start = consumed + index + MARKER.length;
        const finding: NativeFinding = {
          id: `finding-${(findingCount += 1)}`,
          type: "contextual_secret",
          detector: "generic-token",
          confidence: "high",
          action: "redact",
          obfuscation: "none",
          start,
          end: start + value.length,
        };
        const action =
          policy === undefined
            ? "redact"
            : policy(finding, { findingIndex: findings.length });
        const decided = { ...finding, action };
        findings.push(decided);
        text += settled.slice(cursor, index + MARKER.length);
        if (action === "redact" || action === "block") {
          const context = { placeholderIndex: (placeholderCount += 1) };
          let placeholder: string;
          if (formatter === undefined) {
            placeholder = `<SECRET_${context.placeholderIndex}>`;
          } else {
            try {
              placeholder = formatter(decided, context);
            } catch {
              fail("PLACEHOLDER_FAILURE", "The placeholder formatter failed.");
            }
          }
          text += placeholder;
        } else {
          text += value;
        }
        cursor = index + MARKER.length + value.length;
      }
      text += settled.slice(cursor);
      consumed += settled.length;
      return { text, findings };
    }

    function drain(boundary: number): NativeIncrementalResult {
      const settled = pending.slice(0, boundary);
      pending = pending.slice(boundary);
      return sanitize(settled);
    }

    return {
      get state() {
        return state;
      },
      append: (chunk: string) => {
        requireAccepting();
        inputCodeUnits += chunk.length;
        if (inputCodeUnits > limits.maxInputCodeUnits) {
          fail(
            "INPUT_LIMIT_EXCEEDED",
            "Incremental sanitizer input limit exceeded.",
          );
        }
        pending += chunk;
        const result = drain(settledBoundary(pending));
        if (pending.length > limits.maxBufferedCodeUnits) {
          fail(
            "BUFFER_LIMIT_EXCEEDED",
            "Incremental sanitizer buffer limit exceeded.",
          );
        }
        return result;
      },
      finalize: () => {
        requireAccepting();
        const result = drain(pending.length);
        state = "finalized";
        return result;
      },
      abort: () => {
        requireAccepting();
        pending = "";
        state = "aborted";
      },
    };
  }

  return {
    version: () => VERSION,
    profile: () => "full",
    initialize: () => undefined,
    scan: () => [],
    redact: (input: string) => input,
    scanAndRedact: (input: string) => ({ text: input, findings: [] }),
    createIncrementalSanitizer: session,
  };
}
