/**
 * The runtime-neutral half of both stream adapters: one incremental session,
 * one stateful UTF-8 decoder, and the finding list they produce together.
 *
 * Nothing here imports a `node:` module or touches a host global beyond
 * `TextDecoder`, which both Node.js and browsers provide, so
 * `web-stream.ts` can build on it unchanged (`decision-define-runtime-bindings`).
 *
 * The decoder is fatal and stateful: a chunk may end in the middle of a
 * multibyte character, and the bytes that character continues into arrive in
 * the next chunk. Malformed input is a hard failure rather than a replacement
 * character, because a silent `U+FFFD` would change the text a detector sees.
 *
 * Retained plaintext — the tail the session is still deciding about — never
 * leaves this module. Every termination that is not a normal finalization
 * aborts the session, which discards it.
 */

import { SecretScanError } from "../errors.js";
import type {
  IncrementalSanitizer,
  IncrementalSanitizerResult,
  SecretFinding,
} from "../types.js";

/** One incremental session wrapped as a byte sink. */
export interface StreamSanitizerRuntime {
  /**
   * Every finding whose detection window has closed so far, frozen.
   *
   * Offsets are absolute UTF-16 code units into the logical whole-stream
   * input, exactly as the session reported them; this module never rebases
   * them onto a chunk or onto the sanitized output.
   */
  readonly findings: readonly SecretFinding[];
  append(chunk: Uint8Array): IncrementalSanitizerResult;
  finalize(): IncrementalSanitizerResult;
  abort(): void;
}

export function createStreamSanitizerRuntime(
  session: IncrementalSanitizer,
): StreamSanitizerRuntime {
  const decoder = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  });
  const findings: SecretFinding[] = [];

  /** Idempotent, and safe after the session has already left `accepting`. */
  function abort(): void {
    if (session.state === "accepting") session.abort();
  }

  function decode(chunk?: Uint8Array, stream = false): string {
    try {
      return decoder.decode(chunk, { stream });
    } catch {
      abort();
      throw new SecretScanError("INVALID_UTF8");
    }
  }

  function accumulateFindings(next: readonly SecretFinding[]): void {
    try {
      for (const finding of next) findings.push(finding);
    } catch {
      abort();
      throw new SecretScanError("INVALID_STATE");
    }
  }

  function append(chunk: Uint8Array): IncrementalSanitizerResult {
    if (!(chunk instanceof Uint8Array)) {
      abort();
      throw new SecretScanError("INVALID_CHUNK");
    }
    const result = session.append(decode(chunk, true));
    accumulateFindings(result.findings);
    return result;
  }

  /**
   * Flushes the decoder, then the session.
   *
   * A stream that ends mid-character fails here: the final `decode()` with
   * `stream: false` rejects the truncated sequence rather than emitting a
   * replacement character.
   */
  function finalize(): IncrementalSanitizerResult {
    const decoded = decode();
    let decodedResult: IncrementalSanitizerResult;
    let finalResult: IncrementalSanitizerResult;
    try {
      decodedResult = session.append(decoded);
      finalResult = session.finalize();
    } catch (error) {
      abort();
      throw error;
    }
    accumulateFindings(decodedResult.findings);
    accumulateFindings(finalResult.findings);
    return Object.freeze({
      text: decodedResult.text + finalResult.text,
      findings: Object.freeze([
        ...decodedResult.findings,
        ...finalResult.findings,
      ]),
    });
  }

  return Object.freeze({
    get findings(): readonly SecretFinding[] {
      return Object.freeze([...findings]);
    },
    append,
    finalize,
    abort,
  });
}
