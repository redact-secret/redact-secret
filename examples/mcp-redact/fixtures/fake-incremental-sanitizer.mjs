/**
 * A deterministic stand-in for `@redact-secret/core`'s
 * `createIncrementalSanitizer`, shaped like `IncrementalSanitizer` (`append`
 * / `finalize` / `abort`) but with maximal buffering: `append` always
 * returns `{ text: "", findings: [] }` and buffers the chunk internally;
 * `finalize` runs `fakeScanAndRedact` once over the whole buffered input and
 * returns the result. This is the opposite extreme from the real session
 * (which emits safe output as soon as a detection window closes), chosen
 * deliberately: it proves the streamed golden path (the boundary's
 * `openStream`, driven by `streaming-tool-result.mjs`) correctly depends on
 * *whatever* the session decides to emit and when, rather than re-deriving
 * chunk boundaries itself — a secret split across two `append` calls is
 * only ever visible whole, at `finalize`, exactly like the real session's
 * own chunk-boundary contract (`crates/secret-scan-core/tests/incremental.rs`).
 *
 * `limits.maxBufferedCodeUnits` is enforced: once the buffered length would
 * exceed it, `append` throws a limit-shaped error, matching the real
 * session's fail-closed `BufferLimitExceededError`.
 */

import { fakeScanAndRedact } from "./fake-scanner.mjs";

class FakeIncrementalSanitizer {
  constructor(limits) {
    this.limits = limits;
    this.buffer = "";
    this.state = "accepting";
  }

  append(chunk) {
    if (this.state !== "accepting") {
      throw new Error(`fake session: append() called in state "${this.state}"`);
    }
    if (this.buffer.length + chunk.length > this.limits.maxBufferedCodeUnits) {
      this.state = "failed";
      const error = new Error("simulated buffer limit exceeded");
      error.code = "BUFFER_LIMIT_EXCEEDED";
      throw error;
    }
    this.buffer += chunk;
    return { text: "", findings: [] };
  }

  finalize() {
    if (this.state !== "accepting") {
      throw new Error(`fake session: finalize() called in state "${this.state}"`);
    }
    this.state = "finalized";
    return fakeScanAndRedact(this.buffer);
  }

  abort() {
    this.state = "aborted";
  }
}

export function createFakeIncrementalSanitizer(limits) {
  return new FakeIncrementalSanitizer(limits);
}
