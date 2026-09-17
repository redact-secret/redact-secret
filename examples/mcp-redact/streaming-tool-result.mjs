/**
 * Redaction for a tool result assembled progressively — a server tool
 * handler piping a subprocess, file, or HTTP response in chunks before
 * returning one `CallToolResult` — built directly on
 * `createIncrementalSanitizer`/`IncrementalSanitizer`
 * (`packages/javascript/src/index.ts`), the same bounded session the byte
 * stream adapters use. This is deliberately *not* wired to any MCP
 * streaming transport: the base MCP protocol resolves one `CallToolResult`
 * per call, and the SDK's chunked delivery (the `experimental.tasks`
 * streaming API) is marked unstable ("may change without notice") in
 * `@modelcontextprotocol/sdk@1.30.0`. Feeding chunks through the incremental
 * sanitizer instead of scanning the whole assembled text at once keeps a
 * secret split across chunk boundaries from ever reaching an unbounded
 * buffer, and gives the same "no environment-derived or silent defaults"
 * limits contract streaming callers of this package already expect.
 *
 * `createSession` is injected — `(limits, policy) =>
 * IncrementalSanitizer`-shaped `{ append, finalize, abort }` — so this file
 * is testable without the built native addon, using a fake session
 * (`fixtures/fake-incremental-sanitizer.mjs`) instead of the real one.
 */

/** Every declared limit the session throws `*LimitExceeded` for is treated
 * identically: fail closed. No text accumulated before the limit was hit is
 * ever returned — a partial result is not a safe result. */
function failClosed(state, reason) {
  state.blocked = true;
  state.blockReason = reason;
  try {
    state.session.abort();
  } catch {
    // abort() is cleanup on an already-failed session; a second failure
    // here does not change the outcome.
  }
}

function record(state, result) {
  if (result.findings.some((finding) => finding.action === "block")) {
    state.blocked = true;
    state.blockReason = "policy";
  }
  state.findings.push(...result.findings);
  state.text += result.text;
}

/**
 * Opens one streaming redaction session. `options.limits` is required —
 * mirroring `IncrementalSanitizerOptions`, there is no default.
 *
 * @param {(limits: object, policy: unknown) => { append(chunk: string): { text: string, findings: readonly object[] }, finalize(): { text: string, findings: readonly object[] }, abort(): void }} createSession
 * @param {{ limits: object, policy?: unknown }} options
 */
export function createStreamingToolResultRedactor(createSession, options) {
  if (typeof createSession !== "function") {
    throw new TypeError("createStreamingToolResultRedactor: createSession must be a function");
  }
  if (!options || !options.limits) {
    throw new TypeError("createStreamingToolResultRedactor: options.limits is required");
  }

  const state = {
    session: createSession(options.limits, options.policy),
    blocked: false,
    blockReason: undefined,
    findings: [],
    text: "",
    finalized: false,
  };

  return {
    /** Feeds one chunk. A no-op once the session is blocked or finalized. */
    append(chunk) {
      if (state.blocked || state.finalized) return;
      try {
        record(state, state.session.append(chunk));
      } catch {
        failClosed(state, "limit_exceeded");
      }
    },

    /**
     * Closes the session and returns the outcome: `{ outcome: "ok", result,
     * findings }` with a one-block `CallToolResult`, or `{ outcome:
     * "blocked", blockReason, findings }` with no text at all.
     */
    finalize() {
      if (state.finalized) {
        throw new Error("createStreamingToolResultRedactor: finalize() already called");
      }
      state.finalized = true;
      if (!state.blocked) {
        try {
          record(state, state.session.finalize());
        } catch {
          failClosed(state, "limit_exceeded");
        }
      }
      if (state.blocked) {
        return { outcome: "blocked", blockReason: state.blockReason, findings: state.findings };
      }
      return {
        outcome: "ok",
        result: { content: [{ type: "text", text: state.text }] },
        findings: state.findings,
      };
    },
  };
}
