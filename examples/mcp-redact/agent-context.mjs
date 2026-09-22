/**
 * The AI-context golden path (issue #587): where authoritative redaction
 * belongs across a whole agent turn, not just inside one MCP tool call.
 * Composes `redact-tool-call.mjs`'s primitives into the flow the issue
 * requires:
 *
 * ```
 * user input -> scan -> application policy
 * tool result -> scan -> context construction
 * safe context -> model
 * ```
 *
 * `userInput` is scanned first. A `block` finding there ends the call
 * before a tool is ever dispatched, before anything is logged, and before
 * `context` is built — `userInput` itself never appears in this module's
 * return value on any path. When `buildToolRequest` is supplied, it is
 * called with the *sanitized* input text, never the raw `userInput`, so a
 * tool argument derived from what the user typed is dispatched from
 * already-scanned text. The tool's result is then scanned the same way
 * `wrapClientCallTool` does, before either piece is added to
 * `context.messages` — the only value here that is safe to hand to a model
 * call or a log line.
 *
 * No `@modelcontextprotocol/sdk` import, matching `redact-tool-call.mjs`
 * and `wrap-tool-call.mjs`: `callTool` is a plain, duck-typed async
 * function.
 */

import { redactToolResult } from "./redact-tool-call.mjs";
import { emitFindings } from "./wrap-tool-call.mjs";

/** `maxInputLength` mirrors `DEFAULT_LIMITS.maxStringLength` in
 * `redact-tool-call.mjs`, applied to the whole user turn up front — before
 * `scanAndRedact` is ever called — rather than relying on the per-leaf
 * `LIMIT_MARKER` a huge tool-result leaf would fall back on. */
export const DEFAULT_INPUT_LIMITS = Object.freeze({ maxInputLength: 200_000 });

function isAborted(signal) {
  return signal != null && signal.aborted === true;
}

function aborted(findings) {
  return { outcome: "aborted", findings };
}

/**
 * Scans one plain-text user turn and maps the outcome onto the issue's
 * `redact`/`warn`/`block`/allow contract. Oversized input is rejected by
 * length alone, before `scanAndRedact` sees any of it — no retained
 * plaintext for that path, by construction.
 *
 * @param {Function} scanAndRedact
 * @param {string} text
 * @param {{ policy?: unknown, limits?: { maxInputLength?: number } }} [options]
 */
export function redactUserInput(scanAndRedact, text, options = {}) {
  if (typeof scanAndRedact !== "function") {
    throw new TypeError("redactUserInput: scanAndRedact must be a function");
  }
  if (typeof text !== "string") {
    throw new TypeError("redactUserInput: text must be a string");
  }

  const maxInputLength = options.limits?.maxInputLength ?? DEFAULT_INPUT_LIMITS.maxInputLength;
  if (text.length > maxInputLength) {
    return { outcome: "blocked", blockReason: "input_too_large", findings: [] };
  }

  let result;
  try {
    result = scanAndRedact(text, { policy: options.policy });
  } catch {
    // Covers every core failure the same way, including calling this
    // before `initialize()` — `packages/javascript/src/errors.ts` throws
    // for that case too, so it fails closed exactly like any other
    // scanner error rather than needing its own branch.
    return { outcome: "blocked", blockReason: "core_error", findings: [] };
  }
  if (result.findings.some((finding) => finding.action === "block")) {
    return { outcome: "blocked", blockReason: "policy", findings: result.findings };
  }
  return { outcome: "ok", text: result.text, findings: result.findings };
}

/**
 * Runs one full agent turn through the required flow and returns the safe
 * context to hand to the model, or a blocked/aborted outcome with no
 * `context` field at all.
 *
 * `signal` (a standard `AbortSignal`) is checked before scanning starts,
 * before the tool is dispatched, and again before the tool result is
 * folded into context — covering both cancellation (already aborted before
 * this call began) and abort (the signal fires while the tool call is in
 * flight). Either way the return is `{ outcome: "aborted" }`: whatever was
 * scanned so far is discarded along with everything unscanned, and the
 * caller must not reuse a prior `context`.
 *
 * @param {{
 *   scanAndRedact: Function,
 *   userInput: string,
 *   policy?: unknown,
 *   limits?: { maxInputLength?: number },
 *   onFinding?: (finding: object, context: { scope: "input" | "result" }) => void,
 *   callTool?: (request: unknown, opts: { signal?: AbortSignal }) => Promise<unknown>,
 *   buildToolRequest?: unknown | ((safeInputText: string) => unknown),
 *   signal?: AbortSignal,
 * }} options
 */
export async function buildSafeContext(options = {}) {
  const { scanAndRedact, userInput, policy, limits, onFinding, callTool, buildToolRequest, signal } = options;

  if (isAborted(signal)) return aborted([]);

  const inputOutcome = redactUserInput(scanAndRedact, userInput, { policy, limits });
  emitFindings(inputOutcome.findings, onFinding, "input");
  if (inputOutcome.outcome === "blocked") {
    return { outcome: "blocked", stage: "input", blockReason: inputOutcome.blockReason, findings: inputOutcome.findings };
  }

  const findings = [...inputOutcome.findings];
  const messages = [{ role: "user", content: inputOutcome.text }];

  if (callTool) {
    if (isAborted(signal)) return aborted(findings);

    const request = typeof buildToolRequest === "function" ? buildToolRequest(inputOutcome.text) : buildToolRequest;
    let raw;
    try {
      raw = await callTool(request, { signal });
    } catch {
      // A rejected or aborted call has no result to redact and nothing new
      // was ever captured -- `messages` (holding only the already-sanitized
      // input) is discarded along with this return, since a blocked
      // outcome carries no `context` field for the caller to reuse.
      return { outcome: "blocked", stage: "tool", blockReason: "tool_call_failed", findings };
    }

    if (isAborted(signal)) return aborted(findings);

    const resultOutcome = redactToolResult(scanAndRedact, raw, { policy, limits });
    emitFindings(resultOutcome.findings, onFinding, "result");
    findings.push(...resultOutcome.findings);
    if (resultOutcome.outcome === "blocked") {
      return { outcome: "blocked", stage: "tool", blockReason: resultOutcome.blockReason, findings };
    }
    messages.push({ role: "tool", content: resultOutcome.result });
  }

  if (isAborted(signal)) return aborted(findings);

  return { outcome: "ok", context: Object.freeze({ messages: Object.freeze(messages) }), findings };
}
