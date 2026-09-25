/**
 * The AI-context golden path (issue #587), on the framework-neutral
 * AI-context boundary (`docs/reference/ai-context-boundary.md`, #610) as
 * implemented by `@redact-secret/adapter-ai-context`
 * (redact-secret-adapters#12), with the tool result sanitized by the MCP
 * boundary (`docs/reference/mcp-boundary.md`, #612) as implemented by
 * `@redact-secret/adapter-mcp` (redact-secret-adapters#13). One agent turn:
 *
 * ```
 * user input -> scan -> application policy
 * tool result -> scan -> context construction
 * safe context -> model
 * ```
 *
 * `userInput` is sanitized first. A non-`ok` outcome there ends the turn
 * before a tool is dispatched, before anything is logged, and before any
 * context exists; `userInput` never appears in the return value on any
 * path. When `buildToolRequest` is supplied it gets the *sanitized* input
 * text, never the raw `userInput`, so a tool argument derived from what the
 * user typed is dispatched from already-scanned text. The tool's result is
 * then sanitized before either piece joins the context, the only value here
 * that is safe to hand to a model call or a log line: a whole
 * `CallToolResult` from `callTool` through `redactToolResult`, or chunks
 * from `streamTool` through the boundary's staged stream
 * (`redactStreamedToolResult`, #721).
 *
 * This file detects nothing, walks nothing, and maps no failure: the
 * boundary does all three. What it adds is the order of the turn.
 *
 * No `@modelcontextprotocol/sdk` import: `callTool` is a plain, duck-typed
 * async function.
 */

import { createAiContextBoundary, createAiContextBoundaryWith } from "@redact-secret/adapter-ai-context";

import { redactToolResult } from "./redact-tool-call.mjs";
import { redactStreamedToolResult } from "./streaming-tool-result.mjs";

/**
 * The limits this example's boundary runs under. The contract makes every
 * limit mandatory and explicit, so there is no default to fall back on:
 * a host chooses its own. Exceeding any of them blocks the whole operation
 * as `limit_exceeded`; nothing is truncated or marked and passed on.
 */
export const EXAMPLE_LIMITS = Object.freeze({
  wholeInputLimits: Object.freeze({ maxInputBytes: 262_144, maxFindings: 1024 }),
  incrementalLimits: Object.freeze({
    maxInputCodeUnits: 1_048_576,
    maxBufferedCodeUnits: 65_536,
    maxTokenCodeUnits: 8192,
    maxMultilineCodeUnits: 32_768,
  }),
  traversalLimits: Object.freeze({ maxDepth: 8, maxNodes: 10_000 }),
});

/**
 * The boundary over the real core: loads `@redact-secret/core`, awaits its
 * `initialize()`, and fails every operation closed if that fails.
 *
 * @param {{ policy?: object, onFinding?: Function }} [options]
 */
export function createGoldenPathBoundary(options = {}) {
  return createAiContextBoundary({ ...EXAMPLE_LIMITS, ...options });
}

/**
 * The same boundary over an injected core (`{ scanAndRedact,
 * createIncrementalSanitizer }`): the real core after `initialize()`, or a
 * fake in tests.
 *
 * @param {import("@redact-secret/adapter-ai-context").AiContextCore} core
 * @param {{ policy?: object, onFinding?: Function }} [options]
 */
export function createGoldenPathBoundaryWith(core, options = {}) {
  return createAiContextBoundaryWith(core, { ...EXAMPLE_LIMITS, ...options });
}

const TOOL_ERROR = Object.freeze({ outcome: "tool_error", stage: "tool" });

function withStage(outcome, stage) {
  return Object.freeze({ ...outcome, stage });
}

/**
 * Runs one agent turn and returns the safe context for the model, or a
 * non-`ok` outcome with nothing derived from input:
 *
 * - `{ outcome: "ok", value: [{ role, content }], findings }`, the same
 *   shape the boundary's `buildContext` returns;
 * - the boundary's `{ outcome: "blocked", reason, code? }` or
 *   `{ outcome: "aborted" }`, plus `stage` (`"input"` or `"tool"`);
 * - `{ outcome: "tool_error", stage: "tool" }` when `callTool` rejects, or
 *   `streamTool` throws or its chunks reject. This is the host's own
 *   outcome, outside the contract's set: dispatching a tool is the host's
 *   job, and the error, which may carry input, is never read.
 *
 * A tool is either `callTool` (resolves to one `CallToolResult`) or
 * `streamTool` (returns the chunks of one text result as an
 * `AsyncIterable<string>` or `Iterable<string>`), never both. Streamed
 * chunks go through one staged boundary stream and are released only by a
 * successful finalize, as a one-block `CallToolResult`, so both kinds join
 * the context in the same shape.
 *
 * `signal` (an `AbortSignal`) is checked by the boundary before and after
 * every scan and on every streamed chunk, and here before the tool is
 * dispatched and after it returns. An abort at any point discards
 * everything, including text already sanitized and a stream's staged text;
 * the caller must not reuse an earlier context. `streamTool` gets the same
 * signal and should end its chunks when it fires; this function also stops
 * pulling chunks and closes the iterator.
 *
 * @param {{
 *   boundary: import("@redact-secret/adapter-ai-context").AiContextBoundary,
 *   userInput: string,
 *   callTool?: (request: unknown, opts: { signal?: AbortSignal }) => Promise<unknown>,
 *   streamTool?: (request: unknown, opts: { signal?: AbortSignal }) => AsyncIterable<string> | Iterable<string>,
 *   buildToolRequest?: unknown | ((safeInputText: string) => unknown),
 *   signal?: AbortSignal,
 *   binaryContent?: "block" | "pass",
 * }} options
 */
export async function buildSafeContext(options = {}) {
  const { boundary, userInput, callTool, streamTool, buildToolRequest, signal, binaryContent } = options;
  if (typeof boundary?.sanitizeText !== "function") {
    throw new TypeError("buildSafeContext: boundary must be an @redact-secret/adapter-ai-context boundary");
  }
  if (callTool != null && streamTool != null) {
    throw new TypeError("buildSafeContext: pass callTool or streamTool, not both");
  }
  const tool = callTool ?? streamTool;

  const input = boundary.sanitizeText(userInput, { boundary: "user-input", signal });
  if (input.outcome !== "ok") return withStage(input, "input");

  const findings = [...input.findings];
  const messages = [Object.freeze({ role: "user", content: input.value })];

  if (tool) {
    if (signal?.aborted === true) return withStage({ outcome: "aborted" }, "tool");
    const request = typeof buildToolRequest === "function" ? buildToolRequest(input.value) : buildToolRequest;
    let result;
    if (callTool) {
      let raw;
      try {
        raw = await callTool(request, { signal });
      } catch {
        // Nothing was captured from the failed call, and the sanitized input
        // is discarded with this return: a non-ok outcome carries no context.
        return TOOL_ERROR;
      }
      result = redactToolResult(boundary, raw, { signal, binaryContent });
    } else {
      let chunks;
      try {
        chunks = streamTool(request, { signal });
      } catch {
        return TOOL_ERROR;
      }
      result = await redactStreamedToolResult(boundary, chunks, { signal });
      if (result.outcome === "tool_error") return TOOL_ERROR;
    }
    if (result.outcome !== "ok") return withStage(result, "tool");
    findings.push(...result.findings);
    messages.push(Object.freeze({ role: "tool", content: result.value }));
  }

  if (signal?.aborted === true) return withStage({ outcome: "aborted" }, tool ? "tool" : "input");
  return Object.freeze({ outcome: "ok", value: Object.freeze(messages), findings: Object.freeze(findings) });
}
