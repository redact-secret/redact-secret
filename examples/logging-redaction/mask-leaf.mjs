/**
 * The single primitive both logging integrations build on: mask one leaf
 * string with an injected `scanAndRedact`, and never let a core failure or
 * a `block` finding put text on the wire. Self-contained rather than
 * imported from `examples/tracing-masking/mask-leaf.mjs` -- each example
 * directory stands on its own -- but implements the same markers and
 * fail-closed behavior, by convention, so a reader who has seen one
 * recognizes the other.
 */

export const BLOCK_MARKER = "[REDACTED:BLOCKED]";
export const ERROR_MARKER = "[REDACTED:ERROR]";
export const LIMIT_MARKER = "[REDACTED:LIMIT_EXCEEDED]";
export const CYCLE_MARKER = "[REDACTED:CYCLE]";

/**
 * Bounds enforced by `mask-log-value.mjs`. A field that exceeds
 * `maxStringLength`, or a value reached only after `maxDepth`/
 * `maxArrayLength`/`maxObjectKeys`/`maxTotalLeaves` is spent, never
 * reaches the core: it becomes {@link LIMIT_MARKER} instead. Every log
 * call pays the scan cost (see `benchmark.mjs`), so these bounds also cap
 * per-call latency for pathological merging objects.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 8,
  maxArrayLength: 1000,
  maxObjectKeys: 200,
  maxStringLength: 200_000,
  maxTotalLeaves: 5000,
});

/**
 * Masks one leaf string. Any thrown error -- including `NOT_INITIALIZED`
 * if a host skipped `await initialize()` -- fails closed: the leaf becomes
 * {@link ERROR_MARKER}, never the original text and never the error's own
 * message. A `block` finding replaces the entire leaf with
 * {@link BLOCK_MARKER}, matching the issue's "block findings replace the
 * whole message with a fixed marker": for a plain string log call the leaf
 * *is* the message, and for a merged field or an `err.message` the leaf is
 * that field's whole text.
 */
export function maskLeafWith(scanAndRedact, text, { policy, maxStringLength } = {}) {
  if (typeof text !== "string") {
    throw new TypeError("maskLeafWith: text must be a string");
  }
  const limit = maxStringLength ?? DEFAULT_LIMITS.maxStringLength;
  if (text.length > limit) return LIMIT_MARKER;

  let result;
  try {
    result = scanAndRedact(text, { policy });
  } catch {
    return ERROR_MARKER;
  }
  if (result.findings.some((finding) => finding.action === "block")) {
    return BLOCK_MARKER;
  }
  return result.text;
}
