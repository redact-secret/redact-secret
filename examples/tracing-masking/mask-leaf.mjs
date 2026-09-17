/**
 * The single primitive both tracing examples build on: mask one leaf string
 * with an injected `scanAndRedact`, and never let a core failure or a
 * `block` finding put text on the wire.
 */

export const BLOCK_MARKER = "[REDACTED:BLOCKED]";
export const ERROR_MARKER = "[REDACTED:ERROR]";
export const LIMIT_MARKER = "[REDACTED:LIMIT_EXCEEDED]";
export const CYCLE_MARKER = "[REDACTED:CYCLE]";

/**
 * Bounds enforced by both the masking callback and the span-processor
 * example. There is no ADR for tracing integrations yet (deliberately out
 * of scope for issue #326), so these limits are documented here rather
 * than in `docs/decisions/`. A field that exceeds `maxStringLength`, or a
 * value reached only after `maxDepth`/`maxArrayLength`/`maxObjectKeys`/
 * `maxTotalLeaves` is spent, never reaches the core: it becomes
 * {@link LIMIT_MARKER} instead.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 8,
  maxArrayLength: 1000,
  maxObjectKeys: 200,
  maxStringLength: 200_000,
  maxTotalLeaves: 5000,
});

/**
 * Masks one leaf string. Any thrown error — including `NOT_INITIALIZED` if
 * a host skipped `await initialize()` — fails closed: the leaf becomes
 * {@link ERROR_MARKER}, never the original text and never the error's own
 * message. A `block` finding replaces the entire leaf with
 * {@link BLOCK_MARKER}: `scanAndRedact` already substitutes `block`
 * findings in place like `redact` ones, but an inline placeholder still
 * leaves the rest of the string visible, which is not the documented host
 * decision for a block-worthy secret.
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
