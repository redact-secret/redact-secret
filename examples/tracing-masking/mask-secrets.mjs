/**
 * `maskSecretsWith`: the generic masking callback the issue asks for,
 * shaped so `(data) => maskSecretsWith(scanAndRedact, data)` is a drop-in
 * Langfuse JS `mask` hook (`mask: ({ data }) => maskSecrets(data)`, see
 * `langfuse-mask.mjs`). It never imports `@redact-secret/core` itself —
 * `scanAndRedact` is injected — so this file, like
 * `examples/safe-integration/integration.mjs`, is testable without the
 * built native addon.
 */

import {
  CYCLE_MARKER,
  DEFAULT_LIMITS,
  LIMIT_MARKER,
  maskLeafWith,
} from "./mask-leaf.mjs";

export { BLOCK_MARKER, CYCLE_MARKER, DEFAULT_LIMITS, ERROR_MARKER, LIMIT_MARKER } from "./mask-leaf.mjs";

function isPlainObject(value) {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function maskValue(scanAndRedact, value, ctx, depth, seen) {
  if (typeof value === "string") {
    if (ctx.budget.leaves <= 0) return LIMIT_MARKER;
    ctx.budget.leaves -= 1;
    return maskLeafWith(scanAndRedact, value, {
      policy: ctx.policy,
      maxStringLength: ctx.limits.maxStringLength,
    });
  }

  if (Array.isArray(value)) {
    if (depth >= ctx.limits.maxDepth) return LIMIT_MARKER;
    if (seen.has(value)) return CYCLE_MARKER;
    seen.add(value);
    // Elements beyond the limit are dropped, never passed through unmasked.
    const bounded = value.slice(0, ctx.limits.maxArrayLength);
    const masked = bounded.map((item) => maskValue(scanAndRedact, item, ctx, depth + 1, seen));
    seen.delete(value);
    return masked;
  }

  if (isPlainObject(value)) {
    if (depth >= ctx.limits.maxDepth) return LIMIT_MARKER;
    if (seen.has(value)) return CYCLE_MARKER;
    seen.add(value);
    // Keys beyond the limit are dropped, never passed through unmasked.
    const keys = Object.keys(value).slice(0, ctx.limits.maxObjectKeys);
    const out = {};
    for (const key of keys) {
      // Define data keys without invoking inherited setters such as __proto__.
      Object.defineProperty(out, key, {
        value: maskValue(scanAndRedact, value[key], ctx, depth + 1, seen),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    seen.delete(value);
    return out;
  }

  // Numbers, booleans, null, undefined, and non-plain objects (Date, class
  // instances, ...) are left unchanged: only plain objects, arrays, and
  // strings are walked.
  return value;
}

/**
 * Recursively masks every string inside a plain object/array tree.
 * `scanAndRedact` is called once per leaf string, so a `<SECRET_1>`-style
 * placeholder index restarts at each leaf — identical to calling
 * `scanAndRedact` directly on that one string.
 */
export function maskSecretsWith(scanAndRedact, data, options = {}) {
  if (typeof scanAndRedact !== "function") {
    throw new TypeError("maskSecretsWith: scanAndRedact must be a function");
  }
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const ctx = { policy: options.policy, limits, budget: { leaves: limits.maxTotalLeaves } };
  return maskValue(scanAndRedact, data, ctx, 0, new Set());
}
