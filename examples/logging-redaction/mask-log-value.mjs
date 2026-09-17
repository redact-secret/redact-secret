/**
 * Recursively masks every string inside a pino merging-object tree,
 * including an `Error` value's `message` and `stack`. Structurally the
 * same walk as `examples/tracing-masking/mask-secrets.mjs`'s
 * `maskValue` -- plain objects, arrays, and string leaves -- plus one
 * addition: an `Error` instance is not a plain object, so the tracing
 * walker would leave it untouched, but pino's default `err` serializer
 * turns it into `{ type, message, stack, ... }` and *that* is where a
 * secret in `err.message` becomes visible. This walker pre-empts that by
 * replacing the `Error` itself with an already-redacted plain object in
 * the same shape, before pino's serializer (or `hooks.logMethod`'s
 * caller) ever sees the raw message.
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

function maskString(scanAndRedact, value, ctx) {
  if (ctx.budget.leaves <= 0) return LIMIT_MARKER;
  ctx.budget.leaves -= 1;
  return maskLeafWith(scanAndRedact, value, {
    policy: ctx.policy,
    maxStringLength: ctx.limits.maxStringLength,
  });
}

/**
 * Redacts an `Error`'s own enumerable string properties (`message` is
 * always own on `Error.prototype` instances) plus the standard `message`
 * and `stack` accessors, matching the shape `pino.stdSerializers.err`
 * would have produced -- pre-redacted, so that serializer (which only
 * transforms `instanceof Error` values) sees our plain object, finds it is
 * not an `Error`, and passes it through unchanged.
 */
function maskError(scanAndRedact, error, ctx, depth, seen) {
  const out = {
    // `constructor.name` here is deliberately "the object's own", not the
    // original error's: if a host's `serializers.err` runs afterward (the
    // pino default does), it re-derives `type` from `constructor.name`
    // too, which reports "Object" -- confirmed against pino 10.3.1 while
    // resolving issue #328 -- since this value is a plain object, not an
    // `Error`, by the time that serializer sees it. Harmless (`type` never
    // carried a secret either way) and worth knowing if a log line's
    // `err.type` reads "Object" instead of "Error".
    type: error.name ?? error.constructor?.name ?? "Error",
    message: maskString(scanAndRedact, String(error.message ?? ""), ctx),
  };
  if (typeof error.stack === "string") {
    out.stack = maskString(scanAndRedact, error.stack, ctx);
  }
  for (const key of Object.keys(error)) {
    if (key === "message" || key === "stack") continue;
    // Define data keys without invoking inherited setters such as __proto__.
    Object.defineProperty(out, key, {
      value: maskValue(scanAndRedact, error[key], ctx, depth + 1, seen),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  if (error.cause !== undefined) {
    out.cause = maskValue(scanAndRedact, error.cause, ctx, depth + 1, seen);
  }
  return out;
}

function maskValue(scanAndRedact, value, ctx, depth, seen) {
  if (typeof value === "string") {
    return maskString(scanAndRedact, value, ctx);
  }

  if (value instanceof Error) {
    if (depth >= ctx.limits.maxDepth) return LIMIT_MARKER;
    if (seen.has(value)) return CYCLE_MARKER;
    seen.add(value);
    const masked = maskError(scanAndRedact, value, ctx, depth, seen);
    seen.delete(value);
    return masked;
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

  // Numbers, booleans, null, undefined, and non-plain/non-Error objects
  // (Date, class instances, ...) are left unchanged: only plain objects,
  // arrays, Errors, and strings are walked.
  return value;
}

/**
 * Recursively masks every string (and every `Error`'s `message`/`stack`)
 * inside a plain object/array tree. `scanAndRedact` is called once per
 * leaf string, so a `<SECRET_1>`-style placeholder index restarts at each
 * leaf.
 */
export function maskLogValueWith(scanAndRedact, data, options = {}) {
  if (typeof scanAndRedact !== "function") {
    throw new TypeError("maskLogValueWith: scanAndRedact must be a function");
  }
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const ctx = { policy: options.policy, limits, budget: { leaves: limits.maxTotalLeaves } };
  return maskValue(scanAndRedact, data, ctx, 0, new Set());
}
