/**
 * `createRedactingLogMethodWith`: a pino `hooks.logMethod` (pinned against
 * pino `9.x`, https://github.com/pinojs/pino/blob/main/docs/api.md#hooks
 * and https://github.com/pinojs/pino/blob/main/lib/tools.js, confirmed
 * while resolving issue #328) that redacts a secret out of the message,
 * every string field of a merging object, and a serialized `err.message`,
 * before pino ever serializes or writes the line.
 *
 * `hooks.logMethod` is the only pino extension point that sees the raw
 * message: `formatters.log(obj)` looked like the natural fit at first, but
 * reading `lib/tools.js`'s `_asJson` shows `formatters.log` never receives
 * `msg` at all (pino serializes the message key separately from the
 * merged object) and runs *before* `serializers[key]` -- so a `formatters`
 * hook can redact a plain string field, but never the message, and never
 * a value an `err` serializer hasn't produced yet. `hooks.logMethod`,
 * documented as `logMethod (args, method, level) {}`, instead wraps the
 * log call itself (`lib/tools.js`'s `genLog`: `hook.call(this, args, LOG,
 * level)`) before pino does anything -- before merging, before
 * serializers, before `formatters.log`, before the configured
 * path-based `redact`. Redacting here and then calling `method.apply`
 * with the redacted arguments means every later pino stage (including a
 * host's own `redact` option, still applied by path) runs unchanged on
 * text pino can no longer see in the clear.
 *
 * `args` is exactly what the caller passed to `logger.info(...)` et al.:
 * `(msg, ...interpolationValues)`, `(mergingObject, msg,
 * ...interpolationValues)`, or a bare `Error`. This module treats the
 * whole `args` array as one value tree and redacts it with
 * `maskLogValueWith` (`./mask-log-value.mjs`), so:
 *
 * - a string `msg` or a string interpolation value is redacted in place;
 * - every string field of a merging object is redacted, at any depth;
 * - an `Error` anywhere in the tree -- including a bare `logger.error(err)`
 *   call -- is replaced by an already-redacted `{ type, message, stack,
 *   ...ownProps }` object, in the shape `pino.stdSerializers.err` would
 *   have produced, before that serializer (or any other) ever sees the
 *   real message or stack.
 *
 * A bare leading `Error` (`logger.error(err)`) is normalized to
 * `[{ err }, err.message, ...rest]` first: pino's own `write()` infers
 * `msg` from `err.message` only when the first argument is `instanceof
 * Error`, and replacing that argument with our masked plain object (which
 * is not `instanceof Error`) would silently drop the `msg` field from the
 * output. Normalizing first keeps that shape -- both the `err` object and
 * a top-level `msg` -- with everything inside already redacted.
 *
 * `await initialize()` (`@redact-secret/core`) must resolve before the
 * returned hook is used; `./pino-redact.mjs`'s `createRedactingLogMethod`
 * enforces that ordering for the live integration. This file is
 * dependency-injected and testable without pino installed or the native
 * addon built, matching `examples/tracing-masking/mask-secrets.mjs`.
 */

import { maskLogValueWith } from "./mask-log-value.mjs";

export {
  BLOCK_MARKER,
  CYCLE_MARKER,
  DEFAULT_LIMITS,
  ERROR_MARKER,
  LIMIT_MARKER,
} from "./mask-leaf.mjs";

function normalizeLeadingError(args) {
  if (args.length > 0 && args[0] instanceof Error) {
    const err = args[0];
    return [{ err }, err.message, ...args.slice(1)];
  }
  return args;
}

/**
 * Builds a pino `hooks.logMethod` function. `scanAndRedact` is injected
 * (see `./pino-redact.mjs` for the live factory over `@redact-secret/core`).
 */
export function createRedactingLogMethodWith(scanAndRedact, options = {}) {
  if (typeof scanAndRedact !== "function") {
    throw new TypeError("createRedactingLogMethodWith: scanAndRedact must be a function");
  }
  return function redactingLogMethod(args, method, level) {
    const normalized = normalizeLeadingError(Array.from(args));
    const redacted = maskLogValueWith(scanAndRedact, normalized, options);
    method.apply(this, redacted);
  };
}
