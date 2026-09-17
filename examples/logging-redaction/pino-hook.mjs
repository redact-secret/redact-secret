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
 * ...interpolationValues)`, or a bare `Error`. Before anything is scanned,
 * `joinInterpolatedMessage` (below) closes the gap issue #361 reported: a
 * string `msg` followed by further positional arguments is joined with
 * those arguments into the single string pino's own `quick-format-unescaped`
 * would produce (`./format-pino-message.mjs`), *before* redaction runs, so a
 * secret split across the format string and an interpolation value -- or
 * across two interpolation values -- is scanned as one leaf, not two that
 * never individually match. Everything from that point on -- the joined
 * message, a merging object, or a normalized `Error` -- is one value tree,
 * redacted with `maskLogValueWith` (`./mask-log-value.mjs`), so:
 *
 * - the joined message, or a plain string `msg` with nothing to join, is
 *   redacted as one leaf;
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
 * a top-level `msg` -- with everything inside already redacted. Joining
 * runs after this normalization, uniformly, over whatever shape results.
 *
 * `await initialize()` (`@redact-secret/core`) must resolve before the
 * returned hook is used; `./pino-redact.mjs`'s `createRedactingLogMethod`
 * enforces that ordering for the live integration. This file is
 * dependency-injected and testable without pino installed or the native
 * addon built, matching `examples/tracing-masking/mask-secrets.mjs`.
 */

import { formatPinoMessage } from "./format-pino-message.mjs";
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

function hasMergingObjectFirst(args) {
  return args.length > 0 && typeof args[0] === "object" && args[0] !== null;
}

/**
 * Folds `msg` and any trailing printf-style interpolation values into the
 * single string pino would format, so the redaction pass below sees it as
 * one leaf. A no-op for every other shape -- a bare message with nothing
 * after it, a non-string `msg`, or a merging object with no message --
 * which all fall through to the existing per-leaf walk unchanged.
 */
function joinInterpolatedMessage(args) {
  const msgIndex = hasMergingObjectFirst(args) ? 1 : 0;
  const msg = args[msgIndex];
  if (typeof msg !== "string" || args.length <= msgIndex + 1) {
    return args;
  }
  const joined = formatPinoMessage(msg, args.slice(msgIndex + 1));
  return msgIndex === 1 ? [args[0], joined] : [joined];
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
    const joined = joinInterpolatedMessage(normalized);
    const redacted = maskLogValueWith(scanAndRedact, joined, options);
    method.apply(this, redacted);
  };
}
