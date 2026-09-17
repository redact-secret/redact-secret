/**
 * Joins a pino `msg` format string with its printf-style interpolation
 * values into the exact string pino itself would write -- the scanning
 * boundary `pino-hook.mjs` needs to close issue #361 (a secret split across
 * `msg` and an interpolation value, or across two interpolation values, was
 * invisible to a hook that scanned each argument as its own leaf).
 *
 * pino never formats `msg` inside `hooks.logMethod` -- confirmed reading
 * `lib/tools.js`'s `genLog`/`LOG`, pino `10.3.1`: the hook runs first, and
 * only afterward does `LOG` call `format(msg, formatParams, this[formatOptsSym])`,
 * where `format` is pino's own direct dependency, the `quick-format-unescaped`
 * package (`require('quick-format-unescaped')`, `lib/tools.js:6`; pino's
 * `package.json` pins `^4.0.3`, resolving to `4.0.4` as of this writing).
 * `formatPinoMessage` below is a line-for-line port of that package's
 * string-formatting branch (`typeof f === 'string'`) -- MIT licensed,
 * https://github.com/pinojs/quick-format-unescaped -- not a reimplementation
 * from the docs, so it reproduces pino's exact placeholder consumption,
 * including the parts that read as bugs at first glance: an unmatched
 * placeholder (more `%s` than values) is left as literal text; an unused
 * trailing value (more values than placeholders) is silently dropped, never
 * appended; and `%%` does not consume a value. `format-pino-message.test.mjs`
 * asserts this port byte-for-byte against the real package (an explicit
 * devDependency, pinned to the same `4.0.4`) across a case table.
 *
 * ## Trust boundary
 *
 * - `%s`, `%d`, `%i`, `%f`, and `%%` are reproduced exactly: pino computes
 *   them with `String(value)`/`Number(value)`/`Math.floor(Number(value))`,
 *   and so does this port.
 * - `%j`, `%o`, and `%O` stringify a non-string, non-function value with
 *   `JSON.stringify` (falling back to the literal `"[Circular]"` if it
 *   throws), matching `quick-format-unescaped`'s own *default* `tryStringify`.
 *   pino itself never takes that default: it always supplies its own
 *   `stringify` (`pino.js`'s `formatOpts`, fast-safe-stringify-based, and
 *   additionally redaction-aware whenever the `redact` option is
 *   configured). A value that would render differently under fast-safe
 *   stringification -- a circular reference beyond `JSON.stringify`'s single
 *   top-level catch, a `BigInt`, or a path `redact` would have censored --
 *   renders differently here. This does not weaken redaction: the scan
 *   below still runs against this function's own JSON text, so a secret
 *   inside such a value is still caught by value; only pino's *unrelated*
 *   path-based `redact` censoring of that same value is not reproduced.
 *   A merging-object field is unaffected either way -- it is walked and
 *   redacted independently by `mask-log-value.mjs`, in its original shape,
 *   never funneled through this formatter.
 */

function tryStringify(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return '"[Circular]"';
  }
}

/**
 * `fmt`: the pino `msg` positional argument; must already be a `string` --
 * callers only invoke this once they know `msg` is a string with further
 * positional arguments to consume (see `pino-hook.mjs`'s
 * `joinInterpolatedMessage`). `values`: the arguments positionally after
 * `msg`, 0-indexed to the first interpolation value -- exactly the
 * `formatParams` array pino's own `LOG` passes to `format`.
 */
export function formatPinoMessage(fmt, values) {
  const argLen = values.length;
  if (argLen === 0) return fmt;

  let str = "";
  let a = 0;
  let lastPos = -1;
  const flen = fmt.length;

  for (let i = 0; i < flen; ) {
    if (fmt.charCodeAt(i) === 37 /* '%' */ && i + 1 < flen) {
      lastPos = lastPos > -1 ? lastPos : 0;
      switch (fmt.charCodeAt(i + 1)) {
        case 100: // 'd'
        case 102: // 'f'
          if (a >= argLen) break;
          if (values[a] == null) break;
          if (lastPos < i) str += fmt.slice(lastPos, i);
          str += Number(values[a]);
          lastPos = i + 2;
          i++;
          break;
        case 105: // 'i'
          if (a >= argLen) break;
          if (values[a] == null) break;
          if (lastPos < i) str += fmt.slice(lastPos, i);
          str += Math.floor(Number(values[a]));
          lastPos = i + 2;
          i++;
          break;
        case 79: // 'O'
        case 111: // 'o'
        case 106: // 'j'
          if (a >= argLen) break;
          if (values[a] === undefined) break;
          if (lastPos < i) str += fmt.slice(lastPos, i);
          {
            const type = typeof values[a];
            if (type === "string") {
              str += "'" + values[a] + "'";
              lastPos = i + 2;
              i++;
              break;
            }
            if (type === "function") {
              str += values[a].name || "<anonymous>";
              lastPos = i + 2;
              i++;
              break;
            }
          }
          str += tryStringify(values[a]);
          lastPos = i + 2;
          i++;
          break;
        case 115: // 's'
          if (a >= argLen) break;
          if (lastPos < i) str += fmt.slice(lastPos, i);
          str += String(values[a]);
          lastPos = i + 2;
          i++;
          break;
        case 37: // '%'
          if (lastPos < i) str += fmt.slice(lastPos, i);
          str += "%";
          lastPos = i + 2;
          i++;
          a--;
          break;
      }
      a++;
    }
    i++;
  }

  if (lastPos === -1) return fmt;
  if (lastPos < flen) str += fmt.slice(lastPos);
  return str;
}
