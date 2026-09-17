# Redact secrets in application logs

Two logging integrations, in JavaScript and Python, for keeping a secret out
of free-text log messages and arguments (issue #328), including a secret
split across a pino format string and its interpolation values (issue #361):
a pino [`hooks.logMethod`](https://github.com/pinojs/pino/blob/main/docs/api.md#hooks)
for Node.js, and a `logging.Filter` for Python's standard library. Both are
examples, not package exports: no new dependency is added to
`@redact-secret/core` or `redact-secret`. The hook itself stays duck-typed
against pino's documented, pinned API and dependency-injected (see
`pino-hook.mjs`'s module docstring) — it does not import `pino` and remains
testable without it. `pino`, pinned to the exact `10.3.1` this directory has
always documented against, and its own `quick-format-unescaped` dependency
(pinned to the exact `4.0.4` version `10.3.1` resolves) are now real, pinned
`devDependencies` of this workspace, used only by this directory's test
suite (`pino-consumer.test.mjs`, `format-pino-message.test.mjs`) — see
"Running the tests" below for why issue #361 required that.

pino's own `redact` option and Python's `logging` module have no
value-based detection: pino's `redact` censors by object *path* only, so it
cannot catch a token inside a message string or an error message, and
Python's standard library has none at all. These examples redact by *value*,
alongside either mechanism, not instead of it.

## Why `hooks.logMethod`, not `formatters.log`

`formatters.log(obj)` looked like the natural fit at first, but reading
pino's `lib/tools.js` (`_asJson`) shows it never receives the message at
all — pino serializes `msg` completely separately from the merged object —
and it runs *before* `serializers[key]`, so it cannot see a serialized
`err.message` either. `hooks.logMethod` is the only extension point that
sees the raw call: `(args, method, level)`, before pino merges, serializes,
formats, or redacts anything. Every claim in this paragraph is pinned with
exact source references in [`pino-hook.mjs`](./pino-hook.mjs)'s module
docstring.

| File | Role |
| --- | --- |
| [`mask-leaf.mjs`](./mask-leaf.mjs) / [`python/mask_leaf.py`](./python/mask_leaf.py) | The shared primitive: mask one leaf string, fail closed on any error, replace a `block` finding's whole leaf. |
| [`mask-log-value.mjs`](./mask-log-value.mjs) / [`python/mask_log_value.py`](./python/mask_log_value.py) | Pure, dependency-injected recursive walker over a value tree — dicts/lists/strings, plus an `Error`/`BaseException` special case (see below). No `@redact-secret/core` import, so it's testable without the built native addon — mirrors `examples/tracing-masking/mask-secrets.mjs`. |
| [`format-pino-message.mjs`](./format-pino-message.mjs) | Pure `formatPinoMessage`: a vendored, byte-for-byte port of pino's own `quick-format-unescaped` string-formatting branch. Joins `msg` with its interpolation values into the exact string pino would write, *before* redaction runs — the scanning boundary issue #361 required. |
| [`pino-hook.mjs`](./pino-hook.mjs) | Pure `createRedactingLogMethodWith`: builds a pino `hooks.logMethod` from an injected `scanAndRedact`. Folds `msg` and its interpolation values with `formatPinoMessage` before handing the value tree to `mask-log-value.mjs`. |
| [`pino-redact.mjs`](./pino-redact.mjs) | The live wrapper: real `scanAndRedact`, `await initialize()`-ordered. |
| [`python/logging_filter.py`](./python/logging_filter.py) | `RedactSecretFilter(logging.Filter)` — the whole integration; Python's bindings have no init step, so there is no separate live-wrapper file. Python's `LogRecord.getMessage()` already formats `msg`/`args` before this filter runs, so it never had issue #361's gap. |

## A secret in `msg`, a string field, and a serialized `err.message`

```js
import pino from "pino";
import { createRedactingLogMethod } from "./pino-redact.mjs";

const logMethod = await createRedactingLogMethod();
const logger = pino({
  hooks: { logMethod },
  redact: ["req.headers.authorization"], // pino's own path-based redact still applies, on top
});

logger.info("user logged in with token sk-ant-api03-...");     // msg
logger.info({ authHeader: "Bearer sk-ant-api03-..." }, "hi");  // string field
logger.error(new Error("failed: sk-ant-api03-..."));           // err.message / err.stack
logger.info("api_key=%s", "sk-ant-api03-...");                 // msg + interpolation value, joined and scanned as one leaf (issue #361)
```

```python
import logging
import redact_secret
from logging_filter import RedactSecretFilter

logger = logging.getLogger("app")
handler = logging.StreamHandler()
handler.addFilter(RedactSecretFilter(redact_secret.scan_and_redact, extra_fields=["auth_header"]))
logger.addHandler(handler)

logger.info("user %s logged in with token %s", user_id, token)     # %-style args
logger.info(f"token was {token}")                                  # f-string
try:
    ...
except Exception:
    logger.exception("request failed")                             # exc_info / traceback
logger.info("request", extra={"auth_header": f"Bearer {token}"})   # configured extra field
```

A bare `logger.error(err)` is normalized to `[{ err }, err.message, ...rest]`
first (pino infers `msg` from `err.message` only when the first argument is
`instanceof Error`; replacing it with an already-masked plain object would
silently drop the inferred `msg`). An `Error`/`BaseException` anywhere in the
tree — top-level or nested inside a merging object / `extra` value — is
replaced by an already-redacted `{ type, message, stack, ...ownProps }` (JS)
or `{"type", "message", "stack"}` (Python) mapping, in the shape a default
`err` serializer would have produced, before any real serializer sees the
original message. (One cosmetic note, confirmed against pino `10.3.1`: if a
host's `err` serializer runs afterward — pino's default does — it re-derives
`type` from `constructor.name`, which reports `"Object"` rather than
`"Error"` for our already-plain replacement. Harmless: `type` never carried
a secret either way.)

## Scanning `msg` and its interpolation values as one leaf (issue #361)

pino never formats `msg` inside `hooks.logMethod` — the hook runs first,
before pino calls its own `quick-format-unescaped` dependency to substitute
`%s`/`%d`/`%i`/`%f`/`%j`/`%o`/`%O`/`%%` placeholders (pinned in
`pino-hook.mjs`'s module docstring, `lib/tools.js:6`). Scanning `msg` and
each interpolation value as independent leaves — this directory's original
approach — therefore misses a secret split across that boundary:
`logger.info("api_key=%s", token)` scans `"api_key=%s"` and `token`
separately, and neither leaf alone carries the `api_key=<value>` shape a
contextual detector needs.

`format-pino-message.mjs`'s `formatPinoMessage` closes that gap: when `msg`
is a string followed by further positional arguments, `pino-hook.mjs`
joins them into the exact string pino would format — a byte-for-byte
vendored port of `quick-format-unescaped`'s own algorithm, verified against
the real package in `format-pino-message.test.mjs` — and scans *that* as
one leaf, before pino (or its own formatting call) ever runs. The result
replaces the original `msg` plus interpolation values with a single,
already-redacted string; pino's later `format(msg, [], opts)` call then
sees zero remaining arguments and returns that string unchanged.

**Supported and verified**: `%s`, `%d`, `%i`, `%f`, `%%`, and pino's own
placeholder-consumption quirks — an unmatched placeholder is left as
literal text, an unused trailing value is silently dropped rather than
appended, matching real pino exactly (`format-pino-message.test.mjs` checks
this byte-for-byte against the real `quick-format-unescaped` package).
`pino-consumer.test.mjs` additionally exercises this against a real, pinned
pino `10.3.1` instance and asserts on the exact destination bytes: a
contextual assignment split across `msg` and a value, a provider token
split across two values, a merging object combined with a split message, a
bare `Error`, a `block` finding, and a scanner failure.

**Trust boundary — not fully replicated**: `%j`/`%o`/`%O` stringify a
non-string value with plain `JSON.stringify` (falling back to the literal
`"[Circular]"` on failure), matching `quick-format-unescaped`'s own
*default* stringifier. Real pino never uses that default — it always
supplies its own fast-safe-stringify-based `stringify`, additionally
redaction-aware whenever the `redact` option is configured. A value that
would render differently under pino's actual stringifier (a circular
reference beyond `JSON.stringify`'s single-level detection, a `BigInt`, or
a path `redact` would have censored) renders differently in the text this
module scans — the redaction scan still runs against this function's own
JSON text either way, so a secret inside such a value is still caught by
value; only pino's *unrelated* path-based `redact` censoring of that same
interpolated value is not reproduced at this stage. A merging-object field
is never affected: it is walked and redacted independently, in its
original shape, never funneled through this formatter. Also unreproduced:
pino's `msgPrefix` option (applied by pino itself, after the hook returns,
to whatever single message string it receives — unaffected by this
change) and formatting a `msg`/interpolation split inside a normalized
bare-`Error` call shape's `rest` arguments, which no real pino call
produces (`Error.message` is fixed text, never a printf template).

**This does not extend the trust boundary past `hooks.logMethod` itself.**
Scanning the fully joined message closes the *msg/interpolation* gap, but
`hooks.logMethod` still runs before a host's own `serializers[key]` and
`formatters.log` (see "Why `hooks.logMethod`, not `formatters.log`" above).
A custom serializer or formatter that assembles new text from already-
redacted fields *after* the hook returns is not re-scanned — nothing this
directory does sanitizes a string a downstream pino stage creates. This was
already true before issue #361 and remains true after it; joining `msg`
with its interpolation values only moves that message's own formatting
earlier than it used to happen, it does not move every pino stage earlier.

## Block findings replace the whole message

Matching `examples/tracing-masking`'s masking callback: a `block` finding
doesn't leave a placeholder inline, it replaces the *entire* affected leaf —
the whole message, the whole field, the whole traceback — with
`[REDACTED:BLOCKED]`. A core failure (including `NOT_INITIALIZED` if a host
skips `await initialize()`, JS only) fails the same way, to
`[REDACTED:ERROR]`, and never surfaces the original text or the exception's
own message. Core errors never raise into, or crash, the caller's logging
call — a masked leaf is always returned, never an exception.

## Python `logging.Filter` semantics, pinned

The filter relies on these Python logging behaviors:

- `LogRecord.getMessage()` applies `%` interpolation before scanning. The
  filter stores the sanitized message and clears `args`.
- When `exc_info` is present, the filter renders and sanitizes the traceback,
  including exception chains, then clears the raw exception tuple. If only
  cached `exc_text` remains, it sanitizes that string directly. Reaching the
  exception depth limit emits a fixed marker.
- `stack_info` and configured string extras are sanitized directly.
- Attach the filter to each emitting handler. Ancestor logger filters do not
  run for propagated child records. Record mutations are shared across
  handlers, so filter ordering matters. Custom formatters must not append
  unscanned data after this filter.

See [`python/test_logging_filter.py`](./python/test_logging_filter.py) for
handler setup and regression tests.

## False positives, false negatives, and cost

- **False positives.** Log lines are dense with IDs, hashes, and config
  echoes; losing one to a false positive loses debugging information. Pass
  a `policy` that returns `"warn"` for medium/low-confidence findings
  instead of `"redact"`/`"block"` if that tradeoff matters more than hiding
  a possible secret — `scanAndRedact`/`scan_and_redact` leaves `warn`
  findings' text untouched, matching `examples/tracing-masking`.
  `RANGE_UNIT`, plumbing and the policy protocol are documented in the root
  README's "Core operations" section.
- **False negatives.** Non-string structured fields are not scanned unless
  serialized to a string first (numeric/binary secrets are out of scope, as
  in every other example here). Secrets split across separate log calls are
  never joined — each call's leaves are scanned independently, with no
  cross-call state (unlike a secret split across `msg` and its own
  interpolation values within one call, which is joined and scanned as one
  leaf — see "Scanning `msg` and its interpolation values as one leaf"
  above; that was the gap issue #361 closed). A secret embedded in a
  `%j`/`%o`/`%O` interpolation value is still scanned by value, but the text
  it's scanned in approximates pino's own stringifier rather than
  reproducing it exactly — see that section's trust-boundary note.
- **Cost.** Every log call pays the scan cost; see "Measured overhead"
  below and `DEFAULT_LIMITS` in `mask-leaf.mjs`/`mask_leaf.py`, which also
  bound the worst case for a pathological merging object or `extra` value.

## Limits

Every walk is bounded, exactly like `examples/tracing-masking`: `maxDepth`
(nesting), `maxArrayLength`/`maxObjectKeys` (elements dropped beyond the
limit, never passed through unmasked), `maxStringLength` (an oversized leaf
is marked `[REDACTED:LIMIT_EXCEEDED]`, not scanned), and `maxTotalLeaves` (a
whole-call budget). A self-referencing object is marked
`[REDACTED:CYCLE]` rather than recursed into forever. Override via the
`limits` option.

## Running the tests

```bash
node --test examples/logging-redaction/pino-hook.test.mjs
node --test examples/logging-redaction/format-pino-message.test.mjs
node --test examples/logging-redaction/pino-consumer.test.mjs
python3 -B -m unittest discover -s examples/logging-redaction/python -p "test_*.py"
```

`pino-hook.test.mjs` and `python/test_logging_filter.py` both use a fake
`scanAndRedact`/`scan_and_redact` and read
[`fixtures/logging-redaction-cases.json`](./fixtures/logging-redaction-cases.json),
so message strings, merging/extra fields, nesting, arrays, and Unicode
produce identical redacted output in both languages by construction, not by
inspection. Neither requires the built native addon or extension, or `pino`
installed.

Issue #361 required more than that: a real pino consumer, not a fake, since
the bug was about how `pino-hook.mjs` interacted with pino's *own* message
formatting. `pino` and its `quick-format-unescaped` dependency are now
pinned `devDependencies` of this workspace (`10.3.1` and `4.0.4`, exactly
matching what `pino@10.3.1` resolves), used only by two test files:
`format-pino-message.test.mjs` asserts `formatPinoMessage` byte-for-byte
against the real `quick-format-unescaped` package, and
`pino-consumer.test.mjs` wires `createRedactingLogMethodWith` (still with
the fake `scanAndRedact` — this is about the pino integration boundary, not
the Rust core's detection accuracy) into a real pino `10.3.1` logger and
asserts on the exact destination bytes: ordinary formatting, a contextual
assignment and a provider token each split across `msg`/interpolation
values, a merging object combined with a split message, a bare `Error`, a
`block` finding, a scanner failure, and coexistence with pino's own
path-based `redact`. `@redact-secret/core` itself is still not exercised by
either test — `pino-redact.mjs` remains the thin, untested-here live wrapper
it always was, requiring the built native addon.

## Measured overhead

Per-call redaction overhead for a message with no findings (the common
case), from `benchmark.mjs`/`python/benchmark.py`, run once against a
release build on this machine (Apple Silicon, macOS; numbers are
machine-dependent — the script, not these numbers, is the artifact worth
trusting):

| | 1 KB message | 64 KB message |
| --- | --- | --- |
| JS (`@redact-secret/core`, native addon, release) | median 0.22 ms/call, p95 0.28 ms/call | median 15.8 ms/call, p95 22.8 ms/call |
| Python (`redact_secret`, `maturin develop --release`) | median 0.26 ms/call, p95 0.29 ms/call | median 20.1 ms/call, p95 29.6 ms/call |

```bash
cd bindings/node && npm install && npm run build && cd ../..
npm run js:build
node examples/logging-redaction/benchmark.mjs

cd bindings/python && maturin develop --release && cd ../..
python3 examples/logging-redaction/python/benchmark.py
```
