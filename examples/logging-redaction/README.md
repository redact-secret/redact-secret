# Redact secrets in application logs

Two logging integrations, in JavaScript and Python, for keeping a secret out
of free-text log messages and arguments (issue #328): a pino
[`hooks.logMethod`](https://github.com/pinojs/pino/blob/main/docs/api.md#hooks)
for Node.js, and a `logging.Filter` for Python's standard library. Both are
examples, not package exports: no new dependency is added to
`@redact-secret/core` or `redact-secret`, and `pino` is not installed in this
workspace — the hook is duck-typed against pino's documented, pinned API
(see `pino-hook.mjs`'s module docstring) and verified against a real pino
`10.3.1` install while resolving this issue.

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
| [`pino-hook.mjs`](./pino-hook.mjs) | Pure `createRedactingLogMethodWith`: builds a pino `hooks.logMethod` from an injected `scanAndRedact`. |
| [`pino-redact.mjs`](./pino-redact.mjs) | The live wrapper: real `scanAndRedact`, `await initialize()`-ordered. |
| [`python/logging_filter.py`](./python/logging_filter.py) | `RedactSecretFilter(logging.Filter)` — the whole integration; Python's bindings have no init step, so there is no separate live-wrapper file. |

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
  cross-call state.
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
python3 -B -m unittest discover -s examples/logging-redaction/python -p "test_*.py"
```

Both suites use a fake `scanAndRedact`/`scan_and_redact` — no built native
addon or extension is required. `pino-hook.test.mjs` and
`python/test_logging_filter.py` both read
[`fixtures/logging-redaction-cases.json`](./fixtures/logging-redaction-cases.json),
so message strings, merging/extra fields, nesting, arrays, and Unicode
produce identical redacted output in both languages by construction, not by
inspection. `pino-hook.mjs` was additionally verified once against a real,
installed pino `10.3.1` (message, field, `err`, block, and coexistence with
pino's own path-based `redact` all behave as documented above) — that
verification is not part of the committed test suite, since it would add a
`pino` dependency this repo's examples otherwise avoid.

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
