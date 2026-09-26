# Reference: redact secrets in application logs

The application-logging reference architecture (#611; index in
[runtime-boundary reference architectures](../../docs/guides/reference-architectures.md)).
A Node.js service logs through [pino](https://github.com/pinojs/pino), and
the released [`@redact-secret/adapter-pino`](https://www.npmjs.com/package/@redact-secret/adapter-pino)
redacts every message, merging-object field, and error before pino
serializes anything, and every string of the finished line (child-logger
bindings and `mixin()` output included) before pino writes it.

```bash
npm run reference:logging   # from the repository root: npm ci here, then the smoke test
```

| File | Role |
| --- | --- |
| [`app.mjs`](./app.mjs) | The whole integration: `createAppLogger`, a pino logger whose `hooks.logMethod` and `hooks.streamWrite` are the adapter's. |
| [`smoke.mjs`](./smoke.mjs) | The end-to-end smoke test, on real pino and the real core. |
| [`package.json`](./package.json) / [`package-lock.json`](./package-lock.json) | This directory as a consumer project: `@redact-secret/adapter-pino@0.1.1` (with `@redact-secret/adapter@0.1.1`), `@redact-secret/core@0.1.0-beta.8`, and `pino@10.3.1`, all from the npm registry, with every transitive version pinned by the lockfile. |
| [`python/`](./python) | The Python `logging.Filter` example. It is not part of the reference; see [Python](#python). |

This directory used to carry its own copy of the pino hook, its message
formatter, and the value walker. That code graduated into
`@redact-secret/adapter-pino` and `@redact-secret/adapter`
(`decision-graduate-adapters-to-a-separate-repository`), and the tests that
pinned its behavior against pino now run in
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters).
This reference installs the released packages instead of keeping a second,
divergent copy.

```js
import pino from "pino";
import { createRedactingLogMethod, createRedactingStreamWrite } from "@redact-secret/adapter-pino";

const logger = pino({
  hooks: {
    logMethod: await createRedactingLogMethod(),
    streamWrite: await createRedactingStreamWrite(), // bindings and mixin() output never pass logMethod
  },
  redact: ["req.headers.authorization"], // pino's own path-based redact still applies, afterwards
});

logger.info("api_key=%s", value); // the format string and its values are joined, then scanned as one string
```

## Trust zone

Plaintext exists in the application process: in the caller's own variables,
in the arguments of the `logger.info(...)` call, in child-logger bindings and
`mixin()` output until `hooks.streamWrite` scans the finished line, and inside
the adapter while it scans. Everything after `hooks.streamWrite` (the
destination, a transport's worker thread, and whatever collects the log
stream) sees only redacted text.

## Authoritative scan point

pino's `hooks.logMethod`. It receives the caller's raw arguments before pino
merges, serializes, formats, or redacts anything, and it is the only pino
extension point that sees the message itself. The adapter joins `msg` with
its interpolation values exactly as pino would format them, scans that as
one string, scans every string field of a merging object, and replaces any
`Error` with an already-redacted `{ type, message, stack }`. It then hands
pino the redacted arguments. The adapter's own documentation carries the
pino source references behind each of these claims.

`hooks.logMethod` never sees child-logger bindings (`logger.child({...})`,
`setBindings()`), which pino serializes once when the child is created, or
`mixin()` output, which pino merges after the hook returns. With
`@redact-secret/adapter-pino@0.1.0` and `logMethod` alone, a secret in
either reached the destination in plaintext. `hooks.streamWrite`, added in
`0.1.1`, scans every string value of the finished JSON line just before it
reaches the destination, so this reference installs both. The smoke test's
`child-logger bindings` and `mixin output` scenarios fail without it.

## Preventive versus authoritative scanning

The two hooks are the authoritative scan for this process's logs. pino's `redact`
option is preventive and path-based only: it censors known keys, such as an
`authorization` header, but cannot find a secret inside a message string.
Keep it for the fields you already know about. A log pipeline that also
scans downstream (a collector or a SIEM rule) is defense in depth, not a
replacement: by then the secret has already left the process.

## Failure and limit behavior

Every case below is exercised by `smoke.mjs` against the real core.

| Case | What the destination receives |
| --- | --- |
| A `redact` finding | The line, with each finding's span replaced by `<SECRET_N>` |
| A `block` finding (the host's policy) | The whole affected leaf becomes `[REDACTED:BLOCKED]` |
| A core or policy failure | The whole affected leaf becomes `[REDACTED:ERROR]`; the error never reaches the log call |
| A string over `maxStringLength` | `[REDACTED:LIMIT_EXCEEDED]`, without scanning it |
| Depth, array, key, or leaf budget exhausted | The remaining values are dropped or marked, never written unscanned |
| A self-referencing object | `[REDACTED:CYCLE]` |

A log call never throws because of redaction. The defaults are
`DEFAULT_LIMITS` in `@redact-secret/adapter`; pass `limits` to
`createRedactingLogMethod` to change them.

## Streaming behavior

Not applicable. Every log call is scanned on its own, as one whole input,
before pino writes it. There is no state across calls.

## What it does not protect

- **Anything that assembles new text after `hooks.streamWrite`.** A
  transport or destination that builds a string from the written line is
  not scanned again. (Custom serializer, `formatters.log`, and `msgPrefix`
  output is part of the line, so `streamWrite` scans its string values.)
- **Object keys.** `hooks.streamWrite` scans string values, not keys.
- **A secret split across log calls.** Each call is scanned independently.
- **Other writers.** `console.log`, `process.stdout.write`, a second logger
  without the hook, and a child process's output bypass it.
- **Non-string values.** Numbers, binary buffers, and encoded values
  (base64, percent-encoding) are not decoded or scanned.
- **Detection gaps.** A line with no finding is not proof that it held no
  secret; see [detection and limits](../../docs/reference/detection.md) and
  the [support matrix](../../docs/support-matrix.md). One example seen while
  building this reference: `@redact-secret/core@0.1.0-beta.8` does not
  detect the assignment in `login failed: password=<value>`, while it does
  detect `login failed with password=<value>`. The core fix
  ([#812](https://github.com/redact-secret/redact-secret/issues/812)) is on
  `main` and ships in the next core release. This reference installs the
  released beta.8, so `smoke.mjs` keeps the second form until its core pin
  moves past beta.8.
- **The process itself.** Plaintext still exists in memory and in the
  caller's own variables.

## Evidence

- Support: the [support matrix](../../docs/support-matrix.md).
- Core cost per scan and per artifact: `redact-secret-benchmarks`'
  [operational evidence](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/reports/2026-09-25-beta8-141-operational-evidence.md).
- Which pino and core versions the adapter is qualified against, and which
  it refuses: the adapters repository's
  [`compatibility.json`](https://github.com/redact-secret/redact-secret-adapters/blob/ea92c2abd451b66899722170344e73d8f34ef47e/compatibility.json).

## Python

[`python/logging_filter.py`](./python/logging_filter.py) is a
`logging.Filter` for Python's standard library. It keeps its own copy of the
integration code and is tested with a fake scanner, standard library only:

```bash
python3 -B -m unittest discover -s examples/logging-redaction/python -p "test_*.py"
```

The supported Python path is the released
[`redact-secret-adapters`](https://pypi.org/project/redact-secret-adapters/)
distribution. The filter relies on these `logging` behaviors:

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

[`python/benchmark.py`](./python/benchmark.py) times the filter against a
release build of the `redact_secret` extension on your machine.
