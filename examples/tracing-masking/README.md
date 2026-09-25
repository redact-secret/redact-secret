# Reference: redact secrets in OpenTelemetry traces

The OpenTelemetry tracing reference architecture (#611; index in
[runtime-boundary reference architectures](../../docs/guides/reference-architectures.md)).
A Node.js service traces LLM calls with the OpenTelemetry SDK, and the
released [`@redact-secret/adapter-otel`](https://www.npmjs.com/package/@redact-secret/adapter-otel)
redacts span and span-event attributes (OpenInference, GenAI semantic
conventions, or anything else string-shaped) before the exporter sees them.
The same directory shows the masking callback for a tracing SDK with its own
`mask` hook, such as Langfuse, from the released
[`@redact-secret/adapter`](https://www.npmjs.com/package/@redact-secret/adapter).

```bash
npm run reference:tracing   # from the repository root: npm ci here, then the smoke test
```

| File | Role |
| --- | --- |
| [`app.mjs`](./app.mjs) | The whole integration: `createAppTracerProvider` (the redacting `SpanProcessor` in front of the exporter's processor) and `createAppMaskCallback` (the masking callback). |
| [`smoke.mjs`](./smoke.mjs) | The end-to-end smoke test, on the real OpenTelemetry SDK and the real core. |
| [`package.json`](./package.json) / [`package-lock.json`](./package-lock.json) | This directory as a consumer project: `@redact-secret/adapter-otel@0.1.0`, `@redact-secret/adapter@0.1.0`, `@redact-secret/core@0.1.0-beta.8`, `@opentelemetry/sdk-trace-base@2.11.0`, and `@opentelemetry/api@1.9.1`, all from the npm registry, with every transitive version pinned by the lockfile. |
| [`python/`](./python) | The Python `SpanProcessor` and Langfuse examples. They are not part of the reference; see [Python](#python). |

This directory used to carry its own copy of the span processor, the
masking walker, and their leaf primitive. That code graduated into
`@redact-secret/adapter-otel` and `@redact-secret/adapter`
(`decision-graduate-adapters-to-a-separate-repository`), whose real-span
tests run in
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters).
This reference installs the released packages instead of keeping a second,
divergent copy.

```js
import { BatchSpanProcessor, BasicTracerProvider } from "@opentelemetry/sdk-trace-base";
import { createRedactingSpanProcessor } from "@redact-secret/adapter-otel";

const provider = new BasicTracerProvider({
  spanProcessors: [await createRedactingSpanProcessor(new BatchSpanProcessor(exporter))],
});
```

```js
import { Langfuse } from "langfuse";
import { createMaskSecrets } from "@redact-secret/adapter";

const maskSecrets = await createMaskSecrets();
const langfuse = new Langfuse({ mask: ({ data }) => maskSecrets(data) });
```

## Trust zone

Plaintext exists in the application process: in the code that sets
attributes, in the SDK's in-memory span while it is open, and in every span
processor that runs before the redacting one. Everything the wrapped
processor hands on (the batch queue, the exporter, the collector, the
tracing backend) sees only redacted attributes.

For the masking callback, plaintext exists until the host SDK calls `mask`;
what the SDK sends after that is masked.

## Authoritative scan point

The redacting processor's `onEnd`. It redacts the ended span's attributes,
and each event's attributes, in place, and only then calls the wrapped
processor. It must be the only path to an exporter: a processor registered
beside it receives the same span before or without redaction.

## Preventive versus authoritative scanning

The span processor is the authoritative scan for what this process
exports. Redacting a prompt before it is set as an attribute is preventive:
it helps, but any attribute set elsewhere is still covered only by the
processor. A collector-side redaction processor is defense in depth; by then
the plaintext has left the process.

## Failure and limit behavior

Every case below is exercised by `smoke.mjs` against the real core.

| Case | What the exporter receives |
| --- | --- |
| A `redact` finding | The attribute, with each finding's span replaced by `<SECRET_N>` |
| A `block` finding (the host's policy) | The whole attribute value becomes `[REDACTED:BLOCKED]` |
| A core or policy failure | The whole attribute value becomes `[REDACTED:ERROR]`; the span still ends and exports |
| A string over `maxStringLength` | `[REDACTED:LIMIT_EXCEEDED]`, without scanning it |
| Numbers, booleans, and their arrays | Unchanged; they carry no free text |

The masking callback walks nested values under `DEFAULT_LIMITS` from
`@redact-secret/adapter`: past a depth, array, key, or leaf budget, values
are dropped or marked, never passed on unscanned, and a cycle becomes
`[REDACTED:CYCLE]`.

## Streaming behavior

Not applicable. A span is scanned once, when it ends. A streamed LLM
response is covered only once its text is set as an attribute or event on a
span that ends.

## What it does not protect

`@redact-secret/adapter-otel@0.1.0` redacts span attributes and span-event
attributes only. It does not scan:

- the span name, the status message, link attributes, or resource
  attributes;
- a span seen by another processor, or exported by another provider;
- baggage, propagated trace context headers, or metrics and logs signals.

It also shares the general limits: a secret split across attributes is not
joined, encoded values are not decoded, and a span with no finding is not
proof that it held no secret ([detection and limits](../../docs/reference/detection.md)).

## Evidence

- Support: the [support matrix](../../docs/support-matrix.md).
- Core cost per scan and per artifact: `redact-secret-benchmarks`'
  [operational evidence](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/reports/2026-09-25-beta8-141-operational-evidence.md).
- Which OpenTelemetry SDK and core versions the adapter is qualified
  against, and which it refuses: the adapters repository's
  [`compatibility.json`](https://github.com/redact-secret/redact-secret-adapters/blob/a7fbcc32b56ada3b5107e9fbddb9a019eeaf6d43/compatibility.json).

## Python

The Python files keep their own copy of the integration code and are tested
with a fake scanner, standard library only:

```bash
python3 -B -m unittest discover -s examples/tracing-masking/python -p "test_*.py"
```

The supported Python path is the released
[`redact-secret-adapters`](https://pypi.org/project/redact-secret-adapters/)
distribution.

| File | Role |
| --- | --- |
| [`python/mask_secrets.py`](./python/mask_secrets.py) / [`python/langfuse_mask.py`](./python/langfuse_mask.py) | The masking walker and its Langfuse wrapper (`Langfuse(mask=mask_secrets)`). |
| [`python/redact_span_attributes.py`](./python/redact_span_attributes.py) / [`python/otel_span_processor.py`](./python/otel_span_processor.py) | A duck-typed `SpanProcessor` and its live factory. |

Pinned for `opentelemetry-sdk==1.44.0`: `ReadableSpan.attributes` returns a
read-only `MappingProxyType`, and there is no public mutation API before
export, so the processor writes the private `_attributes` field (and each
event's `_attributes`). If a future SDK removes that field, the exporter
assertion in `test_redact_span_attributes.py` fails loudly rather than
letting plaintext through.

Langfuse is not installed in this workspace. `langfuse_mask.py` follows
Langfuse's published [masking documentation](https://langfuse.com/docs/observability/features/masking)
and is example-only: once copied out, tracking Langfuse's `mask` contract is
the integrator's responsibility.
