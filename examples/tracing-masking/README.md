# Mask secrets in LLM tracing

Two integration points, in JavaScript and Python, for keeping secrets out of
LLM tracing and observability storage (issue #326): a **masking callback**
for host SDKs like Langfuse that hand you a value to mask, and an
**OpenTelemetry `SpanProcessor`** for pipelines built directly on OTel spans
(OpenInference, GenAI semantic-convention attributes). Both are examples, not
package exports: no new dependency is added to `@redact-secret/core` or
`redact-secret`, and every OpenTelemetry/Langfuse package used here is
example-only.

## Masking callback

`maskSecretsWith`/`mask_secrets_with` recursively walks strings inside plain
objects, arrays, and dicts/lists, redacting each with `scanAndRedact`/
`scan_and_redact`. Keys, numbers, booleans, and non-plain objects (`Date`,
class instances, tuples, ...) are left unchanged.

| File | Role |
| --- | --- |
| [`mask-leaf.mjs`](./mask-leaf.mjs) / [`python/mask_leaf.py`](./python/mask_leaf.py) | The shared primitive: mask one leaf string, fail closed on any error, replace a `block` finding's whole leaf. |
| [`mask-secrets.mjs`](./mask-secrets.mjs) / [`python/mask_secrets.py`](./python/mask_secrets.py) | Pure, dependency-injected recursive walker (`maskSecretsWith`/`mask_secrets_with`). No `@redact-secret/core` import, so it's testable without the built native addon — mirrors [`examples/safe-integration/integration.mjs`](../safe-integration/integration.mjs). |
| [`langfuse-mask.mjs`](./langfuse-mask.mjs) / [`python/langfuse_mask.py`](./python/langfuse_mask.py) | The live wrapper: real `scanAndRedact`/`scan_and_redact`, shaped to drop into Langfuse's `mask` hook directly. |

**Support level — example-only; not a maintained package.**
`decision-graduate-adapters-to-a-separate-repository` graduated pino, Python
`logging`, and OpenTelemetry `SpanProcessor` into the separate
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters)
repository; the Langfuse masking callback did not, because it needs no
package — it is `mask-secrets.mjs`'s shared walker plus the one line of host
code shown above, with no wiring subtle enough to justify a maintained
dependency. Langfuse itself is not installed in this workspace (unlike
pino or `opentelemetry-sdk`, both real, pinned `devDependencies` here), so
there is no exact SDK version pinned against; `langfuse-mask.mjs`/
`langfuse_mask.py` are confirmed against Langfuse's published masking docs
(https://langfuse.com/docs/observability/features/masking) as of resolving
issue #326, not against an installed, version-pinned package. Copy this file
out of the repository to use it; from that point on, tracking Langfuse's own
`mask` contract for drift is the integrator's responsibility, not this
repository's.

**Block findings.** `scanAndRedact` already substitutes `block` findings in
place, like `redact` ones — but an inline placeholder still leaves the rest
of the string visible. The masking callback goes further: a leaf with a
`block` finding is replaced *entirely* with a fixed marker
(`[REDACTED:BLOCKED]`), never a partial value. Findings otherwise pass
through unmodified strings for `warn`/`allow`, as `scanAndRedact` already
does.

**Initialization (JS only).** `await initialize()` must resolve before
`scanAndRedact` is called (`packages/javascript/src/index.ts`); Python's
bindings have no such step (the native extension loads on `import
redact_secret`). `createMaskSecrets()` enforces the order for JS. If a core
call is ever made before `initialize()` anyway, or fails for any other
reason, the affected leaf fails closed to `[REDACTED:ERROR]` rather than
throwing the original text or the error's own message back to the host SDK.

**Limits.** Every walk is bounded: `maxDepth` (nesting), `maxArrayLength` /
`maxObjectKeys` (elements dropped beyond the limit, never passed through
unmasked), `maxStringLength` (an oversized leaf is marked, not scanned), and
`maxTotalLeaves` (a whole-call budget). A self-referencing object is
detected and marked (`[REDACTED:CYCLE]`) rather than recursed into forever.
See `DEFAULT_LIMITS` in `mask-leaf.mjs`/`mask_leaf.py`; override via the
`limits` option.

## OpenTelemetry `SpanProcessor`

This integration graduated: `@redact-secret/adapter-otel` in the separate
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters)
repository builds on the same approach documented here
(`decision-graduate-adapters-to-a-separate-repository`). That package is
currently `private: true`, pending a real-span test confirming
`ReadableSpan.attributes` mutability at both ends of its declared
`@opentelemetry/sdk-trace-base ^2.0.0` range — see that repository for
current status. This directory's example stays as the executable reference
for the approach until that package is public.

| File | Role |
| --- | --- |
| [`redact-span-attributes.mjs`](./redact-span-attributes.mjs) / [`python/redact_span_attributes.py`](./python/redact_span_attributes.py) | Pure `RedactingSpanProcessorWith`: wraps any duck-typed `SpanProcessor` and redacts string/string-array attributes on a span and its events before delegating. No OpenTelemetry import — `SpanProcessor` is a structural interface in both languages. |
| [`otel-span-processor.mjs`](./otel-span-processor.mjs) / [`python/otel_span_processor.py`](./python/otel_span_processor.py) | The live factory: wires the real `scanAndRedact`/`scan_and_redact` in. |

It redacts every string and string-array attribute value, which covers
OpenInference (`llm.input_messages`, `input.value`, ...) and GenAI
semantic-convention attributes (`gen_ai.prompt`, ...) without allowlisting
either convention's attribute names.

Pinned while resolving issue #326:

- JS: `@opentelemetry/sdk-trace-base@2.11.0`. `SpanProcessor.onEnd(span:
  ReadableSpan)`; `span.attributes` is typed `readonly` but is a plain,
  mutable object at runtime, so `onEnd` mutates it in place.
- Python: `opentelemetry-sdk==1.44.0`. `SpanProcessor.on_end(span:
  ReadableSpan)`; `ReadableSpan.attributes` returns a read-only
  `MappingProxyType` — there is no public mutation API before export, so
  this reaches into the private `_attributes` field (and each event's
  `_attributes`) instead, the accepted workaround absent a public API. If a
  future SDK version removes that field, the exporter assertion in
  `test_redact_span_attributes.py` fails loudly rather than silently letting
  plaintext through.

## False positives and false negatives

- **False positives** corrupt observability data rather than blocking
  anything, since trace payloads are mostly code, config, and IDs. The
  default policy redacts high-confidence and known-type findings and warns
  on the rest (`crates/secret-scan-core/src/policy.rs`); pass a custom
  `policy` to relax redaction to `warn` for types you find too aggressive
  here.
- **False negatives**: a secret split across separate attributes or chat
  messages is not joined across leaves — each leaf is scanned independently.
  Encoded values (base64, URL-encoded JSON) are not decoded before
  scanning, so an encoded secret is not detected.

## Running the tests

```bash
npm run examples:test
python3 -B -m unittest discover -s examples/tracing-masking/python -p "test_*.py"
```

Both suites use a fake `scanAndRedact`/`scan_and_redact` — no built native
addon or extension is required. `mask-secrets.test.mjs` and
`python/test_mask_secrets.py` both read
[`fixtures/mask-secrets-cases.json`](./fixtures/mask-secrets-cases.json), so
nested objects, arrays, chat-message arrays, tool-call arguments/results,
and Unicode produce byte-identical masked output in both languages by
construction, not by inspection.

## Upstream validation

Acceptance criterion for issue #326: open an upstream docs/example PR or
discussion with at least one tracing SDK to validate integrator demand, and
link it from the issue. That is a real action against an external
repository (Langfuse, Arize Phoenix, or another SDK's own repo) and is not
performed by this change; it is tracked as follow-up.
