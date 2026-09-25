# Runtime-boundary reference architectures

[Documentation home](../README.md)

Three small, executable references show where authoritative redaction
belongs on the three adoption paths the project targets (#611, part of
#609). Each one is a separate consumer project under `examples/`. Each
installs only published or publish-shaped artifacts, and each has one
command that runs its end-to-end smoke test against the real core.

| Path | Reference | Installs | Smoke test |
| --- | --- | --- | --- |
| Application logging | [`examples/logging-redaction`](../../examples/logging-redaction/README.md) | `@redact-secret/adapter-pino`, `@redact-secret/core`, and `pino` from npm, pinned exactly by its `package-lock.json` | `npm run reference:logging` |
| OpenTelemetry tracing | [`examples/tracing-masking`](../../examples/tracing-masking/README.md) | `@redact-secret/adapter-otel`, `@redact-secret/adapter`, `@redact-secret/core`, and the OpenTelemetry SDK from npm, pinned exactly by its `package-lock.json` | `npm run reference:tracing` |
| AI context construction | [`examples/ai-context`](../../examples/ai-context/README.md) | `@redact-secret/core` from npm, pinned exactly; `@redact-secret/adapter-ai-context` and `@redact-secret/adapter-mcp` as the publish-shaped tarballs pinned in [`adapters/pin-source.json`](../../adapters/README.md), through the [`examples/mcp-redact`](../../examples/mcp-redact/README.md) golden path | `npm run reference:ai-context` |

`npm run references:smoke` runs all three. The `Reference architectures`
job in `.github/workflows/ci.yml` runs exactly these commands on every push
and pull request. Each needs network access for its install, so none of
them is part of the offline `npm run ci`.

## What every reference states

Each README answers the same questions, in the same order:

- **Trust zone.** Where plaintext exists, and which components are inside
  that zone.
- **Authoritative scan point.** The one call after which nothing
  downstream can see the unscanned value.
- **Preventive versus authoritative scanning.** Which scans are advisory
  and which one the integration relies on.
- **Failure and limit behavior.** What reaches the destination when the
  core fails, a policy blocks, or an input exceeds a limit.
- **Streaming behavior**, where the path has one.
- **What it does not protect.**

## What every smoke test guarantees

- It runs the released or pinned packages over the released core. No
  fake scanner and no copied integration code.
- Every sample value is unmistakably synthetic
  (`AKIASYNTHETICEXAMPLE`, `synthetic-example-value-0000`, and similar).
- It checks everything that reached the destination (log bytes, exported
  spans, model context, tool requests, audit callbacks) for every synthetic
  value *before* it prints anything, and its assertion messages are fixed
  text. A failing run therefore never prints plaintext. Nothing is written
  to disk.

## Where the evidence lives

These references do not restate measured numbers. The generated records
are:

- **Detection support.** The [support matrix](../support-matrix.md),
  generated from the pinned `benchmarks/support-matrix.json`: which
  credential families each reference can be expected to catch, and at what
  status.
- **Core performance and artifact size.**
  [`benchmarks/operational-evidence.json`](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/benchmarks/operational-evidence.json)
  in `redact-secret-benchmarks`, with its
  [beta.8 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/reports/2026-09-25-beta8-141-operational-evidence.md)
  (redact-secret-benchmarks#141).
- **Adapter compatibility.** The adapters repository's
  [`compatibility.json`](https://github.com/redact-secret/redact-secret-adapters/blob/f014a996ebb9693fbe1c8cc14f144435f011c2b8/compatibility.json)
  at the pinned commit: which host and core ranges each package is
  qualified against, and which versions it refuses (redact-secret-adapters#11).
  Its overhead workloads are
  [`scripts/measure-overhead.mjs`](https://github.com/redact-secret/redact-secret-adapters/blob/f014a996ebb9693fbe1c8cc14f144435f011c2b8/scripts/measure-overhead.mjs).

## Python

The Python halves of `examples/logging-redaction` and
`examples/tracing-masking` are unchanged, stdlib-only examples with fake
scanners (`npm run examples:python`). They are not references: they still
carry their own copy of the integration code. The released
`redact-secret-adapters` PyPI distribution is the supported Python path.
