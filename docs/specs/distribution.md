# Distribution

Rules governing what ships, in what shape, from which registry, and under what identity.

> Generated for [issue #597](https://github.com/redact-secret/redact-secret/issues/597) (DS6a). Each rule
> below states current behavior in the present tense and links the ADR
> (`docs/decisions/`) that decided it. An ADR records why and when; this file
> records what is true now. Per
> [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md),
> a decision that applies an existing policy to one more provider family or
> one more instance is a row here plus its supporting evidence, not a new
> ADR.

## Rules

| Rule | Governing ADR |
| --- | --- |
| Every published binding (core, wasm, node-native, CLI) ships the same version number from the same release, never independently. | [Release bindings in lockstep](../decisions/2026-09-09-release-bindings-in-lockstep.md) |
| Every registry, import, binary, and internal metadata namespace uses the `Redact Secret` / `redact-secret` identity, per the naming matrix; exported error type names and internal crate-directory paths are explicitly excluded. | [Adopt the Redact Secret naming contract](../decisions/2026-09-10-adopt-redact-secret-naming-contract.md) |
| A release ships its full committed artifact set (npm facade, wasm, native node packages, CLI, Python) together, not a partial subset; the musl Node addon targets ship alongside the original six glibc targets. | [Ship the first release's full artifact set](../decisions/2026-09-10-ship-first-release-artifact-set.md) |
| Node consumers fall back to the WebAssembly build when the native addon is unusable for their platform. | [Add a Node WebAssembly fallback when the native addon is unusable](../decisions/2026-09-19-add-node-webassembly-fallback.md) |
| Logging and tracing host-integration adapters (`@redact-secret/adapter*` / `redact-secret-adapters`) ship from the separate `redact-secret/redact-secret-adapters` repository, not this one. | [Graduate logging and tracing adapters to a separate repository](../decisions/2026-09-19-graduate-adapters-to-a-separate-repository.md) |
| The two musl-libc Node addon triples are published alongside the six already-covered glibc targets. | [Publish the musl Node addon packages](../decisions/2026-09-19-publish-musl-node-addon-packages.md) |
| `@redact-secret/core` is verified against Cloudflare Workers and Vercel Edge before those runtimes are claimed as supported. | [Verify @redact-secret/core on Cloudflare Workers and Vercel Edge](../decisions/2026-09-19-verify-edge-runtimes.md) |

