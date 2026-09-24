# Public beta release status

Every published version has one durable record under `docs/releases/<version>/`:
[beta.1](0.1.0-beta.1/README.md), [beta.2](0.1.0-beta.2/README.md),
[beta.3](0.1.0-beta.3/README.md), [beta.4](0.1.0-beta.4/README.md),
[beta.5](0.1.0-beta.5/README.md), and [beta.6](0.1.0-beta.6/README.md).
Beta.1 through beta.3 were also observed together on 2026-09-16: the
[registry observation](registry-observation.json) records their version
availability, npm integrity values, crate and Python checksums, npm dist-tags,
and annotated tag targets. The npm dist-tags below were observed on
2026-09-22. Registry publication, workflow completion,
and a GitHub Release page are separate facts.

| Version | Registry artifacts | Annotated source tag | GitHub Release |
| --- | --- | --- | --- |
| 0.1.0-beta.1 | 8 npm packages, 2 crates, 9 Python files | `7bbd345be0604b8c3d50335985e0bfbbbe3703c9` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.1) |
| 0.1.0-beta.2 | 8 npm packages, 2 crates, 9 Python files | `8cdc1b118449a15be545ecf70bb7f0df53f6126e` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.2) 2026-09-24 |
| 0.1.0-beta.3 | 8 npm packages, 2 crates, 9 Python files | `34ea9b92ed8879082e99f56f8f4715ee4e4f1f35` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.3) 2026-09-24 |
| 0.1.0-beta.4 | 8 npm packages, 2 crates, 9 Python files | `b4a9ae83d737d367ebc1d6d1732e634b44b2452a` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.4) 2026-09-24 |
| 0.1.0-beta.5 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `0cc48374d005a44334bf727e49125165ec7d4157` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.5) 2026-09-24 |
| 0.1.0-beta.6 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `079095e766e4a71e2b7e29413ed17be37bb3315d` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.6) 2026-09-24 |

For `@redact-secret/core`, npm `beta` points to beta.6 and `latest` still points
to beta.1. Use `@redact-secret/core@0.1.0-beta.6` or `@redact-secret/core@beta`
when selecting the current beta. Python spells beta.6 as `0.1.0b6`.
No `latest` dist-tag was changed as part of this release.

Beta.2's [durable release record](0.1.0-beta.2/README.md) preserves its initial
partial failure and subsequent authorized repair. Beta.3 also had a failed
[original release run](https://github.com/redact-secret/redact-secret/actions/runs/35127722228):
its [original manifest](0.1.0-beta.3/original-manifest.json) recorded two native npm
packages as unpublished and the facade as unknown. The successful
[reconciliation run](https://github.com/redact-secret/redact-secret/actions/runs/35129831469)
and registry observations establish the repaired publication state, recorded in
its [durable release record](0.1.0-beta.3/README.md).
The original manifest is preserved verbatim, not rewritten as success. Beta.5
had the same shape of failure — npm registry propagation lag, not a real
publish defect, first for seven npm packages and then for the facade alone —
detailed in its [durable release record](0.1.0-beta.5/README.md). Beta.6
repeated that propagation false negative, once for one native package and once
for the facade. It also recorded no workflow manifest, because of a
shell-quoting defect in the manifest step. Its reconstructed record states the
provenance of each original state ([beta.6](0.1.0-beta.6/README.md)).

Current registry availability is not by itself a reconstruction of every
artifact's original qualification chain. Beta.3's durable record is
limited to that original manifest and inventory, workflow evidence, registry
checksums, and tag identity; it must not be described as a new qualification run.

The beta.2 through beta.6 GitHub Release pages were created on 2026-09-24,
as prereleases on the existing annotated tags, with explicit maintainer
approval under the [release authority](../../AGENTS.md#release-authority).
Beta.2 and beta.3 use their prepared bodies
([beta.2](0.1.0-beta.2/github-release-notes.md),
[beta.3](0.1.0-beta.3/github-release-notes.md)); beta.4 through beta.6 use the
same shape and link their durable records. No package was republished, no tag
was created or moved, and no workflow was dispatched.
Qualified CLI binaries remain Actions artifacts; these bodies do not promise
new binary attachments. Security fixes target the latest beta under
[SECURITY.md](../../SECURITY.md).

## Host-integration adapters

The adapters are released from
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters),
on their own versions, not in lockstep with the core. Observed on the
registries on 2026-09-24:

| Package | Registry | Published version | Published | Requires core |
| --- | --- | --- | --- | --- |
| `@redact-secret/adapter` | npm | `0.1.0` (`latest`) | 2026-09-22 | `@redact-secret/core ^0.1.0-beta.6` (peer) |
| `@redact-secret/adapter-pino` | npm | `0.1.0` (`latest`) | 2026-09-22 | `@redact-secret/core ^0.1.0-beta.6`; peer `pino ^10.0.0` |
| `@redact-secret/adapter-otel` | npm | `0.1.0` (`latest`) | 2026-09-22 | `@redact-secret/core ^0.1.0-beta.6`; peer `@opentelemetry/sdk-trace-base ^2.0.0` |
| `redact-secret-adapters` | PyPI | `0.1.0` | 2026-09-22 | `redact-secret>=0.1.0b6,<0.2`; `[otel]` extra `opentelemetry-sdk>=1.16.0,<2` |

Source tags `adapter@0.1.0`, `adapter-pino@0.1.0`, `adapter-otel@0.1.0` and
`redact-secret-adapters@0.1.0` are on that repository, with the
[`train/2026.09.22`](https://github.com/redact-secret/redact-secret-adapters/releases/tag/train/2026.09.22)
GitHub Release. These commands were run from empty directories against the
public registries on 2026-09-24; each resolved core 0.1.0-beta.6 and redacted
a synthetic value through the adapter:

```bash
npm install @redact-secret/core @redact-secret/adapter-pino pino
npm install @redact-secret/core @redact-secret/adapter-otel @opentelemetry/sdk-trace-base
python -m pip install redact-secret redact-secret-adapters
python -m pip install redact-secret "redact-secret-adapters[otel]"
```

Published 0.1.0 of `@redact-secret/adapter-pino` exports
`createRedactingLogMethod`, `createRedactingLogMethodWith` and
`formatPinoMessage` only. The `createRedactingStreamWrite` hook shown in the
adapters repository's `main` README is unreleased.
