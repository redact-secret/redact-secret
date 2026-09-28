# Public beta release status

Every published version has one durable record under `docs/releases/<version>/`:
[beta.1](0.1.0-beta.1/README.md), [beta.2](0.1.0-beta.2/README.md),
[beta.3](0.1.0-beta.3/README.md), [beta.4](0.1.0-beta.4/README.md),
[beta.5](0.1.0-beta.5/README.md), [beta.6](0.1.0-beta.6/README.md), [beta.7](0.1.0-beta.7/README.md),
[beta.8](0.1.0-beta.8/README.md), [beta.9](0.1.0-beta.9/README.md), and
[beta.10](0.1.0-beta.10/README.md).
Beta.1 through beta.3 were also observed together on 2026-09-16: the
[registry observation](registry-observation.json) records their version
availability, npm integrity values, crate and Python checksums, npm dist-tags,
and annotated tag targets. The npm dist-tags below were last observed on
2026-09-28. Registry publication, workflow completion,
and a GitHub Release page are separate facts.

| Version | Registry artifacts | Annotated source tag | GitHub Release |
| --- | --- | --- | --- |
| 0.1.0-beta.1 | 8 npm packages, 2 crates, 9 Python files | `7bbd345be0604b8c3d50335985e0bfbbbe3703c9` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.1) |
| 0.1.0-beta.2 | 8 npm packages, 2 crates, 9 Python files | `8cdc1b118449a15be545ecf70bb7f0df53f6126e` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.2) 2026-09-24 |
| 0.1.0-beta.3 | 8 npm packages, 2 crates, 9 Python files | `34ea9b92ed8879082e99f56f8f4715ee4e4f1f35` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.3) 2026-09-24 |
| 0.1.0-beta.4 | 8 npm packages, 2 crates, 9 Python files | `b4a9ae83d737d367ebc1d6d1732e634b44b2452a` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.4) 2026-09-24 |
| 0.1.0-beta.5 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `0cc48374d005a44334bf727e49125165ec7d4157` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.5) 2026-09-24 |
| 0.1.0-beta.6 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `079095e766e4a71e2b7e29413ed17be37bb3315d` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.6) 2026-09-24 |
| 0.1.0-beta.7 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `2b98027bbf38d63f07b75129fe2864ef32ed4732` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.7) 2026-09-24 |
| 0.1.0-beta.8 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `5639a0ea02e0eefbd1533bea23a05c749b529bef` | Not created |
| 0.1.0-beta.9 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `f726f2ffb0fd854cc3eeb4c35798695fde3161d3` | Not created |
| 0.1.0-beta.10 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `af7f863f29f9fe482dd233c8b7bc5b77dc427314` | Not created |

Observed on 2026-09-28 (`npm view <package> dist-tags`), all ten npm
packages (`@redact-secret/core`, `@redact-secret/wasm` and the eight native
addons) have `beta` and `latest` both at `0.1.0-beta.10`. The release workflow
publishes prereleases with `--tag beta` only, so it never sets `latest`; every
`latest` value in this file was set by hand, outside the release workflows.
The history of that hand-moved tag, as observed: beta.1 (beta.5 for the musl
addons) until 2026-09-24, beta.6 on 2026-09-24, beta.7 on 2026-09-25, beta.8 at
an unrecorded time after 2026-09-25, and beta.10 at an unrecorded time on or
before 2026-09-28 (an earlier revision of this page recorded beta.8 as the
2026-09-28 value; the registry showed beta.10 when re-observed the same day). Use
`@redact-secret/core@0.1.0-beta.10` or `@redact-secret/core@beta` to select the
current beta. Python spells beta.7 as `0.1.0b7`, beta.9 as `0.1.0b9` and beta.10
as `0.1.0b10`; PyPI has no dist-tag equivalent, so `pip install redact-secret`
resolves the newest version, and `--pre` is needed only because every release is
a prerelease.

The `latest` policy for Beta.11 is recorded in
[releasing](../releasing.md#npm-dist-tag-policy): the Beta.11 publish does not
move `latest`, so after it a bare `npm i @redact-secret/core` still resolves
beta.10 until `latest` is moved again as a separate, explicitly approved action.

Beta.8's manifest is reconstructed, because its run's manifest job failed ([#799](https://github.com/redact-secret/redact-secret/issues/799)); no publication was partial. Beta.9's release run failed only at its `npm:@redact-secret/core` publish job's pre-publish `release:check` gate, on an unrelated `examples/mcp-redact` dependency, not the actual `npm publish` step or a redact-secret artifact defect; Reconcile Release repaired it. Both beta.9's and beta.10's manifests are reconstructed, because this repository's manifest job has never itself populated the tag/registry/verification evidence a durable record requires (see each [record](0.1.0-beta.9/README.md) for what each reconstruction corrects). No beta.8, beta.9 or beta.10 publication was partial by the time of publication.

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
registries on 2026-09-28 (`npm view` for npm, the PyPI JSON API for PyPI):

| Package | Registry | Published version | Published | Requires core |
| --- | --- | --- | --- | --- |
| `@redact-secret/adapter` | npm | `0.1.2` (`latest`) | 2026-09-26 | `@redact-secret/core ^0.1.0-beta.6` (peer) |
| `@redact-secret/adapter-pino` | npm | `0.1.1` (`latest`) | 2026-09-25 | `@redact-secret/core ^0.1.0-beta.6`; peer `pino ^10.0.0` |
| `@redact-secret/adapter-otel` | npm | `0.1.1` (`latest`) | 2026-09-25 | `@redact-secret/core ^0.1.0-beta.6`; peer `@opentelemetry/sdk-trace-base ^2.0.0` |
| `@redact-secret/adapter-ai-context` | npm | `0.1.0-alpha.1` (`alpha`, also `latest`) | 2026-09-26 | `@redact-secret/core ^0.1.0-beta.6` (peer) |
| `@redact-secret/adapter-mcp` | npm | `0.1.0-alpha.1` (`alpha`, also `latest`) | 2026-09-26 | `@redact-secret/core ^0.1.0-beta.6` (peer); MCP SDK peers |
| `redact-secret-adapters` | PyPI | `0.1.0` | 2026-09-22 | `redact-secret>=0.1.0b6,<0.2`; `[otel]` extra `opentelemetry-sdk>=1.16.0,<2` |

Source tags `adapter@0.1.0`, `adapter-pino@0.1.0`, `adapter-otel@0.1.0` and
`redact-secret-adapters@0.1.0` came with the
[`train/2026.09.22`](https://github.com/redact-secret/redact-secret-adapters/releases/tag/train/2026.09.22)
GitHub Release. `adapter@0.1.1`, `adapter-pino@0.1.1` and `adapter-otel@0.1.1`
came with
[`train/2026.09.25`](https://github.com/redact-secret/redact-secret-adapters/releases/tag/train/2026.09.25)
(`ea92c2ab`); `adapter@0.1.2`, `adapter-ai-context@0.1.0-alpha.1` and
`adapter-mcp@0.1.0-alpha.1` came with
[`train/2026.09.26`](https://github.com/redact-secret/redact-secret-adapters/releases/tag/train/2026.09.26)
(`be3f2ad5`). The PyPI package has only `0.1.0`; the later trains published
npm packages only. The install commands below were run from empty directories
against the public registries on 2026-09-24 (before the 0.1.1 and 0.1.2
publications) and each resolved core 0.1.0-beta.6 and redacted a synthetic
value through the adapter; they were not re-run for the later versions:

```bash
npm install @redact-secret/core @redact-secret/adapter-pino pino
npm install @redact-secret/core @redact-secret/adapter-otel @opentelemetry/sdk-trace-base
python -m pip install redact-secret redact-secret-adapters
python -m pip install redact-secret "redact-secret-adapters[otel]"
```

`@redact-secret/adapter-pino@0.1.0` exported `createRedactingLogMethod`,
`createRedactingLogMethodWith` and `formatPinoMessage` only. Since
`@redact-secret/adapter-pino@0.1.1` (2026-09-25), the published package also
ships the `createRedactingStreamWrite` hook.

## Vault

The opt-in, in-memory vault is released from
[`redact-secret-vault`](https://github.com/redact-secret/redact-secret-vault),
on its own alpha versions, not in lockstep with the core. Observed on the
registries on 2026-09-28:

| Package | Registry | Published version | Published | Requires core |
| --- | --- | --- | --- | --- |
| `@redact-secret/vault` | npm | `0.1.0-alpha.3` (`alpha`, also `latest`) | 2026-09-28 | peer `@redact-secret/core` exactly `0.1.0-beta.10` |
| `@redact-secret/vault-server` | npm | `0.1.0-alpha.3` (`alpha`, also `latest`) | 2026-09-28 | peer `@redact-secret/core` exactly `0.1.0-beta.10`; depends on `@redact-secret/vault` exactly `0.1.0-alpha.3` |
| `redact-secret-vault` | PyPI | `0.1.0a3` | 2026-09-28 | no `redact-secret` dependency: it declares only the `test` and `lint` extras |

Source tag `v0.1.0-alpha.3` (`bd01c061`) is on the vault repository. The npm
pin is exact, not a range, so each core release needs a matching vault release
before the two install together; the vault's core pin, unlike the adapters'
`^0.1.0-beta.6` range, moves with the core. The Python package is the native
server-authority counterpart of `@redact-secret/vault-server` and does not
import the core.
