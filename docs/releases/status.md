# Public beta release status

Beta.1 through beta.3 were observed on 2026-09-16:
[registry observation](registry-observation.json) records their version
availability, npm integrity values, crate and Python checksums, npm dist-tags,
and annotated tag targets. Beta.4's registry checksums and tag target are in its
[durable release record](0.1.0-beta.4/README.md); beta.5's and beta.6's are in
their durable release records ([beta.5](0.1.0-beta.5/README.md),
[beta.6](0.1.0-beta.6/README.md)). The npm dist-tags below were observed on
2026-09-22. Registry publication, workflow completion,
and a GitHub Release page are separate facts.

| Version | Registry artifacts | Annotated source tag | GitHub Release |
| --- | --- | --- | --- |
| 0.1.0-beta.1 | 8 npm packages, 2 crates, 9 Python files | `7bbd345be0604b8c3d50335985e0bfbbbe3703c9` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.1) |
| 0.1.0-beta.2 | 8 npm packages, 2 crates, 9 Python files | `8cdc1b118449a15be545ecf70bb7f0df53f6126e` | Missing; [body prepared](beta.2-release-notes.md) |
| 0.1.0-beta.3 | 8 npm packages, 2 crates, 9 Python files | `34ea9b92ed8879082e99f56f8f4715ee4e4f1f35` | Missing; [body prepared](beta.3-release-notes.md) |
| 0.1.0-beta.4 | 8 npm packages, 2 crates, 9 Python files | `b4a9ae83d737d367ebc1d6d1732e634b44b2452a` | Missing; [record](0.1.0-beta.4/README.md) |
| 0.1.0-beta.5 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `0cc48374d005a44334bf727e49125165ec7d4157` | Missing; [record](0.1.0-beta.5/README.md) |
| 0.1.0-beta.6 | 10 npm packages (including 2 musl), 2 crates, 9 Python files | `079095e766e4a71e2b7e29413ed17be37bb3315d` | Missing; [record](0.1.0-beta.6/README.md) |

For `@redact-secret/core`, npm `beta` points to beta.6 and `latest` still points
to beta.1. Use `@redact-secret/core@0.1.0-beta.6` or `@redact-secret/core@beta`
when selecting the current beta. Python spells beta.6 as `0.1.0b6`.
No `latest` dist-tag was changed as part of this release.

Beta.2's [durable release record](0.1.0-beta.2/README.md) preserves its initial
partial failure and subsequent authorized repair. Beta.3 also had a failed
[original release run](https://github.com/redact-secret/redact-secret/actions/runs/35127722228):
its [original manifest](beta.3-original-manifest.json) recorded two native npm
packages as unpublished and the facade as unknown. The successful
[reconciliation run](https://github.com/redact-secret/redact-secret/actions/runs/35129831469)
and current registry observations establish the repaired publication state.
The original manifest is preserved verbatim, not rewritten as success. Beta.5
had the same shape of failure — npm registry propagation lag, not a real
publish defect, first for seven npm packages and then for the facade alone —
detailed in its [durable release record](0.1.0-beta.5/README.md). Beta.6
repeated that propagation false negative, once for one native package and once
for the facade. It also recorded no workflow manifest, because of a
shell-quoting defect in the manifest step. Its reconstructed record states the
provenance of each original state ([beta.6](0.1.0-beta.6/README.md)).

Current registry availability is not by itself a reconstruction of every
artifact's original qualification chain. Beta.3's local closeout record is
limited to that original manifest, workflow evidence, registry checksums, and
tag identity; it must not be described as a new qualification run.

The prepared GitHub Release bodies target the existing annotated tags and are
prereleases. Creating those pages requires the explicit release approval in
`AGENTS.md`; no package republish, new tag, or workflow dispatch is needed.
Qualified CLI binaries remain Actions artifacts; these bodies do not promise
new binary attachments. Security fixes target the latest beta under
[SECURITY.md](../../SECURITY.md).
