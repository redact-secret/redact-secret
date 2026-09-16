# Public beta release status

Observed 2026-09-16. [Registry observation](registry-observation.json) records
version availability, npm integrity values, crate and Python checksums, npm
dist-tags, and annotated tag targets. Registry publication, workflow completion,
and a GitHub Release page are separate facts.

| Version | Registry artifacts | Annotated source tag | GitHub Release |
| --- | --- | --- | --- |
| 0.1.0-beta.1 | 8 npm packages, 2 crates, 9 Python files | `7bbd345be0604b8c3d50335985e0bfbbbe3703c9` | [Published](https://github.com/redact-secret/redact-secret/releases/tag/v0.1.0-beta.1) |
| 0.1.0-beta.2 | 8 npm packages, 2 crates, 9 Python files | `8cdc1b118449a15be545ecf70bb7f0df53f6126e` | Missing; [body prepared](beta.2-release-notes.md) |
| 0.1.0-beta.3 | 8 npm packages, 2 crates, 9 Python files | `34ea9b92ed8879082e99f56f8f4715ee4e4f1f35` | Missing; [body prepared](beta.3-release-notes.md) |

For `@redact-secret/core`, npm `beta` points to beta.3 and `latest` still points
to beta.1. Use `@redact-secret/core@0.1.0-beta.3` or `@redact-secret/core@beta`
when selecting the current beta. Python spells beta.3 as `0.1.0b3`.
No dist-tag was changed as part of this review.

Beta.2's [durable release record](0.1.0-beta.2/README.md) preserves its initial
partial failure and subsequent authorized repair. Beta.3 also had a failed
[original release run](https://github.com/redact-secret/redact-secret/actions/runs/35127722228):
its [original manifest](beta.3-original-manifest.json) recorded two native npm
packages as unpublished and the facade as unknown. The successful
[reconciliation run](https://github.com/redact-secret/redact-secret/actions/runs/35129831469)
and current registry observations establish the repaired publication state.
The original manifest is preserved verbatim, not rewritten as success.

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
