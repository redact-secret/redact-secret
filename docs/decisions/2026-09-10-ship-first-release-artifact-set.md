---
decision_id: decision-ship-first-release-artifact-set
status: accepted
scope: workspace
title: Ship the first release's full artifact set
decided_at: 2026-09-10
full_record: https://github.com/redact-secret/redact-secret/blob/180335698aba54f71e3e994f1a90da6752f06396/docs/decisions/2026-09-10-ship-first-release-artifact-set.md
spec: distribution
aliases: decision-publish-musl-node-addons
---
# Ship the first release's full artifact set

Summarized in place 2026-09-22 by
[#600](https://github.com/redact-secret/redact-secret/issues/600) (DS6d
disposition grade). The `full_record` link above is the complete pre-summary
text, including the per-artifact publication-path table under the names then
in force and both former `Current application` appendices. The current
artifact mapping lives in [`docs/specs/distribution.md`](../specs/distribution.md).
[Folded records](#folded-records) lists the decision merged into this one;
its `decision_id` survives in `aliases:`.

## Decision

Branch A of `RB-9` (#79): the first release ships the full four-artifact
product `decision-release-bindings-in-lockstep` promises -- the Rust crate,
the CLI binary, the PyPI distribution, and the npm package -- rather than
narrowing the promise. The core and CLI crates are publishable; binding
crates are not. `release.yml` publishes crates.io (core before CLI) and PyPI
(trusted publishing of the qualified wheels) beside npm, and the npm facade
depends on its per-platform native packages and its WebAssembly package in
the same release graph. Narrowing to npm only (Branch B) was rejected: it
reopened an accepted ADR for sequencing reasons and stranded qualification
work already built.

## Consequences

Registry credentials are external setup this decision does not provision.
The release manifest's per-registry state makes a partial crates.io or PyPI
publication visible; closing its repair gap was left to `RB-7`/`RB-8` (#77,
#78). The decision authorized no version, tag, or publication.

## Folded records

| Original `decision_id` | Date | Issue | Decision | Full record |
| --- | --- | --- | --- | --- |
| `decision-publish-musl-node-addons` | 2026-09-19 | [#443](https://github.com/redact-secret/redact-secret/issues/443) | Publish the two already-qualified musl Node addon triples beside the six glibc targets; on Linux the loader selects `gnu` or `musl` by detected libc, never by probe-and-fall-back. The CLI keeps its musl exclusion. | [full record](https://github.com/redact-secret/redact-secret/blob/180335698aba54f71e3e994f1a90da6752f06396/docs/decisions/2026-09-19-publish-musl-node-addon-packages.md) |
