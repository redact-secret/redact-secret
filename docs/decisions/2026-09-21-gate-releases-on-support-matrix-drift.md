---
decision_id: decision-gate-releases-on-support-matrix-drift
status: accepted
scope: workspace
title: Gate release qualification on support-matrix drift, with recorded acknowledgement to override
decided_at: 2026-09-21
spec: evidence-and-gates
aliases: decision-project-support-matrix-into-docs-and-release-notes
---

# Gate release qualification on support-matrix drift, with recorded acknowledgement to override

This record is the representative ADR for the support-matrix cluster (issue
[#599](https://github.com/redact-secret/redact-secret/issues/599), DS6c, under
epic [#591](https://github.com/redact-secret/redact-secret/issues/591)): the
generated support matrix reaches this repository only as a pinned, committed
copy, and every surface that consumes it -- docs, release notes, and release
qualification -- is checked offline against that one pin.
[Folded records](#folded-records) lists the decision merged into this one
under
[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)'s
Merge grade; its `decision_id` is preserved in this record's `aliases:`
field above, and its full original text stays reachable at its permalink.
The current rules live in
[`docs/specs/evidence-and-gates.md`](../specs/evidence-and-gates.md).

## Decision

Issue #510's ADR (`decision-project-support-matrix-into-docs-and-release-notes`)
explicitly scoped qualification-side matrix drift out of itself and pointed
to this issue (#511, A10). This repository never checks out or invokes
`redact-secret-benchmarks` from CI -- cross-repository generated evidence
always flows through a pinned, committed copy, the same pattern
`benchmarks/pin-manifest.json` established. `scripts/check-support-matrix-drift.py`
follows that precedent: it ports `buildSupportMatrixDrift`
(`redact-secret-benchmarks`' `benchmarks/support/drift.ts`, issue #51 there)
into pure Python and compares two already-pinned matrices --
`benchmarks/support-matrix.json` as the candidate, and the most recent prior
release tag's copy of that same file as the baseline, read straight out of
git history. Both inputs are files this repository already carries;
nothing here fetches, clones, or resolves anything over the network.

Of the four kinds of drift:

- a **regression** (a family that carried `stable` in the baseline and does
  not in the candidate) fails qualification by default. Overriding it
  requires an entry in `benchmarks/support-matrix-drift-acknowledgements.json`,
  keyed by a content fingerprint of `family|baselineStatus|candidateStatus|reason`
  -- the same disposition pattern `scripts/run-sast.py` uses for
  `sast/baseline.json`, chosen deliberately over inventing a second
  mechanism. Fingerprinting on `reason` too means a *new* reason for the
  same family's regression is never silently covered by an old
  acknowledgement of a different one.
- an **improvement** (a family reaching `stable`) never blocks; its
  evidence bundle is carried in the record for review, already backed by
  whatever #503's stable criteria required to earn it.
- a **newAndUnclassified** family never blocks either -- the matrix schema
  already requires every family to carry a status, so "arrives without a
  status" cannot reach this gate at all.
- **staleProviderProvenance** is a warning only, matching the issue's own
  text.

The `support-matrix-drift` job in `.github/workflows/artifact-qualification.yml`
runs this gate for every full qualification run, writing
`support-matrix-drift.json` before evaluating whether any regression is
unacknowledged -- the same "write the record before failing the check" order
`release-manifest.py`'s digest comparison already established for issue
#528, so a run this gate fails still leaves a durable artifact. `release.yml`'s
`record-manifest` job downloads that artifact and passes it to
`scripts/release-manifest.py --support-matrix-drift`, which embeds it in the
durable release manifest as a seventh, optional field, `support_matrix_drift`,
without re-deciding the regression/acknowledgement question -- that decision
already happened, once, at qualification time.

A candidate whose `sourceReport.dirty` is `true` is rejected by default:
issue #508 established that candidate-derived and published-derived
evidence answer different questions, and an uncommitted benchmarks checkout
is not reproducible published-artifact evidence. `--allow-dirty-candidate`
exists only for a local dry run during RC prep.

## No previous release tag, or no baseline yet

No previous release tag carrying `benchmarks/support-matrix.json` -- true
until the first release after issue #510 introduced that file, and true
again for any repository that adopts this pattern before its own first
release -- is treated as "nothing to regress from yet", not a gate failure:
the qualification job records an empty `{}` drift record and passes. This
is an accepted, visible bootstrap gap, not a silent one: the recorded
manifest's `support_matrix_drift` field is empty exactly when this
happened, and stays that way for exactly one release.

## Alternatives considered

Checking out `redact-secret-benchmarks` in CI to run its own
`support-matrix-drift.ts` CLI was rejected for the same reason #510's ADR
rejected fetching the matrix live: it would make `artifact-qualification.yml`
network-dependent and non-reproducible from a given commit, unlike every
other generated-and-checked evidence in this repository. Porting the pure
diff function into Python, against files already pinned here, keeps the
gate inside this repository's existing deterministic, offline boundary
(issue #511 acceptance criterion 3).

Re-deciding the regression/acknowledgement question a second time inside
`release-manifest.py` -- mirroring how `verify-crate-digest.py` and
`release-manifest.py` independently measure the same digest for issue #528
-- was considered and rejected: that double-check exists there because two
genuinely independent measurements exist (publish-time and record-time).
Here there is only one measurement, so a second check would just
re-validate the same JSON blob's shape, which `normalize_support_matrix_drift`
already does, without adding real defense.

## Consequences

A release candidate that regresses a family out of `stable` cannot qualify
without a human adding a rationale to
`benchmarks/support-matrix-drift-acknowledgements.json` first, and that
acknowledgement stops covering the family the moment its regression reason
changes. Release authority is unchanged (acceptance criterion 5): this gate
informs `release.yml`'s qualification step; it does not itself grant
authority to tag, publish, or release.

## Folded records

Each row is a decision merged into this one (Merge grade). The `decision_id`
column is preserved verbatim in this record's `aliases:` frontmatter field so
an old reference still resolves; the permalink is the folded record's last
text on `main` before this merge, at
`ed80bc8aaa5058e11bf8b6fc43214b0194de886a`.

| Original `decision_id` | Date | Issue | Decision | Full record |
| --- | --- | --- | --- | --- |
| `decision-project-support-matrix-into-docs-and-release-notes` | 2026-09-21 | [#510](https://github.com/redact-secret/redact-secret/issues/510) | Keep a pinned copy of the benchmarks-generated `support-matrix.json` and its schema, render `docs/support-matrix.md`, the README section, and a release-note fragment from it, and fail `npm run ci` on drift; never fetch it live. | [full record](https://github.com/redact-secret/redact-secret/blob/ed80bc8aaa5058e11bf8b6fc43214b0194de886a/docs/decisions/2026-09-21-project-the-support-matrix-into-docs-and-release-notes.md) |
