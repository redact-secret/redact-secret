---
decision_id: decision-project-support-matrix-into-docs-and-release-notes
status: accepted
scope: workspace
title: Project the generated support matrix into docs and release notes via a pinned copy
decided_at: 2026-09-21
---

# Project the generated support matrix into docs and release notes via a pinned copy

## Decision

[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
generates `support-matrix.json` (that repository's #509/A8): one evidence-derived
status -- `stable` / `provisional` / `pending` / `unsupported` -- per provider x
credential-family taxonomy entry. This repository never re-derives or hand-adjusts
a status; it only projects that artifact.

That artifact is a gitignored build output in the benchmark repository (it
requires a full evaluation run: `npm run eval:classify` against the pinned
scanner set, then `npm run eval:matrix`) and is never committed there. This
repository keeps its own pinned, committed copy, `benchmarks/support-matrix.json`,
plus a vendored copy of its schema, `benchmarks/support-matrix-schema.json` --
the same pattern `benchmarks/pin-manifest.json`
(`decision-govern-benchmark-regression-promotion`,
`scripts/check-benchmark-pins.py`) already established for cross-repository
generated evidence. `scripts/generate-support-matrix-docs.py` renders
`docs/support-matrix.md` and a `README.md` section from that one pinned file,
so a status change reaches every surface by regenerating, never by editing
prose. `npm run support-matrix:check` (wired into `npm run ci`) fails the
build if either is out of date.

An alternative -- fetching the matrix over the network at doc-build or CI time
from a deployed benchmark site -- was rejected: nothing in
`redact-secret-benchmarks` publishes a stable, versioned URL for it today (its
own `public/results/*.json` is also gitignored, produced fresh per deploy),
and a live fetch would make this repository's `npm run ci` network-dependent
and non-reproducible from a given commit, unlike every other generated-and-checked
document here (`docs/coverage/*`, `benchmarks/pin-manifest.json`).

## Scope split

This issue (#510, A9) covers only README/docs and release notes, in this
repository. The benchmark UI projection is
[`redact-secret-benchmarks`#50](https://github.com/redact-secret/redact-secret-benchmarks/issues/50)
(already merged), which reads the live matrix directly inside that repository
and needs no pinned copy -- its own `scripts/check-support-ui.mjs` gates the
UI against the schema's status vocabulary using a synthetic probe matrix built
from the checked-in taxonomy, not against a specific generated matrix's
content. `scripts/tests/test_generate_support_matrix_docs.py` mirrors that
probe-matrix technique for this repository's docs. Qualification-side matrix
drift (whether a release may proceed against a stale or regressed matrix) is
out of scope here and belongs to #511 (A10).

## Refreshing the pin

Regenerate `benchmarks/support-matrix.json` from a `redact-secret-benchmarks`
checkout of `main` (`npm ci && npm run eval:classify && npm run eval:matrix`),
copy `results-output/support-matrix.json` over the pinned copy, then run
`python3 -B scripts/generate-support-matrix-docs.py`. Nothing here checks that
the pin is *current* against that repository's `main` (unlike
`pin-manifest.json`'s `pins.sourceRevision` ancestry check) -- only that the
pinned copy and the generated docs agree with each other. Ancestry drift is
deferred to whichever of #510's follow-ups or #511 takes it up; until then, a
stale pin is a silent gap the same way `pin-manifest.json`'s pinned
`0.1.0-beta.4` revision already is.

## Consequences

`docs/support-matrix.md` and README's support-status section can never
individually drift from `benchmarks/support-matrix.json`, or from each other,
without failing `npm run ci`. Release notes gain a generated fragment
(`--release-note`) instead of a hand-written status claim, documented in
[the release runbook](../releasing.md#close-out). The pin can still go stale
relative to `redact-secret-benchmarks`' actual `main`; that is an accepted,
visible gap, not a silent one -- `docs/support-matrix.md` records the pinned
source revision and links to it.
