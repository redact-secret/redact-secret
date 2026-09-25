# Vendored benchmark pins

This directory carries immutable inputs copied from or identifying
[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks).
Nothing here is hand-edited, and nothing at runtime reads this
directory; it exists so the offline `npm run ci` path can reconcile the
regression ledger without a network, and so releases can be qualified against
a support matrix that was produced by a recorded benchmark run.

| File | Source | Covered by | Re-pinned by |
| --- | --- | --- | --- |
| `pin-source.json` | Product-owned record of the exact benchmark commit | `scripts/check-benchmark-pins.py` check 6: a development check requires it on benchmarks `develop`; release qualification requires it on benchmarks `main`. | `npm run benchmark-pins:sync -- --ref <40-sha>` |
| `pin-manifest.json` | `benchmarks/pin-manifest.json` at `pin-source.json`'s immutable commit, written by `scripts/generate-pin-manifest.mjs` | `scripts/check-benchmark-pins.py` check 6 (live, `benchmark-pin-drift` job): its `revision` must be an ancestor of the pinned commit and must already contain the manifest, and the content must be byte-identical to the file at that commit. Checks 1, 2, and 7 (offline, `npm run ci`) reconcile the ledger and the pinned product version against it. | `npm run benchmark-pins:sync -- --ref <40-sha>` |
| `support-matrix-schema.json` | `schemas/support-matrix-v1.json` at immutable beta.8 contract commit [`cfaeac4d83a4c98cffd77328d3416eb920a7d25b`](https://github.com/redact-secret/redact-secret-benchmarks/blob/cfaeac4d83a4c98cffd77328d3416eb920a7d25b/schemas/support-matrix-v1.json) | `scripts/check-benchmark-pins.py` check 5 (live): byte-identical to that pinned benchmark commit. | `npm run benchmark-pins:sync` |
| `support-matrix.json` | a gitignored `npm run eval:classify && npm run eval:matrix` output, not a committed file | `npm run support-matrix:check` (docs generated from it must not drift) and the release gate in `scripts/check-support-matrix-drift.py`. Whether it is current against benchmarks `main` is not checked; there is no committed upstream file to compare with. | Regenerate in a benchmarks checkout and copy the result here (`scripts/generate-support-matrix-docs.py` docstring). |
| `support-matrix-drift-acknowledgements.json` | none; this repository owns it | `scripts/check-support-matrix-drift.py` | Release qualification, per [`decision-gate-releases-on-support-matrix-drift`](../docs/decisions/2026-09-21-gate-releases-on-support-matrix-drift.md). |

`support-matrix-drift-schema.json` was a third vendored file; issue #605
removed it rather than adding a check, since nothing here read it.

## What the manifest is pinned to

`pin-source.json` is the authoritative immutable benchmark snapshot.
`pin-manifest.json` additionally records the benchmarks commit
`generate-pin-manifest.mjs` ran at, and `pins.sourceRevision` /
`pins.redactSecretVersion` are the product commit and published version that
run measured. The copy stored *at* `revision` in the benchmarks repository is
always the previous generation, because the generator records `HEAD` and the
result is committed afterwards, so the check compares content against the
file at `pin-source.json`'s later exact commit, not against the file at `revision`.

## Who re-pins, and when

The product change that needs a benchmark snapshot chooses its exact commit.
Development CI accepts a commit on benchmarks `develop`; the Release
workflow raises the same check to benchmarks `main`, making snapshot promotion
an explicit production boundary. The support-matrix schema remains pinned to
the separate immutable benchmark commit whose contract this repository consumes.
Refresh the declared sources with one command in this repository:

```bash
npm run benchmark-pins:sync -- --ref <40-sha>  # needs `gh` authenticated
npm run benchmark-pins:check  # offline reconciliation, same as `npm run ci`
```

If `benchmark-pins:check` then reports a ledger record whose corpus hash is
no longer in the manifest, that record's `benchmarkRevalidation` gate is still
open and the benchmarks corpus it will be measured against has changed:
re-pin the record's `corpusHashes` to the family's current hash and say so in
its `note`. Records whose gate has passed keep the hash they were measured
against; they are anchored by `benchmarkCommit` instead.

Issue #637 is the incident this guards against: the manifest sat at
`0.1.0-beta.3` while `main` shipped `0.1.0-beta.6`, and named a benchmarks
revision at which the manifest did not exist, with every check green.
