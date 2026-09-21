# Support-matrix drift gate

Issue [#511](https://github.com/redact-secret/redact-secret/issues/511),
A10; part of [#500](https://github.com/redact-secret/redact-secret/issues/500).
Downstream of [#510's support matrix](support-matrix.md) and
[redact-secret-benchmarks#51](https://github.com/redact-secret/redact-secret-benchmarks/issues/51),
which produced the diff logic this repository ports. Decision record:
[`decision-gate-releases-on-support-matrix-drift`](decisions/2026-09-21-gate-releases-on-support-matrix-drift.md).

## What it does

`scripts/check-support-matrix-drift.py` compares the pinned
`benchmarks/support-matrix.json` (the candidate) against the most recent
prior release tag's copy of that same file (the baseline, read straight out
of git history) and reports four kinds of drift:

- **regressions** -- a family that carried `stable` in the baseline and does
  not in the candidate. Fails qualification by default.
- **improvements** -- a family reaching `stable`, with the evidence bundle
  that earned it.
- **newAndUnclassified** -- a family the baseline has no entry for at all.
- **staleProviderProvenance** -- a family whose status did not cross the
  `stable` boundary but whose `providerSource` differs between the two
  matrices.

Only regressions block. Everything else is informational.

## Overriding a regression

Add an entry to `benchmarks/support-matrix-drift-acknowledgements.json`,
keyed by `sha256(f"{family}|{baselineStatus}|{candidateStatus}|{reason}")[:16]`
(printed in the gate's own error output), carrying at least a `rationale`:

```json
{
  "<fingerprint>": {
    "rationale": "why this regression is acceptable for this release"
  }
}
```

The fingerprint includes the regression's `reason`, so a new reason for the
same family is a new fingerprint -- an old acknowledgement never silently
covers it.

## Running it locally

```sh
python3 -B scripts/check-support-matrix-drift.py \
  --baseline <(git show v0.1.0-beta.5:benchmarks/support-matrix.json) \
  --candidate benchmarks/support-matrix.json \
  --out support-matrix-drift.json
```

`--candidate` defaults to the pinned copy. A candidate whose
`sourceReport.dirty` is `true` is rejected by default (issue #508); pass
`--allow-dirty-candidate` for a local dry run only.

## Determinism and no network access

Both inputs are local files, one already committed and the other read from
git history; nothing here fetches, clones, or invokes
`redact-secret-benchmarks`. `.github/workflows/artifact-qualification.yml`'s
`support-matrix-drift` job runs this for every full qualification run and
uploads the record; `release.yml`'s `record-manifest` job embeds it in the
durable release manifest under `support_matrix_drift`. Release authority is
unchanged: this gate informs the decision, it does not grant authority to
tag, publish, or release.
