# v0.1.0 release-readiness checklist

[Documentation home](../README.md) · [Release runbook](../releasing.md)

This is the reviewable readiness checklist for
[issue #531](https://github.com/redact-secret/redact-secret/issues/531),
closing Epic [#526](https://github.com/redact-secret/redact-secret/issues/526)
("Release engineering debt — build once, qualify the exact artifact, publish
the exact artifact"). It exists so a future stable-release decision is made
against stated, checkable criteria instead of a feeling that the beta line
went well enough. The beta.5 failures and fixes that motivate each line are
recorded in the
[beta.5 release retrospective](../audits/beta5-release-retrospective.md).

**This checklist is evidence, not release approval.** Follow the
[release authority](../../AGENTS.md#release-authority) and the
[release runbook](../releasing.md) for those decisions; this page only states
what "release engineering is ready for v0.1.0 stable" means, evaluated
against a real run.

## How to read this table

Each row states a criterion in a form that can be checked against a specific
release run's artifacts and logs — a command to run, a manifest field to
inspect, or a workflow-run history to query — not a subjective judgment call.
The **Status as of beta.5** column is evidence, current as of this writing
(2026-09-21); it is not a release decision, and a later run must be checked
again in its own right rather than assumed to still match.

The status column below was re-evaluated on 2026-10-03 against the frozen
Beta.13 candidate `401158d09a677b110fa60209256ba184b1f08f8f` (issue
[#1069](https://github.com/redact-secret/redact-secret/issues/1069)); the rows
are read as the release gates for `0.1.0-beta.13`. Every row says what was
observed, on which run, and what only a real Release run can prove. The
candidate's product source is identical to `0027da0` (the revision the
`0.1.0-beta.13` preparation merged at); only documentation differs. See the
[Beta.13 readiness record](../audits/evidence/1071/README.md).

| # | Criterion | How to evaluate it against a run | Status on the Beta.13 candidate (2026-10-03) |
| --- | --- | --- | --- |
| 1 | Build-once / qualify-exact / publish-exact holds for every artifact class. | For every entry in the release manifest's `artifact_digests` with `comparable: true`, the `built`, `qualified`, and `published` digests are identical. `scripts/release-manifest.py` already fails the run loudly, naming the artifact, file, and both digests, if any comparable entry disagrees — so "met" means `record-manifest` exits `0` with no digest-mismatch error. Entries the ecosystem re-packs before upload (`npm publish`'s tarball) must instead carry `comparable: false` with a non-empty `note`, not a silently skipped field. | **Structurally met; live observation pending the Beta.13 Release run.** Single Python build consumed by `release.yml` since [#527](https://github.com/redact-secret/redact-secret/issues/527)/[#528](https://github.com/redact-secret/redact-secret/issues/528); [Artifact qualification run 37093118224](https://github.com/redact-secret/redact-secret/actions/runs/37093118224) and [Package Release Rehearsal run 37087510742](https://github.com/redact-secret/redact-secret/actions/runs/37087510742) (on `0027da0`, identical product source) are green, and the beta.11 Release run succeeded end to end with the three-stage digests. The `record-manifest` exit on a real Beta.13 run is proven only by that run: a named condition, not a waiver. |
| 2 | Artifact identity is provable from the manifest, not inferred from workflow topology. | `python3 -B scripts/validate-release-records.py --version <version>` passes, and the checked-in `docs/releases/<version>/manifest.json` carries a non-null `artifact_digests` entry for every identity in `artifact_set` — comparable-with-matching-digests or explicitly marked incomparable with a reason, never absent. | **Structurally met; live observation pending the Beta.13 Release run.** `scripts/validate-release-records.py` and the checked-in `artifact_digests` schema are exercised by CI on this candidate, and published manifests since beta.5 carry the field (beta.8 to beta.12 manifests are reconstructed, see [release status](status.md)). A manifest produced directly by a Release run, not reconstructed, is proven only by the Beta.13 Release run. |
| 3 | Registry-state verification produces no false negatives. | `scripts/tests/npm-registry-metadata.test.mjs` (bounded-wait behavior, including a simulated slow-registry case) passes for the frozen revision, and no step in the release run reports a failure for a version that an independent, immutable-endpoint registry query shows had in fact already published. | **Fixed; live observation pending the Beta.13 Release run.** Bounded `waitForVisible` waits ([#529](https://github.com/redact-secret/redact-secret/issues/529)) are covered by the unit tests in CI on this candidate, and the beta.11 Release run saw one propagation-lag false negative that a Reconcile dry run confirmed as already published, which is the behavior this row is about. **Observed on the Beta.13 run: not met.** Absence of any false negative on the Beta.13 run was to be proven only by that run, and it was not: the run's registry-state snapshots for `@redact-secret/node-darwin-x64` and `@redact-secret/node-win32-x64-msvc` read `unpublished` while their publish jobs and the live registry say published, and the manifest's published digest was empty for those two packages and three PyPI files (propagation lag; no failure, no recovery; see the [record](0.1.0-beta.13/README.md#publication)). |
| 4 | The release completes without a recovery run. | `gh run list --workflow=release.yml --branch rc/<version>` shows exactly one run for that version reaching `tag-release` successfully, and `gh run list --workflow=reconcile-release.yml` shows zero dispatches against that version. | **Met on the Beta.13 Release run** ([37100486438](https://github.com/redact-secret/redact-secret/actions/runs/37100486438), 2026-10-03): the single Release dispatch for `0.1.0-beta.13` succeeded through `tag-release` and `record-manifest`, and no `reconcile-release.yml` was dispatched against that version ([record](0.1.0-beta.13/README.md)). Before that run, this row read: A clean run reaching `tag-release` with zero `reconcile-release.yml` dispatches for `0.1.0-beta.13`. Beta.12 is a counter-example, now explained and fixed: its first Release run ([36841178285](https://github.com/redact-secret/redact-secret/actions/runs/36841178285)) failed the `CI / Benchmark pin drift (commit ancestry...)` gate, and its second ([36844232498](https://github.com/redact-secret/redact-secret/actions/runs/36844232498)) failed `Record release manifest` with `python3: Argument list too long` ([#1115](https://github.com/redact-secret/redact-secret/issues/1115), fixed on `main` in `f90ce6bb`). `npm run benchmark-pins:check:ancestry` reports 0 errors on this candidate. This row is a named condition of the Beta.13 Release, not a waiver and not something inspection can mark met. |
| 5 | The Reconcile Release path has been exercised deliberately, with authorization, not only used under pressure during a real recovery. | At least one authorized `reconcile-release.yml` dispatch with `dry_run=true` against a known-good published version plans `skip` for every artifact, **and** at least one dispatch naming a `source_commit` outside the matching RC branch's history is rejected by `reconcile-guard.py`'s ancestor check. Both are recorded (run URL, inputs, outcome). | **Met.** Authorized dispatches on this candidate, both with `--ref main`: the dry run ([run 37093975420](https://github.com/redact-secret/redact-secret/actions/runs/37093975420), version `0.1.0-beta.12`, `source_commit` `4227160c` with `source_run` 36844232498) succeeded and every npm package reported "already published and matches this revision's content; nothing to publish"; the refusal ([run 37095965449](https://github.com/redact-secret/redact-secret/actions/runs/37095965449), a non-ancestor `source_commit` `6777f580`) failed closed with `6777f580dfed8e4a6895ccf6ce1538d731331fad is not an ancestor of 401158d09a677b110fa60209256ba184b1f08f8f` and no plan computed. Commands: [release rehearsal coverage](../audits/release-rehearsal-coverage.md#commands-for-the-live-exercise-as-run). |
| 6 | A durable manifest is written for every release run, including failed runs. | The workflow run's artifact list contains `release-manifest-<version>` regardless of the run's overall conclusion — checkable directly on any historical run, not only a hypothetical future one. | **Met, historically and by the fixes since.** `record-manifest` runs with `if: always()`; beta.5's original run produced a manifest despite its failures. Beta.12 is the one run that lost its manifest (`Argument list too long`, [#1115](https://github.com/redact-secret/redact-secret/issues/1115)); the fix is on `main` and the manifest was rebuilt from preserved inputs. Whether Beta.13 writes a manifest directly is proven only by its Release run. |

## Reading the table honestly

Other release gates, checked on the same candidate on 2026-10-03: Artifact
qualification, SAST, Scorecard and the Package Release Rehearsal are green (the
rehearsal on the identical-source `0027da0`); `scripts/verify-release-governance.py`
exits 0 (the `release` environment exists with required reviewer
`milocosmopolitan`, administrators cannot bypass it, and `main` is protected
with its required checks).

Rows 4 and 5 are met. Rows 1, 2 and 6 held on the Beta.13 run (a manifest was
uploaded, every comparable digest agreed across stages, and the record
validates); row 3 was not met, because two registry-state snapshots were
false negatives. Historically, rows 1-3 and 6 were structurally fixed and
covered by green deterministic gates, and row 4 was not yet demonstrated. Rows 1-4 and the
manifest part of row 6 can only be proven by a real Release run, which this
checklist does not authorize: they are **named conditions of the
`0.1.0-beta.13` Release, discharged by that run**, not waivers. If that run
needs a Reconcile dispatch, row 4 stays unmet and says so.

Treating "the code changed" as equivalent to "the criterion holds" would be
exactly the "feeling that things went well enough" this checklist exists to
replace; the table above keeps those apart.

## Version and release boundary

This checklist describes readiness criteria as of the source revision this
page is checked in at. Re-evaluate every row against the actual candidate
revision and release run under review; do not carry a prior version's
"met" forward without checking it again. This page does not select a
version, create a tag, authorize publication, or deploy — see
[release authority](../../AGENTS.md#release-authority) and the
[release runbook](../releasing.md) for those decisions.
