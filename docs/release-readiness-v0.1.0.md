# v0.1.0 release-readiness checklist

[Documentation home](README.md) · [Release runbook](releasing.md)

This is the reviewable readiness checklist for
[issue #531](https://github.com/redact-secret/redact-secret/issues/531),
closing Epic [#526](https://github.com/redact-secret/redact-secret/issues/526)
("Release engineering debt — build once, qualify the exact artifact, publish
the exact artifact"). It exists so a future stable-release decision is made
against stated, checkable criteria instead of a feeling that the beta line
went well enough. The beta.5 failures and fixes that motivate each line are
recorded in the
[beta.5 release retrospective](audits/beta5-release-retrospective.md).

**This checklist does not select a version, create a tag, authorize
publication, or deploy.** It does not itself constitute release approval.
Follow [release authority](../AGENTS.md#release-authority) and the
[release runbook](releasing.md) for those decisions; this page only states
what "release engineering is ready for v0.1.0 stable" means, evaluated
against a real run.

## How to read this table

Each row states a criterion in a form that can be checked against a specific
release run's artifacts and logs — a command to run, a manifest field to
inspect, or a workflow-run history to query — not a subjective judgment call.
The **Status as of beta.5** column is evidence, current as of this writing
(2026-09-21); it is not a release decision, and a later run must be checked
again in its own right rather than assumed to still match.

| # | Criterion | How to evaluate it against a run | Status as of beta.5 |
| --- | --- | --- | --- |
| 1 | Build-once / qualify-exact / publish-exact holds for every artifact class. | For every entry in the release manifest's `artifact_digests` with `comparable: true`, the `built`, `qualified`, and `published` digests are identical. `scripts/release-manifest.py` already fails the run loudly, naming the artifact, file, and both digests, if any comparable entry disagrees — so "met" means `record-manifest` exits `0` with no digest-mismatch error. Entries the ecosystem re-packs before upload (`npm publish`'s tarball) must instead carry `comparable: false` with a non-empty `note`, not a silently skipped field. | **Met**, by construction, since [#527](https://github.com/redact-secret/redact-secret/issues/527)/[#528](https://github.com/redact-secret/redact-secret/issues/528): `release.yml` now consumes `artifact-qualification.yml`'s single Python build instead of invoking `python-wheels.yml` a second time, and every artifact family (npm, WASM, crate, Python) records the three-stage digest. Not yet observed on a real `release.yml` run since the fix landed — beta.5 predates it. |
| 2 | Artifact identity is provable from the manifest, not inferred from workflow topology. | `python3 -B scripts/validate-release-records.py --version <version>` passes, and the checked-in `docs/releases/<version>/manifest.json` carries a non-null `artifact_digests` entry for every identity in `artifact_set` — comparable-with-matching-digests or explicitly marked incomparable with a reason, never absent. | **Structurally met** by [#528](https://github.com/redact-secret/redact-secret/issues/528)'s manifest schema; not yet exercised end-to-end on a published version, since beta.5's manifest predates the `artifact_digests` field. The next real release is the first to produce a manifest this criterion can be checked against directly. |
| 3 | Registry-state verification produces no false negatives. | `scripts/tests/npm-registry-metadata.test.mjs` (bounded-wait behavior, including a simulated slow-registry case) passes for the frozen revision, and no step in the release run reports a failure for a version that an independent, immutable-endpoint registry query shows had in fact already published. | **Fixed** by [#529](https://github.com/redact-secret/redact-secret/issues/529): every registry-state read now has a bounded, documented wait (`waitForVisible`) instead of a single point-in-time check. Covered by CI unit tests; not yet proven on a real release run, since beta.5's propagation-delay failures predate the fix. |
| 4 | The release completes without a recovery run. | `gh run list --workflow=release.yml --branch rc/<version>` shows exactly one run for that version reaching `tag-release` successfully, and `gh run list --workflow=reconcile-release.yml` shows zero dispatches against that version. | **Not yet demonstrated.** Beta.5 needed three `reconcile-release.yml` dispatches (one dry run, two real recovery runs) before the tag was created. This criterion is what criteria 1 and 3 are expected to jointly produce on the next real release, but it can only be confirmed by that release actually happening cleanly. |
| 5 | The Reconcile Release path has been exercised deliberately, with authorization, not only used under pressure during a real recovery. | At least one authorized `reconcile-release.yml` dispatch with `dry_run=true` against a known-good published version plans `skip` for every artifact, **and** at least one dispatch naming a `source_commit` outside the matching RC branch's history is rejected by `reconcile-guard.py`'s ancestor check. Both are recorded (run URL, inputs, outcome). | **Not met.** Every `reconcile-release.yml` dispatch on record (beta.2, beta.3, and beta.5's three dispatches) was a real recovery against an actual partial-publication failure, never a deliberate rehearsal or a deliberate refusal-path exercise. [#530](https://github.com/redact-secret/redact-secret/issues/530) wrote the exact pending commands in [release rehearsal coverage](audits/release-rehearsal-coverage.md#reconcile-release); running them needs separate explicit authorization under [release authority](../AGENTS.md#release-authority), which has not been given. |
| 6 | A durable manifest is written for every release run, including failed runs. | The workflow run's artifact list contains `release-manifest-<version>` regardless of the run's overall conclusion — checkable directly on any historical run, not only a hypothetical future one. | **Already met, historically.** `record-manifest` runs with `if: always()`; beta.5's original partial run ([35528414802](https://github.com/redact-secret/redact-secret/actions/runs/35528414802)) produced a manifest despite the false-negative failures in that same run, which is what made the recovery run possible at all. No further change needed; this criterion is about not regressing it. |

## Reading the table honestly

Four of six criteria (1, 2, 3, 6) are **structurally fixed** — the code and
workflow changes exist and are covered by deterministic tests — but have not
yet been proven true end-to-end on a real, live release, because every fix
landed after beta.5 published. That is expected: proving them requires the
next real release to actually happen. Criteria 4 and 5 are **not met** and
cannot be marked met by inspection; criterion 4 requires a clean release run
to occur, and criterion 5 requires a deliberate, authorized exercise that has
not been requested.

Treating "the code changed" as equivalent to "the criterion holds" for 1, 2,
3, or 6 would be exactly the "feeling that things went well enough" this
checklist exists to replace. The honest reading is: release engineering is
better positioned for v0.1.0 than it was for beta.5, but this checklist is
not yet fully green, and nothing here should be read as saying it is.

## Version and release boundary

This checklist describes readiness criteria as of the source revision this
page is checked in at. Re-evaluate every row against the actual candidate
revision and release run under review; do not carry a prior version's
"met" forward without checking it again. This page does not select a
version, create a tag, authorize publication, or deploy — see
[release authority](../AGENTS.md#release-authority) and the
[release runbook](releasing.md) for those decisions.
