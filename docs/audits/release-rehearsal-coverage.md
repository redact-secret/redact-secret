# Release rehearsal coverage and the Reconcile Release exercise

Written on 2026-09-21 against `f67d866` (`main`) / this issue's working branch,
for issue [#530](https://github.com/redact-secret/redact-secret/issues/530),
"Rehearse the full release path, including the Reconcile Release repair
path", part of Epic [#526](https://github.com/redact-secret/redact-secret/issues/526).

**Authority:** this document records what the rehearsal path covers, what it
cannot cover, and what remains to be run live. It does not itself select a
version, create a tag, publish a package, or deploy, and it does not
authorize a `Reconcile Release` dispatch — that authorization is a separate,
explicit act under `AGENTS.md`'s "Release authority" section.

## Beta.5's three failure modes

Recorded by [#526](https://github.com/redact-secret/redact-secret/issues/526)
and the [beta.5 release readiness review](beta5-release-readiness-review.md):

1. **npm registry propagation delay reported as a publish failure.** Fixed by
   [#529](https://github.com/redact-secret/redact-secret/issues/529): every
   registry-state read now has a bounded, documented wait
   (`scripts/npm-registry-metadata.mjs`'s `waitForVisible`).
2. **A recovery run was needed** to carry the release to completion — the
   direct consequence of (1) and (3).
3. **The qualified Python wheel and the published Python wheel were not
   byte-identical.** Fixed by
   [#527](https://github.com/redact-secret/redact-secret/issues/527) (build
   every Python artifact exactly once per release run) and generalized by
   [#528](https://github.com/redact-secret/redact-secret/issues/528) (a
   digest carried through the manifest for every artifact class, not only
   Python).

## What `package-release-rehearsal.yml` rehearses now

Before this change, the workflow rehearsed exactly one thing: issue #141's
npm dependency cutover (`scripts/record-dependency-cutover-plan.py` plus
`scripts/publish-dependency-package.mjs --dry-run`). It never touched Python,
never ran the #527/#528 digest checks it was supposed to be exercising, and
its own header comment scoped it to that one cutover — it did not claim to
cover the beta.5 failure modes, and did not.

This change adds the pre-publish half of the #527/#528 fix to the rehearsal,
for every artifact family where that check is a pure local comparison against
`artifact-qualification`'s recorded inventory (no registry involved):

| Artifact family | Check added | Mirrors |
| --- | --- | --- |
| Node addon (`node-addon`) | `verify-python-digest.py --family node-addon --target <target>` on the assembled `.node` file | `release.yml`'s `publish-native-dependencies` |
| Browser WebAssembly (`browser`, `browser-common`) | `verify-python-digest.py --family browser --family browser-common` on the assembled `.js`/`.wasm` files | `release.yml`'s `publish-wasm-dependency` |
| Python wheels and source distribution (`python-wheel`, `python-sdist`) | `verify-python-digest.py` (default families) on every downloaded `.whl` and the `.tar.gz` | `release.yml`'s `publish-pypi` |

Each of these runs the identical script `release.yml` runs before its own
real publish step, against the identical qualification artifacts, with the
identical failure mode: a digest mismatch fails the step and names the file
and both digests. A `workflow_dispatch` of the rehearsal now exercises the
exact property that broke in beta.5, on demand, without publishing anything —
closing the "fixes from #527 and #528 validated on the rehearsal path" half
of this issue's first acceptance criterion for every artifact class where
that is possible without a real publish.

## Rehearsing at a throwaway unpublished version

Added for issue [#632](https://github.com/redact-secret/redact-secret/issues/632),
from item 1 of the [beta.6 release retrospective](beta6-release-retrospective.md).
Until then the rehearsal qualified whatever version its branch carried, and on
`main` that version is always already on every registry. Two beta.6 defects
therefore surfaced only on the freshly bumped RC and cost two extra
qualification cycles: [#607](https://github.com/redact-secret/redact-secret/pull/607)
(`cargo package` of `redact-secret-cli` alone cannot resolve its exact
`redact-secret` requirement before that version is on crates.io) and
[#608](https://github.com/redact-secret/redact-secret/pull/608) (npm dependency
digest checks passed fewer files than the inventory records).

**How it works.** `package-release-rehearsal.yml` starts with a `version` job.
It derives `<X.Y.Z>-beta.<run id>` from the branch version
(`scripts/rehearsal-version.py derive`) and proves npm (all eleven scoped
packages), crates.io (both crates), and PyPI answer **404** for it
(`check-unpublished`); any other answer, including a rate limit, fails the run.
Every job that builds, packs, or qualifies a version-bearing artifact then runs
`.github/actions/apply-rehearsal-version` right after its checkout, which
rewrites the lockstep set in that job's own working tree: the workspace
`Cargo.toml` (version and exact core requirement), `Cargo.lock`'s workspace
members, every lockstep JSON manifest and exact `@redact-secret/*` pin, both
npm lockfiles, the TypeScript `VERSION`, and the quickstart pins. Nothing is
committed or pushed, and nothing is published. `artifact-qualification.yml` and
`python-wheels.yml` take the version as an optional `rehearsal-version` input,
empty for `release.yml` and every push or pull request run, so those paths are
unchanged. The bump is uncommitted, so the inventory job's `cargo package`
passes `--allow-dirty` when (and only when) a rehearsal version is set.

**Why `-beta.<run id>` and not `-rehearsal.<run id>`.** The Python wheel
qualification (`scripts/qualify-python-wheel.py`) and the quickstart pin check
(`scripts/clean-install-doc.mjs`) accept only `X.Y.Z-beta.N`, and PEP 440 has no
spelling for a `-rehearsal` segment, so maturin could not build the wheel. A
run id is a number far above any published beta, and the registry probe checks
the claim instead of assuming it.

**What it covers now, before an RC exists:**

| Path | Runs at the unpublished version |
| --- | --- |
| Inventory crate packaging | `cargo package` of both crates against a core version crates.io does not have (#607) |
| Lockstep and `--locked` resolution | every manifest, exact pin, and lockfile agrees on the new version |
| Digest checks | node-addon, browser, Python, and the npm dependency packages are verified against an inventory recorded at that version (#527/#528/#608) |
| Wheel and quickstart | the PEP 440 spelling of the version in the wheel, and the pinned quickstart install lines |
| Unpublished-state probe | that no registry carries the version, so a probe that assumed absence is checked, not trusted |

It still cannot cover anything that needs a real publish (see the next
section), and it does not rehearse the RC-branch preparation itself
(changelog, release notes, `docs/releases/<version>/`).

**Evidence that it would have caught #607.** Run on 2026-09-23 against
`main` at `42d1fb0`, after `scripts/rehearsal-version.py apply --version
0.1.0-beta.12345678901` (a throwaway checkout, not committed):

```
$ cargo package --no-verify --locked --allow-dirty -p redact-secret-cli      # pre-#607 form
  failed to select a version for the requirement `redact-secret = "=0.1.0-beta.12345678901"`
  candidate versions found which didn't match: 0.1.0-beta.6, 0.1.0-beta.5, ...
  location searched: crates.io index
$ cargo package --no-verify --locked --allow-dirty -p redact-secret -p redact-secret-cli   # #607's fix
  Packaged 61 files ... Packaged 13 files ...
```

The same run passed `scripts/check-rust-workspace.py` and `cargo metadata
--locked` at the bumped version, so the bump itself is consistent. The pre-#607
form passes on `main` as it stands, which is the gap this closes.
`scripts/tests/test_rehearsal_version.py` guards the wiring: every building job
applies the version, `release.yml` never passes one, and the inventory packages
both crates together.

**#608 is a different case.** Its defect was the digest scope the qualified
inventory records against the files a package ships (`--suffix .node`, the
wasm `.d.ts` files). That scope does not depend on whether the version is
published, and the existing `scripts/tests/test_verify_python_digest.py`
cases from that fix already fail against the pre-#608 script. What the
throwaway version adds is that these checks now run against an inventory
recorded at a version that has never existed, which is the state `release.yml`
sees. This document does not claim a rehearsal at the throwaway version would
fail on pre-#608 code for a reason the version introduced.

## What the rehearsal cannot cover, and why

These are genuine gaps, not omissions to be silently worked around:

- **`redact-secret`/`redact-secret-cli` crate digest verification
  (`verify-crate-digest.py`).** Unlike the Python and Node/WASM checks, this
  compares the qualified digest against the checksum **crates.io itself
  reports** for the file it received (`GET
  /api/v1/crates/<crate>/<version>`). That comparison target does not exist
  until `cargo publish` has actually run. There is no pre-publish
  local-only form of this check to rehearse.
- **Every post-publish registry-state read** (npm `unpublished`/`published`
  probes, the PyPI `state` step, the crates.io `state` step). Same reason:
  these ask a registry about a version that, in a no-publication rehearsal,
  was never published, so there is nothing there to observe. The bounded-wait
  behavior these reads depend on (#529) is instead exercised deterministically
  by `scripts/tests/npm-registry-metadata.test.mjs`, including a simulated
  slow-registry case (`waitForVisible keeps polling through 404s until the
  version is visible ... a simulated slow-registry publish`) — unit-level
  coverage of the same property, run on every CI invocation rather than only
  on a manual rehearsal dispatch.
- **`verify-registry-install` (node and browser lanes).** This installs the
  real, published package from the real registry — no local tarball, no
  `overrides`. It exists specifically to prove something the qualification
  and rehearsal paths cannot: that what a consumer's package manager actually
  resolves matches what was qualified. By construction it requires a real
  publish to have happened first.
- **The annotated tag and the durable manifest's "published" state.** Both
  are written only after every publish job succeeds; a no-publication
  rehearsal has nothing to tag and nothing to observe as published.

None of this is a defect in the rehearsal — a rehearsal that faked these
would be worse than one that states plainly it cannot reach them (the same
reasoning #529 states for a registry gate: "a timeout that quietly passes
would be worse than the current behavior"). The residual exposure is that the
beta.5 wheel mismatch was a **pre-publish** defect and is now caught
pre-publish, on demand; the propagation-delay false negative and the crate
digest check are **post-publish** properties that can only be proven true by
a real release completing cleanly, which is what the next real release run
is for.

## Reconcile Release

`reconcile-guard.py`'s repair-window logic — accept a commit that is an
ancestor of the dispatched RC branch's current tip (or an explicit
`source_commit` override), reject one that has fallen out of that history —
is pure, deterministic, and already covered by unit tests independent of any
live dispatch:

- `scripts/tests/test_reconcile_guard.py::test_ancestor_commit_is_verified`
- `test_ancestor_check_still_accepts_the_exact_tip`
- `test_non_ancestor_commit_is_rejected` — the refusal case this issue's
  third acceptance criterion names
- `test_missing_record_is_rejected`, `test_mismatched_manifest_version_is_rejected`
- `test_source_commit_input_overrides_a_missing_manifest`,
  `test_source_commit_input_is_still_verified_as_an_ancestor`

What unit tests cannot substitute for is a **live, deliberate** dispatch of
`.github/workflows/reconcile-release.yml` against a real published version —
this issue's second and third acceptance criteria explicitly ask for the
workflow to have been run, not only its guard module. That has not been done
as part of this branch: dispatching a GitHub Actions workflow against
production release infrastructure is outside what this issue's implementation
work does on its own judgment, and `Reconcile Release` specifically requires
explicit authorization per `AGENTS.md` before every dispatch, repair or
refusal alike.

### Commands for the pending live exercise

Both use `rc/0.1.0-beta.5`, which is retained on the remote
(`refs/heads/rc/0.1.0-beta.5`) and matches the beta.5 release that needed the
recovery run. `gh run list --workflow=release.yml --branch rc/0.1.0-beta.5`
finds the original Release run if `source_run` is needed (only when that
run's manifest upload itself failed).

**1. Repair-without-republish, against a known-good published version.**
`dry_run: true` computes and prints every artifact's reconciliation plan
(skip, publish, or block) without publishing or tagging anything:

```
gh workflow run reconcile-release.yml \
  --ref rc/0.1.0-beta.5 \
  -f version=0.1.0-beta.5 \
  -f dry_run=true
```

Expect every artifact to plan `skip` (already published at this version,
matching the manifest) — a `publish` entry here would mean beta.5 has a gap
this issue did not anticipate, and is itself a finding worth recording.

**2. The refusal case — a commit outside the RC branch's history.** Pick any
commit that is not an ancestor of `rc/0.1.0-beta.5` (for example, a commit
that exists only on this issue's own branch) and pass it as an explicit
override:

```
gh workflow run reconcile-release.yml \
  --ref rc/0.1.0-beta.5 \
  -f version=0.1.0-beta.5 \
  -f source_commit=<a commit not reachable from rc/0.1.0-beta.5> \
  -f dry_run=true
```

Expect the `reconcile-guard.py` step to fail the run with `<source_commit> is
not an ancestor of rc/0.1.0-beta.5` and no reconciliation plan to be computed
— proving the guard fails closed live, not only under `unittest`.

Both commands require whoever runs them to be authorized for the `release`
GitHub Environment this workflow deploys against, and both should be recorded
(run URL, inputs, and outcome) once run, per this issue's second acceptance
criterion.

## Mapping to #530's acceptance criteria

| Criterion | Status |
| --- | --- |
| The rehearsal covers the three beta.5 failure modes, and #527/#528/#529's fixes are validated on it | Partially closed by this change: the #527/#528 digest-check property is now rehearsed for every artifact class where that is possible without a real publish (node-addon, browser/browser-common, python-wheel/python-sdist). The crate digest check and the propagation-delay behavior remain provably out of the no-publication rehearsal's reach for the reasons stated above; #529's propagation fix is covered instead at the unit-test level. |
| `Reconcile Release` run at least once deliberately, with authorization, recorded | Not done on this branch — pending explicit authorization; commands above. |
| Reconcile's refusal behavior verified live (not just unit-tested) | Not done on this branch — pending explicit authorization; commands above. Deterministic coverage of the same logic already exists (`test_non_ancestor_commit_is_rejected`). |
| Gaps the rehearsal cannot cover are written down | Done — this document, "What the rehearsal cannot cover, and why". |
| Nothing in this work selects a version, tags, publishes, or deploys; any reconcile run requires explicit authorization | Satisfied — this branch adds only local, no-registry checks to a workflow that was already publish-free, and performs no live dispatch of any kind. |
