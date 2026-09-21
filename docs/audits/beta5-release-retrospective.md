# 0.1.0-beta.5 release retrospective

Written on 2026-09-21 against `main`, for issue
[#531](https://github.com/redact-secret/redact-secret/issues/531), part of
Epic [#526](https://github.com/redact-secret/redact-secret/issues/526),
"Release engineering debt — build once, qualify the exact artifact, publish
the exact artifact."

**Authority:** this document records what happened during the beta.5 release
and what has since been fixed. It does not itself select a version, create a
tag, publish a package, or deploy, and it does not approve v0.1.0 or any
other release. The companion
[v0.1.0 release-readiness checklist](../release-readiness-v0.1.0.md) states
the criteria a later, explicitly approved release decision is made against.

## What was published

Beta.5 is the strongest release evidence to date: 10 npm packages (including
the two musl Linux Node addons), both Rust crates, and all nine Python
distribution files (eight abi3 wheels and the sdist) were published and
fresh-install verified, from the approved and qualified source revision
`0cc48374d005a44334bf727e49125165ec7d4157` on `rc/0.1.0-beta.5`. The complete
qualification, publication, recovery, and verification account, including
every workflow run ID, is the durable record at
[`docs/releases/0.1.0-beta.5/README.md`](../releases/0.1.0-beta.5/README.md);
this document summarizes it only as far as needed to state what broke and
what fixed it. It did not, however, publish cleanly in one pass.

## What failed, and why

Three problems showed up. All three are release-engineering debt, not
detection debt — nothing about secret detection, redaction, or policy
behavior was involved in any of them.

1. **npm registry propagation delay was reported as a publish failure.** The
   original release run published nine of the ten npm packages successfully,
   but npm's registry had not yet made each new version queryable by the time
   the workflow's post-publish verification step checked it. The step timed
   out and reported failure even though publication had already succeeded.
   This is a **false negative**: the workflow's own report was wrong about
   what had happened on the registry.
2. **A recovery run was needed.** The pipeline could not carry itself to
   completion in one pass — a direct consequence of (1) and, on its first
   recovery attempt, a repeat of the same false-negative shape.
3. **The qualified Python wheel and the published Python wheel were not
   byte-identical.** `release.yml` and `artifact-qualification.yml` each
   independently invoked `.github/workflows/python-wheels.yml`, so the
   release run built the wheels twice from the same source revision.
   Byte-for-byte comparison after the fact found that all eight published
   wheels differed from the qualification job's own recorded hashes by 1–5
   bytes each — the signature of a non-deterministic build input (most
   likely an embedded timestamp), not different content. The sdist, which
   has no compiled step, matched exactly. This meant qualification had
   proven a property about bytes that were never the bytes a user actually
   installed.

## What the recovery run did

1. A dry run ([35530191051](https://github.com/redact-secret/redact-secret/actions/runs/35530191051))
   verified the preserved manifest and inventory, independently
   content-matched all nine already-published npm dependency packages
   against their qualified shasums, and planned publication of only the
   remaining package, the `@redact-secret/core` facade.
2. The first recovery run
   ([35530799370](https://github.com/redact-secret/redact-secret/actions/runs/35530799370))
   published the facade, but hit the identical false-negative shape as the
   original run: npm again took longer to converge than the workflow's
   one-minute verification window, now for the single remaining package.
   Independent verification against npm's immutable per-version registry
   endpoint (not the aggregate `npm view` cache, which the same lag can leave
   stale) confirmed the published shasum matched the qualified content
   exactly, before any further action was taken.
3. A final recovery run
   ([35531013273](https://github.com/redact-secret/redact-secret/actions/runs/35531013273))
   re-verified the same already-matching content — idempotent, nothing was
   republished — passed clean installs on all eight published Node targets
   and Chromium, and created the annotated tag `v0.1.0-beta.5` at the frozen
   source revision.

Every step of this recovery was correct, but a release that needs three
extra workflow dispatches, two of them to re-confirm that a "failure" had
not actually happened, is exactly the outcome Epic #526 was opened to close.

## How each problem was resolved

- **Problem 3 (wheel mismatch) — resolved by
  [#527](https://github.com/redact-secret/redact-secret/issues/527) and
  generalized by [#528](https://github.com/redact-secret/redact-secret/issues/528).**
  `release.yml` no longer invokes `python-wheels.yml` on its own; it now
  consumes the single build `artifact-qualification.yml` already produced,
  so within one release run every Python artifact — wheels and sdist alike —
  is built exactly once, and qualification and publication consume that same
  artifact by construction. This does not make the wheel *build itself*
  reproducible (two independent builds from the same source might still
  differ by a stray byte); it removes the second build entirely, so there is
  nothing left for a mismatch to occur between. #528 generalizes the
  *recording* half of this beyond Python: the durable release manifest now
  carries a `built`/`qualified`/`published` digest triple for every artifact
  identity (npm, WASM, crate, and Python alike), with an explicit
  `comparable: false` plus a stated reason for artifact classes an ecosystem
  re-packs before upload (for example, `npm publish` wraps a file in a new
  tarball). Where digests are marked comparable, `scripts/release-manifest.py`
  now fails the run loudly, naming the artifact, the file, and both digests,
  if they ever disagree — a structural check that exists independently of
  which jobs happen to call which workflow, so a future refactor cannot
  silently reintroduce a second build.
- **Problems 1 and 2 (propagation delay reported as failure, forcing a
  recovery run) — resolved by
  [#529](https://github.com/redact-secret/redact-secret/issues/529).** Every
  registry-state read in the release pipeline (the npm wrapper version
  check, the unpublished-state probes before each publish, the
  `verify-registry-install` lanes) now uses a bounded, documented wait
  (`scripts/npm-registry-metadata.mjs`'s `waitForVisible`) instead of a
  single point-in-time check. A propagation delay within the timeout no
  longer fails the run; exceeding the timeout still fails, with a message
  naming what was being waited on and for how long, so a genuine failure
  still fails loudly. This behavior is exercised deterministically in CI,
  including a simulated slow-registry case, independent of any live release
  dispatch.
- **Rehearsal coverage and the Reconcile Release exercise —
  [#530](https://github.com/redact-secret/redact-secret/issues/530).**
  `package-release-rehearsal.yml` previously rehearsed only the npm
  dependency cutover from an unrelated earlier issue; it never touched
  Python and never ran the #527/#528 digest checks it was meant to exercise.
  It now runs those exact digest checks — the identical script, against the
  identical qualification artifacts, with the identical failure mode —
  before any real release dispatch, for every artifact family where that
  comparison is possible without a real publish (Node addon, browser/WASM,
  Python wheels and sdist). The full account of what the rehearsal now
  covers, and what it structurally cannot cover without a real publish, is
  [`docs/audits/release-rehearsal-coverage.md`](release-rehearsal-coverage.md).

## What remains open

- **Reconcile Release has not yet been exercised deliberately.** Every
  dispatch of `reconcile-release.yml` to date (visible via
  `gh run list --workflow=reconcile-release.yml`) was a real recovery against
  an actual partial-publication failure — beta.2, beta.3, and beta.5's three
  dispatches recorded above — never a deliberate rehearsal against a
  known-good published version, and never a deliberate exercise of its
  refusal path (a commit outside the matching RC branch's history). #530
  wrote down the exact commands for both
  ([`docs/audits/release-rehearsal-coverage.md`](release-rehearsal-coverage.md#reconcile-release)),
  but running them requires the same explicit, separate authorization every
  `Reconcile Release` dispatch requires under
  [`AGENTS.md`'s release authority section](../../AGENTS.md#release-authority),
  and that authorization has not been given. This is tracked as item 5 of the
  [v0.1.0 release-readiness checklist](../release-readiness-v0.1.0.md).
- **The Python wheel build itself is not proven reproducible.** #527 removed
  the second build that let beta.5's mismatch occur, but nothing yet asserts
  that building the same wheel twice, independently, produces identical
  bytes. The 1–5 byte drift beta.5 observed (most likely an embedded
  timestamp) has not been root-caused, only made structurally unobservable
  by construction. No GitHub issue exists for this yet; it is worth filing
  as its own follow-up (pin or strip the non-deterministic build input, or
  add a periodic double-build comparison independent of the single-build
  release path) rather than being carried only in this document and
  [prior release-record prose](../releases/0.1.0-beta.5/README.md#known-discrepancy-non-reproducible-python-wheel-builds).

## Beta.5's published wheel bytes were correct throughout

None of the above changes the fact that what was published in beta.5 was
verified correct by three independent means, unrelated to qualification's
own (differently-built) output: downloading each file directly from
`files.pythonhosted.org` and hashing it locally, confirming those hashes
against PyPI's JSON API, and a real `pip install redact-secret==0.1.0b5`
followed by a clean `scan_and_redact` call. The problem beta.5 exposed was
that qualification could not have caught a real divergence had one existed —
not that one did.
