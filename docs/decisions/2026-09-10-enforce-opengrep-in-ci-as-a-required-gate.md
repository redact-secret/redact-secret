---
decision_id: decision-enforce-opengrep-in-ci-as-a-required-gate
status: accepted
scope: workspace
title: Enforce OpenGrep in CI as a required, SARIF-integrated gate
decided_at: 2026-09-10
spec: evidence-and-gates
---

# Enforce OpenGrep in CI as a required, SARIF-integrated gate

## Decision

Run issue #155's pinned OpenGrep command
(`python3 scripts/run-sast.py --out ... --sarif-out ...`) as a GitHub Actions
workflow (`.github/workflows/sast.yml`) on every pull request and every push
to `main`, gated by that command's own exit code and nothing else. The job
has least-privilege permissions (`contents: read`, plus `security-events:
write` scoped to the SARIF upload step alone), commit-pinned actions, and a
bounded `timeout-minutes`. The normalized JSON report and its SARIF
projection are both retained as workflow artifacts; the SARIF file is also
uploaded to GitHub code scanning on a best-effort basis
(`continue-on-error: true`), so an environment where code scanning is
unavailable -- a private repository without Advanced Security, a fork pull
request's restricted token -- degrades that one step to a no-op without
ever changing whether the job passes or fails.

`run-sast.py`'s SARIF projection (`build_sarif`) carries every
`false_positive`/`hardening` baseline disposition forward as a SARIF
`suppression` with its recorded rationale, rather than omitting the finding.
GitHub's third-party SARIF ingestion retains that metadata but does not apply
it to alert state by itself. After successful upload processing, a
commit-pinned `advanced-security/dismiss-alerts` step synchronizes the SARIF
state on `refs/heads/main` only: reviewed findings are dismissed as `won't
fix`, and action-managed alerts are re-opened when their baseline suppression
disappears. Pull-request runs may upload SARIF but cannot perform this
repository-wide mutation. This is a projection of the existing baseline gate,
never a second source of truth: neither the SARIF file nor the best-effort
upload and synchronization steps influence `run-sast.py`'s own exit code, and
the workflow's "Enforce scan result" step checks the scan step's real outcome
(`steps.scan.outcome`, which `continue-on-error` does not mask) after every
artifact and upload step has already run `if: always()`.

Applying this check to live repository state -- making it a required status
check in `main`'s branch protection (issue #143), and recording a specific
run's evidence on issue #145 -- is deliberately left to a repository
administrator acting outside this change, matching the boundary
`scripts/verify-release-governance.py` already documents for issue #143:
a pull request can make the check exist and pass; it cannot make GitHub
require it, because that is a live settings mutation with repository-wide
blast radius, not a source change. The workflow's "Record OpenGrep
evidence" job-summary step writes the exact run URL and rules digest that
recording asks for, so a human need only copy it forward.

## Rationale

A SAST scan that only ever runs locally, or optionally in CI, protects
nothing: a contributor who does not run it, or a CI job that is not
required, can merge a real finding no one reviewed. Making the exact same
pinned command issue #155 already made reproducible into the CI gate --
rather than a parallel, looser check -- means there is still only one
command whose pass/fail this repository trusts.

Least-privilege permissions and commit-pinned actions follow this
repository's existing workflow convention (`ci.yml`, `python-wheels.yml`);
a `timeout-minutes` bound follows from the same fail-closed posture
`run-sast.py` already applies to tool/rule tampering and scan errors --
none of those failure shapes should also be able to hang a runner
indefinitely.

Uploading SARIF makes findings visible in GitHub's code scanning UI, which
is valuable, but availability of that upload is an infrastructure property
(Advanced Security licensing, fork-token scope) unrelated to whether this
repository's own code passed its own gate. Treating it as advisory --
`continue-on-error: true`, checked nowhere in the pass/fail decision --
keeps the enforcement signal exactly one command's exit code, as issue #156
requires. The same best-effort boundary applies to issue #172's main-only
suppression synchronization: it repairs GitHub alert state after ingestion,
but can neither make a failed scan pass nor make an otherwise passing scan
fail.

## Consequences

- `sast/baseline.json`'s finding ids are derived from `(rule_id, path,
  start_line, end_line)`, so any edit that shifts line numbers above an
  already-dispositioned finding changes its id and makes it reappear as
  unclassified even though the underlying code did not change. This
  surfaced immediately: adding `build_sarif` and its CLI plumbing to
  `scripts/run-sast.py` shifted its own two previously-baselined
  `dangerous-subprocess-use-audit` findings, which this change re-baselines
  at their new line numbers with the same reviewed rationale rather than
  leaving stale entries at the old ones.
- `main` branch protection requiring this check, and the exact run
  evidence issue #145 asks for, remain follow-up administrator actions --
  this decision makes both possible, not automatic.
- Every `pull_request` run and every push to `main` now cannot merge or land
  with an unresolved blocking OpenGrep finding, an unacknowledged scan
  error, or a tool/rule-integrity failure, without a human deliberately
  widening `sast/baseline.json`.
- A successful `main` run synchronizes `false_positive` and `hardening`
  suppressions into GitHub alert state after SARIF processing. The pinned
  action dismisses matching alerts as `won't fix` with `Suppressed via SARIF`
  and re-opens alerts it manages when the corresponding suppression is later
  removed; pull-request runs never mutate that state.
