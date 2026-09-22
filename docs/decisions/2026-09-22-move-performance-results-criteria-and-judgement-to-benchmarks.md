---
decision_id: decision-move-performance-results-criteria-and-judgement-to-benchmarks
status: accepted
scope: workspace
spec: evidence-and-gates
title: Move performance results, criteria, and judgement to redact-secret-benchmarks
decided_at: 2026-09-22
---

# Move performance results, criteria, and judgement to redact-secret-benchmarks

## Decision

`assessment/` keeps measurement tooling only: the per-surface runners
(`scripts/assessment-*.mjs`, the Rust `assessment_adapter`,
`assessment/adapters/*`), the result schema, the workload generator and
profiles, and the accuracy corpus. `evaluateAcceptance` and
`validateAcceptanceCriteria` (`assessment/acceptance.ts`) also stay, as
reusable evaluation tooling that takes a caller-supplied criteria document —
core no longer authors, commits, or ships one of its own.

[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
now owns performance results, RC acceptance criteria, acceptance evaluation
and reports, threshold recalibration, and publication, via
[benchmarks issue #136](https://github.com/redact-secret/redact-secret-benchmarks/issues/136):
a workflow there checks out a pinned core revision, runs this repository's
`npm run assessment:all` with release builds, and evaluates the result
against criteria it holds, with no cross-repository token or artifact
handoff.

**Linux x86_64 is the only official performance profile.** The macOS arm64
profile this repository previously fixed in `acceptance-criteria.json` is
retired; its historical thresholds were partly derived from Rust debug-build
timings (`assessment/README.md`'s "Performance build correction" section) and
needed recalibration regardless of ownership.

## Why

- Assessment is "never itself a release gate"
  (`decision-define-cross-language-evaluation-protocol`;
  `docs/releasing.md`), so it was never the natural home for a release-facing
  pass/fail judgement in the first place — see
  [Amendment to the cross-language evaluation protocol](#amendment-to-the-cross-language-evaluation-protocol)
  below.
- Raw result bundles belong in `redact-secret-benchmarks`, per
  [`decision-govern-benchmark-regression-promotion`](2026-09-18-govern-benchmark-regression-promotion.md).
- [`docs/benchmark-candidate.md`](../benchmark-candidate.md) already splits
  the work this way: core builds immutable candidate artifacts,
  `redact-secret-benchmarks` evaluates them at a pinned SHA.
- Host-dependent run output and "what is fast enough" are measurement and
  judgement, not product contract — the same distinction
  [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
  draws for "Final evidence, benchmark measurement."

## Scope

- `git ls-files assessment/results` is empty: `results/beta.2/`,
  `results/complete-v4/`, `results/complete-linux-x64-v4/`, and
  `results/release-profile/` are removed. `assessment/acceptance-criteria.json`
  and `assessment/acceptance-criteria-linux-x64.json` are removed. Every
  removed path remains readable as historical evidence at the pre-removal
  commit,
  [`de6add470321f40d7b1cb36808d9f4559e6c2e99`](https://github.com/redact-secret/redact-secret/tree/de6add470321f40d7b1cb36808d9f4559e6c2e99/assessment),
  linked from `assessment/README.md` and every document that cited a removed
  path.
- `assessment/complete.test.ts` and `assessment/acceptance.test.ts` no longer
  read a committed `results/` baseline or a committed criteria document; both
  now build synthetic fixtures in-memory (and, where a test exercises linking
  to real files, in a temporary directory) so `buildCompleteAssessment` and
  `evaluateAcceptance`'s code paths stay covered without binding a unit test
  to evidence that belongs elsewhere.
- `.github/workflows/complete-assessment.yml` stays as a manually dispatched
  core smoke run: it still builds real artifacts and runs
  `npm run assessment:all`, but no longer runs an acceptance-evaluation step
  or uploads an acceptance result, since it has no criteria document to
  evaluate against. `redact-secret-benchmarks#136`'s workflow is the
  judgement run.
- `assessment/README.md`, `docs/reference/detection-reliability.md`, and
  `docs/releasing.md` are updated to describe this ownership split; every
  other document that linked a removed path (`docs/audits/evidence/376/`,
  `docs/audits/detection-assurance-epic-closeout.md`,
  `docs/audits/detection-reliability-published-evidence.md`) is repointed at
  the pre-removal commit rather than left broken.

## Amendment to the cross-language evaluation protocol

[`decision-define-cross-language-evaluation-protocol`](2026-09-12-define-cross-language-evaluation-protocol.md)
never assigned RC performance-criteria ownership or judgement to `assessment/`
— it defined only the schema, corpus, profiles, and result contract, and
stated that `assessment/` "is never itself a release gate." In practice,
`assessment/acceptance-criteria.json` and its pinned `results/` baselines
were nonetheless authored and committed in this repository (first fixed at
commit `a356e702e59b03cf297e0af15ba0423bc8466d48`, later extended to a second,
Linux x86_64 profile), which is the gap this decision closes. That document's
"Files" and "Common result contract" sections are unaffected: the schema,
corpus, profiles, and generator remain exactly as defined there.

That document gains this note, appended after its "Consequences" section:

> **Amended 2026-09-22 by `decision-move-performance-results-criteria-and-judgement-to-benchmarks`:**
> this protocol's committed corpus, profiles, and result contract stay in
> `assessment/`. The RC acceptance criteria and pinned baselines this
> repository committed on top of that contract, and the pass/fail judgement
> against them, were never part of this protocol and are now explicitly
> owned by `redact-secret-benchmarks`, not committed here as
> `assessment/results/` or `assessment/acceptance-criteria*.json`.

## Summary of the beta.5 gate ADR

[`decision-gate-beta5-on-precision-gains-and-positive-preservation`](2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md)
is summarized in place per DS6d's disposition grade
(`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`):
its path and `decision_id` are unchanged, its body is replaced with a short
summary, and a `full_record:` permalink preserves the pre-summary text. Its
release-qualification accuracy-corpus re-pin and its discovered
out-of-scope macOS performance-threshold gap both named
`assessment/acceptance-criteria*.json` and `assessment/results/complete*-v4/`
paths this decision removes; the full record is the durable copy of that
detail.

## Consequences

- Core CI no longer runs an RC acceptance-evaluation step; `redact-secret-benchmarks#136`'s
  workflow is the authoritative performance gate once it lands.
- A future core issue proposing a new performance threshold or a new
  environment profile belongs in `redact-secret-benchmarks`, not here.
- `scripts/assessment-acceptance.mjs` (`npm run assessment:acceptance`)
  requires an explicit `--criteria` path; it no longer defaults to a bundled
  document.
- This decision selects no version, creates no tag, and authorizes no
  release; release approval remains a separate, explicit step per
  `AGENTS.md`.
