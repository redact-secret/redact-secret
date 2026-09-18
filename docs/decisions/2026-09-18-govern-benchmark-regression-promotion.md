---
decision_id: decision-govern-benchmark-regression-promotion
status: accepted
scope: workspace
title: Govern benchmark-originated product regressions
decided_at: 2026-09-18
---

# Govern benchmark-originated product regressions

## Decision

[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
owns evaluation truth: discovery fixtures, generated variants, differential and
holdout evaluation, raw evidence, known-gap lifecycle, and fixed-candidate
revalidation. Its
[promotion decision](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/decisions/2026-09-18-govern-benchmark-promotion.md)
is authoritative for the detailed lifecycle and transition evidence. The
coordinating work is tracked by
[benchmark issue #10](https://github.com/redact-secret/redact-secret-benchmarks/issues/10)
and [product issue #390](https://github.com/redact-secret/redact-secret/issues/390).

This repository owns detector implementation, minimal canonical regression
fixtures, cross-surface conformance, and release-blocking behavior. The
Evaluation Engine remains in the benchmark repository. The complete benchmark
corpus, generated exploration variants, competitor observations, holdout cases,
scoring reports, and raw result bundles are not copied here. `assessment/`
continues to measure the bounded cross-language protocol defined by
`decision-define-cross-language-evaluation-protocol`; it is not another
discovery benchmark and is not the intake path for benchmark findings.

## Canonical product location

A promoted whole-input regression is the smallest deterministic case in
`conformance/fixtures/synchronous-corpus.json`, using `tier: "regression"` and
the existing canonical UTF-8 range schema. Add positive and negative controls
that isolate the changed grammar or boundary. When chunking, retained lexical
state, or finalization can affect the behavior, add the smallest matching case
to `conformance/fixtures/incremental-corpus.json`; every supported incremental
runner then checks every applicable partition. Do not add an incremental copy
when the behavior has no incremental risk.

`conformance/benchmark-regressions.json` is the lightweight provenance and gate
manifest. It links benchmark fixture IDs and corpus hashes to the product issue,
fixing commit, canonical fixture IDs, and evidence for the two acceptance gates.
It does not add benchmark-only fields to `CanonicalFixture` or
`CanonicalExpectation`, and it carries no fixture input or matched value.

A detector-level unit test is also required when the repair depends on an
internal helper contract, cursor advancement, candidate emission before overlap
resolution, or a near-miss branch that the public canonical result cannot
isolate. The canonical fixture remains required because a unit test cannot prove
the supported surfaces share the behavior.

## Product acceptance gate

A benchmark-originated product bug is fully verified only when both records are
present:

1. the canonical regression passes the required Rust, Node, browser WebAssembly,
   Python, and CLI consumers that support the affected whole-input or incremental
   behavior, with a stable evidence link recorded in the manifest; and
2. the exact fixed candidate is rerun by `redact-secret-benchmarks`, with the
   benchmark verification evidence linked from the manifest and known-gap
   record.

Neither gate changes release authority. A finding can be implemented without
being verified; it cannot be described as verified until both gates pass.

## Historical reconciliation

The closed issues remain historical records and are not reopened or rewritten.
The manifest records their current evidence without checking work that was not
performed:

| Issue | Existing product evidence | Outstanding under this decision |
| --- | --- | --- |
| [#292](https://github.com/redact-secret/redact-secret/issues/292) | detector repair and unit controls in `8d8d5b4` | canonical conformance fixture and supported-surface evidence; fixed-candidate benchmark rerun |
| [#293](https://github.com/redact-secret/redact-secret/issues/293) | canonical whole-input fixtures and repair in `a62339e` | recorded supported-surface conformance evidence; fixed-candidate benchmark rerun |
| [#294](https://github.com/redact-secret/redact-secret/issues/294) | canonical whole-input and incremental fixtures and repair in `49f41ea` | recorded supported-surface conformance evidence; fixed-candidate benchmark rerun |

All six gates remain `pending` in the manifest. This preserves the issues'
unchecked acceptance items and does not imply that their completed detector
work regressed.

## Consequences

Product CI can validate provenance links without importing benchmark data or
running the Evaluation Engine. Benchmark failures remain discovery evidence
until reviewed and promoted. Canonical product regressions remain small,
deterministic, synthetic or explicitly revoked, and reusable by every supported
binding through the existing conformance contract.
