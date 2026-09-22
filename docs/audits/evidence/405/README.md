# Issue #405 — OpenAI token shapes 1-3 discovery evidence triage

[Audit archive](../../README.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[OpenAI grammar freeze (#368)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Beta.5 precision gate (#376)](../../../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) ·
[Benchmark-regression governance](../../../decisions/2026-09-18-govern-benchmark-regression-promotion.md) ·
[Issue #405](https://github.com/redact-secret/redact-secret/issues/405) ·
[Prior evidence: #367](../367/README.md) · [Prior evidence: #376](../376/README.md) ·
[Prior evidence: #402](../402/README.md)

Triaged 2026-09-18 against candidate commit `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
(this repository's `main`). This is a review of discovery evidence, not a
detector change: it adds no fixture, corrects no grammar, and closes no gate.
It changes no code.

## Summary

Issue #405 reports nine `detector-coverage` fixtures —
`openai-token-shape-1/2/3-{bare,quoted,unicode-crlf}` — regressing from
`EXACT` (published `0.1.0-beta.4` baseline) to a complete miss against
candidate `fe4f1d1`. **This is the same fixture family, with the same
disposition, already reviewed twice: once in
[`evidence/367/README.md`](../367/README.md) at the contract-freeze itself,
and again in [`evidence/402/README.md`](../402/README.md) against candidate
`ec1f86b0c07e`.** `fe4f1d1` is `ec1f86b0c07e` plus one documentation-only
commit (`cb38b47`, #402's own audit write-up); no line of detector code
changed between the two candidates:

```
git log --oneline ec1f86b0c07efc10ecbbd9fa22d7083f8982b942..fe4f1d1688450baee402472b1a7f2cc802e2fd79
# fe4f1d1 Merge pull request #403 from redact-secret/workbench/402-release-regression-triage
# cb38b47 docs(audits): add audit documentation and evidence for 402
git log --oneline -- crates/secret-scan-core/src/detectors/openai.rs
# unchanged since d5d3d56 (pre-#367 freeze); no commit in that range touches this file
```

No new evidence is introduced by this issue. No product defect is confirmed.
No code change is made under this issue.

## Why the miss is intended

Issue #368's decision record
([`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md#folded-records),
OpenAI row)
narrowed `openai-token` from "any `sk-` value at least 20 bytes long" to the
documented `<segment>T3BlbkFJ<segment>` shape with segments at an exact
length (20/20 legacy, 74/74, 74/58, or 58/74 namespaced). `evidence/367`
names the benchmark's `shape-1..3` fixtures explicitly as the accepted cost
of that freeze:

> `openai-token-shape-1..3-*` (48-byte random bodies, no marker) | policy/T3 |
> provider finding removed; intended policy change, reported by #376, cases kept

The offsets #405 reports are internally consistent with that same
marker-less shape, not a new one: each `{bare, quoted, unicode-crlf}` triple
for a given shape shares one match length (shape-1: 51 bytes; shape-2: 56;
shape-3: 59), with the `quoted`/`unicode-crlf` start offsets shifted by
exactly their prefix's byte length (7 and 21 respectively) — the same
context-shift pattern this detector's own tests assert
(`crates/secret-scan-core/src/detectors/openai.rs:388-393,414-422`). A value
built from `sk-` plus a same-length run with no `T3BlbkFJ` marker is exactly
what `rejects_the_marker_less_broad_shapes_the_previous_rule_accepted`
(`crates/secret-scan-core/src/detectors/openai.rs:325`) and
`an_explicit_namespace_never_falls_back_to_the_legacy_branch`
(`crates/secret-scan-core/src/detectors/openai.rs:315`) assert is rejected.

## Re-verification

Re-run independently at candidate commit `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
rather than taken on citation alone:

```
cargo test -p redact-secret --lib detectors::openai
# 21 passed, 631 filtered out (1 suite)
```

This includes both tests named above, plus
`issue_368_twins_are_rejected_and_their_paired_positives_preserved`, which
locks in the exact accept/reject boundary the frozen grammar draws (a
marker-bearing positive at a documented segment length is kept; the same key
with the marker corrupted, or a segment one byte off, is rejected).

## What this document does not claim

- It does not assert that no product defect could ever exist in this
  detector; it reports what two independent, dated reviews (#367, #402) plus
  this document's own re-run of the relevant test suite at the exact
  candidate commit `fe4f1d1` currently show.
- It does not evaluate the six other `detector-coverage` families #402
  covered (`slack-token-shape-1`, `docker-token-shape-1`,
  `cloudflare-token-shape-1`) or the `sendgrid` fixture-ID collision; #405
  reports only the `openai-token-shape-1/2/3` family, and this document is
  scoped to match.
- It is not a `known-gaps.json` record — that lifecycle artifact belongs to
  `redact-secret-benchmarks`, per `decision-govern-benchmark-regression-promotion`.
  Issue #405's own body already states it was filed there as an `observed`
  known-gap, which this document's disposition supports promoting to
  `reviewed`.

## Recommendation

Issue #405 does not warrant a `conformance/benchmark-regressions.json` entry:
that manifest is for a promoted, fixed regression with a fixing commit, and
no fix is needed here. The nine fixtures are the same accepted false-negative
cost `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md` recorded
when the grammar was frozen. The recommended next step lives in
`redact-secret-benchmarks`: mark the existing `openai-token-shape-1/2/3`
known-gap record `reviewed`, citing #367, #402, and this document, rather
than promoting #405 as a release-blocking regression.

## Authority

This document reviews and cross-references existing evidence. It does not
change detector behavior, change #405's state, select a version, create a
tag, publish a package, or authorize any release operation. A release still
requires the explicit approval `AGENTS.md` mandates.
