---
decision_id: decision-gate-beta5-on-precision-gains-and-positive-preservation
status: accepted
scope: workspace
title: Gate beta.5 on precision gains and positive preservation
decided_at: 2026-09-18
full_record: https://github.com/redact-secret/redact-secret/blob/de6add470321f40d7b1cb36808d9f4559e6c2e99/docs/decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md
---

# Gate beta.5 on precision gains and positive preservation

Summarized in place 2026-09-22 by
[`decision-move-performance-results-criteria-and-judgement-to-benchmarks`](2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md)
(DS6d disposition grade). The `full_record` link above is the complete
pre-summary text, including the sections this summary omits.

## Decision

For issue #376, this gate accepted the seven precision fixes (#368–#374), the
shared context/streaming matrix (#375), and the contract freeze (#367) as
producing a genuine, evidenced precision gain over beta.4, with no measured
loss on required positives, no new collateral redaction, and every intended
behavioral change explicitly recorded. Full evidence remains in
[`docs/audits/evidence/376/README.md`](../audits/evidence/376/README.md) and,
for the durable candidate comparison, `redact-secret-benchmarks`'s
[`docs/beta-5-results.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/beta-5-results.md).
In summary: fixed-corpus twin discrimination moved 32/56 → 56/56 (24 twin
false alarms eliminated), all 58 fixed-corpus and 168 expanded-corpus
required T1/T2 positives were preserved at zero leaked spans, and existing
T1/T3 negatives stayed at zero flags. Eighteen `detector-coverage` policy/T3
rows for four of the seven families lost their provider finding as the
intended, reviewed policy change from freezing their contracts.

This gate also re-pinned the then-committed `assessment/acceptance-criteria.json`
and `assessment/acceptance-criteria-linux-x64.json` to four corrected
`assessment/fixtures/accuracy-corpus.json` fixtures and discovered a
pre-existing, out-of-scope macOS performance-threshold gap (every non-Rust
surface missing its fixed processing-time and throughput thresholds by
roughly 20–30%, unaffected on Linux x86_64). Both criteria files and every
`assessment/results/` baseline this gate cited were later removed by
[#603](https://github.com/redact-secret/redact-secret/issues/603) (DS11):
performance results, criteria, and judgement now belong to
`redact-secret-benchmarks`, and the macOS profile is retired. The
`full_record` link preserves the exact numbers, paths, and re-pin mechanics
as they stood at this gate.

## Consequences

Beta.5's precision-relevant behavior remains evidenced against a frozen
beta.4 baseline with fixed-corpus and expanded-corpus results kept separate,
every required positive preserved, and every intended policy change
recorded. This decision selected no version, created no tag, published no
package, and authorized no release.
