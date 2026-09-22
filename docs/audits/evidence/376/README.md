# Issue #376 — beta.5 candidate precision gate

[Audit archive](../../README.md) ·
[Decision record](../../../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) ·
[Issue #376](https://github.com/redact-secret/redact-secret/issues/376) ·
[Benchmark comparison document](https://github.com/redact-secret/redact-secret-benchmarks/pull/13)

**Kind (per [DS0](../../../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)):**
final evidence, benchmark measurement — a `redact-secret-benchmarks` run
produced it, per that repository's own
[evidence convention](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/evidence/README.md).
The measurement now lives there; this stub keeps the permalink and the
one-line result the decision record above relies on, per the "What the core
repository keeps instead" section of that convention.

**Result:** PASS. Fixed-corpus twin false alarms 24 → 0 (56/56 discrimination
target met); 0 required-positive misses (T1/T2) in either corpus, before or
after.

Full evidence:
[`redact-secret-benchmarks/evidence/376/README.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/evidence/376/README.md),
which in turn links the full narrative, per-issue fixture mapping,
policy-change table, and anomalies in that repository's
[`docs/reports/beta-5/results.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md).

This repository's own release-qualification accuracy-corpus re-pin, which
the same gate also performed, is not benchmark measurement and is
unaffected by this move — see
[`assessment/results/complete-v4/README.md`](../../../../assessment/results/complete-v4/README.md)
and
[`assessment/results/complete-linux-x64-v4/README.md`](../../../../assessment/results/complete-linux-x64-v4/README.md).
