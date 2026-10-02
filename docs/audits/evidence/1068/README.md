# #1068 — Beta.13 performance, memory and artifact-size budgets: product-side disposition

Product judgement. Records what this repository contributes to
[#1068](https://github.com/redact-secret/redact-secret/issues/1068) (parent
#1065) and what it deliberately does not. It freezes no threshold and gives no
verdict.

## Ownership

[`decision-move-performance-results-criteria-and-judgement-to-benchmarks`](../../../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md)
puts performance results, acceptance criteria and pass/fail judgement in
`redact-secret-benchmarks`. This record therefore does not hold budgets.
"Thresholds fixed before candidate judgement" is met there, by a committed
criteria document that predates the candidate run, and is cited from #1068
when it lands. Final raw measurements stay in that repository too.

## Optional optimization and research cards: all closed

All 30 cards listed in #1068's follow-up sections are closed as of 2026-10-02:
#1121–#1135, #1145–#1149 and #1160–#1169. Each one's own evidence record or
commit holds its disposition; the judgement that a measured rejection or
deferral is valid completion stands. Rejected unconditional alternatives
(#1148 Luhn table, unconditional #1163 PEM search, #1169 digit-block discovery)
and the profile/size research (#1126–#1130, no third profile, unwind kept)
are not stable blockers.

## What remains before #201 can close

| Item | Owner | State |
|---|---|---|
| Frozen workloads and thresholds for Rust core, Node addon, WASM full/common (PII and non-PII), Python, CLI, whole-input and incremental paths | `redact-secret-benchmarks` | not yet committed; must precede candidate judgement |
| Verdict or reviewed tradeoff per breach on the exact Beta.13 stable candidate | `redact-secret-benchmarks` | needs the frozen candidate commit |
| Move in-repo measurement code and `unsafe` allocator out of `crates/` | #1152 | open; blocked by benchmarks#608 |
| Audit that no quadratic or unbounded hot path remains on the supported default path | this repository | not performed here; see below |

## Not claimed

- The exploratory medians in #1068's comments are isolated native stages on a
  development host, not frozen budgets and not shipped whole-scan speedups.
- No claim that no quadratic path remains. That needs a pass over the
  adversarial complexity workloads on the candidate commit, which is a
  measurement and belongs with the frozen workloads above.
- No version, tag, publication or deployment is authorized by this record.
