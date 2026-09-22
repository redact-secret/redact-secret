# Issue #200 — detection reliability published-evidence run

[Audit archive](../../README.md) · [Issue #200](https://github.com/redact-secret/redact-secret/issues/200) ·
[Published evidence review](../../detection-reliability-published-evidence.md)

Recorded 2026-09-13 at commit `a356e702e59b03cf297e0af15ba0423bc8466d48`.
Verdict: `evidence-published-formal-same-revision-rc-matrix-pending`. This is
the raw `verification-summary.json` behind the review's own narrative.

## What is here

A completed cross-language testbed run (`assessment/results/complete/`) over
five surfaces (rust-core, python, node, browser-wasm, cli), 15 total runs, 2
performance repetitions, 0 validation failures, against the pinned
`assessment/fixtures/accuracy-corpus.json` (9 fixtures: 3 logs, 2 code, 2
chat, 2 negative-text; 6 expected findings, 3 expected-empty) and
`workload-profiles.json` (2 profiles evaluated).

The per-surface detection tallies (1 true positive of 6 expected, 5 false
negatives, 1 false positive of 2 actual, 1 incorrect range) and the paired
range-interpretation counts for the `chat-bearer-token` fixture are recorded
raw, alongside the redaction-evidence completeness counts and the
disposition drawn from `assessment/results/beta.2/README.md`: zero confirmed
detector defects, four documented-limitation fixtures, and one
contract-disagreement fixture (`chat-bearer-token`).

`universal_accuracy_claimed` and `release_authorized` are both `false`;
`remaining_evidence_owners` (180, 203, 224) names the issues that own the
gaps this run left open, matching [evidence/199](../199/README.md)'s own
`follow_up_issues`.
