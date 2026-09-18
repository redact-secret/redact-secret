# Issue #406 — release-regression discovery evidence triage (Slack shape-1)

[Audit archive](../../README.md) ·
[Governance decision](../../../decisions/2026-09-18-govern-benchmark-regression-promotion.md) ·
[Slack bot grammar freeze (#371)](../../../decisions/2026-09-17-freeze-slack-bot-token-segment-grammar.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Beta.5 precision gate (#376)](../../../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) ·
[Issue #406](https://github.com/redact-secret/redact-secret/issues/406) ·
[Prior evidence: #367](../367/README.md) ·
[Prior evidence: #376](../376/README.md) ·
[Prior evidence: #402](../402/README.md)

Triaged 2026-09-18 against candidate commit `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
(this repository's `main`). This is a review of discovery evidence, not a
detector change: it adds no fixture, corrects no grammar, and closes no gate.
It changes no code.

## Summary

Issue #406 reports that the `detector-coverage` corpus's Slack shape-1
fixtures — `slack-token-shape-1-bare` (expected `{0,53}`),
`slack-token-shape-1-quoted` (expected `{7,60}`), and
`slack-token-shape-1-unicode-crlf` (expected `{21,74}`) — regress from `EXACT`
(published `0.1.0-beta.4` baseline) to a complete miss (0 findings) at
candidate `fe4f1d1`. **This exact three-row group is already accounted for by
this repository's own prior gate evidence, reviewed on the same day
(2026-09-18) the candidate #406 evaluated was itself reviewed under #402.**
Nothing new is found here. No product defect is confirmed, and no code change
is made under this issue.

| Group | Count | Disposition | Prior evidence |
| --- | ---: | --- | --- |
| `slack-token-shape-1-{bare,quoted,unicode-crlf}` | 3 | intended, reviewed policy change | [#367](../367/README.md), [#376](../376/README.md#policy-changes-never-hidden-by-deleting-cases), [#402](../402/README.md) |

## Why this is not a regression

`decision-freeze-slack-bot-token-segment-grammar` (#371) narrowed the
`xoxb-` bot shape from beta.4's "recognized prefix plus a 20-byte minimum
suffix" rule to the provider-documented three-section grammar:

```
xoxb-<10-13 [0-9]>-<10-13 [0-9]>-<18+ [A-Za-z0-9]>
```

`slack-token-shape-1` is exactly the pre-freeze shape the decision retired:
an `xoxb-`-prefixed value with no `-`-sectioned body (`docs/audits/evidence/376/README.md`,
"Policy changes", names `slack-token-shape-1` — "no dash-sectioning" —
verbatim as one of eighteen `detector-coverage` policy/T3 rows moving from a
provider finding to silent, an intended, reviewed change with cases kept, not
deleted). `docs/audits/evidence/402/README.md` independently re-triaged the
same row at candidate `ec1f86b0c07e` with the identical disposition. The
`bare`, `quoted`, and `unicode-crlf` contexts fail for the same structural
reason: the value itself is out of contract, independent of the bytes
surrounding it, so all three benchmark contexts share one disposition.

`crates/secret-scan-core/src/detectors/slack.rs` has not changed since
`ec1f86b0c07e` (the commit #402 reviewed):

```
git log --oneline ec1f86b..fe4f1d1 -- crates/secret-scan-core/src/detectors/slack.rs
# (empty)
```

so #402's disposition carries forward unchanged to #406's candidate.

Re-verified independently at candidate `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
rather than taken on citation alone:

```
cargo test -p redact-secret detectors::slack
# 21 passed, 782 filtered out (14 suites)
```

That suite includes the unit tests asserting rejection of exactly the
now-out-of-contract shape-1 body, across plain and Unicode/CRLF-surrounded
contexts:

| Test | Location |
| --- | --- |
| `rejects_a_bot_value_missing_the_dash_before_the_secret_section` | `crates/secret-scan-core/src/detectors/slack.rs:237` |
| `a_bot_section_grammar_failure_never_falls_back_to_the_interim_guard` | `crates/secret-scan-core/src/detectors/slack.rs:344` |
| `issue_371_twins_are_rejected_and_their_paired_positives_preserved` (`bot-plain-twin`, `bot-unicode-crlf-twin`) | `crates/secret-scan-core/src/detectors/slack.rs:413` |

No code path in `SlackTokenDetector` accepts a no-separator `xoxb-` body; none
is expected to.

## What this document does not claim

- It does not assert that no product defect could ever exist in the Slack
  detector; it reports what three independent, dated reviews (#367, #376,
  #402) plus this document's own re-run of `detectors::slack` at the exact
  candidate commit currently show.
- It is not a `known-gaps.json` record — that lifecycle artifact belongs to
  `redact-secret-benchmarks`, per `decision-govern-benchmark-regression-promotion`.
  This document is the review that record's promotion decision should cite.
  Per issue #406's own governance note, the `observed` known-gap record
  already exists in that repository's `benchmarks/known-gaps.json`; this
  document supplies the product-side review it cites.

## Recommendation

The three fixtures in #406 do not warrant a
`conformance/benchmark-regressions.json` entry: that manifest is for a
promoted, fixed regression with a fixing commit, and no fix is needed here.
The known-gap record already filed in `redact-secret-benchmarks` should cite
#367, #376, #402, and this document rather than #406 being promoted as a
release-blocking regression.

## Authority

This document reviews and cross-references existing evidence. It does not
change detector behavior, change #406's state, select a version, create a
tag, publish a package, or authorize any release operation. A release still
requires the explicit approval `AGENTS.md` mandates.
