# Issue #402 — release-regression discovery evidence triage

[Audit archive](../../README.md) ·
[Governance decision](../../../decisions/2026-09-18-govern-benchmark-regression-promotion.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Beta.5 precision gate (#376)](../../../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) ·
[Issue #402](https://github.com/redact-secret/redact-secret/issues/402) ·
[Prior evidence: #367](../367/README.md) ·
[Prior evidence: #376](../376/README.md)

Triaged 2026-09-18 against candidate commit `ec1f86b0c07efc10ecbbd9fa22d7083f8982b942`
(this repository's `main`, unchanged since #402 was filed). This is a review of
discovery evidence, not a detector change: it adds no fixture, corrects no
grammar, and closes no gate. It changes no code.

**Kind (per [DS0](../../../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)):**
final evidence, product judgement. Stays in this repository.

## Summary

`release-regression-check` reported 19 fixtures regressing against the
`0.1.0-beta.4` baseline: 18 `expanded-corpus` / `detector-coverage` (kind
`policy`) misses across four provider families, and one `fixed-corpus`
`EXACT` → `PARTIAL` shift for a SendGrid fixture. Per
`decision-govern-benchmark-regression-promotion`, this is discovery evidence
until reviewed; review is this document.

**All 19 are already accounted for by this repository's own prior gate
evidence, recorded the same day (2026-09-18) as, or before, the candidate
this issue evaluated.** Nothing new was found. No product defect is
confirmed for any of the 19, and no code change is made under this issue.

| Group | Count | Disposition | Prior evidence |
| --- | ---: | --- | --- |
| `openai-token-shape-1/2/3-{bare,quoted,unicode-crlf}` | 9 | intended, reviewed policy change | [#367](../367/README.md), [#376](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md#policy-changes) |
| `slack-token-shape-1-{bare,quoted,unicode-crlf}` | 3 | intended, reviewed policy change | [#367](../367/README.md), [#376](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md#policy-changes) |
| `docker-token-shape-1-{bare,quoted,unicode-crlf}` | 3 | intended, reviewed policy change | [#367](../367/README.md), [#376](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md#policy-changes) |
| `cloudflare-token-shape-1-{bare,quoted,unicode-crlf}` | 3 | intended, reviewed policy change | [#367](../367/README.md), [#376](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md#policy-changes) |
| `common-formats--sendgrid-token-segmented-unicode-crlf` | 1 | known benchmark-harness fixture-ID collision; byte-perfect detection confirmed | [#376, "Benchmark fixture-ID collision"](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md#anomalies-not-product-regressions) |

## The 18 detector-coverage misses

This repository's own gate evidence for #376 already named these four
families and this exact fixture-ID shape verbatim (quoted here from that
record; the full measurement has since moved to
[`redact-secret-benchmarks`'s beta.5 results, "Policy changes"](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md#policy-changes),
per [`evidence/376`](../376/README.md)):

> Eighteen `detector-coverage` policy/T3 rows for four of the seven frozen
> families move from a provider finding to silent, matching the reviewed
> contracts frozen by #367: `openai-token-shape-1/2/3` (no `T3BlbkFJ`
> marker), `slack-token-shape-1` (no dash-sectioning), `docker-token-shape-1`
> (32-byte body, contract is exactly 27), `cloudflare-token-shape-1` (no hex
> checksum tail). This is the intended, reviewed behavior change; cases are
> kept, not deleted.

`docs/audits/evidence/367/README.md` independently corroborates the same
four rows in its own audit of the benchmark's policy/T3 samples, one day
earlier, with the same "provider finding removed; intended policy change"
disposition. Each family's own frozen-grammar decision record states the
narrowing and its accepted false-negative cost:
[OpenAI](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md),
[Slack](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md),
[Docker](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md),
and Cloudflare's own module doc
(`crates/secret-scan-core/src/detectors/cloudflare.rs:1-41`, issue #373 under
#367).

Re-verified independently at candidate commit `ec1f86b0c07e` rather than
taken on citation alone:

```
cargo test -p redact-secret detectors::
# 591 passed, 212 filtered out (14 suites)
```

That run includes each family's own unit test asserting rejection of exactly
the now-out-of-contract shape the benchmark's `shape-1/2/3` fixtures exercise:

| Family | Test | Location |
| --- | --- | --- |
| OpenAI | `rejects_the_marker_less_broad_shapes_the_previous_rule_accepted` | `crates/secret-scan-core/src/detectors/openai.rs:325` |
| Slack | `rejects_a_bot_value_missing_the_dash_before_the_secret_section`, `issue_371_twins_are_rejected_and_their_paired_positives_preserved` | `crates/secret-scan-core/src/detectors/slack.rs:237,413` |
| Docker | `docker_distinguishes_unicode_crlf_twins_from_their_paired_positives` | `crates/secret-scan-core/src/detectors/additional_providers.rs:758` |
| Cloudflare | `rejects_a_body_one_byte_short_of_the_documented_length`, `rejects_a_non_hex_checksum` | `crates/secret-scan-core/src/detectors/cloudflare.rs:162,187` |

No detector accepts the pre-freeze shape; none is expected to. The `bare`
and `quoted` contexts fail for the same structural reason as `unicode-crlf`
(the value itself is out of contract, independent of surrounding bytes), so
the same disposition applies to all three contexts per family.

## The one fixed-corpus partial match

This repository's own gate evidence for #376 already documented this exact
symptom (quoted here from that record; the full measurement has since moved
to
[`redact-secret-benchmarks`'s beta.5 results, "Anomalies"](https://github.com/redact-secret/redact-secret-benchmarks/blob/695500611224a434ce89392b97d4107275587079/docs/reports/beta-5/results.md#anomalies-not-product-regressions),
per [`evidence/376`](../376/README.md)):

> **Benchmark fixture-ID collision, not fixed here.** A materialization-path
> collision between `common-formats` and `detector-coverage` fixtures
> sharing an ID causes one `PARTIAL` score against an `EXACT` baseline;
> isolated reproduction confirms byte-perfect detection. Documented in
> `redact-secret-benchmarks`'s `docs/beta-5-results.md` as an open
> follow-up.

`sendgrid.rs` has not changed since `0.1.0-beta.4`
(`git log v0.1.0-beta.4..HEAD -- crates/secret-scan-core/src/detectors/sendgrid.rs`
is empty), so a genuine detection regression in this repository is already
unlikely on that basis alone. Re-verified independently at candidate commit
`ec1f86b0c07e`:

```
cargo test -p redact-secret --test canonical_corpus
# 2 passed (1 suite)
```

This exercises `sendgrid-positive-crlf-host` and `sendgrid-positive-unicode-prefix`
(`conformance/fixtures/synchronous-corpus.json`) — a CRLF-terminated host
line before the assignment, and a 4-byte astral character before it — both
asserted against their exact UTF-8 byte ranges. Both pass. This corroborates,
rather than merely cites, the #376 finding: detection is byte-perfect on the
product side for both a preceding CRLF and a preceding Unicode character:
the harness-side fixture-ID collision is the more likely account of the
`PARTIAL` result, and issue #402's own evidence artifact
(`candidate-evidence-v1.json`) does not carry the real start/end spans that
would be needed to rule that out conclusively from the product side alone.

## What this document does not claim

- It does not compute or confirm the fixture-ID collision's exact mechanism
  in `redact-secret-benchmarks`; that repository's own `docs/beta-5-results.md`
  already tracks it as an open follow-up and owns the fix.
- It does not assert that no product defect could ever exist in these four
  detectors or in SendGrid; it reports what two independent, dated reviews
  (#367, #376) plus this document's own re-run of the relevant test suites at
  the exact candidate commit currently show.
- It is not a `known-gaps.json` record — that lifecycle artifact belongs to
  `redact-secret-benchmarks`, per `decision-govern-benchmark-regression-promotion`.
  This document is the review that record's promotion decision should cite.

## Recommendation

None of the 19 fixtures in #402 warrants a `conformance/benchmark-regressions.json`
entry: that manifest is for a promoted, fixed regression with a fixing
commit, and no fix is needed here. The recommended next step lives in
`redact-secret-benchmarks`: record the 18 `detector-coverage` rows as known,
reviewed gaps citing #367/#376, and resolve or regenerate the one
fixture-ID collision already tracked in its `docs/beta-5-results.md`, rather
than promoting #402 as a release-blocking regression.

## Authority

This document reviews and cross-references existing evidence. It does not
change detector behavior, change #402's state, select a version, create a
tag, publish a package, or authorize any release operation. A release still
requires the explicit approval `AGENTS.md` mandates.
