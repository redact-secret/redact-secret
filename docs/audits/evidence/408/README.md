# Issue #408 — release-regression discovery evidence triage (Cloudflare shape-1)

[Audit archive](../../README.md) ·
[Governance decision](../../../decisions/2026-09-18-govern-benchmark-regression-promotion.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Beta.5 precision gate (#376)](../../../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) ·
[Issue #408](https://github.com/redact-secret/redact-secret/issues/408) ·
[Prior evidence: #367](../367/README.md) ·
[Prior evidence: #376](../376/README.md) ·
[Prior evidence: #402](../402/README.md)

Triaged 2026-09-18 against candidate commit `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
(this repository's `main`). This is a review of discovery evidence, not a
detector change: it adds no fixture, corrects no grammar, and closes no gate.
It changes no code.

## Summary

Issue #408 reports that the `detector-coverage` corpus's Cloudflare shape-1
fixtures — `cloudflare-token-shape-1-bare` (expected `{0,45}`),
`cloudflare-token-shape-1-quoted` (expected `{7,52}`), and
`cloudflare-token-shape-1-unicode-crlf` (expected `{21,66}`) — regress from
`EXACT` (published `0.1.0-beta.4` baseline) to a complete miss (0 findings) at
candidate `fe4f1d1`. **This exact three-row group is already accounted for by
this repository's own prior gate evidence, recorded the same day (2026-09-18)
as, or before, the candidate #408 evaluated: it was independently reviewed
under #402 with the identical disposition.** Nothing new is found here. No
product defect is confirmed, and no code change is made under this issue.

| Group | Count | Disposition | Prior evidence |
| --- | ---: | --- | --- |
| `cloudflare-token-shape-1-{bare,quoted,unicode-crlf}` | 3 | intended, reviewed policy change | [#367](../367/README.md), [#376](../376/README.md#policy-changes-never-hidden-by-deleting-cases), [#402](../402/README.md) |

## Why this is not a regression

`decision-freeze-precision-contracts-seven-provider-families` (#367, via
child issue #373) narrowed the `cfut_` shape from beta.4's "recognized prefix
plus a 20-byte minimum suffix" rule to the reviewed grammar
`cfut_[A-Za-z0-9]{40}[0-9a-f]{8}` — a `cfut_` prefix, an exact 40-byte
alphanumeric body, and an exact 8-byte lowercase-hex checksum tail (module
doc, `crates/secret-scan-core/src/detectors/cloudflare.rs:1-41`). The full
contracted shape is 5 + 40 + 8 = 53 bytes after the match start; issue #408's
three fixtures are all 45 bytes wide (`{0,45}`, `{52-7,52}=45`,
`{66-21,66}=45`), i.e. `cfut_` plus a 40-byte body with **no** checksum tail
— exactly the retired shape the module doc names verbatim as an intentional
false negative:

> A body one byte short of 40 (the beta.4 `cloudflare-token-user-plain-twin`
> regression shape) and a non-hex or uppercase-hex checksum ... are now
> intentional false negatives instead of matches.

`docs/audits/evidence/376/README.md` ("Policy changes") and
`docs/audits/evidence/367/README.md` both independently name this exact
fixture-ID family verbatim, one and two days before #408 was filed:

> Eighteen `detector-coverage` policy/T3 rows for four of the seven frozen
> families move from a provider finding to silent, matching the reviewed
> contracts frozen by #367: ... `cloudflare-token-shape-1` (no hex checksum
> tail). This is the intended, reviewed behavior change; cases are kept, not
> deleted.

`docs/audits/evidence/402/README.md` re-triaged the identical three-row
group (`cloudflare-token-shape-1-{bare,quoted,unicode-crlf}`) at candidate
`ec1f86b0c07e`, with the same "intended, reviewed policy change" disposition.
The `bare`, `quoted`, and `unicode-crlf` contexts fail for the same
structural reason: the value itself is out of contract (no checksum
segment), independent of the bytes surrounding it, so all three benchmark
contexts share one disposition.

`crates/secret-scan-core/src/detectors/cloudflare.rs` has not changed since
`ec1f86b0c07e` (the commit #402 reviewed) or since `fe4f1d1` (the candidate
#408 evaluated):

```
git log --oneline ec1f86b0c07efc10ecbbd9fa22d7083f8982b942..HEAD -- crates/secret-scan-core/src/detectors/cloudflare.rs
# (empty)
git log --oneline fe4f1d1688450baee402472b1a7f2cc802e2fd79..HEAD -- crates/secret-scan-core/src/detectors/cloudflare.rs
# (empty)
```

so #402's disposition carries forward unchanged to #408's candidate.

Re-verified independently at candidate `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
(via this repository's current `main`, which contains that commit) rather
than taken on citation alone:

```
cargo test -p redact-secret detectors::cloudflare
# 19 passed, 784 filtered out (14 suites)
```

That suite includes the unit tests asserting rejection of exactly the
now-out-of-contract shape-1 body, across plain and length/alphabet-mutated
contexts:

| Test | Location |
| --- | --- |
| `rejects_a_body_one_byte_short_of_the_documented_length` | `crates/secret-scan-core/src/detectors/cloudflare.rs:162` |
| `rejects_a_non_hex_checksum` | `crates/secret-scan-core/src/detectors/cloudflare.rs:187` |
| `finds_a_match_across_crlf_and_a_unicode_prefix` | `crates/secret-scan-core/src/detectors/cloudflare.rs:253` |

No code path in `CloudflareTokenDetector` accepts a checksum-less `cfut_` +
40-byte body; none is expected to. The last of the three tests above confirms
the detector still finds the *contracted* shape across a CRLF line ending and
a preceding Unicode character — the surrounding-byte handling exercised by
the `unicode-crlf` context is intact; only the out-of-contract value itself
is silent.

## What this document does not claim

- It does not assert that no product defect could ever exist in the
  Cloudflare detector; it reports what three independent, dated reviews
  (#367, #376, #402) plus this document's own re-run of
  `detectors::cloudflare` at the exact candidate commit currently show.
- It is not a `known-gaps.json` record — that lifecycle artifact belongs to
  `redact-secret-benchmarks`, per `decision-govern-benchmark-regression-promotion`.
  This document is the review that record's promotion decision should cite.
  Per issue #408's own governance note, the `observed` known-gap record
  already exists in that repository's `benchmarks/known-gaps.json`; this
  document supplies the product-side review it cites.

## Recommendation

The three fixtures in #408 do not warrant a
`conformance/benchmark-regressions.json` entry: that manifest is for a
promoted, fixed regression with a fixing commit, and no fix is needed here.
The known-gap record already filed in `redact-secret-benchmarks` should cite
#367, #376, #402, and this document rather than #408 being promoted as a
release-blocking regression.

## Authority

This document reviews and cross-references existing evidence. It does not
change detector behavior, change #408's state, select a version, create a
tag, publish a package, or authorize any release operation. A release still
requires the explicit approval `AGENTS.md` mandates.
