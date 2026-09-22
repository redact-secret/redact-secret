# Issue #407 — release-regression discovery evidence triage (Docker shape-1)

[Audit archive](../../README.md) ·
[Governance decision](../../../decisions/2026-09-18-govern-benchmark-regression-promotion.md) ·
[Docker Hub PAT/OAT exact-length grammar freeze (#370)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Beta.5 precision gate (#376)](../../../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) ·
[Issue #407](https://github.com/redact-secret/redact-secret/issues/407) ·
[Prior evidence: #367](../367/README.md) ·
[Prior evidence: #376](../376/README.md) ·
[Prior evidence: #402](../402/README.md)

Triaged 2026-09-18 against candidate commit `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
(this repository's `main` at the time #407 was filed). This is a review of
discovery evidence, not a detector change: it adds no fixture, corrects no
grammar, and closes no gate. It changes no code.

## Summary

Issue #407 reports that the `detector-coverage` corpus's Docker shape-1
fixtures — `docker-token-shape-1-bare` (expected `{0,41}`),
`docker-token-shape-1-quoted` (expected `{7,48}`), and
`docker-token-shape-1-unicode-crlf` (expected `{21,62}`) — regress from `EXACT`
(published `0.1.0-beta.4` baseline) to a complete miss (0 findings) at
candidate `fe4f1d1`. **This exact three-row group is already accounted for by
this repository's own prior gate evidence, reviewed the same day (2026-09-18)
the candidate #407 evaluated was itself reviewed under #402.** Nothing new is
found here. No product defect is confirmed, and no code change is made under
this issue.

| Group | Count | Disposition | Prior evidence |
| --- | ---: | --- | --- |
| `docker-token-shape-1-{bare,quoted,unicode-crlf}` | 3 | intended, reviewed policy change | [#367](../367/README.md), [#376](../376/README.md#policy-changes-never-hidden-by-deleting-cases), [#402](../402/README.md) |

## Why this is not a regression

`decision-freeze-precision-contracts-seven-provider-families` (Docker row, #370) narrowed the
`docker-token` detector from beta.4's "recognized prefix plus a shared
20-byte minimum suffix" rule to two independently validated, per-prefix
exact-length shapes:

```
dckr_pat_<exactly 27 bytes from [A-Za-z0-9_-]>   (personal access token)
dckr_oat_<exactly 32 bytes from [A-Za-z0-9_-]>   (organization access token)
```

The `redact-secret-benchmarks` `detector-coverage` fixture generator
(`fixtures/generated/detector-coverage.mjs`) builds `docker-token`'s
`shape-1`/`shape-2` pair from one shared body length for the whole family —
`["docker-token", ["dckr_pat_", "dckr_oat_"], 32]` — applying `32` to *both*
prefixes rather than each prefix's own documented length. `shape-1` is the
first prefix in that array, `dckr_pat_`, so every `shape-1` fixture is
`dckr_pat_` followed by a 32-byte body:

```
dckr_pat_ZByg3TZMUmABS7UvAuqZ7UGqTnUvdlUs   (41 bytes total)
```

reproduced deterministically from the generator's own `synthetic()` seed
(`detector-coverage:docker-token:dckr_pat_`, 32 bytes) — independently
computed here, not taken on citation alone. A 32-byte suffix under
`dckr_pat_` is exactly the shape `decision-freeze-precision-contracts-seven-provider-families`
(Docker row) names as an intentional false negative: "Any `dckr_pat_`/`dckr_oat_` value
whose suffix is not exactly the documented length for its own segment name"
is out of scope by design, the same exact-length precedent `npm-token`,
`google-api-key`, `notion-token`, and `new-relic-user-api-key` already set.
`docs/audits/evidence/402/README.md` names this exact row verbatim:

> `docker-token-shape-1` (32-byte body, contract is exactly 27)

`shape-2` (`dckr_oat_` plus the same generator's 32-byte body) is unaffected:
32 is `dckr_oat_`'s own documented length, so that row still matches exactly
and is not part of this issue's report.

The `bare`, `quoted`, and `unicode-crlf` contexts fail for the same
structural reason: the value itself is out of contract, independent of the
bytes surrounding it, so all three benchmark contexts share one disposition.

`crates/secret-scan-core/src/detectors/additional_providers.rs` has not
changed since `ec1f86b0c07e` (the commit #402 reviewed), nor since `fe4f1d1`
(the candidate #407 itself evaluates), through this repository's current
`main`:

```
git log --oneline ec1f86b0c07e..fe4f1d1 -- crates/secret-scan-core/src/detectors/additional_providers.rs
git log --oneline fe4f1d1..HEAD -- crates/secret-scan-core/src/detectors/additional_providers.rs
# (both empty)
```

so #402's disposition for this row carries forward unchanged to #407's
candidate.

Re-verified independently at candidate `fe4f1d1688450baee402472b1a7f2cc802e2fd79`
rather than taken on citation alone:

```
cargo test -p redact-secret detectors::
# 591 passed, 212 filtered out (14 suites)
```

That run includes the unit test asserting rejection of exactly the
now-out-of-contract shape, across plain and Unicode/CRLF-surrounded
contexts:

| Test | Location |
| --- | --- |
| `docker_distinguishes_unicode_crlf_twins_from_their_paired_positives` | `crates/secret-scan-core/src/detectors/additional_providers.rs:758` |

No code path in `KnownFormatProviderDetector`/`DOCKER` accepts a
non-27-byte `dckr_pat_` suffix; none is expected to.

## What this document does not claim

- It does not assert that no product defect could ever exist in the Docker
  detector; it reports what two independent, dated reviews (#367, #402) plus
  this document's own re-run of `detectors::` and its own reproduction of the
  benchmark's `shape-1` bytes at the exact candidate commit currently show.
- It is not a `known-gaps.json` record — that lifecycle artifact belongs to
  `redact-secret-benchmarks`, per `decision-govern-benchmark-regression-promotion`.
  This document is the review that record's promotion decision should cite.
  Per issue #407's own governance note, the `observed` known-gap record
  (`product-407`) already exists in that repository's `benchmarks/known-gaps.json`;
  this document supplies the product-side review it cites.

## Recommendation

The three fixtures in #407 do not warrant a
`conformance/benchmark-regressions.json` entry: that manifest is for a
promoted, fixed regression with a fixing commit, and no fix is needed here.
The known-gap record already filed in `redact-secret-benchmarks` should cite
#367, #376, #402, and this document rather than #407 being promoted as a
release-blocking regression. Should the benchmark's `detector-coverage`
generator later gain per-prefix body lengths, `docker-token-shape-1` would
become a `dckr_pat_` + 27-byte positive and this disposition would need
re-review at that time — that generator change belongs to
`redact-secret-benchmarks`, not this repository.

## Authority

This document reviews and cross-references existing evidence. It does not
change detector behavior, change #407's state, select a version, create a
tag, publish a package, or authorize any release operation. A release still
requires the explicit approval `AGENTS.md` mandates.
