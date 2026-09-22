# Issue #376 — beta.5 precision gate

[Audit archive](../../README.md) ·
[Decision record](../../../decisions/2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md) ·
[Issue #376](https://github.com/redact-secret/redact-secret/issues/376) ·
[Benchmark comparison document](https://github.com/redact-secret/redact-secret-benchmarks/pull/13)

This directory holds this repository's own gate evidence: aggregate
provenance and counts only. It never contains a raw per-fixture result
bundle — per
[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)'s
own governance, "[d]o not copy a discovery matrix, generated variants,
competitor observations, holdout material, or raw result bundles into
`redact-secret`." The full 612-row candidate evidence, fixture-ID mapping,
and anomaly analysis live in that repository's
[`docs/beta-5-results.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/beta-5-results.md)
(PR [#13](https://github.com/redact-secret/redact-secret-benchmarks/pull/13)).

## Candidate measurement provenance

| Field | Value |
| --- | --- |
| Candidate product commit | `a637ac1c156a05630243185a6adccadc28f5a1ab` (clean at measurement time; two Rust `#[cfg(test)]`-only commits behind this gate's own HEAD, no production code changed) |
| Benchmark commit | `c1f777ae20bb38c105a615ffa28005f64d4d6596` (clean, `redact-secret-benchmarks` `main` HEAD) |
| Corpus SHA-256 | `c896dc80d571ae8dbb2dbe567468b825cf0152711c4bb59f7645644de6520e1f` |
| Run ID | `808cd7dd-b356-4bdf-9521-9045b4893900`, `complete`, 612/612 fixtures, 0 failures |
| Baseline compared | `0.1.0-beta.4` |

## Fixed-corpus result (`common-formats`, 114 fixtures — this issue's tracked metric)

| Metric | Before (beta.4) | After (candidate) |
| --- | ---: | ---: |
| Twin false alarms (of 56 must-not-flag rows) | 24 | 0 |
| Twin discrimination | 32 / 56 | 56 / 56 (target met) |
| Required-positive misses (58 T1/T2 positives) | 0 | 0 |

Every one of the 24 twins was already authored `expected: []` under beta.4 —
the candidate's own flagged/silent outcome changed, not the expectation. No
must-not-flag classification was corrected by the #367 contract audit, so
there is no frozen-baseline-vs-corrected-contract split to report for this
specific 24→0 result: it is a genuine detection change. See
[`docs/audits/evidence/367/README.md`](../367/README.md) for the twelve
underlying mutations and their contract basis, and
[`beta4-twin-baseline.json`](../367/beta4-twin-baseline.json) for the frozen
per-fixture baseline this candidate is compared against.

## Expanded-corpus result (498 fixtures)

| Metric | Before | After |
| --- | ---: | ---: |
| Negative flags | 0 | 0 |
| Required-positive misses (168 T1/T2 positives) | 0 | 0 |
| Policy/T3 rows newly silent | — | 18 / 158 (intended policy change; see below) |

7 DigitalOcean `detector-coverage` rows (added by
`redact-secret-benchmarks#10` after the beta.4 baseline was captured) have no
beta.4 comparison point and are reported distinctly, never scored as
regressions.

## Policy changes (never hidden by deleting cases)

Eighteen `detector-coverage` policy/T3 rows for four of the seven frozen
families move from a provider finding to silent, matching the reviewed
contracts frozen by
[#367](https://github.com/redact-secret/redact-secret/blob/main/docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md):
`openai-token-shape-1/2/3` (no `T3BlbkFJ` marker), `slack-token-shape-1` (no
dash-sectioning), `docker-token-shape-1` (32-byte body, contract is exactly
27), `cloudflare-token-shape-1` (no hex checksum tail). This is the intended,
reviewed behavior change; cases are kept, not deleted.

## T1/T3 negative preservation

No new collateral redaction. Existing T1/T3 negatives (6 and 104 files) stay
at zero flags, unaffected by the seven contract fixes.

## Release-qualification accuracy corpus re-pin

`assessment/fixtures/accuracy-corpus.json` (release-qualification protocol,
[`decision-define-cross-language-evaluation-protocol`](../../../decisions/2026-09-12-define-cross-language-evaluation-protocol.md)
— a separate, bounded cross-language measurement, not another discovery
benchmark) had four fixtures whose OpenAI/DigitalOcean/Docker/Cloudflare/
Hugging Face/Linear/Slack values predated the seven frozen contracts,
explicitly deferred to this gate by the
[OpenAI](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) and
[Docker](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)
decision records. This gate corrects `code-openai-api-key`,
`logs-additional-provider-tokens-one`, `code-additional-provider-tokens-one`,
and `chat-additional-provider-tokens-one` to their contracted grammars and
re-pins `assessment/acceptance-criteria.json` and
`assessment/acceptance-criteria-linux-x64.json`. Accuracy counts are
unchanged in value (21 true positives / 1 false positive / 5 false negatives
/ 0 policy mismatches, identical across all five required surfaces both
before and after, on macOS and on Linux x86_64) — only the corpus's byte
content and hash moved. The five false negatives are pre-existing and
unrelated to the seven provider families (`github-token` ×2, `generic-token`,
`aws-access-key`, `bearer-token`); confirmed present, unchanged, against the
original unrewritten fixtures before this fix was committed. See
[`assessment/results/complete-v4/README.md`](https://github.com/redact-secret/redact-secret/blob/de6add470321f40d7b1cb36808d9f4559e6c2e99/assessment/results/complete-v4/README.md)
and
[`assessment/results/complete-linux-x64-v4/README.md`](https://github.com/redact-secret/redact-secret/blob/de6add470321f40d7b1cb36808d9f4559e6c2e99/assessment/results/complete-linux-x64-v4/README.md)
(both removed by [#603](https://github.com/redact-secret/redact-secret/issues/603);
performance results, criteria, and judgement now belong to
`redact-secret-benchmarks`) for the full re-pin evidence, including a
discovered, out-of-scope performance-threshold gap (below).

## Required checks

`npm run ci` (decisions:validate, precision-contracts:check, coverage:check,
assessment:check, and every other constituent check), `cargo fmt --all
--check`, `cargo clippy`, and `cargo test` all pass at this gate's HEAD. In
`redact-secret-benchmarks`: `npm run fixtures:check`, `npm test` (164/164),
`npm run test:integration` (6/6), `npm run bench -- --strict` (27/27), and
`npm run build` all pass, after a required harness fix (below).

## What this evidence does not claim, and remaining limitations

- **Benchmark-harness `locate()` ambiguity, fixed.** A newly-added
  `redact-secret-benchmarks#10` fixture placing the same secret twice on one
  line made Gitleaks and TruffleHog's comparison adapter throw, failing
  `bench --strict` for reasons unrelated to any redact-secret change.
  Fixed in `redact-secret-benchmarks` PR
  [#13](https://github.com/redact-secret/redact-secret-benchmarks/pull/13).
- **Benchmark fixture-ID collision, not fixed here.** A materialization-path
  collision between `common-formats` and `detector-coverage` fixtures sharing
  an ID causes one `PARTIAL` score against an `EXACT` baseline; isolated
  reproduction confirms byte-perfect detection. Documented in
  `redact-secret-benchmarks`'s `docs/beta-5-results.md` as an open follow-up.
- **Stale `detector-coverage` generic fixtures, not fixed here.** The four
  narrowed providers' generic `detector-coverage` fixtures predate the
  reviewed contracts and need regenerating on the benchmark side; documented
  in the same anomalies section.
- **A pre-existing, out-of-scope performance-threshold gap was discovered,
  not fixed here.** Every non-Rust surface (Python, Node, browser
  WebAssembly, CLI) currently misses its fixed processing-time and
  throughput thresholds in `assessment/acceptance-criteria.json` by roughly
  20-30%, reproduced on real macOS hardware outside any development sandbox.
  Rust shows the same absolute timing but has far more threshold margin.
  This is independent of the accuracy-corpus fixtures this gate touches (they
  are not performance-profile inputs) and of the seven provider-detector
  changes (which narrow existing grammars, not add scanning work); it most
  plausibly reflects growth in per-scan overhead since the thresholds were
  fixed at commit `a356e702e59b03cf297e0af15ba0423bc8466d48`. Not
  re-derived or hidden by this gate — see
  `assessment/results/complete-v4/README.md` for the full analysis and a
  recommended follow-up investigation. The Linux x86_64 profile is
  unaffected: its performance thresholds pass cleanly on the qualified
  `ubuntu-latest` runner.

No aggregate cross-tier accuracy or ranking is computed anywhere in this
evidence. No credential was verified against a live provider.
