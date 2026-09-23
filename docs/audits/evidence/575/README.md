# Epic A #575 — portfolio, second stabilization batch and qualification

[Audit archive](../../README.md) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[First batch #642](../642/README.md) ·
[Benchmarks counterpart redact-secret-benchmarks#112](https://github.com/redact-secret/redact-secret-benchmarks/issues/112) ·
[Spec: detector families](../../../specs/detector-families.md)

Written 2026-09-23 on branch `workbench/575-epic-a-final-batch`. Every value
used in detector and corpus checks was a deterministic synthetic value. This
record contains no credential value.

## Result

PASS. The benchmark measurement is frozen at
[redact-secret-benchmarks evidence/575](https://github.com/redact-secret/redact-secret-benchmarks/blob/186e6e7053195ad14ebecf823c1cb269d3496654/evidence/575/README.md).
It is pinned to benchmarks `main` at the PR #178 merge commit. Its one-line
result:

> All seven selected taxonomy families are `stable`, so 15 existing families
> have now moved from `provisional` to `stable` against the beta.6 baseline
> (8 in #642, 7 here). None of the 41 previously stable existing families
> regressed. The full 93-family matrix reports 49 `stable`. The candidate
> misses no T1/T2 expected span (0 leaked), and the three Microsoft Entra
> leading-dash misses that blocked #642 are fixed.

## Portfolio

The epic requires exactly 15 existing families (present in the 79-family
beta.6 taxonomy), split into 10 efficiency and 5 market-value candidates.
New #574 families such as `netlify:personal-access-token`,
`confluent:cloud-api-secret` and `heroku:oauth-access-token` do not count
toward the 15, even when they are `stable`.

### Market value (5)

The #575 formula weights runtime/AI exposure 30%, credential impact 25%,
remaining gate distance 25%, provider usage 10% and shared-detector
efficiency 10%. Each criterion is scored 1–5 by judgement. Gate distance is
measured from the #642 support run.

| Taxonomy family | AI/runtime exposure | Credential impact | Gate distance | Usage | Shared detector | Weighted |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `anthropic:secret-api-key` | 5 | 4 | 4 | 4 | 1 | 4.00 |
| `google:generic-api-key` | 4 | 4 | 4 | 5 | 1 | 3.80 |
| `huggingface:api-token` | 5 | 3 | 2 | 3 | 1 | 3.15 |
| `microsoft-entra:application-client-secret` | 3 | 5 | 1 | 4 | 1 | 2.90 |
| `azure-devops:personal-access-token` | 3 | 5 | 4 | 3 | 1 | 3.55 |

Entra has the longest remaining path: it needed a product fix (#707) to clear
its twin, metamorphic and mutation failures. It is included for its
credential impact (tenant application authentication), and because that fix
was also the last global leaked-span blocker.

### Efficiency (10)

| Taxonomy family | Batch | Remaining path when selected |
| --- | --- | --- |
| `linear:personal-api-key` | #642 | T1 re-tier; twins and ledger per [#642](../642/README.md) |
| `notion:legacy-integration-token` | #642 | T1 re-tier; twins and ledger per [#642](../642/README.md) |
| `new-relic:user-api-key` | #642 | T1 re-tier; twins and ledger per [#642](../642/README.md) |
| `grafana:cloud-access-policy-token` | #642 | T1 re-tier; twins and ledger per [#642](../642/README.md) |
| `grafana:service-account-token` | #642 | T1 re-tier; twins and ledger per [#642](../642/README.md) |
| `datadog:api-key` | this batch | T1 + ledger (shared-provider cluster) |
| `datadog:application-key` | this batch | 3 twins + 1 benign + ledger (already T1) |
| `new-relic:license-key` | this batch | T1 + ledger |
| `docker:personal-access-token` | this batch | T1 + ledger (shared-detector cluster) |
| `docker:oauth-access-token` | this batch | T1 + OAT width fix (#708) + ledger (shared-detector cluster) |

### Why these seven for the second batch

The candidates were limited to existing families with a provider-domain
source from the #643–#662 research. Families whose verdict was "not found"
(#643 without a ruling, #646, #649, #651, #653, #657, #660, #661), or whose
source class is still waiting on a ruling that has no precedent (#650, #652,
#658, #659, #662), were left out. The remaining pool was datadog ×2,
new-relic license, huggingface, entra and docker ×2, which is exactly seven.
`api_org_` stays outside the Hugging Face contract, so its missing source
does not block the `hf_` family.

Two T1 sources rest on SDK-reference material on the provider's own domain:
Entra (#655, an example) and Hugging Face (#654, a type annotation). The
benchmark contracts record that accepting them is the maintainer's ruling,
on the same footing as `google:generic-api-key`'s example source (#642).

## Product fixes in this batch

Both fixes went through the promotion lifecycle
(`decision-govern-benchmark-regression-promotion`). For each, a benchmark
known gap was recorded as `promoted` before the fix, and the exact fixed
candidate was rerun.

| Issue | Change | Canonical fixtures | Benchmark rerun |
| --- | --- | --- | --- |
| [#707](https://github.com/redact-secret/redact-secret/issues/707) | `microsoft-entra-client-secret`: the three bytes before `<digit>Q~` take `[A-Za-z0-9_.~-]`, the suffix alphabet; the outer boundary is unchanged | `microsoft-entra-client-secret-leading-dash-{bare,assignment,crlf-unicode,joined-identifier}` | 3 former MISS fixtures report EXACT |
| [#708](https://github.com/redact-secret/redact-secret/issues/708) | `docker-token`: `dckr_oat_` accepts exactly 27 or 32 body bytes (new `RunLength::OneOf`); `dckr_pat_` still takes exactly 27 | `docker-oat-{27-byte-body-dotenv,27-byte-body-crlf-unicode,26-byte-body-rejected,28-byte-body-rejected}`; `docker-boundary-pat-length-under-oat-prefix` is now a supported positive | new `oat-27` fixtures report EXACT; 26/28 twins clean |

Trade-offs:

- **#707.** Removes a false negative on secrets the portal and CLI issue.
  Precision is unchanged at the edges, because a `-` or an alphanumeric byte
  directly before the leading run still rejects the match.
- **#708.** Removes a false negative on the width Docker's own example uses.
  The added false-positive surface is a 27-byte body after the literal
  `dckr_oat_` prefix, which is provider-specific.
- **Left open on both.** The marker digit and total length are not coupled
  (#161). A fresh OAT has not been measured empirically (#647).

Product source: `023367441dfa3314cd19890fed2ef68281ada5fd`. At that commit
the Rust workspace (0 failures), the JS test suites (node and wasm), the
conformance schema/regression tests, `coverage:check` and the doc checks all
pass.

## Qualification against the epic's Definition of done

| Gate | Result |
| --- | --- |
| Exactly 15 selected existing families move to `stable` in one final measurement | Met in candidate mode: classify run `6e727b2f-dd5b-4aac-ae6d-1b1c7e887248` shows all 15 `stable` |
| 10 efficiency + 5 market value, with evidence and binding gates | This record, plus the per-family research records #642–#662 |
| No previously stable family regresses | 0 regressions against #642's 42-stable matrix, which includes all 33 beta.6 baseline families |
| T1/T2 leaked span rate 0 | 0 `MISS` in candidate run `20414439-a9a6-4977-87b6-cbb0bc27f8c2` |
| No stable claim derived by adding per-issue estimates | Every count above comes from one classify run |
| Product findings follow the promotion lifecycle | #707 and #708, with `product-707` and `product-708` known gaps |
| Exact source and benchmark provenance | Product `0233674`, benchmark `55c65e6` (candidate) and `6e2567d` (classify); gitleaks 8.30.1 and trufflehog 3.97.4 |
| #574 committed families at `provisional` or better | Yes; `heroku:oauth-access-token` is `stable` |
| No plaintext or real-derived credential material | None in this record, the benchmark evidence or the ledger notes |

## Update 2026-09-23: clean-main qualification and follow-ups

Both branches merged: this repository's PR #709 as main `44bb3d6` (fix commit
`dc855b6`), and redact-secret-benchmarks PR #178 as main `186e6e7`. Both merges
rewrote the branch commits named above. The measurement was repeated at the two
clean mains with the same pinned scanners:

- **Candidate run** `a9862a93-f185-4abf-94fd-a71d17504fd8`: 1,466 of 1,466
  fixtures, corpus hash unchanged, 0 `MISS`.
- **Pinned candidate-mode classification** `715d2d8e-0862-4ba8-9ef2-18b90091030c`:
  49 `stable`, identical family for family to the branch run, 0 regressions.

The raw records are in the benchmark evidence's `clean-main/` addendum (benchmark
follow-up branch `workbench/575-post-merge-follow-ups`).

Follow-ups closed:

- `benchmark-gap-707` and the new `benchmark-gap-708` in
  `conformance/benchmark-regressions.json` record the fix commit, and both gates
  are `passed`: main CI job links for product conformance, and the benchmark
  evidence for revalidation. Known gaps `product-707` and `product-708` are
  `fixed` in the benchmark repository, and the contract `review` text no longer
  describes them as current misses.
- The benchmark pin manifest named a pre-merge branch revision (`d22fd86`), which
  broke this repository's `Benchmark pin drift` job on main. The benchmark
  follow-up re-points it to `186e6e7`, and this repository vendors that copy.
- The evidence links are re-pinned to benchmarks `main`.
- The benchmark follow-up settles 12 candidate-mode ledger rows for
  netlify and confluent. The vendored `benchmarks/support-matrix.json` is
  now run `8a2e90a9` (benchmarks `43b2d61`): 51 `stable`, i.e. 36 + 15.
  `docs/support-matrix.md`, the README summary and CHANGELOG are regenerated
  from it.

Still open, and not closable before a release:

- **Published-mode status.** A published-mode classification at benchmarks
  main (`3797613a`, default product = published 0.1.0-beta.6) reports 43
  `stable`. Entra, Docker, New Relic license and Datadog application key stay
  `provisional` there, because beta.6 does not contain their detector changes.
  Their open ledger rows (including the six New Relic license and Entra ids
  noted earlier) are real beta.6 misses. They can only be settled against a
  published beta.7.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
