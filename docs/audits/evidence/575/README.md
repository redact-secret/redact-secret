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
[redact-secret-benchmarks evidence/575](https://github.com/redact-secret/redact-secret-benchmarks/blob/2849733f66479441a812891f2a32b69fcca3b697/evidence/575/README.md).
It is linked at the benchmark branch commit; re-pin the link to the `main`
merge commit once `workbench/112-retier-provider-families` merges. Its
one-line result:

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

## Not done yet

- **Clean-main measurement.** The run above is candidate mode, on branches.
  The epic's final measurement must be repeated after this branch and
  benchmarks `workbench/112-retier-provider-families` merge. The published
  matrix also needs the release, because #707 and #708 are unreleased.
- **Published-mode ledger ids.** `queue:check` in the benchmark repo still
  lists 3 `new-relic-license-key` and 3 `microsoft-entra-client-secret` ids
  that exist only in published mode. Settle them before the published matrix
  is regenerated.
- **`benchmark-gap-708` in `conformance/benchmark-regressions.json`.** The
  benchmark fixture ids for #708 are not yet in the vendored pin manifest, so
  the record can only be added after benchmarks main includes them and
  `npm run benchmark-pins:sync` runs. The product-conformance and
  benchmark-revalidation gates for `benchmark-gap-707` stay `pending` until
  evidence is linked from merged commits.
- **Contract review text.** The benchmark contracts' `review` text still
  describes the #707 and #708 misses as current. Update it when the known
  gaps move to `fixed`.
- **Support matrix docs.** `docs/support-matrix.md`, README and CHANGELOG
  support counts follow the published matrix. Update them at the pin sync
  after release, not from this candidate run.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
