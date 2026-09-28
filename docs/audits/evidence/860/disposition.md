# Issue #860: final disposition of all 50 candidates

[Tier B re-rank](tier-b-rerank.md) ·
[Tier A index at `270faf8`](https://github.com/redact-secret/redact-secret/blob/270faf84dc12f6a4a4cf61fe3ffab7aadc4f7262/docs/audits/evidence/860/README.md) ·
[Issue #860](https://github.com/redact-secret/redact-secret/issues/860)

This is step 4 of #860, as of 2026-09-28, after all eight maintainer rulings
(R1–R8). Every candidate gets one disposition:

- **distinct family:** a new provider detector with its own finding types;
- **extend existing family:** a change to a detector that already exists;
- **generic coverage sufficient:** the existing generic, JWT or contextual
  detectors are the answer;
- **pending-unsupported:** a lead exists, but no family is proposed now.

Readiness applies to distinct families only. It is READY, ISSUANCE-GATED
(with the property named in the handoff or re-rank) or DATE-GATED.

Tier A rows are taken from the Tier A handoffs at `270faf8`, and Tier B and
Tier C rows from this record. Nothing here is a support-status, recall or
stable claim. Negative findings stay recorded in the per-candidate research
tables on #860.

**Counts:**

| Disposition | Readiness | Count |
| --- | --- | ---: |
| distinct family | READY | 12 |
| distinct family | split: Convex (hex body READY, cloud body gated) | 1 |
| distinct family | ISSUANCE-GATED | 10 |
| distinct family | DATE-GATED | 1 |
| extend existing family | — | 2 |
| generic coverage sufficient | — | 23 |
| pending-unsupported | — | 1 |
| **Total** | | **50** |

The READY families are Doppler, Trigger.dev, E2B, PostHog, Helicone,
Firecrawl, Composio, 1Password, Inngest, Resend, Apify and W&B. The
ISSUANCE-GATED families are Daytona, ClickHouse Cloud, Weaviate, NVIDIA,
PlanetScale, RunPod, Cerebras, Cartesia, Browserbase and Arcade. Baseten is
DATE-GATED.

| # | Candidate | Tier | Disposition | Readiness / basis | Record |
| ---: | --- | --- | --- | --- | --- |
| 01 | `nvidia:ngc-api-key` | B | distinct family | ISSUANCE-GATED: body length and alphabet after `nvapi-` | [re-rank](tier-b-rerank.md#re-rank) |
| 02 | `resend:api-key` | B | distinct family | READY: `re_` + 8 + `_` + 24 (R5) | [resend.md](resend.md) |
| 03 | `fal:api-key` | C | extend existing family (`generic-token` names and schemes; `bearer-token` span) | no provider anchor; the gap is the `FAL_KEY` name and the `Key` scheme | [fal-contextual-gap.md](fal-contextual-gap.md) |
| 04 | `firecrawl:api-key` | A | distinct family | READY | Tier A `firecrawl.md` |
| 05 | `e2b:api-key` | A | distinct family | READY | Tier A `e2b.md` |
| 06 | `browserbase:api-key` | B | distinct family | ISSUANCE-GATED: body length (the R2 regex floor is 5) | [re-rank](tier-b-rerank.md#re-rank) |
| 07 | `modal:token-secret` | C | generic coverage sufficient | the `as-` prefix is too generic for bare detection; `MODAL_TOKEN_SECRET=` is covered by context | step 2 |
| 08 | `cerebras:inference-api-key` | B | distinct family | ISSUANCE-GATED: body length and alphabet after `csk-` | [re-rank](tier-b-rerank.md#re-rank) |
| 09 | `runpod:api-key` | B | distinct family | ISSUANCE-GATED: exact body length (to separate Redirect.pizza `rpa_` + 30) | [re-rank](tier-b-rerank.md#re-rank) |
| 10 | `baseten:api-key` | A | distinct family | DATE-GATED: no `b10_` key before 2026-10-01 15:00 GMT | Tier A `baseten.md` |
| 11 | `sambanova:cloud-api-key` | C | generic coverage sufficient | unprefixed UUID, empirical only | step 2 |
| 12 | `deepinfra:api-token` | C | generic coverage sufficient | no format | step 2 |
| 13 | `apify:api-token` | B | distinct family | READY: `apify_api_` + 20 or more alphanumerics (R2, R4) | [apify.md](apify.md) |
| 14 | `qdrant:cloud-api-key` | C | generic coverage sufficient | JWT (R7) | [re-rank](tier-b-rerank.md#tier-c-rulings-r4r7-applied) |
| 15 | `weaviate:cloud-api-key` | A | distinct family | ISSUANCE-GATED: WCD issuance of the OSS generator format | Tier A `weaviate.md` |
| 16 | `upstash:redis-rest-token` | C | generic coverage sufficient | no literal prefix (R4); the read-only sibling has no lexical marker | step 2 |
| 17 | `cartesia:api-key` | B | distinct family | ISSUANCE-GATED: `.` separator and segment lengths (drift) | [re-rank](tier-b-rerank.md#re-rank) |
| 18 | `stability-ai:api-key` | C | generic coverage sufficient | `sk-` + 48, identical to legacy OpenAI; existing `sk-` handling | step 2; R4 |
| 19 | `assemblyai:api-key` | C | generic coverage sufficient | unprefixed 32 hex | step 2 |
| 20 | `trigger-dev:secret-api-key` | A | distinct family | READY | Tier A `trigger-dev.md` |
| 21 | `nebius:ai-studio-api-key` | C | generic coverage sufficient | JWT (R7, R4) | [re-rank](tier-b-rerank.md#tier-c-rulings-r4r7-applied) |
| 22 | `hyperbolic:api-key` | C | generic coverage sufficient | JWT (R7) | same |
| 23 | `novita:api-key` | C | generic coverage sufficient | `sk_` is shared | step 2 |
| 24 | `luma:api-key` | C | **pending-unsupported** | `luma-` / `luma-api-` prefix T1 by R4; no length; identifier collision | [re-rank](tier-b-rerank.md#tier-c-rulings-r4r7-applied) |
| 25 | `reka:api-key` | C | generic coverage sufficient | no format | step 2 |
| 26 | `hume:api-key` | C | generic coverage sufficient | no format | step 2 |
| 27 | `speechmatics:api-key` | C | generic coverage sufficient | 31 alphanumerics by one example (R5); unprefixed | same |
| 28 | `gladia:api-key` | C | generic coverage sufficient | no format | step 2 |
| 29 | `lambda-cloud:api-key` | C | generic coverage sufficient | `secret_` is shared with Notion legacy | step 2 |
| 30 | `infisical:machine-identity-token` | C | generic coverage sufficient | JWT (R7); the legacy `st.` service token is a retained lead | same |
| 31 | `composio:api-key` | A | distinct family | READY for `ak_`, `oak_` and `uak_`. Tier A lifts step 2's `uak_` gate under R6, and the maintainer is asked to confirm it | Tier A `composio.md` |
| 32 | `daytona:api-key` | A | distinct family | ISSUANCE-GATED: code private since v0.190.0 | Tier A `daytona.md` |
| 33 | `arcade:api-key` | B | distinct family (`arc_proj_` only) | ISSUANCE-GATED: sub-prefix, length and alphabet. Bare `arc_` is not selected (shared prefix) | [re-rank](tier-b-rerank.md#re-rank) |
| 34 | `helicone:api-key` | A | distinct family | READY | Tier A `helicone.md` |
| 35 | `portkey:api-key` | C | generic coverage sufficient | no format | step 2 |
| 36 | `braintrust:api-key` | C | generic coverage sufficient | `sk-` + 40 or more is T1 by R2 (provider-authored), but has no signal independent of legacy OpenAI; `bt-st-` is an open lead | [re-rank](tier-b-rerank.md#r2-authorship-checks) |
| 37 | `wandb:api-key` | B | distinct family (`wandb_v1_`) | READY: `wandb_v1_`, 86 total, `[A-Za-z0-9_]` (R1, R5); legacy 40-hex stays generic | [wandb.md](wandb.md) |
| 38 | `posthog:personal-api-key` | A | distinct family | READY | Tier A `posthog.md` |
| 39 | `onepassword:service-account-token` | B | distinct family | READY: `ops_eyJ` + Base64url, variable, floor 250 (R5) | [onepassword.md](onepassword.md) |
| 40 | `doppler:service-token` | A | distinct family | READY (seven `dp.<type>.` types) | Tier A `doppler.md` |
| 41 | `mongodb-atlas:programmatic-api-key` | C | generic coverage sufficient | unprefixed UUID (the style guide is excluded by R5); `mdb_sa_sk_` is a retained sibling lead | [re-rank](tier-b-rerank.md#tier-c-rulings-r4r7-applied) |
| 42 | `clickhouse-cloud:api-key` | A | distinct family | ISSUANCE-GATED: 42 vs 39 unresolved | Tier A `clickhouse-cloud.md` |
| 43 | `planetscale:service-token` | B | distinct family | ISSUANCE-GATED: today's suffix length inside 32–64 (R3, 2022) and alphabet | [re-rank](tier-b-rerank.md#re-rank) |
| 44 | `aiven:authentication-token` | C | generic coverage sufficient | no prefix; Base64 alphabet only | step 2 |
| 45 | `turso:database-auth-token` | C | generic coverage sufficient | JWT (R7) | [re-rank](tier-b-rerank.md#tier-c-rulings-r4r7-applied) |
| 46 | `redis-cloud:api-key` | C | generic coverage sufficient | `A`/`S` + 50 by CLI help example (R5); a one-letter lead cannot anchor | same |
| 47 | `algolia:admin-api-key` | C | generic coverage sufficient | 32 lowercase hex (R1, R5), but Admin and Search-only keys are lexically identical | same |
| 48 | `convex:deployment-key` | B | distinct family | **split:** READY for hex-body keys (R1); ISSUANCE-GATED for the cloud `eyJ2` body (R4) | [convex.md](convex.md) |
| 49 | `clerk:secret-key` | C | extend existing family (disambiguate from `stripe_credential`) | redacted today, but under the wrong family; separating it needs an issued body length and context | step 2 |
| 50 | `inngest:signing-key` | B | distinct family | READY: `signkey-(prod\|test\|branch)-` + 64 lowercase hex (R5) | [inngest.md](inngest.md) |

"Step 2" means the
[step-2 selection comment](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852451907).
The Tier A family files live beside the Tier A index linked above.
