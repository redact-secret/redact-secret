# Issue #654 — T1 provider evidence for `huggingface:api-token`

[Audit archive](../../README.md) ·
[Issue #654](https://github.com/redact-secret/redact-secret/issues/654) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 1](https://github.com/redact-secret/redact-secret/issues/654#issuecomment-5784926544) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/654#issuecomment-5785640146) ·
[Hugging Face contract freeze](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Benchmarks counterpart redact-secret-benchmarks#112](https://github.com/redact-secret/redact-secret-benchmarks/issues/112)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND, for the `hf_` user variant (prefix; length on example strength)

A huggingface.co source states the `hf_` prefix. A provider-published OpenAPI
example fixes a 34-character body length, on example strength only. The body
alphabet is not provider-stated. The `api_org_` variant in the same contract
has no current provider-domain source.

| property (`user` variant, `hf_[A-Za-z0-9]{34}`) | provable at T1 | basis |
| --- | --- | --- |
| prefix `hf_` | yes | SDK reference type on huggingface.co (`hf_${string}`) |
| body length 34 | yes, example strength only | Hub OpenAPI revoke-endpoint example: `hf_` + 34 placeholder characters; the schema says only `minLength` 1, `maxLength` 200 |
| body alphabet `[A-Za-z0-9]` | no | example placeholder is one repeated letter; no prose. A retired provider Space validator used `[a-zA-Z0-9]` (see below), but that is code, not documentation |
| delimiter (no `_`/`-` in body) | no | the provider documents other `hf_…_` tokens (`hf_oauth_…`, `hf_jwt_…`), so a post-prefix `_` is not provably "not Hugging Face" |
| marker / checksum | no | none documented anywhere |
| `api_org_` variant prefix | no | only a 2021 archived provider page shows the placeholder `api_org_XXXXXXX`; the current SDK rejects org tokens at login |

Reviewer call carried over from pass 1: the prefix source is a TypeScript
type annotation rendered in the provider's SDK reference, not a prose
paragraph. This document reads it as "the provider documents the lexical
shape" under the T1 bar in `benchmarks/lib/assessment.ts`. The bar itself is
unchanged. Whoever re-tiers the family should confirm that reading.

## The source

**Prefix.** `https://huggingface.co/docs/huggingface.js/hub/modules` (also
served as `…/hub/modules.md`), the `@huggingface/hub` SDK reference, section
Type Aliases → `AccessToken`. Re-fetched 2026-09-23 (HTTP 200):

> **AccessToken**: `string` Actually `hf_${string}`, but for convenience, using the string type

The page links its source, `packages/hub/src/types/public.ts:28` in
`huggingface/huggingface.js`. `observedAt`: 2026-09-23 (first observed
2026-09-22).

**Length (example only).** `https://huggingface.co/.well-known/openapi.json`
(OpenAPI 3.1.0, `info.version` 0.0.1; linked from
`https://huggingface.co/docs/hub/api`), operation
`POST /api/credentials/revoke`, summary "Revoke leaked tokens". Re-fetched
2026-09-23: the only `hf_` example is `hf_` followed by 34 characters, all one
letter repeated. Schema bounds are `minLength` 1 and `maxLength` 200. Under
the DigitalOcean precedent (#367, "the examples establish length only"), this
fixes the length and nothing else.

**Candidate, not relied on.** The Hugging Face-owned Space
`huggingface.co/spaces/huggingface/inference-playground` at revision
`ed1ed33727ecf4dfa47edd91ffc79aa4f26ed36e` (commit "regex check validity of hf
token", 2024-07-25, author `mishig`), file
`src/lib/components/InferencePlayground/InferencePlayground.svelte` line 137,
re-fetched 2026-09-23 from the provider domain:

> `const RE_HF_TOKEN = /\bhf_[a-zA-Z0-9]{34}\b/;`

with the failure text "Please provide a valid HF token." The file no longer
exists at `main` (the check was removed in `8cfdfbf`, 2025-10-20). It is
provider-authored code hosted on the provider's domain, but it is application
code in a retired revision, not documentation. This document does not treat it
as meeting the bar for the alphabet. Whether it does is a reviewer decision for
the re-tier batch.

## Proposed `covers` sentence

> Hugging Face's SDK reference on huggingface.co types the user access token
> as `hf_${string}`, establishing the `hf_` prefix, and the provider's Hub
> OpenAPI spec (`/.well-known/openapi.json`, `POST /api/credentials/revoke`)
> gives a raw access-token example of `hf_` followed by 34 placeholder
> characters, which establishes the 34-character body length on example
> strength only. The `[A-Za-z0-9]` body alphabet is not provider-stated and
> remains a support-policy union of the tool alphabets (gitleaks letters only,
> trufflehog alphanumeric). The `api_org_` variant is not covered by this
> provider source.

## Contradictions with the current contract

Contract (`docs/contracts/precision/precision-contracts.json`, detector
`huggingface-token`; implementation
`crates/secret-scan-core/src/detectors/additional_providers.rs` `HUGGING_FACE`,
`PrefixShape::exact("hf_", 34, is_alnum)` and
`PrefixShape::exact("api_org_", 34, is_alnum)`, boundary `is_alnum_dash`):

- **`user` variant `hf_[A-Za-z0-9]{34}`: no contradiction.** Prefix and length
  agree with the provider sources. The alphabet is wider than every observed
  sample (all letters only) and every letters-only tool, and identical to the
  provider's own retired validator and to three other provider-authored code
  sites recorded in the broad-discovery pass. No source says digits never
  occur.
- **Stale source record.** The contract's `huggingface-docs-tokens` source
  (`observedAt` 2026-09-17) and the `user` prefix basis "provider (placeholder
  `hf_...`)" predate this evidence. The re-tier batch would add the SDK
  reference and OpenAPI sources; this document does not edit them.
- **`organization-token` variant `api_org_[A-Za-z0-9]{34}`.** No current
  provider-domain source states it. The only provider-domain text is an
  archived 2021 quick-tour page
  (`web.archive.org/web/20210506064850/https://api-inference.huggingface.co/docs/python/html/quicktour.html`,
  re-fetched 2026-09-23: "You should see a token api_XXXXXXXX or
  api_org_XXXXXXX."), placeholders only. Provider staff announced org-token
  deprecation (forum, 2024-01-12) and `huggingface_hub` login rejects
  `api_org` tokens. A re-tier of the family to T1 would therefore apply to the
  `user` variant only; `api_org_` stays T2 (tracked in #485).
- **Uncovered provider shapes in the `hf_` namespace** (reported, not
  decided): `hf_oauth_…` and `hf_jwt_…` (provider docs), plus `hf_app_`,
  `hf_oauth__refresh_`, `oauth_app_secret_` and dotted `hf_s3_…` in provider
  code. The contract's `$` and alnum-dash boundary reject all of them.

## Sources checked

Every class in the issue's "Done when" was checked on 2026-09-22 and the
load-bearing pages were re-fetched on 2026-09-23. URL-level tables are in the
[research pass 1](https://github.com/redact-secret/redact-secret/issues/654#issuecomment-5784926544)
and [broad-discovery](https://github.com/redact-secret/redact-secret/issues/654#issuecomment-5785640146)
comments.

| source class | result |
| --- | --- |
| product docs and API reference (incl. OpenAPI) | `docs/hub/security-tokens` (re-checked 2026-09-23): `hf_...` placeholder only; about 20 other hub pages give no format; `/.well-known/openapi.json`: 34-character example, bounds 1–200 |
| changelog / release notes | `huggingface.co/changelog` and `changelog/token-presets`: no format |
| engineering / security blog | `blog/trufflesecurity-partnership` (TruffleHog output, tool evidence only), `2024-security-features`, `space-secrets-disclosure`, `security-incident-july-2026`: no format |
| secret-scanning partner pages | GitHub supported-patterns page (re-checked 2026-09-23): `hf_user_access_token` and `hf_org_api_key` rows, no pattern, not provider domain; no Hugging Face token-format announcement found |
| SDK / CLI docs on provider domain | `docs/huggingface.js/hub/modules`: prefix found; `docs/huggingface_hub` authentication, quick-start, CLI, `hf_api`, utilities: placeholders only |
| provider-authored code (corroboration) | inference-playground Space `ed1ed33` on huggingface.co (re-fetched 2026-09-23); `huggingface.js` `checkCredentials.ts` ("must start with 'hf_'"); hf-mcp-server, agent-manager, Repo2RLEnv regexes (`hf_[A-Za-z0-9]{34}` / `{30,}`) |
| general web search (added 2026-09-23) | three WebSearch queries on token format, length and alphabet: results were the forum threads, secretlint #1449, scanner docs (GitGuardian, RedHunt Labs) and third-party blogs already classed as non-provider, plus `huggingface.js` issue #2521 (2026-09-22, third-party reporter; quotes the SDK prefix check, no provider statement). Nothing new on the provider domain |
| Reddit (added 2026-09-23) | `reddit.com` and `old.reddit.com` JSON returned 403 and WebSearch refused the domain. The PullPush archive answered: four queries over comments and submissions found no statement of `hf_` token length or alphabet. A DuckDuckGo `site:reddit.com` query listed only setup/how-to threads |

Reddit was reachable only through the archive mirror, not live. Reddit cannot
meet the T1 bar, so this limit does not affect the verdict.

## Open items

- Reviewer confirmation that an SDK type annotation (`hf_${string}`) satisfies
  the T1 bar for the prefix.
- Body alphabet. The empirical check in the
  [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/654#issuecomment-5785640146)
  (issue two or three fresh tokens, record only whether any digit appears,
  revoke) is the only thing that would settle letters-only versus
  alphanumeric. With 62 symbols and 34 draws, a digit-free key happens by
  chance about 0.25% of the time.
- Twin pairs. The family still fails `minimumTwinPairs` (2 < 5); this evidence
  makes prefix and length twins provable, not alphabet or delimiter twins.

## What this document does not do

It changes no detector, contract, fixture, or tier.
`docs/contracts/precision/precision-contracts.json` is untouched; the re-tier
and any `covers` or `sources` edit happen in the T1 re-tier batch of #575. It
contains no credential and no full example token value; every token is
described by structure only.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
