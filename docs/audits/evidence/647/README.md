# Issue #647 — T1 provider evidence for `docker:oauth-access-token`

[Audit archive](../../README.md) ·
[Issue #647](https://github.com/redact-secret/redact-secret/issues/647) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/647#issuecomment-5784905657) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/647#issuecomment-5785379682) ·
[Docker contract freeze (#370)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Prior evidence: #566](../566/README.md)

Written 2026-09-23 on branch `workbench/647-docker-oat-t1-evidence`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND, for the identifying element only

A provider-domain source states the Organization Access Token prefix. Body
length and alphabet are not provider-stated, and the only provider-domain
example contradicts the contract's 32-character `oat_` body.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix `dckr_oat_` (including both `_`) | yes | prose `Format` column, provider domain |
| body length | no | provider example shows 27; contract's 32 is trufflehog 3.97.4 only |
| body alphabet | no | provider example is `[A-Za-z0-9]`; contract's `_`/`-` is trufflehog only |
| marker / checksum / terminator | no | none documented anywhere |

## The source

`https://docs.docker.com/reference/api/ai-governance/api.yaml`, the
`components.securitySchemes.bearerAuth.description` table (line 543 onward;
the rendered page `/reference/api/ai-governance/latest/` loads it). Re-fetched
2026-09-23; column header `Format`:

> `| Organization Access Token (OAT) | `dckr_oat_*` | Scoped to an organization. Create one under Organization Settings → Access Tokens. |`

The sibling row gives `dckr_pat_*` for the Personal Access Token. The
provider-authored source is `docker/docs` `content/reference/api/ai-governance/api.yaml`,
present since `553c69e1b7` (2026-06-02). `observedAt`: 2026-09-23 (first
observed 2026-09-22). The `*` is a glob, not a grammar.

Supporting example, not a grammar: `https://docs.docker.com/reference/api/hub/latest.yaml`
`createOrgAccessTokenResponse.token` (two occurrences, re-counted 2026-09-23):
`dckr_oat_` followed by a 27-character `[A-Za-z0-9]` body.

Precedent fit: same class as `vercel-docs-access-tokens` (prose prefix) and
`digitalocean-oauth-reference` (example prefix plus example length). The T1
bar in `benchmarks/lib/assessment.ts` is unchanged.

## Proposed `covers` sentence

> Docker's own API reference (docs.docker.com AI Governance API spec,
> `bearerAuth` credential table) states the Organization Access Token format
> as `dckr_oat_*`, establishing the `dckr_oat_` prefix; the body's length and
> alphabet are not provider-stated. Docker's Hub API spec shows one example
> OAT with a 27-character alphanumeric body, which conflicts with the
> 32-character body the contract adopts from trufflehog 3.97.4 alone.

## Contradictions with the current contract

Contract `oat` variant: `dckr_oat_[A-Za-z0-9_-]{32}`.

- **Length.** The contract rejects Docker's own documented example (27). Every
  Docker-authored artefact that shows a width shows 27 (the Hub example and
  `docker/portcullis` `rules.go`, whose comment says it copies the PAT shape).
  Only trufflehog says 32, in prose in trufflehog PR #4062, and the scanners
  that state 32 trace back to it, so their count is not independent evidence.
- **Alphabet.** Docker-authored artefacts show alphanumeric only; the contract
  allows `_`/`-`. One unverified public value has a 32-character body with
  `-`/`_`, which would favour the contract. It is not named here because it may
  be a live leak.
- **Taxonomy label.** The family is labelled "OAuth access token". Docker and
  GitHub (`docker_organization_access_token`) both say *Organization* Access
  Token.

The 27-versus-32 question is **not decided here**. Moving the `oat` branch to
T1 while keeping `{32}` would yield a contract that rejects the provider's own
example; that decision needs the empirical measurement below and belongs to
the T1 re-tier batch.

## Sources checked

Every class required by the issue was checked on 2026-09-22 and the two
load-bearing pages re-fetched 2026-09-23. Full URL-level table: see the
[research pass 2 comment](https://github.com/redact-secret/redact-secret/issues/647#issuecomment-5784905657).

| source class | result |
| --- | --- |
| product docs and API reference (OpenAPI) | ai-governance spec: prefix found; Hub spec: 27-char example; OAT/PAT/security docs pages: no `dckr_` string |
| changelog / release notes | Hub API changelog, deprecated page, Docker Hub and Desktop release notes: no format |
| engineering / security blog | OAT launch post (2024-10-15) and four other posts: no prefix, length, or format |
| secret-scanning partner pages | GitHub partner list: existence only, no pattern, not provider domain; no Docker token-format announcement found |
| SDK / CLI docs | `docker login` reference: no `dckr_`; provider repos `docker-agent` (prefix only) and `portcullis` (27-char rule, unclear provenance) are corroboration only |

Not read: Reddit and Google-ranked forum threads (blocked), recorded as
unchecked. Neither can meet the T1 bar, so they do not change the verdict.

## Open item

Empirical measurement of one freshly issued OAT (length, alphabet over two or
three keys, fixed segments, PAT control), as specified in the
[broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/647#issuecomment-5785379682).
It needs an org owner on a Team or Business plan and is the only thing that
can settle 27 versus 32. Record counts only; revoke each key.

## What this document does not do

It changes no detector, contract, fixture, or tier. `docs/contracts/precision/precision-contracts.json`
is untouched; the re-tier and any `covers` edit happen in the T1 re-tier batch
of #575. It contains no credential and no full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
