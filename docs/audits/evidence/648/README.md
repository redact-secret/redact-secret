# Issue #648 — T1 provider evidence for `docker:personal-access-token`

[Audit archive](../../README.md) ·
[Issue #648](https://github.com/redact-secret/redact-secret/issues/648) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Second-pass research](https://github.com/redact-secret/redact-secret/issues/648#issuecomment-5784933999) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/648#issuecomment-5785334002) ·
[Sibling: #647 OAT evidence](../647/README.md) ·
[Docker contract freeze (#370)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Prior evidence: #566](../566/README.md)

Written 2026-09-23 on branch `chore/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND, for the identifying element only

A provider-domain source states the Personal Access Token prefix. It is the
same source that establishes the OAT prefix in [#647](../647/README.md). Body
length and alphabet are not provider-stated. Unlike the OAT branch, nothing
Docker publishes contradicts the contract's PAT branch.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix `dckr_pat_` (namespace `dckr_`, type marker `pat_`, both `_` delimiters) | yes | prose `Format` column, provider domain |
| body length (27) | no | no Docker page states it; every docs.docker.com PAT example is a placeholder; 27 comes from tools and an empirical tally |
| body alphabet (`[A-Za-z0-9_-]`) | no | tools and an empirical tally only; Docker-owned scanner rules are narrower |
| marker / checksum / terminator | no | none documented anywhere |

## The source

`https://docs.docker.com/reference/api/ai-governance/api.yaml`, the
`components.securitySchemes.bearerAuth.description` table. The rendered page
`/reference/api/ai-governance/latest/` loads this file. Re-fetched 2026-09-23
(HTTP 200). Line 540 introduces the table: "The `password` field of the token
request accepts any of the following credential types". Column header
`Format` is at line 543. Line 546:

> `| Personal Access Token (PAT) | `dckr_pat_*` | Recommended over passwords. Create one under Account Settings → Security. |`

Line 547 gives `dckr_oat_*` for the Organization Access Token (see #647). The
provider-authored source is `docker/docs`
`content/reference/api/ai-governance/api.yaml`, present in every revision
since `553c69e1b7` (2026-06-02). `observedAt`: 2026-09-23 (first observed
2026-09-22). The `*` is a glob, not a grammar.

Not a width source: `https://docs.docker.com/reference/api/hub/latest.yaml`
has two `dckr_pat_` examples (`/v2/auth/token`), both with a 15-character
placeholder body (re-counted 2026-09-23).

Precedent fit: same class as `vercel-docs-access-tokens` (prose prefix). The
T1 bar in `benchmarks/lib/assessment.ts` is unchanged.

## Proposed `covers` sentence

> Docker's own API reference (docs.docker.com AI Governance API spec,
> `bearerAuth` credential table) states the Personal Access Token format as
> `dckr_pat_*`, establishing the `dckr_pat_` prefix. Docker does not state the
> body's length or alphabet; the 27-character `[A-Za-z0-9_-]` body is
> corroborated by trufflehog 3.97.4 and other scanner rules and by the
> lengths of public strings, not by the provider.

## Contradictions with the current contract

Contract `pat` variant: `dckr_pat_[A-Za-z0-9_-]{27}`. The detector
(`crates/secret-scan-core/src/detectors/additional_providers.rs`, doc comment
at L223–233) implements the same shape.

- **Prefix.** None. The contract literal `dckr_pat_` is what Docker states.
- **Length.** No provider contradiction, because no provider source gives a
  width. The Hub spec's 15-character bodies are placeholders. Tools
  (trufflehog, Nosey Parker, betterleaks, osv-scalibr) and Docker's own
  `mcp-gateway` and `portcullis` rules all say 27. In the broad-discovery
  tally, 69 of 92 distinct non-placeholder public bodies are 27 characters
  long.
- **Alphabet.** No provider-domain contradiction. Two Docker-owned repositories
  hold narrower rules: `docker/portcullis` (alphanumeric only; its header says
  it copied its rules from Trivy) and `docker/mcp-gateway` (`[-0-9a-zA-Z]`, no
  `_`). They are code, not documentation. The public tally contradicts them:
  of the 69 bodies with 27 characters, 27 contain `_` and 19 contain `-`.
  The contract's wider alphabet is the safer choice, and it is still
  tool-corroborated only.
- **OAT branch.** The 27-versus-32 conflict belongs to the `oat` variant of
  the same contract. [#647](../647/README.md) records it and it is not decided
  here. Moving the whole `docker-token` contract to T1 still depends on that
  decision, because one contract carries both variants.

## Sources checked

Every class required by the issue's "Done when" was checked on 2026-09-22 in
the linked passes. The load-bearing spec and the pages below were re-fetched on
2026-09-23. Full URL-level tables:
[second pass](https://github.com/redact-secret/redact-secret/issues/648#issuecomment-5784933999),
[broad discovery](https://github.com/redact-secret/redact-secret/issues/648#issuecomment-5785334002).

| source class | result |
| --- | --- |
| product docs and API reference (OpenAPI) | ai-governance `api.yaml`: prefix found (re-fetched 2026-09-23). Hub `latest.yaml`: 15-char placeholders only (re-counted 2026-09-23). `security/access-tokens/` and `enterprise/security/access-tokens/`: no `dckr_` string (re-fetched 2026-09-23). Registry API reference, repos/manage/access, Scout metrics-exporter, DHI guides: placeholders only |
| changelog / release notes | Docker Hub release notes (re-fetched 2026-09-23: no `dckr_`; PATs introduced 2019-09-19), Desktop, Engine and Scout CLI release notes, security announcements: no format |
| engineering / security blog | `docker-hub-new-personal-access-tokens` (re-fetched 2026-09-23: no `dckr_`), `changes-to-how-docker-handles-personal-authentication-tokens`, OAT launch post, OIDC post, `tag/access-tokens`, `tag/security`: no format |
| secret-scanning partner pages | GitHub supported-secret-scanning-patterns (re-fetched 2026-09-23): Docker Personal Access Token listed, no pattern given, and it is not a provider domain. GitHub changelog: no Docker format announcement |
| SDK / CLI docs | `docs.docker.com/reference/cli/docker/login/` (re-fetched 2026-09-23): no `dckr_`. The `mcp-gateway`, `portcullis` and `docker-agent` repos count as corroboration only |

Not read in the broad pass: reddit.com search (HTML wall; the pullpush archive
was read instead), DuckDuckGo (bot challenge), Semgrep and Xygeni rule docs,
and an in-org `gh search code` retry (rate limit). None of these can meet the
T1 bar, so they do not change the verdict.

## Open items

- The OAT branch width decision ([#647](../647/README.md)) gates the re-tier
  of the shared `docker-token` contract.
- Optional empirical check of one or two freshly issued PATs: is the body 27
  characters, and do `_` or `-` appear? The steps are in the
  [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/648#issuecomment-5785334002).
  It would move length and alphabet from tool-corroborated to measured, but it
  cannot make them T1. Record counts only and revoke each key.

## What this document does not do

It changes no detector, contract, fixture, or tier.
`docs/contracts/precision/precision-contracts.json` is untouched. The re-tier
and any `covers` edit happen in the T1 re-tier batch of #575. It contains no
credential and no full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
