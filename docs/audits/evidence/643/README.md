# Issue #643 — T1 provider evidence for `atlassian:api-token`

[Audit archive](../../README.md) ·
[Issue #643](https://github.com/redact-secret/redact-secret/issues/643) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5784974657) ·
[Correction](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5785223482) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5785417879) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5786038856) ·
[Atlassian contract freeze (#299)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The four
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23, with one source awaiting a maintainer ruling

No Atlassian documentation page, API reference, OpenAPI schema, changelog
entry, blog post, secret-scanning page, or SDK/CLI doc states the `ATAT`
prefix or any other lexical shape for the Atlassian account API token. Every
class the issue's "Done when" lists has now been checked; the one gap left by
pass 2 (the developer blog) is closed below.

The only statement of the prefix on an Atlassian-owned domain is a reply on
`community.atlassian.com` from an account labelled "Atlassian Team". The T1
precedent does not say whether a staff answer on the provider's community site
counts as provider documentation. That ruling is the maintainer's
([correction comment](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5785223482));
this document does not make it. If it is accepted, the verdict becomes FOUND
for the identifying element only, as in the second column below.

| property | provable at T1 | provable if the staff answer is accepted | basis |
| --- | --- | --- | --- |
| prefix `ATAT` | no | yes | staff forum answer only |
| 12-char header `ATATT3xFfGF0` | no | no | customer observation in the same thread; scanners; maintainer's own keys |
| length (192 observed) | no | no | provider docs say "varied"; ID-8131 title and all samples say 192 |
| body alphabet `[A-Za-z0-9_-]` | no | no | tools and samples only |
| delimiter `=` 9 chars from the end | no | no | tools and samples only |
| marker / checksum (`[0-9A-F]{8}` CRC32) | no | no | CredSweeper and DataDog SDS rules plus samples; no provider statement |

## The source

No provider-documentation source. The borderline provider-domain source:

`https://community.atlassian.com/forums/Bitbucket-questions/Can-we-confirm-BitBucket-s-token-prefixes/qaq-p/3093481`,
answer by "Dhananjay Goyani_fsa964" (user 4386002; page metadata
`"label":"Atlassian Team"`, rankID 13), posted 2025-08-25. Re-fetched
2026-09-23:

> You can rely on following prefixes for Bitbucket tokens. API Token: ATAT App Password: ATBB Access Tokens (Workspace, Project, Repo): ATCT

`observedAt`: 2026-09-23 (first observed 2026-09-22). The question it answers
is a customer's observation of the longer `ATATT3xFfGF0` / `ATCTT3xFfGN0`
headers; the answer confirms only the 4-character prefixes. No official page
read in any pass links to the thread.

Contrary provider-staff statement, also re-fetched 2026-09-23
(`https://community.developer.atlassian.com/t/about-the-format-of-atlassian-security-tokens/62553`,
ibuchanan, "Atlassian Staff", 2022-10-13), which predates the 2023-01-18
token change:

> Atlassian considers the authorization code and all API tokens to be opaque in the sense that clients cannot depend on their size, structure, or format.

Provider documentation, re-fetched 2026-09-23
(`https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/`):

> We use a varied API token length tokens rather than fixed length to ensure tokens are more secure and reliable.

The same page states that tokens created before 2024-12-15 were set to expire
between 2026-03-14 and 2026-05-12, so no pre-2023 unprefixed token can still be
live.

## Proposed `covers` sentence

Only if the maintainer accepts the staff answer as a provider source:

> An Atlassian-staff answer on Atlassian's own community site
> (community.atlassian.com thread 3093481, 2025-08-25) states that API tokens
> can be relied on to carry the `ATAT` prefix, distinct from `ATBB` (app
> passwords) and `ATCT` (access tokens), establishing the `ATAT` prefix; body
> length, alphabet, the `=` delimiter and the 8-character hex suffix are not
> provider-stated, and Atlassian's documentation describes the length as
> "varied".

Otherwise there is no `covers` sentence and the family stays T2.

## Contradictions with the current contract

Contract pattern: `^ATAT[A-Za-z0-9_-]{100,}$` (T2). Detector:
`crates/secret-scan-core/src/detectors/atlassian.rs`, `PREFIX = "ATAT"`,
`MIN_BODY_LEN = 100`, alphabet `is_alnum_dash`.

- **`=` is outside the alphabet.** Every observed modern token has exactly one
  `=` at 1-based position 184 of 192, which the maintainer confirmed on a
  freshly issued key. An anchored full match of the contract fails on a real
  token; the shipped detector deliberately stops at the `=` (documented in
  the module comment of `atlassian.rs` to keep `KEY=<token>` assignments
  working), so the `=` and the 8-character suffix are not redacted. This is a
  known design choice, not a provider contradiction, but it means the
  contract describes a prefix of the token, not the token.
- **No provider contradiction on the prefix.** The staff answer's `ATAT`
  matches the contract anchor exactly.
- **Length.** The contract's `{100,}` open minimum is consistent with the
  provider's "varied" wording and with every observed 192-character token.
- **Checksum.** The trailing `[0-9A-F]{8}` is a CRC32 over the preceding 184
  characters according to two independent tools, and every real sample
  passes. The contract does not model it. No provider source states it, so it
  cannot be a T1 property.
- **Staff statements disagree.** 2022 "opaque … cannot depend on … format"
  versus 2025 "You can rely on following prefixes". The 2022 statement came
  before the 2023-01-18 format change.

## Sources checked

Every class required by the issue has been checked. Full URL-level tables are
in the [pass 2](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5784974657),
[broad-discovery](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5785417879)
and [web-search](https://github.com/redact-secret/redact-secret/issues/643#issuecomment-5786038856)
comments; only the new work from 2026-09-23 is given at URL level here.

| source class | result |
| --- | --- |
| product docs and API reference (OpenAPI) | 2026-09-22: the support.atlassian.com API-token, access-token and revocation KB pages, 5 developer.atlassian.com REST intros, 8 OpenAPI/Swagger specs incl. `api.bitbucket.org/swagger.json`: no prefix, pattern or format. Support page re-fetched 2026-09-23: "varied" length, no `ATAT` |
| changelog / release notes | 2026-09-22: `dac-changelogs.services.atlassian.com/changes`, all 48 apiGroups, 87 matching entries (CHANGE-665, -845, -2108, -2403, -2533, -3387): length and expiry only, no prefix; public tracker ID-8131: 192 length only |
| engineering / security blog | Main blog: 10 posts and RSS searches (2026-09-22). **Developer blog, closed 2026-09-23:** `blog.developer.atlassian.com` (root, `?s=api+token`, `/feed/`, and an old post URL) now 302-redirects to `atlassianblog.wpengine.com`, the "Inside Atlassian" blog backing `atlassian.com/blog`, which holds the former developer-blog posts under `/blog/development/` (for example "Update to Jira Cloud's Swagger/OpenAPI docs"). WordPress REST full-text scan of `atlassianblog.wpengine.com/wp-json/wp/v2/posts` for "api token", "api tokens", "access token", "app password", "token length", "secret scanning", "basic auth" (up to 50 posts each): no `ATAT`, `ATCT`, `ATBB`, `ATATT` or token-format text; the two keyword hits (`prefix`, `format of`) are unrelated. Wayback CDX index of `blog.developer.atlassian.com/*` filtered for token, auth, credential, password, secret, api-key and scan: 10 post slugs (cloudtoken, kubetoken, single-shared-secret, bitbucket-oauth-with-python, Forge external auth, and similar), none about API-token format |
| secret-scanning partner pages | GitHub partner list: `atlassian_api_token` partner, multiple "Token versions", no shape, not provider domain. Atlassian secret-scanning pages (Bitbucket DC, Confluence security, Marketplace DC scanner) and provider-authored `git-secrets-scan`: no Atlassian API-token rule |
| SDK / CLI docs | ACLI `jira auth login`, install and get-started, Forge CLI `login` and getting-started; `@forge/cli`, `@forge/cli-shared`, `@forge/auth` npm packages; `gh search code` in `atlassian` and `atlassian-labs`: no prefix strings |
| community (provider domain, borderline) | community.atlassian.com 3093481 (staff answer, re-fetched 2026-09-23); community.developer.atlassian.com 62553 (staff "opaque", re-fetched 2026-09-23) and 67192 (staff "no specified range") |

Not read, recorded as unchecked: Reddit itself (blocked; one r/jira thread read
through an archive), Atlassian Community search (JavaScript only), the
betterleaks regex behind Kingfisher. None of these can meet the T1 bar, so
they do not change the verdict. Old developer-blog posts that were not
migrated cannot be read live (their URLs redirect to the blog home page); the
Wayback slug index is the evidence that none of them concerned token format.

## Open items

- **Maintainer ruling** on whether an "Atlassian Team" answer on
  community.atlassian.com meets the T1 provider-source bar for the `ATAT`
  prefix. This decides between the verdict above and FOUND (prefix only).
- **Twin pairs:** 3 of the 5 needed for `stable`; separate from T1.
- **CRC32 on a fresh key:** the maintainer's check of a freshly issued key
  confirmed the 12-character header, 192 characters, a single `=` at position
  184, an uppercase-hex suffix and a `[A-Za-z0-9_-]` body, and confirmed the
  `ATCTT3xFfGN0` header on a Bitbucket access token; the CRC32 check was not
  run ("NOT sure"). It is corroboration only and cannot make any property T1.
- **Redaction of the `=` and suffix:** whether the detector should cover the
  full 192 characters is a product question for the T1 re-tier batch or a
  separate issue, not for this record.

## What this document does not do

It changes no detector, contract, fixture, or tier. The contract grammar and
`crates/secret-scan-core/src/detectors/atlassian.rs` are untouched; any
re-tier and `covers` edit happen in the T1 re-tier batch of #575. It does not
decide whether the staff forum answer counts. It contains no credential and
no full example token value; only fixed headers are quoted.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
