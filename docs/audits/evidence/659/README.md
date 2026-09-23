# Issue #659 — T1 provider evidence for `sentry:user-auth-token`

[Audit archive](../../README.md) ·
[Issue #659](https://github.com/redact-secret/redact-secret/issues/659) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 2](https://github.com/redact-secret/redact-secret/issues/659#issuecomment-5784944138) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/659#issuecomment-5785641052) ·
[Sentry contract freeze](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
Sibling: [#658 org token](https://github.com/redact-secret/redact-secret/issues/658)

Written 2026-09-23 on branch `chore/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.
This record adds one provider-domain source that neither pass found, and
re-fetches the load-bearing pages.

## Verdict: FOUND-partial, prefix only, from a placeholder on a provider domain

One page on a Sentry domain shows `sntryu_` as the leading element of a Sentry
auth token: `skills.sentry.dev`, Sentry's agent-skill library, which
`docs.sentry.io/llms.txt` links. That page gives a placeholder, not a grammar.
Its own prose calls the token an "org auth token", so on the Sentry domain
alone `sntryu_` is not tied to the personal/user token type. That tie, and the
body's length and alphabet, come only from Sentry-authored sources on
github.com, which the existing precedent does not accept as provider
documentation. Whether this placeholder is enough to establish the identifying
element at T1 is a maintainer decision. It is **not** decided here.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix `sntryu_` (including the `_`) | contested: yes if a placeholder on skills.sentry.dev counts | provider-domain placeholder `sntryu_...` for an auth token; the page labels it "org auth token", not personal/user |
| prefix ↔ personal/user token type | no | only `getsentry/sentry` `types/token.py` (`USER = "sntryu_"`), on github.com |
| body length 64 (total 71) | no | only github.com source (`token_hex(nbytes=32)`, `max_length=71`) plus tools |
| body alphabet lowercase hex `[0-9a-f]` | no | only github.com source (`secrets.token_hex`) plus tools |
| marker / checksum / second delimiter | no | none documented anywhere; source shows prefix plus random hex only |

## The source

`https://skills.sentry.dev/sentry-create-alert/SKILL.md`, "Phase 1: Gather
Configuration" table. Re-fetched 2026-09-23 (HTTP 200, `text/plain`, served
by Vercel). `observedAt`: 2026-09-23.

> `| Auth token | Yes | `sntryu_...` (needs `alerts:write` scope) |`

The same file's Prerequisites section says: "Sentry org auth token with
`alerts:write` scope". The `...` is an elision. No length or alphabet is given.

Provenance: the served file matches byte for byte
`getsentry/sentry-for-ai` `src/skills/sentry-create-alert/SKILL.md` at
`55cc40b55d` (2026-08-04), except for a footer the server appends. The domain
is Sentry's own: `https://docs.sentry.io/llms.txt` (re-fetched 2026-09-23)
lists "[All Skills](https://skills.sentry.dev/): Full skill index" under
"Browse the skill library". `sentry.dev` is the same domain family as
`cli.sentry.dev`, `develop.sentry.dev` and `mcp.sentry.dev`, which the earlier
passes counted as provider domains. No other skill file served there (all
eight SKILL.md files and four entry points, fetched 2026-09-23) contains
`sntry*_`.

Why this is only partial:

- It is a placeholder in an agent-instruction file, not reference
  documentation. The closest precedents are Docker's `dckr_oat_*` glob in the
  API spec (#647) and the example prefix in `digitalocean-oauth-reference`.
- The page misnames the token type, so the provider domain does not say which
  token `sntryu_` belongs to.

Everything else about the shape is corroborated only, and was re-checked
2026-09-23 against `getsentry/sentry` master `e8a423a1f8`:

- `src/sentry/types/token.py`: "The values equate to the expected prefix of each
  of the token types"; `USER = "sntryu_"`; unprefixed legacy tokens are still
  accepted.
- `src/sentry/models/apitoken.py` L110: `f"{token_type}{secrets.token_hex(nbytes=32)}"`.
  L200: `max_length=71`.

These are on github.com, which is the same class `assessment.ts` already
declines for `new-relic-license-key` and `sentry-org-auth-token`.

## Proposed `covers` sentence

For use only if the maintainer accepts the placeholder as T1 for the prefix:

> Sentry's own agent-skill library (skills.sentry.dev, linked from
> docs.sentry.io/llms.txt) shows a Sentry auth token as `sntryu_...`,
> establishing the `sntryu_` prefix on a provider domain. That page labels the
> token an org auth token. The mapping of `sntryu_` to the personal/user token,
> the 64-character body and the lowercase-hex alphabet are not stated on any
> Sentry domain. They come from Sentry's source code on github.com
> (`types/token.py`, `apitoken.py`) and from gitleaks 8.30.1, and remain
> tool-corroborated.

## Contradictions with the current contract

Contract (`benchmarks/lib/assessment.ts`, T2): `^sntryu_[0-9a-f]{64}$`.

- **Prefix, length and alphabet: no contradiction.** The provider-domain
  placeholder shows only the prefix, which matches. Sentry's source emits
  exactly `sntryu_` plus 64 lowercase hex characters.
- **Token-type label on the provider page.** skills.sentry.dev pairs `sntryu_`
  with "org auth token". Sentry's source assigns `sntrys_` to org tokens, and
  the current contract also puts org tokens under `sntrys_`. This is a
  provider documentation slip, not evidence that `sntryu_` is an org token. If
  the placeholder is accepted, the maintainer should be aware of it.
- **Legacy unprefixed tokens** (bare 64 hex) are still valid under Sentry's
  code, and the contract does not match them. The detector (`sentry.rs`)
  deliberately scopes them out.
- **Naming.** Sentry's docs call these "Personal Tokens", and GitHub renamed
  its pattern to `sentry_personal_token`. The family label is still "User auth
  token".
- The RFC 0032 `[a-zA-Z0-9]{64}` alphabet and the uppercase hex that consumers
  accept are both settled in the
  [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/659#issuecomment-5785641052)
  as proposal or tolerance, not issued shape.

## Sources checked

Every class the issue requires was checked. The full URL-level table for
2026-09-22 is in the
[research pass 2 comment](https://github.com/redact-secret/redact-secret/issues/659#issuecomment-5784944138).
The rows below record the 2026-09-23 re-check and the gaps this pass closed.

| source class | URL(s), 2026-09-23 | result |
| --- | --- | --- |
| product docs and API reference, including OpenAPI | `docs.sentry.io/account/auth-tokens/` (+ `.md`), `/api/auth.md`, `/cli/configuration.md`, `/llms.txt`, `/ai/agent-skills/`, `/product/sentry-mcp/`; `getsentry/sentry-docs` shallow clone @ `cb90866` (2026-09-23) grepped in full | no `sntryu` anywhere; `sntrys_` only as 4 placeholders. OpenAPI (`sentry-api-schema`) unchanged from pass 2: bearer, no pattern |
| changelog / release notes | `sentry.io/changelog/github-secret-scanning/` | re-read; "a Sentry user token or org auth token" only, no format |
| engineering / security blog | `blog.sentry.io` sitemap index, 1,283 URLs, filtered for token/secret/auth/credential/prefix/scanning | no post on token prefixes or formats. The WebSearch summary claiming "the Sentry blog announced prefixed tokens" traces to this issue's own text, not to a blog post |
| secret-scanning partner pages | GitHub partner list and 2025-11-12 GitHub changelog (pass 2) | existence and naming only, no format, not provider domain. No Sentry-domain token-format announcement found |
| SDK / CLI / tooling docs on provider domain | all 48 `cli.sentry.dev` sitemap pages; `cli.sentry.dev/commands/auth/`; `skills.sentry.dev` index, 8 SKILL.md files, 4 entry points; `mcp.sentry.dev` | `cli.sentry.dev`: only `sntrys_` placeholders (configuration, library-usage, migrating-from-v3). **`skills.sentry.dev/sentry-create-alert/SKILL.md`: `sntryu_...` placeholder (the source above)** |
| general web search (gap in the prior pass) | WebSearch: `"sntryu_" sentry token`; `sentry personal token format prefix sntryu`; `sntryu`/`sntrys` restricted to sentry.io and sentry.dev; blog query | hits are github.com issues and code, fossies mirror, third-party docs, and `sntrys_` placeholders on docs.sentry.io/cli.sentry.dev. No Sentry-domain page states `sntryu_`, apart from the skill found by direct sweep |
| Reddit (gap in the prior pass) | Pullpush `search/submission` and `search/comment` `q=sntryu`; WebSearch `site:reddit.com` | 0 submissions, 0 comments, 0 results. reddit.com JSON still 403. Archive coverage is not complete, and Reddit cannot meet the bar in any case |
| forums | WebSearch hits on the retired `forum.sentry.io` | 401/invalid-token threads only, no format |
| provider code on github.com (corroboration only) | `gh search code sntryu --owner getsentry` (23 hits) | `sentry` types/models, `sentry-cli`, `getsentry/cli`, `sentry-for-ai` and its plugin mirrors, `sentry-mcp` tests. No `sentry-docs` hit |

Nothing was blocked apart from reddit.com (403), and Pullpush covers Reddit.

## Open items

1. **Maintainer scope call.** Does a placeholder in a Sentry-hosted agent-skill
   file (`skills.sentry.dev`) meet the T1 bar for the prefix, given that the
   same page labels the token an org token? If yes, the family moves into the
   T1 re-tier batch with the `covers` sentence above. If no, the verdict
   reduces to NOT FOUND — EXHAUSTIVE as of 2026-09-23 on Sentry domains, and
   the github.com question from pass 2 is still open.
2. The empirical check of one freshly issued personal token (prefix, total
   length 71, lowercase hex, single `_`), as specified in the
   [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/659#issuecomment-5785641052).
   Record counts only, and revoke the token.
3. Twin pairs (0 of 5) are not addressed here.

## What this document does not do

It changes no detector, contract, fixture or tier.
`benchmarks/lib/assessment.ts` (in `redact-secret-benchmarks`) and
`crates/secret-scan-core/src/detectors/sentry.rs` are untouched. The re-tier
and any `covers` edit belong to the T1 re-tier batch of #575. This document
contains no credential and no full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
