# Issue #658 — T1 provider evidence for `sentry:organization-auth-token`

[Audit archive](../../README.md) ·
[Issue #658](https://github.com/redact-secret/redact-secret/issues/658) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Second-pass research](https://github.com/redact-secret/redact-secret/issues/658#issuecomment-5784936079) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/658#issuecomment-5785640846) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/658#issuecomment-5785992810) ·
[Sentry contract freeze](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)

Written 2026-09-23 on branch `chore/beta7-research`. The three
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND on a provider domain — EXHAUSTIVE as of 2026-09-23; one provider-authored candidate awaits a maintainer ruling

No page on a Sentry domain (docs.sentry.io, sentry.io, blog.sentry.io,
develop.sentry.dev, cli.sentry.dev) states the organization auth token's
prefix or structure. Every source class in the issue's "Done when" was
checked. Sentry's own design document, RFC 0091 in `getsentry/rfcs`, does
state the prefix and structure, but it is hosted on github.com and Sentry
itself classifies its RFCs as proposals (see below). No accepted T1 contract
cites a github.com-hosted provider document as its `providerSource`. If the
maintainer accepts RFC 0091, the verdict becomes FOUND for the prefix and
delimiter structure only.

| property | provable at T1 | basis |
| --- | --- | --- |
| prefix `sntrys_` | no on a provider domain; yes if RFC 0091 is accepted | RFC 0091 states it as static; docs.sentry.io shows it only in placeholders |
| structure `PREFIX_FACTS_SECRET`, exactly two `_` | no; yes if RFC 0091 is accepted | RFC 0091 structure line and its `token.count('_') != 2` parse rule |
| payload marker `eyJ` | no; derivable if RFC 0091 is accepted | RFC says FACTS is "base64 encoded JSON"; `eyJ` follows but is never written |
| payload alphabet (standard base64, `={0,2}` kept) | no | RFC says "base64" only; standard alphabet and kept padding are provider source code (`orgauthtoken_token.py`) |
| secret length 43, standard base64 | no | RFC gives it as a "may … implementation detail"; provider code and seven measured tokens corroborate |
| payload length | no | varies with org slug and URLs; nothing states a bound |
| checksum | no | none exists; the payload is unsigned (getsentry/cli#848) |

## The source

Provider domains: none. Load-bearing candidate, re-fetched 2026-09-23:

`https://github.com/getsentry/rfcs/blob/main/text/0091-ci-upload-tokens.md`
(raw copy). Merged in PR #91 (`54c6937c8f`, 2023-06-13), token format
revised in PR #105 (`a018ea459f`, 2023-06-26); no later commits. The repo
README lists it under "accepted and live RFCs"; the file header still reads
`RFC Status: draft`. `observedAt`: 2026-09-23 (first observed 2026-09-22).

> `PREFIX`: `sntrys_` - this is static and helps to identify this is a Sentry token.

> `FACTS`: A base64 encoded JSON string of the facts.

> `SECRET`: A random secret part for the token. We may use `b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")`, but this is an implementation detail.

> `if not token.startswith("sntrys_") or token.count('_') != 2:`

Counterweight found this pass, on a provider domain:
`https://develop.sentry.dev/sdk/getting-started/standards/spec-lifecycle/`
(fetched 2026-09-23) defines Sentry's spec statuses and says of the
`proposal` status: "Reserved. Not yet in use; proposals currently live as
RFCs. Treat as not-yet-a-spec." The page governs SDK specs, not server
token formats, but it is Sentry's own statement of what an RFC is.

Twin-source precedent: benchmarks `assessment.ts` already cites
provider-owned github.com documents as `twinSource` (DataDog/documentation,
google/google-authenticator wiki), never as a T1 `providerSource`.

## Proposed `covers` sentence (only if RFC 0091 is accepted)

> Sentry's own design document, RFC 0091 (getsentry/rfcs, merged 2023-06-13,
> revised 2023-06-26), states the static `sntrys_` prefix and the
> `PREFIX_FACTS_SECRET` structure with exactly two `_` delimiters, FACTS
> being base64-encoded JSON (hence the `eyJ` marker). The standard-base64
> payload alphabet with kept `=` padding and the 43-character secret
> (32 random bytes, padding stripped) are an RFC "implementation detail",
> corroborated by Sentry's source code (getsentry/sentry
> `orgauthtoken_token.py`, getsentry/sentry-cli `auth_token`) and by the
> gitleaks and trufflehog rules. No Sentry web domain documents the format.

## Contradictions with the current contract

Contract (benchmarks `assessment.ts`, T2, unchanged in the 2026-09-23
checkouts): `^sntrys_eyJ[A-Za-z0-9+/]{26,}={0,2}_[A-Za-z0-9+/]{43}$`.
Detector `sentry-org-auth-token` (`crates/secret-scan-core/src/detectors/sentry.rs`)
implements the same grammar.

- **None.** Every provider statement and all seven tokens measured in the
  web-search pass (payloads 96–152, totals 147–203, including `url: null`
  and `url: ""` self-hosted tokens) match the pattern.
- The contract is looser than the evidence in four places: `eyJ` versus the
  observed `eyJpYXQiO`; a `{26,}` payload minimum versus an observed 96; the
  payload length is always a multiple of 4; the secret's last character has
  only 16 possible values. None of these is provider-stated, and the
  `url: null` / `url: ""` tokens argue for keeping the `eyJ` anchor loose.
- Tool and third-party claims that conflict with the contract are wrong on
  the evidence: Base64URL alphabet (Glama blog, Google AI overview,
  CredSweeper), fixed total length (trufflehog `{197}`), "no padding"
  (secretlint proposal). A URL-safe `_` would break the provider's own
  two-`_` parse rule.
- The `sentry.rs` module comment calls the `eyJ` marker and payload minimum
  "documented"; neither is documented on a provider domain. Wording only, no
  behaviour change proposed here.

## Sources checked

Every class required by the issue was checked on 2026-09-22; the classes
below were re-checked live on 2026-09-23. Full URL-level tables:
[second-pass](https://github.com/redact-secret/redact-secret/issues/658#issuecomment-5784936079),
[broad-discovery](https://github.com/redact-secret/redact-secret/issues/658#issuecomment-5785640846),
[web-search](https://github.com/redact-secret/redact-secret/issues/658#issuecomment-5785992810).

| source class | result |
| --- | --- |
| product docs and API reference (OpenAPI) | 2026-09-23: docs.sentry.io `/account/auth-tokens/` (HTML and `.md`), `/api/auth/`, `/api/guides/create-auth-token/`, `/security-legal-pii/security/`: no `sntrys` and no prefix statement. `getsentry/sentry-docs` @ `cb90866` (2026-09-23), full `git grep`: `sntrys` only as placeholders (`sntrys_eyJ...`, `sntrys_YOUR_TOKEN_HERE`). OpenAPI (`sentry-api-schema` @ `33d437a`, 2026-09-22): plain bearer, no format |
| changelog / release notes | 2026-09-23: `sentry.io/changelog/feed.xml`, 319 items to 2026-09-23, zero `sntry` matches. The 2025-12-30 GitHub secret-scanning entry names token types, no format |
| engineering / security blog | 2026-09-22: blog.sentry.io sitemap (1283 URLs) and site-restricted search: no token-format post |
| secret-scanning partner pages | 2026-09-23: GitHub partner list names Sentry Organization Token (`sentry_organization_token`) plus Personal, Integration and User App Auth tokens; no pattern, not a provider domain. No Sentry "token format" announcement exists |
| SDK / CLI docs on provider domain | 2026-09-23: `cli.sentry.dev/configuration/` placeholders only; `docs.sentry.io/cli/configuration/` and `develop.sentry.dev` no `sntrys` |
| provider-authored, off-domain | RFC 0091 (candidate above); getsentry/sentry `orgauthtoken_token.py` and `types/token.py`, sentry-cli, getsentry/cli `token-claims.ts`, sentry-wizard: corroboration only |
| broad web (added 2026-09-23) | two WebSearch queries surfaced only known sources plus Nexla docs ("Organization auth tokens carry the `sntrys_` prefix"; third-party) and dltHub (placeholder only) |

Not read: Reddit (HTTP 403 again on 2026-09-23; the Chrome extension blocks
it). Reddit cannot meet the T1 bar, so this does not change the verdict.

## Open items

- **Maintainer ruling**: does a merged, provider-authored design RFC on
  github.com (header `draft`, index "accepted", Sentry's own docs calling
  RFCs "not-yet-a-spec") meet the provider-source bar? This is the only
  path to T1 for this family. The ruling likely also decides sibling #659.
- Empirical check of one freshly issued org token and one Internal
  Integration token, as specified in the
  [web-search pass](https://github.com/redact-secret/redact-secret/issues/658#issuecomment-5785992810).
  It would settle the `sntryi_` versus `sntrys_` attribution conflict
  (Glean docs). It cannot supply a T1 source. Record counts only; revoke
  each key.
- Twin pairs remain 0 < 5 regardless of the ruling.

## What this document does not do

It changes no detector, contract, fixture, or tier.
`docs/contracts/precision/precision-contracts.json`, `benchmarks/support-matrix.json`
and the benchmarks `assessment.ts` are untouched; any re-tier or `covers`
edit happens in the T1 re-tier batch of #575. It contains no credential and
no full example token value. Several public GitHub issues carry what look
like live org tokens; they are not linked here.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
