# Issue #644 — T1 provider evidence for `datadog:api-key`

[Audit archive](../../README.md) ·
[Issue #644](https://github.com/redact-secret/redact-secret/issues/644) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass](https://github.com/redact-secret/redact-secret/issues/644#issuecomment-5784947033) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/644#issuecomment-5785363522) ·
[Web-search pass](https://github.com/redact-secret/redact-secret/issues/644#issuecomment-5786058943) ·
[Datadog contract freeze](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)

Written 2026-09-23 on branch `milocosmopolitan/beta7-research`. The three
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND, for length and marker only

A provider-domain source fixes the API key value at exactly 32 characters
and names the `DD-API-KEY` header and `DD_API_KEY` environment variable. It
states no character class. The key has no prefix, so length plus marker is
the whole identifying element.

| property | provable at T1 | basis |
| --- | --- | --- |
| length 32 (exact) | yes | `ApiKey.key` `minLength: 32` / `maxLength: 32` in the v1 spec served on docs.datadoghq.com |
| marker / keyword context (`DD-API-KEY`, `DD_API_KEY`) | yes | `securitySchemes.apiKeyAuth` in the same spec (v1 and v2) |
| alphabet (lowercase hex) | no | the spec's example is 32 lowercase hex, but no character class is stated; tool- and provider-code-corroborated only |
| prefix / delimiter | not applicable | no source of any class describes one |
| checksum / terminator | no | none documented anywhere |

## The source

`https://docs.datadoghq.com/resources/json/full_spec_v1.json` (title
"Datadog API V1 Collection"), schema `components.schemas.ApiKey`,
property `key`. Fetched 2026-09-23 (HTTP 200, `last-modified` 2026-09-17,
body sha256 prefix `6ae0e2ec3a6221bb`). Exact quote, example value left out:

> `"key": {"description": "API key.", "maxLength": 32, "minLength": 32, "readOnly": true, "type": "string"}`

Same file, `components.securitySchemes.apiKeyAuth`:

> `{"description": "Your Datadog API Key.", "in": "header", "name": "DD-API-KEY", "type": "apiKey", "x-env-name": "DD_API_KEY"}`

`observedAt`: 2026-09-23. This is new relative to the research pass, which
cited the same schema only on github.com. The provider-authored source is
`DataDog/documentation` `hugo/data/api/v1/full_spec.yaml`, re-fetched at
`master` 2026-09-23 (last changed in `2fa3c70e35`, 2026-09-17, matching the
JSON's `last-modified`), and the identical schema in
`DataDog/datadog-api-client-go` `.generator/schemas/v1/openapi.yaml`. The
rendered page `/api/latest/key-management/create-an-api-key/` shows the
v1 32-character example response but does not print the constraint, and the
JSON is not linked from that page's HTML or scripts; the docs site serves it
under its static `/resources/json/` path, which the docs content links for
other resources.

Scope limits of the constraint:

- It sits on the v1 key model (`/api/v1/api_key`, disabled on US1-FED and
  US2-FED). `full_spec_v2.json` (fetched 2026-09-23) gives
  `FullAPIKeyAttributes.key` no length; only `last4` is fixed at 4/4.
- Nothing on any source suggests v1 and v2 issue different shapes; AWS's
  partner rotation doc (v2 API) also states 32 hex, but that is not provider
  domain.

Precedent fit: same class as `sendgrid:api-key` (T1 on a provider-stated
total length, other lexical parts tool-corroborated). The T1 bar in
`benchmarks/lib/assessment.ts` is unchanged.

## Proposed `covers` sentence

> Datadog's own API reference spec (docs.datadoghq.com
> `/resources/json/full_spec_v1.json`, v1 `ApiKey` schema, generated from
> DataDog/documentation `hugo/data/api/v1/full_spec.yaml`) fixes the API key
> value at exactly 32 characters (minLength 32, maxLength 32) and names the
> `DD-API-KEY` header and `DD_API_KEY` environment variable. The constraint is
> stated on the v1 key model; the v2 schema states no length. The
> lowercase-hex alphabet is not provider-stated: the spec's example fits it,
> and it is corroborated by Datadog-owned code and tools only.

## Contradictions with the current contract

Contract (`crates/secret-scan-core/src/detectors/datadog.rs`, frozen by the
linked ADR): exactly 32 `[0-9a-f]` (`API_KEY_LEN`, `is_lower_hex`), bounded
by non-hex bytes, no prefix, gated by a same-line marker (`dd_api_key`,
`dd-api-key`, … → High; `datadog` → Medium).

- **Length, prefix, delimiter:** none. The provider source and every other
  source agree on 32 and no prefix.
- **Markers:** none. The contract's `dd-api-key` / `dd_api_key` markers are
  the provider-documented header and env-var names.
- **Alphabet case:** not a contradiction with the provider source, which is
  silent. Datadog-owned validators (agent scrubber, `privateactionrunner`
  `keys.go`, `experimental check`, dd-trace-java) accept `A-F`; datadog-ci's
  masking regex and every observed value are lowercase. A hand-uppercased key
  would be a false negative for the contract. Recorded, not decided.

Twin coverage: `benchmarks/support-matrix.json` in this worktree records 11
twin pairs (the issue body's 0 predates it), so `positiveContract` is the only
remaining failing gate.

## Sources checked

Every class required by the issue's "Done when" was checked 2026-09-22; the
load-bearing sources were re-fetched 2026-09-23. Full URL-level tables: see
the [research pass](https://github.com/redact-secret/redact-secret/issues/644#issuecomment-5784947033),
[broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/644#issuecomment-5785363522)
and [web-search pass](https://github.com/redact-secret/redact-secret/issues/644#issuecomment-5786058943).

| source class | result |
| --- | --- |
| product docs and API reference (OpenAPI the docs load) | `/resources/json/full_spec_v1.json`: 32/32 and markers (re-fetched 2026-09-23); `full_spec_v2.json`: no key length; rendered Key Management pages (re-fetched 2026-09-23): no constraint printed; `api-app-keys`, `personal-access-tokens`, SDS library rules: no API-key shape |
| changelog / release notes | `app.datadoghq.com/release-notes` login-gated, **not read**; `datadoghq.com/whats-new/` 404; datadog-agent and datadog-api-client-go changelogs: no API-key format entry |
| engineering / security blog | leaked-credentials post (2023-12-18): regex given to GitHub, not published; API-authentication post (2026-06-09): "API keys used for telemetry intake are not changing"; code-security post: nothing |
| secret-scanning partner pages | GitHub partner list: `datadog_api_key` listed, no pattern; GitHub changelog 2026-06-17: adds `datadog_pat`/`datadog_sat` only |
| SDK / CLI docs on provider domain | datadoghq.dev Python and TypeScript client docs: `key` with no length shown (Python source validations are 32/32, github.com); eleven docs.datadoghq.com agent/serverless/CI pages: no shape |

Corroboration only (not T1): Datadog-owned code on github.com (datadog-ci,
datadog-agent, dd-agent v5 `len(k) != 32`, dd-trace-java), AWS Secrets
Manager partner docs, and scanners (trufflehog, betterleaks, GitLab,
GitGuardian "Prefixed: False").

Not read: the login-gated release notes page and Reddit outside r/datadog
(blocked or rate-limited, see the web-search pass). Neither can outrank the
provider spec found, so they do not change the verdict.

## Open items

- Empirical check of one freshly issued key (length 32, any uppercase `A-F`,
  any fixed leading text, v2-created key same shape), as specified in the
  [web-search pass](https://github.com/redact-secret/redact-secret/issues/644#issuecomment-5786058943).
  It would settle the alphabet case; it cannot raise the alphabet to T1.
  Record counts only; revoke the key.
- Sibling `datadog:application-key-legacy`: the same v1 spec fixes
  `ApplicationKey.hash` at 40/40. Separate family, separate issue.

## What this document does not do

It changes no detector, contract, fixture, or tier.
`docs/contracts/precision/precision-contracts.json` and
`benchmarks/support-matrix.json` are untouched; the re-tier and the `covers`
edit happen in the T1 re-tier batch of #575 (benchmarks counterpart
redact-secret/redact-secret-benchmarks#112). It contains no credential and no
full example token value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
