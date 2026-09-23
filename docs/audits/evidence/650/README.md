# Issue #650 — T1 provider evidence for `generic:bearer-token`

[Audit archive](../../README.md) ·
[Issue #650](https://github.com/redact-secret/redact-secret/issues/650) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[RFC research pass](https://github.com/redact-secret/redact-secret/issues/650#issuecomment-5784934512) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/650#issuecomment-5785324331) ·
[Bearer contract freeze](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Prior evidence: #553](../553/README.md)

Written 2026-09-23 on branch `chore/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND-partial, for the carrier grammar only

A generic Bearer credential has no issuing provider, so the only possible
"provider" is an RFC, and the T1 bar in `benchmarks/lib/assessment.ts` admits
one ("The provider (or an RFC) documents the lexical shape the contract
requires"). RFC 6750 §2.1 states the scheme keyword, separator, value
alphabet and padding position. It does not define the token itself (§5.2),
and it states no length.

The RFC pass in the issue recorded **NOT FOUND — EXHAUSTIVE** on a stricter
reading: every accepted RFC-backed T1 contract (`jwt`, `private-key`) carries
its identifying element inside the secret span, while here the `Bearer`
keyword sits outside it. Both readings rest on the same RFC text. Which one
applies is a maintainer decision for the T1 re-tier batch; this document
records the evidence for either.

| property | provable at T1 | basis |
| --- | --- | --- |
| scheme keyword `Bearer` (outside the span) | yes | RFC 6750 §2.1 ABNF; case-insensitive per RFC 9110 §11.1 and RFC 5234 §2.3 |
| separator (one or more SP) | yes | RFC 6750 §2.1 `1*SP` |
| value alphabet `[A-Za-z0-9._~+/-]` | yes | RFC 6750 §2.1 `b64token` |
| padding (`=` only as a trailing run, any count) | yes | RFC 6750 §2.1 `*"="` |
| value prefix / header | no | RFC 6750 §5.2: encoding and contents unspecified |
| value length (floor or ceiling) | no | none in RFC 6750; RFC 6749 §5.1 leaves size undefined |
| marker / checksum | no | none in any RFC or source checked |

## The source

`https://www.rfc-editor.org/rfc/rfc6750` §2.1 (plain text
`rfc6750.txt`, lines 252–254). Re-fetched 2026-09-23:

> `b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
> `credentials = "Bearer" 1*SP b64token`

Scope limit, same RFC, §5.2 (re-fetched 2026-09-23):

> "This document does not specify the encoding or the contents of the token"

Supporting, re-fetched 2026-09-23:

- RFC 9110 §11.1: "It uses a case-insensitive token to identify the
  authentication scheme".
- RFC 6749 §5.1: "The access token string size is left undefined by this
  specification."

`observedAt`: 2026-09-23 (first observed 2026-09-20 in the contract's
`twinSource`, and 2026-09-22 in the RFC pass). RFC 6750 is a Proposed
Standard, updated by RFC 8996 and RFC 9700, neither of which changes the
grammar. The RFC's own example value is 15 bytes, `b64token` alphabet only.

## Proposed `covers` sentence

> RFC 6750 §2.1 defines Bearer credentials as `"Bearer" 1*SP b64token`,
> establishing the case-insensitive (RFC 9110 §11.1) `Bearer` scheme keyword
> that precedes the secret span, the space separator, the value alphabet
> `ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/"` and trailing-only `=`
> padding. RFC 6750 §5.2 leaves the token's encoding and contents
> unspecified and no RFC states a length, so the 16-byte floor, the cap of
> two `=` and HTAB acceptance are project policy.

## Contradictions with the current contract

Contract (`benchmarks/lib/assessment.ts` L149 at redact-secret-benchmarks
`f57e895`): tier T3, no pattern, `twinSource` RFC 6750 §2.1. Product detector:
`crates/secret-scan-core/src/detectors/bearer_token.rs` at `7c8d62a`.

- **Padding.** The `twinSource` note says "trailing `=`"; the ABNF is `*"="`
  (any count). The product caps it at 2 (`MAX_TRAILING_EQUALS`, L22).
- **Length floor.** The product requires 16 bytes (`MIN_TOKEN_LEN`, L21).
  The RFC states none, and its 15-byte example is a false negative under the
  floor.
- **Separator.** The RFC requires SP; the product also accepts HTAB
  (`is_space_or_tab`, L74).
- **Scheme case.** The `twinSource` note quotes `"Bearer"`; the scheme is
  case-insensitive. The product agrees (`starts_with_ci`); the note does not
  say so.
- **Position.** The RFC places the credential in the `Authorization` header
  (§2.1) or the `access_token` parameter (§2.2–2.3, no keyword). The product
  accepts `Bearer <value>` anywhere and does not detect the `access_token=`
  forms under this family.
- **Scoring route (not an evidence contradiction).** `assessment.ts` L329
  routes every `bearer-token` detector-coverage positive to `policy`,
  regardless of tier. A T1 re-tier alone would therefore not clear the
  `positiveContract` gate. `jwt` and `private-key` get their T1 from
  common-formats controls that carry an offline validator (L334); no such
  validator is possible for an arbitrary `b64token` value. The separate
  `minimumTwinPairs: 3 < 5` gate is also untouched by this evidence.

## Sources checked

The issue's required source classes assume a vendor; for an IETF standard
they map as below. The URL-level tables are in the
[RFC pass](https://github.com/redact-secret/redact-secret/issues/650#issuecomment-5784934512)
(all 2026-09-22) and the
[broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/650#issuecomment-5785324331).
Rows marked 2026-09-23 were added or re-fetched for this record.

| source class (issue) | IETF equivalent checked | result |
| --- | --- | --- |
| product docs and API reference | RFC 6750 §2.1–2.3, §5.2 (re-fetched 2026-09-23); RFC 6749 §1.4, §5.1 (re-fetched 2026-09-23), §A.12, §10.10; RFC 9110 §11.1–11.6 (re-fetched 2026-09-23); RFC 7235; RFC 5234 §2.3 | carrier grammar found; token contents and length unspecified |
| changelog / release notes | RFC 6750 errata (5335, 6161, 9053, 9054); updating RFCs 8996, 9700; datatracker status | no change to the grammar; no token format |
| engineering / security blog | IETF OAuth WG list (2010 length thread; 2011-12-12 Mike Jones reply to the draft-14 APPS review, fetched 2026-09-23); successor draft-ietf-oauth-v2-1-16 §1.4.2 | "no requirement on the particular structure or format of a bearer token" |
| secret-scanning partner pages | GitHub supported-patterns list (`http_bearer_authentication_header`, generic, no grammar); IANA http-authschemes and oauth-parameters registries | no format; tool corroboration only |
| SDK / CLI docs | companion profiles RFC 9068, 9449, 8693, 7662 | tokens opaque; DPoP uses the same `token68` syntax |

Broad discovery (non-provider, corroboration only): Stack Overflow, Hacker
News, the Auth0 blog, the Gravitee and Microsoft Q&A forums, Nosey Parker,
gitleaks/betterleaks, GitGuardian, secrets-patterns-db and TruffleHog, all
recorded in the broad-discovery pass. On 2026-09-23 this record also opened
the fly.io post "API Tokens: A Tedious Survey", which states no lexical format
for generic Bearer tokens, and ran a Reddit-restricted web search, which
returned no Reddit results.

Not read: the Semgrep `hardcoded-bearer-token` rule (registry page renders
empty without JavaScript; the raw rule path returned 404), the Xygeni detector
index, and Reddit threads (no search hits; direct access login-walled). All
three are tool or community sources and cannot meet the T1 bar, so they do not
change the verdict.

## Open items

- **Maintainer decision.** Whether an RFC grammar whose identifying element
  lies outside the secret span meets the T1 bar. If yes, the family joins the
  T1 re-tier batch with the `covers` sentence above, and the L329 scoring route
  needs its own change before the `positiveContract` gate can pass. If no, the
  issue's RFC-pass verdict (NOT FOUND — EXHAUSTIVE) stands and the family
  stays T3.
- **Twin pairs.** `minimumTwinPairs: 3 < 5` is independent of this evidence.
  The RFC makes alphabet, separator, padding position and scheme-keyword twins
  provable; length and prefix twins are not.
- **Empirical check.** The policy choices (16-byte floor, cap of two `=`) can
  be measured against real issuers as listed in the broad-discovery pass.
  Record lengths and character classes only.

## What this document does not do

It changes no detector, contract, fixture, or tier.
`docs/contracts/precision/precision-contracts.json` and the benchmarks
contract table are untouched; any re-tier or `covers` edit happens in the T1
re-tier batch of #575. It contains no credential and no full example token
value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
