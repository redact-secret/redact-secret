# Issue #652 — T1 provider evidence for `generic:otp-seed`

[Audit archive](../../README.md) ·
[Issue #652](https://github.com/redact-secret/redact-secret/issues/652) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Research pass 1](https://github.com/redact-secret/redact-secret/issues/652#issuecomment-5784956222) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/652#issuecomment-5785438819) ·
[Benchmarks counterpart #112](https://github.com/redact-secret/redact-secret-benchmarks/issues/112)

Written 2026-09-23 on branch `chore/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: FOUND-partial, envelope and alphabet only, conditional on the provider attribution

A Google-domain copy of Google's *Key Uri Format* documents the `otpauth`
envelope, the `hotp`/`totp` type set and a REQUIRED Base32 `secret`. It
states no length. No RFC defines `otpauth`. The two IETF drafts are
individual submissions, and one of them has expired.

The finding depends on a reviewer judgement that this document cannot make:
that Google counts as the "provider" of a generic OTP seed. If reviewers
reject that attribution, read this as **NOT FOUND — EXHAUSTIVE as of
2026-09-23**. Every source class the issue requires was checked (see below).

| property | provable at T1 | basis |
| --- | --- | --- |
| marker: `otpauth://` scheme plus `hotp`/`totp` type | yes (if Google is accepted as provider) | Key Uri Format, Google Code Archive copy |
| delimiter: `?` opens PARAMETERS, `secret=` key, REQUIRED | yes (same condition) | same source |
| alphabet: Base32, `A–Z` `2–7`, `=` padding | yes, uppercase set only | same source, "Base32 according to RFC 3548"; alphabet from RFC 4648 §6 (the successor of RFC 3548) |
| lowercase value is out of grammar | no | RFC 4648 describes base32 as designed for case-insensitive forms, and Google's own consumer uppercases input |
| length (contract floor 16) | no | provider states none; the RFC 4226 §4 R6 floor of ≥128 bits (26 chars) applies only to HOTP and conflicts with the 16 |
| prefix on the seed body | not applicable | the seed has no prefix; the scheme is the marker |
| checksum | no | none exists |

## The source

`https://storage.googleapis.com/google-code-archive/v2/code.google.com/google-authenticator/wiki/KeyUriFormat.wiki`
is the raw wiki file from Google's Code Archive of the Google-owned
`google-authenticator` project. The archive's `wikis.json` lists
`/KeyUriFormat.wiki`. Re-fetched 2026-09-23 (HTTP 200):

> `otpauth://TYPE/LABEL?PARAMETERS` (line 6)

> Valid types are **hotp** and **totp**, to distinguish whether the key will be used for counter-based HOTP or for TOTP. (line 23)

> REQUIRED: The **secret** parameter is an arbitrary key value encoded in Base32 according to [RFC 3548](http://tools.ietf.org/html/rfc3548). (line 43)

`observedAt`: 2026-09-23 (first observed 2026-09-22). The archive copy has no
padding sentence and no length.

**Why this is the Google-attributable copy.** Three facts tie the document to
Google:

1. The original `code.google.com/p/google-authenticator/wiki/KeyUriFormat` URL
   returned 301 to `https://github.com/google/google-authenticator` on
   2026-09-23. One earlier request returned 503.
2. `https://firebase.google.com/docs/auth/web/totp-mfa` (re-fetched 2026-09-23)
   links the document from the words "a Google Authenticator-compatible key URI".
3. IANA's provisional `otpauth` registration
   (`https://www.iana.org/assignments/uri-schemes/prov/otpauth`, registered
   2020-05-14, re-fetched 2026-09-23) cites the GitHub-wiki copy as
   reference [3]. The change controllers are two individuals. Google is not
   one of them.

The copy on the GitHub wiki
(`https://github.com/google/google-authenticator/wiki/Key-Uri-Format`,
re-fetched 2026-09-23) adds this sentence: "The padding specified in RFC 3548
section 2.2 is not required and should be omitted." Pass 1 traced the
sentence to a 2017-05-04 community edit (`f061a58`, account `nzgeek`) on a
publicly editable wiki. Google did not write it.

**RFC anchors.** These were re-fetched 2026-09-23 from `rfc-editor.org`. None of
them defines `otpauth`.
- RFC 4226 §4 R6: "The length of the shared secret MUST be at least 128 bits. This document RECOMMENDs a shared secret length of 160 bits."
- RFC 6238: "Keys SHOULD be of the length of the HMAC output".
- RFC 4648 §6 gives the Base32 alphabet and describes it as for "a form that needs to be case insensitive".

## Proposed `covers` sentence

> Google's Key Uri Format (Google Code Archive copy of the google-authenticator
> project wiki; the document Google's Firebase TOTP docs link as the
> "Google Authenticator-compatible key URI" and IANA's provisional `otpauth`
> registration cites) documents the `otpauth://TYPE/LABEL?PARAMETERS`
> envelope, TYPE ∈ {hotp, totp}, and a REQUIRED `secret` parameter encoded in
> Base32 per RFC 3548 (alphabet A–Z2–7 per RFC 4648 §6). It states no secret
> length: the 16-character floor is project policy, and RFC 4226 §4 R6's
> 128-bit MUST is stricter than it. The GitHub wiki's "padding should be
> omitted" sentence is a 2017 community edit and is not provider-attributed.

## Contradictions with the current contract

The contract is `otpauth-uri` in `redact-secret-benchmarks`
`benchmarks/lib/assessment.ts` L151 at `f57e895` (main, 2026-09-23). It has
tier T3 and no `pattern`. `docs/contracts/precision/precision-contracts.json`
has no otpauth entry. The spec row is `docs/specs/detector-families.md` L65
(`otpauth_secret`, `always-redact`, generic policy default). The detector is
`crates/secret-scan-core/src/detectors/otpauth.rs`: literal lowercase
`otpauth://totp/` or `otpauth://hotp/`, and a value of `[A-Z2-7]{16,}=*`
that fills the whole parameter.

- **`twinSource` provenance.** The contract cites the GitHub wiki for "padding
  omitted". That text is the 2017 community edit, and the Google-hosted
  original does not contain it. The detector's acceptance of trailing `=` is
  consistent with the original.
- **Length floor.** The detector sets `MIN_SECRET_LEN = 16` (80 bits). That
  is below RFC 4226 R6's MUST of ≥128 bits, RFC 6238's SHOULD (160 bits for
  SHA-1) and Apple's documented "at least 160 bits". The detector's doc
  comment calls 128 bits "recommended", but RFC 4226 makes it a MUST. The only
  provider anchor for 16 is Google's Android consumer, which sets
  `MIN_KEY_BYTES = 10` for manual entry only. That anchor is provider code,
  not docs.
- **Case (false negative).** The detector rejects lowercase values. RFC 4648
  describes base32 as designed for a case-insensitive form, Google's consumer
  uppercases input, and Microsoft Entra documents a–z as valid in its CSV
  seed. Because of this, a lowercase twin cannot be proven from the provider.
- **Scheme case (false negative).** The detector matches the scheme only in
  lowercase. Google's consumer lowercases the scheme before comparing it
  (provider code).
- **`%3D` padding and `apple-otpauth://` (false negatives).** Both are
  recorded in the passes. Neither affects the T1 bar.

None of these is decided here.

**Harness gap** (recorded only; see pass 1 §2). `classifyFixture` sends every
`detector-coverage` positive for `otpauth-uri` to policy/T3 (L329 at
`f57e895`). A T1 move would need four changes:
- a `providerSource` that points at the archive URL;
- a `pattern` over the inner span, with `covers` saying the 16 is policy;
- an envelope content check;
- a `common-formats` positive, which is hash-pinned.

## Sources checked

Every class required by the issue was checked on 2026-09-22. The load-bearing
pages were re-fetched on 2026-09-23. The full URL-level tables are in
[pass 1 §3](https://github.com/redact-secret/redact-secret/issues/652#issuecomment-5784956222)
and the
[broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/652#issuecomment-5785438819).

| source class | result |
| --- | --- |
| product docs and API reference (incl. OpenAPI/JSON schemas) | Key Uri Format (archive copy): envelope, type, Base32, no length. `support.google.com/accounts/answer/1066447` and `/a/answer/175197` have no otpauth or Base32 text. Google publishes no API or OpenAPI schema for this format |
| changelog / release notes | `google-authenticator` has 1 tag and 0 releases. The `google-authenticator-android` v2.21 and v5.00 release notes contain no format statement |
| engineering / security blog | security.googleblog.com 2023-04 sync post has no format. Site searches of security.googleblog.com, blog.google, support.google.com and developers.google.com found no format document |
| secret-scanning partner pages | GitHub supported-patterns list has no OTP or otpauth pattern. There is no provider token-format announcement (a generic seed has no issuer) |
| SDK / CLI docs on provider domain | Firebase TOTP MFA docs (web, android, ios) link the Key Uri Format and define no grammar of their own. The `google-authenticator-libpam` README says "alphanumeric secret key" |
| RFC / standards (generic-family route) | RFC 4226, 6238, 4648 and 3548 define no `otpauth`. IANA registration is Provisional. `draft-linuxgemini-otpauth-uri-03` is an individual submission, active until 2027-02-25. `draft-andesco-otpauth-uri-00` is an individual submission that expired 2026-08-23. Datatracker was re-checked 2026-09-23 |
| other vendors, community, tools (corroboration only) | Apple, Microsoft Entra, AWS IAM, Twilio, Reddit, SO, HN, GitHub issues, five scanner rule sets. See the broad-discovery pass. None meets the bar |

Not read: most Reddit threads (the host is blocked, and two were read via
Wayback) and one JS-rendered Google support thread. They are recorded as
unchecked. None of them can meet the T1 bar, so they do not change the
verdict.

## Open items

- **Reviewer decision on attribution.** Is Google's Key Uri Format the
  provider document for a generic OTP seed under the existing T1 precedent?
  Yes gives FOUND-partial as above. No gives NOT FOUND — EXHAUSTIVE as of
  2026-09-23.
- **Length floor.** Choose between 16 (Google consumer code, historical
  producers) and 26 (RFC 4226 MUST). This belongs to the T1 re-tier batch.
- **Optional empirical check.** Decode one freshly issued Google, GitHub, AWS
  and Microsoft enrolment URI offline and record counts and classes only.
  This settles case, padding and length in practice. The procedure is in the
  [broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/652#issuecomment-5785438819).

## What this document does not do

It changes no detector, contract, fixture or tier.
`docs/contracts/precision/precision-contracts.json` and the benchmarks
`assessment.ts` are untouched. The re-tier and any `covers` edit happen in
the T1 re-tier batch of #575. It contains no credential and no example seed
value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
