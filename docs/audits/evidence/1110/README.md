---
owner: #1110
reviewed_source: f6f481b168b000ac27e8d60598cd2cb5c0265d59
status: in-progress
retire_on: after-issue:#1110
---

# #1110 Ory siblings: evidence reconciliation and adoption ruling

Temporary review. Written 2026-10-07 before implementing
[#1110](https://github.com/redact-secret/redact-secret/issues/1110). The
implemented contract is in the
[detector families spec](../../../specs/detector-families.md#beta15-ory-session-and-oauth2-tokens-1110)
and the machine-readable form is
[`ory-siblings.handoff.json`](../../../contracts/contribution/examples/ory-siblings.handoff.json).
No credential was issued or requested; no value here is a real key.

## Reconciliation

The historical handoff is the
[#1014 Ory record](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/ory.md)
(READY for the siblings, BLOCKED for the admin keys, T1). It was re-read against
the current sources on 2026-10-07.

| Source | Result |
| --- | --- |
| `credential-evidence` (`main` at `ba1cbe6`) | No Ory record, contract or handoff exists in `records/` or `docs/`. The historical #1014 record is therefore the only research handoff. |
| `redact-secret-benchmarks` (`develop`) | No Ory contract or corpus. The support dossier `benchmarks/support/dossiers/_candidates-not-yet-families.md` lists the `ory:network-api-key` siblings as `ready`, T1, "no detector on main", and the admin keys as `issuance-gated`, T2, BLOCKED. [#583](https://github.com/redact-secret/redact-secret-benchmarks/issues/583) still lists resolving the Ory-sibling handoff (core #1110) as remaining scope. |
| Kratos `session/session.go` at `b86338d` | Re-read: `Token` is `x.OrySessionToken` + `randx.MustString(32, randx.AlphaNum)`; `x.OrySessionToken` is `ory_st_`. |
| `ory/x` `randx/sequence.go` at `5bdd368` | Re-read: `AlphaNum` is exactly `[A-Za-z0-9]`. |
| fosite `token/hmac/hmacsha.go` at `a5f0b09` | Re-read: `minimumEntropy = 32`; the token is the `RawURLEncoding` key and signature joined by `.` and split with `strings.Cut(token, ".")`. |
| [Ory token formats](https://www.ory.com/docs/security-compliance/token-formats) | Re-read: the prefix table lists `ory_at_`, `ory_rt_`, `ory_ac_`, `ory_session_`, `ory_st_`, `ory_lo_`, `ory_pat_`, `ory_apikey_`, `ory_wak_` and a bare `ory_` internal cookie prefix; no length or alphabet for any row. |
| [Talos token format](https://www.ory.com/docs/talos/reference/token-format#api-key-format) | Re-read: documents the Talos API key `<prefix>_v1_<identifier>_<checksum>` with a user-defined 1 to 16 character prefix, a Base58 identifier of about 64 characters and a Base58 HMAC-SHA256 checksum of about 44 characters, plus a JWT and a macaroon (`<prefix>_v1_<base64url>`, default `mc`) derivation. It names none of the `ory_` prefixes. |

Sibling shapes against the current sources:

| Shape | Stated by | Verdict |
| --- | --- | --- |
| `ory_st_` + exactly 32 `[A-Za-z0-9]` | Kratos generator and `randx` alphabet (code); prefix in Ory's docs | Supported. T1, R1 and R9. |
| `ory_(at\|rt\|ac)_` + base64url key of at least 43 + `.` + exactly 43 | fosite HMAC strategy (code: alphabet, separator, 32-byte entropy floor, 32-byte HMAC signature); prefixes in Ory's docs and Hydra changelog | Supported. T1, R1 and R9. The 43 floor is exact for the default and the minimum Hydra accepts; wider keys are claimed because the floor has no ceiling. |

Neither shape appears on the Talos page: it names no `ory_` prefix, so it neither
confirms nor contradicts the siblings. The code is the source for them.

## New source evidence: admin keys

The Talos page does not document `ory_pat_`, `ory_apikey_` or `ory_wak_`. Its
API key format is a different, user-prefixed layout of another product, which the
historical record already declined to use for the admin keys. Nothing on either
page gives a body length or alphabet for the three admin prefixes, so the
admin-key gate is unchanged and they are out of this contract. The Talos
structure (`<prefix>_v1_` + Base58 identifier of about 64 + `_` + Base58 checksum
of about 44, prefix 1 to 16 characters) is source-stated, but its prefix is
user-defined, so it is not an Ory-prefixed credential family; if it is wanted it
is its own piece of work with its own contract.

## Adoption ruling (2026-10-07)

The maintainer delegated this decision. Ruling: the core adopts the two sibling
shapes above as one new always-redact detector, `ory-token`, with finding types
`ory_session_token` and `ory_oauth2_token`, high confidence, `Provider`
specificity, T1. The ruling rests on the pinned provider code re-read today
(Kratos, `ory/x`, fosite) and on Ory's token-format page for the prefixes, not on
the historical record alone. The admin keys, the `ory_lo_` logout token, JWT
access tokens, enterprise custom OAuth2 prefixes and pre-2023 unprefixed session
tokens are excluded; each limitation is an exclusion. Security-first applies:
the family redacts at every confidence. Independent evaluation and
support-status promotion are separate and are not decided here.

## What the benchmarks side needs

Contract: the spec section linked above and `ory-siblings.handoff.json`. Shapes:
the two above. Twins to seed (one property each): `ory_st_` with 31 or 33 body
bytes, with `-` or `_` in the body, uppercase prefix, glued prefix or suffix;
`ory_at_` with a 42-byte key, a 42- or 44-byte signature, no `.`, two `.`, `+` or
`/`. Benign and excluded: cookie names, placeholders, `ory_lo_`, the admin
prefixes, a JWT that only mentions `ory_at_`. Carriers are listed in the spec.
The admin keys stay a structure-only issuance check owned by the benchmarks
issuance research issue.
