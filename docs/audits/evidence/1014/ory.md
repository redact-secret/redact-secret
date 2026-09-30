# #1014 handoff: `ory:network-api-key` (Ory session and OAuth2 siblings)

[#1014 index](README.md) · rank 26 ·
[Research table #39](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447540)

**Readiness: READY for the siblings (`ory_st_` session token; `ory_at_`,
`ory_rt_`, `ory_ac_` OAuth2 tokens). BLOCKED for the candidate as named: the
Network admin keys (`ory_pat_`, `ory_apikey_`, `ory_wak_`).** **Route:** new
detector `ory-token`, finding types `ory_session_token` and
`ory_oauth2_token`. The admin keys get no type until the gate clears.

## Role and blast radius

- `ory_st_` is an Ory Kratos session token, sent as `X-Session-Token` by
  native and API clients. A leaked token is an account takeover for the
  session lifetime, and sessions are routinely logged by identity debugging.
- `ory_at_` and `ory_rt_` are Ory Hydra opaque OAuth2 access and refresh
  tokens; `ory_ac_` is an authorization code. An access token acts for the
  subject within its scopes; a refresh token mints new ones.
- The admin keys are the higher blast radius but not derivable today: a
  project API key (`ory_pat_`/`ory_apikey_`) calls the Admin API (identities,
  OAuth2 clients, relationships), and a workspace key (`ory_wak_`) manages
  projects and organizations.

## Discovery (broad first, source classes labelled afterwards)

Searched, 2026-09-30: web search for each prefix with "length", "regex",
"example"; GitHub issues and repositories; scanner rule sets (gitleaks
`b58d3f1`, trufflehog `48b58d3`, noseyparker `2e6e7f3`, betterleaks, the
GitHub partner list, Veles); third-party blog posts showing Hydra output;
provider docs and changelogs. Findings by class:

| Source | Class | What it gives |
| --- | --- | --- |
| [kratos `session.go#L279-L280`](https://github.com/ory/kratos/blob/b86338da04a040247a07f46100a86dcfb3875909/session/session.go#L279-L280), [`x/token_prefixes.go`](https://github.com/ory/kratos/blob/b86338da04a040247a07f46100a86dcfb3875909/x/token_prefixes.go) (prefix constants dated 2023-03-17) | provider code (R1, R9) | `ory_st_` and `ory_lo_` + `randx.MustString(32, randx.AlphaNum)` |
| [ory/x `randx/sequence.go`](https://github.com/ory/x/blob/5bdd368ee69b399f4dccbd4ceb3837cd5d623795/randx/sequence.go#L16-L17) | provider code (R1) | `AlphaNum` is exactly `[A-Za-z0-9]` |
| [fosite `token/hmac/hmacsha.go#L39-L83`](https://github.com/ory/fosite/blob/a5f0b09bf31c17297b25637bb3fec2ff7a55b159/token/hmac/hmacsha.go#L39-L83) (2025-07-03) | provider code (R1, R9) | token = `RawURLEncoding(key)` + `.` + `RawURLEncoding(HMAC-SHA512/256 signature)`; `minimumEntropy = 32` bytes, configurable upward |
| [hydra CHANGELOG `#L3417`](https://github.com/ory/hydra/blob/4174065ffb052799890f7480f5360a877a67ffc1/CHANGELOG.md#L3417) | provider changelog | "adds token prefixes to access tokens (`ory_at_`), refresh tokens (`ory_rt_`), and authorize codes (`ory_ac_`) ... useful when scanning for secrets ... only issued for non-JWTs" |
| [Ory token formats](https://www.ory.com/docs/security-compliance/token-formats), observed 2026-09-30 | provider docs | prefix table for all of the above and the admin keys; "when using JSON Web Tokens (JWTs), the prefix is not applied"; no lengths |
| [Ory changelog v26.2.13](https://changelog.ory.com/announcements/ory-network-ory-hydra-ory-kratos-ory-keto-v26-2-13-released), 2026-05-22 | provider changelog | enterprise projects can set a custom OAuth2 prefix (`fmt.Sprintf` template, one `%s` for `at`/`rt`/`ac`); "Leave the setting empty to keep the default `ory_%s_` prefix"; prefix limited to ASCII letters, digits and underscores |
| [hydra#3856](https://github.com/ory/hydra/issues/3856), 2024-10-08, closed as not planned | issue (community) | confirms the defaults are hard-coded and unchanged by the request |
| [terraform-provider-ory README](https://github.com/ory/terraform-provider-ory/blob/da33c56623b927b2cade727279a89e18cd37eb53/README.md) | provider docs | `ory_pat_...` project key, `ory_wak_...` workspace key, placeholders only |
| [Ory API keys docs](https://www.ory.com/docs/concepts/personal-access-token) | provider docs | "Ory API Keys have a `ory_apikey_` or `ory_pat_` prefix"; no length or alphabet |
| [Ory Talos token format](https://www.ory.com/docs/talos/reference/token-format) | provider docs (other product) | `<prefix>_v1_<identifier ~64 Base58>_<checksum ~44 Base58>`, user-defined 1-16 char prefix; does not mention `ory_pat_` |
| blog posts quoting Hydra output | third-party observation | full-width `ory_at_`/`ory_rt_` examples (43 + `.` + 43) and one visibly shorter example that looks abbreviated |

Scanner coverage: gitleaks, trufflehog, noseyparker and the GitHub partner
list have no Ory rule. Nothing independent of Ory publishes an admin-key
body.

## Supported shape

All bodies are derived from two Ory sources each (provider code plus provider
docs or changelog). Test values are built at run time.

| Role | Prefix | Body | Tier |
| --- | --- | --- | --- |
| Kratos session token | `ory_st_` | exactly 32 `[A-Za-z0-9]` (39 total) | T1 (R1, R9: prefix, length and alphabet from the generator; prefix also in docs) |
| Hydra access token | `ory_at_` | key: at least 43 `[A-Za-z0-9_-]`; `.`; signature: exactly 43 `[A-Za-z0-9_-]` | T1 (R1, R9 code; prefix from docs and changelog) |
| Hydra refresh token | `ory_rt_` | same | T1 |
| Hydra authorization code | `ory_ac_` | same | T1 |

Derivation of the Hydra widths. The key is `entropy` random bytes, at least
32, as unpadded URL-safe Base64: 32 bytes is 43 characters, and each extra
byte adds 1 or 2, so the key part has no fixed ceiling (the operator can
raise the entropy). The signature is HMAC-SHA512/256 = 32 bytes = 43
characters. The `.` separator is the only `.` in the token.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `ory_pat_`, `ory_apikey_`, `ory_wak_` admin keys | BLOCKED: no provider source gives a body length or alphabet (see What is missing) |
| `ory_lo_` logout token (`ory_lo_` + 32 alphanumeric) | same generator as the session token and grammar is T1, but it is a flow token passed in a logout URL, not an account credential; out of the first contract and claimable later with the same body |
| JWT access tokens | the prefix is not applied to JWTs; they stay with `jwt` (R7) |
| Enterprise custom OAuth2 prefixes (`<custom>_at_`) | not distinctive; accepted false negative |
| `ory_session_…`, `ory_kratos_session`, other `ory_` cookie names | cookie names, not tokens; fail every body grammar above |
| Session tokens issued before the 2023-03-17 prefix change | unprefixed; no distinctive shape |

## Tier rationale

- **Session token:** T1 under R1 and R9. The generator fixes prefix, length
  and alphabet, and the docs confirm the prefix.
- **OAuth2 tokens:** T1 under R1 and R9. The fosite strategy fixes the
  alphabet, the separator, the signature width and the 43-character floor of
  the key part. The floor is exact for the default entropy and the minimum
  Hydra accepts; wider keys are still claimed because the floor is open
  ended, which is the same handling as Buildkite and Fly.
- **Admin keys:** prefix T1 (docs, SDK and Terraform README), length and
  alphabet not found: BLOCKED. Talos is a separate product with a
  user-defined prefix; nothing ties `ory_pat_` to its layout, so it is not
  used to fill the gap.

## What is missing (admin keys)

The exact gap is the body of `ory_pat_`, `ory_apikey_` and `ory_wak_`: total
length and alphabet, and whether a checksum segment exists. The Ory Network
key service is closed source, Ory's docs and Terraform README show
placeholders only, and no scanner rule exists. Closing it needs one of:

1. a maintainer-issued project API key and workspace API key checked for
   structure only (issuance checklist below); or
2. a provider statement (docs, staff, or an Ory-authored scanner rule) that
   gives the widths.

A policy floor (`[A-Za-z0-9_-]{20,}` was floated in step 1) is not proposed:
no R10 extension covers Ory and the floor would be a guess.

## Overlap and output policy

- **Existing detectors.** None claims `ory_`. Step 1 measured the env
  context (`ORY_*=`) as a generic `contextual_secret`; the bare, chat and
  JSON `"token"` occurrences are missed. A `ory_at_` token is a `.`-joined
  pair and is not a JWT (no `eyJ` header, two segments), so `jwt` does not
  fire.
- **Longest-prefix order.** None of the four prefixes is a prefix of another.
- **New output.** Two provider types, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector`. `ory_st_` as `PrefixShape::exact(…, 32,
is_alnum, …)`. The OAuth2 shapes are a two-segment body: key `[A-Za-z0-9_-]`
run of at least 43, one `.`, then exactly 43 of the same class, then a
boundary that also rejects a following `.` plus a third segment, so a
three-segment JWT never matches. Signals: `ory-generator-prefix`,
`ory-hydra-hmac-shape`.

## Test axes

**Positives:** every #860 index context for each role; `X-Session-Token:`
header; `Authorization: Bearer ory_at_…`; `ORY_ACCESS_TOKEN=`;
`Ory(access_token=…)`; an OAuth2 token response JSON; a key part of 44 and
48 bytes (raised entropy).

**Near-miss twins:** `ory_st_` with 31 or 33; `ory_st_` with `-` or `_`;
`ory_at_` with a 42-byte key; a 42-byte or 44-byte signature; a missing `.`;
two `.`; a `+` or `/` in the body; `ORY_ST_` uppercase; a leading and a
trailing glue byte.

**Benign:** `ory_kratos_session` and `ory_session_…` cookie names; `ory_st_`
placeholders shorter than 32; a JWT whose payload mentions `ory_at_`;
`ORY_SESSION_TOKEN=${ORY_SESSION_TOKEN}`; an `ory_pat_` placeholder.

## False-positive / false-negative boundary

- **Accepted false negatives:** admin keys until the gate clears; JWT access
  tokens (R7); tokens with an enterprise custom prefix; an operator-changed
  HMAC hasher (signature width differs); pre-2023 unprefixed session tokens;
  an unusually short third-party example that does not match the code.
- **Accepted false positives:** an unrelated `ory_(st|at|rt|ac)_` run of the
  exact width; none is known.

## Issuance checklist (structure only; admin keys)

For one Ory Network project API key and one workspace API key (the session
and OAuth2 tokens do not need it):

- prefix and total length;
- whether the body has `_` or `.` separators and their segment lengths;
- alphabet class of each segment (hex, base62, base58, base64url);
- `rawValueRetained: false` and revoked.

Follow the [#860 issuance-check protocol](../860/README.md#issuance-check-protocol-structure-only).
No key was requested or issued for this record.
