# #1014 handoff: `fly:access-token`

[#1014 index](README.md) · rank 20 ·
[Research table #18](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447016)

**Readiness: READY, conditional on ruling Q7** (a floor derived from provider
wire-format code is T1). **Route:** new detector `fly-token`, finding type
`fly_access_token`, claiming the token run that begins at the first `fm1r_`,
`fm1a_` or `fm2_` member, including any comma-joined `fo1_` member. A bare
`fo1_` token is not claimed.

## Role and blast radius

Fly.io macaroon tokens authorize the Fly API and Machines API. The provider
documents that `fly tokens create` makes deploy, org and read-only tokens,
with "20 years" as the default validity. Scope varies by caveat from one app
to an entire org. `fly auth login` produces a session bundle
(`fm2_…,fo1_…`) that acts as the user. Tokens live in `FLY_API_TOKEN`,
`FLY_ACCESS_TOKEN` and CI secrets, where the documented copy step includes the
`FlyV1 ` scheme and a space.

## Supported shape

Discovery was broad first (web search, GitHub issues and PRs, community
posts, scanner rule sets, provider code), sources labelled afterwards.
Re-checked 2026-09-30.

- **Provider code (R1), wire format.** `superfly/macaroon` `format.go` at
  [`a0202e1`](https://github.com/superfly/macaroon/blob/a0202e10fd947786884323dcbce46efbe8652171/format.go#L11-L60)
  (2024-07-18): labels `fm1r`, `fm1a`, `fm2`, `fo1`; scheme `FlyV1`; `Parse`
  strips the scheme case-insensitively, splits on `,`, `strings.Cut(tok,
  "_")`, `base64.StdEncoding.DecodeString` for `fm*` members and skips `fo1`
  members; `encodeTokens` joins members with `,`. Decoded size: `nonce.go`
  has `nonceRndSize = 16`, `crypto.go` signs with HMAC-SHA256 (32 bytes) and
  `macaroon.go` stores the tail, so any decoded macaroon holds at least
  16 + 32 = 48 bytes, which is at least 64 standard-Base64 characters.
- **Provider-authored redaction rule (R2).** `superfly/flyctl`
  `agent/server/session.go` at
  [`fe73b72`](https://github.com/superfly/flyctl/blob/fe73b7215a0ce2ed8e846d927446c1577cbcc217/agent/server/session.go#L685)
  (last change 2026-09-25): `redactTokenRx =
  (fo1_|fm1[ar]_|fm2_)[a-zA-Z0-9/+_-]+=*`. This is Fly's own redaction of
  tokens in agent logs: the prefix set, an alphabet that covers both
  standard Base64 and URL-safe characters, optional `=` padding, and no length
  bound (`+`).
- **Provider docs.** "Access tokens", <https://docs.fly.io/security/tokens/>:
  scoped tokens start `fm2_`, a default 20-year lifetime, advice to use the
  narrowest token. No length or alphabet statement.
- **Community and issues, empirical (T2).** A flyctl fork issue
  ([Roshan931/flyctl#8](https://github.com/Roshan931/flyctl/issues/8),
  2026-09-29) measures a deploy token of 691 characters in the
  `FlyV1 fm2_…,fm2_…` form and notes third-party fields that silently stored
  a 116-character truncation; a Dork Labs PR
  ([dork-labs/dorkos#2388](https://github.com/dork-labs/dorkos/pull/2388))
  describes `fm2_…` scoped tokens, `fo1_…` session tokens, `FlyV1` for macaroons
  and a 4096-character client limit.
- **Scanner rule sets (T2, disagree).** gitleaks `flyio-access-token`
  ([`b58d3f1`](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml#L582-L590)):
  `fo1_[\w-]{43}` and `fm1[ar]_`/`fm2_` + `[a-zA-Z0-9+/]{100,}={0,3}`;
  trufflehog `flyio`: `FlyV1 fm\d+_[A-Za-z0-9+/=,_-]{500,700}`.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Member prefix | `fm1r_`, `fm1a_`, `fm2_` | wire-format code, provider redaction rule | T1 (R1, R2) |
| Member body | `[A-Za-z0-9+/_-]` run, then `=`{0,2}; floor 64 | alphabet: provider redaction rule (R2) and `StdEncoding` (R1); floor: derived from the 48-byte minimum decoded macaroon | alphabet T1; floor T1 only with Q7 |
| Bundle separator | `,` between members | `Parse`/`encodeTokens` (R1) | T1 |
| Trailing `fo1_` member | `fo1_` + `[A-Za-z0-9/+_-]+` inside a bundle that already has an `fm` member | redaction rule (R2); length of a standalone `fo1_` is not provider-stated (gitleaks 43 is T2) | T1 as bundle member only |
| Scheme | optional `FlyV1 ` before the first member | `StripAuthorizationScheme` (R1) | T1, not part of the redacted span |

The span starts at the first member prefix and ends at the last body or `=`
byte of the last member. The scheme and its space are left in place.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Standalone `fo1_` token | no provider-stated length; 43 URL-safe bytes rests on gitleaks (T2). Stays with generic coverage; Q9 asks whether to claim it with a policy floor |
| `fm1r_`/`fm1a_`/`fm2_` with a body below 64 characters | below the smallest decodable macaroon; includes the tiny fixtures `fm2_hi` in flyctl tests |
| `Bearer` value from `fly auth token` of another shape | not found in provider sources; no claim |
| A truncated token (for example 116 characters) | still claimed if at least 64, which is an intended redaction; the truncation is a user-side fault, not a grammar |

## Tier rationale

The prefixes, the comma bundle, the alphabet and the absence of any upper
bound are provider facts (R1 wire-format code, R2 Fly's own redaction rule).
The only non-provider number is the 64-character floor. It is derived, not
stated, so it needs Q7. Gitleaks' 100 and trufflehog's 500 are scanner
choices and are not used; a floor of 100 would still miss no real token seen
(deploy tokens reported at 500 to 700 characters) and is an acceptable
alternative if the maintainer prefers a stricter floor.

## Overlap and output policy

- **Existing detectors.** None claims `fm2_`/`fm1r_`/`fm1a_`/`fo1_`.
  Measured on `main` `b9e9091`: `FLY_API_TOKEN=FlyV1 fm2_…` unquoted is
  **missed** today (the space after the scheme ends the contextual value); the
  quoted form and the form without the scheme are found. This detector closes
  that case because the span starts at `fm2_` regardless of the scheme.
- **`bearer-token`.** `Authorization: FlyV1 …` is not a `Bearer` header, and
  `Authorization: Bearer fm2_…` is also claimed by this contract; the provider
  finding must win, as with other provider prefixes.
- **New output.** One provider type, high confidence, always redact.

## Implementation notes

A custom token-run detector (not one fixed-width `PrefixShape`): find a member
prefix at an identifier boundary, consume `[A-Za-z0-9+/_-]` then `=`{0,2},
require at least 64 body characters, then while the next byte is `,` followed
by a member prefix (`fm1r_`, `fm1a_`, `fm2_`, `fo1_`) consume that member too.
Boundary before the first prefix: not `[A-Za-z0-9_-]`. A `,` followed by
anything else ends the run. Signals: `fly-macaroon-prefix`,
`fly-macaroon-floor`.

## Test axes

**Positives:** every #860 index context; `FLY_API_TOKEN=FlyV1 fm2_…` unquoted
and quoted; `FLY_API_TOKEN=fm2_…`; a GitHub Actions `env:` secret line; a
`Authorization: FlyV1 fm2_…,fm2_…` header; a two-member and a three-member
bundle; a session bundle ending `,fo1_…`; `fm1r_` and `fm1a_` members; a body
with `+`, `/`, `-`, `_`; `=` and `==` padding; bodies of 64, 100, 700 and 2000
characters.

**Near-miss twins:** body of 63; `fm3_`; `fm2-`; `FM2_` uppercase; a comma
followed by a non-member; a leading glue byte; a bare `fo1_` of 43 bytes.

**Benign:** `fm2_hi`-style fixtures; identifiers such as `fm2_config_path`;
`FlyV1` alone; `FLY_API_TOKEN=${FLY_API_TOKEN}`.

## False-positive / false-negative boundary

- **Accepted false negatives:** a standalone `fo1_`; a body under the floor; a
  future prefix (`fm3`); any non-comma separator between members.
- **Accepted false positives:** an unrelated `fm2_` + at least 64 alphabet
  bytes (a Base64 blob after an identifier that happens to end `fm2_`; the
  boundary rule removes the glued case). None is known.

## Issuance checklist (optional confirmation; structure only)

For one deploy token and one session bundle: member count, each member prefix
and body length, whether any body contains `-` or `_` (expect standard Base64
only for `fm*`), whether `fo1_` is 43 bytes, `rawValueRetained: false` and
revoked. Not required for READY; it would replace the derived floor with an
observed minimum.
