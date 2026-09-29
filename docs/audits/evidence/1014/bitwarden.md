# #1014 handoff: `bitwarden:secrets-manager-access-token`

[#1014 index](README.md) · rank 1 ·
[Research table #30](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447282)

**Readiness: READY.** **Route:** new detector
`bitwarden-secrets-manager-access-token`, finding type
`bitwarden_secrets_manager_access_token`.

## Role and blast radius

A Bitwarden Secrets Manager access token authenticates a machine account
(`BWS_ACCESS_TOKEN`, used by the `bws` CLI, the SDKs and CI integrations).
The token carries both the client secret and the symmetric key that decrypts
the secrets, so a leaked token exposes every secret the machine account can
read, in plaintext. No public scanner rule or GitHub partner pattern covers
it.

## Supported shape

Sources, all provider code, re-checked 2026-09-29:

- `bitwarden/sdk-internal` `crates/bitwarden-core/src/auth/access_token.rs`
  at
  [`824c1cf`](https://github.com/bitwarden/sdk-internal/blob/824c1cf06636daa2778d53435cdbf354ab58eff2/crates/bitwarden-core/src/auth/access_token.rs#L47-L85)
  (last changed 2025-09-30). The parser splits once on `:`, splits the first
  part on `.` into exactly three parts, requires the version to be `"0"`,
  parses the second part as a UUID, and requires the Base64 key to decode to
  16 bytes. Its test comment says the key is generated with Base64 padding
  and that padding is ignored on decode.
- `bitwarden/server` `CreateAccessTokenCommand.cs` at
  [`bb3a9da`](https://github.com/bitwarden/server/blob/bb3a9daf9883353fa942a17ba5d8c2b1f642960b/bitwarden_license/src/Commercial.Core/SecretsManager/Commands/AccessTokens/CreateAccessTokenCommand.cs#L14-L29):
  `_clientSecretMaxLength = 30` and `CoreHelpers.SecureRandomString(30)`.
- `CoreHelpers.SecureRandomString` at
  [`de7104b`](https://github.com/bitwarden/server/blob/de7104b7134f51de34cb081c192ecb172020d508/src/Core/Utilities/CoreHelpers.cs#L205-L209):
  the defaults are upper, lower and numeric, with `special = false`.
- The docs example at <https://bitwarden.com/help/access-tokens/> (observed
  2026-09-29) has the same segment lengths (1, 36, 30, 24 with `==`).

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Version | literal `0` | parser (R1) | T1 |
| Separator | `.` | parser (R1) | T1 |
| Token id | UUID, 8-4-4-4-12 hex with `-` | parser `Uuid` parse (R1) + docs example | T1 |
| Separator | `.` | parser (R1) | T1 |
| Client secret | exactly 30 `[A-Za-z0-9]` | server generator (R1) | T1 |
| Separator | `:` | parser (R1) | T1 |
| Encryption key | 16 bytes as standard Base64: 22 `[A-Za-z0-9+/]` then `==` | parser length check (R1) + provider test comment + docs example | T1 |

Total length 94. The UUID is written in lowercase by the server (.NET
`Guid.ToString()`); the parser also accepts uppercase, so the contract accepts
both cases in the UUID segment.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Key without `==` padding | the parser accepts it, but the generator always pads. Claiming it would widen the issued grammar; generic context still covers a named assignment |
| Version other than `0` | the parser rejects it today; a future version is a grammar change to re-research |
| `0.<uuid>` alone, or `0.<uuid>.<secret>` without `:<key>` | not a usable token; a bare version-dotted UUID can be a benign identifier |
| Password Manager personal API key (`client_id` `user.<uuid>` + 30-char `client_secret`) | a different credential with no distinctive token grammar; stays with generic context |
| Organization API key (`organization.<uuid>` client id + secret) | same reason |

## Tier rationale

T1 for every part under R1: the provider's parser and server generator define
the grammar, and the provider docs example agrees. No scanner source is used.

## Overlap and output policy

- **Existing detectors.** None claims this shape. It is not a JWT and not a
  connection string. Measured on `main` `b9e9091`: `BWS_ACCESS_TOKEN=` gives
  `contextual_secret`; bare, chat and JSON `"token"` are missed.
- **Generic overlap.** In a named context, `contextual_secret` may cover the
  same span; the provider type wins, as for the #860 families.
- **New output.** Provider type, high confidence, always redact.

## Implementation notes

A single fixed-layout matcher: anchor on `0.` at an identifier boundary, then
check the 36-byte UUID (`-` at offsets 8, 13, 18 and 23, hex elsewhere), `.`,
30 alphanumerics, `:`, 22 Base64 bytes and `==`. This needs a small custom
shape rather than `PrefixShape`, because the literal lead `0.` is too short to
index alone; anchoring on the `.`-UUID-`.` structure is O(1) per candidate
and linear overall. Leading boundary: the byte before `0` must not be
`[A-Za-z0-9._-]` (so `10.<uuid>` and `v0.<uuid>` are not claimed). Trailing
boundary: the byte after `==` must not be `[A-Za-z0-9+/=]`. Signals:
`bitwarden-parser-layout`, `bitwarden-generator-length`.

## Test axes

**Positives:** every #860 index context; `BWS_ACCESS_TOKEN=` in `.env`;
`bws secret list --access-token …`; a GitHub Actions `with: access_token:`
block; an MCP server config `env` block; a Docker `-e BWS_ACCESS_TOKEN=`.

**Near-miss twins:**

- client secret of 29 or 31 bytes;
- a `-` or `_` in the client secret;
- key of 21 or 23 Base64 bytes, or with one `=`;
- key without padding (unclaimed by design);
- version `1.`;
- a UUID with a missing or misplaced `-`, or a non-hex byte;
- `:` replaced by `.`;
- a leading glue byte (`10.`, `v0.`, `x0.`) and a trailing glue byte.

**Benign:** a semantic version followed by a UUID (`0.` + UUID in a changelog);
`0.` + UUID + `.json`; a Password Manager `user.` client id;
`BWS_ACCESS_TOKEN=${BWS_ACCESS_TOKEN}`.

## False-positive / false-negative boundary

- **Accepted false negatives:** an unpadded copy of a token; a token split
  across lines; a future version.
- **Accepted false positives:** an unrelated string that happens to be
  `0.` + UUID + `.` + 30 alphanumerics + `:` + a 16-byte Base64 value. No
  benign format with that layout is known.

## Issuance checklist (optional confirmation; structure only)

For one machine-account token:

- total length (expect 94) and segment lengths (1, 36, 30, 24);
- alphabet classes per segment (client secret expected alphanumeric only);
- whether the key ends `==`;
- `rawValueRetained: false` and revoked.
