# #1014 handoff: `xata:api-key`

[#1014 index](README.md) · rank 11 ·
[Research table #37](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447540)

**Readiness: READY** (derivation done 2026-09-30; was "derive the body range
first"). **Route:** new detector `xata-api-key`, finding types `xata_user_api_key`
(`xau_`) and `xata_organization_api_key` (`xao_`).

## Role and blast radius

Xata is a hosted Postgres platform. A user API key (`XATA_API_KEY`, sent as
`Authorization: Bearer`) acts as that user across every organization, project
and database the user can reach: create and delete branches, read connection
data, manage keys. An organization key is scoped to one organization. Both
appear in `.env` files, CLI output and MCP server configs, which is where
agents see them.

## Discovery (broad first, source classes labelled afterwards)

Searched the open web (Google-style queries for the prefix, a regex or a leak;
Stack Overflow, Reddit and GitHub-issue phrasing), then the public scanner rule
sets, then provider code and docs, 2026-09-30.

- **Forums and issue trackers.** No post discloses a key shape or a leak. The
  prefix `xau_` shows up only as a placeholder (`xau_some_key`, `xau_redacted`,
  `xau_test123`) in provider SDK repos (source class: provider code, tests and
  examples).
- **Third-party scanner rule sets.** gitleaks `b58d3f1`, noseyparker
  `2e6e7f3`, trufflehog `19f011a`, betterleaks `c4c0ffd` and osv-scalibr
  `1e9b16c` have no Xata rule. The Kingfisher changelog lists "Xata" among 61
  rules added in one release, but the rule is absent from the Kingfisher tree
  at `7433793` (2026-09-29), so no grammar can be cited from it (source class:
  third-party scanner, inconclusive).
- **Partner list.** Xata is not on the GitHub secret-scanning partner list.
- **Provider code.** `xataio/xata` (open-sourced 2026-04-15) contains both the
  generator and the validator; see below. This is the only source that fixes the
  grammar.

## Supported shape

Sources, re-checked 2026-09-30 at `xataio/xata`
[`fc4ac97`](https://github.com/xataio/xata/tree/fc4ac97f62a3830c4e4202b08a3ca51855970113)
(the commit cited in the step-1 table; `key.go` is unchanged at tip
`9be334c`, 2026-09-30):

- `internal/api/key/key.go`
  ([L19–L57](https://github.com/xataio/xata/blob/fc4ac97f62a3830c4e4202b08a3ca51855970113/internal/api/key/key.go#L19-L57);
  single path commit `1f5a77f`, 2026-04-15; provider code, R1 and R9). The
  generator reads 20 random bytes, appends the little-endian CRC32 (IEEE) of
  those 20 bytes, and encodes the 24 bytes with `jxskiss/base62` using the
  alphabet `0-9a-zA-Z`. The key is `xau` or `xao`, `_`, then that encoding. The
  validator (`IsValid`) requires: total length at most `MaxLength = 40`, exactly
  one `_`, a prefix that starts with `xau` or `xao`, a successful base62
  decode, at least 4 decoded bytes and a matching CRC32.
- Issuance path: `services/auth/store/sqlstore/store_sql.go` calls
  `key.NewUserKey` and `key.NewOrganizationKey` for new keys, and the same
  `IsValid` gates use of a key in `internal/api/auth.go`,
  `services/auth/rpc/auth.go` and `services/projects/rpc/limits.go` (checked at
  tip `9be334c`). The grammar is therefore the live one, not dead code.
- Independent artifacts of the same provider: `key_test.go`
  ([L31–L40](https://github.com/xataio/xata/blob/fc4ac97f62a3830c4e4202b08a3ca51855970113/internal/api/key/key_test.go#L31-L40))
  carries a "valid known key" fixture whose body is 33 characters, and
  `xataio/client-ts` CLI
  ([`init/index.ts` L468](https://github.com/xataio/client-ts/blob/394dad90297568bd990b15f673de82605dcfa46d/packages/cli/src/commands/init/index.ts#L468),
  2026-03-26) prints `XATA_API_KEY=xau_` followed by 33 mask characters. Both
  agree with the derivation below.

**Derivation of the body width** (scratch script, not committed). The
`jxskiss/base62` `Encode` path (`_encodeV2`) reads the byte string as a bit
stream from the end in 6-bit groups. A group whose value is 30, 31, 62 or 63
(top four low bits set, probability 4/64) is emitted as a 5-bit group
instead. So the width is 32 characters (192 bits, no 5-bit group) up to 39
(all groups 5-bit), and every emitted symbol is in the 62-character alphabet.
A line-by-line port of the provider's encoder, run over 2,000,000 random
20-byte inputs with their CRC32, gave 13.1% at 32, 86.6% at 33 and 0.34% at 34.
An exact probability model of the same process gives 13.5%, 86.2%, 0.31%, then
3.9e-8 at 35 and 9.8e-15 at 36 (none seen). The provider's test fixture (body
33) decodes and its CRC32 (little-endian) verifies in the port, which confirms
the byte order and the port.

| Key | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| User key | `xau_` + `[0-9A-Za-z]{32,36}` | prefix: generator and validator (R1); alphabet: generator alphabet (R1); width: derived from the generator's encoder for 24 bytes, upper bound from the validator's `MaxLength` 40 (R1, R9) | T1 |
| Organization key | `xao_` + `[0-9A-Za-z]{32,36}` | same | T1 |

In practice 99.9% of keys have a body of 32 to 34. The window 35 to 36 costs
nothing in false positives (the `xau_`/`xao_` prefix is what carries the
specificity) and keeps the contract equal to what the provider's own validator
accepts, so the contract uses 32 to 36. Total length is 36 to 40.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Keys of the Xata classic platform (pre-2026) | no provider source states their grammar. `client-ts` and `xata-py` only show `xau_` placeholders. Unknown, not assumed to equal the new grammar. Generic context remains |
| `xau_`/`xao_` + body shorter than 32 or longer than 36 | fails the derived width and the validator's length cap |
| Placeholders in SDK examples (`xau_test`, `xau_some_key`, `xau_redacted`, `xau_****`) | fail the width; benign |
| Database connection strings and branch ids | not API keys; other detectors |
| Hash output (`HashKey` HMAC-SHA256 hex) | a server-side lookup value, not a client credential |

## Tier rationale

T1 under R1 and R9: the prefix, the alphabet and the length limit come from the
provider's generator and validator, which are the code that mints and accepts
keys today (dated 2026-04-15, unchanged 2026-09-30). The exact body width is
derived from the encoder rather than stated, the way the Polar and Unkey
windows are; the derivation is reproduced above and agrees with two provider
artifacts (test fixture, CLI mask). No T2 fact is needed.

## Overlap and output policy

- **Existing detectors.** None claims `xau_`/`xao_` (checked against the
  detector sources at `main` `cfa87360`). Measured in the step-1 probe: bare,
  chat and JSON `"token"` are missed; `XATA_API_KEY=` and `API_KEY=` forms give
  `contextual_secret`.
- **Checksum (ruling Q1).** The CRC32 is offline-verifiable. Per the Polar and
  crates.io precedent, the lexical grammar is the contract and a post-check that
  can only reject is deferred to Q1. Do not reject on checksum until Q1 is
  ruled. Note for the post-check: decode with the non-standard bit-packed
  base62 (not big-integer base62); a standard base62 decoder will fail genuine
  keys.
- **New output.** Two provider types, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with `PrefixShape::at_least("xau_", 32,
is_alnum, …)` plus a body-cap post check at 36 (the `nvidia.rs` `within_body_cap`
pattern, because the run is maximal and a 37-byte run must fail whole), and the
same for `xao_`; boundary `[A-Za-z0-9_-]`. The prefix is 4 bytes, so anchoring at an
identifier start is load-bearing: `xau_` inside `maxau_…` or a longer identifier
must not match. Signals: `xata-generator-prefix`, `xata-generator-width`.

## Test axes

**Positives:** every #860 index context; `XATA_API_KEY=` in `.env`;
`Authorization: Bearer`; a Xata MCP server config `env` block; `xau_` and
`xao_`; bodies of 32, 33 and 34 (and 36 for the boundary); test values built at
run time with the provider's algorithm (20 random bytes, CRC32 little-endian,
bit-packed base62), never a real key.

**Near-miss twins:** body of 31 and 37; a `-` or `_` in the body; `XAU_`
uppercase; `xat_`; `xau-`; a leading glue byte and a trailing glue byte.

**Benign:** `xau_test`, `xau_redacted`, `xau_some_key`; `xau_` plus 33 `*`;
`XATA_API_KEY=${XATA_API_KEY}`; a `xau_`-prefixed snake_case identifier shorter
than 32.

## False-positive / false-negative boundary

- **Accepted false negatives:** classic-platform keys of unknown shape; a
  future generator change; keys broken by whitespace.
- **Accepted false positives:** an unrelated `xau_`/`xao_` followed by 32 to 36
  alphanumerics with no `_` or `-`; none known. Without the checksum (Q1) a
  random alphanumeric run after the prefix is accepted.

## Issuance checklist (optional confirmation; structure only)

For one user key and one organization key: prefix, total length (expect 36 to
40, most likely 37), alphabet classes, whether the CRC32 verifies with the
provider's encoder, and whether the key is a classic-platform key;
`rawValueRetained: false` and revoked. Not a precondition.
