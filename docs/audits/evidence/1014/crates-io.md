# #1014 handoff: `crates-io:api-token`

[#1014 index](README.md) · rank 6 ·
[Research table #22](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447282)

**Readiness: READY.** **Route:** new detector `crates-io-token`, finding types
`crates_io_api_token` (`cio`) and `crates_io_trusted_publishing_token`
(`cio_tp_`).

## Role and blast radius

A crates.io API token (`CARGO_REGISTRY_TOKEN`, `~/.cargo/credentials.toml`)
publishes, yanks and changes owners of crates within its scopes. A
trusted-publishing token is minted from a CI OIDC exchange and can publish
for its short lifetime. Both are supply-chain credentials.

## Supported shape

Sources: `rust-lang/crates.io` server code, re-checked 2026-09-29:

- `crates/crates_io_database/src/utils/token.rs` at
  [`7b2475e`](https://github.com/rust-lang/crates.io/blob/7b2475e26337856ab054844c9078bb23c11b2f19/crates/crates_io_database/src/utils/token.rs#L10-L91)
  (2025-12-01): `TOKEN_PREFIX = "cio"`, `TOKEN_LENGTH = 32`, generated with
  `rand::distr::Alphanumeric`. `HashedToken::parse` rejects any token without
  the prefix, so no unprefixed token is accepted today.
- `crates/crates_io_trustpub/src/access_token.rs` at
  [`f937ab0`](https://github.com/rust-lang/crates.io/blob/f937ab051067e793ed647c7b587a5419db85949b/crates/crates_io_trustpub/src/access_token.rs#L21-L102)
  (2026-06-24): `PREFIX = "cio_tp_"`, `RAW_LENGTH = 31` alphanumerics, then
  one checksum character from `A-Za-z0-9` (XOR of the raw bytes, modulo 62).
  The parser requires exactly 32 characters after the prefix.

| Role | Prefix | Body | Alphabet | Tier |
| --- | --- | --- | --- | --- |
| API token | `cio` | exactly 32 | `[A-Za-z0-9]` (`Alphanumeric`) | T1 (R1) |
| Trusted-publishing token | `cio_tp_` | exactly 32 (31 + 1 check character) | `[A-Za-z0-9]` | T1 (R1) |

Total lengths 35 and 39.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Tokens from before the `cio` prefix | the server no longer accepts them (`parse` rejects unprefixed tokens) |
| `cio` + 32 inside a longer alphanumeric run | the identifier boundary rejects it; never truncated |
| Words and identifiers that start with `cio` (`ciound`, `cio_config`) | fail the exact 32-alphanumeric body and the boundary |

## Tier rationale

T1 for every fact under R1. noseyparker's `\bcio[a-zA-Z0-9]{32}\b` agrees; it
is not needed. No scanner covers `cio_tp_`.

## Overlap and output policy

- **Existing detectors.** None claims `cio`. Measured on `main` `b9e9091`:
  `CARGO_REGISTRY_TOKEN=` gives `contextual_secret`; bare, chat and JSON
  `"token"` are missed.
- **Short prefix.** `cio` is a 3-letter trigram, so the exact 32-byte body and
  both identifier boundaries are what keep this precise. A random 35-byte
  alphanumeric run starts with `cio` about once in 238,000 runs, and must
  also stand alone between boundaries. That residual rate is the accepted
  false positive below.
- **Checksum.** The `cio_tp_` check character could reject near-misses; it is
  optional under ruling Q1.
- **New output.** Two provider types, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with `PrefixShape::exact("cio_tp_", 32,
is_alnum, …)` ordered before `PrefixShape::exact("cio", 32, is_alnum, …)`.
The `cio` shape's body alphabet excludes `_`, so `cio_tp_…` never matches it.
Boundary `[A-Za-z0-9_-]`. Signals: `crates-io-generator-prefix`,
`crates-io-generator-length`.

## Test axes

**Positives:** every #860 index context; `CARGO_REGISTRY_TOKEN=` in a CI
`env:` block; `[registry] token = "cio…"` in `credentials.toml`;
`cargo publish --token cio…`; a `cio_tp_` token in a GitHub Actions log line.

**Near-miss twins:** body of 31 or 33; a `-` or `_` in the body; `CIO` +
32; `cio_tp_` + 31 or 33; a leading glue byte (`xcio…`, `_cio…`) and a
trailing glue byte.

**Benign:** English and code words starting with `cio`; `cio` + 32 inside a
64-byte alphanumeric run; `CARGO_REGISTRY_TOKEN=${{ secrets.CRATES_TOKEN }}`.

## False-positive / false-negative boundary

- **Accepted false negatives:** a token glued to identifier bytes.
- **Accepted false positives:** a standalone 35-byte alphanumeric value that
  happens to start with `cio`, such as a random id. Rare, and if it happens a
  random value is redacted.

## Issuance checklist (optional confirmation; structure only)

For one API token: total length (expect 35), alphabet classes (upper, lower,
digits; no punctuation), `rawValueRetained: false` and revoked.
