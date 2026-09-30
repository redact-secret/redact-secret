# #1014 handoff: `rubygems:api-key`

[#1014 index](README.md) · rank 4 ·
[Research table #21](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447282)

**Readiness: READY.** **Route:** new detector `rubygems-api-key`, finding type
`rubygems_api_key`.

## Role and blast radius

A RubyGems.org API key (`GEM_HOST_API_KEY`, `~/.gem/credentials`) can push
and yank gems and manage owners within its scopes. A leak is a supply-chain
risk for every gem the account owns.

## Supported shape

Source: `rubygems/rubygems.org` `app/controllers/concerns/api_keyable.rb` at
[`d4cfcc9`](https://github.com/rubygems/rubygems.org/blob/d4cfcc961d08cb5f661f2e5dc0081736233b97ec/app/controllers/concerns/api_keyable.rb#L19-L21)
(last changed 2026-03-03), re-checked 2026-09-29:
`generate_rubygems_key` returns `"rubygems_#{SecureRandom.hex(24)}"`.
`SecureRandom.hex` emits lowercase hex, two characters per byte.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `rubygems_` | server generator (R1) | T1 |
| Body | exactly 48 | 24 bytes hex (R1) | T1 |
| Alphabet | lowercase hex | `SecureRandom.hex` (R1) | T1 |

Total length 57. The GitHub partner list has `rubygems_api_key` with push
protection.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Pre-prefix legacy keys (unprefixed hex) | no distinctive shape; generic context covers `GEM_HOST_API_KEY=` and `:rubygems_api_key:` |
| OIDC-exchanged short-lived keys | issued by the same generator (same prefix and shape), so they are covered, not excluded |
| `rubygems_` identifiers (`rubygems_version`, `rubygems_mfa_required`) | fail the 48-hex body |

## Tier rationale

T1 for all three facts under R1, from the provider's own generator. gitleaks
and noseyparker use the same `rubygems_[a-f0-9]{48}`; trufflehog's class has
a typo and is looser. Neither scanner is needed for the grammar.

## Overlap and output policy

- **Existing detectors.** None claims `rubygems_`. Measured on `main`
  `b9e9091`: `GEM_HOST_API_KEY=` gives `contextual_secret`; bare, chat and
  JSON `"token"` are missed.
- **New output.** Provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with `PrefixShape::exact("rubygems_", 48,
is_lower_hex, …)` and the `[A-Za-z0-9_-]` boundary. Signals:
`rubygems-generator-prefix`, `rubygems-generator-length`.

## Test axes

**Positives:** every #860 index context; `GEM_HOST_API_KEY=` in a CI `env:`
block; the YAML `:rubygems_api_key: rubygems_…` line of
`~/.gem/credentials`; `gem push --key`; a `Authorization:` header with the
bare key (RubyGems sends it without a scheme).

**Near-miss twins:** body of 47 or 49; an uppercase hex byte; a `g` in the
body; `RUBYGEMS_` uppercase; `rubygems-` separator; a leading glue byte
(`xrubygems_…`) and a trailing glue byte.

**Benign:** `rubygems_version`, `rubygems_mfa_required` metadata keys; the
`:rubygems_api_key:` YAML key with a placeholder; a bare 48-hex value.

## False-positive / false-negative boundary

- **Accepted false negatives:** legacy unprefixed keys outside named
  contexts; an uppercased copy.
- **Accepted false positives:** an unrelated `rubygems_` + exactly 48
  lowercase hex; none is known.

## Issuance checklist (optional confirmation; structure only)

For one scoped key: total length (expect 57), body length (48), alphabet
(lowercase hex only), `rawValueRetained: false` and revoked.
