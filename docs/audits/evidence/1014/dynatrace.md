# #1014 handoff: `dynatrace:api-token`

[#1014 index](README.md) · rank 7 ·
[Research table #31](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447540)

**Readiness: READY.** **Route:** new detector `dynatrace-token`, finding type
`dynatrace_token`.

## Role and blast radius

Dynatrace access tokens (`DT_API_TOKEN`, `Authorization: Api-Token …`) and
platform tokens authenticate the environment and account APIs. Depending on
scopes, a token reads monitoring data (which can include request payloads and
logs), changes configuration, ingests data or manages the account through
SCIM. The docs say to rotate a token immediately if it leaks.

## Supported shape

Sources, re-checked 2026-09-29:

- Dynatrace docs, "Token format",
  <https://docs.dynatrace.com/docs/dynatrace-api/basics/dynatrace-api-authentication>
  (updated 2026-08-04): a token has "three components separated by dots";
  the prefix "identifies the token type"; "The public portion of the token is
  a 24-character public identifier"; "The secret portion of the token is a
  64-character string that should be treated like a password". The token
  identifier (prefix plus public portion) "can be safely displayed in the UI
  and can be used for logging purposes". The prefix table lists `dt0s01` (API
  token), `dt0s02`, `dt0s03`, `dt0s04`, `dt0s06`, `dt0s08`, `dt0s09` and
  `dt0s16` (platform token). The same page's request examples use the
  classic prefix `dt0c01` as a placeholder (R4). The page's full-length
  example uses only `A–Z` and `2–7` in both portions (checked byte by byte,
  not reproduced).
- `Dynatrace/dynatrace-operator` `pkg/util/dttoken/token.go` at
  [`2a39d88`](https://github.com/Dynatrace/dynatrace-operator/blob/2a39d88a0ee1fbb61e2d22db02520b3dc92ffc80/pkg/util/dttoken/token.go#L14-L58)
  (2026-07-22): "The format is
  `<prefix>.<24-character-public-portion>.<64-character-private-portion>`",
  generated with `base32.StdEncoding` and truncated to the portion size.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `dt0` + `c` or `s` + 2 digits | docs table + R4 placeholder for `dt0c01` | T1 |
| Separator | `.` | docs | T1 |
| Public portion | exactly 24 | docs + provider generator | T1 |
| Separator | `.` | docs | T1 |
| Secret portion | exactly 64 | docs + provider generator | T1 |
| Alphabet (both portions) | uppercase base32 `[A-Z2-7]` | provider generator (R1) + docs example | T1 |

Total length 96.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Token identifier alone (`<prefix>.<24>`, no secret portion) | documented as safe to log |
| Portions with lowercase, `0`, `1`, `8` or `9` | never generated; scanners that allow them (`[a-z0-9]`, `[A-Z0-9]`) are wider than the issued grammar |
| Dynatrace OAuth client secrets and tenant tokens in other shapes | not in the documented three-part format |
| The docs placeholder `dt0c01.abc123.…` | fails both portion lengths |

## Tier rationale

T1 for every fact. The docs state the three-part structure and both lengths,
and name the prefixes. The alphabet comes from provider code (R1) and matches
the docs' full-length example. gitleaks (`dt0c01` only, case-insensitive
alphanumeric) and noseyparker (`[A-Z0-9]`) are wider and are not used.

## Overlap and output policy

- **Existing detectors.** None claims `dt0`. Measured on `main` `b9e9091`:
  `DT_API_TOKEN=` gives `contextual_secret`; `Authorization: Bearer` gives
  `bearer_token`; bare, chat and JSON `"token"` are missed. The documented
  header is `Authorization: Api-Token …`; the provider type should win there
  over `authorization_credential`.
- **New output.** Provider type, high confidence, always redact. The span is
  the whole token, not only the secret portion, so the redacted output does
  not keep a half-token.

## Implementation notes

`KnownFormatProviderDetector` with a literal `dt0` anchor, then one of
`c`/`s`, two digits, `.`, 24 base32, `.`, 64 base32; a fixed-width check after
the anchor. Boundary: the byte before `dt0` and the byte after the secret
must not be `[A-Za-z0-9_.-]`. Signals: `dynatrace-documented-format`,
`dynatrace-generator-alphabet`.

## Test axes

**Positives:** every #860 index context; `Authorization: Api-Token …`;
`DT_API_TOKEN=` in `.env`; a Kubernetes `DynaKube` secret `apiToken:` value;
an OpenTelemetry exporter header `Authorization=Api-Token …`; a `dt0c01`
token and a `dt0s16` token.

**Near-miss twins:** public portion of 23 or 25; secret portion of 63 or 65;
a lowercase byte; a `0`, `1`, `8` or `9` in a portion; `dt0x01` (unknown
letter); `dt1c01`; the second `.` replaced by `-`; a leading glue byte and a
trailing glue byte (`.x`).

**Benign:** a token identifier alone (`dt0s01.` + 24) in a log line; the docs
placeholder `dt0c01.abc123.…`; `DT_API_TOKEN=${DT_API_TOKEN}`.

## False-positive / false-negative boundary

- **Accepted false negatives:** a lowercased copy; any future format with a
  different alphabet or length.
- **Accepted false positives:** an unrelated `dt0[cs]NN.` + 24 + `.` + 64
  base32 value; none is known.

## Issuance checklist (optional confirmation; structure only)

For one classic access token and one platform token:

- prefix, total length (expect 96) and portion lengths (24, 64);
- alphabet classes (expect uppercase letters and digits 2–7 only);
- `rawValueRetained: false` and revoked.
