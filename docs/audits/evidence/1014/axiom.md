# #1014 handoff: `axiom:api-token`

[#1014 index](README.md) · rank 10 ·
[Research table #33](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447540)

**Readiness: READY** (by R5; the issuance check below is recommended).
**Route:** new detector `axiom-token`, finding types `axiom_api_token`
(`xaat-`) and `axiom_personal_token` (`xapt-`).

## Role and blast radius

Axiom is a log, event and trace store. An API token (`AXIOM_TOKEN`) is
ingest-only or has query and dataset-management rights, depending on how it
was created. A personal access token (`xapt-`, used with an org id) has the
user's full access to the Axiom console and API, including queries over all
ingested logs.

## Supported shape

Sources, re-checked 2026-09-29:

- `axiomhq/axiom-go` `internal/config/token.go` at
  [`ae983c9`](https://github.com/axiomhq/axiom-go/blob/ae983c9447003f74f00e55a2ca64ea119b558fb8/internal/config/token.go#L7-L18)
  (2023-09-19): `IsAPIToken` is `strings.HasPrefix(token, "xaat-")`,
  `IsPersonalToken` is `strings.HasPrefix(token, "xapt-")`, and
  `IsValidToken` accepts only these two.
- SDK fixtures in `axiom/client_test.go` at the same revision (2026-08-20)
  write both token kinds as `xa?t-` + an 8-4-4-4-12 UUID layout of
  placeholder bytes.
- Axiom docs (<https://axiom.co/docs/llms-full.txt>, observed 2026-09-29)
  include one response example `"token": "xaat-…"` whose body is a lowercase
  hexadecimal UUID, and state that a personal access token "starts with
  `xapt-`" and that the service-account password is "the string starting
  with `xaat-`".

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `xaat-` or `xapt-` | SDK runtime check (R6) + docs | T1 |
| Body | UUID layout 8-4-4-4-12 with `-`, 36 bytes | docs response example + SDK fixtures (R5) | T1 |
| Alphabet | lowercase hex | docs response example (R5) | T1 |

Total length 41.

**Why an issuance check is still recommended.** The only real-shaped example
is one docs response. The SDK fixtures fix the layout but use placeholder
bytes, and one docs placeholder elsewhere (`xaat-` + `x` runs of 10, 9 and 7)
does not follow the UUID layout. It is `x`-filled and is read as
illustrative, but one maintainer-issued token, checked for structure only,
would settle both the layout and the case.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Uppercase-hex UUID body | not observed in any provider source; accepted false negative |
| `xaat-your-api-token` and other placeholders | fail the UUID layout |
| Axiom org ids, dataset names | not credentials |

## Tier rationale

The prefix is T1 under R6. Length and alphabet are T1 under R5: a docs
response example plus the SDK fixtures' layout. No scanner covers Axiom.

## Overlap and output policy

- **Existing detectors.** None claims `xaat-`/`xapt-`. Measured on `main`
  `b9e9091`: `AXIOM_TOKEN=` gives `contextual_secret`; bare, chat and JSON
  `"token"` are missed. A bare UUID stays unclaimed; the prefix is
  load-bearing.
- **New output.** Two provider types, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with `xaat-` and `xapt-` literal prefixes and a
fixed 36-byte UUID-layout check (lowercase hex, `-` at body offsets 8, 13, 18
and 23). Boundary `[A-Za-z0-9_-]`. Signals: `axiom-sdk-prefix`,
`axiom-documented-layout`.

## Test axes

**Positives:** every #860 index context; `AXIOM_TOKEN=` in `.env`; a Vector or
Fluent Bit sink config `token:` field; an OpenTelemetry
`Authorization=Bearer xaat-…` header; a Grafana or Postgres-wire service
account `password:` field; one `xapt-` token.

**Near-miss twins:** a UUID with a missing or extra group byte; an uppercase
hex byte; a `g` in the body; `xaat_` (underscore); `xabt-`; a leading glue
byte and a trailing glue byte.

**Benign:** `xaat-your-api-token`; a bare UUID; `AXIOM_TOKEN=${AXIOM_TOKEN}`;
an Axiom org id.

## False-positive / false-negative boundary

- **Accepted false negatives:** an uppercased copy; any token that does not
  follow the UUID layout (see the issuance check).
- **Accepted false positives:** an unrelated `xaat-`/`xapt-` + lowercase UUID;
  none is known.

## Issuance checklist (recommended; structure only)

For one basic API token, one advanced API token and one personal token:

- total length (expect 41) and the positions of `-` in the body;
- alphabet classes (expect lowercase hex only);
- whether advanced tokens share `xaat-`;
- `rawValueRetained: false` and revoked.
