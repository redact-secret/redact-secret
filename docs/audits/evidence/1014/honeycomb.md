# #1014 handoff: `honeycomb:api-key`

[#1014 index](README.md) · rank 9 ·
[Research table #32](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447540)

**Readiness: READY for the ingest key; ISSUANCE-GATED for the management
key.** **Route:** new detector `honeycomb-api-key`, finding type
`honeycomb_ingest_key` now; `honeycomb_management_key` after the gate.

## Role and blast radius

An ingest key (`HONEYCOMB_API_KEY`, `X-Honeycomb-Team`, OpenTelemetry
exporter headers) sends telemetry into an environment; a leaked key lets
anyone write or spoof traces and events and burn the event quota. A
management key (`Authorization: Bearer`) manages environments and API keys
for the team. Ingest keys are routinely pasted into OpenTelemetry collector
configs, which is where agents see them.

## Supported shape

Sources, re-checked 2026-09-29:

- Honeycomb docs, "Authentication",
  <https://docs.honeycomb.io/api/authentication>: key IDs carry a type prefix
  (`hc[x]ik_` ingest, `hc[x]lk_` configuration, `hc[x]mk_` management), and
  "The character shown as [x] varies and is assigned at key creation". For
  ingest keys, "The key value is the Key ID and Secret concatenated with no
  separator". The docs' ingest placeholder has a 58-byte body after the
  prefix; the management placeholder is 26 bytes, `:`, 32 bytes.
- `honeycombio/libhoney-go` `libhoney.go` at
  [`02e9dbf`](https://github.com/honeycombio/libhoney-go/blob/02e9dbf361012fafbe8698f429b65630500dc10a/libhoney.go#L74-L178)
  (2026-04-14): `classicIngestKeyRegex = ^hc[a-z]ic_[a-z0-9]*$`, applied only
  when `len(key) == 64`. The test fixtures
  ([`libhoney_test.go`](https://github.com/honeycombio/libhoney-go/blob/02e9dbf361012fafbe8698f429b65630500dc10a/libhoney_test.go#L1225-L1250))
  include `hcxik_` and `hcxic_` keys of 64 bytes, lowercase alphanumeric.
- `honeycombio/libhoney-py` `client.py` at
  [`11b5941`](https://github.com/honeycombio/libhoney-py/blob/11b59417c1df1d97384dc5e870f2ea462da02b80/libhoney/client.py#L11-L18)
  (2024-03-06): `^hc[a-z]ic_[a-z0-9]{58}$`.
- `terraform-provider-honeycombio` builds the ingest key as `key.ID +
  key.Secret`
  ([`api_key_resource.go`](https://github.com/honeycombio/terraform-provider-honeycombio/blob/b74d528db4fd6d01503e1b46a13b2146a38b45c3/internal/provider/api_key_resource.go#L417-L420)).

| Key | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Ingest (environment) | `hc` + `[a-z]` + `ik_` + exactly 58 `[a-z0-9]` | prefix: docs; length: docs placeholder + SDK length gate + fixtures (R5); alphabet: SDK fixtures (R5) | T1 |
| Ingest (classic environment) | `hc` + `[a-z]` + `ic_` + exactly 58 `[a-z0-9]` | SDK regex in two provider SDKs (R1) | T1 |
| Management | `hc` + `[a-z]` + `mk_` + 26 + `:` + 32 | prefix and lengths: docs; alphabet: **not found** (the placeholder is digits only, and no fixture exists) | prefix/length T1, alphabet open |

Ingest keys are 64 bytes in total.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Management key (`hc?mk_…:…`) | ISSUANCE-GATED: the alphabet of both segments is unresolved. The gate property is the alphabet classes of the 26- and 32-byte segments |
| Configuration key (sent value: 22 unprefixed alphanumerics) | no distinctive shape; generic context |
| Classic key (32 lowercase hex, no prefix) | no distinctive shape; generic context |
| Key IDs alone: `hc?ik_`/`hc?mk_` + 26, `hc?lk_`, `hc?en_` environment ids | non-secret identifiers shown in the UI and API |

## Tier rationale

- **Classic ingest keys:** T1 under R1, from the SDK regex and length gate.
- **Environment ingest keys:** the prefix is T1 (docs). The length is T1 by
  the docs placeholder, the SDK's 64-byte gate and the fixtures (R5). The
  alphabet is T1 by the SDK fixtures and matches the classic regex (R5).
- **Management keys:** stay gated on the alphabet.

## Overlap and output policy

- **Existing detectors.** None claims `hc?ik_`. Measured on `main` `b9e9091`:
  `HONEYCOMB_API_KEY=` gives `contextual_secret`; bare, chat and JSON
  `"token"` are missed. In an OpenTelemetry `headers: x-honeycomb-team: …`
  map, today's coverage depends on the header name.
- **Key id.** A key id is the first 26 bytes of the body. It is not reported
  alone, and a 26-byte `hc?ik_` run fails the 58-byte body.
- **New output.** Provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with an `hc` anchor, one `[a-z]` byte, then
`ik_` or `ic_`, then exactly 58 `[a-z0-9]`; boundary `[A-Za-z0-9_-]`.
Signals: `honeycomb-documented-prefix`, `honeycomb-sdk-length`.

## Test axes

**Positives:** every #860 index context; `X-Honeycomb-Team: …`;
`OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=…`; an OpenTelemetry collector
YAML `headers:` map; `HONEYCOMB_API_KEY=` in `.env`; a `libhoney.Init`
config; both `ik` and `ic` forms, and more than one `[x]` letter.

**Near-miss twins:** body of 57 or 59; an uppercase byte; a `-` in the body;
`hcik_` (no type letter); `hcAik_`; `hcxmk_` + 58; a leading glue byte and a
trailing glue byte.

**Benign:** a key id (`hcxik_` + 26) in an API response; `hcxen_` environment
ids; a 32-hex classic key; `HONEYCOMB_API_KEY=${HONEYCOMB_API_KEY}`.

## False-positive / false-negative boundary

- **Accepted false negatives:** configuration and classic keys outside named
  contexts; management keys until the gate clears.
- **Accepted false positives:** an unrelated `hc?ik_`/`hc?ic_` + exactly 58
  lowercase alphanumerics; none is known.

## Issuance checklist (structure only)

Required for the management key; optional for ingest keys. For one ingest key
and one management key:

- prefix letters and total length (ingest: expect 64);
- management: segment lengths around `:` (expect 26 and 32) and the alphabet
  classes of each segment;
- `rawValueRetained: false` and revoked.
