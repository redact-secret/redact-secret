# Evidence: #1213, Canva `client_secret` and the Basic envelope

**Result:** no-code coverage validation. All eight measured positives are one
`redact` finding spanning exactly the credential: `client_secret` as an
assignment, a quoted assignment, a form body (the span stops at the `&`
delimiter, also as the last parameter) and JSON, as a generic
`contextual_secret`; and the `Authorization: Basic` envelope (raw HTTP and
curl `-H`) as an `authorization_credential` over the encoded credential, not a
decoded secret-only span. None of the nine controls is flagged. Nothing in the
product changed for this issue; a regression test pins the validated behavior.

Issue [#1213](https://github.com/redact-secret/redact-secret/issues/1213),
Batch 1 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231),
handoff [#232](https://github.com/redact-secret/credential-evidence/issues/232)).

## Sources

| Role | Source |
| --- | --- |
| Provider fact (slot and role) | [`canva:client-secret` proposed contract](https://github.com/redact-secret/credential-evidence/blob/6dd2ae3cf46947548dcfad4bb746bcfd80f9f431/records/contracts/canva/client-secret@1.json): Canva documents a `cnvca` prefix; the separator, body length and alphabet are not documented. |
| Independent oracle | [benchmarks#717 Batch 1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/14271c7e85ad9300e100c6a4b5e33105e7429166/evidence/717/report.md) over `benchmarks/batch1/corpus.mjs` (82 cases, corpus sha256 `ddd709174816443e`). Its expectations were not edited. |
| Project policy (this record) | The boundary and tradeoffs below. |

## Baseline and replay

Published `@redact-secret/core` 0.1.0-beta.13 and core `d4e86769` agree on
Node, WASM, Python and CLI. The replay column is the same corpus through the
CLI built from this branch (whole and 7-byte streamed, 0 disagreements); it is
identical to the baseline. UTF-8 byte ranges.

| Case (layout) | Expected span | Baseline and replay |
| --- | --- | --- |
| `canva-assignment-positive` (`client_secret=`) | 56-99 | exact, `contextual_secret`, `generic-token`, redact |
| `canva-assignment-quoted-positive` | 17-60 | exact, same |
| `canva-form-body-positive` (stops at `&code=`) | 181-224 | exact, same |
| `canva-form-body-last-positive` | 70-113 | exact, same |
| `canva-json-positive` | 48-91 | exact, same |
| `canva-json-unicode-prefix-positive` (non-ASCII field first) | 38-81 | exact, same |
| `canva-basic-raw-http-positive` (`Authorization: Basic`) | 81-161 | exact, `authorization_credential`, `generic-token`, redact |
| `canva-basic-curl-positive` (curl `-H`) | 33-113 | exact, same |
| the nine controls (`client_id` as assignment and JSON, two placeholders, `${...}` and `{{ }}` references, mask, `cnvca` prefix prose, public form parameters) | none | clean |

Unsupported, observed and never scored: a bare `cnvca` value outside a
credential slot is not flagged, by decision.

## Adopted boundary

| Question | Decision |
| --- | --- |
| Slot | `client_secret` is already a high-signal name (the OAuth 2.0 client secret), read in assignments, form bodies and JSON by the contextual grammar; `Authorization: Basic` is the existing authorization scheme. No name, scheme or type was added. |
| Span and action | The value only, ending at the form delimiter; `redact` by default. For `Basic`, the whole encoded envelope, never a decoded secret-only span. |
| Attribution | Generic (`contextual_secret`, `authorization_credential`); no Canva attribution is promised. |
| No bare-prefix detector | `cnvca` alone, as prose or as a value under a non-credential name, is not claimed: the separator, length and alphabet are undocumented, and a bare prefix would be a new grammar. |
| Not the credential | `client_id` and other public app identifiers, placeholders, references, masks and the public form parameters. |

## Tradeoffs

* Accepted contextual-policy false positive: a non-secret literal put into the
  exact `client_secret` or `Authorization: Basic` slot is redacted by default.
  False negatives: a Canva secret outside a credential slot (the bare value),
  a value under the 8-byte (assignment) or 12-byte (`Basic`) floor, and layouts
  other than those listed. The `Basic` envelope also covers the public client
  id half, because the encoded value is one credential.

## Tests

`crates/secret-scan-core/tests/batch1_credential_slots_1209_1213.rs`
(`canva_*` tests): exact UTF-8 spans, type and action for the six
`client_secret` layouts and the two `Basic` envelopes (built by an in-test
Base64 encoder, never decoded), a multibyte-prefix offset, every control
including the bare `cnvca` value, and whole-input, every two-chunk UTF-8 byte
partition and per-line incremental parity. The independent replay of the exact
candidate on the four surfaces is the benchmarks side's step and stays open.
