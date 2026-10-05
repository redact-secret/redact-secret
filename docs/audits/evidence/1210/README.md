# Evidence: #1210, Asana `X-Hook-Secret` handshake credentials

**Result:** no-code coverage validation. The exact `X-Hook-Secret` header value
is already one `redact` finding spanning exactly the value in all six measured
layouts, as a generic `contextual_secret`, and none of the eight controls
(the HMAC `X-Hook-Signature`, `X-Hook-Secret-Id`, `X-Hook-Secrets`,
placeholders, references, masks, a bare string) is flagged. Nothing in the
product changed for this issue; a regression test pins the validated behavior.

Issue [#1210](https://github.com/redact-secret/redact-secret/issues/1210),
Batch 1 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231),
handoff [#232](https://github.com/redact-secret/credential-evidence/issues/232)).

## Sources

| Role | Source |
| --- | --- |
| Provider fact (slot and role) | [`asana:webhook-secret` proposed contract](https://github.com/redact-secret/credential-evidence/blob/6dd2ae3cf46947548dcfad4bb746bcfd80f9f431/records/contracts/asana/webhook-secret@1.json): the handshake shared secret travels in `X-Hook-Secret`; `X-Hook-Signature` is an HMAC of the body, not the secret. No alphabet or width is stated. |
| Independent oracle | [benchmarks#717 Batch 1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/14271c7e85ad9300e100c6a4b5e33105e7429166/evidence/717/report.md) over `benchmarks/batch1/corpus.mjs` (82 cases, corpus sha256 `ddd709174816443e`). Its expectations were not edited. |
| Project policy (this record) | The boundary and tradeoffs below. |

## Baseline and replay

Published `@redact-secret/core` 0.1.0-beta.13 and core `d4e86769` agree on
Node, WASM, Python and CLI. The replay column is the same corpus through the
CLI built from this branch (whole and 7-byte streamed, 0 disagreements); it is
identical to the baseline. UTF-8 byte ranges.

| Case (layout) | Expected span | Baseline and replay |
| --- | --- | --- |
| `asana-raw-http-positive` (request header) | 73-105 | exact, `contextual_secret`, `generic-token`, redact |
| `asana-raw-http-response-positive` (handshake response echo) | 32-72 | exact, same |
| `asana-raw-http-unicode-prefix-positive` (non-ASCII first line) | 49-85 | exact, same |
| `asana-curl-single-positive` (curl, single quotes) | 32-60 | exact, same |
| `asana-curl-double-positive` (curl, double quotes) | 32-76 | exact, same |
| `asana-json-header-map-positive` (JSON header map) | 63-95 | exact, same |
| the eight controls | none | clean |

Unsupported, observed and never scored: `X-Old-Hook-Secret` is flagged
generically (a prefixed name may carry the same credential).

## Adopted boundary

| Question | Decision |
| --- | --- |
| Slot | The value after `X-Hook-Secret:` in a raw header line, a quoted `curl -H` argument or a JSON header map. The contextual assignment grammar reads it: `x_hook_secret` ends in the high-signal `secret` name behind a prefix (#702), so no name was added. |
| Span, action, type | Exactly the value, `redact`, generic `contextual_secret`; no Asana attribution is justified by a shared header, and no alphabet or width is claimed. |
| Not the credential | `X-Hook-Signature` (HMAC output), `X-Hook-Secret-Id` and `X-Hook-Secrets` are other names; placeholders, references and masks use the shared exclusions; a bare string in prose has no slot. |

## Tradeoffs

* Accepted contextual-policy false positive: a non-secret literal put into the
  exact `X-Hook-Secret` slot is redacted. False negatives: a value under 8
  bytes, a value on the line after the header, any other layout, and a
  placeholder shape the shared rules do not list.
* The `X-Old-Hook-Secret` flag is a side effect of the prefixed `secret` name
  rule and is not part of this claim.

## Tests

`crates/secret-scan-core/tests/batch1_credential_slots_1209_1213.rs`
(`asana_*` tests): exact UTF-8 spans and action for the six layouts including a
multibyte prefix, every control, and whole-input, every two-chunk UTF-8 byte
partition and per-line incremental parity. The independent replay of the exact
candidate on the four surfaces is the benchmarks side's step and stays open.
