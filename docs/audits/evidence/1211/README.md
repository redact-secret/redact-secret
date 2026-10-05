# Evidence: #1211, Airtable `macSecretBase64` credential fields

**Result:** a measured gap, fixed with one exact name. Before this change none
of the seven positives (JSON, pretty JSON, YAML, quoted YAML, spaced and
env-file assignment, a field after a non-ASCII value) produced a finding, on
every surface of published beta.13 and of core `d4e86769`. `mac_secret_base64`
(the normalized `macSecretBase64`) is now a high-signal contextual name matched
only as the whole name, so all seven are one `redact` finding spanning the
complete encoded value, padding included, and all eight controls stay clean. No
`*Base64` generalization, no decoding, no width claim, no new detector or type.

Issue [#1211](https://github.com/redact-secret/redact-secret/issues/1211),
Batch 1 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231),
handoff [#232](https://github.com/redact-secret/credential-evidence/issues/232)).

## Sources

| Role | Source |
| --- | --- |
| Provider fact (slot and role) | [`airtable:webhook-mac-secret` proposed contract](https://github.com/redact-secret/credential-evidence/blob/6dd2ae3cf46947548dcfad4bb746bcfd80f9f431/records/contracts/airtable/webhook-mac-secret@1.json): creating a webhook returns `macSecretBase64`, the Base64 MAC secret used to compute the HMAC-SHA256 that `X-Airtable-Content-MAC` carries. Length and handling beyond that are an open question; nothing is claimed. |
| Independent oracle | [benchmarks#717 Batch 1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/14271c7e85ad9300e100c6a4b5e33105e7429166/evidence/717/report.md) over `benchmarks/batch1/corpus.mjs` (82 cases, corpus sha256 `ddd709174816443e`). Its expectations were not edited. |
| Project policy (this record) | The name, span, action and tradeoffs below. |

## Baseline and replay

Before: published beta.13 and core `d4e86769`, all four surfaces, no finding on
any positive. After: the same corpus through the CLI built from this change
(whole and 7-byte streamed, 0 disagreements, scored by the benchmark's
`score.mjs`). UTF-8 byte ranges.

| Case (layout) | Expected span | Before | After |
| --- | --- | --- | --- |
| `airtable-json-positive` (create-webhook JSON) | 45-89 | miss | exact, `contextual_secret`, `generic-token`, redact |
| `airtable-json-pretty-positive` (pretty JSON) | 24-68 | miss | exact, same |
| `airtable-yaml-positive` (YAML mapping) | 52-96 | miss | exact, same |
| `airtable-yaml-quoted-positive` (quoted YAML) | 29-73 | miss | exact, same |
| `airtable-assignment-spaced-positive` (`macSecretBase64 = "..."`) | 19-63 | miss | exact, same |
| `airtable-assignment-env-positive` (`macSecretBase64=...`) | 16-60 | miss | exact, same |
| `airtable-json-unicode-prefix-positive` (non-ASCII field first) | 40-84 | miss | exact, same |
| the eight controls (`X-Airtable-Content-MAC` HMAC, hook and base ids, `thumbnailBase64`, `macSecretBase64Length`/`Present`, `macSecretBase64Id`, placeholder, `${...}` reference, mask) | none | clean | clean |

## Adopted boundary

| Question | Decision |
| --- | --- |
| Vocabulary | `mac_secret_base64` joins `EXACT_HIGH_SIGNAL_NAMES`, the whole-name mechanism of `db_pass` (#823), `fal_key` and the Convex names (#919). Only the whole normalized name matches: `macSecretBase64Length`, `macSecretBase64Id`, `macSecretBase64Hash`, a prefixed `oldMacSecretBase64` and every other `*Base64` field (`thumbnailBase64`) do not. |
| Layouts | JSON, YAML and direct assignment, through the existing contextual assignment grammar (quoted and unquoted values, `=` and `:`). |
| Span and action | The complete encoded value, `=` padding included, `redact` by default; the field name and quotes stay outside. The value is never decoded. |
| Attribution | Generic `contextual_secret`; no universal Base64 width or alphabet is inferred or checked beyond the shared 8-byte contextual floor. |
| Not the credential | `X-Airtable-Content-MAC` is an HMAC output and not a slot; hook and base ids are public fields; placeholders, references and masks use the shared exclusions. |

## Tradeoffs

* Accepted contextual-policy false positive: a non-secret literal put into the
  exact `macSecretBase64` field is redacted by default. False negatives: the
  same secret under any other field name (`mac_secret`, a prefixed name,
  `macSecret`), a value under 8 bytes, a value on the line after the key, and a
  structure other than the supported layouts.
* The name set grows by one exact entry; the cost is one lookup in the
  existing high-signal check.

## Tests

`crates/secret-scan-core/tests/batch1_credential_slots_1209_1213.rs`
(`airtable_*` tests): exact UTF-8 spans and action for the seven layouts, with
padding and a multibyte prefix (the multibyte test asserts the byte offset
differs from the character offset), every control including the neighbouring
`*Base64` names, a hook response next to an `X-Airtable-Content-MAC` header
(one finding, the secret), and whole-input, every two-chunk UTF-8 byte
partition and per-line incremental parity. Overlap does not arise: one finding
or none per input. The independent replay of the exact candidate on the four
surfaces is the benchmarks side's step and stays open.
