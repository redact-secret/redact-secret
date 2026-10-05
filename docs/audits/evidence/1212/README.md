# Evidence: #1212, explicit `Authorization: ApiKey` credentials

**Result:** a measured gap, fixed by recognizing the `ApiKey` scheme word in the
existing `Authorization` / `Proxy-Authorization` grammar of `generic-token`.
Before this change none of the eight positives (raw HTTP, `Proxy-Authorization`,
a non-ASCII first line, curl `-H` in single and double quotes, curl with a proxy
header, two JSON header maps) produced a finding, on every surface of published
beta.13 and of core `d4e86769`. Now each is one `redact` finding spanning the
undecoded encoded value, generic `authorization_credential`, and all eight
controls stay clean. No Elastic attribution, no decoding, no id/api_key split,
no alphabet or width inference, no new detector, registry entry or type.

Issue [#1212](https://github.com/redact-secret/redact-secret/issues/1212),
Batch 1 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231),
handoff [#232](https://github.com/redact-secret/credential-evidence/issues/232)).

## Sources

| Role | Source |
| --- | --- |
| Provider fact (slot and role) | [`elastic:elasticsearch-api-key` proposed contract](https://github.com/redact-secret/credential-evidence/blob/6dd2ae3cf46947548dcfad4bb746bcfd80f9f431/records/contracts/elastic/elasticsearch-api-key@1.json): the encoded value (Base64 of `id:api_key`) is sent as `Authorization: ApiKey <value>`. The Base64 alphabet and padding, the id and key widths and whether the id half is non-secret are open questions; nothing is claimed and the id is not treated as benign. |
| Independent oracle | [benchmarks#717 Batch 1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/14271c7e85ad9300e100c6a4b5e33105e7429166/evidence/717/report.md) over `benchmarks/batch1/corpus.mjs` (82 cases, corpus sha256 `ddd709174816443e`). Its expectations were not edited. |
| Project policy (this record) | The scheme, span, action, attribution and tradeoffs below. |

## Baseline and replay

Before: published beta.13 and core `d4e86769`, all four surfaces, no finding on
any positive. After: the same corpus through the CLI built from this change
(whole and 7-byte streamed, 0 disagreements, scored by the benchmark's
`score.mjs`). UTF-8 byte ranges.

| Case (layout) | Expected span | Before | After |
| --- | --- | --- | --- |
| `elastic-raw-http-positive` (`Authorization`) | 89-149 | miss | exact, `authorization_credential`, `generic-token`, redact |
| `elastic-raw-http-proxy-positive` (`Proxy-Authorization`) | 87-147 | miss | exact, same |
| `elastic-raw-http-unicode-prefix-positive` (non-ASCII first line) | 51-111 | miss | exact, same |
| `elastic-curl-single-positive` (curl, single quotes) | 34-94 | miss | exact, same |
| `elastic-curl-double-positive` (curl, double quotes) | 34-94 | miss | exact, same |
| `elastic-curl-proxy-positive` (curl, proxy header) | 71-131 | miss | exact, same |
| `elastic-json-header-map-positive` (JSON header map) | 64-124 | miss | exact, same |
| `elastic-json-header-map-proxy-positive` (JSON header map, proxy) | 42-102 | miss | exact, same |
| the eight controls (bare `ApiKey` prose, `X-Authorization`, `Authorization-Info`, newline between scheme and value, `<your-api-key>`, `YOUR_API_KEY`, `${ES_API_KEY}`, mask) | none | clean | clean |

Unsupported, observed and never scored: a key id alone (`{"id": ...}`) is not
flagged, and is neither claimed nor assumed benign.

## Adopted boundary

| Question | Decision |
| --- | --- |
| Scheme | `ApiKey` (any case) joins `Basic`, `Token` and `Key` in `parse_authorization_from`, after the header name, optional quote, `:` and spaces or tabs. It is one scheme word followed by at least one space or tab: `Apis` and `ApiKey<value>` do not match. |
| Carrier | `Authorization` and `Proxy-Authorization` at a line start, and, like `Basic` and `Key`, mid-line after a byte that cannot continue a header name (a quoted curl `-H` argument, a JSON header map with a quoted key). `X-Authorization`, `Authorization-Info` and a value on the next line are not the header. `Token` stays line-start only. |
| Value, span, action | The run of the authorization value alphabet `[A-Za-z0-9+/=_-]`, at least 12 bytes, `=` padding included, exactly the span; always `redact` (the `always-redact` default of `authorization_credential`), high confidence when long and random enough, as for `Basic`. The encoded value is never decoded and the `:` of a decoded id and key never appears in it. |
| Attribution | Generic `authorization_credential` with the signal `authorization-apikey-scheme`. `ApiKey` is not unique to Elastic and Cloud and Serverless roles are not distinguishable from the carrier, so no Elastic type is claimed. |
| Excluded | The shared references, placeholder vocabulary and masks (`<your-api-key>`, `YOUR_API_KEY`, `${ES_API_KEY}` and masks leave no value run or are excluded by the shared exclusions); bare prose has no header carrier. |
| Overlap | A provider detector on the same bytes keeps precedence through the existing specificity rule (a Mailchimp key under `Authorization: apikey` stays one finding). |

## Tradeoffs

* Accepted contextual-policy false positive: a non-secret literal of 12+ bytes
  put into the exact `Authorization: ApiKey` slot is redacted by default.
  False negatives: a value under 12 bytes, a value on the next line, a quoted
  value containing a space or other byte outside the alphabet, `Token`-style
  mid-line headers (unchanged), and an Elasticsearch key sent in any other
  carrier.
* An Elastic id half that is public is still redacted with its secret half, by
  construction: the encoded value is one credential and is not split.

## Tests

`crates/secret-scan-core/tests/batch1_credential_slots_1209_1213.rs`
(`apikey_*` tests): exact UTF-8 spans, type and action for all eight layouts
and the case, tab and spacing variants, a multibyte-prefix offset, every
control, the neighbouring `Basic`, `Key` and `Apis` readings, the Mailchimp
overlap, and whole-input, every two-chunk UTF-8 byte partition and per-line
incremental parity. The keyword-jump oracle test of the authorization pass
(`generic_token::tests`) now includes `ApiKey` pieces. The independent replay of
the exact candidate on the four surfaces is the benchmarks side's step and
stays open.
