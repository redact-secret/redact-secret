# Evidence: #1209, explicit `X-Figma-Token` header values

**Result:** detection of an explicit `X-Figma-Token` header value was already
covered and is unchanged: all five measured positives (raw HTTP, raw HTTP behind
a non-ASCII line, quoted curl `-H` in single and double quotes, JSON header map)
are one `redact` finding spanning exactly the value, generic type
`contextual_secret`. The one measured false positive, the instructional
placeholder `YOUR_FIGMA_TOKEN` in the exact credential slot, is fixed by adding
`figma` to the closed provider-word list of the shared placeholder rule. No new
detector, registry entry, vocabulary name or type.

Issue [#1209](https://github.com/redact-secret/redact-secret/issues/1209),
Batch 1 of the credential-evidence adoption inventory
([#231](https://github.com/redact-secret/credential-evidence/issues/231),
handoff [#232](https://github.com/redact-secret/credential-evidence/issues/232)).

## Sources

| Role | Source |
| --- | --- |
| Provider fact (slot and role) | [`figma:personal-access-token` proposed contract](https://github.com/redact-secret/credential-evidence/blob/6dd2ae3cf46947548dcfad4bb746bcfd80f9f431/records/contracts/figma/personal-access-token@1.json): the token is passed in the `X-Figma-Token` request header. The contract states no prefix, alphabet or width, and the `figd_` prefix rests on two scanner-rule artifacts only. |
| Independent oracle | [benchmarks#717 Batch 1 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/14271c7e85ad9300e100c6a4b5e33105e7429166/evidence/717/report.md) over `benchmarks/batch1/corpus.mjs` (82 cases, corpus sha256 `ddd709174816443e`). Its expectations were not edited and the product's output was not copied as truth. |
| Project policy (this record) | The span, action, type, placeholder boundary and tradeoffs below. |

## Baseline and replay

The baseline (published `@redact-secret/core` 0.1.0-beta.13 and core
`d4e86769`, Node, WASM, Python and CLI identical) is the benchmarks report
above. The after column is the same corpus replayed through the CLI built from
this change (whole and 7-byte streamed scans, scored with the benchmark's own
`score.mjs`, 0 stream disagreements). Offsets are UTF-8 byte ranges.

| Case (layout) | Expected span | Before | After |
| --- | --- | --- | --- |
| `figma-raw-http-positive` (raw HTTP) | 69-109 | exact, `contextual_secret`, `generic-token`, redact | unchanged |
| `figma-raw-http-unicode-prefix-positive` (non-ASCII first line) | 93-136 | exact, same | unchanged |
| `figma-curl-single-positive` (curl, single quotes) | 27-59 | exact, same | unchanged |
| `figma-curl-double-positive` (curl, double quotes) | 27-51 | exact, same | unchanged |
| `figma-json-header-map-positive` (JSON header map) | 120-160 | exact, same | unchanged |
| `figma-placeholder-example-control` (curl, `YOUR_FIGMA_TOKEN`) | none | **flagged** (`contextual_secret`, 24-40, redact) | clean |
| the other eight controls (`-Id` and `-Hint` names, `<your-figma-token>`, `${FIGMA_TOKEN}`, `{{ secrets.figma_token }}`, two masks, public ids) | none | clean | clean |

Unsupported variants, observed and never scored: `X-Old-Figma-Token` is flagged
generically (a prefixed name may carry the same credential), a newline-separated
value and bare `figd_` prose are not flagged.

## Adopted boundary

| Question | Decision |
| --- | --- |
| Slot | The value after `X-Figma-Token:` in a raw header line, a quoted `curl -H` argument or a JSON header map. The existing contextual assignment grammar reads it: `x_figma_token` is a prefixed `_token` name, so it is high-signal under the #702 rule. No name was added. |
| Span and action | Exactly the value, `redact` by default (`contextual_secret`, high). The header name and carrier stay outside the span. |
| Attribution | Generic. PAT and plan tokens share the header, so no personal-access-token subtype is inferred from it. No bare `figd_`/`figp_` grammar and no width or alphabet claim. |
| Placeholder boundary | `figma` joins `PLACEHOLDER_PROVIDER_WORDS` (the #774, #919 and #1203 mechanism), so an instructional placeholder is silent under every contextual name: `YOUR_FIGMA_TOKEN`, `your-figma-token`, `replace-with-your-figma-token`, `YOUR_FIGMA_PERSONAL_ACCESS_TOKEN`. A placeholder glued to random material (`YOUR_FIGMA_TOKEN_<random>`) and a random value stay reported. |
| Reference and mask boundary | Unchanged shared rules: `${...}`, `{{ ... }}`, `<...>`, masks. |
| Lookalikes | `X-Figma-Token-Id` and `X-Figma-Token-Hint` are different names and stay clean; a value on the next line is not a header value. |

## Tradeoffs

* False positive (accepted, existing contextual policy): a non-secret literal
  put into the exact `X-Figma-Token` slot is redacted by default. Documented
  false negatives: a value on the line after the header, a token shorter than
  the 8-byte contextual floor, and any layout other than the three above.
  `X-Old-Figma-Token` is matched only because the prefixed `_token` rule covers
  it; it is observed, not claimed.
* False negative added by the fix: a real token made only of a lead word,
  `figma` and credential words, which random token material never is. The
  glued form `re_yourfigmakey` behind a vendor prefix is now also read as a
  placeholder, because the glued-word split shares the list.

## Tests

`crates/secret-scan-core/tests/batch1_credential_slots_1209_1213.rs`
(`figma_*` tests): exact UTF-8 spans in all five layouts with a multibyte
prefix, action and type, every control of the corpus, the placeholder fix with
its glued and random neighbours, and whole-input, every two-chunk UTF-8 byte
partition and per-line incremental parity for every input. Overlap does not
arise: every input yields one finding or none.

Node/WASM, Python, Rust and CLI share this core, so the behavior is the same on
every surface. The independent replay of the exact candidate on the four
surfaces is the benchmarks side's acceptance step and stays open.
