# Evidence: #1233, HubSpot `personalAccessKey` and `HUBSPOT_PERSONAL_ACCESS_KEY`

**Result:** a measured gap, fixed with two exact names. Before this change none
of the 8 positives (YAML account, quoted YAML, CRLF and end of input, YAML with a
same-shape neighbour, `.env`, `export` with quotes, `.env` at the end of input,
docker-compose) produced a finding, on every surface of published
`0.1.0-beta.13` and of candidate `a148dadf`. `personal_access_key` and
`hubspot_personal_access_key` (the normalized `personalAccessKey` and
`HUBSPOT_PERSONAL_ACCESS_KEY`) are now high-signal names matched only as whole
names, so all 8 are one `redact` finding over exactly the value, and the 4 row
controls stay clean. No `*key` rule, no detector, no type, no HubSpot
attribution.

Issue [#1233](https://github.com/redact-secret/redact-secret/issues/1233),
found by the independent Batch 2 round-2 measurement of
[benchmarks#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739).
Package: [#1225](../1225/README.md), whose vocabulary admission rule this record
applies.

## Sources

| Role | Source |
| --- | --- |
| Provider fact (field and variable) | credential-evidence `65602481`, `docs/handoffs/batch-2-research-r3.md`, row `hubspot:personal-access-key`: the field `personalAccessKey` of an account entry with `authType: personalaccesskey` in `~/.hscli/config.yml`, and the variable `HUBSPOT_PERSONAL_ACCESS_KEY`. **Caveat recorded by the evidence:** the field name rests on HubSpot's own `hubspot-local-dev-lib` source (provider-sdk-source), not a documentation sentence, and the legacy `portals` layout is unresolved (observed, not scored). Project-authored, not independent validation of the product. |
| Independent oracle | [benchmarks#761 round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) (merge `fe7a5d1a`), frozen corpus sha256 `a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921`. Its expectations were not edited. |
| Product policy | The vocabulary admission rule of [#1225](../1225/README.md): a name is added only when the evidence names the exact field, as one whole normalized name, with the shared exclusions, a false-positive and false-negative statement and neighbouring-name controls. |

## Baseline and replay

Before: published `0.1.0-beta.13` and candidate `a148dadf`, all four surfaces,
no finding on any of the 8 positives, whole and streamed at 7-byte and 1-byte
chunks. After: the CLI built from this change on the same frozen corpus (all 1935
cases, whole and 7-byte streamed), scored with the benchmark's `score-r2.mjs`.
UTF-8 byte ranges.

| Case id (`hubspot:personal-access-key:r2:<name>:positive`) | Before | After |
| --- | --- | --- |
| `personalAccessKey-yaml-account` | miss | exact, `contextual_secret`, redact |
| `personalAccessKey-yaml-quoted` | miss | exact, same |
| `personalAccessKey-yaml-eof-crlf` | miss | exact, same |
| `personalAccessKey-yaml-same-shape` | miss | exact, same (the same-shape public neighbour stays outside) |
| `HUBSPOT_PERSONAL_ACCESS_KEY-env` | miss | exact, same |
| `HUBSPOT_PERSONAL_ACCESS_KEY-export-quoted` | miss | exact, same |
| `HUBSPOT_PERSONAL_ACCESS_KEY-env-eof` | miss | exact, same |
| `HUBSPOT_PERSONAL_ACCESS_KEY-docker-compose` | miss | exact, same |
| the 4 row controls (public-only config, placeholders and references, masks, suffix lookalikes) | clean | clean |

The one unscored observation of the row, `personalAccessKey-legacy-portals`
(unsupported, observed), changed from no finding to a finding. That is a
consequence of reading the name wherever it appears, not a claim about the legacy
layout, which stays unresolved and is not scored or asserted.

## Adopted boundary

| Question | Decision |
| --- | --- |
| Vocabulary | `personal_access_key` and `hubspot_personal_access_key` join `EXACT_HIGH_SIGNAL_NAMES`, the whole-name mechanism of `mac_secret_base64` (#1211), `db_pass` and `fal_key`. Not matched: `personalAccessKeyId`, `personalAccessKeyExpiresAt`, `personalAccessKeyHint`, `personalAccessKeyLength`, `my_personal_access_key`, `oldPersonalAccessKey`, `HUBSPOT_PERSONAL_ACCESS_KEY_ID` and every other `*Key` name (`accessKey`, `personalKey`, `hubspot_key`). |
| Layouts | The existing contextual assignment grammar: YAML (account entry, quoted, CRLF, end of input), `.env`, `export`, docker-compose list item and mapping. |
| Span and action | Exactly the value, `redact` at high confidence, `warn` at medium (a low-entropy literal); the name, quotes and the neighbouring `portalId` and `authType` stay outside. |
| Attribution | Generic `contextual_secret`; no HubSpot type, no width or alphabet claim beyond the 8-byte contextual floor. |
| Silent | `portalId`, `authType`, a public-only config, placeholders, references, masks and empty values. |

## Tradeoffs

* False positive: a non-secret literal of 8 or more bytes under the exact name is
  redacted by default. The name is specific, so none is known.
* False negative: the same key under any other name, a value under 8 bytes, a
  value split across lines, and an SDK positional argument.
* Normalization lowercases camel case, so a bare `PERSONAL_ACCESS_KEY` variable
  is read too; it is the same name and the same credential role.
* The evidence for the field name is SDK source, not documentation. If HubSpot
  renames the field the entry becomes a harmless dead name; the cost of being
  wrong is one lookup.
* Policy: no new decision. This is the #1225 admission rule applied once, as
  `mac_secret_base64` was, so it is a spec row and this evidence, not an ADR.

## Tests

`crates/secret-scan-core/tests/batch2_gaps_1232_1234.rs` (`hubspot_*`): exact
UTF-8 spans, type, action and confidence for 12 layouts including the 8
benchmark layouts and a multi-byte prefix; no HubSpot attribution; a low-entropy
literal as `warn` at medium; and 22 controls (public config, placeholders,
references, masks, empty values, the neighbouring and prefixed names, other `*Key`
names), each under whole-input, every two-chunk UTF-8 byte partition and per-line
incremental parity.

## Gates of the issue

The 8 gates are stated per package in the [#1225 record](../1225/README.md#gates-of-the-issue).
This record closes the repair of the demonstrated gap, the evidenced vocabulary
addition and the deterministic conformance for it; the independent replay of the
fixed candidate on Node, WASM, Python and the CLI stays open.

## Final state at 4e004108 / replay accepted (2026-10-06)

Addendum. The text above is kept as written; the statements below are superseded
and this section is the current state. Replay facts shared by all Batch 2 records
are in the [#1223 record](../1223/README.md).

The fix is in candidate `4e0041081aad22d0101bd52db52017b67b5bd3db` (PR #1235) and
was replayed by the benchmark: benchmarks
[#771](https://github.com/redact-secret/redact-secret-benchmarks/pull/771)
(merge `74c88531f7f185e687eabe6477fff5b06f54e2e9`), frozen round-2 corpus
`sha256:a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921` (1935
cases), Node, WASM, Python and the CLI, whole and at 7-byte and 1-byte chunks
([round-3 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/round3/report.md),
[ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/74c88531f7f185e687eabe6477fff5b06f54e2e9/evidence/739/ledger.json)).

| Earlier statement (in this record) | State now |
| --- | --- |
| "the independent replay of the fixed candidate on Node, WASM, Python and the CLI stays open" (Gates) | Done and accepted: benchmarks #771. |
| "none of the 8 positives ... produced a finding, on every surface" (Result) | Still the record of the baseline. On `4e004108` all 8 positives pass on every surface and stream (the 8 `personalAccessKey-*` and `HUBSPOT_PERSONAL_ACCESS_KEY-*` cases), with the 4 row controls clean. |

Disposition at `74c88531` for `hubspot:personal-access-key`: `fixed by candidate
4e004108, replay verified on Node, WASM, Python and CLI (whole, 7-byte and 1-byte
streams)`; 0 positives failing, 0 controls flagged; whole equals stream on 60/60
entries at both chunk sizes and the four surfaces are identical on 15/15 cases.
The only other HubSpot difference from `a148dadf` is the unscored
`personalAccessKey-legacy-portals` observation, which changed from no finding to a
`contextual_secret` / `redact` finding at 55-91: the name is read wherever it
appears, the legacy `portals` layout stays unresolved and is not scored, and no
other row moved because of this change.

Gate "independent replay of the fixed candidate": **met**, candidate
`4e0041081aad22d0101bd52db52017b67b5bd3db`, accepted as benchmarks #771. No
package digest is claimed (no candidate package was published). Figures are read
from the merged report and ledger; the harness was not re-run for this addendum.
