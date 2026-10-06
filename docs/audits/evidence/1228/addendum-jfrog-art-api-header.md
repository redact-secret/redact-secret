# Addendum to #1228 and #1230: the `X-JFrog-Art-Api` header

**Result:** a measured product gap, fixed by one whole-name vocabulary entry.
The independent round-1 measurement of Groups C and E (benchmarks, candidate
`e1284537`) found the `X-JFrog-Art-Api` header carrier silent on every surface
and every chunking: 73 cases of group `G-jfrog` (C `jfrog:reference-token` 33,
E `jfrog:api-key` 40), 71 with no finding and 2 with a finding on another span.
Before: the header value stayed in the `--redact` output, while the same value
under `X-Api-Key` was a high `redact`. After: the value is a `contextual_secret`,
high, `redact`, exactly the value. The `curl -u user:<secret>` password slot of
the same group is **not** implemented (issue #1247); it stays a stated false
negative. Evidence is project-authored and maintainer-only, not independent
validation of the product's reading.

## Evidence read (read-only, `snapshot-2026.10.06.5`)

* Cases `jfrog-reference-token-header-and-basic-password-value` (Group C) and
  `jfrog-api-key-header-and-basic-password-value` (Group E), `must-flag`, basis
  `project-policy`. JFrog documents that an API key or a reference token is sent
  in the `X-JFrog-Art-API` header or as the Basic password. "The value is flagged
  because of where it sits, not because of its shape, and no key type is inferred
  from the position", extent "the value only", no prefix, width or alphabet is
  claimed (the documented `AKCp` + 69 form and the unprefixed 44-character
  reference example are not reconciled).
* The #1225 whole-name admission rule has two conditions: the evidence names the
  exact field, and a baseline shows the miss. Both are now met for this header.

## Root cause

`X-JFrog-Art-Api` normalizes (`.`/`-` to `_`, camel-case boundary, lower case) to
`x_jfrog_art_api`, which is not in the contextual vocabulary
(`generic_token.rs` `HIGH_SIGNAL_NAMES`, `EXACT_HIGH_SIGNAL_NAMES`) and is not a
`*_api_key` or `*_token` name, so the header line was never an assignment the
generic reader evaluates. `X-Api-Key`, `Fal-Key` and `X-Algolia-Api-Key` already
worked because their normalized names (`x_api_key`, `fal_key`,
`x_algolia_api_key`) end in `api_key` or are an exact entry.

## The change

`x_jfrog_art_api` is added to `EXACT_HIGH_SIGNAL_NAMES`
(`crates/secret-scan-core/src/detectors/generic_token.rs`). Both documented
spellings (`X-JFrog-Art-Api`, `X-JFrog-Art-API`) and any other letter case
normalize to it. Nothing else changes: the 8-byte value floor, entropy tiers, the
shared placeholder, reference and mask exclusions, the `Name: value` header
grammar, the curl `-H` quoting and the JSON-member grammar are the existing
ones. The finding is generic (`contextual_secret`), with no JFrog attribution and
no reference-token or API-key subtype, as the Cases say.

## Measured behaviour (synthetic values built at run time, whole input, 7-byte and 1-byte chunks equal)

| Input | Before | After |
| --- | --- | --- |
| raw HTTP, CRLF or LF, `X-JFrog-Art-Api: <v>` or `X-JFrog-Art-API: <v>`, at end of input, with trailing whitespace | silent | high, `redact`, exactly `<v>` |
| `curl -H "X-JFrog-Art-Api: <v>" <url>`, single quotes, `--header`, flag after the URL | silent | same |
| JSON header map `{"X-JFrog-Art-Api":"<v>"}`, compact or pretty-printed | silent | same |
| shapes: 32 hex, 64 alphanumeric, 40 URL-safe, 16 lower-case, hyphenated, dotted and underscored, 150 bytes, 16 bytes, the documented `AKCp` + 69 form | silent | same, any shape of 8+ bytes with a random-looking body |
| the header twice, a same-shape neighbour header, a neighbouring `X-Api-Key`, multibyte text around it, a 70 KB preceding body | silent | one finding per value, no neighbour touched |
| placeholders, `${ENV}`, `{{ }}`, mask, empty value, prose naming the header | silent | silent |
| `X-JFrog-Art-Api-Id`, `JFrog-Art-Api`, `X-Art-Api`, `X-JFrog-Api`, `My-X-JFrog-Art-Api` | silent | silent (whole name only) |
| `curl -u user:<secret>` | silent | silent: not implemented, issue #1247 |

## Tradeoffs

* False positive added: a non-secret literal of 8 or more bytes sent in this
  header (a placeholder-shaped test string that is not in the closed placeholder
  rules). The header exists only to carry a credential, so the cost is low.
* False negative kept, stated: the Basic password slot (`curl -u user:<secret>`
  and the `Authorization: Basic` envelope of a JFrog host) is not read by this
  entry and has no reader at all; it is issue #1247. A value of fewer than 8
  bytes, and an all-digit value (see the digits-only record), are also not read
  by this entry.
* No attribution, no width, no alphabet and no era claim is added; the finding
  type is the generic one a user action policy already controls.

## Per-party consequences

* Product: the Group C `jfrog:reference-token` and Group E `jfrog:api-key` header
  positives become exact; no other family's reading changes.
* Benchmarks: the header-carrier positives of the 73 `G-jfrog` cases (the case
  ids containing `art-api` or starting `header` or `fx-...-art-api-header`) are
  expected to move on a re-run at a commit carrying this fix; the `curl -u`
  (`basic-*`, `curl-u-password-*`) positives stay misses until #1247. A digits-only
  header value (`header-shape-digits24`) is the digits-only record's case.
* credential-evidence: no correction; the Case text is applied as written.

## Tests

`crates/secret-scan-core/tests/jfrog_art_api_header_1228_1230.rs` (5 tests): every
shape under four letter cases of the header in raw HTTP (CRLF, LF, end of input,
trailing whitespace), curl `-H` (double, single, `--header`, after the URL) and
JSON header maps; multibyte and large context, a repeated header and a neighbour;
placeholders, references, masks, empty and prose silent; neighbouring header names
silent; the `curl -u` password slot silent until #1247. Every input runs whole, in
7-byte chunks and in 1-byte chunks with equal text and findings.
