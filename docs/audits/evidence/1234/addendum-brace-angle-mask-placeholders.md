# Addendum to #1234: brace, angle, documented-mask and upper-case placeholders

**Result:** a measured residual of [#1234](README.md) and its
[service-word addendum](addendum-service-word-placeholders.md), fixed by four
closed rules. The independent round-1 measurement of Groups C, D and E
(benchmarks, candidate `e1284537`) found 46 benign controls flagged on 10 rows
by documentation placeholders the earlier `YOUR_`-lead fix did not reach: 39 in
`G-brace`, 1 in `G-angle`, 6 in `G-docmask`. Before: a `{NAME}` brace template,
an angle placeholder with spaces, a documented mask and an upper-case reference
name were a `warn` or a high `redact` `contextual_secret` under a credential
slot. After: they are silent. Real-shaped values in the same slots are
unchanged. No vocabulary, detector, registry entry or type changes. Evidence is
project-authored, maintainer-only, not independent validation.

Cases (credential-evidence `snapshot-2026.10.06.5`, all `must-not-flag`):
`adobe-client-secret-placeholders-references-and-public-identifiers`,
`meta-app-secret-pipe-placeholders-derived-proof-and-non-values`,
`meta-instagram-app-secret-placeholders-and-references-non-values`,
`contentful-api-token-placeholders-and-token-free-preview-url-non-values`,
`airtable-legacy-api-key-placeholders-references-and-non-values`,
`adobe-jwt-service-account-identifiers-and-private-key-references`,
`contentful-cma-personal-access-token-documented-placeholders-and-masks`,
`zoom-build-api-key-placeholders-and-non-values`.

## Root causes (all in `crates/secret-scan-core/src/detectors/generic_token.rs`)

| Gap | Observed on `e1284537` | Root cause |
| --- | --- | --- |
| `G-brace` (39) | `access_token={short-lived-access-token}` read as the 25-byte value `{short-lived-access-token` (high `redact`); `{your-app_id}\|{your-app_secret}` read as the 12-byte `{your-app_id` (`warn`) | `query_parameter_value` ends a query, fragment or form value at the first `}` (`is_query_value_stop`), so the brace group was cut before its close and the leftover looked like a value; a quoted `"{YOUR_CLIENT_SECRET}"` was never a reference |
| `G-angle` (1) | `private_key: <contents of private.key>` read as the 9-byte `<contents` (`warn`) | the unquoted value ends at the first space, so `starts_with_angle_bracket_reference` never saw the closing `>` |
| `G-docmask` (5 of 6) | `CFPAT-xxx` (9 bytes) and `CFPAT-123...789` (15 bytes) `warn` | `CFPAT` is an upper-case vendor prefix, which the vendor-placeholder rule accepts only when listed; the middle-elision display has no rule (the existing ones elide the tail or mask the middle) |
| `G-docmask` (1 of 6) | `"x-api-key": "ZOOM_API_KEY"` `warn` | the credential-variable-name reference rule (#911) reads unquoted values only |

## The change

1. **Brace placeholder** (`brace_placeholder_len`, `is_brace_placeholder_reference`,
   `query_brace_placeholder`). A whole value that is `{words}`, or two such
   groups joined by `|` or `:`, is a reference. Closed grammar: ASCII letters in
   words (1 to 24 each) joined by `_`, `-`, `.` or one space, at most 48 bytes
   between the braces (the RFC 6570 `{name}` template convention). A digit, any
   other byte, an empty group, a longer word or material outside the braces
   keeps the value reported. The query value scan takes the whole group when a
   value boundary follows it.
2. **Angle placeholder with spaces.** `<` ... `>` joins the delimited reference
   openers, so `<contents of private.key>` is one reference value when a value
   boundary follows the `>`; `<x>` glued to material, an unclosed `<` and a
   bracket crossing a line keep today's reading.
3. **Documented masks.** `CFPAT` joins the listed upper-case placeholder
   prefixes (the Contentful CMA token prefix; `CFPAT-xxx`, `CFPAT-<your-token>`,
   `CFPAT-your-token`), and `is_elided_middle_display` reads a visible head
   (1 to 12 `[A-Za-z0-9_-]`), exactly `...` or `…`, and a visible tail (1 to 12)
   as a display with the middle elided (`CFPAT-123...789`).
4. **Quoted variable name for its own slot** (`is_quoted_variable_name_for_slot`).
   A quoted `UPPER_SNAKE` credential variable name is a reference when its last
   word is the last word of the slot's name (`password` family counts as one):
   `"x-api-key": "ZOOM_API_KEY"`, `"password": "ADMIN_PASSWORD"`. A quoted
   `"api_key": "OTHER_TOKEN"` and any random value stay reported.

## Boundary and tradeoffs

| Value | Result |
| --- | --- |
| `{CLIENT_SECRET}`, `{your-app_id}`, `{your-app_id}\|{your-app_secret}`, `{user-access-token}`, `{YOUR_DEVELOPER_API_KEY}`, `{entry.fields.slug}`, `{your api key}` under every contextual name, in a request line, a form body, a quoted curl URL, `curl -d`, `curl -F`, a fragment, and as a quoted JSON value | silent |
| `{<24 random alphanumerics>}`, a brace-wrapped GUID, a word over 24 letters, a group glued to random material | reported (unchanged; the plain scan reads up to the closing brace) |
| `<contents of private.key>`, `<your private key>`, `<paste your api key here>` under an unquoted slot | silent |
| `<contents of key>` glued to random material, `<contents <random>`, `<<random>` | reported (unchanged) |
| `CFPAT-xxx`, `CFPAT-123...789`, `CFPAT-<your-token>`, `CFPAT-your-token`, `abc...xyz` | silent |
| `CFPAT-` + 43 random alphanumerics, `CFPAT-yourtoken<random>`, an ellipsis display whose head is 13 bytes | reported, `redact`, exact value |
| `"x-api-key": "ZOOM_API_KEY"`, `"password": "ADMIN_PASSWORD"`, `"client_secret": "APP_CLIENT_SECRET"` | silent |
| `"api_key": "OTHER_TOKEN"`, `"password": "ADMIN_PASSWORD_2f9QxL7m"`, `"api_key": "<20 random upper-case and digits>"` | reported (unchanged) |

* False positives removed: documentation placeholders redacted or warned.
* False negatives added, each narrow: a real secret that is letters only in
  short words inside one pair of braces; a real secret wrapped in angle brackets
  with spaces; a real secret of the shape `<=12 visible>...<=12 visible>`;
  a quoted all-caps word chain whose last word is the slot's own last word. No
  issuer generates any of them, and the surrounding documentation convention
  names each as a placeholder.
* The shared rules also serve the `bearer-token` carrier
  (`Authorization: Bearer {ACCESS_TOKEN}` is silent).
* Policy: no new decision. It extends the existing closed placeholder
  recognition (`<...>`, `${}`, `{{ }}`, vendor-prefixed and masked displays)
  to the same kind of documentation form, as #1209, #1234 and #1236 did.

## Not reproduced

`contentful:delivery-api-access-token` `preview-url-no-token-query` (one case,
`G-brace`) was observed as a 15-byte `warn`; its input is a URL template with
`{entry.fields.slug}`. The new brace rule keeps the URL-template forms
`https://app.example.test/preview/{entry.fields.slug}` and the same under a
`?x={entry.fields.slug}` query silent, but the case text was not read, so the
case is not claimed closed here; the measurer replays it.

## Tests

`crates/secret-scan-core/tests/placeholder_brace_angle_mask_1234.rs` (8 tests):
every brace placeholder under five names in five carriers and as quoted JSON
values; real-shaped values and brace-wrapped values with digits, GUIDs and
glued material detected; angle placeholders with spaces silent and the glued,
unclosed and nested twins reported; documented masks and the `CFPAT` forms
silent and the random `CFPAT-` body, a long-head ellipsis and a glued
placeholder reported; quoted variable names silent only in their own slot. Every
input runs whole, in 7-byte chunks and in 1-byte chunks with equal text and
findings.
