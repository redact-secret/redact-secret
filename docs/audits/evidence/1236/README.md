# Evidence: #1236, Square documentation placeholders under a Square name

**Result:** a measured false positive, fixed in the vendor-prefixed placeholder
rule of `generic-token`. Three synthetic placeholders from the #1014 Square
handoff each produced one high, `redact` `contextual_secret` over the whole
value. They now produce no finding. Real Square values, off-width random bodies,
placeholders glued to material and every other uppercase lead are unchanged.
No vocabulary, detector, registry entry or type changes.

Issue [#1236](https://github.com/redact-secret/redact-secret/issues/1236).
Handoff: [`../1014/square.md`](../1014/square.md), "Benign" controls. Oracle:
redact-secret-benchmarks `beta8-583a` (ledger record `product-1236`, benchmarks#770),
cases `beta8-583a--square-token-your-access-token-placeholder`,
`--square-token-angle-brackets-placeholder` and
`--square-oauth-application-secret-angle-brackets-placeholder`.

## Root cause

The contextual value reaches `is_non_secret_reference` in
`crates/secret-scan-core/src/detectors/generic_token.rs`, which calls
`is_vendor_prefixed_placeholder`. That rule strips a short lowercase vendor
prefix (at most 12 bytes, or the listed `sk-ant-admin01`) and excuses an
instructional, `<...>`, filler or placeholder-word remainder. Three shapes fell
outside it:

1. `EAAA-your-access-token`: the lead is uppercase, and an uppercase lead
   qualified only in front of a whole `<...>` (#756, #993).
2. `EAAA<your-production-access-token>`: no `-`/`_` separator, and the uppercase
   lead again.
3. `sandbox-sq0csb-<your-sandbox-application-secret>`: the prefix is 14 bytes,
   over the 12-byte cap, so the split at its second `-` left `sq0csb-<...>`, which is
   no placeholder. (`sq0csp-xxxxxxxx` and `YOUR_ACCESS_TOKEN` were already silent.)

## The change

* `UPPERCASE_PLACEHOLDER_PREFIXES = ["EAAA"]` with `is_uppercase_prefixed_placeholder`:
  after `EAAA`, a `-`/`_` separator and an instructional placeholder, lead-word
  phrase, repeated filler or whole `<...>` reference; or, with no separator, one
  whole `<...>` reference.
* `sandbox-sq0csb` is added to `LONG_VENDOR_PLACEHOLDER_PREFIXES`, the #1015 mechanism.

## Boundary and tradeoffs

| Value | Result |
| --- | --- |
| the three inputs, `EAAA_YOUR_ACCESS_TOKEN`, `EAAA-xxxxxxxx`, `sq0csp-<...>`, `sq0csp-xxxxxxxx`, `sandbox-sq0csb-xxxxxxxx`, `YOUR_ACCESS_TOKEN` | silent, whole and in 7-byte and 1-byte chunks |
| `EAAA` + 60, `sq0csp-` + 43 or 44, `sandbox-sq0csb-` + 43 | still `square_access_token` / `square_oauth_application_secret`, exact span, redact |
| `EAAA`, `EAAA-`, `sq0csp-`, `sandbox-sq0csb-` + a shorter random body | still reported by `generic-token` |
| a placeholder + random material, `EAAAyouraccesstoken` + material | still reported |
| `KEY_YOUR_API_KEY` | still reported (#756) |

* False positive removed: a documentation placeholder redacted as a credential.
* False negative added: a real value whose whole body is a placeholder phrase or
  an `<...>` reference after `EAAA` or `sandbox-sq0csb-`. Square's alphabet is
  `[A-Za-z0-9_-]`, so `<` and `>` never occur in an issued value, and no issued
  body is a `your-...` word phrase. A credential that merely contains the word
  `your` inside random material is not matched, because every remaining word must
  be on the closed placeholder lists.
* The dedicated `square-token` detector is unchanged and independent: it decides
  real-shaped values; this rule only silences the generic fallback.
* Policy: no new decision. It applies the #774/#949/#1015 vendor-prefixed
  placeholder rule to two more prefixes, so it is a spec row and this record.

## Tests

`crates/secret-scan-core/tests/square_placeholders_1236.rs`: the three inputs and
a sweep of 14 variants, silent in whole-input and in 7-byte and 1-byte
incremental runs equal to whole; real-shaped values built at run time with exact
spans; off-width bodies, glued placeholders and an unlisted uppercase lead still
reported. Before the change the two silence tests fail.
