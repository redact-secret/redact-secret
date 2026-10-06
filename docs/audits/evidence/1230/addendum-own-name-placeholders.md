# Addendum to #1230: `YOUR_<the slot's own name>` placeholders (round-2 regression)

**Result:** a regression of this work's `hapikey` entry, fixed by a closed rule.
The round-2 replay of candidate `e1cc1f31` found `?hapikey=YOUR_HAPIKEY` (a
`must-not-flag` control of `hubspot-legacy-api-key-placeholders-masked-display-and-references`)
reported as a 12-byte `contextual_secret` `warn`; it was clean on beta.13 and on
the previous candidate because `hapikey` was not a readable slot. The same hole
existed for the env and member forms (`HAPIKEY=YOUR_HAPIKEY`,
`"hapikey":"YOUR_HAPIKEY"`).

## Root cause

`is_instructional_token_placeholder` (`detectors/text.rs`) accepts a lead word
(`your`, `insert`, `enter`, `paste`, `replace`) followed only by listed credential,
provider, service or password words. `hapikey` is none of them, so
`YOUR_HAPIKEY` was a value as soon as the name made the slot readable. Every name
admitted by a whole-name entry has the same exposure.

## The change (`generic_token.rs`, `is_own_name_placeholder`)

A value is a placeholder when, after a lead word and any `_`, `-`, `.` or space
(further lead words allowed), the rest with separators removed and in any case
equals the concatenation of one or more trailing words of the slot's own
normalized name as written (before any alias). So the rule needs no list and
covers the names admitted by these fixes and the earlier closeout fixes:
`hapikey`, `personal_access_key`, `x_jfrog_art_api` (`YOUR_ART_API`,
`YOUR_JFROG_ART_API`), `token_key`, `encoded`, the Atlas `private_api_key` and
`public_api_key`, Zendesk `credentials`, `mac_secret_base64`, `fal_key`. `MY_` is
not a lead word (`my` plus `password` is a weak real password; the existing rule
excludes it for the same reason).

## Tradeoffs

* False positive removed: a documentation placeholder spelled with the slot's own
  name.
* False negative added: a real value spelled exactly as a lead word and the
  slot's own name words, which no issuer generates.
* Unchanged and reported: a placeholder glued to or followed by random material,
  the name inside a random value, a word off the name, `YOUR_HAPIKEYS`, a bare
  lead, and every real-shaped value.

## Tests

`crates/secret-scan-core/tests/placeholder_own_name_1230.rs` (3 tests): six
spellings of the placeholder in a curl URL, a request line, an env variable, a
prefixed variable and a JSON member; sixteen placeholders for the other admitted
names; the real-shaped twins detected. Every input runs whole, in 7-byte and in
1-byte chunks with equal text and findings.
