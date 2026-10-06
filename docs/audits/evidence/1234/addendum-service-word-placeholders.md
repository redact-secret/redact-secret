# Addendum to #1234: placeholders that name a product, service or scope

**Result:** a measured residual of [#1234](README.md), fixed by a closed list of
service and scope words read by the same bare-value rule. Before: the placeholder
spellings the Batch 2 provider documentation uses, outside the closed word lists,
were a high, `redact` `contextual_secret` over the whole value, while
`YOUR_USER_PASSWORD` and `YOUR_APP_SECRET` were silent (an inconsistency, not a
policy). After: they are silent. Real-shaped values that contain these words
inside random material are unchanged. No vocabulary, detector, registry entry or
type changes.

This record is separate from the #1234 README on purpose (the README is a final
record; another change edits the Batch 2 records). The README's statement that
`YOUR_DB_PASSWORD` and `your_database_password` "stay reported by the rule's own
design" is superseded by this addendum for the listed words only.

## Measured before

CLI `0.1.0-beta.14` built from `efe71496`, check mode, one line each, synthetic
inputs:

| Input | Before |
| --- | --- |
| `{"password":"YOUR_DB_PASSWORD"}`, `YOUR_DATABASE_PASSWORD`, `YOUR_ATLAS_PASSWORD`, `YOUR_MONGODB_PASSWORD` | `contextual_secret`, high, redact, whole value |
| `{"client_secret":"YOUR_ZOOM_CLIENT_SECRET"}` | same |
| `{"access_token":"YOUR_SPOTIFY_ACCESS_TOKEN"}` | same |
| `{"personalAccessKey":"YOUR_HUBSPOT_PERSONAL_ACCESS_KEY"}` | same |
| `{"private_key":"YOUR_PRIVATE_KEY"}`, `private_api_key = "YOUR_PRIVATE_API_KEY"` | same |
| `{"password":"YOUR_USER_PASSWORD"}`, `{"client_secret":"YOUR_APP_SECRET"}` | silent |

9 of the 11 inputs were findings, so the rule was inconsistent: `user` and `app`
are in the credential-word list, `db`, `zoom` and the others were not.

## Root cause

`is_instructional_token_placeholder` (`crates/secret-scan-core/src/detectors/text.rs`)
requires every word after the lead word to be a credential word, a provider
word, a lead word or (since #1234) a password word. A product or scope word
outside every list failed the whole value.

## The change

A separate closed list `PLACEHOLDER_SERVICE_WORDS` (`adobe`, `airtable`, `asana`,
`atlas`, `box`, `canva`, `contentful`, `database`, `db`, `dropbox`, `elastic`,
`hubspot`, `instagram`, `jfrog`, `meta`, `mongodb`, `private`, `salesforce`,
`spotify`, `zendesk`, `zoom`) is accepted by `is_instructional_token_placeholder`
only. The rule that decides stays the existing one: a lead word (`your`,
`insert`, `enter`, `paste`, `replace`), then only listed words each separated by
`_`, `-` or `.`, with at least one credential noun (`key`, `secret`, `token`,
`jwt` or a password word). The list is separate from the provider list for the
reason the password list is: the glued rule (`yourdbkey` behind a vendor prefix)
and the `my` rules read the shared lists and keep their behavior. The lead set is
unchanged: `MY_` is not a lead word (`my` + `password` is a common weak real
password).

The closed list is the principle: a word is added with the documentation that
spells a placeholder with it, never an open wildcard. `YOUR_STAGING_DB_PASSWORD`,
`YOUR_ACMECLOUD_API_KEY` and `your_zoom_webinar_secret` stay reported (one word
off the lists).

## Boundary and tradeoffs

| Value | Result |
| --- | --- |
| `YOUR_DB_PASSWORD`, `YOUR_ZOOM_CLIENT_SECRET`, `your-hubspot-personal-access-key`, `INSERT_PRIVATE_API_KEY_HERE`, `replace.with.your.atlas.password` | silent under every contextual name (JSON, assignment, YAML, `export`, CRLF) |
| a service word with no lead word (`db_password_prod`, `atlas-api-key-7`), `YOUR_ZOOM_ACCOUNT`, `YOUR_DB_HOST` (no credential noun) | reported (unchanged): not this rule |
| `YOUR_ZOOM_CLIENT_SECRET` + random material (glued, or after a separator), a random word between the lead and the noun, `YOUR_ZOOMCLIENT_SECRET`, a digit in a word | reported, redact (unchanged) |
| a random 40-byte value that contains `zoom`, `db` or `hubspot` anywhere | reported, redact, exact span (unchanged) |
| `Authorization: Bearer YOUR_SPOTIFY_ACCESS_TOKEN` | silent: `bearer-token` shares the rule |

* False positive removed: a documentation placeholder redacted as a credential.
* False negative added: a real value spelled exactly as a lead word, listed
  words and a noun (`your_db_password`). No issuer generates it, and a user who
  writes it as a value wrote the placeholder. Because a lead word is required
  and each word is a whole listed word, a random credential cannot satisfy the
  rule by chance: a 16-byte random value would need to be `your`, then listed
  words only.
* Policy: no new decision. It applies the existing placeholder rule to more
  words of the same kind, as `figma` was added in #1209; a spec-row change and
  this record.

## Tests

`crates/secret-scan-core/tests/placeholder_service_words_1234.rs` (6 tests): the
11 measured inputs; each of the 21 words under four leads, five separators and
four layouts (silent); no-lead and no-noun values reported; unlisted word, glued
material, fused words and a digit reported; real-shaped values with the service
word inside random material detected with the exact value span, `redact`;
the Bearer carrier. Every case runs whole, in 7-byte chunks and in 1-byte chunks
with equal text and findings.
