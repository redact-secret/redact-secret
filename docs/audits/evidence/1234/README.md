# Evidence: #1234, the `YOUR_PASSWORD` placeholder under a password name

**Result:** a measured false positive, fixed by naming the password family as
nouns of the existing instructional-placeholder rule. `{"password":"YOUR_PASSWORD"}`
produced one medium, `warn` `contextual_secret` over the 13-byte placeholder,
while `"password":"<password>"`, `YOUR_ACCESS_TOKEN` and `YOUR_CLIENT_SECRET`
under their names were silent. It now produces no finding. Real passwords, short
passwords and a placeholder glued to material are unchanged. No vocabulary,
detector, registry entry or type changes.

Issue [#1234](https://github.com/redact-secret/redact-secret/issues/1234), found
by the independent Batch 2 round-2 measurement of
[benchmarks#739](https://github.com/redact-secret/redact-secret-benchmarks/issues/739).
Package: [#1226](../1226/README.md), controls "placeholders, references, masks".
Related, closed: #817 (short passwords).

## Sources

| Role | Source |
| --- | --- |
| Independent oracle | [benchmarks#761 round-2 report](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/round2/report.md) and [ledger](https://github.com/redact-secret/redact-secret-benchmarks/blob/fe7a5d1acd8ba56e4f1c537117f78a944369a9c6/evidence/739/ledger.json) (merge `fe7a5d1a`), frozen corpus sha256 `a312308a141e3157c859f62e53c5e0762ca91c2e0083d0e02497848ebee8b921`. Case `mongodb-atlas:database-user-password:r2:password-member-placeholders:control`. Its expectation was not edited. |
| Baselines | Published `0.1.0-beta.13` and candidate `a148dadf4a43b5441ed88386d055428b2e278f25`, identical, all surfaces, whole and streamed. |
| Product policy | The #756 and #993 instructional-placeholder rule, the #1226 controls, and `decision-redact-provider-named-credential-assignments`. |

## Root cause

`is_instructional_token_placeholder` accepts a value of two or more words split on
`_`, `-` or `.`, whose first word is a lead word (`your`, `insert`, `enter`,
`paste`, `replace`), whose later words are listed credential, provider or lead
words, and in which at least one later word is a credential noun. The noun list
is `jwt`, `key`, `secret`, `token`, and the credential-word list has no password
word, so `YOUR_PASSWORD` failed on its second word and was reported, while
`YOUR_ACCESS_TOKEN` (noun `token`) and `YOUR_CLIENT_SECRET` (noun `secret`) were
silent. It is specific to the `YOUR_<NAME>` form under the password family, not
to the name `password`: `YOUR_PASSWORD` was reported under any contextual name.

## The change

A separate list `PLACEHOLDER_PASSWORD_WORDS` (`password`, `passwd`, `pwd`,
`passphrase`) is accepted, as a credential word and as a noun, by
`is_instructional_token_placeholder` only. The list is separate because the
shared word list also feeds rules where a password word would change behavior:
`placeholder-password` and the `my` + word glue (`mypassword` is a common weak
real password) stay as they were, and the glued and vendor-prefixed forms are
untouched.

## Before and after

Before: published `0.1.0-beta.13` and candidate `a148dadf`, all surfaces. After:
the CLI built from this change on the frozen corpus (1935 cases, whole and 7-byte
streamed), scored with the benchmark's `score-r2.mjs`; the replay of the fixed
candidate on Node, WASM and Python is the benchmarks side's step and stays open.

| Case | Before | After |
| --- | --- | --- |
| `mongodb-atlas:database-user-password:r2:password-member-placeholders:control` | flagged (`contextual_secret`, medium, warn, 13 bytes) | clean |
| the other controls and positives of the row and of the other 57 | unchanged | unchanged |

## Boundary and tradeoffs

| Value under `password`, `passwd`, `pwd`, `passphrase`, `db_password` | Result |
| --- | --- |
| `YOUR_PASSWORD`, `your_password`, `YOUR-PASSWORD`, `your-pwd-here`, `YOUR_PASSWD`, `YOUR_PASSPHRASE`, `INSERT_PASSWORD`, `ENTER_YOUR_PASSWORD`, `PASTE_YOUR_PASSWORD_HERE`, `REPLACE_WITH_YOUR_PASSWORD` | silent (quoted, unquoted, JSON, YAML, spaced) |
| `YOUR_API_KEY`, `YOUR_ACCESS_TOKEN`, `YOUR_CLIENT_SECRET` | silent (unchanged) |
| `YOUR_PASSWORD9f2cK7mQx`, `YOUR_PASSWORD_9f2cK7mQx` | reported, redact (unchanged) |
| `YOUR_PASSWORD9`, `YOUR_PASSWORDx` | reported, warn (unchanged) |
| `your_password_for_staging`, `YOUR_DB_PASSWORD`, `YOUR_PASS` | reported (one word off the list, unchanged) |
| a real password value of 12 bytes with mixed character classes | reported at medium, warn (unchanged) |
| `hunter2` | below the 8-byte floor, silent (unchanged, #817) |
| `mypassword` | reported, warn (unchanged) |

* False positive removed: a documentation placeholder reported as a password,
  which a policy that escalates `warn` would redact.
* False negative added: a real password spelled exactly as a lead word plus
  these nouns (`your_password`). No issuer generates that, and a user who writes
  it as a password has written the placeholder.
* `YOUR_PASS`, `YOUR_DB_PASSWORD` and `your_database_password` stay reported by
  the rule's own design (a word off the closed list), the same one-word-off stance
  as `YOUR_ACMECLOUD_API_KEY`; widening the list is a separate change if a
  baseline shows the miss.
* Policy: no new decision. It applies the existing placeholder rule to one more
  credential noun family, as `figma` was added to its provider words in #1209, so
  it is a spec row and this evidence, not an ADR.

## Tests

`crates/secret-scan-core/tests/batch2_gaps_1232_1234.rs`: the four password-family
names and `db_password` / `DB_PASSWORD` against 14 placeholders in JSON,
assignment, YAML and spaced CRLF layouts; the benchmark's member document with an
angle placeholder beside it; real values, the 8-byte floor, a glued placeholder,
a digit and an extra letter, an unlisted word and `mypassword`, each under
whole-input, every two-chunk UTF-8 byte partition and per-line incremental parity.

## Gates of the issue

The 8 gates are stated per package in the [#1226 record](../1226/README.md#gates-of-the-issue).
This record closes the repair of the demonstrated false positive and its
deterministic conformance; the independent replay of the fixed candidate on
Node, WASM, Python and the CLI stays open.
