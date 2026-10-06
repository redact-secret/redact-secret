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
| "the replay of the fixed candidate on Node, WASM and Python is the benchmarks side's step and stays open" (Before and after) and "the independent replay ... stays open" (Gates) | Done and accepted: benchmarks #771. |
| `password-member-placeholders:control` "flagged ... After: clean" (CLI replay) | Confirmed by the benchmark on all four surfaces: clean. |

Disposition at `74c88531` for `mongodb-atlas:database-user-password`: `fixed by
candidate 4e004108, replay verified on Node, WASM, Python and CLI (whole, 7-byte
and 1-byte streams)`; 0 positives failing, 0 controls flagged; whole equals stream
on 148/148 entries at both chunk sizes and the four surfaces are identical on
37/37 cases. The round-3 report states the side effect precisely: the new
password-word list changed one control (the Atlas `YOUR_PASSWORD` placeholder);
the password-field and URI-userinfo positives, the low-entropy warn cases and all
other password-named cases are unchanged. The percent-escaped URI password stays
observed and not scored (see the [#1226 record](../1226/README.md)).

Gate "independent replay of the fixed candidate": **met**, candidate
`4e0041081aad22d0101bd52db52017b67b5bd3db`, accepted as benchmarks #771. No
package digest is claimed (no candidate package was published). Figures are read
from the merged report and ledger; the harness was not re-run for this addendum.

## Closure statement (2026-10-06)

What this issue can honestly claim after the Groups C, D and E measurement rounds.

The 46 placeholder controls flagged on round 1 (brace `{NAME}` and
`{your-app_id}|{your-app_secret}`, angle, documented mask and upper-case
reference name), on 10 rows of Groups C, D and E, are clean on the final candidate
on every surface and mode. That includes the 12 pipe composites left open on round
2 and the `YOUR_HAPIKEY` control that regressed on round 2 and was repaired by
`c8d661b3`. The 12-control closure was measured after `c6dd6859` and should be
cited with the round-2 regression history ([section 2](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#2-regressions)). No
placeholder control of these corpora is flagged except the six `x-api-key` Adobe
client-id controls, which are a role question (recorded deviation b), not a
placeholder. The false-positive cost of the placeholder grammar on real traffic is
not measured.

The closeout also added tracked policies that these records do not claim as covered:
the `curl -u` password slot ([redact-secret#1247](https://github.com/redact-secret/redact-secret/issues/1247)), the JFrog `AKCp` bare
reader, deferred ([redact-secret#1248](https://github.com/redact-secret/redact-secret/issues/1248)), the bare `token` member
([redact-secret#1256](https://github.com/redact-secret/redact-secret/issues/1256), rule [#1241](../1241/README.md)), the existing Case
contradictions ([credential-evidence#264](https://github.com/redact-secret/credential-evidence/issues/264)) and the percent-escaped X layout
confirmation ([credential-evidence#265](https://github.com/redact-secret/credential-evidence/issues/265)).

Source: the [round-3 report of Groups C, D and E](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md) (section 7, [dispositions](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/report.md#6-final-disposition-of-all-43-rows)),
its [scores](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/scores.json) and
[identity](https://github.com/redact-secret/redact-secret-benchmarks/blob/c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291/evidence/groups-cde/round3/identity.json), at benchmarks commit
`c1837c240a9eb4ec43bfa6abc6e2e3d7f34c7291`, measuring candidate
`c6dd685974b8df6a84514e07e41e35afa711a2ac` (unpublished, 0.1.0-beta.14) on one
host. Project-authored, maintainer-only evidence, not independent validation;
the fixes target measured failures and no generalisation is claimed.
