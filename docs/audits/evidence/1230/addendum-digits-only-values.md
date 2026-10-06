# Addendum to #1230: a digits-only value in a credential-named slot

**Decision:** implemented. A value of 16 or more ASCII digits in a
credential-named slot is a `contextual_secret` at **medium** confidence (`warn`,
text unchanged), exactly the value, where it was silent. Round-1 gap group
`G-digits24` (7 scored cases: Airtable query, Dropbox member, Reddit access and
refresh member, form and fragment; the same shape in the JFrog header and the
`hapikey` parameter groups) is the measured reason. Evidence is project-authored
and maintainer-only, not independent validation.

## What the evidence says

The Cases for these slots (`airtable-legacy-api-key-url-parameter-value`,
`dropbox-legacy-long-lived-access-token-response-member`,
`reddit-oauth-refresh-token-response-member-and-request-field`,
`reddit-oauth-revoke-token-request-body-token-field`,
`reddit-oauth-access-token-response-member`,
`reddit-oauth-access-token-bearer-header-and-redirect-fragment`,
`jfrog-api-key-header-and-basic-password-value`,
`hubspot-legacy-api-key-hapikey-query-parameter-value`) flag the value of the
named slot "because of where it sits, not because of its shape". The round-1
measurement observed hexadecimal, alphanumeric, URL-safe and lower-case values of
the same slots flagged and the 24-digit one silent in each of the 7 scored
cases (one of the Reddit ones is the revoke-body `token=` slot, read by its own
record) and, once those slots are read, in the JFrog and `hapikey` digit cases.

## Root cause

`is_boolean_null_or_digits` (`generic_token.rs`) excluded every digits-only
value of any length from every contextual assignment, a blanket rule written to
keep counts, ports and ids silent. A 24-digit run under `api_key` or
`access_token` is read by the same name rules as any other run, so the exclusion
was the only thing that kept it silent.

## The change

For a contextual assignment only (`is_non_secret_assignment_reference`):

* a digits-only value is a non-secret reference when it has fewer than **16**
  digits or is a counting run (`1234567890123456`, with the wrap `9` to `0`);
  one repeated digit was already filler;
* from 16 digits it is read, and its confidence is capped at **medium**
  (`warn`) however random it looks, because a decimal run has no shape that
  separates a secret from a long id. The default action is therefore a
  report, not a redaction; a user action policy can still escalate `warn`;
* the ambiguous bucket (`auth`, `credential`, `credentials`, a ruleset's names)
  keeps its own entropy bar, which no digit run reaches (at most 3.32 bits per
  character against 3.5);
* the Bearer header carrier, `Authorization: Basic`, the call-keyword carrier and
  every other value check are unchanged (`is_non_secret_reference` is
  untouched); a Bearer value of 24 digits was already a `bearer_token`.

The floor of 16 is the least run that carries about 53 bits if random: no counter,
port, page number or small id reaches it, and a number of that length under a
name that ends in `key`, `secret`, `password` or `token` is more likely a key
than a count.

## Measured false-positive evidence

Before and after, the same CLI built at `cd091762` and with the change, every
tracked text file scanned, finding sets compared (new and removed findings):

| Corpus | Files scanned | New findings | Removed findings |
| --- | ---: | ---: | ---: |
| redact-secret (sources, tests, fixtures, docs, conformance, assessment) | 1,529 | 0 | 0 |
| credential-evidence (records, cases, fixtures, handoffs) | 4,398 | 0 | 0 |
| the other sibling repositories (adapters, gateway, www, sites, eval, pii-eval, custodian, ledger, token-counter, catalog, topology, anonymizer) | 3,232 | 0 | 0 |
| the Rust unit tests of the core (1,907) and the conformance corpora (`cargo test --workspace`, `npm run precision-contracts:check`) | all | unchanged | unchanged |

Zero new findings across 9,159 files means the 16-digit floor does not move any
benign text in the maintainers' own repositories, including the precision and
false-positive corpora; it also means these corpora hold no numeric secret under a
credential name, so they cannot show a recall gain. The recall evidence is the
round-1 group itself. The corpora do not contain a numeric id under a credential
name of 16 or more digits; the tests of this change pin the boundary instead.

## Tradeoffs

* False positive added: a decimal id of 16 or more digits under a name that ends
  in `key`, `secret`, `password` or a non-request-scoped `token` (a snowflake id
  stored as `bot_token`, a numeric cursor `next_token`). Cost: one `warn`, text
  unchanged by default.
* False negative kept, stated: a numeric secret of fewer than 16 digits (a PIN,
  a short numeric password) and a numeric secret that is a counting run; the
  numeric value under an ambiguous name; the Basic and call-keyword carriers.
* No redaction is added: medium confidence is `warn` under the default policy.
  A deployment that treats `warn` as `block` or `redact` gets the stricter
  behaviour from its own policy.

## Per-party consequences

* Product: `G-digits24` cases become findings; no other value changes.
* Benchmarks: the seven `shape-digits24` scored cases (and the JFrog and `hapikey`
  digit cases) are expected to move on a re-run at a commit carrying this change;
  the finding is a `warn`, so a scorer that requires `redact` for them must read
  the type and action as the contextual medium default.
* credential-evidence: no correction; the Cases say position, not shape, and the
  product now reads the digit shape by position at the lower confidence.

## Tests

`crates/secret-scan-core/tests/numeric_secret_values_1230.rs` (5 tests): a 24-digit
value in the baseline slots (query, member, form, fragment, header, `hapikey`,
JSON number) is one medium `warn`, exactly the value, text unchanged; the 16-digit
floor with 15, 12 and 8 digits silent; counting and repeated runs silent; a mixed
run keeps its high `redact`; non-credential names, ambiguous names, request-scoped
tokens and the bare `token` silent; context, large preceding body and
placeholders. Every input runs whole, in 7-byte chunks and in 1-byte chunks with
equal text and findings.
