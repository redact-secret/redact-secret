# Addendum to #1230: the Zendesk `{email}/token:{api_token}` credential string

**Result:** a measured product defect, fixed by a reader anchored on the
documented literal. The independent round-1 measurement of Group E (benchmarks,
candidate `e1284537`) found, in `zendesk:api-token` (`G-zendesk-cred`, 32 scored
cases), two failures of the `email/token:<token>` string. In a JSON member and an
environment value it was one `contextual_secret`, `warn`, over the **whole** string
including the email: medium confidence, text unchanged by default, so the token
stayed in the `--redact` output while the report looked like a hit (10 over-wide
cases, plus 2 more combined with a miss). A masked display
(`ZENDESK_BASIC_CREDENTIALS=agent@example.test/token:********`) was flagged the same
way, a false positive on a `conflict` case. In a `curl -u` argument it was silent
(20 cases). Before: the token was never redacted by default. After: the finding is
the token only, `contextual_secret`, high, `redact`; masks, references,
templates and placeholder tokens are silent. Evidence is project-authored and
maintainer-only, not independent validation.

## Evidence read (read-only, `snapshot-2026.10.06.5`)

* Case `zendesk-api-token-basic-credential-token-part` (`must-flag`, basis
  `project-policy`, credential-evidence#246): the documented credential string is
  `{email_address}/token:{api_token}`, Zendesk calls the token a password that can
  impersonate anyone in the account, so "the literal `/token:` after an email
  address marks where the secret part begins"; no length, alphabet or prefix is
  stated, so the token is flagged "because of where it sits, not because of its
  shape". "The extent is the token only: the email address, the `/token`
  separator and any quote are outside it", and the email is an identifier whose
  confidentiality Zendesk does not state. The carriers are a `curl -u` argument, a
  JSON configuration string and an environment assignment. The Basic header form
  carries the same string base64-encoded; that is a separate question. The family
  is deprecated and retired in phases through 2027-04-30; a retired credential
  still sits in configuration.
* The evidence fixtures give the non-values: `{email_address}/token:{api_token}`,
  `agent@example.test/token:${ZENDESK_API_TOKEN}`,
  `agent@example.test/token:********`, `agent@example.test/token` (no token) and an
  email address alone.

## Root cause

The generic reader saw the string only as the value of a credential-named slot
(`credentials`, `ZENDESK_BASIC_CREDENTIALS`): an ambiguous name, medium `warn`,
span = the whole value. Nothing read the `/token:` separator, so the token had no
span of its own and a mask after the separator did not make the string a
reference (the composite-placeholder rule excludes any value with `@` or `/`).

## The change (`crates/secret-scan-core/src/detectors/generic_token.rs`)

* **A reader anchored on `/token:`** (`email_token_candidates`): wherever the
  literal `/token:` stands directly after an email address (a local part of
  `[A-Za-z0-9._%+-]`, `@`, and a domain of two or more dot-separated labels whose
  last label is two or more ASCII letters), the value after it is a
  `contextual_secret`: the span is the token only; `high` and `redact` at 16 or
  more random-looking bytes, `medium` (`warn`) below that or at low entropy; any
  shape, a digits-only token (of 16 or more digits, at medium) included, since
  the literal is the slot. The value is scanned like an unquoted assignment value,
  so `${ENV}`, `{{ }}`, `{...}`, `<...>`, a mask, a placeholder and an empty
  token are silent, and the same exclusions as every contextual value apply (the
  8-byte floor and the shared reference, placeholder and mask rules). A JSON-escaped
  closing quote leaves no backslash on the span.
* **It wins the overlap** against the whole-string reading: the token-only
  candidate is `redact` where the generic one is `warn`, and the resolved-action
  severity is the first overlap key
  (`resolve-overlap-precedence-by-resolved-action-severity`); where the generic
  reading is also `redact` (`ZENDESK_API_TOKEN=<email>/token:<token>`), the
  narrower span wins, so the email stays visible and the token is redacted.
* **A masked or placeholder token makes the whole string a reference**
  (`is_email_token_credential_with_placeholder`): an email, `/token:` and an empty
  token, a mask, a reference, a template or a placeholder is silent under every
  contextual name, which removes the false positive.
* The reader does not look at flags or carriers. A `curl -u "<email>/token:<token>"`
  argument is therefore read as a consequence of the literal; no `-u` or `--user`
  reader exists, and a plain `-u user:<password>` stays unread (issue #1247).

## Measured behaviour (synthetic values built at run time; whole input, 7-byte and 1-byte chunks equal)

| Input | Before | After |
| --- | --- | --- |
| `ZENDESK_BASIC_CREDENTIALS=<email>/token:<t>` (plain, quoted, `export`, CRLF, end of input, trailing whitespace) | the whole string, `warn` (medium) | `<t>` only, high, `redact` |
| JSON `{"credentials": "<email>/token:<t>"}`, pretty or compact, last member or not | the whole string, `warn` | `<t>` only, high, `redact` |
| a non-credential name (`{"auth": "..."}`, prose) | silent or the whole string | `<t>` only |
| `curl <url> -u "<email>/token:<t>"` or `'...'` | silent | `<t>` only (the literal, not a flag reader) |
| emails with a plus address, a sub-domain, upper case, `%` and `_` | mixed | `<t>` only |
| shapes: 32 hex, 64 alphanumeric, 40 URL-safe, 16 lower-case, hyphenated, dotted and underscored | mixed | same, exact |
| two strings, a neighbouring `password=`, multibyte text, a 74 KB preceding body | the whole strings | each token exact, the email visible |
| `.../token:********`, `${ZENDESK_API_TOKEN}`, `$ZENDESK_API_TOKEN`, `{{ secrets.X }}`, `{api_token}`, `<api_token>`, `<your api token>`, `YOUR_API_TOKEN`, a run of `x`, an empty token | the whole string, `warn` (masks) | silent |
| `{email_address}/token:{api_token}`, `<email>/token` (no colon), an email alone, a left side that is not an email (`agent`, `agent@`, `@example.test`, `agent@example`, `a b@example.test`) | silent or the whole string | silent |
| `-u agent:<password>` | silent | silent (issue #1247) |

## False-positive measurement

The CLI built before and after the change over the tracked text files of the
maintainers' repositories: redact-secret 1,540 files, credential-evidence 4,398,
the other sibling repositories 3,232 (9,170 files). New findings from this
reader: **3**, the three credential strings of credential-evidence's
`zendesk-authored.json` (`curl -u`, a JSON `credentials` member and an
environment value; each the 39-byte token only, high, `redact`, true positives).
Removed findings: **2**, the whole-string `warn` over the environment fixture
(replaced by the token-only finding) and the whole-string `warn` over the masked
display `agent@example.test/token:********` (the false positive of the
measurement). No other `/token:` in 9,170 files became a finding. The fixture
file holds the strings inside JSON strings with escaped line breaks, which the
reader ends at (a token holds no backslash).

## Tradeoffs

* False positive added: a non-secret literal of 8 or more bytes after
  `<email>/token:` (only the documented form has this shape).
* False negative kept, stated: a token under 8 bytes; the same string inside a
  base64 `Basic` envelope (read as one whole `authorization_credential` span, the
  #1230 contract); a plain `-u user:<password>` (#1247).
* The finding is the generic type: no Zendesk attribution, no width, alphabet or
  prefix claim.

## Per-party consequences

* Product: the Group E `zendesk:api-token` credential-string positives become
  exact and redacted; the masked display becomes silent. The `curl -u` cases of
  the same Case are read by the anchor, which the work item had scoped to #1247;
  the incidental read is documented here and pinned by a test, and can be limited
  to JSON and environment values by one carrier check if #1247's design prefers a
  single flag reader.
* Benchmarks: the `credential-*` cases of `zendesk:api-token` (JSON, environment
  and, through the anchor, `curl -u`) and the masked-display `conflict` case are
  expected to move on a re-run; the type is `contextual_secret`, the action
  `redact` at high confidence.
* credential-evidence: no correction.

## Tests

`crates/secret-scan-core/tests/zendesk_email_token_1230.rs` (7 tests): the token in
JSON and environment values over five email forms and seven token shapes, and in a
non-named slot; context, a large preceding body, two strings and a neighbouring
secret; the token-only span winning over the whole-string reading in the redacted
output, with the email visible; masks, references, templates, placeholders, empty
tokens and non-credential strings silent; left sides that are not emails unread;
the credential string inside an enclosing JSON string ending at its escape; the `curl` Basic form read by the literal and a plain user and password not. Every
input runs whole, in 7-byte chunks and in 1-byte chunks with equal text and
findings.
