---
decision_id: decision-settle-the-snapshot-2026-10-04-4-added-case-roots
status: accepted
scope: workspace
title: Settle the root causes that credential-evidence snapshot-2026.10.04.4 added
decided_at: 2026-10-05
spec: engine
---

# Settle the root causes that credential-evidence snapshot-2026.10.04.4 added

## Context

[#1205](https://github.com/redact-secret/redact-secret/issues/1205) follows
[#1203](https://github.com/redact-secret/redact-secret/issues/1203).
credential-evidence `snapshot-2026.10.04.4` adds 70 cases. On both published
`@redact-secret/core@0.1.0-beta.13` and the unpublished candidate `1e45cecf`
(PRs #1202 and #1204) 58 pass, 7 fail and 5 are pending (T0). The benchmark
triage (redact-secret-benchmarks#698, PR #703) leaves **57 root causes** that
core has not classified: 1 flagged control, 5 positive misses, 1 partial
positive, 26 peer-differential occurrences and 24 assertion failures.

Replayed with the product API and CLI on each case input, the 57 are **24 base
cases**: every `context.indent`, `context.unicode-prefix` and `encoding.crlf`
variant, every metamorphic or mutation assertion and every peer occurrence of
one base case replays with the same findings, so a variant count is not a
defect count. Published beta.13 and `main` before this record return identical
findings (UTF-8 byte ranges, actions and sanitized output) on all 24, and on
all 70 added cases. None is a beta.13 regression. The tests are
`crates/secret-scan-core/tests/evidence_snapshot_2026_10_04_4_1205.rs`, which
pins every case id.

## Decision

Each base case gets one disposition. Two are in-contract false positives and
are fixed; the rest are carriers or families the product does not read, which
the existing records already cover or this one states.

| Root cause | Base cases | Disposition |
| --- | --- | --- |
| Compose `${NAME:?message}`: the text after `?` read as the value (`generic-token` warn) | `docker-compose-resolution-authored--required-message` | in-contract bug, **fixed**: the required-variable message is not a value; the `:-` default stays reported |
| A value that is the assigned name (`{"aws_secret_access_key": aws_secret_access_key}` in notebook source; `generic-token` redact on 21 bytes beside the 8 expected spans) | `jupyter-notebook-files-authored--same-value-in-source-stream-result-json-error-and-traceback` | in-contract bug, **fixed**: a value equal to its own normalized name is a reference |
| Key behind a percent-encoded JSON quote in a URL (`variables=%7B%22apiKey%22%3A%22SG....%22%7D`) | `graphql-requests-and-responses-authored--get-url-variables-value` | encoded carrier: the byte before the key is the `2` of `%22`; `decision-defer-encoded-input-decoding` |
| JSON `{"name": "access_token", "value": "..."}` object pair (HAR `postData.params`, `queryString`) | `har-exports-authored--bearer-token-in-postdata-params`, `har-exports-authored--bearer-token-in-url-and-querystring-array` (its `url` string is claimed exactly) | unsupported: no JSON name/value pairing |
| HTTP session cookie in HAR `headers` and `cookies` arrays | `har-exports-authored--session-cookie-in-headers-and-cookies-arrays` | unsupported: no session-cookie family (#1203), and the object pair above |
| Terraform state output: the value under `"db_admin_password": { "value": ... }` | `hashicorp-terraform-authored--state-json-output-password-with-sensitive-true` | unsupported: a credential name that keys an object, not a one-line assignment |
| Secret literal cut by a notebook `source` array element boundary | `jupyter-notebook-files-authored--source-value-split-between-array-elements` | fragment, `decision-define-fragmented-credentials-as-outside-the-raw-input-contract` |
| Mask `****...` ended by a JSON-escaped line break (`generic-token` medium, `warn`) | `jupyter-notebook-files-authored--stdout-mask-where-source-has-environment-reference` | contract: the escaped line break is two value bytes, so the run is not a mask; `warn`, text unchanged |
| JS added literals, shell and backslash-CRLF continuations (the core redacts an incidental fragment, the peers nothing) | `line-break-and-fragment-authored--key-split-across-javascript-added-literals`, `--key-split-before-last-character-by-shell-continuation`, `--key-split-by-backslash-crlf-continuation`, `--key-split-by-unquoted-shell-continuation` | fragment (#1199); the incidental `generic-token` redaction is not a claim |
| SendGrid key as base64 or hex, one to three layers (a peer decodes, the core does not) | 11 `base64-hex-representation-projections--sendgrid-key-*` cases | encoded carrier, `decision-defer-encoded-input-decoding`; peer divergence |

Counts: 2 fixed in-contract bugs, 12 encoded carriers (1 percent-encoded, 11
base64/hex), 5 fragments, 4 unsupported (three HAR cases and one
Terraform state output), 1 contract pin = 24 base
cases. 0 left open.

### The two fixes

- **`${NAME:?message}`.** A name that directly follows `${`, the `:` of the
  `:?` modifier and the text after `?` are not an assignment
  (`is_parameter_expansion_message`). In Compose and POSIX shell the text is the
  error shown when the variable is unset. `${NAME:-default}` is not matched: a
  default is a literal a person can put a credential into, and the
  `default-literal` evidence case requires it to stay reported. FN cost: a
  secret written as the error message of its own required variable.
- **Self reference.** `is_self_reference` returns no finding when the value
  normalizes (`normalize_name`) to the assigned name: `aws_secret_access_key =
  aws_secret_access_key`, `{"awsSecretAccessKey": aws_secret_access_key}`.
  Another identifier (`other_secret_access_key`) and the name with material
  glued to it are still reported, as under the #948 policy. FN cost: none, since
  no issued secret is the name of its own variable. `password = password` and
  `client_secret = client_secret` were already clean; this makes the long
  provider-named names consistent with them.

### Why the others are not fixed

- **Percent-encoded delimiter.** All detectors require a non-alphanumeric byte
  before a token. A `%22`, `%3D` or `%2F` ends in a hex digit, so a token behind
  one is missed for every family, not only SendGrid (measured with `ghp_`, `sk-ant-`,
  `AKIA` and `SG.`). Treating `%XX` as a boundary is percent decoding by another
  name, and the reopening bar of `decision-defer-encoded-input-decoding`
  (per-encoding evidence, a false-positive corpus, span model) applies. The same
  key behind a raw `"` or `=` in the query or in an escaped JSON string is claimed
  exactly (pinned).
- **JSON pairs and parent-keyed objects.** The only sibling pairing is the
  YAML `env` item of #1016, on adjacent lines. A HAR, Postman or Terraform-state
  reader needs a JSON structure model the core does not have; reading
  `"name"`/`"value"` generically would claim every form field, header list and
  cookie jar. A proposal names one grammar and brings, before code, its
  documentation (HAR 1.2 `name`/`value`, Terraform state `outputs.<n>.value`
  with `sensitive`), the span to keep valid, a benign corpus (HAR form fields and
  headers are mostly non-secret), and incremental-retention bounds. The
  one-member form `"access_token": "..."` is claimed today, so a name/value
  pair is a documented FN, not an unprotected format.
- **Session cookie.** The #1203 record already declares no session-cookie
  family.
- **Escaped line break after a mask.** `decision-defer-encoded-input-decoding`
  excludes backslash-escape decoding, and the fragment record names escaped
  newline text. The unquoted value therefore runs to the closing quote, and a
  value of `****...\n` is not a mask. The finding is `medium`, so the default
  policy warns and leaves the text unchanged; no secret reaches the output as a
  result. The same boundary has a larger consequence worth recording: in a
  JSON-escaped multi-line string a credential assigned right after `\n` follows
  the letter `n`, which is not a prefix boundary, so `user=bob\npassword=<value>`
  inside one JSON string is not read, and a value followed by `\n` extends over
  the following text. Both are the same out-of-contract carrier and are
  unchanged here; a proposal to read escaped line breaks is a new decision under
  the #491 reopening criteria, not a fix.

### Evidence handoff

The product does not edit credential-evidence. The corrections are listed in
#1205 with case ids and proposed changes. The principle: an expectation that
needs percent decoding, base64 or hex decoding, fragment reconstruction, or a
JSON structure reader is not assertable on the raw-input contract and belongs as
`review-required` or an expected rejection, not as a `redact` expectation on a
product that declares none of those families.

## Consequences

`docs/specs/engine.md` gains one row citing this record;
`docs/specs/contextual-detection.md` gains the two exclusion rows. CHANGELOG
records the two fixes and the scope under Unreleased. No public interface
changes, no version change, and no release is made by this record. The pins in
the test file make a later reopening a visible change: a carrier added for any
row above must turn its `assert_clean` into a positive in the same change.
