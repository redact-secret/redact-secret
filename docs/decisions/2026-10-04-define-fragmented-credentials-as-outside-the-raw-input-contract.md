---
decision_id: decision-define-fragmented-credentials-as-outside-the-raw-input-contract
status: accepted
scope: workspace
title: Define a credential fragmented across lines, literals or continuations as outside the raw-input contract
decided_at: 2026-10-04
spec: engine
---

# Define a credential fragmented across lines, literals or continuations as outside the raw-input contract

## Context

Issues [#1199](https://github.com/redact-secret/redact-secret/issues/1199),
[#1200](https://github.com/redact-secret/redact-secret/issues/1200) and
[#1201](https://github.com/redact-secret/redact-secret/issues/1201) queued the
failures that credential-evidence `snapshot-2026.10.04.3` added to the
`sendgrid-token`, `generic-token` and `connection-string` families (official
replay 37202404479, which scanned `@redact-secret/core@0.1.0-beta.12`).

Reproducing every failing case against the published
`@redact-secret/core@0.1.0-beta.13` and against this repository's `main`
returned the same findings as the replay on all 85 failing base cases. The
failures are not a beta.13 regression.

The 16 SendGrid `line-break-and-fragment-authored--key-*` cases cut one valid
key into pieces by a mechanism with its own runtime meaning:

| Mechanism | Cases | What the bytes mean at runtime |
| --- | --- | --- |
| Literal LF or CRLF in plain text | `key-split-by-literal-line-feed`, `key-split-by-literal-crlf` | a line break inside the token; a human re-joins it |
| Markdown soft break or code-span line ending | `key-wrapped-in-markdown-paragraph`, `key-wrapped-in-markdown-code-span` | a renderer folds the line ending into a space |
| Shell backslash-newline outside quotes or in double quotes | `key-split-by-unquoted-shell-continuation`, `key-split-after-prefix-by-shell-continuation`, `key-split-before-last-character-by-shell-continuation`, `key-split-by-double-quoted-shell-continuation`, `key-split-by-backslash-crlf-continuation` | the shell deletes the backslash and the newline |
| Shell backslash-newline inside single quotes | `key-split-by-backslash-newline-in-single-quotes` | nothing is deleted: the value keeps the backslash and the newline, so it is not the key |
| String-literal line continuation | `key-split-by-javascript-literal-continuation`, `key-split-by-python-literal-continuation` | the language deletes the backslash and the newline when it evaluates the literal |
| String-literal addition or adjacency | `key-split-across-javascript-added-literals`, `key-split-in-three-javascript-added-literals`, `key-split-across-python-adjacent-literals` | the language joins the literals when it evaluates them |
| Literal backslash and `n` in a log line | `key-with-literal-backslash-n-in-log-line` | two characters of escaped text, not a newline |

A SendGrid key is `SG.<22>.<43>` in contiguous bytes. None of the sixteen
inputs contains that run. Each expectation is the enclosing range of the
reconstructed key, which only an evaluator of the carrier's language could
produce.

## Decision

The raw-input contract detects a credential that is contiguous in the input
bytes (after the invisible-character normalization of
`decision-normalize-invisible-characters-before-detection`). A credential cut
into fragments by a line break, a string-literal operator, a shell or
language line continuation, a markdown line ending, or an escaped-newline
text is outside that contract, and the core does not reconstruct it. This
applies to every detector family, not only SendGrid.

The core does not interpret shell quoting, string-literal grammar, markdown
or log escaping, because the meaning of one backslash-newline differs by
carrier (the table above) and a single rule that joins them would wrongly
join the single-quoted case or redact bytes that are not the credential.
Adding an interpreter for any of them is source-language evaluation, which
the issues and `AGENTS.md`'s deterministic-boundary rule keep out of core.

A contextual or generic detector may still redact the contiguous prefix or
suffix of a fragment under a credential name. That output is incidental. It
is not a claim to cover the fragment, and it leaves the other fragments in
the output. Callers that need split-credential coverage scan the
reconstructed value in their own host layer.

Encoded carriers (base64, hex, nested layers) stay governed by
`decision-defer-encoded-input-decoding`, whose reopening criteria are
unchanged. The 13 SendGrid and 34 generic-token
`base64-hex-representation-projections--*` cases under
`ENCODED_VALUE=` and a neutral `payload` key are decoded-carrier cases of the
same kind. A raw encoded run is not a credential-named assignment, so it
claims nothing.

Evidence expectations on these cases are `project-policy` or
`tool-corroborated`. The 22 SendGrid and 34 generic scored cases that are
`maintainer-only` are single-maintainer policy evidence, disclosed as such.
This decision does not rest on them and does not turn them into independent
review.

The support-scope inventory of such out-of-scope inputs is owned by
[redact-secret-benchmarks#622](https://github.com/redact-secret/redact-secret-benchmarks/issues/622).
A benchmark that scores the enclosing range of a fragmented case measures a
scope gap, not a detection miss (credential-eval#34 and credential-evidence#150
track fragment semantics).

### Reopening bar

A proposal to support one mechanism names that mechanism alone, states its
runtime meaning, resolves redaction of the separator bytes (the output must
stay valid for the carrier), bounds the lookahead against the incremental
retention model, and brings a false-positive corpus. The literal line feed
and the markdown soft break need no language semantics and are the first
candidates; shell and string-literal evaluation are not.

## Consequences

`docs/specs/engine.md` gains one row citing this record. No detector,
fixture or public interface changes. `crates/secret-scan-core/tests/evidence_snapshot_2026_10_04_3_1199_1200_1201.rs`
pins the sixteen fragment cases and the encoded cases by evidence id: the
unsplit key in the same carrier is redacted exactly, the fragmented or
encoded form claims no SendGrid finding, and a backslash inside single
quotes is never read as a continuation.

The one in-contract defect found in the three queues,
`generic-connection-grammar-authored--amqp-uri-all-sub-delimiters`, is fixed
separately in `connection_string.rs` and is not covered by this exclusion:
its password is contiguous in the input.
