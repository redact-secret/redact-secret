# Residual detection-assurance evidence gaps

The five historical evidence-dimension backlog IDs formerly reported as
`pending` by
[`docs/coverage/coverage-declarations.json`](../coverage/coverage-declarations.json), routed here by
[the detection-assurance closeout audit](./detection-assurance-closeout-audit.md)
under issue #118 and reconciled to their current follow-up issues by
[#185](https://github.com/redact-secret/redact-secret/issues/185).

- **Recorded on:** 2026-09-10, at `e8bf910`.
- **Historical tracker:** [#136](https://github.com/redact-secret/redact-secret/issues/136),
  which has no parent by design and is closed as a tracking-artifact closeout.
- **Resolved owners:** [#186](https://github.com/redact-secret/redact-secret/issues/186),
  [#187](https://github.com/redact-secret/redact-secret/issues/187),
  [#188](https://github.com/redact-secret/redact-secret/issues/188), and
  [#189](https://github.com/redact-secret/redact-secret/issues/189), and
  [#190](https://github.com/redact-secret/redact-secret/issues/190).
- **Status:** all five historical gaps are resolved. They remain deliberately outside Epic #95's tree. **Nothing in
  this document blocks Epic #95's closeout.**
- **Authority:** this document records deferred evidence gaps. It does not
  authorize implementation changes or any release operation.

## Why these are deferred and not blocking

Each entry is an honestly-labeled `pending` dimension cell under
[`evidence-requirements.md`](../coverage/evidence-requirements.md)'s bounded
exception rule (§5): a dimension that is genuinely required, currently
unmet, and tracked with an owning backlog item — an honest gap, not an
invented pass. None is a detector regression, a false negative against
currently declared corpus evidence, or a security-boundary violation; each
is missing *breadth* evidence for a dimension whose *depth* evidence (a
positive match, its boundaries, its malformed-input survival, its
adversarial caps) already exists and passes for that row.

`docs/coverage/coverage-report.md`'s own generator originally computed these 5 backlog
IDs from the corpus and declarations at the revision above — this document
does not introduce a new gap, it gives the already-declared `backlogId` slugs
a narrative, an exit condition, and an owner. Current declarations report no
remaining backlog IDs or pending cells. The former five structural
`host-context` cells now resolve `supported` from one class-level
`connection_string_password` representative, and `bearer_token.overlap` now
resolves `supported` from its dedicated competing-candidate fixture. The new
independent nested-assignment fixtures likewise resolve
`contextual_secret.overlap` and `authorization_credential.overlap` without
borrowing evidence between the sibling finding types. Finally,
`authorization_credential.host-context` resolves from five positive fixtures
owned by that type, one in each representative lexical class.

## Current reconciliation

| Backlog ID | Historical tracker | Current owner | Current pending cell(s) | Exit evidence |
|---|---|---|---|---|
| `structural-host-context-breadth` | #136 | [#186](https://github.com/redact-secret/redact-secret/issues/186) | **Resolved:** no pending cells | `connection_string_password` supplies positive `dotenv`, `shell`, `javascript`, `log`, and `markdown` fixtures in the [canonical corpus](../../conformance/fixtures/synchronous-corpus.json). The [generator regression](../../scripts/tests/test_generate_coverage_declarations.py) proves the representative and all four `owned-elsewhere` resolutions; the regenerated [declarations](../coverage/coverage-declarations.json) and [report](../coverage/coverage-report.md) are validated by `npm run coverage:check`, and the canonical detector result is validated by `cargo test -p redact-secret --test canonical_corpus scan_matches_the_canonical_synchronous_corpus`. |
| `bearer-token-overlap` | #136 | [#187](https://github.com/redact-secret/redact-secret/issues/187) | **Resolved:** no pending cells | The [canonical overlap fixture](../../conformance/fixtures/synchronous-corpus.json) pins the winning `bearer_token` metadata and byte range. The [candidate-contention regression](../../crates/secret-scan-core/src/detectors/mod.rs) proves both built-in detectors emit overlapping candidates, while the [policy/redaction regression](../../crates/secret-scan-core/tests/detectors_conformance.rs) pins the default redaction outcome. The regenerated [declarations](../coverage/coverage-declarations.json) and [report](../coverage/coverage-report.md) are validated by `npm run coverage:check`, and the canonical result is validated by `cargo test -p redact-secret --test canonical_corpus scan_matches_the_canonical_synchronous_corpus`. |
| `contextual-secret-overlap` | #136 | [#188](https://github.com/redact-secret/redact-secret/issues/188) | **Resolved:** no pending cells | The independent [canonical overlap fixture](../../conformance/fixtures/synchronous-corpus.json) pins the winning `contextual_secret` metadata and byte range without borrowing its sibling finding type. The [candidate-contention regression](../../crates/secret-scan-core/src/detectors/generic_token.rs) proves two contextual candidates overlap, while the [policy/redaction regression](../../crates/secret-scan-core/tests/detectors_conformance.rs) pins the span-width tie breaker and default redaction outcome. The regenerated [declarations](../coverage/coverage-declarations.json) and [report](../coverage/coverage-report.md) are validated by `npm run coverage:check`, and the canonical result is validated by `cargo test -p redact-secret --test canonical_corpus scan_matches_the_canonical_synchronous_corpus`. |
| `authorization-credential-overlap` | #136 | [#189](https://github.com/redact-secret/redact-secret/issues/189) | **Resolved:** no pending cells | The dedicated [canonical Token overlap fixture](../../conformance/fixtures/synchronous-corpus.json) pins the winning `authorization_credential` metadata and byte range without borrowing `contextual_secret` evidence. The [candidate-contention regression](../../crates/secret-scan-core/src/detectors/generic_token.rs) proves the structural authorization candidate overlaps a nested contextual assignment candidate, while the [policy/redaction regression](../../crates/secret-scan-core/tests/detectors_conformance.rs) pins specificity precedence and the default redaction outcome. The regenerated [declarations](../coverage/coverage-declarations.json) and [report](../coverage/coverage-report.md) are validated by `npm run coverage:check`, and the canonical result is validated by `cargo test -p redact-secret --test canonical_corpus scan_matches_the_canonical_synchronous_corpus`. |
| `authorization-credential-host-context-breadth` | #136 | [#190](https://github.com/redact-secret/redact-secret/issues/190) | **Resolved:** no pending cells | `authorization_credential` supplies positive `dotenv`, `shell`, `javascript`, `log`, and `markdown` fixtures in the [canonical corpus](../../conformance/fixtures/synchronous-corpus.json), one in each representative lexical class. The [generator regression](../../scripts/tests/test_generate_coverage_declarations.py) proves the evidence belongs to `authorization_credential` itself; the regenerated [declarations](../coverage/coverage-declarations.json) and [report](../coverage/coverage-report.md) are validated by `npm run coverage:check`, and the canonical detector results are validated by `cargo test -p redact-secret --test canonical_corpus scan_matches_the_canonical_synchronous_corpus`. |

## Backlog

| ID | Class | Row(s) / dimension | Finding | Exit condition |
|---|---|---|---|---|
| `structural-host-context-breadth` | `resolved-evidence-gap` | `private_key`, `jwt`, `bearer_token`, `connection_string_password`, `otpauth_secret` — `host-context` (class-level) | Resolved by #186: `connection_string_password` now carries supported positive evidence across all five representative lexical classes. | Demonstrated by the linked corpus fixtures, generator regression, generated declarations/report, coverage check, and canonical Rust conformance test in the reconciliation table above. |
| `bearer-token-overlap` | `resolved-evidence-gap` | `bearer_token` — `overlap` | Resolved by #187: the structural Bearer candidate now contends with a wider contextual assignment candidate, wins on specificity, and is redacted under the default policy. | Demonstrated by the linked canonical fixture, direct candidate-contention regression, policy/redaction regression, generated declarations/report, coverage check, and canonical Rust conformance test in the reconciliation table above. |
| `contextual-secret-overlap` | `resolved-evidence-gap` | `contextual_secret` — `overlap` | Resolved by #188: two `contextual_secret` candidates from nested assignments overlap, the narrower candidate wins on span width, and the default policy redacts the winning range. | Demonstrated by the linked canonical fixture, direct candidate-contention regression, policy/redaction regression, generated declarations/report, coverage check, and canonical Rust conformance test in the reconciliation table above. |
| `authorization-credential-overlap` | `resolved-evidence-gap` | `authorization_credential` — `overlap` | Resolved by #189: a structural Token authorization candidate contends with a nested contextual assignment candidate, wins on specificity, and is redacted under the default policy. | Demonstrated by the linked canonical fixture, direct candidate-contention regression, policy/redaction regression, generated declarations/report, coverage check, and canonical Rust conformance test in the reconciliation table above. |
| `authorization-credential-host-context-breadth` | `resolved-evidence-gap` | `authorization_credential` — `host-context` (type-level) | Resolved by #190: `authorization_credential` now carries its own positive evidence across all five representative lexical classes, without borrowing `contextual_secret` evidence. | Demonstrated by the linked corpus fixtures, generator regression, generated declarations/report, coverage check, and canonical Rust conformance test in the reconciliation table above. |

## Sequencing notes

- `authorization-credential-overlap` and `authorization-credential-host-context-breadth`
  were independent gaps on the same row; resolving the former does not alter
  the latter's pending status or exit condition.
- `structural-host-context-breadth` closed once on
  `connection_string_password`; no redundant fixtures were added for the
  other four structural types.
- None of these five historical entries was a prerequisite for another; each
  was closed independently with type- or class-owned evidence as required.

## Not in scope

The exit conditions above describe fixture-level corpus additions only.
Filing new fixtures does not itself authorize a version, tag, release,
publication, deployment, or archival — those remain out of scope for this
document, the historical tracker #136, and the current owner issues, exactly
as they are for Epic #95.

## Plaintext safety

No entry above reproduces a matched value, a fixture input, or a
credential-shaped string. Detector ids, finding types, dimension names,
representative-context names, and byte-range vocabulary are safe metadata.
