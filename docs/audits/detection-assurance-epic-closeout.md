# Detection assurance epic closeout

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#180](https://github.com/redact-secret/redact-secret/issues/180).
- Reviewed on: 2026-09-13.
- Status: **COMPLETED EVIDENCE CLOSEOUT; NO RELEASE AUTHORIZATION.**

This note closes the administrative detection-assurance epic by linking the
current evidence owners, the five historical gap closeouts, and the separate
beta.2 assessment report. It preserves the historical issue record: closed
tracking issues remain closed, and their older observations are not edited into
current-state claims.

## Current evidence ownership

| Evidence area | Owner | Current evidence |
| --- | --- | --- |
| Historical pending detection-evidence reconciliation | [#185](https://github.com/redact-secret/redact-secret/issues/185) | [Residual evidence backlog](detection-assurance-residual-evidence-backlog.md) maps every historical backlog id to its current owner and exit evidence. |
| Structural host-context breadth | [#186](https://github.com/redact-secret/redact-secret/issues/186) | `connection_string_password` supplies the representative structural host-context evidence across all five lexical classes. |
| Bearer overlap resolution | [#187](https://github.com/redact-secret/redact-secret/issues/187) | The dedicated canonical fixture and direct contention regression pin the winning `bearer_token` range and redaction outcome. |
| Contextual-secret overlap resolution | [#188](https://github.com/redact-secret/redact-secret/issues/188) | The independent nested-assignment fixture pins `contextual_secret` overlap without borrowing a sibling finding type. |
| Authorization-credential overlap resolution | [#189](https://github.com/redact-secret/redact-secret/issues/189) | The dedicated Token authorization fixture pins the `authorization_credential` overlap outcome. |
| Authorization-credential host-context breadth | [#190](https://github.com/redact-secret/redact-secret/issues/190) | `authorization_credential` supplies direct positive evidence across the five representative lexical classes. |
| Separate beta.2 detection assessment | [#191](https://github.com/redact-secret/redact-secret/issues/191) | [Beta.2 detection assessment](../../assessment/results/beta.2/README.md) reports the fixed non-conformance corpus, artifact identities, metrics, and mismatch dispositions. |

The generated coverage state has no remaining unresolved rows, unsupported
rows, or pending evidence dimensions: [coverage-report.md](../coverage/coverage-report.md)
reports 25 supported inventory rows, 35 coverage declarations, and "None" for
unresolved finding types, unresolved schemes, and pending evidence dimensions.

## Supported and unsupported scope

Current supported detector evidence is the canonical Rust-core behavior in
`conformance/fixtures/synchronous-corpus.json`, expressed through generated
[coverage declarations](../coverage/coverage-declarations.json) and the
[coverage report](../coverage/coverage-report.md). The coverage work is not an
accuracy score: it proves declared fixture behavior, overlap precedence,
host-context breadth, and range/redaction expectations for the canonical
corpus.

The beta.2 assessment is intentionally separate from conformance. Its corpus
has 9 hand-reviewed fixtures: 3 logs, 2 source-code fixtures, 2 chat fixtures,
and 2 ordinary negative-text fixtures. Six fixtures carry one expected finding
each, and 3 fixtures are expected empty. Results describe only that small
synthetic corpus.

Unsupported or explicitly limited beta.2 shapes are documented rather than
silently relabeled:

- shortened GitHub classic-token shapes remain outside the fixed provider
  grammar;
- shortened AWS access-key-id shapes remain outside the fixed provider
  grammar;
- `seed` remains outside the contextual setting-name allowlists; and
- the Bearer assessment range includes the scheme, while the stable detector
  contract selects and redacts only the credential value.

Those limits do not authorize weaker server enforcement. Browser scanning
remains preventive UX, and server-side scanning remains authoritative.

## Findings and dispositions

All beta.2 Node and browser WebAssembly runs completed the 9-fixture corpus and
produced the same safe mismatch set:

| Runtime | True positives | False negatives | False positives | Incorrect ranges | Policy-correct / evaluable | Negative fixtures with findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Node 22.16.0 | 1 | 5 | 1 | 1 | 1 / 1 | 0 |
| Chromium 153.0.8010.12 | 1 | 5 | 1 | 1 | 1 / 1 | 0 |
| Firefox 155.0 | 1 | 5 | 1 | 1 | 1 / 1 | 0 |
| WebKit 26.6 | 1 | 5 | 1 | 1 | 1 / 1 | 0 |

The false-positive and false-negative counts are against exact detector, type,
and range matching. The Bearer range disagreement contributes one false
positive and one false negative; no expected-empty fixture emitted a finding.

Confirmed detector defects from this assessment: **0**. The dispositions are
documented limitations or a range-contract disagreement, not relabeled product
output. If any unsupported shape becomes a product requirement, the change must
land in the deterministic Rust core with synthetic regression coverage and an
explicit false-positive/false-negative tradeoff.

## Verification evidence

The following committed checks protect this closeout:

- `npm run coverage:check` regenerates and validates the inventory,
  declarations, and report, including the no-pending coverage state.
- `cargo test -p redact-secret --test canonical_corpus scan_matches_the_canonical_synchronous_corpus`
  validates the canonical fixture behavior used by the five gap closeouts.
- `assessment/adapters/beta2-evidence.test.ts` verifies the beta.2 report,
  summary metrics, artifact identities, corpus identities, and safe mismatch
  dispositions.

This issue does not authorize a version change, tag, publication, deployment,
or release. Release authority remains governed by `AGENTS.md`.
