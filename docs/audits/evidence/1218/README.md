# Evidence: #1218, policy control after overlap arbitration

**Result:** a user policy is evaluated only on finalized findings, in whole-input
scans and in incremental sessions at every tested partition. A rule for the type
that lost an overlap never runs, and the winner takes the user policy's action
for the winner's type, even when the loser's type would have received a stricter
action. No arbitration behavior changed. Option C (candidate inspection) is
deferred.

Issue [#1218](https://github.com/redact-secret/redact-secret/issues/1218),
under epic #1216. The rule is the #1218 row of
[`engine.md`](../../../specs/engine.md); the decision is the
[applies-to-user-policy section](../../../decisions/2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md#applies-to-user-policy-1218)
of the accepted overlap-precedence ADR. Measured on `main` at `db0e5c8d` plus
this change. Every fixture is synthetic.

## Matrix

Synthetic detectors, winner `High` confidence (default `redact`), loser
`Medium` confidence but `Provider` specificity (default `warn`). Policies:
winner allow or warn with loser block or redact, and the inverse. Both
registration orders. All rows give the same result: one finding, the winner's
type and range, the user policy's action for the winner, one policy call
`(winner, index 0, count 1)`, no call for the loser.

| Shape | Winner span | Loser span |
| --- | --- | --- |
| equal range | whole anchor | whole anchor |
| winner contains loser | whole anchor | inner span |
| loser contains winner | inner span | whole anchor |
| partial overlap, winner first | bytes 0..20 | bytes 10..32 |
| partial overlap, loser first | bytes 10..32 | bytes 0..20 |

Built-in shape: `bearer_token` over `new_relic_license_key`, whole input and
incremental (every byte split into two chunks, one character per chunk, and
two repeated clusters with every split plus a three-way split). Each run
matched the whole-input text and findings, and the policy was called once per
winner with indexes 0 and 1 in finalized order.

## Behavior recorded from the runs

- **Callback ordering:** finalized order, one call per finding; the whole-input
  context carries the finalized count, the incremental one only the index.
- **Callback failure:** an error returned for the loser type is never observed;
  an error for the winner type yields `PolicyFailure` and an incremental
  session in `Failed` state.
- **Input bounds:** the finding limit counts finalized findings, not
  candidates, and is checked before any policy call (two overlapping
  candidates fit a limit of one finding; two clusters fail with
  `FindingLimitExceeded` and no policy call).
- **Scope limit:** with the winner allowed and the loser blocked, the text is
  returned unchanged. With the winner blocked, only the winner's range is
  replaced; loser-only bytes outside it remain in the output.
- **Workaround:** a registry holding only the loser detector reports the loser
  and applies its policy rule; the full registry still reports only the winner.

## Commands run

| Command | Result |
| --- | --- |
| `cargo test --test policy_after_overlap_1218` (in `crates/secret-scan-core`) | 12 passed, 0 failed |
| Same test with the severity key in `pipeline.rs` forced to 0 (mutation, reverted) | 10 of the 11 tests then present failed |
| `cargo test --test overlap_resolution --test incremental_partitions --test incremental --test detectors_conformance` | 9, 14, 48 and 14 passed, 0 failed |
| `cargo test --lib pipeline` (DP oracle and component-split tests) | 24 passed, 0 failed |
| `cargo test --locked -p redact-secret` | 77 suites, 2667 passed, 0 failed |
| `cargo clippy --locked -p redact-secret --all-targets -- -D warnings` | finished, no error |
| `cargo fmt --all --check` | clean |
| `npm run decisions:validate` | 0 errors; the extended ADR now exceeds the 12000-byte guideline (warning) |
| `npm run decisions-index:check`, `doc-links:check`, `docs-reachability:check` | OK |

The DP oracle tests in `src/pipeline.rs` and the existing partition tests were
run and pass; they are unchanged.

## Tests added

`crates/secret-scan-core/tests/policy_after_overlap_1218.rs`.
