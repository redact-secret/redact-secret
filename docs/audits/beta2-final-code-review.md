# Beta.2 final code review

[Documentation home](../README.md) · [Release runbook](../releasing.md) · [Audit archive](README.md)

- Reviewed on: 2026-09-13.
- Source: `41637bd5f434e6c2c4b423a09a9b11162179bcfa`, clean `main` at final review.
- Base refresh: all six findings, #234 through #239, are closed on this base.
- Local environment: macOS arm64, Node 22.16.0, Python 3.14.7.
- Verdict: **ready for `0.1.0-beta.2` candidate preparation**. Publication still
  requires exact-RC qualification, rehearsal, SAST, publisher checks, and the
  separate explicit release approval required by `AGENTS.md`.

This review covers core pipeline/redaction and incremental retention, host input
validation, JavaScript byte-stream adapters, Python binding failure handling,
release/recovery state transitions, qualification evidence, and current-facing
documentation. It is a risk-focused review, not proof that every source line or
every possible credential grammar is correct.

## Findings

| Priority | Issue | Confirmed behavior |
| --- | --- | --- |
| P1 (closed) | [#234: invalid incremental input cleanup](https://github.com/redact-secret/redact-secret/issues/234) | At the reviewed source, JavaScript and Python rejected invalid input before the core saw the error. Closed on the refreshed base. |
| P1 (closed) | [#237: partial PyPI recovery](https://github.com/redact-secret/redact-secret/issues/237) | At the reviewed source, an existing version with only a matching subset of qualified files failed exact-set verification before recovery could upload missing files. Closed on the refreshed base. |
| P2 (closed) | [#235: leading BOM preservation](https://github.com/redact-secret/redact-secret/issues/235) | At the reviewed source, the shared stream decoder removed U+FEFF, changing output and original-input finding offsets relative to whole-input scanning. Closed on the refreshed base. |
| P2 (closed) | [#236: finding accumulation](https://github.com/redact-secret/redact-secret/issues/236) | Shared stream accumulation no longer uses argument spread; helper and installed-artifact regressions cover dense finding sets. |
| P2 (closed) | [#238: unknown registry states](https://github.com/redact-secret/redact-secret/issues/238) | Registry lookup failures remain `unknown` and block release/recovery plans; deterministic tests cover npm, crates.io, and PyPI failures. |
| P3 (closed) | [#239: stale current-facing prose](https://github.com/redact-secret/redact-secret/issues/239) | Current architecture, release documentation, and workflow comments were reconciled with the implemented behavior. |

No finding from this audit remains open. The issue bodies and merged fixes retain
the pinned triggers, acceptance criteria, and regression evidence. Candidate
qualification must still be run from the frozen RC revision.

## Reproduction evidence

The probes are offline and use synthetic input. They print only error codes,
states, sizes, booleans, and safe offsets, never retained text. Build the reviewed
code before running them; an old local binary with the same version is not
evidence for the current source.

```bash
npm run js:build
cargo build -p redact-secret-node -p redact-secret-python --locked
node docs/audits/evidence/beta2-final-review/reproduce.mjs
python3 -B docs/audits/evidence/beta2-final-review/reproduce.py
```

The default extension paths are macOS debug libraries. Each probe accepts its
library path as the first argument for another host. The Python probe requires
PyYAML. Direct library loading isolates the current binding implementation;
it is not a wheel/npm installation qualification.

| Probe | Observed result |
| --- | --- |
| JavaScript append of number/lone surrogate after an ordinary retained marker | `INVALID_INPUT` / `UNPAIRED_SURROGATE`; state `accepting`; finalization re-emitted all 31 prior characters. |
| Python append of number/lone surrogate after the same marker | `InvalidInputError`; state `accepting`; finalization re-emitted the prior marker. |
| BOM-prefixed synthetic assignment, including splits after BOM byte 1 and 2 | At the reviewed source, whole-input finding start 9, stream start 8, and output equality false for all four partitions tested. This is retained as historical reproduction evidence for closed issue #235. |
| 150,000 short synthetic assignment lines, 5,700,000 bytes | Direct incremental append returned 150,000 findings; shared stream helper raised `RangeError`; owned session remained `accepting`. Total-input limit was 6,000,000 bytes; each line was below the token bound. |
| Two-file synthetic Python inventory, one correctly published file | At the reviewed source, `verify_pypi` rejected the matching subset. This is retained as historical reproduction evidence for closed issue #237. |
| Exact npm facade state-reporting step, with an offline failing npm stub | Recorded `npm:@redact-secret/core` as `unpublished`, not `unknown`. |

The dense-input probe measures the JavaScript call-argument ceiling, not
throughput. It uses many small independent lines because a huge token would
exercise a different limit. The issue requests a smaller helper-level regression
where possible, plus real-artifact coverage.

The Node probes use a freshly compiled addon. Browser impact follows the shared
wrapper/decoder source; this audit did not reproduce these new cases in all
three browser engines. Those real-artifact regressions remain issue acceptance
criteria. PyPI recovery and registry-error probes use synthetic metadata and
offline stubs, not uploads or live outage simulation. The BOM, dense-finding,
PyPI recovery, and registry-state defects have since been fixed on the refreshed
base. The probes remain historical reproduction evidence for the reviewed failures.

## Existing verification

Passed locally against the reviewed implementation:

- `npm run ci`: JavaScript build/types and 110 wrapper tests, 34 conformance
  schema tests, 81 assessment tests, integration examples, and repository
  declaration/release/SAST machinery tests.
- `npm run rust:check`: 44 workspace-policy tests and zero policy errors.
- `cargo test --workspace --locked`: 472 tests across 20 suites.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- Fresh Node and Python debug builds used by the probes above.

The final reviewed head's [SAST run](https://github.com/redact-secret/redact-secret/actions/runs/34789837241)
and [artifact qualification run](https://github.com/redact-secret/redact-secret/actions/runs/34789837423)
completed successfully with exact `headSha`
`41637bd5f434e6c2c4b423a09a9b11162179bcfa`. Artifact qualification completed
49 jobs with no failure and includes the installed Node, browser, Python wheel,
native addon, CLI, and inventory lanes. This integration-commit evidence does
not replace qualification and rehearsal of the prepared RC revision.

The full Python installed-wheel suite, browser engine matrix, foreign native
targets, fresh advisory scan, and live publisher permissions were not rerun
locally. Those limits do not invalidate the isolated reproductions and do not
establish final release qualification either.

## Incomplete work and prose quality

An exhaustive search of indexed source for `TODO`, `FIXME`, `todo!`, and
`unimplemented!` did not reveal an unfinished production stub. Error throws in
test doubles and qualifier assertions were not counted as unfinished work.
This does not prove the absence of incomplete behavior: the failures above
show why acceptance checks matter more than placeholder searches.

No attempt was made to infer AI authorship from style. The actionable prose
findings are contradictions: completed assessment runners described as future
work, implemented multi-registry recovery described as absent, and outdated
publication/ancestry statements. Historical dated audits remain historical.
Hashing the beta.1 candidate review is not a beta.2 API sign-off.

The release runbook consolidates the current procedures and links beta.1
publication evidence. All six findings are closed on the final reviewed base.
Version `0.1.0-beta.2` is approved for candidate preparation only; this review
does not authorize publication, tagging, deployment, or release reconciliation.
