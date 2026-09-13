# Beta.2 final code review

[Documentation home](../README.md) · [Release runbook](../releasing.md) · [Audit archive](README.md)

- Reviewed on: 2026-09-13.
- Source: `e77ceaf1d885c1b6f311142974cb8502d0d78d5a`, clean `main` at review start.
- Local environment: macOS arm64, Node 22.16.0, Python 3.14.7.
- Verdict: **fix or explicitly disposition the findings below before release
  approval**. Existing automated checks pass; they do not cover these failures.

This review covers core pipeline/redaction and incremental retention, host input
validation, JavaScript byte-stream adapters, Python binding failure handling,
release/recovery state transitions, qualification evidence, and current-facing
documentation. It is a risk-focused review, not proof that every source line or
every possible credential grammar is correct.

## Findings

| Priority | Issue | Confirmed behavior |
| --- | --- | --- |
| P1 | [#234: invalid incremental input cleanup](https://github.com/redact-secret/redact-secret/issues/234) | JavaScript and Python reject invalid input before the core sees the error. Previously retained input survives; the session remains `accepting` and can emit it on finalization. |
| P1 | [#237: partial PyPI recovery](https://github.com/redact-secret/redact-secret/issues/237) | An existing version with only a matching subset of qualified files fails exact-set verification, before recovery can upload missing wheels/sdist. |
| P2 | [#235: leading BOM preservation](https://github.com/redact-secret/redact-secret/issues/235) | The shared stream decoder removes U+FEFF, changing output and original-input finding offsets relative to whole-input scanning. |
| P2 | [#236: finding accumulation](https://github.com/redact-secret/redact-secret/issues/236) | Argument spread in `findings.push` raises a raw `RangeError` on an accepted chunk with many findings. The shared helper leaves its session accepting. |
| P2 | [#238: unknown registry states](https://github.com/redact-secret/redact-secret/issues/238) | Failed registry queries become `unpublished` in release records; crate/PyPI recovery can also infer absence from non-200 responses. |
| P3 | [#239: stale current-facing prose](https://github.com/redact-secret/redact-secret/issues/239) | Current architecture/workflow comments describe completed assessment and recovery work as absent, and reference obsolete branch/publication state. |

P1 means address before the next release; P2 means a reproducible correctness
or operational defect requiring a fix or explicit disposition; P3 is maintenance
work. Issue bodies contain pinned source links, triggers, and acceptance criteria.
No detector or runtime implementation was changed as part of this audit.

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
| BOM-prefixed synthetic assignment, including splits after BOM byte 1 and 2 | Whole-input finding start 9; stream start 8; output equality false for all four partitions tested. |
| 150,000 short synthetic assignment lines, 5,700,000 bytes | Direct incremental append returned 150,000 findings; shared stream helper raised `RangeError`; owned session remained `accepting`. Total-input limit was 6,000,000 bytes; each line was below the token bound. |
| Two-file synthetic Python inventory, one correctly published file | `verify_pypi` rejected the matching subset. Workflow inspection confirms its HTTP-200 branch stops at this rejection. |
| Exact npm facade state-reporting step, with an offline failing npm stub | Recorded `npm:@redact-secret/core` as `unpublished`, not `unknown`. |

The dense-input probe measures the JavaScript call-argument ceiling, not
throughput. It uses many small independent lines because a huge token would
exercise a different limit. The issue requests a smaller helper-level regression
where possible, plus real-artifact coverage.

The Node probes use a freshly compiled addon. Browser impact follows the shared
wrapper/decoder source; this audit did not reproduce these new cases in all
three browser engines. Those real-artifact regressions remain issue acceptance
criteria. PyPI recovery and registry-error probes use synthetic metadata and
offline stubs, not uploads or live outage simulation.

## Existing verification

Passed locally against the reviewed implementation:

- `npm run ci`: JavaScript build/types and 110 wrapper tests, 34 conformance
  schema tests, 81 assessment tests, integration examples, and repository
  declaration/release/SAST machinery tests.
- `npm run rust:check`: 44 workspace-policy tests and zero policy errors.
- `cargo test --workspace --locked`: 472 tests across 20 suites.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- Fresh Node and Python debug builds used by the probes above.

The reviewed head's [SAST run](https://github.com/redact-secret/redact-secret/actions/runs/34781471881)
was successful when checked. Its
[artifact qualification run](https://github.com/redact-secret/redact-secret/actions/runs/34781471951)
was initially running and was confirmed completed successfully at the final
check, with the exact reviewed `headSha`. This is existing remote qualification
evidence; it does not cover the newly reproduced cases. No new workflow was
dispatched for this audit.

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

The new release runbook consolidates actual procedures, notes current recovery
limitations, and links beta.1 publication evidence. The contribution guide and
documentation navigation now point to it. All six findings were filed as new
issues after checking that no open issue already covered them. No version,
branch, tag, release, package publication, or repository setting was changed.
