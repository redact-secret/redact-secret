# #1168 - Exact IBAN country-length table against artifact size

Product judgement. Final record for
[#1168](https://github.com/redact-secret/redact-secret/issues/1168) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving; the artifact-size
gate does not reject it because the measured size change is within about 0.01%.
Baseline: the #1167 commit on this branch, on `origin/main` `a2b2aa6c` (after
#1149, whose arithmetic this lookup does not touch). All inputs are synthetic
or published documentation IBANs.

## Change (`crates/secret-scan-core/src/pii/pii_iban.rs`)

`COUNTRY_LENGTHS` (89 sorted rows, SWIFT Release 103) stays the single source
of truth. A `const COUNTRY_LENGTH_GRID: [[u8; 26]; 26]` is built from it at
compile time, and `country_length` checks both bytes are `A..=Z` (one
`wrapping_sub` and compare each) and reads the cell; `0` is unregistered, so
lowercase, digits, non-ASCII and absent prefixes still give `None`. Length,
display, checksum and context eligibility are unchanged. No unsafe, dependency,
allocation, or public API change.

## Equivalence

The pre-change binary search is kept in the test module as
`country_length_oracle`. Tests compare the shipped lookup with it over **all
65,536 byte pairs**, assert exactly 89 registered pairs and lowercase/mixed-case
rejection, check every source row lands in its grid cell, that the grid has no
other nonzero cell, and that the grid is 676 bytes. The existing release 103
row tests (sorted, unique, every row accepts exactly its length, `PF`/`FP`/`US`/
`ZZ` unknown) still pass, as do the #1149 arithmetic oracle tests.
`tests/pii_phone_iban_1167_1168.rs` pins whole-input findings for compact and
print forms, the first/last/absent countries, lowercase, fullwidth and
checksum-valid wrong-length neighbours, and checks every two-way split and the
single-character partition of the incremental session reproduce the whole
result, plus dense and sparse inputs at chunk sizes 1, 7, 64 and 4,096.

## Size (the gate)

Measured with the repository's toolchain, before and after
(`size-runs.txt`, one build per side):

| Artifact | raw | gzip -9 | brotli -11 |
|---|---|---|---|
| wasm `full` / `common` (no PII linked) | 0 | 0 | 0 |
| wasm `full-pii` | +61 B (+0.007%) | -188 B | +52 B |
| wasm `common-pii` | +69 B (+0.010%) | -164 B | +47 B |
| native release binary linking PII (example `pii_identity_evaluation`) | -112 B | -325 B | not measured |

The 676-byte grid is paid for by removing the binary-search code and the
267-byte tuple table (the source `const` is only read in const evaluation and
tests, so it is not emitted); net, the wasm PII artifacts grow by well under 0.1
KB and gzip shrinks. Not measured: brotli for the native binary, size with a
post-link optimizer such as `wasm-opt` (the pipeline runs none and none is
installed), the Node/Python native addon artifacts, and layout noise across
rebuilds. Size verdict: no meaningful cost, so no reason to reject.

## Timing

Host: Apple M4 (arm64), rustc stable, release (`lto = "fat"`,
`codegen-units = 1`), a **shared and heavily loaded host** (load average 71 at
the start of run 1, 27 at run 2), benchmark lock held, 41 alternating
old/new/old rounds (A/A control), median, two runs (`raw-stage-runs.txt`).
Harness: `timing-harness.rs.txt`. Absolute times differ between runs because of
load; compare ratios within a run.

| Workload | run 1 | run 2 | A/A |
|---|---|---|---|
| lookup only: GB / first AD / last YE / absent ZZ | -83% to -85% | -86% to -94% | within noise (one -16%) |
| lookup only, mixed 8 | -88% | -93% | +0.3%, -28.9% |
| detection loop, compact dense (valid GB) | +0.0% | -7.1% | +0.2%, -3.5% |
| compact mixed (DE and FR) dense | -1.5% | +0.3% | -0.3%, +1.5% |
| print form dense | -7.2% | +0.0% | -2.0%, +0.9% |
| unknown-country noise (`ZZ`, `US`, `XY`...) | -19.2% | -18.4% | +0.6%, -0.4% |
| bad checksum | +3.1% | +0.3% | +24.5%, +0.2% |
| sparse (prose, one IBAN) | -0.6% | -1.8% | +0.8%, -1.6% |
| caps-sparse (uppercase tokens with digits) | -31.0% | -12.4% | +9.6%, +2.5% |

Reading: the lookup itself is about 85% to 90% faster (an absolute saving of
about 3 ns per candidate on this host), matching the issue's -81.6%. The
whole detection loop barely changes where a candidate is a valid IBAN, because
the checksum dominates (compact/print rows are inside noise); it gains
noticeably where candidates are rejected by country (unknown-country -18% to
-19% in both runs) and on uppercase-token noise (-12% to -31%, noisy). The only
positive figure (bad checksum, +3.1% in run 1) sits next to an A/A of +24.5% in
that row and +0.3% in run 2, so it is noise. The issue's compact -9.3% and print
-12.5% were not reproduced on this host; the sparse row is neutral, as the issue
found. Stage times only: whole-scan benefit was not measured and, since IBAN
extraction is a small part of a scan, should be assumed small.

## Disposition

Adopted. Size cost is effectively zero, the lookup is exact for all 65,536
inputs, and the detector gains on rejected candidates. Behavior-preserving
internals: no consumer-observable change, so no `CHANGELOG.md` entry (needs the
`no-changelog` label). Native/WASM budget qualification belongs to #1068.

## Temporary in-repo measurement

No measurement file was added to `src/` or `examples/`. The timing harness was
compiled only temporarily in a working copy (appended to `pii_iban.rs`) and is
kept as inert text under `docs/audits/evidence/1168/`:

- `timing-harness.rs.txt`: the alternating old/new/A-A harness; moves to the
  measurement engine before the beta.13 release per #1152 (tracked cross-repo
  as `redact-secret-benchmarks#608`).
- `raw-stage-runs.txt`, `size-runs.txt`: raw timing and size numbers.

Size was measured by running the existing `scripts/measure-wasm-profiles.mjs
--guard-only` (unchanged) and by building an existing example; no tooling was
modified. `examples/alloc_attribution.rs` was not used or changed.
