# #1161 - single-pass connection-password fill-in prose classification

Product judgement. Final record for
[#1161](https://github.com/redact-secret/redact-secret/issues/1161) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving, low priority.
Baseline: the #1160 commit on the same branch (both issues edit
`detectors/connection_string.rs`, so this was re-baselined onto #1160's
result). All inputs are synthetic.

## Adopt gate

The issue says to preserve the exact lexical predicates, qualify whole
connection-string cost before prioritizing, and allows a measured rejection.
Gate applied: adopt when (a) the old function agrees with the new on every
input in the differential tests, (b) the stage is faster on every workload
including the separator-noise and single-token cases, with an A/A control, and
(c) the whole scan shows no resolvable regression. (a) and (b) hold clearly.
(c) could not be resolved either way on this host (see below), so no whole-scan
gain is claimed and nothing contradicts adoption.

## Change (`is_fill_in_password_prose`)

The `Vec<&str>` of non-empty `_`/`-` tokens is replaced by one iterator pass
that keeps the first token, the last token, a saturating count (only "fewer
than two" matters) and whether any token equals `password`
(case-insensitive). The rules are unchanged: at least two non-empty tokens;
true when the last token is `here` (ASCII case-insensitive); otherwise true when
the first token is `insert`, `replace` or `todo` and some token is `password`.
No new placeholder exemption, so a real password is suppressed in exactly the
same cases as before. No unsafe, no dependency, no public API change.

## Equivalence

The pre-change function is kept in the test module as
`oracle_is_fill_in_password_prose`. Tests compare it with the shipped function
on 49 named shapes (empty, only separators, leading/trailing/doubled
separators, `here` and `HERE` in first/middle/last position, prefixes with and
without `password`, `todo_passwords`, `password_todo`, mixed case, NUL, space,
dot, `e` acute, fullwidth low line, U+FB00, dotted capital I), every
concatenation of up to six pieces from ten atoms (about 1.1 million inputs), 40,000
generated inputs and eleven long inputs (up to 100,000 bytes: long runs of
separators, 50,000 tokens, `here`/`password` at the far end). The existing
`case_insensitive_differential_tests` against a lowercasing implementation
still pass. The function is a pure function of the password text, so
whole-input and incremental partitioning cannot change its result.

## Measurement

Host: Apple M4 (arm64), rustc 1.98.1, release profile (`lto = "fat"`,
`codegen-units = 1`), **a shared host under heavy load (load average 14 to
21)**. Stage harness `timing-harness.rs.txt`, 41 alternating old/new/old
rounds, medians, benchmark lock held, two consecutive runs (`raw-stage.txt`).
Run 1 had A/A within 6%; run 2 landed in a load spike (A/A up to 46%) but gives
the same direction.

| Workload (ns per call) | old (run 1) | new | change | A/A | change (run 2) |
|---|---|---|---|---|---|
| secret-like value (not prose) | 54.85 | 27.27 | -50.3% | +2.6% | -56.8% |
| `your_password_here` forms | 61.17 | 30.91 | -49.5% | -1.3% | -65.5% |
| `REPLACE_ME_PASSWORD` forms | 70.34 | 34.26 | -51.3% | +5.6% | -49.0% |
| single token | 61.92 | 25.21 | -59.3% | -1.9% | -69.9% |
| separator noise | 46.83 | 28.56 | -39.0% | +0.8% | -34.9% |
| 30 tokens | 386.94 | 131.67 | -66.0% | +1.7% | -75.0% |

These are larger than the issue's x86_64 numbers (-10% to -29%); different ISA
and allocator. No row regresses.

Whole scan (`../1160/whole-scan-harness.rs.txt`, built as two release
binaries from baseline and candidate source, 7 rounds base/candidate/base
A/A; summary by `../1160/aggregate.py.txt`, raw in `raw-whole-scan.txt`):
sparse, dense IPv6, dense reg-name, dense placeholder, malformed and prose
noise. Findings counts are identical per case. Round-to-round spread was -70%
to +230% and the A/A control medians moved up to 22%, so **the whole-scan
effect is unresolved and no whole-scan gain is claimed**. The stage saving is
about 25 to 250 ns per classified password, at most roughly 0.1 to 0.5 ms of
an 8 to 11 ms dense scan of 2,000 URLs (1% to 5%); it is a separate stage
number, not a scan claim.

Allocation requests were not counted. Structurally, one Vec allocation per
classified password is removed. Native/WASM qualification belongs to #1068 and
the benchmarks repository.

## Disposition

Adopted. Behavior-preserving internals: no consumer-observable change, so no
`CHANGELOG.md` entry (needs the `no-changelog` label).

## Temporary in-repo measurement

No in-repo measurement file was added or changed for this issue (tracked in
#1152; it moves to the measurement engine before the beta.13 release, see
`redact-secret-benchmarks#608`). Kept as inert `.txt` text, never built by
Cargo and never under `src/`: `timing-harness.rs.txt` (a module appended
temporarily to `detectors/connection_string.rs`; it re-declares the pre-change
function), `raw-stage.txt` and `raw-whole-scan.txt` (raw output), and the
shared `../1160/whole-scan-harness.rs.txt` (temporarily copied to
`crates/secret-scan-core/tests/zz_whole.rs`, removed before commit).
`examples/alloc_attribution.rs` was not used.

**Update (#1152):** the allocation-counting harness `crates/secret-scan-core/examples/alloc_attribution.rs` was removed from this repository, and the allocation counts moved to the separate measurement engine, a package that counts allocations with the third-party `stats_alloc` crate and has no `unsafe` in this repository's crates; it reproduces the #1121 baseline exactly. The inert `*.txt` harness files in this directory stay as history: they are not built or scanned, and they hold the only record of the private-helper timing harnesses. See [`../1152/README.md`](../1152/README.md) for what moved, what was reproduced and what was lost. The original example is recoverable with `git show ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda:crates/secret-scan-core/examples/alloc_attribution.rs`.
