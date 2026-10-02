# #1165 - Sort and deduplicate PII contextualization keys in one Vec

Product judgement. Final record for
[#1165](https://github.com/redact-secret/redact-secret/issues/1165) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving. Baseline:
`a2b2aa6c` (main after #1159). All inputs are synthetic.

## Change (`crates/secret-scan-core/src/pii.rs`)

`PiiDomain::contextualized` collected the established alternatives'
`(ByteRange, IdentityDomain)` keys into a `BTreeSet` and then drained it into a
`Vec`. The new private `context_candidate_keys` collects them into one `Vec`,
`sort_unstable()`s and `dedup()`s it. Both orders are the derived `Ord` of the
same tuple, so the resulting sequence and distinctness are identical; the
binary-search index into `contexts`, barriers, equidistance, named negatives,
domain association and arbitration are untouched. No unsafe, dependency,
public API or product-visible change.

## Equivalence

The old `BTreeSet` collection is kept in the test module as
`oracle_context_candidate_keys`:

- 400 generated rounds (xorshift32, fixed seed) of 0..=3,000 keys with many
  shared starts/ends across all six domains, in generated and in reversed
  order: shipped helper equals the oracle;
- empty input; every domain duplicated in both orders collapses to six keys.

A mutation check (removing `dedup`) makes both tests fail. The helper is the
only changed code, so the differential is at helper level; the old key
collection is not retained on the product path.

Context matching itself is exercised through the existing `pii` suite (71 pii
tests, including the #902 association oracles) and the whole workspace suite,
which run whole and incremental scans over the same code path.

## Measurement

Host: Apple M4 (arm64), rustc 1.98.1, release profile, **a shared and heavily
loaded host** (load average 10 to 45 during the runs; the benchmark lock was
held, other tenants were not controllable). Different ISA from the issue's
x86_64 run.

Stage, helper only (`timing-harness.rs.txt`; 41 alternating old/new/old
rounds, median; the A/A column is old against old):

| Workload | old ns | new ns | change | A/A |
|---|---:|---:|---:|---:|
| 1 key | 185.0 | 48.6 | -73.7% | -0.4% |
| 3 keys (sparse) | 207.4 | 55.6 | -73.2% | -2.9% |
| 1,000 shuffled mixed-domain keys | 58,855 | 31,625 | -46.3% | +1.6% |
| 3,000 keys, 40 distinct | 80,109 | 49,054 | -38.8% | -3.0% |

The reduction is smaller than the issue's -65% / -87.5% on its x86_64 host;
it has the same sign on every workload.

Whole scan (`whole-scan-harness.rs.txt`, public `scan` with PII on, base and
new binaries, 3 rounds of alternating base/new/new/base, 61 scans each;
`ab-whole-scan-raw.txt`; sparse = 2,000 prose lines with one contextual email,
dense-email = 2,000 contextual emails, dense-mixed = 2,000 lines of email, card,
IBAN, SSN, phone, prose control): median of medians differs between -2.1% and
+6.4% in both directions (min column -4.7% to +1.0%), inside the run-to-run
spread of 2,500 to 5,300 microseconds on the prose control that does not touch
this path. **The whole-scan effect cannot be resolved on this loaded host and
no whole-scan gain is claimed**; the stage saving (tens of microseconds on
1,000 keys) is a small part of a multi-millisecond scan. Native/WASM budget
qualification belongs to #1068 and the benchmarks repository.

## Disposition

Adopted. Behavior-preserving internals: no consumer-observable change, so no
`CHANGELOG.md` entry (needs the `no-changelog` label).

## Temporary in-repo measurement

No in-repo measurement file is left in the tree for this issue (tracked in
#1152; it moves to the measurement engine before the beta.13 release; any
benchmarks-repository reference is written `redact-secret-benchmarks#608`).
The harnesses were compiled only temporarily and are kept as inert `.txt`:
`timing-harness.rs.txt` (a module included into the `pii.rs` test tree, which
re-declares the BTreeSet path), `whole-scan-harness.rs.txt` (a temporary
`tests/zz_whole.rs`, deleted afterwards) and `ab-whole-scan-raw.txt` (raw
output). Neither is built by Cargo, and `examples/alloc_attribution.rs` was not
used.

**Update (#1152):** the allocation-counting harness `crates/secret-scan-core/examples/alloc_attribution.rs` was removed from this repository, and the allocation counts moved to the separate measurement engine, a package that counts allocations with the third-party `stats_alloc` crate and has no `unsafe` in this repository's crates; it reproduces the #1121 baseline exactly. The inert `*.txt` harness files in this directory stay as history: they are not built or scanned, and they hold the only record of the private-helper timing harnesses. See [`../1152/README.md`](../1152/README.md) for what moved, what was reproduced and what was lost. The original example is recoverable with `git show ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda:crates/secret-scan-core/examples/alloc_attribution.rs`.
