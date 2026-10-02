# #1166 - Borrow exact built-in PII public type names when constructing Candidates

Product judgement. Final record for
[#1166](https://github.com/redact-secret/redact-secret/issues/1166) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving. Baseline: the
#1165 commit on this branch (`a2b2aa6c` plus #1165). Same pattern as #1145
(`Cow<'static, ...>`, statics, `std::ptr::eq` sharing tests). All inputs are
synthetic.

## Change (`crates/secret-scan-core/src/pii.rs`)

`PiiDomain::detect` built every candidate's type name as an owned `String`
(`public_type(family_id)` formats and replaces characters). It now takes a
`Cow<'static, str>` from `public_type_name`:

- the six built-in family ids (`pii:global:email`, `iban`, `network-address`,
  `payment-card`, `phone`, `pii:us:ssn`) map to six static strings;
- every other id (custom, test-registered such as `pii:global:us-ssn`, known
  but unbuilt, malformed) falls back to the unchanged owned `public_type`;
- the ambiguity name `pii_ambiguous_<domain>` stays owned.

A `Cow::Borrowed` name goes through the existing `pub(crate) Candidate::built_in`
(already used by built-in detectors), an owned one through `Candidate::new`.
The identifier/length validation runs on the same bytes as before. No public
accessor, public constructor, `Candidate` field, serialization of type names,
Rust/Node/WASM/Python binding, dependency or unsafe changed (`Candidate`
already stored `Cow<'static, str>`).

## Equivalence

`public_type` is kept as the oracle (it is also the fallback). Tests:

- for each of the six ids the name is `Cow::Borrowed`, equals `public_type`,
  is a valid identifier within `MAX_IDENTIFIER_LENGTH`, and two lookups return
  the same bytes (`std::ptr::eq`);
- 14 other ids (the two known but unbuilt ids, custom, near misses with case,
  trailing space or extra segments, empty, non-ASCII, malformed) are `Cow::Owned`
  and byte-equal to `public_type`;
- production families detect an email, card, IBAN, SSN and phone text twice:
  every candidate borrows, two detections and a clone share the pointer, and the
  names equal the oracle; the ambiguous join and a custom family id stay owned
  with the same names as before;
- the existing suite compares public findings' type names with `public_type`
  for every production family and runs whole and incremental partitions with
  PII on (`incremental_partition_gaps`, `incremental_batching`, adversarial
  bounds), which would diverge on any type-name change.

## Measurement

Host: Apple M4 (arm64), rustc 1.98.1, release profile, **a shared and heavily
loaded host** (load average 15 to 47 during the runs; the benchmark lock was
held). Different ISA from the issue's x86_64 run.

Stage, `Candidate` construction only (`timing-harness.rs.txt`; 41 alternating
old/new/old rounds, median; A/A is old against old):

| Workload | old ns | new ns | change | A/A |
|---|---:|---:|---:|---:|
| 1 candidate | 301.1 | 59.5 | -80.2% | -1.3% |
| 6 candidates (one per family) | 1,876 | 76.1 | -95.9% | +1.7% |
| 1,000 built-in candidates | 249,005 | 5,003 | -98.0% | -2.5% |
| 1,000 custom-family candidates (owned path) | 176,136 | 179,511 | +1.9% | +2.0% |

The built-in rows are larger than the issue's -82% / -92.7% because the
remaining new cost is only the `Vec` and fixed-size structs; the custom row is
the unchanged owned path, equal to its A/A within noise. Downstream `Finding`
construction still owns its type string, so this is not a whole-scan figure.

Whole scan (`whole-scan-harness.rs.txt`, public `scan` with PII on, base and
new binaries, 3 rounds of alternating base/new/new/base, 61 scans each;
`ab-whole-scan-raw.txt`; sparse = one contextual email in 2,000 prose lines,
dense-email = 2,000 contextual emails, dense-mixed = 1,200 findings of five
families, plus a prose control): median of medians -4.7% to +9.9%, with the
prose control (no candidates) at +3.6%, inside run-to-run spread. The stage
saving is about 0.2 microseconds per candidate against 3 to 4 microseconds per
finding of whole scan. **The whole-scan effect cannot be resolved on this
loaded host and no whole-scan gain is claimed.** Finding counts match between
the two binaries in every row. Native/WASM budget qualification belongs to
#1068 and the benchmarks repository; allocation counts were not instrumented.

## Disposition

Adopted. Behavior-preserving internals: no consumer-observable change, so no
`CHANGELOG.md` entry (needs the `no-changelog` label).

## Temporary in-repo measurement

No in-repo measurement file is left in the tree for this issue (tracked in
#1152; it moves to the measurement engine before the beta.13 release; any
benchmarks-repository reference is written `redact-secret-benchmarks#608`).
The harnesses were compiled only temporarily and are kept as inert `.txt`:
`timing-harness.rs.txt` (a module included into the `pii.rs` test tree),
`whole-scan-harness.rs.txt` (a temporary `tests/zz_whole.rs`, deleted
afterwards; the base binary came from a one-line toggle forcing the owned path)
and `ab-whole-scan-raw.txt`. Neither is built by Cargo, and
`examples/alloc_attribution.rs` was not used.

**Update (#1152):** the allocation-counting harness `crates/secret-scan-core/examples/alloc_attribution.rs` was removed from this repository, and the allocation counts moved to the separate measurement engine, a package that counts allocations with the third-party `stats_alloc` crate and has no `unsafe` in this repository's crates; it reproduces the #1121 baseline exactly. The inert `*.txt` harness files in this directory stay as history: they are not built or scanned, and they hold the only record of the private-helper timing harnesses. See [`../1152/README.md`](../1152/README.md) for what moved, what was reproduced and what was lost. The original example is recoverable with `git show ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda:crates/secret-scan-core/examples/alloc_attribution.rs`.
