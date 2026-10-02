# #1163 - adaptive PEM delimiter discovery

Product judgement. Final record for
[#1163](https://github.com/redact-secret/redact-secret/issues/1163) (parent
#1068, epic #1065). Baseline: `main` at `a2b2aa6c`. All inputs are
synthetic; no value is printed.

## Verdicts

| part | verdict |
|---|---|
| unconditional exact `-----` substring search (the issue's prototype), shipped `find_literal` | **rejected** (dash noise +92% to +225%, near-miss +70%, zero-body +59%) |
| 64-byte probe, then `find_literal` | **rejected** (same dash-noise regression, +97% and +224%) |
| **8-byte dash-jump probe, then an exact search that reads every fifth byte** | **adopted** (sparse -65%, dense -10% to -55%, dash noise -56% to -73%; one zero-body shape +1% to +2.5%) |

Behavior-preserving; no changelog entry needed (`no-changelog` label).

## Change

`crates/secret-scan-core/src/detectors/private_key.rs` only.

`find_next_delimiter` used to jump from dash to dash and test five bytes at
each. It now asks `next_dash_run(bytes, from)` for the first offset where a
run of five dashes starts, then runs the unchanged label checks there.

- `next_dash_run` walks the first `DELIMITER_PROBE_BYTES` (8) bytes one at a
  time. A delimiter-dense input finds its next delimiter inside that window,
  so it never pays for a search setup.
- A window with no run hands the rest of the input to
  `next_dash_run_strided`, an exact search that reads every fifth byte. Any
  five consecutive bytes contain exactly one sampled offset, so a run of five
  dashes contains a sampled dash; the run is then extended left (never before
  `from`) and right to its full length, and the leftmost start is returned.
  A lone dash or a run of four costs one read per five bytes and a short
  extension, which is why dash noise improves instead of regressing.

It returns the first offset the earlier walk returned, including the
`from` beyond the end, a `from` that is not a UTF-8 boundary, and a run in
the last four bytes. No public API, dependency, `unsafe`, cache or retained
input changed.

## Why not the researched search

The issue's prototype regressed dense input (+42%). On this host the
unconditional exact search regresses a different set of shapes, and the
probe-then-`find_literal` adaptive variant does not fix them, because
`find_literal` tests a lead-byte candidate for every dash it passes:

| workload (in-process, harness baseline) | exact search | 64-byte probe + exact search |
|---|---|---|
| sparse ASCII | -79.6% | -78.6% |
| dense 4-line / long body | -44% / -66% | -38% / -66% |
| zero-length body (END directly followed by BEGIN) | **+59.3%** | +8.0% |
| single-dash noise | **+92.0%** | **+97.4%** |
| four-dash runs | **+224.9%** | **+224.0%** |
| near-miss (`PUBLIC KEY`) | **+70.5%** | -13.9% |
| sparse text with dash noise | **+40.4%** | **+43.6%** |

(`raw-exact-search-variants.txt`; A/A control within +-3% in that run.)
These are in-process numbers against a harness copy of the old detector and
are used only to rank the variants; the adopted code is judged below on the
shipped function.

## Equivalence

Tests in `detectors/private_key.rs`:

- `adaptive_discovery_matches_the_earlier_walks_across_the_probe_window`:
  3,000 generated texts (delimiters, near-miss labels, six-dash runs, lone
  dashes, multibyte text) with gaps below, at and above the probe size, a
  start offset every few bytes including past the end and inside multibyte
  characters; `find_next_delimiter` against the earlier every-byte scan and
  `next_dash_run` against the earlier dash-jump walk.
- `strided_search_matches_the_dash_jump_walk_for_every_run_length_offset_and_start`:
  runs of 1 to 12 dashes at every offset of a 40-byte text from every start,
  covering each phase of the every-fifth-byte sampling.
- `adaptive_discovery_lists_the_same_delimiters_on_sparse_dense_and_noisy_inputs`:
  sparse, dense, dash-noise, near-miss, nested and unterminated inputs of
  tens of kilobytes, whole delimiter lists compared.
- The existing `dash_jumping_delimiter_search_and_trimmed_lookbehind_match_the_oracles`
  and the two `junction_scan_matches_the_whole_join_*` tests drive the
  incremental retention tracker over random and exhaustive chunkings against
  the earlier every-byte scan and the earlier joined-text scan, so the
  chunk-junction and retention behavior, nested and malformed blocks and
  cursor ends are covered through the same function.

## Measurement

Apple M4, macOS arm64, `rustc` 1.98.1, release profile. **The host was
shared and loaded** (load average 3 to 40 across the session). Timing was
serialized behind a lock directory; every run alternated the binaries in
A B B A order over three rounds, and each run is the median of 61 (or 41)
timed batches of 20 ms or more.

The verdict rests on a cross-binary comparison of the shipped
`PrivateKeyDetector::detect`: one release test binary built from
`origin/main`, one from the candidate, plus a control binary built from
`origin/main` with the candidate's functions added and unused, which moves
code addresses the way the candidate does without changing the detector. An
earlier in-process comparison against a harness copy of the old detector
reported +62% on zero-length bodies that the cross-binary comparison does not
show, so in-process numbers are not used for the adoption claim.

Change against the shipped detector, minimum and median over the runs
(`raw-production-ab-final.txt`; control binary against the shipped one in
`raw-production-ab-control.txt`: -0.5% to +0.2% on the minimum in every row):

| workload | median | minimum |
|---|---|---|
| sparse ASCII, 74 KB, one block | -64.7% | -64.7% |
| sparse Unicode, 78 KB | -64.7% | -64.7% |
| sparse text with dash noise | -69.1% | -69.2% |
| dense, 1-line body | -9.8% | -9.7% |
| dense, 4-line body | -36.3% | -36.7% |
| dense, 22-line body | -54.7% | -54.6% |
| near-miss `PUBLIC KEY` blocks | -17.9% | -16.9% |
| single-dash noise | -73.3% | -72.9% |
| four-dash-run noise | -56.9% | -56.2% |
| dense, zero-length body (END directly followed by BEGIN) | -1.7% | +2.5% |

The zero-length-body shape is the only one that does not improve: it is not
a key (no encoded body), the per-delimiter work is about 5 ns, and the
candidate is within +2.5% of the shipped code on the minimum and -1.7% on
the median, against a control band of +-1%. The first version of the probe (an index loop with a separate bounds check,
binary `prod-n2` in `raw-production-ab-final.txt`) was +4.6% median / +6.1%
minimum there; the final form (`rest.get(from..)` and a slice iteration,
binary `prod-n3`) removed most of it.

Allocation was not re-counted: the change adds no allocation.

## Not measured

No whole-scan, native/WASM or released-size claim. The WASM binding runs the
same Rust and was not timed.

## Temporary in-repo measurement

No measurement file remains in the repository tree outside this directory.
The harnesses use `std::time::Instant` and `println!`, which `rust:check`
forbids under `crates/secret-scan-core/src`, so they were appended
temporarily to `crates/secret-scan-core/src/detectors/private_key.rs` and
removed before the commit. Nothing was added to `alloc_attribution.rs`.

- `timing-harness-production-only.rs.txt`: appended to a copy of
  `origin/main`, to the candidate, and to the control to build the three
  binaries (ignored test `measure_1163_production`).
- `timing-harness.rs.txt`: the in-process variant harness (ignored test
  `measure_1163`), latest revision. The `naive` (exact `find_literal`) and
  64-byte-probe rows in `raw-exact-search-variants.txt` came from its
  predecessor, which also carried those two functions.
- `raw-exact-search-variants.txt`, `raw-production-ab-*.txt`: raw runs;
  `summary-production-ab-*.txt` are the same runs reduced to median, 25th
  percentile and minimum against the shipped binary.

Neither harness is part of the build. Per #1152 any measurement code that
stays in the repository moves to the measurement engine before the beta.13
release; cross-repository references to the benchmarks repository are
written `redact-secret-benchmarks#NNN`, for example
`redact-secret-benchmarks#608`.
