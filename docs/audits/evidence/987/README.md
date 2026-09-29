# Evidence: #987, per-candidate and per-finding string allocations

**Result: not worth doing.** The allocations the revised scope would remove
cost at most about 1.4% of scan time on the densest finding-bearing
workload, and 0.2% to 0.9% on the others. That is under the roughly 2%
threshold the research comment on #987 set for going ahead, so no product
code changes. Scans that produce no findings never reach these allocations.

Issue [#987](https://github.com/redact-secret/redact-secret/issues/987),
parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
Harness: [#981](../981/README.md) (`benches/scan_cost.rs`).

## What the revised scope would remove

The research comment scoped the change to the `type_name` and `detector`
strings. The finding id, `signals`, and every other allocation stay as they
are. Measured on the integrated code, these strings come from two places:

- `Candidate::new` copies `type_name` once per candidate.
- `DetectedFinding::new` copies `type_name` and `detector` once per finding
  it builds. The whole-input path builds each finding once. The incremental
  path builds it three times: the pipeline result, then the global rebuild
  and the local rebuild in `IncrementalSanitizer`.

That comes to 3 allocations per finding on the whole path and 7 on the
incremental path.

## Method

Everything ran on `beta11/980-perf` at `acd2af68`, with #981, #982, #983,
#984, #985, #986 and #989 integrated. Host: Apple M4 (arm64), rustc 1.98.1,
`bench` profile. The host is shared, so every comparison ran interleaved,
with several rounds per variant.

1. **Counting the allocations.** A throwaway example, never committed,
   installed a counting `#[global_allocator]` and ran one `scan_and_redact`
   and one `IncrementalSanitizer` session (64 KiB chunks, the CLI limits)
   per harness workload. A second build added exactly one extra copy at
   each in-scope site: one more `type_name` clone in `Candidate::new`, and
   one more `type_name` clone plus one more `detector` clone in
   `DetectedFinding::new`. The difference between the two builds' counts is
   the number of in-scope allocations. It matches 3 per finding (whole) and
   7 per finding (incremental) exactly.
2. **Cost per allocation.** On the same host, `String::from` on a
   12 to 17 byte identifier followed by a drop costs 19.1 to 20.0 ns, over
   5 × 20 M iterations.
3. **Checking the cost in situ.** Three `scan_cost` binaries: A is the
   unchanged code, B has one extra copy per site (twice the in-scope
   allocations), and C has two (three times as many). They ran interleaved
   with `--no-detectors`: 10 rounds of 51 runs each on the 64 KiB
   workloads, and 4 rounds of 15 runs each on `mixed-10m`. The table uses
   the median of each round's median.

## Numbers

In-scope allocations per scan, with the cost estimated at 19.5 ns each:

| Workload | Path | Findings | All allocations | In scope | A median | Estimated share |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| mixed-10m | whole | 10,239 | 176,534 | 30,717 | 335.1 ms | 0.18% |
| mixed-10m | incremental | 10,239 | 2,526,249 | 71,673 | 453.9 ms | 0.31% |
| provider-tables-64k | whole | 112 | 4,618 | 336 | 2.222 ms | 0.29% |
| provider-tables-64k | incremental | 112 | 19,938 | 784 | 3.093 ms | 0.49% |
| unicode-invisible-64k | whole | 269 | 1,721 | 807 | 1.778 ms | 0.89% |
| unicode-invisible-64k | incremental | 269 | 19,015 | 1,885 | 2.560 ms | 1.44% |

The `scale-logs` and `open-assignment-whitespace` workloads have no
findings and no in-scope allocations. The two `minified-json` workloads
(41 and 162 findings) come to 0.1% whole and 0.3% incremental.

Interleaved timings, as paired medians:

| Workload | Path | B − A | C − A | C − B |
| --- | --- | ---: | ---: | ---: |
| mixed-10m | whole | +0.75% | +0.41% | −0.24% |
| mixed-10m | incremental | +1.30% | +1.34% | −0.03% |
| provider-tables-64k | whole | +1.42% | +1.12% | −0.03% |
| provider-tables-64k | incremental | +2.07% | +2.16% | +0.16% |
| unicode-invisible-64k | whole | +0.77% | +1.44% | +0.34% |
| unicode-invisible-64k | incremental | +2.65% | +2.70% | +0.94% |

C − B adds one more full set of in-scope allocations, and it measures −0.2%
to +0.9%. That is the same range as the estimate. B − A is larger, but
C − A is no larger than B − A. If B − A were caused by allocation, adding a
second set of allocations would have raised C − A further. So most of
B − A comes from the injected build itself, for example changes to
inlining and code layout in `Candidate::new`, and not from the allocations.
A first, shorter A/B pass showed the same thing: `provider-tables-64k`
whole moved +2.2% for 336 allocations, which would mean 143 ns per
allocation. That is seven times the cost measured in isolation.

## Caveats

- `unicode-invisible-64k` has one finding per 244 bytes. It was built as a
  stress case, so its 1.4% sits at the high end of the range. Real input
  with fewer secrets moves toward the `mixed-10m` figures (0.2% to 0.3%).
- The allocator is slower in WebAssembly (`dlmalloc`), but so is the rest
  of the scan. These numbers do not measure that ratio. None of the latency
  rows in the benchmarks repository produce findings (`scale-logs`), so
  none of them would move.
- The revised scope would also have made `RegisteredDetector::id` a static
  string. That copy is made once per registry build, not per candidate, so
  it is not counted here.

## Decision

Following the research comment's rule (under about 2%, close as not worth
it), #987 is closed without a code change. `Candidate`, `DetectedFinding`
and `RegisteredDetector` keep their `String` storage, which also avoids the
churn at 68 `Candidate::new` call sites and the textual conflict with #984
in `generic_token.rs`. If a future profile of finding-dense input puts
these allocations above 2%, the research comment's scope still applies
unchanged: `Cow<'static, str>` storage, the unchanged `impl Into<String>`
constructors and `&str` accessors, and no `OnceCell`.
