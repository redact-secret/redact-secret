# Evidence: #1123, literal deduplication and first-byte jumps in the exact matcher

**Result:** rejected. No runtime change. Literal deduplication removes 2 of 208
comparisons in the full profile and 0 of 7 in common, and its destination
`SlotSet` per literal would roughly double the entry storage. A scalar
first-byte jump showed no difference beyond noise on clean, minified,
prefix-noise and dense early-exhaustion workloads. The rank/popcount directory,
`assert_skip_is_exact` and the substring-oracle tests stay as they are.

Baseline: `44382b3f3006a3a34a2bab917711d00e2e53284a`, `LiteralMatcher` in
`crates/secret-scan-core/src/detectors/prefilter.rs`. Synthetic text only.

## Literal deduplication (change 1)

Counted from the compiled matcher of each built-in profile:

| Profile | Entries | Unique literals | Duplicate entries | Same-slot duplicates | Lead groups | Groups with more than one entry | Largest group |
|---|---:|---:|---:|---:|---:|---:|---:|
| full | 208 | 206 | 2 | 0 | 114 | 34 | 17 |
| common | 7 | 7 | 0 | 0 | 5 | 2 | 2 |

- The comparison saved is at most 2 `starts_with` calls, and only at offsets
  where a duplicated literal's lead occurs and one of its owners is still
  unmatched. The group-level `is_subset_of(&present)` gate already stops a group
  once all its slots are present.
- Storage: an `Entry` is a 16-byte slice plus a `u16` slot, 24 bytes. A
  deduplicated entry needs a destination `SlotSet` (4 x `u64` = 32 bytes), so
  206 x 48 bytes (about 9.9 KB) replaces 208 x 24 bytes (about 5.0 KB). A
  variant that keeps a slot list instead needs an index plus a variable-length
  side table for 2 literals.
- Both variants add compile-time and conservative `MAX_SLOTS` handling for no
  measurable gain, so none was kept.

## First-byte candidate jump (change 2)

Prototype (scalar, exact): a 256-entry first-byte table of the 43 distinct
first bytes in the full profile, tested before the pair-table lookup; the final
byte is excluded as a lead because a literal has at least two bytes. The result
was asserted equal to `present()` on every workload (`SlotSet` equality). The
prototype was a throwaway test in `prefilter.rs`, not committed.

Workloads, 256 KiB each: clean prose; minified JSON; prefix noise (repeated
partial literals such as `gh_`, `AK`, `sk-`, `xo`, never a full literal); dense
early exhaustion (every declared literal first, then prose).

Timing (release test binary, alternating order, 4 runs of 200 iterations,
microseconds per call, best of the 8 samples per cell, with the observed range):

| Workload | A current | B first-byte |
|---|---:|---:|
| clean | 434 (434-1075) | 411 (411-1863) |
| minified | 848 (848-1354) | 763 (763-1696) |
| prefix noise | 3103 (3103-6109) | 3082 (3082-5650) |
| dense early exhaustion | 4.8 (4.8-14.8) | 5.7 (5.7-51.1) |

The machine was shared: load average 47-82 during the runs and the same variant
varied up to 2.5x between consecutive runs, so these are not acceptance numbers.
The best values are within about 10% of each other in both directions and the
ranges overlap completely. The pair-table test is already one load and one bit
test on an 8 KiB table, so a first-byte filter replaces one cheap test with
another and adds a branch. A jump that skips many bytes needs a vectorized
search such as `memchr`, which this issue does not mandate and which a
43-byte first set would not suit (`memchr3` covers three). No dependency was
proposed.

The matcher costs about 0.45 ms per 256 KiB of clean text in the best run, so
even a large relative gain here is bounded by a small share of a whole scan.

## Not measured, and why

- Instruction counts: no counter was available on this macOS host.
- Allocation calls, live memory, initialization: unchanged by construction,
  since no code changed.
- WASM full/common raw and gzip size: unchanged by construction, since no
  runtime source changed; the rejected variants were never linked into an
  artifact.
- Whole and streaming latency: not run; the matcher is the only code the
  prototype touched and it showed no matcher-level gain.

## Reopen criteria

Reopen only with deterministic instruction counts on a quiet host showing a
consistent matcher-only reduction on prefix-noise and minified text, or if the
declared literal population grows enough that duplicate literals or group sizes
stop being negligible.
