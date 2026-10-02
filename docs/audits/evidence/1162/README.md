# #1162 - glued-placeholder DP on a stack buffer with an exact long-value fallback

Product judgement. Final record for
[#1162](https://github.com/redact-secret/redact-secret/issues/1162) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving. Baseline:
`origin/main` at `a2b2aa6c` (after #1145 to #1149); the issue's pinned baseline
`9c66a706` was requalified against it, and `detectors/text.rs` had not changed
in the function. All inputs are synthetic; no value is printed.

## Change (`crates/secret-scan-core/src/detectors/text.rs`)

`is_glued_instructional_placeholder` lowercased the value into a `String` and
ran its word-split DP on two heap `Vec<bool>`. Now:

- values of at most 256 bytes (`GLUED_PLACEHOLDER_STACK_BOUND`) use borrowed
  ASCII case-insensitive comparisons (`eq_ignore_ascii_case` on the byte
  slices) and two `[bool; 257]` arrays in a separate function
  (`glued_placeholder_split`), so the early rejections never pay for its frame;
- values above 256 bytes call the original implementation, kept verbatim as
  `is_glued_instructional_placeholder_heap`, as the very first step, before any
  validation is duplicated. No accepted length is truncated.

Unchanged: the empty/ASCII-alphabetic gate, lead first-match order, the word
lists and their chain order, the credential-noun condition, the `len > 0`
rule, and every caller. No unsafe, dependency, allocation or public API.

The borrowed compare equals the lowercased-copy compare only while every
listed word has no ASCII uppercase; a test asserts that for all four lists
(digits are fine: `oauth2`).

## Equivalence (tests in `text.rs`, module `glued_placeholder_stack_tests`)

The heap function is the oracle (it is also the production fallback):

- 20,000 seeded random strings and 20,000 `your`-prefixed strings drawn from
  lead, credential, provider, digit, separator, Kelvin-sign and accented
  pieces (the second set must reach more than 100 accepted values);
- named values (empty, lead only, accepted, one-letter-off, separator, mixed
  case, Kelvin sign);
- lengths 240 to 300 for three repeating units, each with 0/1/2 bytes cut, a
  non-word tail, and upper-cased: this spans the 256-byte bound on both sides;
  exact 256 (accepted, stack) and 259 (accepted, fallback) are asserted, and a
  100-unit value ending in a non-ASCII letter is rejected;
- the word-list case invariant above.

The 1,000+ existing generic-token, non-secret-value and incremental tests that
reach the function through the detectors all pass unchanged (full
`cargo test -p redact-secret`).

## Measurement

Host: Apple M-series (arm64) shared and **heavily loaded** (load average 11 to
36 during the runs), release profile (`lto = "fat"`, `codegen-units = 1`),
benchmark lock held, alternating old/new/old (A/A) order reversed each round,
41-round medians. Wall-clock on a loaded host; the A/A column shows how much
to trust a row. Stage times are not whole-scan claims.

Stage (`timing-harness.rs.txt`; `raw-stage-final.txt`, ns per call, final
split build; the first unsplit run `raw-stage-unsplit-first-run.txt` agrees):

| Workload | old | new | change | A/A |
|---|---|---|---|---|
| lead + 29 letters, no split | 4,643 | 2,044 | -56.0% | -4.6% |
| 21 chars, rejected placeholder | 10,524 | 4,830 | -54.1% | +10.0% |
| 20 chars, accepted placeholder | 5,002 | 2,784 | -44.3% | -0.6% |
| 25 chars, ambiguous splits | 9,279 | 5,473 | -41.0% | -12.9% |
| 64 chars, accepted | 26,004 | 12,802 | -50.8% | +1.7% |
| 256 chars (at bound), accepted | 85,035 | 39,375 | -53.7% | +3.3% |
| 304 chars (fallback path) | 95,716 | 98,900 | +3.3% | -5.0% |
| no lead word (22 letters) | 96.9 | 21.2 | -78.1% | -9.7% |
| non-alphabetic (`your_api_key`) | 5.67 | 7.23 | +27.6% | -8.3% |

Absolute values moved about 5x between the two runs because of host load; the
direction of every row repeated. Two honest caveats: the fallback row is
within the A/A spread (first run -0.4%), as the issue found; and the
non-alphabetic early reject is **about 1.5 ns slower in both runs** (5.4 to
6.5 and 5.7 to 7.2). That path does the same checks as before, so this is a
code-layout or inlining effect, a nanosecond on a path that costs far more in
the surrounding detector call.

Whole scan (`whole-scan-harness.rs.txt`, public `scan` with the default
registry; `raw-whole-scan-final.txt`: three alternating rounds forward and
reversed, base, new, and a second base as A/A). 2,000 `NAME=<prefix>_<glued>`
lines of about 45 bytes; the A/A rows are not stable on this host (-8% to
-17% from the second base build alone), so **no whole-scan gain is claimed**:

| Workload | new vs base | A/A |
|---|---|---|
| dense placeholder values | -8.7% (earlier run -37.1%) | -0.2% (-16.5%) |
| dense ambiguous values | -32.6% (-41.7%) | -14.9% (-11.3%) |
| dense alphabetic values | +7.6% (-16.8%) | -8.4% (-15.2%) |
| sparse (1 line in 50) | +8.1% (-15.8%) | +4.7% (-13.5%) |
| 500 long (>256) values | -15.7% (-3.1%) | -12.4% (-1.0%) |
| prose only | -18.5% (+1.4%) | -19.7% (+10.3%) |

Only the ambiguous and placeholder shapes point the same way in both runs; the
rest is noise. The expected benefit is the removal of one `String` and two
`Vec` allocations per candidate that reaches this check (`your...` values after
a vendor prefix).

Not measured: WASM stack use and code size (#1068 and the benchmarks
repository own native/WASM qualification), allocation counts (the existing
`examples/alloc_attribution.rs` was not used), RSS. The two arrays are 514
logical bytes on a path that is only entered for a lead-word match.

## Disposition

Adopted. Behavior-preserving internals: no consumer-observable change, so no
`CHANGELOG.md` entry (needs the `no-changelog` label).

## Temporary in-repo measurement

No measurement file remains in the product tree (tracked in #1152; the
measurement moves to the measurement engine before the beta.13 release, and
`redact-secret-benchmarks#608` is the benchmarks-side reference). Used only
temporarily in the working copy, and kept here as inert `.txt`, never built by
Cargo:

- `timing-harness.rs.txt`: a `#[cfg(test)]` module appended to
  `detectors/text.rs` that times old against new and an A/A control (uses
  `std::time`, which `scripts/check-rust-workspace.py` forbids under `src/`,
  so it was removed before commit);
- `whole-scan-harness.rs.txt`: a temporary integration test
  `tests/zz_whole_scan_1162.rs` using the public `scan`, built once against the
  base and once against the change (also used for #1164);
- raw outputs `raw-*.txt`. `examples/alloc_attribution.rs` was not used or
  changed.
