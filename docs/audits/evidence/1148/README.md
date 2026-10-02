# #1148 - Luhn contribution-table arithmetic

Product judgement. Final record for
[#1148](https://github.com/redact-secret/redact-secret/issues/1148) (parent
#1068, epic #1065). Verdict: **rejected, no code change.** The issue's
conditional adopt gate (no regression on late-malformed input and a meaningful
whole-path benefit) is not met by any variant. All inputs are synthetic
well-known test PANs; no value is printed by the harness beyond timings.

## Question

`validate_luhn_v1` makes an all-digits pass and then a branchy doubling /
subtract-nine sum. The issue's prototype fuses the digit check into the sum and
replaces the branch with a 10-entry doubled-contribution table. The research
log reported -5.2% on a 16-digit PAN, but +54% on late-malformed input, in an
isolated stage on Linux x86_64.

## Method

Stage harness `timing-harness.rs.txt` (a temporary `#[cfg(test)]` module
appended to `structured_validators.rs`, release profile with `lto = "fat"`,
`codegen-units = 1`; it must never live under `src/`, which forbids
`std::time`). Four variants in one binary: `base` (shipped), `pre_table`
(lexical pre-pass kept, table contribution), `fused` (the issue's prototype,
early return on the first non-digit), `fused_acc` (fused, branch-free validity
accumulation). 31 rounds, median of per-round ns/call, variants alternated and
the order reversed on odd rounds, plus an A/A control that runs `base` in an
extra slot. Whole path: `whole-scan-harness.rs.txt` (an integration test
using the public `scan` with PII on) over 2,000 lines of text.

Host: Apple M4 (arm64), rustc 1.98.1, **a shared host that was not otherwise
idle**, so absolute numbers are approximate; the A/A control stayed within
0.2% in every row, which bounds the layout/noise effect for this run only.
This is a different ISA from the issue's x86_64 Xeon run, so the signs below
are evidence about this target, not a refutation of the research numbers.

## Stage results (ns per call, change vs `base`)

| Workload | base | pre_table | fused | fused_acc |
|---|---|---|---|---|
| 16-digit valid | 12.6 | +41.6% | +10.1% | -1.8% |
| 16-digit bad checksum | 12.5 | +42.4% | +10.3% | -2.3% |
| 19-digit valid | 17.4 | +17.1% | -6.8% | -18.3% |
| early-malformed | 1.55 | +0.7% | +37.1% | +662% |
| late-malformed | 8.9 | -4.7% | +48.5% | +32.1% |

## Why it is rejected

- The shapes the detector actually produces (16-digit) do not improve: the
  prototype is +10% slower here and the only variant near parity is the
  branch-free one, which turns an early-malformed call from 1.6 ns into 11.8
  ns. Only the 19-digit case, which is a tail shape, improves.
- Keeping the lexical pre-pass (the "table only" idea in the issue) removes the
  late-malformed regression but is +17% to +42% slower on valid digits on this
  target, so there is no variant with both properties.
- Whole path (`whole-scan-harness.rs.txt`, same host): a 120 kB text with 2,000
  supported test PANs scans in about 4.4 ms. At 12.6 ns per Luhn call the
  validator is about 25 microseconds of that, 0.6%; the best observed stage
  gain (-18% on one tail shape) would be under 5 microseconds, below run-to-run
  noise of the whole scan. A Luhn call that reaches the validator has already
  passed the PAN normalization, length-range and boundary checks.
- The late-malformed shape cannot reach this function from the current caller
  (`PanDigits` holds only ASCII digits), so the regression would not be hit
  today, but a fix that depends on that precondition would make a public-looking
  helper unsafe for future callers for no measurable benefit.

## Disposition

Code unchanged. The existing Luhn tests (parity, bounds, malformed, checksum
mismatch) remain the contract. Revisit only if a representative whole-scan
profile shows Luhn above the noise floor. No consumer-observable change, no
changelog entry.

## Temporary in-repo measurement

No in-repo measurement file was added or changed for this issue (tracked in
#1152). The two harnesses were compiled only temporarily in a working copy and
are kept here as inert `.txt` text: `timing-harness.rs.txt` (a module appended
to `structured_validators.rs`) and `whole-scan-harness.rs.txt` (a temporary
integration test). Neither is built by Cargo, and `examples/alloc_attribution.rs`
was not used.

**Update (#1152):** the allocation-counting harness `crates/secret-scan-core/examples/alloc_attribution.rs` was removed from this repository, and the allocation counts moved to the separate measurement engine, a package that counts allocations with the third-party `stats_alloc` crate and has no `unsafe` in this repository's crates; it reproduces the #1121 baseline exactly. The inert `*.txt` harness files in this directory stay as history: they are not built or scanned, and they hold the only record of the private-helper timing harnesses. See [`../1152/README.md`](../1152/README.md) for what moved, what was reproduced and what was lost. The original example is recoverable with `git show ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda:crates/secret-scan-core/examples/alloc_attribution.rs`.
