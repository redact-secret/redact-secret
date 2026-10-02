# #1167 - Compact numeric phone parsing behind an exact shape guard

Product judgement. Final record for
[#1167](https://github.com/redact-secret/redact-secret/issues/1167) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving, small stage
benefit. Baseline: `origin/main` at `a2b2aa6c` (after #1149), which already
contains the pinned reviewed baseline's phone parser unchanged. All inputs are
synthetic.

## Change (`crates/secret-scan-core/src/pii/pii_phone.rs`)

`parse_main` now starts with one guard: when the input has at least four bytes
and **both byte 0 and byte 3 are ASCII digits**, only the compact ten-digit
display can match, so it tries that pattern and the existing exchange rules and
returns; everything else goes through the unchanged general path
(`parse_main_general`, the previous body: `+1` forms, spaced, hyphen,
parenthesized, then the seven-digit local form).

Why the guard is exact, not heuristic:

- `### ### ####` and `###-###-####` and `###-####` all have a space or `-` at
  byte 3, never a digit.
- `(###) ###-####` has a digit at byte 3 (`(212)`: `(`,2,1,2), so a byte-3 only
  guard would route it into the compact matcher. The discarded prototype named
  in the issue had exactly that defect. The first-byte guard is mandatory, and a
  mutation check confirms it (removing it fails six tests, the first on
  `(200) 555-2345`).
- `+1` forms start with `+`, which is not a digit.

Unchanged: pattern order, `valid_full_digits`/`valid_exchange` (NANP, N11),
reserved-555 handling, extension parsing, left/right boundaries, the 18/35 byte
caps, spans, metadata, and every public contract. No unsafe, dependency,
allocation or public API change.

## Equivalence

The pre-change function is kept verbatim in the test module as
`parse_main_oracle`. Tests compare the shipped function with it on:

- named shapes: empty and every short length, valid and invalid exchanges, N11,
  all four compact/spaced/hyphen/parenthesized displays, `+1` forms, trailing
  and leading characters, ASCII letters, a multi-byte letter, fullwidth digits;
- **all 18^4 = 104,976 combinations of the first four bytes** drawn from
  `0-9 + ( ) - space . a` and a multi-byte lead byte (combinations that are not valid UTF-8 are skipped), each followed by six
  different tails (compact, local, parenthesized and spaced continuations), so
  every outcome of the byte-0 and byte-3 guards is covered with matching and
  non-matching rests;
- every three-digit area code 000..=999 in eight displays (compact, spaced,
  hyphen, parenthesized, local, `+1`, area in the exchange position and in the
  line position), each cut at **every prefix length** (boundary digits and
  truncation), about 120,000 comparisons.

Public surface (`tests/pii_phone_iban_1167_1168.rs`, PII on): the whole-input
result is pinned for compact, spaced, hyphen, parenthesized, `+1`, local,
extension, malformed and over-long displays, and **every two-way split plus the
single-character partition** of the incremental session reproduce the whole
result; dense and sparse inputs agree for chunk sizes 1, 7, 64 and 4,096.

## Measurement

Host: Apple M4 (arm64), rustc stable, release profile (`lto = "fat"`,
`codegen-units = 1`), a **shared and loaded host** (load average 6.5 to 15
around the runs), benchmark lock held. The harness (`timing-harness.rs.txt`)
re-declares the detection loop and runs it with the shipped `parse_main` and
with `parse_main_oracle`, alternated old/new/old (A/A control), 41 rounds,
median, two runs (`raw-stage-runs.txt`). These are **stage** times of the phone
detection loop over a whole input, not whole-scan claims.

| Workload | run 1 | run 2 | A/A (both runs) |
|---|---|---|---|
| compact-dense (1,500 numbers) | -4.2% | -3.5% | -0.2%, +1.8% |
| parenthesized-dense | -4.7% | -3.7% | +0.1%, -1.7% |
| hyphen-dense | -3.4% | -2.0% | -0.6%, -0.1% |
| plus-dense | -22.7% | -25.3% | +1.7%, -0.3% |
| malformed (N11 and short) | -15.5% | -16.8% | -0.5%, +1.8% |
| noise numbers (timestamps, versions) | -9.3% | -10.0% | -2.0%, -6.6% |
| sparse (prose, one phone) | -3.7% | -4.1% | +0.4%, -5.9% |
| numeric-sparse (digit-rich prose, one phone) | -9.5% | -16.7% | -0.4%, -4.4% |

Reading: no workload regresses. The compact-dense gain (-2% to -4%) matches the
issue's -1.6% on x86_64. The sparse gain is -4%, far from the issue's -21.6%;
the issue itself says its sparse figure includes compiler inlining and layout
effects. The plus-dense row cannot be caused by the guard (a `+` bypasses it),
so it is a code-layout effect of splitting `parse_main`, and the larger rows
should be read as layout-inflated. The sparse A/A in run 2 (-5.9%) is as large
as the sparse gain, so the sparse row is not resolved. Whole-scan benefit was
not measured; phone detection is one stage of many.

## Disposition

Adopted, because the code change is a ten-line guard with a proof-by-case
argument, no workload regresses, and the oracle tests cover the whole guard
domain. The benefit is small and the dense compact case is -2% to -4%; if the
maintainers want zero added branches, this can be reverted without
consequence. Behavior-preserving internals: no consumer-observable change, so
no `CHANGELOG.md` entry (needs the `no-changelog` label). Native/WASM budget
qualification belongs to #1068.

## Temporary in-repo measurement

No measurement file was added to `src/` or `examples/`. The harness was
compiled only temporarily in a working copy (appended to `pii_phone.rs`) and is
kept as inert text under `docs/audits/evidence/1167/`:

- `timing-harness.rs.txt`: the alternating old/new/A-A stage harness; moves to
  the measurement engine before the beta.13 release per #1152 (tracked
  cross-repo as `redact-secret-benchmarks#608`).
- `raw-stage-runs.txt`: the raw numbers of the two runs.

`examples/alloc_attribution.rs` was not used or changed. The permanent files
changed are the product source `pii_phone.rs` (guard plus test oracle) and the
integration test `tests/pii_phone_iban_1167_1168.rs`.

**Update (#1152):** the allocation-counting harness `crates/secret-scan-core/examples/alloc_attribution.rs` was removed from this repository, and the allocation counts moved to the separate measurement engine, a package that counts allocations with the third-party `stats_alloc` crate and has no `unsafe` in this repository's crates; it reproduces the #1121 baseline exactly. The inert `*.txt` harness files in this directory stay as history: they are not built or scanned, and they hold the only record of the private-helper timing harnesses. See [`../1152/README.md`](../1152/README.md) for what moved, what was reproduced and what was lost. The original example is recoverable with `git show ab6f6eaeb511429c626e0ba29d97f3f8dbb62bda:crates/secret-scan-core/examples/alloc_attribution.rs`.
