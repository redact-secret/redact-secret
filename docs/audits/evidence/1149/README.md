# #1149 - IBAN letter expansion fused into one modulo step

Product judgement. Final record for
[#1149](https://github.com/redact-secret/redact-secret/issues/1149) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving. Baseline: the
#1148 record commit on this branch (no #1148 code change to rebase onto).
All inputs are synthetic or widely published documentation IBANs; no value is
printed.

## Change (`crates/secret-scan-core/src/structured_validators.rs`)

`validate_iban_mod97_v1` expanded each letter into two decimal digits with
two `% 97` steps. A letter now takes one step,
`(remainder * 100 + value) % 97` with `value` in 10..=35 (`push_letter_value`).
Digits keep `(remainder * 10 + digit) % 97`. The two forms are algebraically
equal: `((r * 10 + t) % 97 * 10 + u) % 97 = (r * 100 + 10 * t + u) % 97`. With
`r <= 96` the operand is at most `96 * 100 + 35 = 9,635`, inside `u16`.

Unchanged: the lexical checks and their order, the 15..=34 length bound, the
byte rotation, registry identity/version lookup, the 34-byte
`CandidateTooLong` gate, failure classes, provenance, and which candidates the
IBAN detector offers (this is arithmetic only; it does not skip country,
length or context rules). No unsafe, no dependency, no allocation, no public
API change.

## Equivalence

The pre-change function is kept in the test module as `iban_two_step_oracle`.
Tests compare it with the shipped function, and through the registry:

- every remainder 0..=96 times every letter value 10..=35: the fused step
  equals the two-step pair (2,522 states, the whole reachable domain), plus the
  `u16` bound;
- every length 15..=34, 60 generated bodies each (letter-heavy, digit-heavy,
  mixed, and A/Z boundary letters), all 100 check-digit pairs 00..=99 per body
  (120,000 candidates). Old and new agree on each; each body admits one or two
  valid pairs (mod 97), which also confirms the oracle is not vacuous;
- malformed and out of range: every length 0..=40 with every position replaced
  by `A Z 0 9 a z - space`, a fullwidth digit, `e` acute and NUL, including
  multi-byte replacements, and over-length inputs (`CandidateTooLong` before
  the algorithm);
- published documentation examples (GB, DE, FR, MT) and a checksum-mismatch and
  a late-malformed case.

A mutation check (using `* 10` instead of `* 100` in `push_letter_value`)
makes six tests fail, so the tests have power.

## Measurement

Host: Apple M4 (arm64), rustc 1.98.1, release profile (`lto = "fat"`,
`codegen-units = 1`), **a shared and at times heavily loaded host** (load
average up to 60 during the first attempt, which was discarded). The numbers
below are the second stage run, taken when load had fallen to about 10, with
the benchmark lock held and a 41-round alternating old/new/A-A median
(`timing-harness.rs.txt`). The A/A control stayed within 0.6% of itself in every
row of that run. Different ISA from the issue's x86_64 run, so figures differ.

| Workload (ns per call) | old | new | change |
|---|---|---|---|
| 22 chars, mixed (GB, DE) | 84.8 | 68.9 | -18.9% |
| 31 chars, letter-heavy (MT) | 174.2 | 110.4 | -36.6% |
| 34 chars, all letters | 266.8 | 123.3 | -53.8% |
| 34 chars, numeric | 134.1 | 125.2 | -6.7% |
| 22 chars, bad checksum | 94.3 | 69.0 | -26.8% |
| late-malformed (reaches lexical check end) | 6.03 | 5.86 | -2.8% |
| early-malformed (lowercase country) | 0.51 | 0.51 | 0.0% |
| short (below 15) | 0.51 | 0.51 | 0.0% |

Invalid and malformed inputs never run the arithmetic, so they cannot
regress; their rows are unchanged within A/A noise. The numeric control, which
the research run saw as noisy, is 6.7% faster here with no slowdown in any
row.

Whole path (`whole-scan-harness.rs.txt`, public `scan` with PII on, 2,000
IBAN lines of about 137 kB): the first interleaved base/new pair on the quietest
moment gave 5.10 ms (base) and 7.88 ms (new) with the prose control also
slower on the same run (1.14 ms vs 1.99 ms), and later pairs inverted, so the
whole-scan comparison **could not be resolved on this loaded host** and no
whole-scan gain is claimed. The stage saving, 2,000 calls of 15 to 140 ns, is
at most about 30 to 290 microseconds of a roughly 5 ms scan (0.5% to 6%), so
the benefit is real but small relative to the scan. Native/WASM budget
qualification belongs to #1068 and the benchmarks repository.

## Disposition

Adopted. Behavior-preserving internals: no consumer-observable change, so no
`CHANGELOG.md` entry (needs the `no-changelog` label).

## Temporary in-repo measurement

No in-repo measurement file was added or changed for this issue (tracked in
#1152). The harnesses were compiled only temporarily in a working copy and are
kept as inert `.txt` text: `timing-harness.rs.txt` (a module appended to
`structured_validators.rs`; it re-declares the pre-change function) and
`whole-scan-harness.rs.txt` (a temporary integration test). Neither is built
by Cargo, and `examples/alloc_attribution.rs` was not used.
