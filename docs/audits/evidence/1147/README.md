# #1147 - ASCII email NFC fast path and `@` discovery

Product judgement. Final record for
[#1147](https://github.com/redact-secret/redact-secret/issues/1147) (parent
#1068, epic #1065). Baseline: `main` at `ad877c03`. All inputs are synthetic;
no value is printed.

## Verdicts

| part | verdict |
|---|---|
| ASCII fast path for the email NFC check | **adopted** (dense ASCII -60% to -62%) |
| density-aware / `match_indices` `@` discovery as researched | **rejected** (`@`-noise +54% to +116%; probe-then-jump +7% to +19%) |
| plain byte walk for `@` (not in the issue; found while qualifying the above) | **adopted** (sparse ASCII -35%, sparse Unicode -15%, no regression) |

Behavior-preserving; no changelog entry needed (`no-changelog` label).

## Change

`crates/secret-scan-core/src/pii/pii_email.rs` only.

1. `is_nfc(value)` is `value.is_ascii() || is_nfc_normalizing(value)`. Every
   ASCII scalar is its own NFC form and none composes with a neighbour, so the
   result is identical; the normalizer now runs only for a candidate with a
   non-ASCII local-part character. (The domain is ASCII-only by
   `is_domain_alphanumeric`.) Non-ASCII NFC semantics are untouched: the old
   predicate is the fallback, so a decomposed or compatibility-form local part
   is still rejected.
2. `@` is found by walking bytes (`at_offsets`) instead of decoded characters.
   `@` is ASCII, so each offset is a character boundary. Eligibility, order
   and every later check are the same code.

`detect_email_candidates_with(input, ats, is_nfc)` takes the discovery
iterator and the NFC predicate as parameters, so the tests run the pre-change
walk and predicate as an oracle through the same extraction code. No public
API, dependency, `unsafe`, cache or retained input changed.

## Equivalence

Tests in `nfc_fast_path_tests`:

- `is_nfc_equals_the_normalizing_predicate` and
  `candidates_equal_the_always_normalizing_detector` over about 6,000 generated
  strings (ASCII, mixed, combining marks, compatibility forms such as `U+FB01`
  and `U+212B`, Hangul jamo, emoji, invisible characters, the shared boundary
  pieces), well-formed candidates around composed and decomposed local parts,
  and local parts of 62..=66 bytes plus candidates at the 254-byte limit. The
  candidate vectors are compared by `Debug` text (spans, types, confidence,
  sensitivity, obfuscation flags, order). Guards assert the corpus reaches
  non-ASCII inputs, NFC rejections and real candidates.
- `at_offsets_equal_the_character_walk` over the same corpus.
- `whole_and_incremental_scans_equal_the_old_predicate`: whole scan and every
  character-boundary split plus random three-way partitions through
  `IncrementalSanitizer`, old oracle family vs production family: redacted
  text, finding IDs, type, detector, confidence, action and range are equal.

## Measurement

Apple M4, macOS arm64, `rustc` 1.98.1, release profile. **The host was shared
and heavily loaded** (load average 7 to 43 during the runs, other agents
compiling). Runs were serialized behind a lock, variants alternated AB/BA over
41 batches (15 in the first three runs), median reported, with an A/A control
(the pre-change code compiled twice). Only the same-run ratio is meaningful.
The first three runs ran at load 7 to 43 and their A/A control moved up to
+-37%, so they are kept as raw data (`raw-discovery-variants.txt`) but not used
for any claim; runs 4 and 5 (A/A within +-3.8%) and the final production
runs below carry the verdicts. Isolated stage, not a whole scan.

Discovery variants (all with the ASCII NFC path; baseline = pre-change), runs 4
and 5, change vs pre-change:

| workload | NFC only | `match_indices` | byte walk | probe then jump |
|---|---|---|---|---|
| sparse ASCII, 74 KB | -0.7% / +4.6% | -93.4% / -93.1% | -50.0% / -48.1% | -93.4% / -93.4% |
| sparse Unicode, 78 KB | -3.5% / -2.7% | -89.6% / -89.9% | -22.6% / -17.2% | -89.3% / -89.4% |
| dense ASCII, 1,000 emails | -60.3% / -62.5% | -61.8% / -63.2% | -60.0% / -61.6% | -60.4% / -62.1% |
| dense Unicode (composed and decomposed locals) | +0.6% / -11.5% | +4.5% / -12.5% | +4.9% / -4.9% | +5.9% / -14.2% |
| dense Korean locals | +3.5% / +1.0% | +1.5% / -2.1% | +3.4% / +1.6% | +3.6% / -0.1% |
| `@` noise | -4.3% / +0.8% | **+93.0% / +96.2%** | +4.2% / -0.5% | **+18.5% / +17.5%** |
| `@` noise, mixed | +0.1% / +0.2% | **+63.8% / +66.8%** | -3.6% / -0.9% | **+7.5% / +10.9%** |

The A/A control in those two runs: -2.4% to +3.8%. `match_indices` is the
research's design and reproduces its `@`-noise regression (it was +30% to +55%
on the research host). The probe-then-jump version (scalar window, `memchr`
jump after a miss) was the attempt at a density-aware design; it still loses
7% to 19% on `@`-dense input, outside the A/A band, so the density-aware part
is **rejected**. The byte walk keeps the sparse gain that a byte loop can give
without a vectorized search and shows no regression beyond the A/A band on any
workload.

Production code against the pre-change character walk with always-normalizing
NFC (`raw-final-production.txt`, two runs at load 7 to 9, A/A -3.1% to +2.6%):

| workload | run 4 | run 5 |
|---|---|---|
| sparse ASCII | 60.6 -> 39.5 us (-34.9%) | 48.7 -> 31.5 us (-35.3%) |
| sparse Unicode | 47.6 -> 40.3 us (-15.4%) | 56.1 -> 47.9 us (-14.7%) |
| dense ASCII | 544.8 -> 217.2 us (-60.1%) | 692.1 -> 262.4 us (-62.1%) |
| dense Unicode | -0.3% | -2.5% |
| dense Korean locals | -1.5% | -2.8% |
| `@` noise | -9.4% | -9.5% |
| `@` noise, mixed | -3.2% | -4.7% |

The sparse gain is smaller than the research's `match_indices` figure (-88%)
by design: it is the price of not regressing `@`-dense input. Allocations were
not re-counted: the change adds no allocation (a byte iterator and a branch),
and the research's allocation counts were unchanged by its variants.

## Not measured

No whole-scan, native/WASM or released-size claim. The WASM binding runs the
same Rust; no WASM-specific timing was taken.

## Temporary in-repo measurement

No measurement file remains in the repository tree outside this directory. The
timing harnesses used `std::time::Instant` and `println!`, which `rust:check`
forbids under `crates/secret-scan-core/src`, so they were applied temporarily
to `crates/secret-scan-core/src/pii/pii_email.rs` and removed before commit:

- `measurement-harness.patch.txt`: final production-vs-pre-change comparison
  (ignored test `measure_1147`, a test-only module). `git apply` it to
  reproduce; run `cargo test -p redact-secret --lib --release measure_1147 --
  --ignored --nocapture`.
- `discovery-variants-harness.patch.txt`: the four discovery variants. It was
  generated against the NFC-only commit (before `at_offsets` existed) and
  applies to that commit's `pii_email.rs`.

Nothing was added to `alloc_attribution.rs`. Neither patch is part of the
build; per #1152 any measurement code that stays in the repository moves to
the measurement engine before the beta.13 release.
