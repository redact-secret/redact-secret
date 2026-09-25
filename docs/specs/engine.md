# Engine

Rules governing the shared Rust core's detection pipeline, plugin/profile contract, and cross-language binding architecture.

> Generated for [issue #597](https://github.com/redact-secret/redact-secret/issues/597) (DS6a). Each rule
> below states current behavior in the present tense and links the ADR
> (`docs/decisions/`) that decided it. An ADR records why and when; this file
> records what is true now. Per
> [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md),
> a decision that applies an existing policy to one more provider family or
> one more instance is a row here plus its supporting evidence, not a new
> ADR.

## Rules

| Rule | Governing ADR |
| --- | --- |
| One Rust core crate is shared by every language binding (JavaScript, Python, CLI) through a monorepo layout. | [Adopt a Rust-core monorepo](../decisions/2026-09-09-adopt-rust-core-monorepo.md) |
| Each language binding is a thin host adapter over the shared Rust core, not an independent reimplementation. | [Define runtime bindings](../decisions/2026-09-09-define-runtime-bindings.md) |
| Every binding is held to the same conformance corpus so detection behavior does not drift by language. | [Govern cross-language conformance](../decisions/2026-09-09-govern-cross-language-conformance.md) |
| Detector selection is scoped by a profile/pack contract (for example `full`, `common`), not by ad hoc per-caller filtering. | [Define the detector profile and pack contract](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md) |
| Whole-input scan and redact operations carry an explicit default bound on buffered bytes and finding count, overridable by the caller. | [Bound whole-input operations by default](../decisions/2026-09-19-bound-whole-input-operations-by-default.md) |
| An organization may register additional detectors through a declarative ruleset contract; this narrows, but does not replace, the profile/pack contract's Non-goal on dynamic plugin loading. | [Define the declarative detector ruleset contract](../decisions/2026-09-19-define-declarative-detector-ruleset-contract.md) |
| Default-ignorable and other invisible Unicode code points are normalized out of the input before detection runs, using a generated table pinned to a fixed UCD version. | [Normalize invisible characters before detection](../decisions/2026-09-19-normalize-invisible-characters-before-detection.md) |
| When candidate findings overlap, the one with the more severe resolved policy action wins, not first-match or longest-match order. | [Resolve overlap precedence by resolved-action severity](../decisions/2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md) |
| Among overlapping candidates, the disjoint subset with the greatest total evidence weight is selected. | [Select optimal disjoint candidates by total evidence weight](../decisions/2026-09-19-select-optimal-disjoint-candidates-by-total-evidence-weight.md) |
| Base64, percent-encoded, and backslash-escaped input is not decoded before detection; decoding stays out of scope. | [Defer encoded-input decoding out of scope, with reasoning](../decisions/2026-09-20-defer-encoded-input-decoding.md) |

| The beta.9 evidence scorer is shadow-only. It computes an internal integer evidence score and a shadow band (`none < low < medium < high`) for `contextual` and `entropy` candidates, and neither value is ever a probability. It never changes a candidate's `Confidence`, specificity, range, overlap weight or action, never removes a deterministic positive, and is not consulted for `private-key`, `provider` or `structural` candidates. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| Evidence signals belong to five groups (`randomness`, `lexical`, `contextual`, `validation`, `negative`). A group's signals combine with halving diminishing returns under a cap, no single group and not `randomness` plus `lexical` can reach `high`, and negative evidence applies only when the whole value matches a reviewed exclusion grammar. The scorer is monotone in its signals. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| Scorer arithmetic from features to band is integer fixed-point with no floating point or `libm` calls, so every host produces identical scores and bands. Maintainer diagnostics carry signal and group identifiers and integer values only, never matched bytes or hashes of them. No public item, field or benchmark projection carries a score, probability, threshold, weight or contribution (`scripts/check-rust-workspace.py` check 10), and changing the scoring model's identity invalidates evidence keyed to the old one. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| The shadow scorer's `randomness` and `lexical` inputs are the integer statistical features of schema `evidence-features/v1`, defined exactly in the "Shadow evidence feature schema" section below. Extraction is not a detector: it reads at most 256 Unicode scalar values of one candidate value, allocates nothing, stores no part of the value, and changes no finding, `Confidence`, overlap weight or action. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |

## Shadow evidence feature schema

Schema identity **`evidence-features/v1`** (issue
[#769](https://github.com/redact-secret/redact-secret/issues/769)). The Rust
core is authoritative: `crates/secret-scan-core/src/evidence/features.rs`
(`extract_features`, `EvidenceFeatures::to_vector`, `FEATURE_NAMES`,
`FEATURE_SCHEMA_VERSION`) and `crates/secret-scan-core/src/evidence/fixed_point.rs`
(`log2_q16`, `permille`). Every item is `pub(crate)`; none is public API. The
benchmark-side candidate-feature dataset
([redact-secret-benchmarks#254](https://github.com/redact-secret/redact-secret-benchmarks/issues/254))
reproduces these definitions and records this identity. Changing a formula,
unit, bound, class boundary or the vector order below is a new identity,
and evidence keyed to `v1` is stale under it.

These features change no shipped behavior, so they carry no
false-positive or false-negative cost in beta.9. Their bounds are a
research trade-off: a value longer than 256 symbols is described by its
first 256 only, so repetition or randomness that appears later is invisible
to the features.

### Input, unit and bound

- The input is one candidate value as a Rust `&str` (for #771, the
  candidate's range in the scan copy, after invisible-character
  normalization). No decoding, case folding or Unicode normalization is
  applied.
- The **symbol** is the Unicode scalar value, the unit `shannon_entropy`
  already counts. A 2-, 3- or 4-byte UTF-8 sequence is one symbol.
- `s` is the first `min(total, 256)` symbols of the value; `n = |s|`.
  Truncation is by symbol, so it never splits a character. Lengths below
  are symbol counts unless named `byte_len`.
- Per-symbol counts `c_x` are taken over `s`. `d` is the number of distinct
  symbols, `c_max` the largest count.

### Arithmetic

Every value is an unsigned 32-bit integer and no floating point is used.
`floor(a / b)` is integer division rounding toward zero. `a ⊖ b` is
`max(0, a − b)`.

- **Q16** values are `real × 65536`.
- `permille(a, b) = floor(1000 × a / b)` computed in 64 bits, and `0` when
  `b = 0`.
- `log2_q16(x)` for `x ≥ 1` is this exact algorithm, and `log2_q16(0) = 0`.
  Its result is never above `log2(x) × 65536` and less than 2 below it.

```python
def log2_q16(x):
    if x == 0:
        return 0
    k = x.bit_length() - 1          # floor(log2 x)
    m = x << (32 - k)               # x / 2**k in Q32: 2**32 <= m < 2**33
    frac = 0
    for _ in range(16):
        m = (m * m) >> 32           # truncating square
        frac <<= 1
        if m >= 1 << 33:
            m >>= 1
            frac |= 1
    return (k << 16) | frac
```

Reference values: `log2_q16(3) = 103872`, `log2_q16(5) = 152169`,
`log2_q16(10) = 217705`, `log2_q16(62) = 390214`, `log2_q16(255) = 523917`.

### Character classes

| Class | Code points | Class alphabet size |
| --- | --- | --- |
| `lower` | `a`–`z` | 26 |
| `upper` | `A`–`Z` | 26 |
| `digit` | `0`–`9` | 10 |
| `symbol` | U+0021–U+007E that is not a letter or digit | 32 |
| `space_control` | U+0000–U+0020 and U+007F | 34 |
| `non_ascii` | U+0080 and above | the number of distinct non-ASCII symbols in `s` |

### Features, in vector order

| # | Name | Definition |
| --- | --- | --- |
| 0 | `byte_len` | UTF-8 byte length of the **whole** value, saturating at `2^32 − 1` |
| 1 | `analysed_chars` | `n` |
| 2 | `truncated` | `1` if the value has more than 256 symbols, else `0` |
| 3 | `distinct_symbols` | `d` |
| 4 | `max_symbol_count` | `c_max` (`0` when `n = 0`) |
| 5 | `shannon_entropy_q16` | `H = log2_q16(n) ⊖ floor(Σ_x c_x × log2_q16(c_x) / n)`, bits per symbol in Q16; `0` when `n = 0`. Same definition and counts as the legacy `f64` `shannon_entropy`, which never enters this value. |
| 6 | `min_entropy_q16` | `log2_q16(n) ⊖ log2_q16(c_max)`, bits per symbol in Q16 |
| 7 | `information_bits_q16` | `n × H`, estimated bits of information in Q16 |
| 8–13 | `class_lower`, `class_upper`, `class_digit`, `class_symbol`, `class_space_control`, `class_non_ascii` | number of symbols of `s` in each class |
| 14 | `class_count` | number of classes with a non-zero count |
| 15 | `class_transitions` | number of `i ∈ [1, n)` whose class of `s[i]` differs from the class of `s[i−1]` |
| 16 | `class_alphabet_size` | `A`: sum of the class alphabet sizes of the classes present |
| 17 | `entropy_efficiency_permille` | `min(1000, permille(H, log2_q16(d)))` when `d ≥ 2`, else `0` |
| 18 | `alphabet_efficiency_permille` | `min(1000, permille(H, log2_q16(A)))` when `A ≥ 2`, else `0` |
| 19 | `distinct_ratio_permille` | `permille(d, n)` |
| 20 | `length_permille` | `permille(n, 256)` |
| 21 | `longest_run` | length of the longest run of one repeated symbol (`0` when `n = 0`) |
| 22 | `adjacent_repeat_permille` | `permille(#{i ∈ [1, n) : s[i] = s[i−1]}, n ⊖ 1)` |
| 23 | `repeated_bigram_permille` | `permille(#{i ∈ [1, n−1) : ∃ j < i, (s[j], s[j+1]) = (s[i], s[i+1])}, n ⊖ 1)` |
| 24 | `smallest_period` | smallest `p ∈ [1, floor(n/2)]` with `s[i] = s[i+p]` for every `i ∈ [0, n−p)`, else `0` |
| 25 | `max_autocorrelation_permille` | `max_k permille(#{i ∈ [0, n−k) : s[i] = s[i+k]}, n − k)` over lags `k ∈ [2, min(32, floor(n/2))]`; `0` when there is no such lag. Lag 1 is `adjacent_repeat_permille`. |
| 26 | `max_autocorrelation_lag` | the smallest lag reaching feature 25 when it is non-zero, else `0` |

Work is bounded by `256²` symbol comparisons and fixed-size stack arrays,
whatever the value's length. The feature vector carries counts and ratios
only: no symbol, substring, class run or hash of the value
(`decision-freeze-the-shadow-evidence-score-and-confidence-contract`,
section 8).

### Golden vectors

The core's unit tests pin these, and an independent reimplementation
written from this page reproduces them. Values are synthetic.

| Input | Vector (features 0–26) |
| --- | --- |
| empty | all `0` |
| `aaaaaaaaaaaaaaaa` | `16,16,0,1,16,0,0,0,16,0,0,0,0,0,1,0,26,0,0,62,62,16,1000,933,1,1000,2` |
| `abcabcabcabcabcabc` | `18,18,0,3,6,103872,103872,1869696,18,0,0,0,0,0,1,0,26,1000,337,166,70,1,0,823,3,1000,3` |
| `XXXX-XXXX-XXXX-XXXX` | `19,19,0,2,16,41239,16248,783541,0,16,0,3,0,0,2,6,58,629,107,105,74,4,666,833,5,1000,5` |
| `Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa` | `32,32,0,32,1,327680,327680,10485760,12,12,8,0,0,0,3,31,62,1000,839,1000,125,1,0,0,0,0,0` |
| U+1F600 `a` U+1F603 `b`, twice | `20,8,0,4,2,131072,131072,1048576,4,0,0,0,0,4,2,7,28,1000,416,500,31,1,0,428,4,1000,4` |
| `ab` | `2,2,0,2,1,65536,65536,131072,2,0,0,0,0,0,1,0,26,1000,212,1000,7,1,0,0,0,0,0` |
| `aabc` | `4,4,0,3,2,98304,65536,393216,4,0,0,0,0,0,1,0,26,946,319,750,15,2,333,0,0,0,0` |
