//! Lightweight statistical features of one ambiguous candidate value
//! (issue #769, schema [`FEATURE_SCHEMA_VERSION`]).
//!
//! These are the `randomness` and `lexical` measurements the beta.9 shadow
//! scorer groups and caps (#770). Extraction is **not a detector**: it never
//! decides whether a value is a secret, never runs unless a caller hands it
//! a value, and nothing it returns can reach a `Finding`, a `Confidence`, an
//! overlap weight, a policy input, an error, or a log
//! (`decision-freeze-the-shadow-evidence-score-and-confidence-contract`).
//!
//! # Numeric contract
//!
//! Every feature is a `u32` computed with integer arithmetic only: no
//! `f32`/`f64` value and no `libm` call (ADR section 7). Logarithms use
//! [`log2_q16`]; ratios use [`permille`]; every division rounds toward zero.
//! The same value therefore yields the same feature vector on every host.
//!
//! # Units and bounds
//!
//! - The **symbol** is the Unicode scalar value (`char`), the unit
//!   [`crate::shannon_entropy`] counts. A multi-byte character is one
//!   symbol, and truncation never splits one.
//! - Only the first [`MAX_ANALYSED_CHARS`] symbols are analysed. `byte_len`
//!   still reports the whole value's UTF-8 length and `truncated` reports
//!   whether anything was left out. Everything is held in fixed-size stack
//!   arrays, so extraction performs no heap allocation, and its time is
//!   bounded by `O(MAX_ANALYSED_CHARS^2)` whatever the input.
//!
//! # Safe diagnostics
//!
//! [`EvidenceFeatures`] stores counts and ratios only. It holds no reference
//! to the value, no substring, no class run and no hash of it (ADR section
//! 8), so printing it with `Debug` cannot reveal the candidate.
//!
//! The exact formula of every feature is documented once, for the product
//! and for the benchmark-side dataset (redact-secret-benchmarks#254), in
//! `docs/specs/engine.md#shadow-evidence-feature-schema`. Any change to a
//! formula, a unit, a bound or the vector order is a new
//! [`FEATURE_SCHEMA_VERSION`].

use super::fixed_point::{log2_q16, permille};

/// Identity of the feature semantics below. A benchmark dataset or scoring
/// artifact keyed to one identity is stale under any other.
pub(crate) const FEATURE_SCHEMA_VERSION: &str = "evidence-features/v1";

/// The most Unicode scalar values extraction reads from one value.
pub(crate) const MAX_ANALYSED_CHARS: usize = 256;

/// The largest autocorrelation lag examined (see
/// [`EvidenceFeatures::max_autocorrelation_permille`]).
pub(crate) const MAX_AUTOCORRELATION_LAG: usize = 32;

/// Number of entries in [`EvidenceFeatures::to_vector`].
pub(crate) const FEATURE_COUNT: usize = 27;

/// Feature names in vector order. The order is part of
/// [`FEATURE_SCHEMA_VERSION`].
pub(crate) const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "byte_len",
    "analysed_chars",
    "truncated",
    "distinct_symbols",
    "max_symbol_count",
    "shannon_entropy_q16",
    "min_entropy_q16",
    "information_bits_q16",
    "class_lower",
    "class_upper",
    "class_digit",
    "class_symbol",
    "class_space_control",
    "class_non_ascii",
    "class_count",
    "class_transitions",
    "class_alphabet_size",
    "entropy_efficiency_permille",
    "alphabet_efficiency_permille",
    "distinct_ratio_permille",
    "length_permille",
    "longest_run",
    "adjacent_repeat_permille",
    "repeated_bigram_permille",
    "smallest_period",
    "max_autocorrelation_permille",
    "max_autocorrelation_lag",
];

/// Character classes, in [`EvidenceFeatures::class_counts`] order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CharClass {
    /// `a`–`z`.
    Lower = 0,
    /// `A`–`Z`.
    Upper = 1,
    /// `0`–`9`.
    Digit = 2,
    /// ASCII punctuation: U+0021–U+007E that is not a letter or digit.
    Symbol = 3,
    /// ASCII controls, space and DEL: U+0000–U+0020 and U+007F.
    SpaceControl = 4,
    /// Any scalar value at or above U+0080.
    NonAscii = 5,
}

/// Number of [`CharClass`] variants.
const CLASS_COUNT: usize = 6;

/// Fixed alphabet size of each ASCII class, in [`CharClass`] order.
/// `NonAscii` has no fixed size; the observed distinct count is used.
const CLASS_ALPHABET_SIZES: [u32; CLASS_COUNT] = [26, 26, 10, 32, 34, 0];

impl CharClass {
    const fn of(ch: char) -> Self {
        match ch {
            'a'..='z' => Self::Lower,
            'A'..='Z' => Self::Upper,
            '0'..='9' => Self::Digit,
            '\u{21}'..='\u{7E}' => Self::Symbol,
            '\u{00}'..='\u{20}' | '\u{7F}' => Self::SpaceControl,
            _ => Self::NonAscii,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// The feature vector of one candidate value. Every field is an integer
/// count, a Q16 fixed-point value (`_q16`, `value / 65536`) or a ratio in
/// thousandths (`_permille`). See the module documentation for the numeric
/// contract and `docs/specs/engine.md` for each formula.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct EvidenceFeatures {
    /// UTF-8 byte length of the whole value (not capped), saturating.
    pub(crate) byte_len: u32,
    /// `n`: symbols analysed, `min(char count, MAX_ANALYSED_CHARS)`.
    pub(crate) analysed_chars: u32,
    /// Whether the value has more than [`MAX_ANALYSED_CHARS`] symbols.
    pub(crate) truncated: bool,
    /// `d`: distinct symbols among the analysed ones.
    pub(crate) distinct_symbols: u32,
    /// `c_max`: count of the most frequent analysed symbol.
    pub(crate) max_symbol_count: u32,
    /// Shannon entropy, bits per symbol, Q16.
    pub(crate) shannon_entropy_q16: u32,
    /// Min-entropy, bits per symbol, Q16.
    pub(crate) min_entropy_q16: u32,
    /// `n * shannon_entropy_q16`: estimated information bits, Q16.
    pub(crate) information_bits_q16: u32,
    /// Analysed symbols per [`CharClass`].
    pub(crate) class_counts: [u32; CLASS_COUNT],
    /// Number of classes with a non-zero count.
    pub(crate) class_count: u32,
    /// Adjacent analysed symbol pairs whose classes differ.
    pub(crate) class_transitions: u32,
    /// Sum of the alphabet sizes of the classes present.
    pub(crate) class_alphabet_size: u32,
    /// Shannon entropy relative to `log2(d)`, permille.
    pub(crate) entropy_efficiency_permille: u32,
    /// Shannon entropy relative to `log2(class_alphabet_size)`, permille.
    pub(crate) alphabet_efficiency_permille: u32,
    /// `d / n`, permille.
    pub(crate) distinct_ratio_permille: u32,
    /// `n / MAX_ANALYSED_CHARS`, permille.
    pub(crate) length_permille: u32,
    /// Longest run of one repeated symbol.
    pub(crate) longest_run: u32,
    /// Share of adjacent pairs that repeat a symbol, permille.
    pub(crate) adjacent_repeat_permille: u32,
    /// Share of bigrams that already occurred earlier, permille.
    pub(crate) repeated_bigram_permille: u32,
    /// Smallest exact period `p <= n / 2`, or `0`.
    pub(crate) smallest_period: u32,
    /// Largest lag-`k` self-match share for `2 <= k <= min(32, n / 2)`,
    /// permille.
    pub(crate) max_autocorrelation_permille: u32,
    /// Smallest lag reaching [`Self::max_autocorrelation_permille`], or `0`
    /// when no lag is examined or no lag has a match.
    pub(crate) max_autocorrelation_lag: u32,
}

impl EvidenceFeatures {
    /// The benchmark-facing representation: every feature as `(name,
    /// value)` in [`FEATURE_NAMES`] order, `truncated` as `0`/`1`.
    #[must_use]
    pub(crate) fn to_vector(self) -> [(&'static str, u32); FEATURE_COUNT] {
        let values: [u32; FEATURE_COUNT] = [
            self.byte_len,
            self.analysed_chars,
            u32::from(self.truncated),
            self.distinct_symbols,
            self.max_symbol_count,
            self.shannon_entropy_q16,
            self.min_entropy_q16,
            self.information_bits_q16,
            self.class_counts[CharClass::Lower.index()],
            self.class_counts[CharClass::Upper.index()],
            self.class_counts[CharClass::Digit.index()],
            self.class_counts[CharClass::Symbol.index()],
            self.class_counts[CharClass::SpaceControl.index()],
            self.class_counts[CharClass::NonAscii.index()],
            self.class_count,
            self.class_transitions,
            self.class_alphabet_size,
            self.entropy_efficiency_permille,
            self.alphabet_efficiency_permille,
            self.distinct_ratio_permille,
            self.length_permille,
            self.longest_run,
            self.adjacent_repeat_permille,
            self.repeated_bigram_permille,
            self.smallest_period,
            self.max_autocorrelation_permille,
            self.max_autocorrelation_lag,
        ];
        let mut vector = [("", 0); FEATURE_COUNT];
        for (slot, (name, value)) in vector.iter_mut().zip(FEATURE_NAMES.iter().zip(values)) {
            *slot = (name, value);
        }
        vector
    }
}

/// `usize` to `u32`, saturating. Every count here is at most
/// [`MAX_ANALYSED_CHARS`], so only `byte_len` can saturate.
fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Extracts [`EvidenceFeatures`] from one candidate value.
///
/// Deterministic, allocation-free and bounded: at most
/// [`MAX_ANALYSED_CHARS`] symbols are read, whatever `value`'s length.
#[must_use]
pub(crate) fn extract_features(value: &str) -> EvidenceFeatures {
    let mut buffer = ['\0'; MAX_ANALYSED_CHARS];
    let mut chars = value.chars();
    let mut n = 0;
    for (slot, ch) in buffer.iter_mut().zip(chars.by_ref()) {
        *slot = ch;
        n += 1;
    }
    let symbols = &buffer[..n];

    let mut features = EvidenceFeatures {
        byte_len: saturating_u32(value.len()),
        analysed_chars: saturating_u32(n),
        truncated: n == MAX_ANALYSED_CHARS && chars.next().is_some(),
        length_permille: permille(saturating_u32(n), saturating_u32(MAX_ANALYSED_CHARS)),
        ..EvidenceFeatures::default()
    };
    let histogram = Histogram::of(symbols);
    add_entropy_features(&mut features, &histogram);
    add_class_features(&mut features, symbols, &histogram);
    add_repetition_features(&mut features, symbols);
    add_periodicity_features(&mut features, symbols);
    features
}

/// First-occurrence symbol histogram in fixed-size arrays (no allocation).
struct Histogram {
    seen: [char; MAX_ANALYSED_CHARS],
    counts: [u32; MAX_ANALYSED_CHARS],
    distinct: usize,
}

impl Histogram {
    fn of(symbols: &[char]) -> Self {
        let mut histogram = Self {
            seen: ['\0'; MAX_ANALYSED_CHARS],
            counts: [0; MAX_ANALYSED_CHARS],
            distinct: 0,
        };
        for &symbol in symbols {
            let distinct = histogram.distinct;
            if let Some(index) = histogram.seen[..distinct].iter().position(|&s| s == symbol) {
                histogram.counts[index] += 1;
            } else {
                histogram.seen[distinct] = symbol;
                histogram.counts[distinct] = 1;
                histogram.distinct += 1;
            }
        }
        histogram
    }

    fn seen(&self) -> &[char] {
        &self.seen[..self.distinct]
    }

    fn counts(&self) -> &[u32] {
        &self.counts[..self.distinct]
    }
}

/// Distinct and maximum counts, Shannon entropy, min-entropy, information
/// bits, and the two entropy-efficiency ratios that depend on `d`.
fn add_entropy_features(features: &mut EvidenceFeatures, histogram: &Histogram) {
    let n = features.analysed_chars;
    let counts = histogram.counts();
    features.distinct_symbols = saturating_u32(histogram.distinct);
    features.max_symbol_count = counts.iter().copied().max().unwrap_or(0);
    features.distinct_ratio_permille = permille(features.distinct_symbols, n);

    // Shannon entropy: log2(n) - floor(sum(c * log2(c)) / n).
    if n > 0 {
        let weighted: u64 = counts
            .iter()
            .map(|&count| u64::from(count) * u64::from(log2_q16(count)))
            .sum();
        let mean = u32::try_from(weighted / u64::from(n)).unwrap_or(u32::MAX);
        features.shannon_entropy_q16 = log2_q16(n).saturating_sub(mean);
    }
    // Min-entropy: log2(n) - log2(c_max).
    features.min_entropy_q16 = log2_q16(n).saturating_sub(log2_q16(features.max_symbol_count));
    features.information_bits_q16 = n.saturating_mul(features.shannon_entropy_q16);
    features.entropy_efficiency_permille =
        entropy_efficiency(features.shannon_entropy_q16, features.distinct_symbols);
}

/// `floor(1000 * entropy / log2(alphabet))`, at most `1000`, or `0` when
/// the alphabet has fewer than two symbols.
fn entropy_efficiency(shannon_entropy_q16: u32, alphabet: u32) -> u32 {
    if alphabet > 1 {
        permille(shannon_entropy_q16, log2_q16(alphabet)).min(1000)
    } else {
        0
    }
}

/// Class counts, classes present, class transitions, class alphabet size and
/// the entropy efficiency against that alphabet.
fn add_class_features(features: &mut EvidenceFeatures, symbols: &[char], histogram: &Histogram) {
    for &symbol in symbols {
        features.class_counts[CharClass::of(symbol).index()] += 1;
    }
    features.class_count = saturating_u32(features.class_counts.iter().filter(|&&c| c > 0).count());
    features.class_transitions = saturating_u32(
        symbols
            .windows(2)
            .filter(|pair| CharClass::of(pair[0]) != CharClass::of(pair[1]))
            .count(),
    );
    let distinct_non_ascii = saturating_u32(
        histogram
            .seen()
            .iter()
            .filter(|&&s| CharClass::of(s) == CharClass::NonAscii)
            .count(),
    );
    features.class_alphabet_size = features
        .class_counts
        .iter()
        .zip(CLASS_ALPHABET_SIZES)
        .map(|(&count, size)| if count == 0 { 0 } else { size })
        .sum::<u32>()
        + distinct_non_ascii;
    features.alphabet_efficiency_permille =
        entropy_efficiency(features.shannon_entropy_q16, features.class_alphabet_size);
}

/// Longest run, adjacent repeats and repeated bigrams.
fn add_repetition_features(features: &mut EvidenceFeatures, symbols: &[char]) {
    let mut run = 0_u32;
    for (index, &symbol) in symbols.iter().enumerate() {
        run = if index > 0 && symbols[index - 1] == symbol {
            run + 1
        } else {
            1
        };
        features.longest_run = features.longest_run.max(run);
    }
    let pairs = features.analysed_chars.saturating_sub(1);
    let adjacent_repeats = saturating_u32(symbols.windows(2).filter(|p| p[0] == p[1]).count());
    features.adjacent_repeat_permille = permille(adjacent_repeats, pairs);
    let repeated_bigrams = saturating_u32(
        (1..symbols.len().saturating_sub(1))
            .filter(|&i| {
                (0..i).any(|j| symbols[j] == symbols[i] && symbols[j + 1] == symbols[i + 1])
            })
            .count(),
    );
    features.repeated_bigram_permille = permille(repeated_bigrams, pairs);
}

/// Smallest exact period and the strongest autocorrelation lag.
fn add_periodicity_features(features: &mut EvidenceFeatures, symbols: &[char]) {
    let n = symbols.len();
    features.smallest_period = saturating_u32(
        (1..=n / 2)
            .find(|&p| (0..n - p).all(|i| symbols[i] == symbols[i + p]))
            .unwrap_or(0),
    );
    for lag in 2..=MAX_AUTOCORRELATION_LAG.min(n / 2) {
        let matches = saturating_u32(
            (0..n - lag)
                .filter(|&i| symbols[i] == symbols[i + lag])
                .count(),
        );
        let share = permille(matches, saturating_u32(n - lag));
        if share > features.max_autocorrelation_permille {
            features.max_autocorrelation_permille = share;
            features.max_autocorrelation_lag = saturating_u32(lag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::fixed_point::{Q16_ONE, log2_q16};

    /// Golden vectors, in [`FEATURE_NAMES`] order. They were produced by an
    /// independent Python reimplementation written from the formulas in
    /// `docs/specs/engine.md`, which is how the benchmark dataset reconciles
    /// against the product. All values are synthetic.
    const GOLDEN: [(&str, [u32; FEATURE_COUNT]); 8] = [
        ("", [0; FEATURE_COUNT]),
        (
            "aaaaaaaaaaaaaaaa",
            [
                16, 16, 0, 1, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 1, 0, 26, 0, 0, 62, 62, 16, 1000,
                933, 1, 1000, 2,
            ],
        ),
        (
            "abcabcabcabcabcabc",
            [
                18, 18, 0, 3, 6, 103_872, 103_872, 1_869_696, 18, 0, 0, 0, 0, 0, 1, 0, 26, 1000,
                337, 166, 70, 1, 0, 823, 3, 1000, 3,
            ],
        ),
        (
            "XXXX-XXXX-XXXX-XXXX",
            [
                19, 19, 0, 2, 16, 41_239, 16_248, 783_541, 0, 16, 0, 3, 0, 0, 2, 6, 58, 629, 107,
                105, 74, 4, 666, 833, 5, 1000, 5,
            ],
        ),
        (
            "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa",
            [
                32, 32, 0, 32, 1, 327_680, 327_680, 10_485_760, 12, 12, 8, 0, 0, 0, 3, 31, 62,
                1000, 839, 1000, 125, 1, 0, 0, 0, 0, 0,
            ],
        ),
        (
            "\u{1F600}a\u{1F603}b\u{1F600}a\u{1F603}b",
            [
                20, 8, 0, 4, 2, 131_072, 131_072, 1_048_576, 4, 0, 0, 0, 0, 4, 2, 7, 28, 1000, 416,
                500, 31, 1, 0, 428, 4, 1000, 4,
            ],
        ),
        (
            "ab",
            [
                2, 2, 0, 2, 1, 65_536, 65_536, 131_072, 2, 0, 0, 0, 0, 0, 1, 0, 26, 1000, 212,
                1000, 7, 1, 0, 0, 0, 0, 0,
            ],
        ),
        (
            "aabc",
            [
                4, 4, 0, 3, 2, 98_304, 65_536, 393_216, 4, 0, 0, 0, 0, 0, 1, 0, 26, 946, 319, 750,
                15, 2, 333, 0, 0, 0, 0,
            ],
        ),
    ];

    fn values(features: &EvidenceFeatures) -> [u32; FEATURE_COUNT] {
        features.to_vector().map(|(_, value)| value)
    }

    /// Deterministic synthetic text: a xorshift stream over `alphabet`.
    fn synthetic(seed: u64, len: usize, alphabet: &[char]) -> String {
        let mut state = seed | 1;
        let modulus = u64::try_from(alphabet.len()).unwrap();
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                alphabet[usize::try_from(state % modulus).unwrap()]
            })
            .collect()
    }

    fn base62() -> Vec<char> {
        ('a'..='z').chain('A'..='Z').chain('0'..='9').collect()
    }

    #[test]
    fn golden_vectors_match_the_independent_reference() {
        for (input, expected) in GOLDEN {
            assert_eq!(
                values(&extract_features(input)),
                expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn vector_names_are_unique_and_in_schema_order() {
        let vector = extract_features("abc").to_vector();
        assert_eq!(vector.map(|(name, _)| name), FEATURE_NAMES);
        for (index, name) in FEATURE_NAMES.iter().enumerate() {
            assert!(!FEATURE_NAMES[..index].contains(name), "duplicate {name}");
        }
        assert_eq!(FEATURE_SCHEMA_VERSION, "evidence-features/v1");
    }

    #[test]
    fn shannon_entropy_reuses_the_legacy_definition_within_two_units() {
        // Same definition over the same scalar-value counts as
        // `crate::shannon_entropy`; only the arithmetic is fixed point.
        let alphabets: [Vec<char>; 3] = [
            base62(),
            vec!['a', 'b'],
            "\u{E9}\u{65E5}\u{1F600}x-".chars().collect(),
        ];
        for (seed, alphabet) in (1_u64..=200).zip(alphabets.iter().cycle()) {
            let len = usize::try_from(seed % 97 + 1).unwrap();
            let input = synthetic(seed, len, alphabet);
            let features = extract_features(&input);
            let legacy = crate::shannon_entropy(&input) * f64::from(Q16_ONE);
            let difference = (legacy - f64::from(features.shannon_entropy_q16)).abs();
            assert!(
                difference <= 2.0 + 1e-6,
                "seed {seed}: {legacy} vs {features:?}"
            );
        }
    }

    #[test]
    fn entropy_relations_hold_for_random_looking_input() {
        for seed in 1_u64..=100 {
            let input = synthetic(seed, 64, &base62());
            let f = extract_features(&input);
            // Min-entropy never exceeds Shannon entropy and Shannon entropy
            // never exceeds log2 of the distinct count, up to rounding.
            assert!(f.min_entropy_q16 <= f.shannon_entropy_q16 + 2, "{f:?}");
            assert!(f.shannon_entropy_q16 <= log2_q16(f.distinct_symbols) + 2);
            assert_eq!(
                f.information_bits_q16,
                f.analysed_chars * f.shannon_entropy_q16
            );
            assert!(f.shannon_entropy_q16 > 4 * Q16_ONE, "{f:?}");
            assert!(f.entropy_efficiency_permille > 900, "{f:?}");
            assert_eq!(f.smallest_period, 0);
            assert!(f.max_autocorrelation_permille < 200, "{f:?}");
            assert_eq!(f.class_counts.iter().sum::<u32>(), f.analysed_chars);
        }
    }

    #[test]
    fn low_entropy_and_filler_values_look_low_entropy_and_repetitive() {
        for filler in ["0000000000000000", "xxxxxxxxxxxxxxxxxxxxxxxx", "********"] {
            let f = extract_features(filler);
            assert_eq!(f.shannon_entropy_q16, 0);
            assert_eq!(f.min_entropy_q16, 0);
            assert_eq!(f.information_bits_q16, 0);
            assert_eq!(f.distinct_symbols, 1);
            assert_eq!(f.longest_run, f.analysed_chars);
            assert_eq!(f.adjacent_repeat_permille, 1000);
            assert_eq!(f.smallest_period, 1);
        }
    }

    #[test]
    fn periodic_values_report_their_period_and_autocorrelation() {
        let f = extract_features(&"k3Z9".repeat(12));
        assert_eq!(f.smallest_period, 4);
        assert_eq!(f.max_autocorrelation_lag, 4);
        assert_eq!(f.max_autocorrelation_permille, 1000);
        assert_eq!(f.distinct_symbols, 4);
        assert_eq!(f.shannon_entropy_q16, 2 * Q16_ONE);
        // A period with a partial last repetition is still a period.
        assert_eq!(extract_features("abcdeabcdeabc").smallest_period, 5);
        // A period longer than half the value is not reported.
        assert_eq!(extract_features("abcdefabc").smallest_period, 0);
    }

    #[test]
    fn symbols_are_scalar_values_and_truncation_never_splits_one() {
        let four_byte = "\u{1F511}";
        let exact = four_byte.repeat(MAX_ANALYSED_CHARS);
        let f = extract_features(&exact);
        assert_eq!(f.analysed_chars, 256);
        assert_eq!(f.byte_len, 1024);
        assert!(!f.truncated);
        assert_eq!(f.class_counts[CharClass::NonAscii.index()], 256);
        assert_eq!(f.class_alphabet_size, 1);

        let over = format!("{exact}a");
        let g = extract_features(&over);
        assert!(g.truncated);
        assert_eq!(g.byte_len, 1025);
        let mut expected = f;
        expected.byte_len = 1025;
        expected.truncated = true;
        assert_eq!(g, expected);

        // Mixed widths: 1-, 2-, 3- and 4-byte scalars each count once.
        let mixed = extract_features("a\u{E9}\u{65E5}\u{1F511}");
        assert_eq!(mixed.analysed_chars, 4);
        assert_eq!(mixed.byte_len, 10);
        assert_eq!(mixed.shannon_entropy_q16, 2 * Q16_ONE);
        assert_eq!(mixed.class_counts[CharClass::NonAscii.index()], 3);
        assert_eq!(mixed.class_alphabet_size, 26 + 3);
    }

    #[test]
    fn maximum_length_and_hostile_inputs_are_bounded_by_the_analysed_prefix() {
        let prefix = synthetic(7, MAX_ANALYSED_CHARS, &base62());
        let hostile = format!("{prefix}{}", "Z".repeat(1 << 20));
        let bounded = extract_features(&hostile);
        let reference = extract_features(&prefix);
        assert!(bounded.truncated);
        assert!(!reference.truncated);
        assert_eq!(bounded.byte_len, u32::try_from(hostile.len()).unwrap());
        assert_eq!(bounded.analysed_chars, 256);
        assert_eq!(bounded.length_permille, 1000);
        // Everything but the whole-value length fields depends on the
        // analysed prefix only.
        let mut expected = reference;
        expected.byte_len = bounded.byte_len;
        expected.truncated = true;
        assert_eq!(bounded, expected);
    }

    #[test]
    fn is_deterministic_and_permutation_invariant_for_count_features() {
        let first = extract_features("aabbccdd1234");
        assert_eq!(first, extract_features("aabbccdd1234"));
        let permuted = extract_features("4321ddccbbaa");
        assert_eq!(first.shannon_entropy_q16, permuted.shannon_entropy_q16);
        assert_eq!(first.min_entropy_q16, permuted.min_entropy_q16);
        assert_eq!(first.class_counts, permuted.class_counts);
        assert_eq!(first.distinct_symbols, permuted.distinct_symbols);
    }

    #[test]
    fn character_classes_partition_ascii_exactly() {
        let ascii: String = (0_u8..=127).map(char::from).collect();
        let f = extract_features(&ascii);
        assert_eq!(f.class_counts, [26, 26, 10, 32, 34, 0]);
        assert_eq!(f.class_alphabet_size, 128);
        assert_eq!(f.class_count, 5);
    }

    #[test]
    fn debug_output_carries_no_part_of_the_value() {
        let value = "SYNTHETICvalueMARKER";
        let rendered = format!("{:?}", extract_features(value));
        assert!(!rendered.contains("SYNTHETIC"));
        assert!(!rendered.contains("MARKER"));
        assert!(!rendered.contains("value"));
    }
}
