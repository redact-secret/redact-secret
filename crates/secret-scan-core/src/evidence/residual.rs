//! Residual randomness features of one ambiguous candidate value (issue
//! #829): the features 27 to 29 of feature schema `evidence-features/v2`.
//!
//! The beta.9 scorer's `randomness` group reads Shannon entropy per symbol
//! (`evidence-features/v1` feature 5). That measure rates a benign sequence
//! such as `abcdefghijklmnopqrstuvwxyz` as high as random material, and it
//! falls when controlled repetition or padding is inserted into random
//! material, which is the reshaping an attacker who has read the scorer
//! would try first (redact-secret-benchmarks#289). The residual features
//! measure only the symbols that no repetition, constant step or earlier
//! copy explains: a benign periodic or sequence value keeps a residual of a
//! few symbols, and inserting a run adds at most one residual symbol.
//!
//! The formulas are normative in `docs/specs/engine.md`, section "Shadow
//! evidence residual features". The benchmark-side dataset reproduces them
//! from that section and this file. Until a scoring model adopts them, no
//! scorer reads them: [`crate::evidence::features::extract_features`] and
//! the reviewed `SHADOW_MODEL` are unchanged, so nothing here changes a
//! finding, `Confidence`, overlap weight, action or shadow band.
//!
//! The numeric contract is the feature schema's: integer arithmetic only
//! (Q16 through [`log2_q16`], every division a floor), at most
//! [`MAX_ANALYSED_CHARS`] Unicode scalar values read, fixed-size stack
//! arrays, no heap allocation, and `O(MAX_ANALYSED_CHARS^2)` symbol
//! comparisons whatever the input. [`ResidualFeatures`] holds counts only,
//! so its `Debug` output cannot reveal the value.

use super::features::MAX_ANALYSED_CHARS;
use super::fixed_point::log2_q16;

/// Names of the residual features, in the order `evidence-features/v2`
/// appends them to the `v1` vector (positions 27, 28 and 29).
pub(crate) const RESIDUAL_FEATURE_NAMES: [&str; 3] = [
    "residual_symbols",
    "residual_entropy_q16",
    "residual_min_entropy_q16",
];

/// The residual features of one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct ResidualFeatures {
    /// `r`: analysed symbols that [`is_predicted`] does not predict.
    pub(crate) symbols: u32,
    /// Shannon entropy of the residual symbols, bits per symbol, Q16.
    pub(crate) entropy_q16: u32,
    /// Min-entropy of the residual symbols, bits per symbol, Q16.
    pub(crate) min_entropy_q16: u32,
}

impl ResidualFeatures {
    /// The features as `(name, value)` in [`RESIDUAL_FEATURE_NAMES`] order.
    #[must_use]
    pub(crate) fn to_vector(self) -> [(&'static str, u32); 3] {
        let [symbols, entropy, min_entropy] = RESIDUAL_FEATURE_NAMES;
        [
            (symbols, self.symbols),
            (entropy, self.entropy_q16),
            (min_entropy, self.min_entropy_q16),
        ]
    }
}

/// Whether the residual predictor predicts `symbols[i]` from the symbols
/// before it. Any one of four rules predicts it:
///
/// 1. **repeat**: `i >= 1` and `s[i] = s[i-1]`;
/// 2. **constant step**: `i >= 2` and `s[i] + s[i-2] = 2 * s[i-1]` over code
///    points (runs, and ascending or descending sequences such as `abc`,
///    `987`, `ace`);
/// 3. **constant step at lag 2**: `i >= 4` and `s[i] + s[i-4] = 2 * s[i-2]`
///    (interleaved sequences such as `aAbBcC`, `1a2b3c`);
/// 4. **context copy**: `i >= 2` and the trigram `s[i-2..=i]` already ended
///    at some `j` in `[2, i)`: the two symbols before `i` were followed by
///    `s[i]` before (tiled, copied and periodic bodies).
///
/// Code points are compared in `u64`, so nothing is signed or overflows.
fn is_predicted(symbols: &[char], i: usize) -> bool {
    let at = |k: usize| u64::from(u32::from(symbols[k]));
    if i >= 1 && symbols[i] == symbols[i - 1] {
        return true;
    }
    if i >= 2 && at(i) + at(i - 2) == 2 * at(i - 1) {
        return true;
    }
    if i >= 4 && at(i) + at(i - 4) == 2 * at(i - 2) {
        return true;
    }
    i >= 2 && (2..i).any(|j| symbols[j - 2..=j] == symbols[i - 2..=i])
}

/// Extracts [`ResidualFeatures`] from one candidate value.
///
/// Deterministic, allocation-free and bounded: at most
/// [`MAX_ANALYSED_CHARS`] symbols are read, whatever `value`'s length.
#[must_use]
pub(crate) fn extract_residual_features(value: &str) -> ResidualFeatures {
    let mut buffer = ['\0'; MAX_ANALYSED_CHARS];
    let mut n = 0;
    for (slot, ch) in buffer.iter_mut().zip(value.chars()) {
        *slot = ch;
        n += 1;
    }
    let symbols = &buffer[..n];

    // Histogram of the residual symbols, by first occurrence.
    let mut seen = ['\0'; MAX_ANALYSED_CHARS];
    let mut counts = [0_u32; MAX_ANALYSED_CHARS];
    let mut distinct = 0;
    let mut r = 0_u32;
    for i in 0..symbols.len() {
        if is_predicted(symbols, i) {
            continue;
        }
        r += 1;
        if let Some(index) = seen[..distinct].iter().position(|&s| s == symbols[i]) {
            counts[index] += 1;
        } else {
            seen[distinct] = symbols[i];
            counts[distinct] = 1;
            distinct += 1;
        }
    }
    let counts = &counts[..distinct];

    // The feature schema's Shannon entropy and min-entropy formulas over the
    // residual counts: log2(r) - floor(sum(c * log2(c)) / r) and
    // log2(r) - log2(c_max), each 0 when r = 0.
    let mut features = ResidualFeatures {
        symbols: r,
        ..ResidualFeatures::default()
    };
    if r > 0 {
        let weighted: u64 = counts
            .iter()
            .map(|&count| u64::from(count) * u64::from(log2_q16(count)))
            .sum();
        let mean = u32::try_from(weighted / u64::from(r)).unwrap_or(u32::MAX);
        features.entropy_q16 = log2_q16(r).saturating_sub(mean);
        let max_count = counts.iter().copied().max().unwrap_or(0);
        features.min_entropy_q16 = log2_q16(r).saturating_sub(log2_q16(max_count));
    }
    features
}

#[cfg(test)]
mod tests;
