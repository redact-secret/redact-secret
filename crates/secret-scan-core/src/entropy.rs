//! Shannon entropy over Unicode scalar values.

/// Distinct symbols counted on the stack before spilling to the heap.
const INLINE_SYMBOLS: usize = 64;

/// Returns Shannon entropy in bits per Unicode scalar value (`char`).
///
/// Entropy is a supporting classification signal only; callers must not
/// treat it as proof that an otherwise unstructured value is a secret.
///
/// The summation visits symbols in first-occurrence order, which is the same
/// order the TypeScript oracle uses, so the result is bit-identical across
/// implementations for the same input.
#[must_use]
pub fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    // First-occurrence ordered histogram. Inputs handed to this function are
    // candidate-sized tokens, so a linear probe per symbol is acceptable and
    // keeps the summation order identical to the oracle's insertion-ordered
    // map without pulling in a hasher.
    //
    // The first `INLINE_SYMBOLS` distinct symbols live in a stack array and
    // only a value with more spills to a `Vec` (#1121), so a typical token
    // costs no heap request. Order is unchanged: the array holds the earliest
    // first occurrences and the spill the later ones.
    let mut inline = [('\0', 0u32); INLINE_SYMBOLS];
    let mut inline_len = 0usize;
    let mut spill: Vec<(char, u32)> = Vec::new();
    let mut symbol_count: u32 = 0;
    for symbol in input.chars() {
        symbol_count += 1;
        if let Some((_, count)) = inline[..inline_len]
            .iter_mut()
            .find(|(seen, _)| *seen == symbol)
        {
            *count += 1;
        } else if let Some((_, count)) = spill.iter_mut().find(|(seen, _)| *seen == symbol) {
            *count += 1;
        } else if inline_len < INLINE_SYMBOLS {
            inline[inline_len] = (symbol, 1);
            inline_len += 1;
        } else {
            spill.push((symbol, 1));
        }
    }

    let total = f64::from(symbol_count);
    let mut entropy = 0.0;
    for &(_, frequency) in inline[..inline_len].iter().chain(&spill) {
        let probability = f64::from(frequency) / total;
        entropy -= probability * probability.log2();
    }
    entropy
}

#[cfg(test)]
// Exact equality is the property under test: the summation order is part of
// the cross-language contract, so results must be bit-identical.
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    /// The pre-#1121 implementation, kept as the bit-exact oracle.
    fn old_entropy(input: &str) -> f64 {
        if input.is_empty() {
            return 0.0;
        }
        let mut frequencies: Vec<(char, u32)> = Vec::new();
        let mut symbol_count: u32 = 0;
        for symbol in input.chars() {
            match frequencies.iter_mut().find(|(seen, _)| *seen == symbol) {
                Some((_, count)) => *count += 1,
                None => frequencies.push((symbol, 1)),
            }
            symbol_count += 1;
        }
        let total = f64::from(symbol_count);
        let mut entropy = 0.0;
        for &(_, frequency) in &frequencies {
            let probability = f64::from(frequency) / total;
            entropy -= probability * probability.log2();
        }
        entropy
    }

    #[test]
    fn inline_histogram_is_bit_identical_across_the_spill_boundary() {
        use crate::test_rng::XorShift32;
        // Alphabets of 3, 40, 64, 65 and 200 distinct scalars cover the
        // inline-only, exactly-full and spilled paths.
        let alphabets: Vec<Vec<char>> = [3u32, 40, 64, 65, 200]
            .iter()
            .map(|&n| {
                (0..n)
                    .map(|i| char::from_u32(0x100 + i * 3).unwrap())
                    .collect()
            })
            .collect();
        let mut rng = XorShift32::new(0x1121_0004);
        for alphabet in &alphabets {
            for _ in 0..400 {
                let len = rng.below(300);
                let text: String = (0..len)
                    .map(|_| alphabet[rng.below(alphabet.len())])
                    .collect();
                assert_eq!(
                    shannon_entropy(&text).to_bits(),
                    old_entropy(&text).to_bits(),
                    "{} distinct, len {len}",
                    alphabet.len()
                );
            }
        }
    }

    #[test]
    fn empty_and_uniform_inputs() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert_eq!(shannon_entropy("ab"), 1.0);
        assert_eq!(shannon_entropy("abcd"), 2.0);
        assert_eq!(shannon_entropy("abcdefghijklmnop"), 4.0);
    }

    #[test]
    fn counts_scalar_values_not_bytes() {
        // Two distinct four-byte symbols, equally frequent.
        assert_eq!(shannon_entropy("😀😃"), 1.0);
        assert_eq!(shannon_entropy("😀😀"), 0.0);
        // Same value as an ASCII pair of the same shape.
        assert_eq!(shannon_entropy("😀😃😀😃"), shannon_entropy("abab"));
    }

    #[test]
    fn is_deterministic_and_order_insensitive_for_permutations_of_equal_counts() {
        let first = shannon_entropy("aabbcc");
        let second = shannon_entropy("ccbbaa");
        assert_eq!(first, second);
        assert_eq!(first, shannon_entropy("aabbcc"));
    }

    #[test]
    fn known_value() {
        // p = {1/2, 1/4, 1/4} -> 1.5 bits.
        assert_eq!(shannon_entropy("aabc"), 1.5);
    }
}
