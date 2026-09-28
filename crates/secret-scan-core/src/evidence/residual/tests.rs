//! Unit tests of the residual features (#829). Every value is synthetic:
//! fixed sequences, periodic blocks and a xorshift stream over
//! `[a-zA-Z0-9]`. None is a credential.

use super::*;
use crate::evidence::features::extract_features;
use crate::evidence::fixed_point::Q16_ONE;

/// Golden values, `[residual_symbols, residual_entropy_q16,
/// residual_min_entropy_q16]`, for the feature schema's golden inputs. They
/// were produced by an independent Python reimplementation written from
/// `docs/specs/engine.md`, "Shadow evidence residual features".
const GOLDEN: [(&str, [u32; 3]); 8] = [
    ("", [0, 0, 0]),
    ("aaaaaaaaaaaaaaaa", [1, 0, 0]),
    ("abcabcabcabcabcabc", [4, 65_536, 65_536]),
    ("XXXX-XXXX-XXXX-XXXX", [2, 65_536, 65_536]),
    ("Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa", [32, 327_680, 327_680]),
    (
        "\u{1F600}a\u{1F603}b\u{1F600}a\u{1F603}b",
        [6, 125_718, 103_872],
    ),
    ("ab", [2, 65_536, 65_536]),
    ("aabc", [2, 65_536, 65_536]),
];

fn values(features: ResidualFeatures) -> [u32; 3] {
    features.to_vector().map(|(_, value)| value)
}

/// Deterministic synthetic text: a xorshift stream over `alphabet`, the
/// generator the feature tests use.
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

/// `Q16` bits to thousandths of a bit, for readable assertions.
fn millibits(q16: u32) -> u32 {
    u32::try_from(u64::from(q16) * 1000 / u64::from(Q16_ONE)).unwrap()
}

#[test]
fn golden_values_match_the_independent_reference() {
    for (input, expected) in GOLDEN {
        assert_eq!(
            values(extract_residual_features(input)),
            expected,
            "input {input:?}"
        );
    }
}

#[test]
fn the_v2_vector_appends_the_residual_features_after_v1() {
    assert_eq!(
        extract_residual_features("abc")
            .to_vector()
            .map(|(name, _)| name),
        RESIDUAL_FEATURE_NAMES
    );
    for (input, _) in GOLDEN {
        let vector = extract_features(input).to_vector();
        assert_eq!(
            vector[27..],
            extract_residual_features(input).to_vector(),
            "input {input:?}"
        );
    }
}

#[test]
fn each_prediction_rule_applies() {
    // Rule 1, repeat: only the first `a` is residual.
    assert_eq!(extract_residual_features("aaaa").symbols, 1);
    // Rule 2, constant step, in either direction and with any step.
    assert_eq!(extract_residual_features("acegik").symbols, 2);
    assert_eq!(extract_residual_features("97531").symbols, 2);
    // Rule 3, constant step at lag 2.
    assert_eq!(extract_residual_features("aZbYcXdW").symbols, 4);
    // Rule 4, context copy: `Qv7-` recurs, and after its first two symbols
    // every symbol of the copy is predicted by the two before it.
    assert_eq!(extract_residual_features("Qv7-Qv7-").symbols, 6);
    // No rule: every symbol is residual.
    assert_eq!(extract_residual_features("Qv7-k").symbols, 5);
    // Astral code points step like any other scalar value.
    let astral: String = (0x1_F600_u32..0x1_F610)
        .map(|c| char::from_u32(c).unwrap())
        .collect();
    assert_eq!(extract_residual_features(&astral).symbols, 2);
}

#[test]
fn relations_hold_for_random_looking_input() {
    for seed in 1_u64..=100 {
        let input = synthetic(seed, 64, &base62());
        let f = extract_residual_features(&input);
        // Random material is almost never a repeat, a step or a copy.
        assert!(f.symbols >= 56, "seed {seed}: {f:?}");
        assert!(f.symbols <= 64);
        assert!(f.entropy_q16 <= log2_q16(f.symbols) + 2);
        assert!(f.min_entropy_q16 <= f.entropy_q16 + 2);
        assert!(f.entropy_q16 > 4 * Q16_ONE, "{f:?}");
    }
}

#[test]
fn benign_periodic_and_sequence_values_have_little_residual() {
    // Values a credential-bearing name can hold that are not secrets.
    // Several of them have Shannon entropy as high as random material; the
    // residual keeps at most a few symbols of each.
    for benign in [
        "abcabcabcabcabcabc",
        "k3Z9k3Z9k3Z9k3Z9k3Z9k3Z9",
        "0123456789",
        "12345678901234567890",
        "abcdefghijklmnopqrstuvwxyz",
        "ZYXWVUTSRQPONMLKJIHGFEDCBA",
        "0123456789abcdef0123456789abcdef",
        "aAbBcCdDeEfFgGhHiIjJ",
        "1a2b3c4d5e6f7g8h9i",
        "2468ace02468ace0",
        "xxxxxxxxxxxxxxxxxxxxxxxx",
        "XXXX-XXXX-XXXX-XXXX",
    ] {
        let f = extract_residual_features(benign);
        assert!(f.symbols <= 8, "{benign}: {f:?}");
        // At most 8 residual symbols carry at most 3 bits; these carry at
        // most 2.5.
        assert!(f.entropy_q16 <= 5 * Q16_ONE / 2, "{benign}: {f:?}");
        assert!(f.min_entropy_q16 <= 5 * Q16_ONE / 2, "{benign}: {f:?}");
    }
    // The contrast with Shannon entropy per symbol, which #829 replaces.
    let alphabet = "abcdefghijklmnopqrstuvwxyz";
    assert!(extract_features(alphabet).shannon_entropy_q16 > 4 * Q16_ONE);
    assert!(extract_residual_features(alphabet).entropy_q16 <= Q16_ONE);
}

/// `body` with a run of `run` copies of `filler` after every `every`
/// symbols: the `controlled-repetition` reshaping.
fn with_runs(body: &str, every: usize, filler: char, run: usize) -> String {
    let symbols: Vec<char> = body.chars().collect();
    let mut out = String::new();
    for chunk in symbols.chunks(every) {
        out.extend(chunk);
        out.extend(std::iter::repeat_n(filler, run));
    }
    out
}

#[test]
fn residual_entropy_resists_controlled_repetition_and_padding() {
    // Repeating a symbol adds at most one residual symbol per run, so the
    // residual entropy of reshaped random material stays within half a bit
    // of the original (the worst case here is eight runs of one symbol,
    // whose eight run heads dilute the residual). Shannon entropy per
    // symbol, the measure #829 replaces, falls further on every one of
    // these reshapings.
    for seed in 1_u64..=50 {
        let body = synthetic(seed, 32, &base62());
        let original = extract_residual_features(&body);
        let original_shannon = extract_features(&body).shannon_entropy_q16;
        for reshaped in [
            with_runs(&body, 4, 'z', 4),
            with_runs(&body, 4, '_', 6),
            with_runs(&body, 8, '0', 12),
            format!("{body}{}", "a".repeat(40)),
            format!("{}{body}", "=".repeat(24)),
        ] {
            let residual = extract_residual_features(&reshaped).entropy_q16;
            let shannon = extract_features(&reshaped).shannon_entropy_q16;
            let drop = original.entropy_q16.saturating_sub(residual);
            assert!(
                millibits(drop) <= 500,
                "seed {seed}: {} -> {}",
                millibits(original.entropy_q16),
                millibits(residual)
            );
            assert!(
                original_shannon.saturating_sub(shannon) > drop,
                "seed {seed}: Shannon {} -> {}",
                millibits(original_shannon),
                millibits(shannon)
            );
        }
    }
}

#[test]
fn residual_keeps_the_unrepeated_part_of_tiled_and_mirrored_bodies() {
    for seed in 1_u64..=50 {
        let body = synthetic(seed, 32, &base62());
        let half: String = body.chars().take(16).collect();
        // Tiling copies the prefix: every later symbol is predicted by its
        // two-symbol context, so the residual is about the prefix.
        let tiled = extract_residual_features(&half.repeat(4));
        assert!(tiled.symbols <= 16 + 2, "{tiled:?}");
        assert!(tiled.symbols >= 12, "{tiled:?}");
        // A mirror is not a copy, so its residual keeps both halves.
        let mirrored: String = half.chars().chain(half.chars().rev()).collect();
        let mirror = extract_residual_features(&mirrored);
        assert!(mirror.symbols >= 26, "{mirror:?}");
        assert!(mirror.entropy_q16 > 3 * Q16_ONE, "{mirror:?}");
    }
}

#[test]
fn min_entropy_is_the_measure_scattered_repetition_moves_most() {
    // Why feature 28, not feature 29, is the proposed successor: one
    // inserted symbol repeated between blocks (not in runs) is residual
    // every time, and min-entropy is set by the most frequent residual
    // symbol alone.
    for seed in 1_u64..=50 {
        let body = synthetic(seed, 32, &base62());
        let original = extract_residual_features(&body);
        let separated = extract_residual_features(&with_runs(&body, 3, '-', 1));
        let entropy_drop = original.entropy_q16.saturating_sub(separated.entropy_q16);
        let min_entropy_drop = original
            .min_entropy_q16
            .saturating_sub(separated.min_entropy_q16);
        assert!(min_entropy_drop > entropy_drop, "seed {seed}");
        assert!(millibits(min_entropy_drop) >= 1000, "seed {seed}");
        assert!(millibits(entropy_drop) <= 500, "seed {seed}");
    }
}

#[test]
fn only_the_first_256_symbols_are_read() {
    let prefix = synthetic(7, MAX_ANALYSED_CHARS, &base62());
    let hostile = format!("{prefix}{}", "Z".repeat(1 << 20));
    assert_eq!(
        extract_residual_features(&hostile),
        extract_residual_features(&prefix)
    );
    let four_byte = "\u{1F511}".repeat(MAX_ANALYSED_CHARS + 1);
    assert_eq!(extract_residual_features(&four_byte).symbols, 1);
}

#[test]
fn is_deterministic() {
    let value = synthetic(11, 48, &base62());
    assert_eq!(
        extract_residual_features(&value),
        extract_residual_features(&value)
    );
}

#[test]
fn debug_output_carries_no_part_of_the_value() {
    let value = "SYNTHETICvalueMARKER";
    let rendered = format!("{:?}", extract_residual_features(value));
    assert!(!rendered.contains("SYNTHETIC"));
    assert!(!rendered.contains("MARKER"));
    assert!(!rendered.contains("value"));
}
