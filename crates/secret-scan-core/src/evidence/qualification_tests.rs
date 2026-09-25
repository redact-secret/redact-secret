//! Qualification of the shadow scorer's worst cases (issue #772,
//! `docs/specs/engine.md`, "Shadow scorer qualification").
//!
//! These tests hold the scorer to the bounds its contract states, on the
//! inputs that cost it most: contextual candidates at `generic-token`'s
//! maximum value length, and repeated or periodic values that drive each
//! feature function's scan to its longest path. They run on every native
//! CI host and, compiled for `wasm32-wasip1`, on V8's WebAssembly engine,
//! so the pinned vectors below are also a cross-host equality check.
//!
//! Every value is synthetic: repetitions of fixed blocks, a de Bruijn
//! sequence, astral code points taken in order, and a fixed-seed linear
//! congruential generator over `[0-9A-Za-z]`, the same generator
//! `scripts/shadow-determinism.mjs` uses. None is a credential.

use crate::evidence::aggregate::ShadowAuthority;
use crate::evidence::features::{
    EvidenceFeatures, FEATURE_COUNT, MAX_ANALYSED_CHARS, extract_features,
};
use crate::evidence::shadow::ShadowComparison;
use crate::incremental::{IncrementalLimits, IncrementalSanitizer};
use crate::registry::DetectorRegistry;

/// `generic-token`'s longest contextual value (`MAX_CONTEXT_VALUE_LENGTH`).
const MAX_CONTEXT_VALUE_BYTES: usize = 4096;

const ALPHANUMERIC: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The 32-symbol synthetic block the other evidence tests use.
const BLOCK_32: &str = "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa";

/// `length` symbols of the fixed-seed generator in
/// `scripts/shadow-determinism.mjs` (`lcgValue`).
fn lcg_value(seed: u32, length: usize) -> String {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            char::from(ALPHANUMERIC[(state >> 16) as usize % ALPHANUMERIC.len()])
        })
        .collect()
}

#[test]
fn the_generators_match_the_input_set_script() {
    // `scripts/tests/shadow-determinism.test.mjs` pins the same prefixes.
    assert_eq!(lcg_value(0x772, 24), "MFtPoopPWwgzkd6zUjyF86fh");
    let pairs = de_bruijn_pairs();
    assert_eq!(pairs.len(), 62 * 62);
    assert_eq!(&pairs[..12], "001020304050");
}

/// B(62, 2): every ordered pair of `[0-9A-Za-z]` exactly once.
fn de_bruijn_pairs() -> String {
    let mut out = String::new();
    for (i, &first) in ALPHANUMERIC.iter().enumerate() {
        out.push(char::from(first));
        for &second in &ALPHANUMERIC[i + 1..] {
            out.push(char::from(first));
            out.push(char::from(second));
        }
    }
    out
}

/// `unit` repeated and cut to exactly `bytes` bytes (ASCII `unit`).
fn fill(unit: &str, bytes: usize) -> String {
    unit.repeat(bytes.div_ceil(unit.len()))[..bytes].to_owned()
}

/// The worst cases of each feature function, at the maximum contextual
/// value length.
fn hostile_values() -> Vec<(&'static str, String)> {
    let random = lcg_value(0x772, MAX_CONTEXT_VALUE_BYTES);
    let astral: String = (0x2_0000_u32..)
        .take(MAX_ANALYSED_CHARS)
        .map(|code_point| char::from_u32(code_point).unwrap())
        .collect();
    vec![
        // The largest autocorrelation lag the features scan, and one past it.
        ("period-32", fill(BLOCK_32, MAX_CONTEXT_VALUE_BYTES)),
        (
            "period-33",
            fill(&format!("{BLOCK_32}X"), MAX_CONTEXT_VALUE_BYTES),
        ),
        // The smallest-period search fails as late as possible for every
        // period.
        (
            "late-period-break",
            format!("{}b{}", "a".repeat(255), &random[256..]),
        ),
        // No bigram repeats: the full quadratic bigram scan.
        (
            "distinct-bigrams",
            fill(&de_bruijn_pairs(), MAX_CONTEXT_VALUE_BYTES),
        ),
        ("single-symbol", "a".repeat(MAX_CONTEXT_VALUE_BYTES)),
        // 256 distinct symbols: the longest histogram scan.
        (
            "astral-distinct",
            format!(
                "{astral}{}",
                &random[..MAX_CONTEXT_VALUE_BYTES - 4 * MAX_ANALYSED_CHARS]
            ),
        ),
        ("max-length", random),
    ]
}

fn vector(features: EvidenceFeatures) -> [u32; FEATURE_COUNT] {
    features.to_vector().map(|(_, value)| value)
}

/// The first `MAX_ANALYSED_CHARS` symbols of `value`.
fn analysed_prefix(value: &str) -> &str {
    value
        .char_indices()
        .nth(MAX_ANALYSED_CHARS)
        .map_or(value, |(end, _)| &value[..end])
}

#[test]
fn features_of_a_hostile_value_read_only_its_first_256_symbols() {
    // Well past any candidate `generic-token` emits.
    let one_mebibyte = fill(BLOCK_32, 1 << 20);
    let mut values = hostile_values();
    values.push(("one-mebibyte", one_mebibyte));
    for (name, value) in values {
        let whole = extract_features(&value);
        let prefix = extract_features(analysed_prefix(&value));
        assert_eq!(whole.analysed_chars, 256, "{name}");
        assert!(whole.truncated, "{name}");
        assert_eq!(whole.byte_len as usize, value.len(), "{name}");
        // Apart from the two fields that describe the whole value, the
        // features are those of the analysed prefix alone.
        assert_eq!(
            EvidenceFeatures {
                byte_len: prefix.byte_len,
                truncated: prefix.truncated,
                ..whole
            },
            prefix,
            "{name}"
        );
    }
}

/// The feature vectors of the hostile values, pinned. A host whose integer
/// arithmetic differed would fail here.
const HOSTILE_VECTORS: [(&str, [u32; FEATURE_COUNT]); 7] = [
    (
        "period-32",
        [
            4096, 256, 1, 32, 8, 327_680, 327_680, 83_886_080, 96, 96, 64, 0, 0, 0, 3, 255, 62,
            1000, 839, 125, 1000, 1, 0, 874, 32, 1000, 32,
        ],
    ),
    (
        "period-33",
        [
            4096, 256, 1, 33, 8, 330_442, 327_680, 84_593_152, 93, 100, 63, 0, 0, 0, 3, 248, 62,
            999, 846, 128, 1000, 1, 0, 870, 33, 0, 0,
        ],
    ),
    (
        "late-period-break",
        [
            4096, 256, 1, 2, 255, 2418, 371, 619_008, 256, 0, 0, 0, 0, 0, 1, 0, 26, 36, 7, 7, 1000,
            255, 996, 992, 0, 996, 2,
        ],
    ),
    (
        "distinct-bigrams",
        [
            4096, 256, 1, 62, 62, 294_241, 134_074, 75_325_696, 52, 52, 152, 0, 0, 0, 3, 208, 62,
            754, 754, 242, 1000, 2, 11, 0, 0, 488, 2,
        ],
    ),
    (
        "single-symbol",
        [
            4096, 256, 1, 1, 256, 0, 0, 0, 256, 0, 0, 0, 0, 0, 1, 0, 26, 0, 0, 3, 1000, 256, 1000,
            996, 1, 1000, 2,
        ],
    ),
    (
        "astral-distinct",
        [
            4096,
            256,
            1,
            256,
            1,
            524_288,
            524_288,
            134_217_728,
            0,
            0,
            0,
            0,
            0,
            256,
            1,
            0,
            256,
            1000,
            1000,
            1000,
            1000,
            1,
            0,
            0,
            0,
            0,
            0,
        ],
    ),
    (
        "max-length",
        [
            4096, 256, 1, 61, 10, 378_000, 306_583, 96_768_000, 125, 97, 34, 0, 0, 0, 3, 149, 62,
            972, 968, 238, 1000, 2, 11, 19, 0, 30, 24,
        ],
    ),
];

#[test]
fn hostile_values_have_pinned_feature_vectors() {
    for ((name, value), (pinned_name, pinned)) in hostile_values().into_iter().zip(HOSTILE_VECTORS)
    {
        assert_eq!(name, pinned_name);
        assert_eq!(vector(extract_features(&value)), pinned, "{name}");
    }
}

// --- whole-input and incremental paths ----------------------------------------

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

fn whole_input_comparisons(input: &str) -> Vec<ShadowComparison> {
    let mut shadow = Vec::new();
    crate::pipeline::detect(input, &registry(), Some(&mut shadow)).unwrap();
    shadow
}

fn incremental_comparisons(input: &str, chunk_bytes: usize) -> Vec<ShadowComparison> {
    let limits = IncrementalLimits::new(4_000_000, 16_512, 8_192, 16_384).unwrap();
    let mut session = IncrementalSanitizer::new(limits).unwrap();
    session.record_shadow();
    let mut start = 0;
    while start < input.len() {
        let mut end = (start + chunk_bytes).min(input.len());
        while !input.is_char_boundary(end) {
            end += 1;
        }
        session.append(&input[start..end]).unwrap();
        start = end;
    }
    session.finalize().unwrap();
    session.take_shadow()
}

/// Two lowercase letters naming `i`: `generic-token` rejects digit suffixes.
fn letters(i: u8) -> String {
    [b'a' + i / 26 % 26, b'a' + i % 26]
        .iter()
        .map(|&b| char::from(b))
        .collect()
}

/// Hostile values in credential-bearing contexts, plus inputs holding many
/// maximum-length and many periodic candidates.
fn hostile_inputs() -> Vec<(String, String)> {
    let mut inputs = Vec::new();
    for (name, value) in hostile_values() {
        inputs.push((format!("{name}/assign"), format!("API_KEY={value}")));
        inputs.push((
            format!("{name}/yaml-quoted"),
            format!("password: \"{value}\"\n"),
        ));
        inputs.push((
            format!("{name}/json"),
            format!("{{\"auth_token\": \"{value}\"}}"),
        ));
    }
    let many: Vec<String> = (0..16_u8)
        .map(|i| {
            format!(
                "service_{}_api_key={}",
                letters(i),
                lcg_value(u32::from(i) + 1, MAX_CONTEXT_VALUE_BYTES)
            )
        })
        .collect();
    inputs.push(("many-max-length".to_owned(), many.join("\n")));
    let periodic: Vec<String> = (0..128_u8)
        .map(|i| {
            let rotation = usize::from(i % 16);
            let rotated = format!("{}{}", &BLOCK_32[rotation..], &BLOCK_32[..rotation]);
            format!(
                "app_{}_secret = {}",
                letters(i),
                fill(&rotated, 32 + usize::from(i % 97))
            )
        })
        .collect();
    inputs.push(("many-periodic".to_owned(), periodic.join("\n")));
    inputs
}

#[test]
fn hostile_inputs_reach_the_scorer() {
    // The battery is only a worst case if the pipeline actually scores it.
    let statistical: usize = hostile_inputs()
        .iter()
        .map(|(_, input)| {
            whole_input_comparisons(input)
                .iter()
                .filter(|comparison| comparison.shadow.authority == ShadowAuthority::Statistical)
                .count()
        })
        .sum();
    assert!(statistical >= 16 + 128, "{statistical}");
}

#[test]
fn hostile_inputs_give_equal_whole_input_and_incremental_comparisons() {
    for (name, input) in hostile_inputs() {
        let whole = whole_input_comparisons(&input);
        for chunk_bytes in [7, 64, 4095, 4096, 4097, usize::MAX / 2] {
            assert_eq!(
                incremental_comparisons(&input, chunk_bytes),
                whole,
                "{name} in chunks of {chunk_bytes}"
            );
        }
    }
}
