//! `ElevenLabs` API key detection (issue #865, research #788).
//!
//! The reviewed grammar is `sk_` followed by exactly 48 lowercase hex bytes,
//! optionally followed by the data-residency suffix `_residency_<region>`
//! where `<region>` is one or more `[a-z0-9]` bytes.
//!
//! ## Evidence and tier (maintainer ruling 2026-09-27, #788)
//!
//! `ElevenLabs` documentation never states a prefix, length or alphabet for
//! the key (observed 2026-09-26). Two parts of the grammar therefore rest on
//! different evidence:
//!
//! - **Prefix `sk_` and the `_residency_<[a-z0-9]+>` suffix: T1, on provider
//!   code.** The `elevenlabs-python` `speech_engine/server.py` docstring
//!   shows `api_key="sk_..."`, and both `elevenlabs-python`
//!   (`speech_engine/resource.py`, `_RESIDENCY_KEY_SUFFIX =
//!   re.compile(r"_residency_[a-z0-9]+$")`) and `elevenlabs-js`
//!   (`SpeechEngineResource.ts`) strip that suffix from a data-residency key
//!   before hashing it. Accepted following the `huggingface:api-token`
//!   precedent (provider SDK code counts as T1). No provider document or
//!   staff statement states prefix, length or alphabet, so the `sk_`
//!   prefix's collision with Stripe and Pollinations is unchanged and the
//!   detector's exclusion of those shapes stays in place.
//! - **Body: exactly 48 lowercase hex bytes, T2 (empirical).** Only tools
//!   (trufflehog v2 `\b((?:sk)_[a-f0-9]{48})\b`, betterleaks) and roughly 35
//!   measured public code fragments state or show the width and alphabet.
//!   The provider guarantees neither, so a length change is a false
//!   negative recorded as drift, not absorbed into a wider match.
//!
//! ## Span decision: the residency suffix is inside the finding
//!
//! The region code is not secret, but the SDK code treats the suffixed
//! string as one key that the issuer hands out whole. Reporting only the
//! 51-byte base would leave `_residency_in` dangling next to a `[REDACTED]`
//! marker and make the redacted output a partial, still-identifying key
//! string. The whole `sk_<48 hex>[_residency_<region>]` run is one finding.
//! (trufflehog stops at the hex body because its `\b` fails before `_`, so
//! it reports nothing for the suffixed form at all.)
//!
//! ## Collisions and boundaries
//!
//! `sk_` is also Stripe's prefix (`sk_live_`, `sk_test_`, `sk_org_`) and
//! Pollinations' planned `sk_` + 32 characters. Neither can match: the byte
//! right after `sk_` must be lowercase hex, and the run must be exactly 48
//! long, so `sk_live_...`, `sk_test_...`, `sk_org_...`, a 32-character body
//! or any 47/49-byte body is rejected. This detector never claims a
//! Stripe-shaped value.
//!
//! The value is never a slice of a wider `[A-Za-z0-9_-]` identifier: a
//! leading `x`, `-` or `_`, a trailing alphanumeric, `-`, or an `_` that does
//! not start exactly `_residency_<region>` rejects the whole candidate. A
//! region followed by more token bytes (`_residency_in_backup`, an uppercase
//! region byte, an empty region) is an intentional false negative on the
//! suffixed form; the 48-hex base then stays unclaimed rather than being
//! reported with a truncated suffix. A body that is one repeated byte
//! (`sk_` + 48 `0` or `a`) is a documentation filler and is rejected.
//!
//! The legacy 32-hex form has tool-only evidence and no provider source; it
//! stays unclaimed when bare and is left to marker-context `generic-token`.

use crate::detectors::pattern;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &str = "sk_";
const BODY_LEN: usize = 48;
const RESIDENCY_MARKER: &str = "_residency_";

const BASE_SIGNALS: [&str; 2] = ["elevenlabs-sdk-prefix", "lowercase-hex-suffix"];
const RESIDENCY_SIGNALS: [&str; 3] = [
    "elevenlabs-sdk-prefix",
    "lowercase-hex-suffix",
    "elevenlabs-residency-suffix",
];

/// `[A-Za-z0-9_-]`: the bytes that make a run part of a wider identifier.
fn is_token_byte(byte: u8) -> bool {
    pattern::is_alnum_dash(byte)
}

/// Recognizes `sk_` + 48 lowercase hex, with an optional
/// `_residency_<[a-z0-9]+>` suffix included in the finding span.
pub(super) struct ElevenLabsApiKeyDetector;

/// End of a valid candidate starting at `start`, and whether it carried the
/// residency suffix, or `None` when the bytes at `start` are not one.
fn match_at(bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    if start > 0 && is_token_byte(bytes[start - 1]) {
        return None;
    }
    let body_start = start + PREFIX.len();
    let body_end = body_start + BODY_LEN;
    let body = bytes.get(body_start..body_end)?;
    if !body.iter().copied().all(pattern::is_lower_hex) {
        return None;
    }
    if body.iter().all(|&byte| byte == body[0]) {
        return None;
    }
    match bytes.get(body_end) {
        None => Some((body_end, false)),
        Some(&next) if !is_token_byte(next) => Some((body_end, false)),
        Some(b'_') => {
            let rest = &bytes[body_end..];
            if !rest.starts_with(RESIDENCY_MARKER.as_bytes()) {
                return None;
            }
            let region_start = body_end + RESIDENCY_MARKER.len();
            let mut end = region_start;
            while end < bytes.len() && pattern::is_lower_alnum(bytes[end]) {
                end += 1;
            }
            if end == region_start || bytes.get(end).copied().is_some_and(is_token_byte) {
                return None;
            }
            Some((end, true))
        }
        Some(_) => None,
    }
}

impl Detector for ElevenLabsApiKeyDetector {
    fn id(&self) -> &'static str {
        "elevenlabs-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut cursor = 0;
        while let Some(offset) = input[cursor..].find(PREFIX) {
            let start = cursor + offset;
            let Some((end, residency)) = match_at(bytes, start) else {
                cursor = start + 1;
                continue;
            };
            cursor = end;
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            let signals: &[&str] = if residency {
                &RESIDENCY_SIGNALS
            } else {
                &BASE_SIGNALS
            };
            candidates.push(
                Candidate::new("elevenlabs_api_key", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

/// The literals one of which every `elevenlabs-api-key` candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) fn required_literals() -> impl Iterator<Item = &'static [u8]> {
    [PREFIX].into_iter().map(str::as_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independently authored synthetic bodies: 48 lowercase hex bytes that no
    // provider issued. The const assertions keep the widths honest.
    const BODY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
    const _: () = assert!(BODY.len() == BODY_LEN);
    const OTHER_BODY: &str = "fedcba9876543210fedcba9876543210fedcba9876543210";
    const _: () = assert!(OTHER_BODY.len() == BODY_LEN);

    fn detect(input: &str) -> Vec<Candidate> {
        ElevenLabsApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn key() -> String {
        format!("sk_{BODY}")
    }

    fn only_range(input: &str) -> (usize, usize) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let range = candidates[0].range();
        (range.start(), range.end())
    }

    #[test]
    fn a_bare_key_is_detected_at_provider_specificity() {
        let input = key();
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "elevenlabs_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
        assert_eq!(ElevenLabsApiKeyDetector.id(), "elevenlabs-api-key");
    }

    #[test]
    fn the_range_is_the_key_alone_in_every_host_context() {
        let k = key();
        let contexts = [
            format!("ELEVENLABS_API_KEY={k}\n"),
            format!("export XI_API_KEY=\"{k}\"\n"),
            format!("elevenlabs:\n  api_key: {k}\n"),
            format!("{{\"xi-api-key\": \"{k}\"}}"),
            format!("client = ElevenLabs(api_key=\"{k}\")"),
            format!("new ElevenLabsClient({{ apiKey: \"{k}\" }})"),
            format!("curl -H \"xi-api-key: {k}\" https://api.elevenlabs.io/v1/user"),
            format!("2026-09-27 INFO calling tts with key {k} ok"),
            format!(
                "{{\"name\":\"tts\",\"arguments\":{{\"headers\":{{\"xi-api-key\":\"{k}\"}}}}}}"
            ),
            format!("Authorization: Bearer {k}"),
            format!("({k})"),
        ];
        for input in contexts {
            let (start, end) = only_range(&input);
            assert_eq!(&input[start..end], k, "{input}");
        }
    }

    #[test]
    fn the_residency_suffix_is_inside_the_finding_span() {
        for region in ["in", "eu", "sg", "us1"] {
            let k = format!("sk_{BODY}_residency_{region}");
            let input = format!("XI_API_KEY={k}\n");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{region}");
            let range = candidates[0].range();
            assert_eq!(&input[range.start()..range.end()], k, "{region}");
            assert_eq!(k.len(), 51 + "_residency_".len() + region.len());
        }
    }

    #[test]
    fn a_repeated_value_is_reported_once_per_occurrence() {
        let a = key();
        let b = format!("sk_{OTHER_BODY}_residency_eu");
        let input = format!("{a} {b} {a}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 3);
        assert_eq!(
            candidates[1].range(),
            ByteRange::new(52, 52 + b.len()).unwrap()
        );
    }

    #[test]
    fn a_body_one_byte_short_or_long_is_an_intentional_false_negative() {
        let short = format!("sk_{}", &BODY[..47]);
        let long = format!("sk_{BODY}0");
        let long_suffixed = format!("sk_{BODY}0_residency_in");
        for input in [short, long, long_suffixed] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn uppercase_or_non_hex_bodies_are_rejected() {
        let upper = format!("sk_{}", BODY.to_uppercase());
        let mut mixed = BODY.to_owned();
        mixed.replace_range(10..11, "A");
        let mut non_hex = BODY.to_owned();
        non_hex.replace_range(47..48, "g");
        let mut dash = BODY.to_owned();
        dash.replace_range(20..21, "-");
        for input in [
            upper,
            format!("sk_{mixed}"),
            format!("sk_{non_hex}"),
            format!("sk_{dash}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn stripe_shaped_values_and_other_sk_lookalikes_are_never_claimed() {
        let alnum24 = "0123456789abcdefABCDEF01";
        let alnum32 = "0123456789abcdefghijklmnopqrstuv";
        for input in [
            format!("sk_live_{alnum24}"),
            format!("sk_test_{alnum24}"),
            format!("sk_org_{alnum24}"),
            format!("sk_live_{BODY}"),
            format!("sk_test_{BODY}"),
            format!("rk_live_{alnum24}"),
            format!("sk_{alnum32}"),
            format!("sk_{}", &BODY[..32]),
            format!("pk_{BODY}"),
            format!("ak_{BODY}"),
            format!("sk-{BODY}"),
            format!("sk{BODY}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_glued_identifier_boundary_rejects_an_embedded_key() {
        let k = key();
        for input in [
            format!("x{k}"),
            format!("xsk_{BODY}"),
            format!("-{k}"),
            format!("_{k}"),
            format!("elevenlabs_{k}"),
            format!("{k}-1"),
            format!("{k}_backup"),
            format!("{k}_"),
            format!("{k}Z"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn suffix_variants_outside_the_frozen_grammar_are_rejected_whole() {
        for suffix in [
            "_residency_",
            "_residency_IN",
            "_residency_in_backup",
            "_residency_in-1",
            "_residency_i_n",
            "_residencyin",
            "_Residency_in",
            "_region_in",
        ] {
            let input = format!("sk_{BODY}{suffix}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_residency_key_ends_at_punctuation_and_whitespace() {
        let k = format!("sk_{BODY}_residency_in");
        for tail in [" ", "\n", "\"", "'", ",", ";", ")", "}", ".", "/"] {
            let input = format!("{k}{tail}next");
            assert_eq!(only_range(&input), (0, k.len()), "{input}");
        }
        // Without a delimiter the following bytes are just more region.
        assert_eq!(only_range(&format!("{k}next")), (0, k.len() + 4));
    }

    #[test]
    fn placeholders_masks_and_non_secret_neighbours_are_clean() {
        let hex = "0123456789abcdef0123456789abcdef";
        for input in [
            "sk_your_api_key_here".to_owned(),
            "sk_...".to_owned(),
            "sk_****1234".to_owned(),
            format!("sk_{}", "*".repeat(48)),
            format!("sk_{}", "0".repeat(48)),
            format!("sk_{}", "a".repeat(48)),
            format!("sk_{}", "x".repeat(48)),
            "elevenlabs_sk_placeholder".to_owned(),
            format!("\"key_id\": \"{hex}\""),
            "\"hashed_xi_api_key\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"".to_owned(),
            "voice_id: 21m00Tcm4TlvDq8ikWAM".to_owned(),
            "https://api.eu.residency.elevenlabs.io/v1/user".to_owned(),
            format!("sha = \"{BODY}\""),
            hex.to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_bare_hex_value_after_an_unrelated_sk_name_is_not_a_key() {
        // `sk_` must directly abut the hex body; a variable named `sk_` +
        // words never does.
        let input = format!("sk_hash = \"{BODY}\"");
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn multibyte_text_keeps_byte_offsets_exact() {
        let k = format!("sk_{BODY}_residency_eu");
        let input = format!("# 🔑 café\r\n{k}\r\n");
        let start = "# 🔑 café\r\n".len();
        assert_eq!(only_range(&input), (start, start + k.len()));
    }

    #[test]
    fn repeated_prefix_bytes_do_not_shift_the_boundary() {
        let k = key();
        let input = format!("sk_sk_sk_{k} sk_");
        assert!(detect(&input).is_empty());
        let input = format!("sk_ {k}");
        assert_eq!(only_range(&input), (4, 4 + k.len()));
    }

    #[test]
    fn dense_prefixes_stay_linear_and_finding_free() {
        let input = "sk_".repeat(50_000);
        assert!(detect(&input).is_empty());
        let input = format!("sk_{BODY}_residency_{}", "a".repeat(100_000));
        assert_eq!(detect(&input).len(), 1);
        let input = format!("sk_{BODY}_residency_{}_", "a".repeat(100_000));
        assert!(detect(&input).is_empty());
    }
}
