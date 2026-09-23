//! Postman API key detection.
//!
//! Postman's own documentation (`learning.postman.com/docs/reference/postman-api/authentication`,
//! observed 2026-09-22) explains only how to generate and send an API key
//! (the `X-API-Key` header or a `postman-api-key` variable); it publishes no
//! prefix, length, or alphabet for the key value itself. With the provider
//! silent, the reviewed grammar rests on tool agreement alone, the same
//! evidence bar `super::linear`'s `lin_oauth_` guard and
//! `super::additional_providers`'s support-policy shapes already use:
//!
//! - gitleaks 8.30.1's `postman-api-token` rule:
//!   `\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)` — a
//!   literal, case-sensitive `PMAK-` prefix, then a case-insensitive
//!   24-hex-byte segment, a literal `-`, and a case-insensitive 34-hex-byte
//!   segment.
//! - trufflehog 3.97.4's `postman` detector: `\b(PMAK-[a-zA-Z-0-9]{59})\b` —
//!   the same literal prefix, then 59 bytes of `[A-Za-z0-9-]` with no
//!   internal structure asserted.
//!
//! Both tools agree on the prefix and on a 59-byte body
//! (`24 + 1 + 34 == 59`); gitleaks additionally corroborates an internal
//! hex-hex structure with the dash fixed at byte 24 of the body.
//! Trufflehog's looser `[A-Za-z0-9-]{59}` is a strict superset of that
//! structured shape (it also accepts non-hex letters and a dash anywhere),
//! so it does not contradict gitleaks' narrower rule — the same
//! "adopt the more specific, evidence-backed shape" reasoning
//! `super::cloudflare`'s checksum-tail [`pattern::PostCheck`] already
//! applies. The reviewed grammar is therefore gitleaks' structured shape: a
//! body missing the internal dash, or one with the dash at any other
//! position, is an intentional false negative rather than a fuzzy match
//! against the looser union.
//!
//! No other Postman credential form (a collection or workspace id, a
//! Postman Vault variable reference, a redacted export placeholder) is
//! documented or tool-corroborated with its own grammar, so none is given
//! one here — the issue's stated exclusion boundary.
//!
//! The 59-byte run mixes two alphabets at fixed offsets (hex, then a single
//! literal dash, then hex again) that no single [`Alphabet`] predicate can
//! express, so — mirroring [`super::cloudflare`]'s checksum-tail shape —
//! this stays one [`PrefixShape::exact`] over the combined
//! [`pattern::is_hex_or_dash`] alphabet, narrowed by a
//! [`pattern::PostCheck`] that pins the dash to its documented offset and
//! requires hex on both sides.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, Alphabet, PrefixShape};

const PREFIX: &str = "PMAK-";
/// The gitleaks-corroborated first hex segment's length.
const HEX_SEGMENT_1_LEN: usize = 24;
/// The gitleaks-corroborated second hex segment's length.
const HEX_SEGMENT_2_LEN: usize = 34;
/// The literal separator's own single-byte width.
const SEPARATOR_LEN: usize = 1;
/// The whole body's length: both tools agree `24 + 1 + 34 == 59`.
const BODY_LEN: usize = HEX_SEGMENT_1_LEN + SEPARATOR_LEN + HEX_SEGMENT_2_LEN;
/// The dash's fixed offset within the body, counted from the body's own
/// start (i.e. immediately after [`PREFIX`]).
const DASH_OFFSET: usize = HEX_SEGMENT_1_LEN;

const SIGNALS: [&str; 2] = ["postman-documented-prefix", "hex-hex-structured-body"];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, the same
/// boundary rule every other prefixed provider in this crate shares.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// `true` when the matched run's dash sits at exactly [`DASH_OFFSET`] and
/// every other byte on both sides is hex — the internal structure
/// [`BODY_LEN`]'s combined [`pattern::is_hex_or_dash`] alphabet alone cannot
/// express, because that alphabet accepts a dash (or a run of them) at any
/// offset.
fn body_is_hex_dash_hex(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body_start = end - BODY_LEN;
    let dash_index = body_start + DASH_OFFSET;
    bytes[dash_index] == b'-'
        && bytes[body_start..dash_index]
            .iter()
            .copied()
            .all(pattern::is_hex)
        && bytes[dash_index + 1..end]
            .iter()
            .copied()
            .all(pattern::is_hex)
}

/// Requires the exact `PMAK-<24 hex>-<34 hex>` shape (case-insensitive hex).
/// A body missing the internal dash, one with the dash at any other offset,
/// a non-hex byte in either hex segment, or a run embedded in a wider
/// identifier is an intentional false negative rather than a fuzzy match.
pub(super) const POSTMAN: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "postman-api-key",
    "postman_api_key",
    &[
        PrefixShape::exact(PREFIX, BODY_LEN, pattern::is_hex_or_dash, &SIGNALS)
            .with_post_check(body_is_hex_dash_hex),
    ],
    BOUNDARY,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Exactly [`HEX_SEGMENT_1_LEN`] lowercase-hex bytes. Locally
    /// constructed synthetic value; never provider-issued.
    const HEX_SEGMENT_1: &str = "0123456789abcdef01234567";
    const _: () = assert!(HEX_SEGMENT_1.len() == HEX_SEGMENT_1_LEN);
    /// Exactly [`HEX_SEGMENT_2_LEN`] lowercase-hex bytes.
    const HEX_SEGMENT_2: &str = "0123456789abcdef0123456789abcdef01";
    const _: () = assert!(HEX_SEGMENT_2.len() == HEX_SEGMENT_2_LEN);

    fn detect(input: &str) -> Vec<Candidate> {
        POSTMAN
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn token() -> String {
        format!("{PREFIX}{HEX_SEGMENT_1}-{HEX_SEGMENT_2}")
    }

    #[test]
    fn detects_the_api_key_with_provider_specificity() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "postman_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn accepts_uppercase_hex_segments() {
        let value = format!(
            "{PREFIX}{}-{}",
            HEX_SEGMENT_1.to_ascii_uppercase(),
            HEX_SEGMENT_2.to_ascii_uppercase()
        );
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn accepts_mixed_case_hex_segments() {
        let value = format!("{PREFIX}0123456789ABCdef01234567-{HEX_SEGMENT_2}");
        assert_eq!(detect(&value).len(), 1);
    }

    /// gitleaks' rule -- the reviewed contract -- pins the dash to byte 24;
    /// a bare 59-hex-byte run with no separator is trufflehog's looser
    /// shape only, not this family's contract.
    #[test]
    fn rejects_a_body_with_no_internal_dash() {
        let bare = format!("{HEX_SEGMENT_1}0{HEX_SEGMENT_2}");
        assert_eq!(bare.len(), BODY_LEN);
        assert!(detect(&format!("{PREFIX}{bare}")).is_empty());
    }

    #[test]
    fn rejects_a_dash_at_the_wrong_offset() {
        // The dash lands one byte early; the run is still the documented
        // total length, but the structural post-check must still reject it.
        let value = format!(
            "{PREFIX}{}-{}0",
            &HEX_SEGMENT_1[..HEX_SEGMENT_1_LEN - 1],
            HEX_SEGMENT_2
        );
        assert!(detect(&value).is_empty());
    }

    #[test]
    fn rejects_a_second_dash_in_place_of_a_hex_byte() {
        let mut segment_2 = HEX_SEGMENT_2.to_string();
        segment_2.replace_range(5..6, "-");
        assert!(detect(&format!("{PREFIX}{HEX_SEGMENT_1}-{segment_2}")).is_empty());
    }

    #[test]
    fn rejects_a_body_one_byte_short_of_the_documented_length() {
        let short = &HEX_SEGMENT_2[..HEX_SEGMENT_2_LEN - 1];
        assert!(detect(&format!("{PREFIX}{HEX_SEGMENT_1}-{short}")).is_empty());
    }

    #[test]
    fn rejects_a_body_one_byte_longer_than_the_documented_length() {
        assert!(detect(&format!("{}0", token())).is_empty());
    }

    /// Both tools agree the hex segments exclude `g`-`z`; a non-hex letter
    /// breaks the alphabet run before the documented length is reached.
    #[test]
    fn rejects_a_non_hex_letter_in_a_hex_segment() {
        let mut segment_1 = HEX_SEGMENT_1.to_string();
        segment_1.replace_range(0..1, "g");
        assert!(detect(&format!("{PREFIX}{segment_1}-{HEX_SEGMENT_2}")).is_empty());
    }

    #[test]
    fn rejects_a_lowercase_prefix() {
        assert!(detect(&format!("pmak-{HEX_SEGMENT_1}-{HEX_SEGMENT_2}")).is_empty());
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(detect(&format!("legacy{}", token())).is_empty());
    }

    #[test]
    fn rejects_the_value_embedded_in_a_wider_identifier_leading_trailing_or_dash_joined() {
        let value = token();
        assert!(detect(&format!("legacy{value}")).is_empty());
        assert!(detect(&format!("{value}_backup")).is_empty());
        assert!(detect(&format!("{value}-1")).is_empty());
    }

    #[test]
    fn rejects_a_percent_encoded_delimiter_lookalike() {
        assert!(detect(&format!("PMAK%2D{HEX_SEGMENT_1}-{HEX_SEGMENT_2}")).is_empty());
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = token();
        let input = format!("({value}).");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = token();
        let input = format!("{value} {value}");
        assert_eq!(detect(&input).len(), 2);
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_masked_value() {
        assert!(detect(&format!("{PREFIX}{}", "*".repeat(BODY_LEN))).is_empty());
        assert!(detect(&format!("{PREFIX}${{POSTMAN_API_KEY}}")).is_empty());
    }

    #[test]
    fn rejects_a_doc_style_x_filled_placeholder() {
        let placeholder = format!(
            "{}-{}",
            "x".repeat(HEX_SEGMENT_1_LEN),
            "x".repeat(HEX_SEGMENT_2_LEN)
        );
        assert!(detect(&format!("{PREFIX}{placeholder}")).is_empty());
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = token();
        assert_eq!(detect(&value), detect(&value));
    }

    /// A pathological run of near-miss prefixes must not make the scan
    /// quadratic: every occurrence is one byte short of the documented
    /// length, so none matches.
    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        let short = &HEX_SEGMENT_2[..HEX_SEGMENT_2_LEN - 1];
        let input = format!("{PREFIX}{HEX_SEGMENT_1}-{short} ").repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
