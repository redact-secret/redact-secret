//! Structural `otpauth://` TOTP/HOTP secret detector.
//!
//! Recognizes the RFC-adjacent `otpauth://totp/...` and `otpauth://hotp/...`
//! URI scheme used by authenticator apps, keyed on the literal scheme plus a
//! required `secret=` query parameter carrying a base32-encoded shared
//! secret. Only the secret value, not the label, issuer, or other
//! parameters, is selected.
//!
//! False-positive/false-negative tradeoff: the URI scheme plus the required
//! `secret=` parameter is a strong structural signal, so false positives are
//! unlikely -- ordinary text does not spell `otpauth://totp/` or
//! `otpauth://hotp/` by accident. The corresponding false negative is a bare
//! base32 TOTP seed presented without the `otpauth://` wrapper (e.g. a
//! "manual entry" QR fallback): that shape carries no scheme to key on, so
//! recognizing it would require a separate, riskier contextual rule over
//! unadorned base32 text, which this detector deliberately does not attempt.

use crate::detectors::pattern::find_literal;
use crate::detectors::prefilter::Literals;
use crate::error::DetectorFailure;
use crate::types::{
    ByteRange, Candidate, Confidence, Detector, DetectorContext, SignalPack, Specificity,
    signal_pack,
};

/// The scheme every supported prefix starts with; discovery searches for it
/// exactly (lowercase ASCII) before checking the type segment.
const SCHEME: &[u8] = b"otpauth://";

/// The two supported `otpauth://<type>/` prefixes, matched literally
/// (lowercase, as every real-world generator emits them) together with the
/// signal name recorded for that form.
const PREFIXES: [(&str, &str); 2] = [("otpauth://totp/", "totp"), ("otpauth://hotp/", "hotp")];

/// RFC 4226's minimum recommended shared-secret length is 128 bits; encoded
/// as base32 (5 bits/char) that is 26 characters. This detector uses a
/// slightly looser practical floor -- 16 base32 characters (80 bits) -- to
/// match what widely-deployed authenticator issuers actually emit, while
/// still excluding trivially short placeholder values.
const MIN_SECRET_LEN: usize = 16;

/// Bounds the label scan (between the type segment and `?`) so a hostile,
/// terminator-free input cannot force unbounded work.
const MAX_LABEL_LENGTH: usize = 2_048;

/// Bounds the query-string scan for the same reason.
const MAX_QUERY_LENGTH: usize = 8_192;

/// The finite signal pack for a `PREFIXES` signal name: the labels are fixed
/// literals, so every candidate of a form shares one slice.
fn signal_pack_for(signal: &str) -> &'static SignalPack {
    if signal == "totp" {
        signal_pack!("otpauth-scheme", "totp")
    } else {
        signal_pack!("otpauth-scheme", "hotp")
    }
}

fn is_boundary_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

/// `true` for bytes that end a URI label or query segment: whitespace,
/// control characters, and delimiters that cannot appear unescaped in
/// either.
fn is_uri_terminator(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r' | b'"' | b'\'' | b'<' | b'>' | b'\\' | b'#'
    )
}

fn is_label_stop(byte: u8) -> bool {
    is_uri_terminator(byte) || byte == b'?' || byte == b'/'
}

fn is_query_stop(byte: u8) -> bool {
    is_uri_terminator(byte) || byte == b'/'
}

fn is_base32_char(byte: u8) -> bool {
    byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)
}

/// Scans forward from `start` until a byte matching `is_stop` or the end of
/// input, bounded by `max_len`. Returns `None` when the bound is exceeded
/// before a stop byte or the end of input is reached.
fn scan_bounded(
    input: &str,
    start: usize,
    max_len: usize,
    is_stop: fn(u8) -> bool,
) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut end = start;
    while end < bytes.len() && !is_stop(bytes[end]) {
        if end - start >= max_len {
            return None;
        }
        end += 1;
    }
    Some(end)
}

/// Finds the `secret` parameter's raw value within `query` (relative to
/// `query_start` in the original input), matching only a whole `&`-delimited
/// key, not a substring of a longer key.
fn find_secret_value(query: &str, query_start: usize) -> Option<(usize, usize)> {
    const KEY: &[u8] = b"secret=";
    let bytes = query.as_bytes();
    let mut index = 0;
    while index + KEY.len() <= bytes.len() {
        let at_key_start = index == 0 || bytes[index - 1] == b'&';
        // A byte-exact match on an all-ASCII key is only possible starting at
        // a UTF-8 character boundary (an ASCII byte can never be a
        // multi-byte character's continuation byte), so `value_start` below
        // is always safe to slice `query` at.
        if at_key_start && bytes[index..index + KEY.len()] == *KEY {
            let value_start = index + KEY.len();
            let value_end = query[value_start..]
                .find('&')
                .map_or(query.len(), |offset| value_start + offset);
            return Some((query_start + value_start, query_start + value_end));
        }
        index += 1;
    }
    None
}

/// Validates that `value` is entirely a base32 run (`[A-Z2-7]+`) optionally
/// followed by `=` padding, with the base32 run at least [`MIN_SECRET_LEN`]
/// characters. Returns the byte range of the full value (including any
/// padding) when valid.
fn base32_secret_range(value: &str, value_start: usize) -> Option<ByteRange> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && is_base32_char(bytes[index]) {
        index += 1;
    }
    let core_len = index;
    while index < bytes.len() && bytes[index] == b'=' {
        index += 1;
    }
    if index != bytes.len() || core_len < MIN_SECRET_LEN {
        return None;
    }
    ByteRange::new(value_start, value_start + index)
}

/// The structural `otpauth://` TOTP/HOTP secret detector.
pub(super) struct OtpauthDetector;

impl Detector for OtpauthDetector {
    fn id(&self) -> &'static str {
        "otpauth-uri"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut position = 0usize;

        // Jump straight to each exact `otpauth://` (lowercase ASCII) instead
        // of testing both full prefixes at every character (#1146). Every
        // old match begins with that scheme, an ASCII `o` is always a UTF-8
        // character boundary, and a scheme that is not followed by a
        // supported type resumes one byte later exactly as the per-character
        // walk did, so the candidate positions and the cursor updates below
        // are unchanged.
        while let Some(prefix_start) = find_literal(bytes, SCHEME, position) {
            let Some((prefix_end, signal)) = PREFIXES.iter().find_map(|&(prefix, signal)| {
                let end = prefix_start + prefix.len();
                (end <= bytes.len() && bytes[prefix_start..end] == *prefix.as_bytes())
                    .then_some((end, signal))
            }) else {
                position = prefix_start + 1;
                continue;
            };

            position = prefix_end;

            let boundary_blocked =
                prefix_start > 0 && is_boundary_identifier_char(bytes[prefix_start - 1]);
            if boundary_blocked {
                continue;
            }

            let Some(label_end) = scan_bounded(input, prefix_end, MAX_LABEL_LENGTH, is_label_stop)
            else {
                continue;
            };
            if bytes.get(label_end) != Some(&b'?') {
                continue;
            }

            let query_start = label_end + 1;
            let Some(query_end) = scan_bounded(input, query_start, MAX_QUERY_LENGTH, is_query_stop)
            else {
                continue;
            };

            let query = &input[query_start..query_end];
            let Some((value_start, value_end)) = find_secret_value(query, query_start) else {
                continue;
            };
            let value = &input[value_start..value_end];
            let Some(range) = base32_secret_range(value, value_start) else {
                continue;
            };

            candidates.push(
                Candidate::built_in("otpauth_secret", Confidence::High, range)
                    .with_specificity(Specificity::Structural)
                    .with_signal_pack(signal_pack_for(signal)),
            );
        }

        Ok(candidates)
    }
}

/// The literals one of which every `otpauth` candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) const REQUIRED_LITERALS: &[Literals] = &[Literals::Prefixes(&PREFIXES)];

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        OtpauthDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn only_range(candidates: &[Candidate]) -> (usize, usize) {
        assert_eq!(candidates.len(), 1);
        (candidates[0].range().start(), candidates[0].range().end())
    }

    #[test]
    fn totp_uri_with_only_the_required_secret_is_detected() {
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "JBSWY3DPEHPK3PXP");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Structural));
        assert_eq!(candidates[0].type_name(), "otpauth_secret");
    }

    #[test]
    fn otpauth_candidates_share_one_signal_slice_per_form() {
        let totp = "otpauth://totp/A:a@example.com?secret=JBSWY3DPEHPK3PXP";
        let hotp = "otpauth://hotp/A:a@example.com?secret=JBSWY3DPEHPK3PXP";
        let (first, second) = (detect(totp), detect(totp));
        assert_eq!(first[0].signals(), ["otpauth-scheme", "totp"]);
        assert!(std::ptr::eq(first[0].signals(), second[0].signals()));
        let other = detect(hotp);
        assert_eq!(other[0].signals(), ["otpauth-scheme", "hotp"]);
        assert!(!std::ptr::eq(first[0].signals(), other[0].signals()));
    }

    #[test]
    fn hotp_uri_with_only_the_required_secret_is_detected() {
        let input = "otpauth://hotp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&counter=0";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn totp_uri_with_every_optional_parameter_is_detected() {
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn hotp_uri_with_every_optional_parameter_is_detected() {
        let input = "otpauth://hotp/Example:alice@example.com?issuer=Example&secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=42";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn trailing_base32_padding_is_included() {
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP===";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "JBSWY3DPEHPK3PXP===");
    }

    #[test]
    fn missing_secret_parameter_produces_no_finding() {
        let input = "otpauth://totp/Example:alice@example.com?issuer=Example&algorithm=SHA1";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn uri_with_no_query_string_produces_no_finding() {
        assert!(detect("otpauth://totp/Example:alice@example.com").is_empty());
    }

    #[test]
    fn invalid_base32_alphabet_produces_no_finding() {
        let input = "otpauth://totp/Example:alice@example.com?secret=jbswy3dpehpk3pxp";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn secret_below_the_minimum_length_produces_no_finding() {
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DP";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn otpauth_mentioned_in_unrelated_prose_produces_no_finding() {
        assert!(detect("See the otpauth spec for details on TOTP.").is_empty());
        assert!(detect("https://example.com/docs/otpauth-format").is_empty());
    }

    #[test]
    fn otpauth_embedded_in_a_wider_identifier_is_excluded() {
        let input = "xotpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn overlong_query_string_terminates_without_a_finding() {
        let input = format!(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&note={}",
            "A".repeat(50_000)
        );
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn multiple_uris_in_the_same_input_are_both_detected() {
        let input = "otpauth://totp/A:a@example.com?secret=JBSWY3DPEHPK3PXP otpauth://hotp/B:b@example.com?secret=NB2HI4DTHIXS6IDU&counter=1";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn duplicate_secret_parameters_select_only_the_first_occurrence() {
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPAAAA&secret=JBSWY3DPEHPK3PXPBBBB";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "JBSWY3DPEHPK3PXPAAAA");
    }

    #[test]
    fn a_duplicate_secret_whose_first_occurrence_is_below_the_minimum_length_produces_no_finding() {
        // Accepted tradeoff: only the first `secret=` occurrence is ever
        // inspected. When it fails validation, the detector does not fall
        // back to a later, syntactically valid duplicate.
        let input =
            "otpauth://totp/Example:alice@example.com?secret=SHORT&secret=JBSWY3DPEHPK3PXPBBBB";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn a_base32_lookalike_in_the_label_is_never_selected() {
        let input = "otpauth://totp/JBSWY3DPEHPK3PXP:alice@example.com?secret=NB2HI4DTHIXS6IDUAAAA";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "NB2HI4DTHIXS6IDUAAAA");
    }

    #[test]
    fn a_secret_value_with_an_rfc4648_excluded_digit_mid_value_produces_no_finding() {
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DP01PK3PXP";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn padding_before_the_end_of_the_value_produces_no_finding() {
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DP=EHPK3PXP";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn an_empty_secret_value_produces_no_finding() {
        let input = "otpauth://totp/Example:alice@example.com?secret=&issuer=Example";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn an_unsupported_type_segment_produces_no_finding() {
        let input = "otpauth://push/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn a_percent_encoded_padding_character_is_not_decoded_and_produces_no_finding() {
        // Accepted tradeoff: the detector never percent-decodes the query
        // string, so a secret that percent-encodes its own `=` padding is
        // not recognized as base32 even though the decoded value would be
        // a valid secret.
        let input = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP%3D%3D";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn a_percent_encoded_secret_key_is_not_decoded_and_produces_no_finding() {
        // Accepted tradeoff: `find_secret_value` matches the literal ASCII
        // bytes "secret=" only; a percent-encoded key byte never matches.
        let input = "otpauth://totp/Example:alice@example.com?%73ecret=JBSWY3DPEHPK3PXP";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn an_unencoded_space_in_the_label_produces_no_finding() {
        // Accepted tradeoff: an unencoded space ends the label scan without
        // the query string's `?` immediately following it, so the whole URI
        // is skipped even though a genuine secret follows later in the line.
        let input = "otpauth://totp/Example Corp:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn trailing_sentence_punctuation_is_absorbed_into_the_value_and_produces_no_finding() {
        // Accepted tradeoff: a sentence-ending period is not a recognized
        // query terminator, so it is absorbed into the candidate value and
        // fails base32 validation.
        let input = "See otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP.";
        assert!(detect(input).is_empty());
    }

    #[test]
    fn an_uppercase_scheme_produces_no_finding() {
        // Accepted tradeoff, documented on `PREFIXES`: the scheme is matched
        // as a literal lowercase byte sequence.
        let input = "OTPAUTH://TOTP/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP";
        assert!(detect(input).is_empty());
    }

    /// The detector as it was before #1146: both full prefixes are tested at
    /// every character. Kept verbatim (only renamed) as the differential
    /// oracle for the exact-scheme discovery above.
    fn detect_per_character_walk(input: &str) -> Vec<Candidate> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut position = 0usize;

        while position <= bytes.len() {
            let Some((prefix_start, prefix_end, signal)) =
                PREFIXES.iter().find_map(|&(prefix, signal)| {
                    let end = position + prefix.len();
                    (end <= bytes.len() && bytes[position..end] == *prefix.as_bytes())
                        .then_some((position, end, signal))
                })
            else {
                position += super::super::text::char_at(input, position).map_or(1, char::len_utf8);
                continue;
            };

            position = prefix_end;

            let boundary_blocked =
                prefix_start > 0 && is_boundary_identifier_char(bytes[prefix_start - 1]);
            if boundary_blocked {
                continue;
            }

            let Some(label_end) = scan_bounded(input, prefix_end, MAX_LABEL_LENGTH, is_label_stop)
            else {
                continue;
            };
            if bytes.get(label_end) != Some(&b'?') {
                continue;
            }

            let query_start = label_end + 1;
            let Some(query_end) = scan_bounded(input, query_start, MAX_QUERY_LENGTH, is_query_stop)
            else {
                continue;
            };

            let query = &input[query_start..query_end];
            let Some((value_start, value_end)) = find_secret_value(query, query_start) else {
                continue;
            };
            let value = &input[value_start..value_end];
            let Some(range) = base32_secret_range(value, value_start) else {
                continue;
            };

            candidates.push(
                Candidate::built_in("otpauth_secret", Confidence::High, range)
                    .with_specificity(Specificity::Structural)
                    .with_signals(["otpauth-scheme", signal]),
            );
        }

        candidates
    }

    fn assert_same(input: &str) {
        assert_eq!(
            detect(input),
            detect_per_character_walk(input),
            "input of {} bytes: {:?}",
            input.len(),
            input.chars().take(200).collect::<String>()
        );
    }

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    #[test]
    fn every_supported_prefix_starts_with_the_searched_scheme() {
        for (prefix, _) in PREFIXES {
            assert!(prefix.as_bytes().starts_with(SCHEME), "{prefix}");
        }
    }

    #[test]
    fn named_shapes_match_the_per_character_walk() {
        let long_label = |n: usize| format!("otpauth://totp/{}?secret={SECRET}", "L".repeat(n));
        // A query of exactly `n` bytes: `secret=<16>&n=<padding>`.
        let query_of = |n: usize| {
            let head = format!("secret={SECRET}&n=");
            format!(
                "otpauth://totp/A?{head}{}",
                "Q".repeat(n.saturating_sub(head.len()))
            )
        };
        let mut named = vec![
            // Nested eligible URIs after malformed or unsupported prefixes.
            format!("otpauth://otpauth://totp/A?secret={SECRET}"),
            format!("otpauth://push/otpauth://hotp/B?secret={SECRET}"),
            format!("otpauth://totp/otpauth://hotp/B?secret={SECRET}"),
            format!("otpauth://totp/A?x=otpauth://hotp/B?secret={SECRET}"),
            format!("otpauth://totp/A?secret=SHORT&u=otpauth://totp/B?secret={SECRET}"),
            format!("otpauth://totp/A?secret={SECRET}&secret={SECRET}"),
            format!("otpauth://totp/A?secret=bad&secret={SECRET}"),
            format!("otpauth://totp/A?note=secret={SECRET}&secret={SECRET}"),
            format!("otpauth://totp/otpauth://totp/A?secret={SECRET}"),
            // Unsupported, truncated and wrong-case type prefixes.
            format!("otpauth://totpx/A?secret={SECRET}"),
            "otpauth://tot".to_string(),
            "otpauth://totp".to_string(),
            "otpauth://".to_string(),
            format!("otpauth:/totp/A?secret={SECRET}"),
            format!("otpauth//totp/A?secret={SECRET}"),
            format!("OTPAUTH://totp/A?secret={SECRET}"),
            format!("otpauth://TOTP/A?secret={SECRET}"),
            format!("otpauth://Totp/A?secret={SECRET}"),
            format!("otpauth://push/A?secret={SECRET}"),
            format!("otpauth://hotp/A?secret={SECRET}"),
            // Percent-encoded and Unicode labels and neighbours.
            format!("otpauth://totp/Ex%20ample%3Aa%40b?secret={SECRET}"),
            format!("otpauth://totp/\u{d55c}\u{ae00}:\u{1f600}?secret={SECRET}"),
            format!("\u{d55c}otpauth://totp/A?secret={SECRET}"),
            format!("\u{1f600}otpauth://totp/A?secret={SECRET}"),
            format!("\u{e9}otpauth://totp/A?secret={SECRET}"),
            format!("a\u{301}otpauth://totp/A?secret={SECRET}"),
            format!("otpauth://totp/A?secret={SECRET}\u{d55c}"),
            format!("otpauth://totp/A?secret={SECRET}&k=\u{1f600}"),
            // Label and query bounds around 2,048 and 8,192.
            long_label(2_046),
            long_label(2_047),
            long_label(2_048),
            long_label(2_049),
            query_of(8_190),
            query_of(8_191),
            query_of(8_192),
            query_of(8_193),
        ];
        // Left-boundary byte before the scheme, every ASCII byte.
        for byte in 0u8..=127 {
            let c = char::from(byte);
            named.push(format!("{c}otpauth://totp/A?secret={SECRET}"));
            named.push(format!("{c}otpauth://hotp/A?secret={SECRET}{c}"));
            // Two URIs separated by every ASCII byte.
            named.push(format!(
                "otpauth://totp/A?secret={SECRET}{c}otpauth://hotp/B?secret={SECRET}"
            ));
        }
        named.push(format!(
            "otpauth://totp/A?secret={SECRET}otpauth://hotp/B?secret={SECRET}"
        ));
        for input in &named {
            assert_same(input);
        }
        // The bound cases really do straddle the limit (guards the test data).
        assert_eq!(detect(&long_label(2_048)).len(), 1);
        assert!(detect(&long_label(2_049)).is_empty());
        assert_eq!(detect(&query_of(8_192)).len(), 1);
        assert!(detect(&query_of(8_193)).is_empty());
    }

    const PIECES: &[&str] = &[
        "otpauth://totp/",
        "otpauth://hotp/",
        "otpauth://",
        "otpauth:/",
        "otpauth://push/",
        "OTPAUTH://TOTP/",
        "tot",
        "p/",
        "Example:a@b.c",
        "?",
        "secret=",
        SECRET,
        "NB2HI4DTHIXS6IDU",
        "SHORT",
        "&",
        "=",
        "/",
        " ",
        "\n",
        "#",
        "'",
        "x",
        "_",
        "-",
        "\u{e9}",
        "\u{d55c}",
        "\u{1f600}",
        "\u{301}",
    ];

    fn assert_every_window_same(input: &str) {
        let bounds: Vec<usize> = input
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(input.len()))
            .collect();
        for (n, &start) in bounds.iter().enumerate() {
            for &end in &bounds[n..] {
                assert_same(&input[start..end]);
            }
        }
    }

    #[test]
    fn generated_inputs_match_the_per_character_walk() {
        let mut rng = crate::test_rng::XorShift32::new(0x1146);
        for _ in 0..4_000 {
            assert_same(&rng.text(PIECES, 14));
        }
    }

    #[test]
    fn every_window_of_generated_inputs_matches_the_per_character_walk() {
        // An incremental session hands the detector arbitrary character-
        // aligned windows; comparing every `[start, end)` window of an input
        // covers every prefix, suffix and chunk partition of it.
        let mut rng = crate::test_rng::XorShift32::new(0x1147);
        for _ in 0..60 {
            assert_every_window_same(&rng.text(PIECES, 9));
        }
        assert_every_window_same(&format!(
            "x otpauth://push/a otpauth://totp/A:b?secret={SECRET}&i=\u{d55c} otpauth://hotp/B?secret=NB2HI4DTHIXS6IDU===\n"
        ));
    }

    #[test]
    fn sparse_and_dense_otp_inputs_match_the_per_character_walk() {
        let filler = "The quick brown fox, request id 12345, status ok; path /var/log/app.log\n";
        let uri =
            format!("otpauth://totp/Example:alice@example.com?secret={SECRET}&issuer=Example");
        for offset in [0usize, 1, 7, 8, 31, 32, 63, 64, 4_095, 4_096, 20_000] {
            let mut sparse = filler.repeat(offset / filler.len() + 1);
            sparse.truncate(offset);
            sparse.push_str(&uri);
            sparse.push_str(&filler.repeat(300));
            assert_same(&sparse);
            assert_same(&format!("{sparse}\u{d55c}\u{1f600}{uri}"));
        }
        let dense = format!("{uri}\n").repeat(400);
        assert_eq!(detect(&dense).len(), 400);
        assert_same(&dense);
        assert_same(&format!("\u{d55c}{uri}\n").repeat(400));
        let noise = "otpauth://push/x otpauth:/ otpauth://tot ".repeat(500);
        assert!(detect(&noise).is_empty());
        assert_same(&noise);
        assert_same(&"otpauth://".repeat(500));
        assert_same(&"otpauth://totp/".repeat(500));
    }
}
