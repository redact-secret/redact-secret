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

use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

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

struct OtpauthDetector;

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

        while position <= bytes.len() {
            let Some((prefix_start, prefix_end, signal)) =
                PREFIXES.iter().find_map(|&(prefix, signal)| {
                    let end = position + prefix.len();
                    (end <= bytes.len() && bytes[position..end] == *prefix.as_bytes())
                        .then_some((position, end, signal))
                })
            else {
                position += super::text::char_at(input, position).map_or(1, char::len_utf8);
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
                Candidate::new("otpauth_secret", Confidence::High, range)
                    .with_specificity(Specificity::Structural)
                    .with_signals(["otpauth-scheme", signal]),
            );
        }

        Ok(candidates)
    }
}

/// The structural `otpauth://` TOTP/HOTP secret detector.
#[must_use]
pub fn otpauth_detector() -> Box<dyn Detector> {
    Box::new(OtpauthDetector)
}

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
}
