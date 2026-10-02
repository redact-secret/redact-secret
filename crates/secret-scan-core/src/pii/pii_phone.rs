//! Conservative E.164/NANP phone family contract v1.
//!
//! V1 recognizes only the frozen `+1` and NANP display subset documented in
//! the family contract. Structure establishes identity, never sensitivity:
//! a public finding still requires associated reviewed high-signal context.

use super::{
    Alternative, ContextRequirement, IdentityDomain, IdentityState, PiiFamily, SensitivityState,
};
use crate::types::{ByteRange, Confidence, Obfuscation, Specificity};
use unicode_normalization::char::is_combining_mark;

const FAMILY_ID: &str = "pii:global:phone";
const OCCURRENCE_EXCLUSIONS: &[&str] = &["en-example-label", "ko-example-label"];
const MAX_MAIN_BYTES: usize = 18;
const MAX_EXTENSION_BYTES: usize = 17;
const MAX_CANDIDATE_BYTES: usize = MAX_MAIN_BYTES + MAX_EXTENSION_BYTES;

pub(super) struct PhoneFamily;

impl PiiFamily for PhoneFamily {
    fn id(&self) -> &'static str {
        FAMILY_ID
    }

    fn context_requirement(&self) -> ContextRequirement {
        ContextRequirement::RequiredForSensitiveClassification
    }

    fn occurrence_exclusions(&self) -> &'static [&'static str] {
        OCCURRENCE_EXCLUSIONS
    }

    fn reject_invisible_normalization(&self) -> bool {
        true
    }

    fn detect(&self, input: &str) -> Vec<Alternative> {
        detect_phones(input)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    Full,
    Local,
}

struct ParsedCandidate {
    end: usize,
    digits: [u8; 10],
    digit_count: usize,
    form: Form,
}

fn detect_phones(input: &str) -> Vec<Alternative> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !matches!(bytes[index], b'+' | b'(' | b'0'..=b'9') || !left_boundary(input, index) {
            index += 1;
            continue;
        }
        if let Some(candidate) = parse_candidate(input, index) {
            let sensitivity = if reserved_555_control(&candidate) {
                SensitivityState::NonSensitive
            } else {
                SensitivityState::NotEstablished
            };
            let identity_confidence = match candidate.form {
                Form::Full => Confidence::High,
                Form::Local => Confidence::Medium,
            };
            if let Some(range) = ByteRange::new(index, candidate.end) {
                output.push(Alternative {
                    family_id: FAMILY_ID,
                    domain: IdentityDomain::Phone,
                    range,
                    identity: IdentityState::Established,
                    identity_confidence,
                    identity_specificity: Specificity::Structural,
                    sensitivity,
                    sensitivity_confidence: Confidence::High,
                    sensitivity_specificity: Specificity::Contextual,
                    obfuscation: Obfuscation::None,
                    reject_invisible_normalization: true,
                });
            }
            index = candidate.end;
        } else {
            index = malformed_display_end(bytes, index).max(index + 1);
        }
    }
    output
}

fn malformed_display_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len()
        && end - start <= MAX_CANDIDATE_BYTES
        && (bytes[end].is_ascii_digit()
            || matches!(bytes[end], b' ' | b'+' | b'-' | b'(' | b')' | b'.' | b'/'))
    {
        end += 1;
    }
    end
}

fn parse_candidate(input: &str, start: usize) -> Option<ParsedCandidate> {
    let remaining = input.get(start..)?;
    let (main_len, digits, digit_count, form) = parse_main(remaining)?;
    if main_len > MAX_MAIN_BYTES {
        return None;
    }
    let main_end = start.checked_add(main_len)?;
    let end = parse_extension(input, main_end, form)?;
    if end - start > MAX_CANDIDATE_BYTES || !right_boundary(input, end) {
        return None;
    }
    Some(ParsedCandidate {
        end,
        digits,
        digit_count,
        form,
    })
}

fn parse_main(value: &str) -> Option<(usize, [u8; 10], usize, Form)> {
    let bytes = value.as_bytes();
    // Exact shape guard (#1167): a digit at byte 0 and a digit at byte 3 can
    // only be the compact ten-digit display. Every other non-`+1` pattern
    // puts `' '` or `'-'` at byte 3, except `(###) ###-####`, whose byte 3 is
    // a digit but whose byte 0 is `(`; the first-byte guard keeps that form
    // on the general path. `+1` forms start with `+`, so they never match.
    if bytes.len() >= 4 && bytes[0].is_ascii_digit() && bytes[3].is_ascii_digit() {
        return parse_compact_ten(bytes);
    }
    parse_main_general(bytes)
}

fn parse_compact_ten(bytes: &[u8]) -> Option<(usize, [u8; 10], usize, Form)> {
    let mut digits = [0_u8; 10];
    match_pattern(bytes, b"##########", &mut digits)?;
    valid_full_digits(&digits).then_some((10, digits, 10, Form::Full))
}

fn parse_main_general(bytes: &[u8]) -> Option<(usize, [u8; 10], usize, Form)> {
    let mut digits = [0_u8; 10];

    if bytes.starts_with(b"+1") {
        for (pattern, compact) in [
            ("+1##########", true),
            ("+1 ### ### ####", false),
            ("+1-###-###-####", false),
        ] {
            if let Some(length) = match_pattern(bytes, pattern.as_bytes(), &mut digits)
                && valid_full_digits(&digits)
            {
                return Some((length, digits, 10, Form::Full));
            }
            if compact {
                digits.fill(0);
            }
        }
        return None;
    }

    for pattern in [
        "##########",
        "### ### ####",
        "###-###-####",
        "(###) ###-####",
    ] {
        if let Some(length) = match_pattern(bytes, pattern.as_bytes(), &mut digits)
            && valid_full_digits(&digits)
        {
            return Some((length, digits, 10, Form::Full));
        }
        digits.fill(0);
    }

    if let Some(length) = match_pattern(bytes, b"###-####", &mut digits)
        && valid_exchange(&digits[..3])
    {
        return Some((length, digits, 7, Form::Local));
    }
    None
}

fn match_pattern(bytes: &[u8], pattern: &[u8], digits: &mut [u8; 10]) -> Option<usize> {
    let candidate = bytes.get(..pattern.len())?;
    let mut digit_index = 0;
    for (actual, expected) in candidate.iter().zip(pattern) {
        if *expected == b'#' {
            if !actual.is_ascii_digit() || digit_index == digits.len() {
                return None;
            }
            digits[digit_index] = *actual;
            digit_index += 1;
        } else if actual != expected {
            return None;
        }
    }
    Some(pattern.len())
}

fn valid_full_digits(digits: &[u8; 10]) -> bool {
    valid_exchange(&digits[..3]) && valid_exchange(&digits[3..6])
}

fn valid_exchange(digits: &[u8]) -> bool {
    matches!(digits, [b'2'..=b'9', b'0'..=b'9', b'0'..=b'9'])
        && !(digits[1] == b'1' && digits[2] == b'1')
}

fn parse_extension(input: &str, main_end: usize, form: Form) -> Option<usize> {
    let suffix = input.get(main_end..)?;
    let extension_like = has_extension_like_continuation(suffix);
    if !extension_like {
        return Some(main_end);
    }
    if form == Form::Local {
        return None;
    }
    let prefix_len = [" extension ", " ext. ", " ext "]
        .into_iter()
        .find_map(|prefix| suffix.starts_with(prefix).then_some(prefix.len()))?;
    let digit_start = main_end + prefix_len;
    let bytes = input.as_bytes();
    let mut end = digit_start;
    while end < bytes.len() && end - digit_start <= 6 && bytes[end].is_ascii_digit() {
        end += 1;
    }
    let count = end - digit_start;
    if !(1..=6).contains(&count)
        || bytes.get(end).is_some_and(u8::is_ascii_digit)
        || has_extension_like_continuation(input.get(end..)?)
    {
        return None;
    }
    Some(end)
}

fn has_extension_like_continuation(suffix: &str) -> bool {
    if let Some(payload) = strip_ascii_case_insensitive_prefix(suffix, ";ext=") {
        return payload.is_empty() || payload.as_bytes().first().is_some_and(u8::is_ascii_digit);
    }
    let Some(after_space) = suffix.strip_prefix(' ') else {
        return false;
    };
    let marker = after_space.trim_start_matches(' ');
    if let Some(payload) = strip_ascii_case_insensitive_prefix(marker, "x") {
        return payload.as_bytes().first().is_some_and(u8::is_ascii_digit);
    }
    if let Some(payload) = marker.strip_prefix('#') {
        return payload.as_bytes().first().is_some_and(u8::is_ascii_digit);
    }
    ["extension", "ext.", "ext"]
        .into_iter()
        .any(|name| has_word_extension_marker(marker, name))
}

fn starts_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn strip_ascii_case_insensitive_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    starts_ascii_case_insensitive(value, prefix).then(|| &value[prefix.len()..])
}

fn has_word_extension_marker(value: &str, name: &str) -> bool {
    let Some(rest) = strip_ascii_case_insensitive_prefix(value, name) else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    if !rest.as_bytes()[0].is_ascii_whitespace() {
        return false;
    }
    // The payload is read on the marker's own line: a line break ends it
    // exactly as the end of the input does, so a marker at a line end is an
    // empty extension whatever the next line holds, and a scan of that line
    // alone agrees with a scan of the whole input (issue #990).
    let payload = rest.trim_start_matches(|character: char| {
        character.is_ascii_whitespace() && !matches!(character, '\n' | '\r')
    });
    payload.is_empty()
        || payload
            .as_bytes()
            .first()
            .is_some_and(|&byte| byte.is_ascii_digit() || matches!(byte, b'\n' | b'\r'))
}

fn reserved_555_control(candidate: &ParsedCandidate) -> bool {
    let (exchange_start, line_start) = match candidate.digit_count {
        10 => (3, 6),
        7 => (0, 3),
        _ => return false,
    };
    candidate.digits[exchange_start..line_start] == *b"555"
        && candidate.digits[line_start..line_start + 2] == *b"01"
}

fn left_boundary(input: &str, start: usize) -> bool {
    let prefix = &input[..start];
    if prefix
        .get(prefix.len().saturating_sub(4)..)
        .is_some_and(|scheme| {
            scheme.eq_ignore_ascii_case("tel:") || scheme.eq_ignore_ascii_case("sms:")
        })
    {
        return false;
    }
    if start >= 2
        && input.as_bytes()[start - 1] == b' '
        && input.as_bytes()[start - 2].is_ascii_digit()
    {
        return false;
    }
    input[..start].chars().next_back().is_none_or(|character| {
        !character.is_alphanumeric()
            && !matches!(character, '_' | '-' | '%' | '+' | '(' | ')' | '.' | '/')
            && !is_combining_mark(character)
    })
}

fn right_boundary(input: &str, end: usize) -> bool {
    input[end..].chars().next().is_none_or(|character| {
        !character.is_alphanumeric()
            && !matches!(character, '_' | '-' | '%' | '+' | '(' | ')' | '.' | '/')
            && !is_combining_mark(character)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-#1167 `parse_main`, kept verbatim as the differential oracle.
    fn parse_main_oracle(value: &str) -> Option<(usize, [u8; 10], usize, Form)> {
        let bytes = value.as_bytes();
        let mut digits = [0_u8; 10];

        if bytes.starts_with(b"+1") {
            for (pattern, compact) in [
                ("+1##########", true),
                ("+1 ### ### ####", false),
                ("+1-###-###-####", false),
            ] {
                if let Some(length) = match_pattern(bytes, pattern.as_bytes(), &mut digits)
                    && valid_full_digits(&digits)
                {
                    return Some((length, digits, 10, Form::Full));
                }
                if compact {
                    digits.fill(0);
                }
            }
            return None;
        }

        for pattern in [
            "##########",
            "### ### ####",
            "###-###-####",
            "(###) ###-####",
        ] {
            if let Some(length) = match_pattern(bytes, pattern.as_bytes(), &mut digits)
                && valid_full_digits(&digits)
            {
                return Some((length, digits, 10, Form::Full));
            }
            digits.fill(0);
        }

        if let Some(length) = match_pattern(bytes, b"###-####", &mut digits)
            && valid_exchange(&digits[..3])
        {
            return Some((length, digits, 7, Form::Local));
        }
        None
    }

    fn assert_same(value: &str) {
        assert_eq!(parse_main(value), parse_main_oracle(value), "{value:?}");
    }

    #[test]
    fn compact_guard_matches_the_oracle_on_named_shapes() {
        for input in [
            "",
            "2",
            "21",
            "212",
            "2125",
            "212555234",
            "2125552345",
            "21255523456",
            "2125552345x",
            "1125552345",
            "2115552345",
            "2121552345",
            "2125512345",
            "2125552345 ext 1",
            "212 555 2345",
            "212-555-2345",
            "(212) 555-2345",
            "(212)555-2345",
            "(2125552345",
            "(212",
            "(2125",
            "555-2345",
            "555-23456",
            "+12125552345",
            "+1 212 555 2345",
            "+1-212-555-2345",
            "+1212555234",
            "+2125552345",
            "212555-2345",
            "2125-552345",
            "212 5552345",
            "212)555-2345",
            "2a25552345",
            "212a552345",
            "2125552a45",
            "212555234\u{e9}",
            "212\u{ff15}552345",
            "\u{ff12}125552345",
            "212.555.2345",
            " 2125552345",
            "9889882345",
            "0125552345",
            "1125552345",
            "9999999999",
            "2002002000",
        ] {
            assert_same(input);
        }
    }

    #[test]
    fn compact_guard_matches_the_oracle_for_every_first_four_byte_class() {
        // Representative byte per class at each of the first four positions
        // and a following digit run, so every guard outcome is covered.
        let alphabet: &[u8] = b"0123456789+()- .a\xc3";
        let tails = [
            "",
            "5552345",
            "555-2345",
            ") 555-2345",
            " 555 2345",
            "-555-2345",
        ];
        let mut buffer = [0_u8; 4];
        let total = alphabet.len().pow(4);
        for n in 0..total {
            let mut m = n;
            for slot in &mut buffer {
                *slot = alphabet[m % alphabet.len()];
                m /= alphabet.len();
            }
            for tail in tails {
                let mut bytes = buffer.to_vec();
                bytes.extend_from_slice(tail.as_bytes());
                if let Ok(text) = core::str::from_utf8(&bytes) {
                    assert_same(text);
                }
            }
        }
    }

    #[test]
    fn compact_guard_matches_the_oracle_for_every_digit_boundary() {
        // Every exchange-code leading digit and the N11 rule, both exchanges,
        // in all four displays, plus truncation at every length.
        for first in b'0'..=b'9' {
            for second in b'0'..=b'9' {
                for third in b'0'..=b'9' {
                    let area = [first, second, third];
                    let area = core::str::from_utf8(&area).unwrap();
                    for display in [
                        format!("{area}5552345"),
                        format!("{area} 555 2345"),
                        format!("{area}-555-2345"),
                        format!("({area}) 555-2345"),
                        format!("{area}-2345"),
                        format!("+1{area}5552345"),
                        format!("5552345{area}"),
                        format!("555{area}2345"),
                    ] {
                        for cut in 0..=display.len() {
                            assert_same(&display[..cut]);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn accepts_only_frozen_full_and_local_displays() {
        for input in [
            "+12125552345",
            "+1 212 555 2345",
            "+1-212-555-2345",
            "2125552345",
            "212 555 2345",
            "212-555-2345",
            "988-988-2345",
            "(212) 555-2345",
            "555-2345",
        ] {
            assert_eq!(detect_phones(input).len(), 1, "{input}");
        }
    }

    #[test]
    fn an_extension_marker_at_a_line_end_is_judged_on_its_own_line() {
        // Issue #990: what follows the line break never decides, so a scan
        // of the line alone agrees with a scan of the whole input.
        for input in [
            "212-555-2345 ext\nhello",
            "212-555-2345 ext\n123",
            "212-555-2345 ext. \r\nhello",
            "212-555-2345 extension\rhello",
            "212-555-2345 ext\n",
        ] {
            assert!(detect_phones(input).is_empty(), "{input:?}");
        }
        assert_eq!(detect_phones("212-555-2345 extra\nhello").len(), 1);
    }

    #[test]
    fn extensions_are_full_form_only_and_strictly_bounded() {
        for input in [
            "212-555-2345 ext 7",
            "212-555-2345 ext. 123456",
            "+12125552345 extension 42",
        ] {
            let found = detect_phones(input);
            assert_eq!(found.len(), 1, "{input}");
            assert_eq!(found[0].range.end(), input.len());
        }
        for input in [
            "212-555-2345 ext ",
            "212-555-2345 ext. 1234567",
            "212-555-2345 extension 1234567",
            "555-2345 ext 1",
            "212-555-2345 x7",
            "212-555-2345 EXT 7",
            "212-555-2345;ext=7",
            "212-555-2345 ext 123 ext 4",
            "212-555-2345 ext 123  ext 4",
            "212-555-2345 ext 123 x7",
            "212-555-2345 extension 123 #4",
            "212-555-2345 ext 123;ext=4",
        ] {
            assert!(detect_phones(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn extension_marker_prefixes_in_ordinary_prose_do_not_suppress_a_phone() {
        for input in [
            "212-555-2345 extra details",
            "212-555-2345 ext notes",
            "212-555-2345 xylophone notes",
        ] {
            let found = detect_phones(input);
            assert_eq!(found.len(), 1, "{input}");
            assert_eq!(found[0].range.end(), "212-555-2345".len());
        }
    }

    #[test]
    fn n11_and_unsupported_or_mixed_forms_are_rejected() {
        for input in [
            "211-555-2345",
            "212-911-2345",
            "911-2345",
            "+82 2 1234 5678",
            "1-212-555-2345",
            "212.555.2345",
            "212 555-2345",
            "212/555/2345",
            "5552345",
            "+1 (212) 555-2345",
            "tel:+12125552345",
            "SMS:+12125552345",
        ] {
            assert!(detect_phones(input).is_empty(), "{input}");
        }
        for n in b'2'..=b'9' {
            let n11 = format!("{}11", char::from(n));
            assert!(detect_phones(&format!("{n11}-234-5678")).is_empty());
            assert!(detect_phones(&format!("555-{n11}-2345")).is_empty());
        }
        for accepted in ["200-200-0000", "999-999-9999", "988-988-2345"] {
            assert_eq!(detect_phones(accepted).len(), 1, "{accepted}");
        }
        for rejected in ["199-234-5678", "555-199-2345", "099-234-5678"] {
            assert!(detect_phones(rejected).is_empty(), "{rejected}");
        }
    }

    #[test]
    fn whole_reserved_exchange_and_line_is_non_sensitive_and_extension_is_ignored() {
        for input in [
            "212-555-0100",
            "+1 212 555 0199",
            "555-0100",
            "212-555-0100 ext 123",
        ] {
            let found = detect_phones(input);
            assert_eq!(found.len(), 1, "{input}");
            assert_eq!(found[0].sensitivity, SensitivityState::NonSensitive);
        }
        for input in ["212-555-0099", "212-555-0200", "212-555-01000"] {
            let found = detect_phones(input);
            if input.ends_with('0') && input.len() > "212-555-0199".len() {
                assert!(found.is_empty(), "{input}");
            } else {
                assert_eq!(found[0].sensitivity, SensitivityState::NotEstablished);
            }
        }
    }

    #[test]
    fn barriers_prevent_partial_candidates_and_scanner_is_bounded() {
        for input in [
            "A212-555-2345",
            "_212-555-2345",
            "9-212-555-2345",
            "212-555-2345Z",
            "212-555-2345_",
            "212-555-2345-6",
            "212\u{200b}-555-2345",
        ] {
            assert!(detect_phones(input).is_empty(), "{input}");
        }
        let long = format!("212-555-2345 extension {}", "7".repeat(10_000));
        assert!(detect_phones(&long).is_empty());
    }
}
