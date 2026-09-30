//! `pii:global:iban` family contract v1.
//!
//! Country lengths are frozen from the SWIFT ISO 13616 IBAN Registry,
//! Release 103 (17 September 2026). The detector recognizes the registry's
//! electronic form and its four-character print grouping. It owns only that
//! bounded display normalization; the existing `iban-mod97` v1 validator
//! remains the authoritative checksum and compact lexical contract.

use unicode_normalization::char::is_combining_mark;

use super::{
    Alternative, ContextRequirement, IdentityDomain, IdentityState, PiiFamily, SensitivityState,
};
use crate::structured_validators::StructuredValidatorRegistry;
use crate::types::{ByteRange, Confidence, Obfuscation, Specificity};

const FAMILY_ID: &str = "pii:global:iban";
const VALIDATOR_ID: &str = "iban-mod97";
const VALIDATOR_VERSION: u16 = 1;
const MAX_COMPACT_BYTES: usize = 34;
const OCCURRENCE_EXCLUSIONS: &[&str] = &["en-example-label", "ko-example-label"];

/// ISO 3166-1 alpha-2/user-assigned prefix and exact electronic-form length.
///
/// The table is intentionally just the detector input needed from SWIFT's
/// registry, not a copy of contact, example-account, or other registry data.
/// It is bytewise sorted so lookup and review remain deterministic.
const COUNTRY_LENGTHS: &[([u8; 2], u8)] = &[
    (*b"AD", 24),
    (*b"AE", 23),
    (*b"AL", 28),
    (*b"AT", 20),
    (*b"AZ", 28),
    (*b"BA", 20),
    (*b"BE", 16),
    (*b"BG", 22),
    (*b"BH", 22),
    (*b"BI", 27),
    (*b"BR", 29),
    (*b"BY", 28),
    (*b"CH", 21),
    (*b"CR", 22),
    (*b"CY", 28),
    (*b"CZ", 24),
    (*b"DE", 22),
    (*b"DJ", 27),
    (*b"DK", 18),
    (*b"DO", 28),
    (*b"EE", 20),
    (*b"EG", 29),
    (*b"ES", 24),
    (*b"FI", 18),
    (*b"FK", 18),
    (*b"FO", 18),
    (*b"FR", 27),
    (*b"GB", 22),
    (*b"GE", 22),
    (*b"GI", 23),
    (*b"GL", 18),
    (*b"GR", 27),
    (*b"GT", 28),
    (*b"HN", 28),
    (*b"HR", 21),
    (*b"HU", 28),
    (*b"IE", 22),
    (*b"IL", 23),
    (*b"IQ", 23),
    (*b"IS", 26),
    (*b"IT", 27),
    (*b"JO", 30),
    (*b"KW", 30),
    (*b"KZ", 20),
    (*b"LB", 28),
    (*b"LC", 32),
    (*b"LI", 21),
    (*b"LT", 20),
    (*b"LU", 20),
    (*b"LV", 21),
    (*b"LY", 25),
    (*b"MC", 27),
    (*b"MD", 24),
    (*b"ME", 22),
    (*b"MK", 19),
    (*b"MN", 20),
    (*b"MR", 27),
    (*b"MT", 31),
    (*b"MU", 30),
    (*b"NI", 28),
    (*b"NL", 18),
    (*b"NO", 15),
    (*b"OM", 23),
    (*b"PK", 24),
    (*b"PL", 28),
    (*b"PS", 29),
    (*b"PT", 25),
    (*b"QA", 29),
    (*b"RO", 24),
    (*b"RS", 22),
    (*b"RU", 33),
    (*b"SA", 24),
    (*b"SC", 31),
    (*b"SD", 18),
    (*b"SE", 24),
    (*b"SI", 19),
    (*b"SK", 24),
    (*b"SM", 27),
    (*b"SO", 23),
    (*b"ST", 25),
    (*b"SV", 28),
    (*b"TL", 23),
    (*b"TN", 24),
    (*b"TR", 26),
    (*b"UA", 29),
    (*b"VA", 22),
    (*b"VG", 24),
    (*b"XK", 20),
    (*b"YE", 30),
];

pub(super) struct IbanFamily;

impl PiiFamily for IbanFamily {
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
        detect_ibans(input)
    }
}

fn detect_ibans(input: &str) -> Vec<Alternative> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut start = 0;
    while start + 4 <= bytes.len() {
        if bytes[start].is_ascii_uppercase()
            && bytes[start + 1].is_ascii_uppercase()
            && bytes[start + 2].is_ascii_digit()
            && bytes[start + 3].is_ascii_digit()
            && valid_left_boundary(input, start)
            && let Some(end) = parse_candidate(input, start)
        {
            if !fully_delimited_reference(input, start, end)
                && let Some(range) = ByteRange::new(start, end)
            {
                output.push(Alternative {
                    family_id: FAMILY_ID,
                    domain: IdentityDomain::Iban,
                    range,
                    identity: IdentityState::Established,
                    identity_confidence: Confidence::High,
                    identity_specificity: Specificity::Structural,
                    sensitivity: SensitivityState::NotEstablished,
                    sensitivity_confidence: Confidence::High,
                    sensitivity_specificity: Specificity::Contextual,
                    obfuscation: Obfuscation::None,
                    reject_invisible_normalization: true,
                });
            }
            start = end;
            continue;
        }
        start += 1;
    }
    output
}

fn parse_candidate(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let expected_len = country_length([bytes[start], bytes[start + 1]])?;
    let mut compact = [0_u8; MAX_COMPACT_BYTES];
    compact[..4].copy_from_slice(&bytes[start..start + 4]);

    let mut compact_len = 4;
    let mut cursor = start + 4;
    let print_form = bytes.get(cursor) == Some(&b' ');
    if print_form {
        cursor += 1;
    }

    while compact_len < expected_len {
        let group_len = if print_form {
            (expected_len - compact_len).min(4)
        } else {
            expected_len - compact_len
        };
        let group_end = cursor.checked_add(group_len)?;
        let group = bytes.get(cursor..group_end)?;
        if !group.iter().all(u8::is_ascii_alphanumeric) {
            return None;
        }
        compact[compact_len..compact_len + group_len].copy_from_slice(group);
        compact_len += group_len;
        cursor = group_end;
        if print_form && compact_len < expected_len {
            if bytes.get(cursor) != Some(&b' ') || bytes.get(cursor + 1) == Some(&b' ') {
                return None;
            }
            cursor += 1;
        }
    }

    if !valid_right_boundary(input, cursor) {
        return None;
    }
    let compact_value = core::str::from_utf8(&compact[..expected_len]).ok()?;
    let evidence =
        StructuredValidatorRegistry::validate(VALIDATOR_ID, VALIDATOR_VERSION, compact_value)
            .ok()?;
    if evidence.provenance.identity != VALIDATOR_ID
        || evidence.provenance.version != VALIDATOR_VERSION
    {
        return None;
    }
    Some(cursor)
}

fn country_length(country: [u8; 2]) -> Option<usize> {
    COUNTRY_LENGTHS
        .binary_search_by_key(&country, |(code, _)| *code)
        .ok()
        .map(|index| usize::from(COUNTRY_LENGTHS[index].1))
}

fn valid_left_boundary(input: &str, start: usize) -> bool {
    input[..start]
        .chars()
        .next_back()
        .is_none_or(|character| !blocks_boundary(character))
}

fn valid_right_boundary(input: &str, end: usize) -> bool {
    input[end..]
        .chars()
        .next()
        .is_none_or(|character| !blocks_boundary(character))
}

fn blocks_boundary(character: char) -> bool {
    character.is_alphanumeric()
        || matches!(character, '_' | '%')
        || is_combining_mark(character)
        || crate::normalize::is_invisible(character)
}

fn fully_delimited_reference(input: &str, start: usize, end: usize) -> bool {
    (input[..start].ends_with("{{") && input[end..].starts_with("}}"))
        || (input[..start].ends_with("${") && input[end..].starts_with('}'))
        || (input[..start].ends_with('<') && input[end..].starts_with('>'))
}

#[cfg(test)]
mod tests {
    use super::{COUNTRY_LENGTHS, MAX_COMPACT_BYTES, country_length, detect_ibans};

    fn compact_values(input: &str) -> Vec<(usize, usize)> {
        detect_ibans(input)
            .into_iter()
            .map(|candidate| (candidate.range.start(), candidate.range.end()))
            .collect()
    }

    fn synthetic_iban(country: [u8; 2], total_len: usize) -> String {
        let bban_len = total_len - 4;
        let mut bban = String::from("SYNX");
        bban.extend(std::iter::repeat_n('0', bban_len - bban.len()));

        let mut remainder = 0_u16;
        for byte in bban.bytes().chain(country).chain(b"00".iter().copied()) {
            if byte.is_ascii_digit() {
                remainder = (remainder * 10 + u16::from(byte - b'0')) % 97;
            } else {
                let expanded = byte - b'A' + 10;
                remainder = (remainder * 10 + u16::from(expanded / 10)) % 97;
                remainder = (remainder * 10 + u16::from(expanded % 10)) % 97;
            }
        }

        format!(
            "{}{}{:02}{bban}",
            char::from(country[0]),
            char::from(country[1]),
            98 - remainder
        )
    }

    #[test]
    fn release_103_country_lengths_are_sorted_unique_and_exact() {
        assert_eq!(COUNTRY_LENGTHS.len(), 89);
        assert!(COUNTRY_LENGTHS.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for (country, expected) in COUNTRY_LENGTHS {
            assert_eq!(country_length(*country), Some(usize::from(*expected)));
            assert!((15..=MAX_COMPACT_BYTES).contains(&usize::from(*expected)));
        }
        // `PF` is listed only as a territory included by France; Release 103
        // does not register `PF` (or the transposed `FP`) as an IBAN prefix.
        for unknown in [*b"AA", *b"FP", *b"PF", *b"US", *b"ZZ"] {
            assert_eq!(country_length(unknown), None);
            assert!(compact_values(&synthetic_iban(unknown, 22)).is_empty());
        }
    }

    #[test]
    fn every_release_103_row_accepts_only_its_exact_country_length() {
        for (country, expected) in COUNTRY_LENGTHS {
            let expected = usize::from(*expected);
            let exact = synthetic_iban(*country, expected);
            assert_eq!(compact_values(&exact), vec![(0, expected)]);

            let wrong_len = if expected == 15 { 16 } else { expected - 1 };
            let checksum_valid_wrong_length = synthetic_iban(*country, wrong_len);
            assert!(
                compact_values(&checksum_valid_wrong_length).is_empty(),
                "{}{} expected={expected} wrong={wrong_len}",
                char::from(country[0]),
                char::from(country[1])
            );
        }
    }

    #[test]
    fn compact_and_print_forms_preserve_the_exact_original_range() {
        let compact = "GB18SYNX00000000000000";
        assert_eq!(compact_values(compact), vec![(0, compact.len())]);
        let print = "GB18 SYNX 0000 0000 0000 00";
        assert_eq!(compact_values(print), vec![(0, print.len())]);
        let wrapped = format!("🔒iban: {print}; done");
        let start = wrapped.find("GB18").unwrap();
        assert_eq!(compact_values(&wrapped), vec![(start, start + print.len())]);
    }

    #[test]
    fn rejects_every_wrong_length_and_malformed_display_neighbor() {
        let compact = "GB18SYNX00000000000000";
        for cut in 4..compact.len() {
            assert!(compact_values(&compact[..cut]).is_empty(), "cut={cut}");
        }
        for extra in ["A", "0", "_", "%", "é", "⃝", "\u{200d}"] {
            assert!(compact_values(&format!("{compact}{extra}")).is_empty());
            assert!(compact_values(&format!("{extra}{compact}")).is_empty());
        }
        for malformed in [
            "gb18SYNX00000000000000",
            "GB18-SYNX-0000-0000-0000-00",
            "GB18  SYNX 0000 0000 0000 00",
            "GB18\tSYNX00000000000000",
            "GB18 SYNX0000 0000 0000 00",
            "GB18 SYNX 0000 0000 0000 000",
            "ZZ75SYNTHETIC878X4Z9Q7",
        ] {
            assert!(compact_values(malformed).is_empty(), "{malformed}");
        }
    }

    #[test]
    fn checksum_mismatch_and_whole_references_are_not_findings() {
        let valid = "GB18SYNX00000000000000";
        assert!(compact_values("GB00SYNX00000000000000").is_empty());
        for reference in [
            format!("{{{{{valid}}}}}"),
            format!("${{{valid}}}"),
            format!("<{valid}>"),
        ] {
            assert!(compact_values(&reference).is_empty());
        }
    }
}
