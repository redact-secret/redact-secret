//! `pii:us:ssn` family contract v1.
//!
//! The detector recognizes only compact ASCII digits and the canonical
//! three-two-four hyphenated display form. The built-in validator applies the
//! current SSA structural exclusions; it deliberately does not replay the
//! pre-randomization High Group List or state allocation tables.

use unicode_normalization::char::is_combining_mark;

use super::{
    Alternative, ContextRequirement, IdentityDomain, IdentityState, PiiFamily, SensitivityState,
};
use crate::structured_validators::StructuredValidatorRegistry;
use crate::types::{ByteRange, Confidence, Obfuscation, Specificity};

const FAMILY_ID: &str = "pii:us:ssn";
const VALIDATOR_ID: &str = "us-ssn-allocation";
const VALIDATOR_VERSION: u16 = 1;
const COMPACT_BYTES: usize = 9;
const DISPLAY_BYTES: usize = 11;
const OCCURRENCE_EXCLUSIONS: &[&str] = &[
    "en-example-label",
    "en-us-ssn-negation",
    "ko-example-label",
    "ko-us-ssn-negation",
];

pub(super) struct UsSsnFamily;

impl PiiFamily for UsSsnFamily {
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
        detect_us_ssns(input)
    }
}

fn detect_us_ssns(input: &str) -> Vec<Alternative> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start].is_ascii_digit() || !valid_left_boundary(input, start) {
            start += 1;
            continue;
        }

        let Some((end, compact)) = parse_candidate(input, start) else {
            start += 1;
            continue;
        };
        if fully_delimited_reference(input, start, end) {
            start = end;
            continue;
        }
        let compact_value = core::str::from_utf8(&compact).ok();
        let validated = compact_value.and_then(|candidate| {
            StructuredValidatorRegistry::validate(VALIDATOR_ID, VALIDATOR_VERSION, candidate).ok()
        });
        if validated.is_some_and(|evidence| {
            evidence.provenance.identity == VALIDATOR_ID
                && evidence.provenance.version == VALIDATOR_VERSION
        }) && let Some(range) = ByteRange::new(start, end)
        {
            output.push(Alternative {
                family_id: FAMILY_ID,
                domain: IdentityDomain::NationalId,
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
    }
    output
}

fn parse_candidate(input: &str, start: usize) -> Option<(usize, [u8; COMPACT_BYTES])> {
    let bytes = input.as_bytes();
    let mut compact = [0_u8; COMPACT_BYTES];
    let display_end = start.checked_add(DISPLAY_BYTES)?;
    if let Some(display) = bytes.get(start..display_end)
        && display[0..3].iter().all(u8::is_ascii_digit)
        && display[3] == b'-'
        && display[4..6].iter().all(u8::is_ascii_digit)
        && display[6] == b'-'
        && display[7..11].iter().all(u8::is_ascii_digit)
        && valid_right_boundary(input, display_end)
    {
        compact[0..3].copy_from_slice(&display[0..3]);
        compact[3..5].copy_from_slice(&display[4..6]);
        compact[5..9].copy_from_slice(&display[7..11]);
        return Some((display_end, compact));
    }

    let compact_end = start.checked_add(COMPACT_BYTES)?;
    let candidate = bytes.get(start..compact_end)?;
    if candidate.iter().all(u8::is_ascii_digit) && valid_right_boundary(input, compact_end) {
        compact.copy_from_slice(candidate);
        return Some((compact_end, compact));
    }
    None
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
        || matches!(character, '_' | '%' | '-')
        || is_combining_mark(character)
        || character.is_whitespace() && !character.is_ascii()
        || is_unicode_dash(character)
        || is_governed_invisible(character)
}

fn is_unicode_dash(character: char) -> bool {
    matches!(
        character,
        '\u{058a}'
            | '\u{05be}'
            | '\u{1400}'
            | '\u{1806}'
            | '\u{2010}'..='\u{2015}'
            | '\u{2e17}'
            | '\u{2e1a}'
            | '\u{2e3a}'..='\u{2e3b}'
            | '\u{2e40}'
            | '\u{301c}'
            | '\u{3030}'
            | '\u{30a0}'
            | '\u{fe31}'..='\u{fe32}'
            | '\u{fe58}'
            | '\u{fe63}'
            | '\u{ff0d}'
    )
}

fn is_governed_invisible(character: char) -> bool {
    let code_point = character as u32;
    crate::invisible_table::INVISIBLE_RANGES
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&code_point))
}

fn fully_delimited_reference(input: &str, start: usize, end: usize) -> bool {
    (input[..start].ends_with("{{") && input[end..].starts_with("}}"))
        || (input[..start].ends_with("${") && input[end..].starts_with('}'))
        || (input[..start].ends_with('<') && input[end..].starts_with('>'))
}

#[cfg(test)]
mod tests {
    use super::detect_us_ssns;

    fn synthetic_compact() -> String {
        let mut hash = 0x811c_9dc5_u32;
        for byte in b"redact-secret-us-ssn-v1-fixture-879" {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        let mut area = 1 + hash % 898;
        if area >= 666 {
            area += 1;
        }
        let group = 1 + (hash / 898) % 99;
        let serial = 1 + (hash / (898 * 99)) % 9_999;
        format!("{area:03}{group:02}{serial:04}")
    }

    fn display(compact: &str) -> String {
        format!("{}-{}-{}", &compact[..3], &compact[3..5], &compact[5..])
    }

    fn ranges(input: &str) -> Vec<(usize, usize)> {
        detect_us_ssns(input)
            .into_iter()
            .map(|candidate| (candidate.range.start(), candidate.range.end()))
            .collect()
    }

    #[test]
    fn accepts_compact_and_canonical_display_forms() {
        let compact = synthetic_compact();
        let displayed = display(&compact);
        assert_eq!(ranges(&compact), [(0, 9)]);
        assert_eq!(ranges(&displayed), [(0, 11)]);
        assert_eq!(ranges(&format!("x={displayed};")), [(2, 13)]);
    }

    #[test]
    fn rejects_every_current_ssa_structural_exclusion() {
        for input in [
            "000-62-6879",
            "666-62-6879",
            "900-62-6879",
            "999-62-6879",
            "890-00-6879",
            "890-62-0000",
        ] {
            assert!(ranges(input).is_empty());
        }
    }

    #[test]
    fn rejects_malformed_display_adjacency_and_references() {
        let compact = synthetic_compact();
        let displayed = display(&compact);
        let area = &compact[..3];
        let group = &compact[3..5];
        let serial = &compact[5..];
        let cases = [
            format!("{area} {group} {serial}"),
            format!("{area}‐{group}‐{serial}"),
            format!("{area}--{group}-{serial}"),
            format!("{area}-{}-{serial}", &group[..1]),
            format!("{displayed}0"),
            format!("1{displayed}"),
            format!("x{displayed}"),
            format!("{displayed}x"),
            format!("_{displayed}"),
            format!("{displayed}_"),
            format!("%{displayed}"),
            format!("{displayed}%"),
            format!("⃝{displayed}"),
            format!("{displayed}⃝"),
            format!("{area}-{group}-‍{serial}"),
            format!("{{{{{displayed}}}}}"),
            format!("${{{compact}}}"),
            format!("<{compact}>"),
        ];
        for input in cases {
            assert!(ranges(&input).is_empty(), "length {}", input.len());
        }
    }

    #[test]
    fn scan_is_bounded_before_validation() {
        let input = "9".repeat(1_000_000);
        assert!(ranges(&input).is_empty());
    }
}
