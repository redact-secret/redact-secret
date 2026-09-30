//! Conservative ISO/IEC 7812 payment-card family contract v1.
//!
//! Identity is limited to the reviewed payment-brand ranges and lengths in
//! the family contract, then validated by the existing `luhn` v1 structured
//! validator. Assignment, issuance, activity, and sensitivity are separate:
//! a public finding still requires reviewed high-signal payment-card context.

use super::{
    Alternative, ContextRequirement, IdentityDomain, IdentityState, PiiFamily, SensitivityState,
};
use crate::structured_validators::StructuredValidatorRegistry;
use crate::types::{ByteRange, Confidence, Obfuscation, Specificity};
use unicode_normalization::char::is_combining_mark;

const FAMILY_ID: &str = "pii:global:payment-card";
const MIN_PAN_DIGITS: usize = 10;
const MAX_PAN_DIGITS: usize = 19;
const MAX_SEPARATORS: usize = 4;
const MAX_DISPLAY_BYTES: usize = MAX_PAN_DIGITS + MAX_SEPARATORS;
const OCCURRENCE_EXCLUSIONS: &[&str] = &["en-example-label", "ko-example-label"];

// Visa Acceptance Solutions publishes these complete values solely for its
// test services. This is the subset for the five brands the positive grammar
// supports, not the page's wider suite (for example, Maestro is omitted).
// Exact whole-value comparison is deliberate: a shared prefix, suffix,
// substring, or lookalike has no negative authority.
const SUPPORTED_BRAND_TEST_PANS: &[&str] = &[
    "2222420000001113",
    "2222630000001125",
    "3566111111111113",
    "378282246310005",
    "4111111111111111",
    "5555555555554444",
    "6011111111111117",
];

pub(super) struct PaymentCardFamily;

impl PiiFamily for PaymentCardFamily {
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
        detect_payment_cards(input)
    }
}

fn detect_payment_cards(input: &str) -> Vec<Alternative> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() || !left_boundary(input, index) {
            index += 1;
            continue;
        }

        let run_end = display_run_end(bytes, index);
        let mut end = run_end;
        while end > index && is_separator(bytes[end - 1]) {
            end -= 1;
        }
        if end > index
            && end - index <= MAX_DISPLAY_BYTES
            && right_boundary(input, end)
            && let Some(digits) = normalize_display(&input[index..end])
            && supported_payment_range(digits.as_bytes())
            && StructuredValidatorRegistry::validate("luhn", 1, digits.as_str()).is_ok()
            && let Some(range) = ByteRange::new(index, end)
        {
            let sensitivity = if SUPPORTED_BRAND_TEST_PANS.contains(&digits.as_str()) {
                SensitivityState::NonSensitive
            } else {
                SensitivityState::NotEstablished
            };
            output.push(Alternative {
                family_id: FAMILY_ID,
                domain: IdentityDomain::PaymentCard,
                range,
                identity: IdentityState::Established,
                identity_confidence: Confidence::High,
                identity_specificity: Specificity::Structural,
                sensitivity,
                sensitivity_confidence: Confidence::High,
                sensitivity_specificity: Specificity::Contextual,
                obfuscation: Obfuscation::None,
                reject_invisible_normalization: true,
            });
        }
        index = run_end.max(index + 1);
    }
    output
}

fn display_run_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len()
        && end - start <= MAX_DISPLAY_BYTES
        && (bytes[end].is_ascii_digit() || is_separator(bytes[end]))
    {
        end += 1;
    }
    if end - start > MAX_DISPLAY_BYTES {
        while end < bytes.len() && (bytes[end].is_ascii_digit() || is_separator(bytes[end])) {
            end += 1;
        }
    }
    end
}

/// The digits of one display-form card number, held on the stack: at most
/// [`MAX_PAN_DIGITS`] ASCII digits, so no heap copy of the number exists.
struct PanDigits {
    buffer: [u8; MAX_PAN_DIGITS],
    len: usize,
}

impl PanDigits {
    fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    fn as_str(&self) -> &str {
        // The buffer only ever holds ASCII digits.
        std::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }
}

fn normalize_display(display: &str) -> Option<PanDigits> {
    let bytes = display.as_bytes();
    let mut digits = PanDigits {
        buffer: [0; MAX_PAN_DIGITS],
        len: 0,
    };
    // Digits seen, counted past the buffer so an over-long run is rejected.
    let mut seen = 0_usize;
    let mut separator = None;
    let mut separators = 0;
    let mut group_digits = 0;
    let mut group_lengths = [0_usize; 5];
    let mut groups = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_digit() {
            if let Some(slot) = digits.buffer.get_mut(seen) {
                *slot = byte;
                digits.len = seen + 1;
            }
            seen += 1;
            group_digits += 1;
            continue;
        }
        if !is_separator(byte)
            || index == 0
            || index + 1 == bytes.len()
            || separators == MAX_SEPARATORS
            || separator.is_some_and(|existing| existing != byte)
        {
            return None;
        }
        group_lengths[groups] = group_digits;
        groups += 1;
        separator = Some(byte);
        separators += 1;
        group_digits = 0;
    }
    if separator.is_some() {
        group_lengths[groups] = group_digits;
        groups += 1;
        if !matches!(&group_lengths[..groups], [4, 4, 4, 4] | [4, 6, 5]) {
            return None;
        }
    }
    (MIN_PAN_DIGITS..=MAX_PAN_DIGITS)
        .contains(&seen)
        .then_some(digits)
}

fn supported_payment_range(digits: &[u8]) -> bool {
    if let Ok(value) = std::str::from_utf8(digits)
        && SUPPORTED_BRAND_TEST_PANS.contains(&value)
    {
        return true;
    }
    let length = digits.len();
    let prefix = |count: usize| -> Option<u32> {
        let mut value = 0_u32;
        for byte in digits.get(..count)? {
            value = value * 10 + u32::from(*byte - b'0');
        }
        Some(value)
    };

    // Frozen to the Visa Acceptance Solutions card-type table retrieved on
    // 2026-09-27. This recognizes a payment-brand range, not an assigned IIN.
    (length == 15 && matches!(prefix(2), Some(34 | 37)))
        || (length == 16
            && matches!(
                prefix(6),
                Some(
                    601_100..=601_109
                    | 601_120..=601_149
                    | 601_174
                    | 601_177..=601_179
                    | 601_186..=601_199
                    | 644_000..=659_999,
                )
            ))
        || ((16..=19).contains(&length) && matches!(prefix(4), Some(3_528..=3_589)))
        || (length == 16 && matches!(prefix(6), Some(510_000..=559_999 | 222_100..=272_099)))
        || ((MIN_PAN_DIGITS..=MAX_PAN_DIGITS).contains(&length) && digits[0] == b'4')
}

fn left_boundary(input: &str, start: usize) -> bool {
    input[..start].chars().next_back().is_none_or(|character| {
        !character.is_alphanumeric()
            && !matches!(character, '_' | '-' | '%')
            && !is_combining_mark(character)
    })
}

fn right_boundary(input: &str, end: usize) -> bool {
    input[end..].chars().next().is_none_or(|character| {
        !character.is_alphanumeric()
            && !matches!(character, '_' | '-' | '%')
            && !is_combining_mark(character)
    })
}

const fn is_separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_frozen_ranges_lengths_and_display_separators() {
        for (ordinal, input) in [
            "4000008770000003",
            "4000 0087 7000 0003",
            "4000-0087-7000-0003",
            "340000877000009",
            "2221008770000000",
            "3528008770000008",
            "6011008770000005",
        ]
        .into_iter()
        .enumerate()
        {
            let found = detect_payment_cards(input);
            assert_eq!(found.len(), 1, "accepted detector case {ordinal}");
            assert_eq!(
                found[0].range,
                ByteRange::new(0, input.len()).unwrap(),
                "accepted detector range case {ordinal}"
            );
            assert_eq!(found[0].sensitivity, SensitivityState::NotEstablished);
        }
    }

    #[test]
    fn frozen_brand_range_table_covers_every_inclusive_boundary() {
        let supported = [
            ("34", 15),
            ("37", 15),
            ("601100", 16),
            ("601109", 16),
            ("601120", 16),
            ("601149", 16),
            ("601174", 16),
            ("601177", 16),
            ("601179", 16),
            ("601186", 16),
            ("601199", 16),
            ("644000", 16),
            ("659999", 16),
            ("3528", 16),
            ("3528", 19),
            ("3589", 16),
            ("3589", 19),
            ("510000", 16),
            ("559999", 16),
            ("222100", 16),
            ("272099", 16),
            ("4", 10),
            ("4", 19),
        ];
        for (ordinal, (prefix, length)) in supported.into_iter().enumerate() {
            let candidate = format!("{prefix}{}", "0".repeat(length - prefix.len()));
            assert!(
                supported_payment_range(candidate.as_bytes()),
                "supported brand boundary {ordinal}"
            );
        }

        let excluded = [
            ("33", 15),
            ("35", 15),
            ("36", 15),
            ("38", 15),
            ("601099", 16),
            ("601110", 16),
            ("601119", 16),
            ("601150", 16),
            ("601173", 16),
            ("601175", 16),
            ("601176", 16),
            ("601180", 16),
            ("601185", 16),
            ("601200", 16),
            ("643999", 16),
            ("660000", 16),
            ("3527", 16),
            ("3590", 16),
            ("3528", 15),
            ("3528", 20),
            ("509999", 16),
            ("560000", 16),
            ("222099", 16),
            ("272100", 16),
            ("4", 9),
            ("4", 20),
        ];
        for (ordinal, (prefix, length)) in excluded.into_iter().enumerate() {
            let candidate = format!("{prefix}{}", "0".repeat(length - prefix.len()));
            assert!(
                !supported_payment_range(candidate.as_bytes()),
                "excluded brand boundary {ordinal}"
            );
        }
    }

    #[test]
    fn display_layout_table_is_exact() {
        let accepted = [
            "4000008770000003",
            "4000 0087 7000 0003",
            "4000-0087-7000-0003",
            "3487 700000 00009",
            "3487-700000-00009",
        ];
        for (ordinal, display) in accepted.into_iter().enumerate() {
            assert!(
                normalize_display(display).is_some(),
                "accepted layout {ordinal}"
            );
        }
        let excluded = [
            "4000 0087-7000 0003",
            "400 0008 7700 00003",
            "4000 00877 000 0003",
            "348 770000 000009",
            "3487 70000 000009",
            "3487 7000000 0009",
            "4000\t0087\t7000\t0003",
        ];
        for (ordinal, display) in excluded.into_iter().enumerate() {
            assert!(
                normalize_display(display).is_none(),
                "excluded layout {ordinal}"
            );
        }
    }

    #[test]
    fn boundary_table_rejects_every_adjacent_class_on_both_sides() {
        let left = ["a", "7", "_", "-", "%", "⃝"];
        for (ordinal, prefix) in left.into_iter().enumerate() {
            let candidate = format!("{prefix}4000008770000003");
            assert!(
                !left_boundary(&candidate, prefix.len()),
                "left adjacent class {ordinal}"
            );
        }
        let right = ["a", "7", "_", "-", "%", "⃝"];
        for (ordinal, suffix) in right.into_iter().enumerate() {
            let candidate = format!("4000008770000003{suffix}");
            assert!(
                !right_boundary(&candidate, 16),
                "right adjacent class {ordinal}"
            );
        }
    }

    #[test]
    fn exact_authoritative_test_values_are_identity_only() {
        for (ordinal, input) in SUPPORTED_BRAND_TEST_PANS.iter().enumerate() {
            let found = detect_payment_cards(input);
            assert_eq!(found.len(), 1, "test-service control {ordinal}");
            assert_eq!(found[0].identity, IdentityState::Established);
            assert_eq!(found[0].sensitivity, SensitivityState::NonSensitive);
        }
        assert_eq!(
            detect_payment_cards("4111111111111129")[0].sensitivity,
            SensitivityState::NotEstablished
        );
    }

    #[test]
    fn rejects_checksum_neighbors_unsupported_ranges_and_ambiguous_boundaries() {
        for (ordinal, input) in [
            "4000008770000004",
            "30000087700004",
            "6759008770000004",
            "4000 0087-7000 0007",
            "4000 00 8770 00007",
            "x4000008770000003",
            "4000008770000003suffix",
            "14000008770000003",
            "40000087700000030000",
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                detect_payment_cards(input).is_empty(),
                "rejected detector case {ordinal}"
            );
        }
    }

    #[test]
    fn scanner_is_bounded_before_validation() {
        let input = format!("{} {}", "4".repeat(1_000_000), "5".repeat(1_000_000));
        assert!(detect_payment_cards(&input).is_empty());
    }
}

/// Differential test for #1086: `normalize_display` keeps the digits on the
/// stack instead of in a heap `String`.
#[cfg(test)]
mod stack_digits_differential_tests {
    use super::*;
    use crate::test_rng::{BOUNDARY_PIECES, XorShift32};

    /// The implementation before #1086.
    fn old_normalize_display(display: &str) -> Option<String> {
        let bytes = display.as_bytes();
        let mut digits = String::with_capacity(MAX_PAN_DIGITS);
        let mut separator = None;
        let mut separators = 0;
        let mut group_digits = 0;
        let mut group_lengths = [0_usize; 5];
        let mut groups = 0;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if byte.is_ascii_digit() {
                digits.push(char::from(byte));
                group_digits += 1;
                continue;
            }
            if !is_separator(byte)
                || index == 0
                || index + 1 == bytes.len()
                || separators == MAX_SEPARATORS
                || separator.is_some_and(|existing| existing != byte)
            {
                return None;
            }
            group_lengths[groups] = group_digits;
            groups += 1;
            separator = Some(byte);
            separators += 1;
            group_digits = 0;
        }
        if separator.is_some() {
            group_lengths[groups] = group_digits;
            groups += 1;
            if !matches!(&group_lengths[..groups], [4, 4, 4, 4] | [4, 6, 5]) {
                return None;
            }
        }
        (MIN_PAN_DIGITS..=MAX_PAN_DIGITS)
            .contains(&digits.len())
            .then_some(digits)
    }

    #[test]
    fn normalized_digits_match_the_string_implementation() {
        let pieces: Vec<&str> = BOUNDARY_PIECES
            .iter()
            .copied()
            .chain([
                "0000", "1234", "4111", "12345", "123456", " ", "-", "--", "  ",
            ])
            .collect();
        let mut rng = XorShift32::new(0x1086_0006);
        let mut inputs: Vec<String> = vec![
            String::new(),
            "-".to_owned(),
            "4111111111111111".to_owned(),
            "4111 1111 1111 1111".to_owned(),
            "4111-1111-1111-1111".to_owned(),
            "3400 123456 12345".to_owned(),
            "0".repeat(MAX_PAN_DIGITS),
            "0".repeat(MAX_PAN_DIGITS + 1),
            "0".repeat(MAX_PAN_DIGITS * 4),
            "0".repeat(MIN_PAN_DIGITS - 1),
        ];
        for _ in 0..8000 {
            inputs.push(rng.text(&pieces, 9));
        }
        // Digit runs of every length with group separators, so the accepted
        // and the over-long cases are both common.
        for _ in 0..4000 {
            let separator = ["", " ", "-", ".", "\u{a0}"][rng.below(5)];
            let groups = 1 + rng.below(6);
            let mut display = String::new();
            for group in 0..groups {
                if group > 0 {
                    display.push_str(separator);
                }
                for _ in 0..rng.below(8) {
                    display.push(char::from(b'0' + u8::try_from(rng.below(10)).unwrap_or(0)));
                }
            }
            inputs.push(display);
        }
        let mut hits = 0;
        for input in &inputs {
            let old = old_normalize_display(input);
            let new = normalize_display(input);
            assert_eq!(
                new.as_ref().map(PanDigits::as_str),
                old.as_deref(),
                "{input:?}"
            );
            hits += usize::from(old.is_some());
        }
        assert!(hits > 20, "the generator must reach the accepted cases");
    }
}
