//! Issues #1167 and #1168: the phone parser now takes the compact ten-digit
//! display behind an exact shape guard, and the IBAN detector looks up the
//! country length in a direct table. The unit tests in `pii/pii_phone.rs` and
//! `pii/pii_iban.rs` compare both against the pre-change code; this file checks
//! the public surface: the whole-input result is pinned and every two-way split
//! and the single-character partition of the incremental session reproduce it,
//! with PII enabled. All values are synthetic or published documentation
//! values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    DefaultPolicy, DetectorRegistry, IncrementalLimits, IncrementalSanitizer, PiiSelection,
    default_placeholder_formatter, scan_and_redact,
};

fn selection() -> PiiSelection {
    PiiSelection::parse(&["pii:global"]).unwrap()
}

fn whole(input: &str) -> (String, Vec<(usize, usize)>) {
    let registry = DetectorRegistry::with_built_in_and_pii(&selection()).unwrap();
    let result = scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();
    let ranges = result
        .findings()
        .iter()
        .map(|finding| (finding.range().start(), finding.range().end()))
        .collect();
    (result.text().to_owned(), ranges)
}

fn incremental(pieces: &[&str]) -> (String, Vec<(usize, usize)>) {
    let total: usize = pieces.iter().map(|piece| piece.len()).sum();
    let limits = IncrementalLimits::new(
        total.max(1),
        IncrementalLimits::minimum_buffered_bytes(total.max(1), total.max(1)),
        total.max(1),
        total.max(1),
    )
    .unwrap();
    let mut session = IncrementalSanitizer::with_built_in_and_pii(limits, &selection()).unwrap();
    let mut text = String::new();
    let mut ranges = Vec::new();
    for piece in pieces {
        let result = session.append(piece).unwrap();
        text.push_str(result.text());
        ranges.extend(
            result
                .findings()
                .iter()
                .map(|finding| (finding.range().start(), finding.range().end())),
        );
    }
    let result = session.finalize().unwrap();
    text.push_str(result.text());
    ranges.extend(
        result
            .findings()
            .iter()
            .map(|finding| (finding.range().start(), finding.range().end())),
    );
    (text, ranges)
}

fn assert_all_partitions_agree(input: &str) -> (String, Vec<(usize, usize)>) {
    let expected = whole(input);
    for cut in 0..=input.len() {
        if input.is_char_boundary(cut) {
            let got = incremental(&[&input[..cut], &input[cut..]]);
            assert_eq!(got, expected, "{input:?} cut={cut}");
        }
    }
    let singles: Vec<String> = input.chars().map(String::from).collect();
    let singles: Vec<&str> = singles.iter().map(String::as_str).collect();
    assert_eq!(incremental(&singles), expected, "{input:?} single chars");
    expected
}

#[test]
fn compact_and_other_phone_displays_are_found_alike_whole_and_incremental() {
    for (input, expect_phone) in [
        ("phone: 212-456-7890 done", true),
        ("phone: 2124567890 done", true),
        ("phone: (212) 456-7890 done", true),
        ("phone: (2124567890 done", false),
        ("phone: 212 456 7890 done", true),
        ("phone: +12124567890 done", true),
        ("phone: +1 212 456 7890 done", true),
        ("phone: 456-7890 done", true),
        ("phone: 2124567890 ext 7", true),
        ("phone: 21245678901 done", false),
        ("phone: 1124567890 done", false),
        ("phone: 2121567890 done", false),
        ("phone: 2124567890x", false),
        ("phone: 212456789", false),
        ("phone: \u{ff12}124567890 done", false),
    ] {
        let (text, ranges) = assert_all_partitions_agree(input);
        assert_eq!(!ranges.is_empty(), expect_phone, "{input:?}");
        if expect_phone && !input.starts_with("phone: 456") {
            assert!(!text.contains("456"), "{input:?} -> {text:?}");
        }
    }
}

#[test]
fn iban_displays_and_country_edges_are_found_alike_whole_and_incremental() {
    for (input, expect_iban) in [
        ("IBAN: GB82WEST12345698765432 done", true),
        ("IBAN: GB82 WEST 1234 5698 7654 32 done", true),
        ("IBAN: DE89370400440532013000 done", true),
        ("IBAN: NO9386011117947 done", true),
        ("IBAN: RU0304452522540817810538091310419 done", true),
        ("IBAN: gb82WEST12345698765432 done", false),
        ("IBAN: ZZ82WEST12345698765432 done", false),
        ("IBAN: PF8212345698765432101234567 done", false),
        ("IBAN: GB82WEST1234569876543 done", false),
        ("IBAN: G\u{ff22}82WEST12345698765432 done", false),
    ] {
        let (_, ranges) = assert_all_partitions_agree(input);
        assert_eq!(!ranges.is_empty(), expect_iban, "{input:?}");
    }
}

#[test]
fn dense_and_sparse_phone_and_iban_inputs_agree_between_whole_and_chunked_scans() {
    let filler = "The quick brown fox, request id 12345, status ok; path /var/log/app.log\n";
    let record = "phone: 2124567890 and iban: GB82WEST12345698765432\n";
    let sparse = format!("{}{record}{}", filler.repeat(200), filler.repeat(200));
    let dense = record.repeat(150);
    for input in [sparse, dense] {
        let expected = whole(&input);
        assert!(!expected.1.is_empty());
        for size in [1_usize, 7, 64, 4_096] {
            let pieces: Vec<&str> = input
                .as_bytes()
                .chunks(size)
                .map(|chunk| core::str::from_utf8(chunk).unwrap())
                .collect();
            assert_eq!(incremental(&pieces), expected, "chunk size {size}");
        }
    }
}
