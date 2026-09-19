//! Invisible code points inside a credential no longer defeat detection
//! (`decision-normalize-invisible-characters-before-detection`, issue #438).
//!
//! Each case pairs an obfuscated input with its control — the same input
//! with the invisible code points taken out — and requires the same finding
//! type, detector, confidence, and action, a range that selects the control's
//! value with the interior code points included, and the control's redacted
//! output. The incremental cases then require every partition of the
//! obfuscated input to reproduce the whole-input result.
//!
//! Every input is synthetic; no test embeds a real credential.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{
    Action, ByteRange, DefaultPolicy, DetectorRegistry, Finding, default_placeholder_formatter,
    redact, scan, scan_and_redact,
};

const ZWSP: &str = "\u{200B}";
const ZWNJ: &str = "\u{200C}";

/// One obfuscated shape: `prefix`, then a value whose pieces are joined by
/// `marker`, then `suffix`. The control joins the same pieces with nothing.
struct Case {
    name: &'static str,
    prefix: &'static str,
    value: &'static [&'static str],
    suffix: &'static str,
    marker: &'static str,
}

impl Case {
    fn obfuscated(&self) -> String {
        format!(
            "{}{}{}",
            self.prefix,
            self.value.join(self.marker),
            self.suffix
        )
    }

    fn control(&self) -> String {
        format!("{}{}{}", self.prefix, self.value.concat(), self.suffix)
    }
}

/// The five shapes of issue #438's reproduction table that split the value,
/// then one case per removed class outside the five-code-point parity set.
const VALUE_CASES: &[Case] = &[
    Case {
        name: "provider grammar + ZWNJ",
        prefix: "token: ",
        value: &["ghp_SYNTHETIC", "REVOKED00000000000000000000"],
        suffix: "\n",
        marker: ZWNJ,
    },
    Case {
        name: "structural authorization header + ZWSP",
        prefix: "Authorization: Bearer ",
        value: &["SYNTHETIC", "REVOKED_BEARER_VALUE_1234"],
        suffix: "\n",
        marker: ZWSP,
    },
    Case {
        name: "contextual assignment value + ZWSP",
        prefix: "api_key = ",
        value: &["SYNTHETIC_REVOKED", "_VALUE_1234"],
        suffix: "\n",
        marker: ZWSP,
    },
    Case {
        name: "connection URI password + ZWSP",
        prefix: "postgres://svc:",
        value: &["SYNTHETIC", "REVOKEDPW"],
        suffix: "@db:5432/app\n",
        marker: ZWSP,
    },
    Case {
        name: "bidi override",
        prefix: "token: ",
        value: &["ghp_SYNTHETIC", "REVOKED00000000000000000000"],
        suffix: "\n",
        marker: "\u{202E}",
    },
    Case {
        name: "tags block",
        prefix: "token: ",
        value: &["ghp_", "SYNTHETIC", "REVOKED00000000000000000000"],
        suffix: "\n",
        marker: "\u{E0041}",
    },
    Case {
        name: "variation selector",
        prefix: "token: ",
        value: &["ghp_SYNTHETICREVOKED0000000000000000000", "0"],
        suffix: "\n",
        marker: "\u{FE0F}",
    },
    Case {
        name: "Hangul filler",
        prefix: "token: ",
        value: &["g", "hp_SYNTHETICREVOKED00000000000000000000"],
        suffix: "\n",
        marker: "\u{3164}",
    },
    Case {
        name: "soft hyphen run",
        prefix: "token: ",
        value: &["ghp_SYNTHETIC", "REVOKED00000000000000000000"],
        suffix: "\n",
        marker: "\u{00AD}\u{00AD}\u{2060}",
    },
];

fn scan_and_redact_built_in(input: &str) -> (String, Vec<Finding>) {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap()
    .into_parts()
}

fn selected(input: &str, range: ByteRange) -> &str {
    assert!(range.is_char_aligned_in(input));
    &input[range.start()..range.end()]
}

fn assert_same_classification(name: &str, obfuscated: &[Finding], control: &[Finding]) {
    assert_eq!(obfuscated.len(), control.len(), "{name}: finding count");
    for (found, expected) in obfuscated.iter().zip(control) {
        assert_eq!(found.id(), expected.id(), "{name}: id");
        assert_eq!(found.type_name(), expected.type_name(), "{name}: type");
        assert_eq!(found.detector(), expected.detector(), "{name}: detector");
        assert_eq!(
            found.confidence(),
            expected.confidence(),
            "{name}: confidence"
        );
        assert_eq!(found.action(), expected.action(), "{name}: action");
    }
}

#[test]
fn a_value_split_by_invisible_code_points_is_detected_like_its_control() {
    for case in VALUE_CASES {
        let (obfuscated, control) = (case.obfuscated(), case.control());
        let (control_text, control_findings) = scan_and_redact_built_in(&control);
        assert_eq!(control_findings.len(), 1, "{}: control", case.name);
        assert!(control_findings[0].action().replaces_text());

        let (text, findings) = scan_and_redact_built_in(&obfuscated);
        assert_same_classification(case.name, &findings, &control_findings);

        // The span is the control's value with the interior code points
        // included, so one placeholder replaces all of it and nothing
        // invisible is orphaned beside it.
        let value = selected(&control, control_findings[0].range());
        let span = selected(&obfuscated, findings[0].range());
        assert!(span.contains(case.marker), "{}: interior", case.name);
        assert_eq!(span.replace(case.marker, ""), value, "{}", case.name);
        assert!(!span.starts_with(case.marker) && !span.ends_with(case.marker));
        assert_eq!(text, control_text, "{}: redacted output", case.name);
    }
}

#[test]
fn the_common_profile_classifies_an_obfuscated_value_like_its_control() {
    // `common` drops the provider detectors, so some controls have no
    // finding at all; normalization must neither add one nor lose one.
    let registry = DetectorRegistry::with_common_built_in([]).unwrap();
    let mut detected = 0;
    for case in VALUE_CASES {
        let control = scan(&case.control(), &registry, &DefaultPolicy).unwrap();
        let findings = scan(&case.obfuscated(), &registry, &DefaultPolicy).unwrap();
        assert_same_classification(case.name, &findings, &control);
        detected += findings.len();
    }
    assert!(detected > 0);
}

#[test]
fn a_contextual_keyword_split_by_an_invisible_code_point_is_detected_like_its_control() {
    let control = "api_key = SYNTHETIC_REVOKED_VALUE_1234\n";
    let obfuscated = format!("api{ZWSP}_key = SYNTHETIC_REVOKED_VALUE_1234\n");
    let (control_text, control_findings) = scan_and_redact_built_in(control);
    let (text, findings) = scan_and_redact_built_in(&obfuscated);

    assert_eq!(control_findings.len(), 1);
    assert_same_classification("keyword", &findings, &control_findings);
    // The value itself is untouched, so the span is the control's, shifted
    // by the removed code point; the keyword keeps its invisible character.
    assert_eq!(
        selected(&obfuscated, findings[0].range()),
        selected(control, control_findings[0].range())
    );
    assert_eq!(
        findings[0].range().start(),
        control_findings[0].range().start() + ZWSP.len()
    );
    assert_eq!(text, control_text.replacen("api", &format!("api{ZWSP}"), 1));
}

#[test]
fn invisible_code_points_adjacent_to_a_match_are_not_absorbed() {
    let value = "SYNTHETICREVOKED_BEARER_VALUE_1234";
    let input = format!("Authorization: Bearer {ZWSP}{value}{ZWNJ}\n");
    let (text, findings) = scan_and_redact_built_in(&input);

    assert_eq!(findings.len(), 1);
    assert_eq!(selected(&input, findings[0].range()), value);
    assert_eq!(
        text,
        format!("Authorization: Bearer {ZWSP}<SECRET_1>{ZWNJ}\n")
    );
}

#[test]
fn an_invisible_code_point_is_not_a_token_boundary() {
    // The stated tradeoff of scanning text as it renders: `word<ZWSP>token`
    // reads as `wordtoken`, so it is classified exactly like that control —
    // including when the control's missing boundary means no provider match.
    let token = "ghp_SYNTHETICREVOKED00000000000000000000";
    for (before, after) in [("x", ""), ("", "x"), ("x", "x")] {
        let control = format!("{before}{token}{after}\n");
        let obfuscated = format!("{before}{ZWSP}{token}{ZWSP}{after}\n");
        let (_, control_findings) = scan_and_redact_built_in(&control);
        let (_, findings) = scan_and_redact_built_in(&obfuscated);
        assert_same_classification("boundary", &findings, &control_findings);
    }
}

#[test]
fn ranges_stay_in_original_coordinates_across_several_findings() {
    let input = format!(
        "{ZWSP}a: ghp_SYNTHETIC{ZWNJ}REVOKED00000000000000000000\n\
         한{ZWSP}글 api_key = SYNTHETIC_REVOKED{ZWSP}_VALUE_1234\n\
         b: ghp_SYNTHETICREVOKED11111111111111111111\n"
    );
    let (text, findings) = scan_and_redact_built_in(&input);

    assert_eq!(findings.len(), 3);
    assert_eq!(
        text,
        format!("{ZWSP}a: <SECRET_1>\n한{ZWSP}글 api_key = <SECRET_2>\nb: <SECRET_3>\n")
    );
    assert!(
        findings
            .windows(2)
            .all(|pair| { pair[0].range().end() <= pair[1].range().start() })
    );
    // Caller-supplied ranges are interpreted against the original input, so
    // redacting with the reported findings reproduces the same output.
    assert_eq!(
        redact(&input, &findings, &default_placeholder_formatter).unwrap(),
        text
    );
}

#[test]
fn a_vendor_placeholder_literal_stays_exempt_when_split() {
    let input = format!("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7{ZWSP}EXAMPLE\n");
    let (text, findings) = scan_and_redact_built_in(&input);
    assert_eq!(findings, Vec::new());
    assert_eq!(text, input);
}

#[test]
fn benign_text_with_invisible_code_points_gains_no_finding() {
    for input in [
        "می\u{200C}خواهم کتاب بخوانم\n",
        "क्\u{200D}ष and क्\u{200C}ष\n",
        "<p>hy\u{00AD}phen\u{00AD}ation in a para\u{00AD}graph</p>\n",
        "family: \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} and \u{2764}\u{FE0F}\n",
        "\u{FEFF}plain text after a byte-order mark\n",
        "\u{200B}\u{200C}\u{E0041}",
    ] {
        let (text, findings) = scan_and_redact_built_in(input);
        assert_eq!(findings, Vec::new(), "{input:?}");
        assert_eq!(text, input);
    }
}

// ---------------------------------------------------------------------------
// incremental partition equivalence
// ---------------------------------------------------------------------------

fn assert_every_partition_matches_whole_input(name: &str, input: &str) {
    let (whole_text, whole_findings) = support::whole_input(input);

    let mut partitions: Vec<Vec<String>> = support::utf8_byte_partitions(input);
    partitions.push(support::single_byte_partition(input));
    partitions.push(
        support::single_char_partition(input)
            .into_iter()
            .map(str::to_owned)
            .collect(),
    );
    for pieces in &partitions {
        let run = support::run(&support::as_chunks(pieces));
        assert_eq!(run.text(), whole_text, "{name}: text");
        assert_eq!(run.findings(), whole_findings, "{name}: findings");
    }
}

#[test]
fn every_partition_of_an_obfuscated_value_matches_the_whole_input() {
    for case in VALUE_CASES {
        let input = format!("before\n{}after\n", case.obfuscated());
        let (_, findings) = support::whole_input(&input);
        assert_eq!(findings.len(), 1, "{}", case.name);
        assert_every_partition_matches_whole_input(case.name, &input);
    }
}

#[test]
fn an_open_construct_split_by_an_invisible_code_point_keeps_its_unit_open() {
    // Each keyword ends its line and its value follows on the next, so the
    // value is only reachable while the session holds the unit open. Judged
    // on the raw text the keyword is not one, the line closes, and the value
    // is released unredacted under any partition that ends a chunk there.
    for (name, input) in [
        (
            "contextual keyword",
            format!("api{ZWSP}_key\n= SYNTHETIC_REVOKED_VALUE_1234\nafter\n"),
        ),
        (
            "contextual keyword, marker at the line end",
            format!("api_key{ZWSP}\n= SYNTHETIC_REVOKED_VALUE_1234\nafter\n"),
        ),
        (
            "authorization header name",
            format!("Author{ZWNJ}ization\n: Bearer SYNTHETICREVOKED_BEARER_VALUE_1234\nafter\n"),
        ),
    ] {
        let control = input.replace(['\u{200B}', '\u{200C}'], "");
        let (_, control_findings) = support::whole_input(&control);
        let (_, findings) = support::whole_input(&input);
        assert_eq!(control_findings.len(), 1, "{name}: control");
        assert_same_classification(name, &findings, &control_findings);
        assert_every_partition_matches_whole_input(name, &input);
    }
}

#[test]
fn a_private_key_delimiter_split_by_an_invisible_code_point_keeps_its_block_open() {
    let input = format!(
        "before\n-----BE{ZWSP}GIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRUQ=\n\
         -----END PRI{ZWNJ}VATE KEY-----\nafter\n"
    );
    let control = input.replace(['\u{200B}', '\u{200C}'], "");
    let (control_text, control_findings) = support::whole_input(&control);
    let (text, findings) = support::whole_input(&input);

    assert_eq!(control_findings.len(), 1);
    assert_same_classification("private key", &findings, &control_findings);
    assert_eq!(text, control_text);
    assert_eq!(findings[0].action(), Action::Block);
    assert_every_partition_matches_whole_input("private key", &input);
}

#[test]
fn limits_are_still_measured_in_original_bytes() {
    // 40 original bytes of which 30 are removed: the scan copy would fit a
    // 16-byte token limit, the retained plaintext does not.
    let limits = redact_secret::IncrementalLimits::new(
        1_000,
        redact_secret::IncrementalLimits::minimum_buffered_bytes(16, 32),
        16,
        32,
    )
    .unwrap();
    let mut session = redact_secret::IncrementalSanitizer::new(limits).unwrap();
    let chunk = format!("abcdefghij{}", ZWSP.repeat(10));
    assert_eq!(chunk.len(), 40);
    let error = session.append(&chunk).unwrap_err();
    assert_eq!(
        error.code(),
        redact_secret::SecretScanErrorCode::TokenLimitExceeded
    );
}
