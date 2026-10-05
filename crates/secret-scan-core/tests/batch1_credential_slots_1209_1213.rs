//! Batch 1 credential slots (redact-secret#1209 to #1213), driven through the
//! public default pipeline.
//!
//! The independent oracle is the focused Batch 1 corpus of
//! redact-secret-benchmarks#717 (`benchmarks/batch1/corpus.mjs` at
//! `14271c7e85ad`). Every input here is re-authored from that corpus's layouts
//! with unmistakably synthetic values; the expected span of a positive is the
//! credential value itself (the encoded envelope for `Basic` and `ApiKey`),
//! computed as the UTF-8 byte offset of the value inside the input, and the
//! expected action is `redact`. Provider documentation establishes the slot
//! and role of each credential, never a universal byte shape, so no test
//! asserts a width, an alphabet or a provider type.
//!
//! * #1209 `X-Figma-Token`: detection was already measured as covered; the
//!   one measured false positive, the placeholder `YOUR_FIGMA_TOKEN`, is fixed.
//! * #1210 Asana `X-Hook-Secret`: no code, the validated behavior is pinned.
//! * #1211 Airtable `macSecretBase64`: a measured gap, one exact field name.
//! * #1212 `Authorization` / `Proxy-Authorization: ApiKey`: a measured gap.
//! * #1213 Canva `client_secret` and the `Basic` envelope: no code, pinned.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Whole-input findings, and the same text and findings under every two-chunk
/// UTF-8 byte partition and a line-per-chunk incremental session.
fn findings_with_parity(input: &str) -> Vec<Finding> {
    let (expected_text, expected) = whole_input(input);
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), expected_text, "{input:?}: {pieces:?}");
        assert_eq!(session.findings(), expected, "{input:?}: {pieces:?}");
    }
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let session = run(&lines);
    assert_eq!(session.text(), expected_text, "{input:?}: per line");
    assert_eq!(session.findings(), expected, "{input:?}: per line");
    expected
}

fn assert_clean(input: &str) {
    let findings = findings_with_parity(input);
    assert!(findings.is_empty(), "{input:?}: {findings:?}");
}

/// Exactly one `redact` finding of `type_name`, spanning exactly `value`
/// (found once in `input`) and nothing else: the carrier and the name stay
/// outside the span, and the sanitized text keeps them and drops the value.
fn assert_value(input: &str, value: &str, type_name: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(value).expect("the value is in the input");
    assert_eq!(input.matches(value).count(), 1, "{input:?}");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    assert_eq!(findings[0].type_name(), type_name, "{input:?}");
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

// ----------------------------------------------------- #1209 X-Figma-Token

const FIGMA_RAW: &str = "Xq7Lm2Zp9TrW4vKc8NbY3hJd6FsA1eGuQw5Rt0Yk";
const FIGMA_UNI: &str = "Hn4Vd8Ks2PxQ7mLb3ZcW9tRy6FjA1eGuTo5Ek0Ms7Nx";
const FIGMA_C1: &str = "Pw3Rn8Kd5VxL2mQb7ZcT9yHs4FjA1eGu";
const FIGMA_C2: &str = "Tz6Qm1Vd9KxP4nLb8RcW2yHs";
const FIGMA_MAP: &str = "Bd5Kx9Rn2VmP7qLc3ZtW8yHs4FjA6eGuQo1Ek0Ms";

#[test]
fn figma_header_value_is_redacted_in_every_supported_layout() {
    for (input, value) in [
        (
            format!(
                "GET /v1/files/FILE0 HTTP/1.1\r\nHost: api.example.test\r\nX-Figma-Token: {FIGMA_RAW}\r\nAccept: application/json\r\n\r\n"
            ),
            FIGMA_RAW,
        ),
        (
            format!(
                "// notiz: caf\u{e9} \u{1F680} Figma-Datei\nGET /v1/me HTTP/1.1\r\nHost: api.example.test\r\nX-Figma-Token: {FIGMA_UNI}\r\n\r\n"
            ),
            FIGMA_UNI,
        ),
        (
            format!(
                "curl -s -H 'X-Figma-Token: {FIGMA_C1}' https://api.example.test/v1/files/FILE0\n"
            ),
            FIGMA_C1,
        ),
        (
            format!(
                "curl -s -H \"X-Figma-Token: {FIGMA_C2}\" https://api.example.test/v1/files/FILE0\n"
            ),
            FIGMA_C2,
        ),
        (
            format!(
                "{{\"method\":\"GET\",\"url\":\"https://api.example.test/v1/files/FILE0\",\"headers\":{{\"Accept\":\"application/json\",\"X-Figma-Token\":\"{FIGMA_MAP}\"}}}}\n"
            ),
            FIGMA_MAP,
        ),
    ] {
        // A shared carrier names no credential subtype: the type is generic.
        assert_value(&input, value, "contextual_secret");
    }
}

#[test]
fn figma_header_value_stays_outside_the_header_name_and_the_unicode_prefix_offset_is_in_bytes() {
    let input = format!("// caf\u{e9} \u{1F680}\nX-Figma-Token: {FIGMA_UNI}\r\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let prefix = "// caf\u{e9} \u{1F680}\nX-Figma-Token: ";
    assert_eq!(findings[0].range().start(), prefix.len());
    assert_ne!(prefix.len(), prefix.chars().count());
    assert_eq!(findings[0].range().end(), prefix.len() + FIGMA_UNI.len());
}

#[test]
fn figma_placeholders_references_masks_and_lookalikes_stay_clean() {
    let id = "4829103847561029384";
    for input in [
        // The measured false positive: the instructional placeholder.
        "curl -H \"X-Figma-Token: YOUR_FIGMA_TOKEN\" https://api.example.test/v1/me\n",
        "X-Figma-Token: YOUR_FIGMA_TOKEN\r\n",
        "X-Figma-Token: your-figma-token\r\n",
        "X-Figma-Token: replace-with-your-figma-token\r\n",
        "{\"headers\":{\"X-Figma-Token\":\"YOUR_FIGMA_PERSONAL_ACCESS_TOKEN\"}}\n",
        "X-Figma-Token: <your-figma-token>\r\n",
        "curl -H \"X-Figma-Token: ${FIGMA_TOKEN}\" https://api.example.test/v1/me\n",
        "{\"headers\":{\"X-Figma-Token\":\"{{ secrets.figma_token }}\"}}\n",
        "X-Figma-Token: ****************\r\n",
        "X-Figma-Token: \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\r\n",
        // Public ids and a newline-separated value are not a header value.
        &format!("{{\"planId\":\"{id}\",\"user\":{{\"id\":\"{id}\",\"handle\":\"example\"}}}}\n"),
        &format!("X-Figma-Token:\r\n{FIGMA_RAW}\r\n"),
        // A bare `figd_` run is not part of this claim.
        &format!("Personal access tokens look like figd_{FIGMA_RAW} in the account settings.\n"),
    ] {
        assert_clean(input);
    }
}

#[test]
fn figma_name_lookalikes_with_a_suffix_stay_clean() {
    for input in [
        format!("X-Figma-Token-Id: {FIGMA_C1}\r\n"),
        format!("curl -H 'X-Figma-Token-Hint: {FIGMA_C1}' https://api.example.test/\n"),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn the_figma_placeholder_exclusion_keeps_a_real_value_and_a_glued_placeholder() {
    // One word off the list, or a placeholder glued to random material, is
    // still a value a person could have pasted a credential into.
    for value in [
        format!("YOUR_FIGMA_TOKEN_{FIGMA_C1}"),
        format!("your-figma-token-{FIGMA_C2}"),
        FIGMA_C1.to_owned(),
    ] {
        assert_value(
            &format!("X-Figma-Token: {value}\r\n"),
            &value,
            "contextual_secret",
        );
    }
}
