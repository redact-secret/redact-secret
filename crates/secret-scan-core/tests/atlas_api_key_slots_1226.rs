//! Atlas programmatic API key slots (redact-secret#1226), driven through the
//! public default pipeline.
//!
//! credential-evidence#256/#258 name two plaintext slots of the private key:
//! the `privateKey` creation-response member and the `private_api_key` Atlas
//! CLI profile property. The public half is `publicKey` (exactly 8 bytes) and
//! the profile property `public_api_key`. Values are assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence, Finding};
use support::{as_chunks, run, single_byte_partition, whole_input};

fn findings_with_parity(input: &str) -> Vec<Finding> {
    let (expected_text, expected) = whole_input(input);
    let one = single_byte_partition(input);
    let session = run(&as_chunks(&one));
    assert_eq!(session.text(), expected_text, "{input:?}: 1-byte");
    assert_eq!(session.findings(), expected, "{input:?}: 1-byte");
    let seven: Vec<String> = input
        .as_bytes()
        .chunks(7)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    let session = run(&as_chunks(&seven));
    assert_eq!(session.text(), expected_text, "{input:?}: 7-byte");
    assert_eq!(session.findings(), expected, "{input:?}: 7-byte");
    expected
}

fn assert_clean(input: &str) {
    let findings = findings_with_parity(input);
    assert!(findings.is_empty(), "{input:?}: {findings:?}");
}

/// One `contextual_secret`, high, `redact`, exactly `value`.
fn assert_value(input: &str, value: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(value).expect("the value is in the input");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    assert_eq!(findings[0].type_name(), "contextual_secret", "{input:?}");
    assert_eq!(findings[0].confidence(), Confidence::High, "{input:?}");
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

/// A synthetic UUID-shaped private key (the shape is invented, not claimed).
fn private_key(seed: usize) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let hex = |len: usize, salt: usize| -> String {
        (0..len)
            .map(|index| HEX[(index * 7 + seed * 5 + salt * 3 + index * index) % 16] as char)
            .collect()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(8, 1),
        hex(4, 2),
        hex(4, 3),
        hex(4, 4),
        hex(12, 5)
    )
}

#[test]
fn the_creation_response_member_is_pinned() {
    let key = private_key(1);
    assert_value(&format!("{{\"privateKey\":\"{key}\"}}\n"), &key);
    assert_value(
        &format!("{{\"desc\":\"ci\",\"privateKey\":\"{key}\",\"publicKey\":\"abcd1234\"}}\n"),
        &key,
    );
    assert_value(&format!("{{\n  \"privateKey\": \"{key}\"\r\n}}\r\n"), &key);
}

#[test]
fn the_cli_profile_property_and_variable_are_pinned() {
    let key = private_key(2);
    assert_value(&format!("private_api_key = \"{key}\"\n"), &key);
    assert_value(&format!("private_api_key = {key}\n"), &key);
    assert_value(&format!("[default]\nprivate_api_key = \"{key}\"\n"), &key);
    assert_value(&format!("MONGODB_ATLAS_PRIVATE_API_KEY={key}\n"), &key);
    assert_value(
        &format!("export MONGODB_ATLAS_PRIVATE_API_KEY=\"{key}\"\n"),
        &key,
    );
}

#[test]
fn masked_and_placeholder_private_key_forms_are_silent() {
    for value in [
        "********-****-****-************",
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "<private-api-key>",
        "YOUR_PRIVATE_API_KEY",
        "${ATLAS_PRIVATE_KEY}",
        "$MONGODB_ATLAS_PRIVATE_API_KEY",
        "redacted",
    ] {
        assert_clean(&format!("{{\"privateKey\":\"{value}\"}}\n"));
        assert_clean(&format!("private_api_key = \"{value}\"\n"));
    }
}

#[test]
fn the_public_half_of_exactly_eight_bytes_is_silent_under_its_names() {
    for input in [
        "{\"publicKey\":\"abcd1234\"}\n",
        "public_key = \"abcd1234\"\n",
        "public_api_key = \"abcd1234\"\n",
        "[default]\r\npublic_api_key = abcd1234\r\n",
        "MONGODB_ATLAS_PUBLIC_API_KEY=abcd1234\n",
        "export MONGODB_ATLAS_PUBLIC_API_KEY=\"abcd1234\"\n",
        "{\"publicApiKey\":\"abcd1234\"}\n",
        "PUBLIC_API_KEY=abcd1234\n",
    ] {
        assert_clean(input);
    }
}

#[test]
fn the_pair_in_one_document_reports_only_the_private_half() {
    let key = private_key(3);
    assert_value(
        &format!("public_api_key = \"abcd1234\"\nprivate_api_key = \"{key}\"\n"),
        &key,
    );
    assert_value(
        &format!("{{\"publicApiKey\":\"abcd1234\",\"privateApiKey\":\"{key}\"}}\n"),
        &key,
    );
}

#[test]
fn a_public_name_with_any_other_length_or_another_name_keeps_its_reading() {
    // Not exactly 8 bytes: the evidence's length is the only thing excused.
    assert_clean("public_api_key = \"abcd123\"\n"); // under the 8-byte floor already
    for value in ["abcd12345", "abcd1234abcd"] {
        let findings = findings_with_parity(&format!("public_api_key = \"{value}\"\n"));
        assert_eq!(findings.len(), 1, "{value}: {findings:?}");
    }
    let long = private_key(4);
    assert_value(&format!("public_api_key = \"{long}\"\n"), &long);
    // The same 8-byte value under a secret name is still read.
    for input in [
        "api_key = \"abcd1234\"\n",
        "private_api_key = \"abcd1234\"\n",
        "secret_api_key = \"abcd1234\"\n",
        "my_public_api_key = \"abcd1234\"\n",
    ] {
        let findings = findings_with_parity(input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    }
}
