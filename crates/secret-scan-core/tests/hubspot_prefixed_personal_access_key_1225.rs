//! A prefixed `HubSpot` personal access key name (redact-secret#1225
//! follow-up), driven through the public default pipeline.
//!
//! `personalAccessKey` and `HUBSPOT_PERSONAL_ACCESS_KEY` were read as whole
//! names (#1233); the same field under a user's own prefix
//! (`MY_HUBSPOT_PERSONAL_ACCESS_KEY`, `my_personal_access_key`) was silent.
//! The value is assembled at run time from generated material.
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

fn body(len: usize, seed: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|index| {
            ALPHABET[(index * 29 + seed * 17 + index * index * 7) % ALPHABET.len()] as char
        })
        .collect()
}

#[test]
fn a_prefixed_personal_access_key_name_is_read_in_every_layout() {
    let key = body(44, 1);
    for name in [
        "MY_HUBSPOT_PERSONAL_ACCESS_KEY",
        "my_hubspot_personal_access_key",
        "MY_PERSONAL_ACCESS_KEY",
        "my_personal_access_key",
        "oldPersonalAccessKey",
        "prod_personal_access_key",
        "hubspotProdPersonalAccessKey",
        "HUBSPOT_PERSONAL_ACCESS_KEY",
        "personalAccessKey",
    ] {
        assert_value(&format!("{name}: {key}\n"), &key);
        assert_value(&format!("{name}={key}\n"), &key);
        assert_value(&format!("export {name}=\"{key}\"\r\n"), &key);
        assert_value(&format!("{{\"{name}\":\"{key}\"}}\n"), &key);
        assert_value(
            &format!(
                "accounts:\n  - authType: personalaccesskey\n    {name}: {key}\n    env: qa\n"
            ),
            &key,
        );
    }
}

#[test]
fn neighbouring_names_stay_silent() {
    let key = body(44, 2);
    for name in [
        "personalAccessKeyId",
        "personalAccessKeyExpiresAt",
        "personalAccessKeyHint",
        "personalAccessKeyLength",
        "my_personal_access_key_id",
        "MY_HUBSPOT_PERSONAL_ACCESS_KEY_ID",
        "MY_HUBSPOT_PERSONAL_ACCESS_KEY_EXPIRES_AT",
        "HUBSPOT_PERSONAL_ACCESS_KEY_ID",
        "my_personal_key",
        "my_access_key_name",
        "hubspot_key",
        "accessKey",
        "personalKey",
        "portalId",
        "authType",
    ] {
        assert_clean(&format!("{name}: {key}\n"));
        assert_clean(&format!("{name}={key}\n"));
    }
}

#[test]
fn a_prefix_that_says_the_value_is_not_the_secret_excludes_it() {
    let key = body(44, 3);
    assert_clean(&format!("publishable_personal_access_key: {key}\n"));
    assert_clean("masked_personal_access_key: ****************************\n");
    assert_clean("redacted_personal_access_key: [redacted-value-here-xx]\n");
}

#[test]
fn placeholders_references_masks_and_short_values_stay_silent_under_the_prefix() {
    for value in [
        "YOUR_PERSONAL_ACCESS_KEY",
        "your_hubspot_personal_access_key_here",
        "<personal-access-key>",
        "${MY_HUBSPOT_PERSONAL_ACCESS_KEY}",
        "$MY_HUBSPOT_PERSONAL_ACCESS_KEY",
        "****************************",
        "xxxxxxxxxxxxxxxxxxxxxxxx",
        "",
        "short",
    ] {
        assert_clean(&format!("MY_HUBSPOT_PERSONAL_ACCESS_KEY={value}\n"));
        assert_clean(&format!("my_personal_access_key: \"{value}\"\n"));
    }
}

#[test]
fn a_low_entropy_value_is_a_warn_at_medium_confidence() {
    let findings = findings_with_parity("MY_PERSONAL_ACCESS_KEY: abababababababab\n");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].action(), Action::Warn);
    assert_eq!(findings[0].confidence(), Confidence::Medium);
}
