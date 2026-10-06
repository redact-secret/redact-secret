//! Instructional placeholders that name a product, service or credential
//! scope are silent like the shorter forms (redact-secret#1234 follow-up),
//! driven through the public default pipeline.
//!
//! The inputs are the Batch 2 documentation placeholders the independent
//! measurement listed (`YOUR_DB_PASSWORD`, `YOUR_ZOOM_CLIENT_SECRET`, ...).
//! Real-shaped controls are assembled at run time from generated material; no
//! credential-shaped literal is committed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, single_byte_partition, whole_input};

/// Whole input, the same input in 7-byte chunks and in 1-byte chunks; the
/// incremental results must equal the whole-input one.
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

/// Exactly one `redact` finding spanning exactly `value`.
fn assert_value(input: &str, value: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(value).expect("the value is in the input");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

/// A synthetic body of `len` bytes over `[A-Za-z0-9]`, mixed so it never
/// reads as a counting run or filler.
fn body(len: usize, seed: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|index| {
            ALPHABET[(index * 29 + seed * 17 + index * index * 7) % ALPHABET.len()] as char
        })
        .collect()
}

const SERVICE_WORDS: [&str; 21] = [
    "adobe",
    "airtable",
    "asana",
    "atlas",
    "box",
    "canva",
    "contentful",
    "database",
    "db",
    "dropbox",
    "elastic",
    "hubspot",
    "instagram",
    "jfrog",
    "meta",
    "mongodb",
    "private",
    "salesforce",
    "spotify",
    "zendesk",
    "zoom",
];

#[test]
fn the_batch2_measured_placeholders_are_silent() {
    for input in [
        "{\"password\":\"YOUR_DB_PASSWORD\"}\n",
        "{\"password\":\"YOUR_DATABASE_PASSWORD\"}\n",
        "{\"password\":\"YOUR_ATLAS_PASSWORD\"}\n",
        "{\"password\":\"YOUR_MONGODB_PASSWORD\"}\n",
        "{\"client_secret\":\"YOUR_ZOOM_CLIENT_SECRET\"}\n",
        "{\"access_token\":\"YOUR_SPOTIFY_ACCESS_TOKEN\"}\n",
        "{\"personalAccessKey\":\"YOUR_HUBSPOT_PERSONAL_ACCESS_KEY\"}\n",
        "{\"private_key\":\"YOUR_PRIVATE_KEY\"}\n",
        "private_api_key = \"YOUR_PRIVATE_API_KEY\"\n",
        // already silent before: the consistency anchors
        "{\"password\":\"YOUR_USER_PASSWORD\"}\n",
        "{\"client_secret\":\"YOUR_APP_SECRET\"}\n",
    ] {
        assert_clean(input);
    }
}

#[test]
fn every_service_word_is_silent_in_every_lead_and_separator_layout() {
    for word in SERVICE_WORDS {
        for value in [
            format!("YOUR_{}_API_KEY", word.to_uppercase()),
            format!("your-{word}-client-secret"),
            format!("INSERT_{}_ACCESS_TOKEN_HERE", word.to_uppercase()),
            format!("replace.with.your.{word}.password"),
            format!("ENTER_YOUR_{}_PASSWORD", word.to_uppercase()),
        ] {
            for template in [
                "api_key={}\n",
                "\"client_secret\": \"{}\"\r\n",
                "password: '{}'\n",
                "export ACCESS_TOKEN={}\n",
            ] {
                assert_clean(&template.replace("{}", &value));
            }
        }
    }
}

#[test]
fn a_service_word_without_a_lead_word_or_a_credential_noun_is_not_enough() {
    // No lead word: a bare service credential name is not an instruction.
    for value in ["db_password_prod", "atlas-api-key-7"] {
        let findings = findings_with_parity(&format!("api_key={value}\n"));
        assert_eq!(findings.len(), 1, "{value}: {findings:?}");
    }
    // A lead word and service words, but no credential noun.
    for value in ["YOUR_ZOOM_ACCOUNT", "YOUR_DB_HOST", "YOUR_PRIVATE_ATLAS"] {
        let findings = findings_with_parity(&format!("api_key={value}\n"));
        assert_eq!(findings.len(), 1, "{value}: {findings:?}");
    }
}

#[test]
fn an_unlisted_word_or_glued_material_keeps_the_value_reported() {
    for value in [
        // one word off every list
        "YOUR_ACMECLOUD_API_KEY".to_owned(),
        "YOUR_STAGING_DB_PASSWORD".to_owned(),
        "your_zoom_webinar_secret".to_owned(),
        // a service word glued to random material, in either position
        format!("YOUR_ZOOM_CLIENT_SECRET{}", body(24, 1)),
        format!("YOUR_ZOOM_CLIENT_SECRET_{}", body(24, 2)),
        format!("YOUR_{}_PASSWORD", body(20, 3)),
        format!("YOUR_DB{}_PASSWORD", body(12, 4)),
        // a service word fused to its neighbour is a different word
        "YOUR_ZOOMCLIENT_SECRET".to_owned(),
        "YOUR_DBPASSWORD".to_owned(),
        // a digit keeps the value detected
        "YOUR_ZOOM9_CLIENT_SECRET".to_owned(),
    ] {
        let findings = findings_with_parity(&format!("client_secret={value}\n"));
        assert_eq!(findings.len(), 1, "{value}: {findings:?}");
    }
}

#[test]
fn real_shaped_values_containing_service_words_stay_detected_with_exact_spans() {
    for (index, word) in SERVICE_WORDS.iter().enumerate() {
        // random material between and around the words: never a whole word list match
        let value = format!("{}{word}{}", body(18, index), body(22, index + 40));
        assert_value(&format!("client_secret={value}\n"), &value);
        let value = format!("{}_{word}_{}", body(10, index + 3), body(24, index + 7));
        assert_value(&format!("{{\"client_secret\":\"{value}\"}}\n"), &value);
    }
    // random value opening with a lead word and a service word, then material
    let value = format!("your_zoom_{}", body(30, 9));
    assert_value(&format!("client_secret={value}\n"), &value);
}

#[test]
fn the_same_rule_is_shared_with_the_bearer_carrier() {
    assert_clean("Authorization: Bearer YOUR_SPOTIFY_ACCESS_TOKEN\n");
    let value = format!("{}spotify{}", body(20, 5), body(20, 6));
    assert_value(&format!("Authorization: Bearer {value}\n"), &value);
}
