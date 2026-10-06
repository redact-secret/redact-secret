//! A digits-only value in a credential-named slot (redact-secret#1230, round-1
//! gap group `G-digits24`), driven through the public default pipeline.
//!
//! The evidence Cases flag a value in a named slot by position, not shape, so a
//! run of 24 decimal digits in the slot is a finding like a hexadecimal or
//! alphanumeric one. A digits-only value has no shape that separates a secret
//! from a long id, so it is read at medium confidence (`warn`, text unchanged)
//! from 16 digits, and a counting or repeated run, or fewer digits, stays
//! silent. Every value is synthetic and assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence};
use support::{assert_clean, assert_value, assert_values_with, findings_with_parity, whole_input};

/// A deterministic, non-counting run of `len` decimal digits.
fn digits(len: usize, seed: usize) -> String {
    (0..len)
        .map(|index| {
            char::from(b'0' + u8::try_from((index * 7 + seed * 3 + index * index) % 10).unwrap())
        })
        .collect()
}

/// One `contextual_secret`, medium, `warn`, exactly `value`, text unchanged.
fn assert_warned(input: &str, value: &str) {
    assert_values_with(input, &[value], Confidence::Medium, Action::Warn);
    let (text, _) = whole_input(input);
    assert_eq!(text, input, "a warn leaves the text unchanged");
}

#[test]
fn a_24_digit_value_is_read_in_the_named_slots_of_the_baseline() {
    let value = digits(24, 1);
    for input in [
        // Airtable query parameter, Dropbox response member, Reddit members, form and fragment.
        format!("GET /v0/appX/Table?maxRecords=3&api_key={value} HTTP/1.1\n"),
        format!("{{\n  \"access_token\": \"{value}\",\n  \"token_type\": \"bearer\"\n}}\n"),
        format!("{{\"refresh_token\":\"{value}\",\"scope\":\"identity\"}}\n"),
        format!("grant_type=refresh_token&refresh_token={value}&client_id=x\n"),
        format!("https://client.example.test/callback#access_token={value}&token_type=bearer\n"),
        // The JFrog header and the HubSpot parameter.
        format!("GET /x HTTP/1.1\nX-JFrog-Art-Api: {value}\n"),
        format!("GET /x?count=10&hapikey={value} HTTP/1.1\n"),
        format!("curl \"https://api.hubspot.example.test/x?hapikey={value}\"\n"),
        // Names of the high-signal vocabulary.
        format!("password={value}\n"),
        format!("{{\"client_secret\": \"{value}\"}}\n"),
        format!("API_KEY={value}\n"),
        format!("export SECRET_KEY=\"{value}\"\n"),
        // A JSON number.
        format!("{{\"api_key\": {value}}}\n"),
    ] {
        assert_warned(&input, &value);
    }
}

#[test]
fn the_floor_is_16_digits_and_counting_or_repeated_runs_are_not_values() {
    for len in [16usize, 17, 20, 24, 40] {
        let value = digits(len, 2);
        assert_warned(&format!("API_KEY={value}\n"), &value);
        assert_warned(&format!("{{\"access_token\":\"{value}\"}}\n"), &value);
    }
    for len in [8usize, 12, 15] {
        assert_clean(&format!("API_KEY={}\n", digits(len, 3)));
        assert_clean(&format!("{{\"access_token\":\"{}\"}}\n", digits(len, 3)));
    }
    for run in [
        "1234567890123456",
        "12345678901234567890",
        "7890123456789012",
        "0000000000000000",
        "1111111111111111",
        "9999999999999999999999",
    ] {
        assert_clean(&format!("API_KEY={run}\n"));
        assert_clean(&format!("{{\"access_token\":\"{run}\"}}\n"));
    }
}

#[test]
fn a_digit_run_with_any_other_byte_keeps_its_reading() {
    // Not digits only: the existing tiers apply, so a random alphanumeric run
    // is still high confidence and `redact`.
    let mixed = ["9f4a82c1d70e3b65", "a1f8d2c47e90b3a6"].concat();
    assert_value(&format!("API_KEY={mixed}\n"), &mixed);
    // A signed or separated number is not a digit run.
    let grouped = format!("{}-{}-{}", digits(6, 6), digits(6, 7), digits(6, 8));
    let findings = findings_with_parity(&format!("API_KEY={grouped}\n"));
    assert!(
        findings.iter().all(|f| f.confidence() != Confidence::High),
        "{findings:?}"
    );
}

#[test]
fn names_that_are_not_credential_names_and_ambiguous_names_stay_silent() {
    let value = digits(24, 9);
    for input in [
        format!("user_id={value}\n"),
        format!("account_number={value}\n"),
        format!("{{\"order_id\":\"{value}\"}}\n"),
        format!("timestamp_ms={value}\n"),
        format!("client_id={value}\n"),
        // The ambiguous bucket keeps its own entropy bar, which a digit run
        // never reaches.
        format!("auth={value}\n"),
        format!("credentials={value}\n"),
        // A request-scoped token name.
        format!("next_page_token={value}\n"),
        format!("csrf_token={value}\n"),
        // The bare `token`.
        format!("token={value}\n"),
        format!("{{\"token\":\"{value}\"}}\n"),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn context_does_not_move_the_span_and_placeholders_stay_silent() {
    let value = digits(24, 10);
    assert_warned(&format!("로그: 설정\nAPI_KEY={value}\n끝\n"), &value);
    let big = "configuration line of ordinary words\n".repeat(2_000);
    assert_warned(&format!("{big}API_KEY={value}\n"), &value);
    let second = digits(24, 11);
    assert_values_with(
        &format!("API_KEY={value}\nSECRET_KEY={second}\n"),
        &[&value, &second],
        Confidence::Medium,
        Action::Warn,
    );
    for placeholder in [
        "${API_KEY}",
        "<api key>",
        "{api_key}",
        "****************************",
        "YOUR_API_KEY",
    ] {
        assert_clean(&format!("API_KEY={placeholder}\n"));
    }
}
