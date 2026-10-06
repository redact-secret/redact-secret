//! Brace, angle, documented-mask and upper-case placeholders under credential
//! slots (redact-secret#1234 follow-up; benchmarks round-1 gap groups
//! `G-brace`, `G-angle` and `G-docmask`), driven through the public default
//! pipeline. Every real-shaped value is assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{assert_clean, assert_value, findings_with_parity};

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A deterministic random-looking value of `len` bytes.
fn random(len: usize, seed: usize) -> String {
    let chars: Vec<char> = ALNUM.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 13 + index * index * 3) % chars.len()])
        .collect()
}

/// The brace placeholders the provider documentation writes.
const BRACE_PLACEHOLDERS: &[&str] = &[
    "{CLIENT_SECRET}",
    "{your-app_id}",
    "{your-app_secret}",
    "{your-app-secret}",
    "{user-access-token}",
    "{short-lived-access-token}",
    "{YOUR_DEVELOPER_API_KEY}",
    "{ACCESS_TOKEN}",
    "{entry.fields.slug}",
    "{your api key}",
    "{your-app_id}|{your-app_secret}",
    "{app-id}:{app-secret}",
    // The square form HubSpot writes (issue #1228).
    "[YOUR_TOKEN]",
    "[your-api-key]",
    "[app-id]|[app-secret]",
];

#[test]
fn brace_placeholders_are_silent_in_query_form_and_url_parameters() {
    for placeholder in BRACE_PLACEHOLDERS {
        for name in [
            "client_secret",
            "access_token",
            "api_key",
            "refresh_token",
            "password",
        ] {
            // A raw request line, a form body, a quoted curl URL and a curl -d,
            // the value ending at each carrier's delimiter.
            assert_clean(&format!(
                "GET /v1/me?{name}={placeholder} HTTP/1.1\nHost: api.example.test\n"
            ));
            assert_clean(&format!(
                "GET /v1/me?{name}={placeholder}&grant_type=x HTTP/1.1\n"
            ));
            assert_clean(&format!(
                "POST /oauth/token HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\ngrant_type=client_credentials&{name}={placeholder}\n"
            ));
            assert_clean(&format!(
                "curl \"https://api.example.test/v1/me?{name}={placeholder}\"\n"
            ));
            assert_clean(&format!(
                "curl -X POST -d \"{name}={placeholder}\" https://api.example.test/token\n"
            ));
            assert_clean(&format!(
                "curl -F {name}={placeholder} -F grant_type=x https://api.example.test/token\n"
            ));
            // A fragment parameter.
            assert_clean(&format!(
                "https://client.example.test/callback#{name}={placeholder}&state=x\n"
            ));
        }
    }
}

#[test]
fn brace_placeholders_are_silent_as_quoted_json_values() {
    for placeholder in BRACE_PLACEHOLDERS {
        assert_clean(&format!("{{\"client_secret\": \"{placeholder}\"}}\n"));
        assert_clean(&format!(
            "{{\n  \"refresh_token\": \"{placeholder}\",\n  \"client_id\": \"x\"\n}}\n"
        ));
        assert_clean(&format!("client_secret: \"{placeholder}\"\n"));
    }
}

#[test]
fn real_shaped_values_next_to_and_inside_braces_stay_detected() {
    let secret = random(40, 1);
    // The plain value, and a placeholder neighbour that is not read.
    assert_value(
        &format!("GET /me?client_secret={secret}&access_token={{your-app_id}} HTTP/1.1\n"),
        &secret,
    );
    assert_value(
        &format!("GET /me?access_token={{user-access-token}}&client_secret={secret} HTTP/1.1\n"),
        &secret,
    );
    // A brace-wrapped value with a digit is not a placeholder: the walk reads
    // it as before, up to the closing brace.
    let with_digits = random(24, 2);
    assert_value(
        &format!("GET /me?client_secret={{{with_digits}}} HTTP/1.1\n"),
        &format!("{{{with_digits}"),
    );
    // A brace-wrapped GUID.
    let guid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
    assert_value(
        &format!("GET /me?client_secret={{{guid}}} HTTP/1.1\n"),
        &format!("{{{guid}"),
    );
    // A placeholder word over the 24-letter bound, and one glued to material.
    let long_word = "a".repeat(25);
    for glued in [
        format!("{{{long_word}}}"),
        format!("{{your-secret}}{}", random(14, 3)),
    ] {
        let findings = findings_with_parity(&format!("GET /me?client_secret={glued} HTTP/1.1\n"));
        assert!(!findings.is_empty(), "{glued}");
    }
}

#[test]
fn angle_placeholders_with_spaces_are_silent_under_unquoted_slots() {
    for placeholder in [
        "<contents of private.key>",
        "<your private key>",
        "<paste your api key here>",
        "<refresh token>",
        "<contents of private.key file>",
    ] {
        assert_clean(&format!("private_key: {placeholder}\n"));
        assert_clean(&format!("api_key = {placeholder}\n"));
        assert_clean(&format!("password: {placeholder}\r\n"));
        assert_clean(&format!("export CLIENT_SECRET={placeholder}\n"));
        assert_clean(&format!("  private_key: {placeholder} # note\n"));
    }
}

#[test]
fn an_angle_group_that_is_not_the_whole_value_keeps_the_reading() {
    let secret = random(32, 4);
    // Material glued after the closing bracket, and an unclosed bracket.
    for input in [
        format!("api_key = <contents of key>{secret}\n"),
        format!("api_key = <contents {secret}\n"),
        format!("api_key = <{secret}\n"),
    ] {
        let findings = findings_with_parity(&input);
        assert!(!findings.is_empty(), "{input}");
    }
    assert_value(&format!("api_key = {secret}\n"), &secret);
}

#[test]
fn documented_masks_and_the_contentful_prefix_placeholders_are_silent() {
    for value in [
        "CFPAT-xxx",
        "CFPAT-xxxxxxxx",
        "CFPAT-123...789",
        "CFPAT-123\u{2026}789",
        "CFPAT-<your-token>",
        "CFPAT-your-token",
        "CFPAT-YOUR_TOKEN",
        "abc...xyz",
    ] {
        assert_clean(&format!(
            "CONTENTFUL_INTEGRATION_TEST_CMA_TOKEN={value} \\\n"
        ));
        assert_clean(&format!(
            "$ node client.js [--ssl] --token '{value}' --space 'cfexample'\n"
        ));
        assert_clean(&format!("{{\"cma_token\": \"{value}\"}}\n"));
        assert_clean(&format!("access_token: {value}\n"));
    }
}

#[test]
fn a_real_shaped_value_behind_the_prefix_or_around_an_ellipsis_stays_detected() {
    let body = random(43, 5);
    let prefixed = ["CFPAT", "-", body.as_str()].concat();
    assert_value(
        &format!("CONTENTFUL_MANAGEMENT_TOKEN={prefixed}\n"),
        &prefixed,
    );
    assert_value(
        &format!("{{\"access_token\": \"{prefixed}\"}}\n"),
        &prefixed,
    );
    // An ellipsis whose sides are longer than a display keeps (13 bytes).
    let long_head = format!("{}...{}", random(13, 6), random(5, 7));
    assert_value(&format!("access_token={long_head}\n"), &long_head);
    // Material glued after the placeholder word keeps the value reported.
    let glued = format!("CFPAT-yourtoken{}", random(20, 8));
    assert_value(&format!("access_token={glued}\n"), &glued);
}

#[test]
fn a_quoted_variable_name_is_a_reference_only_in_its_own_slot() {
    for (name, value) in [
        ("x-api-key", "ZOOM_API_KEY"),
        ("api_key", "MY_API_KEY"),
        ("password", "ADMIN_PASSWORD"),
        ("client_secret", "APP_CLIENT_SECRET"),
        ("access_token", "ZOOM_ACCESS_TOKEN"),
    ] {
        assert_clean(&format!("{{\"{name}\": \"{value}\"}}\n"));
        assert_clean(&format!(
            "curl https://api.example.test/v2 -H \"{name}: {value}\"\n"
        ));
    }
    // Another credential word, a digit-and-lower suffix and a random value
    // keep the reading.
    let random_caps = "Q8W2E7R4T1Y6U3I9O0P5".to_owned();
    for (name, value) in [
        ("api_key", "OTHER_TOKEN"),
        ("password", "ADMIN_PASSWORD_2f9QxL7m"),
        ("api_key", random_caps.as_str()),
    ] {
        let findings = findings_with_parity(&format!("{{\"{name}\": \"{value}\"}}\n"));
        assert!(!findings.is_empty(), "{name}: {value}");
    }
}
