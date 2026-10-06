//! The `X-JFrog-Art-Api` header carrier (redact-secret#1228 Group C `JFrog`
//! reference token, #1230 Group E `JFrog` API key), driven through the public
//! default pipeline.
//!
//! credential-evidence Cases `jfrog-reference-token-header-and-basic-password-value`
//! and `jfrog-api-key-header-and-basic-password-value` flag the value of the
//! `X-JFrog-Art-API` header by its position, not its shape. The `curl -u
//! user:<secret>` password slot is deliberately not read here (issue #1247).
//! Every value is synthetic and assembled at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{assert_clean, assert_value, assert_values_with};

/// A deterministic synthetic value of `len` bytes from `alphabet`.
fn value(alphabet: &str, len: usize, seed: usize) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    (0..len)
        .map(|index| chars[(index * 7 + seed * 11 + index * index * 3) % chars.len()])
        .collect()
}

const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX: &str = "0123456789abcdef";

/// The shapes the Cases flag in the header slot (digits are #1230's
/// digits-only follow-up).
fn shapes() -> Vec<String> {
    let documented = format!("{}{}{}", "AK", "Cp", value(ALNUM, 69, 3));
    vec![
        value(HEX, 32, 1),
        value(ALNUM, 64, 2),
        value(&format!("{ALNUM}-_"), 40, 4),
        "qmxtvbnlkrwzpdsh".to_owned(),
        format!("{}-{}", value(ALNUM, 20, 6), value(ALNUM, 20, 7)),
        format!(
            "{}.{}_{}",
            value(ALNUM, 12, 8),
            value(ALNUM, 12, 9),
            value(ALNUM, 12, 10)
        ),
        value(ALNUM, 150, 11),
        value(ALNUM, 16, 12),
        documented,
    ]
}

#[test]
fn the_header_is_read_in_both_spellings_and_every_carrier_layout() {
    for secret in shapes() {
        for name in [
            "X-JFrog-Art-Api",
            "X-JFrog-Art-API",
            "x-jfrog-art-api",
            "X-JFROG-ART-API",
        ] {
            // Raw HTTP, CRLF and LF, end of input, trailing whitespace.
            assert_value(
                &format!(
                    "GET /artifactory/api/system/ping HTTP/1.1\r\nHost: acme.jfrog.io\r\n{name}: {secret}\r\nAccept: */*\r\n\r\n"
                ),
                &secret,
            );
            assert_value(
                &format!("GET /a HTTP/1.1\n{name}: {secret}\nAccept: */*\n"),
                &secret,
            );
            assert_value(&format!("GET /a HTTP/1.1\n{name}: {secret}"), &secret);
            assert_value(&format!("GET /a HTTP/1.1\n{name}: {secret}  \t\n"), &secret);
            // curl -H, double and single quoted, long option, after the URL.
            assert_value(
                &format!(
                    "curl -H \"{name}: {secret}\" https://acme.jfrog.io/artifactory/api/repositories\n"
                ),
                &secret,
            );
            assert_value(
                &format!(
                    "curl -H '{name}: {secret}' https://acme.jfrog.io/artifactory/api/repositories\n"
                ),
                &secret,
            );
            assert_value(
                &format!("curl --header \"{name}: {secret}\" https://acme.jfrog.io/x\n"),
                &secret,
            );
            assert_value(
                &format!("curl https://acme.jfrog.io/x -H \"{name}: {secret}\"\n"),
                &secret,
            );
            // A JSON header map, compact and pretty-printed.
            assert_value(
                &format!("{{\"headers\":{{\"{name}\":\"{secret}\"}}}}\n"),
                &secret,
            );
            assert_value(
                &format!("{{\n  \"headers\": {{\n    \"{name}\": \"{secret}\"\r\n  }}\n}}\n"),
                &secret,
            );
        }
    }
}

#[test]
fn context_around_the_header_does_not_move_the_span() {
    let secret = value(ALNUM, 64, 20);
    // Multibyte text before and after: the span is a UTF-8 byte range.
    assert_value(
        &format!("로그: 요청 헤더\nX-JFrog-Art-Api: {secret}\n끝\n"),
        &secret,
    );
    // A large preceding body.
    let big = "request line of ordinary words\n".repeat(2_000);
    assert_value(&format!("{big}\nX-JFrog-Art-Api: {secret}\n"), &secret);
    // The header twice: two findings, one per value.
    let second = value(ALNUM, 64, 21);
    assert_values_with(
        &format!("X-JFrog-Art-Api: {secret}\nX-JFrog-Art-Api: {second}\n"),
        &[&secret, &second],
        redact_secret::Confidence::High,
        redact_secret::Action::Redact,
    );
    // A same-shape neighbour header is its own slot: a neighbouring secret
    // under another credential name is read as well, and a public one is not.
    let other = value(ALNUM, 64, 22);
    assert_values_with(
        &format!("X-JFrog-Art-Api: {secret}\nX-Api-Key: {other}\n"),
        &[&secret, &other],
        redact_secret::Confidence::High,
        redact_secret::Action::Redact,
    );
    assert_value(
        &format!("X-Request-Id: {other}\nX-JFrog-Art-Api: {secret}\nX-Trace-Id: {other}\n"),
        &secret,
    );
}

#[test]
fn placeholders_references_masks_and_non_values_are_silent() {
    for placeholder in [
        "<api-key>",
        "<YOUR_API_KEY>",
        "${JFROG_API_KEY}",
        "$JFROG_API_KEY",
        "YOUR_JFROG_API_KEY",
        "********************************",
        "xxxxxxxxxxxxxxxxxxxxxxxx",
        "{{ jfrog_api_key }}",
        "redacted",
    ] {
        assert_clean(&format!(
            "GET /a HTTP/1.1\nX-JFrog-Art-Api: {placeholder}\n"
        ));
        assert_clean(&format!(
            "curl -H \"X-JFrog-Art-Api: {placeholder}\" https://acme.jfrog.io/x\n"
        ));
        assert_clean(&format!("{{\"X-JFrog-Art-Api\":\"{placeholder}\"}}\n"));
    }
    // Empty value and prose that names the header.
    assert_clean("GET /a HTTP/1.1\nX-JFrog-Art-Api:\nAccept: */*\n");
    assert_clean("Send the key in the X-JFrog-Art-Api header or as the basic password.\n");
}

#[test]
fn only_the_whole_header_name_is_read() {
    let secret = value(ALNUM, 40, 30);
    // Neighbouring names stay unread: no suffix, prefix or *_api rule.
    for name in [
        "X-JFrog-Art-Api-Id",
        "X-JFrog-Art-Api-Version",
        "JFrog-Art-Api",
        "Art-Api",
        "X-Art-Api",
        "X-JFrog-Art",
        "X-JFrog-Api",
        "My-X-JFrog-Art-Api",
    ] {
        assert_clean(&format!("GET /a HTTP/1.1\n{name}: {secret}\n"));
    }
}

#[test]
fn the_basic_password_slot_is_a_stated_false_negative_until_1247() {
    // `curl -u user:<secret>` is not read (issue #1247). The user part and
    // the password stay out of the output of this reader.
    let secret = value(ALNUM, 64, 40);
    // The flag and the user are joined at run time so no `-u user:value` text
    // is committed.
    let flag = ["-", "u"].concat();
    assert_clean(&format!(
        "curl {flag} alice:{secret} https://acme.jfrog.io/artifactory/api/system/ping\n"
    ));
}
