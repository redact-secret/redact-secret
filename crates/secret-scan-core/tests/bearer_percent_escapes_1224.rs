//! Percent escapes inside an `Authorization: Bearer` value
//! (redact-secret#1224), driven through the public default pipeline.
//!
//! X's application-only documentation shows the Bearer header carrying
//! `%2F` and `%3D` inside the token. Under an explicit `Authorization:` or
//! `Proxy-Authorization:` header name a `%XX` triplet is part of the run; the
//! bare `Bearer` form and every other grammar keep their alphabet. Values are
//! assembled at run time from generated material.
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

/// One `bearer_token`, high, `redact`, exactly `value`.
fn assert_bearer(input: &str, value: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(value).expect("the value is in the input");
    let range = findings[0].range();
    assert_eq!(
        (range.start(), range.end()),
        (start, start + value.len()),
        "{input:?}"
    );
    assert_eq!(findings[0].type_name(), "bearer_token", "{input:?}");
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

/// The shape X's documentation shows: runs joined by escaped `/`, `+`, `=`.
fn escaped_token(seed: usize) -> String {
    format!(
        "{}%2B{}%2F{}%3D{}",
        body(24, seed),
        body(10, seed + 1),
        body(12, seed + 2),
        body(8, seed + 3)
    )
}

#[test]
fn an_escaped_value_under_the_header_is_redacted_whole() {
    for (index, header) in ["Authorization", "authorization", "Proxy-Authorization"]
        .into_iter()
        .enumerate()
    {
        let value = escaped_token(index);
        assert_bearer(&format!("{header}: Bearer {value}\n"), &value);
        assert_bearer(&format!("{header}:   Bearer\t{value}\r\n"), &value);
        assert_bearer(
            &format!("GET /x HTTP/1.1\n{header}: Bearer {value}\nHost: a\n"),
            &value,
        );
        assert_bearer(
            &format!("curl -H \"{header}: Bearer {value}\" https://x.test\n"),
            &value,
        );
    }
}

#[test]
fn a_short_leading_run_is_no_longer_missed() {
    // Seven bytes before the first escape was under the 12-byte floor.
    let value = format!("{}%2B{}", body(7, 7), body(12, 8));
    assert_bearer(&format!("Authorization: Bearer {value}\n"), &value);
}

#[test]
fn escapes_inside_a_joined_value_are_part_of_it() {
    let value = format!(
        "{}%3A{}:{}%2B{}",
        body(8, 9),
        body(8, 10),
        body(14, 11),
        body(10, 12)
    );
    assert_bearer(&format!("Authorization: Bearer {value}\n"), &value);
}

#[test]
fn the_bare_bearer_form_keeps_its_alphabet() {
    // No header name: the run still ends at the first `%`, and the tail stays
    // readable, which is the 2026-10-05 stated limit for that carrier.
    let head = body(24, 13);
    let value = format!("{head}%2B{}", body(12, 14));
    assert_bearer(&format!("Bearer {value}\n"), &head);
    let findings = findings_with_parity(&format!("Bearer {value}\n"));
    let (text, _) = whole_input(&format!("Bearer {value}\n"));
    assert!(text.contains("%2B"), "{findings:?}: {text:?}");
}

#[test]
fn ordinary_percent_text_after_the_header_value_stays_bounded() {
    // Under the 12-byte floor: silent.
    assert_clean("Authorization: Bearer abc%20def\n");
    assert_clean("Authorization: Bearer ab%2Bcd%3D\n");
    // A `%` that starts no triplet ends the run, as before.
    let run16 = body(16, 15);
    assert_bearer(&format!("Authorization: Bearer {run16}%zz\n"), &run16);
    assert_bearer(&format!("Authorization: Bearer {run16}%\n"), &run16);
    assert_bearer(&format!("Authorization: Bearer {run16}%2\n"), &run16);
    // A scheme glued to an escaped space is not the scheme.
    assert_clean(&format!("Authorization%3A%20Bearer%20{}\n", body(24, 16)));
    // Escaped prose after a real token is part of the same whitespace-free run.
    let value = format!("{run16}%0A%22%7D");
    assert_bearer(&format!("Authorization: Bearer {value}\n"), &value);
    // Whitespace still ends the value.
    assert_bearer(
        &format!("Authorization: Bearer {run16} %2B{}\n", body(12, 17)),
        &run16,
    );
}

#[test]
fn placeholders_and_unrelated_carriers_are_unchanged() {
    assert_clean("Authorization: Bearer YOUR_ACCESS_TOKEN\n");
    assert_clean("Authorization: Bearer xxxxxxxxxxxxxxxxxxxx\n");
    // `secret-token:` and the generic authorization alphabet keep theirs.
    let head = body(16, 18);
    let findings =
        findings_with_parity(&format!("Authorization: Basic {head}%2B{}\n", body(12, 19)));
    for finding in &findings {
        assert_ne!(finding.type_name(), "bearer_token");
    }
}

#[test]
fn the_escaped_value_matches_the_same_value_under_a_field_name() {
    let value = escaped_token(20);
    let field = findings_with_parity(&format!("access_token={value}\n"));
    assert_eq!(field.len(), 1, "{field:?}");
    let range = field[0].range();
    assert_eq!(range.end() - range.start(), value.len());
    assert_bearer(&format!("Authorization: Bearer {value}\n"), &value);
}
