//! MongoDB URI userinfo passwords the strict grammar declined
//! (redact-secret#1226), driven through the public default pipeline.
//!
//! A password with a malformed percent escape, a raw `@`, or a raw `/`, `?` or
//! `#` is read at medium confidence over the password slot; every well-formed
//! URI and every benign control keeps its previous result. Values are
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

/// One `connection_string_password`, `redact`, exactly `password`, at
/// `confidence`; the password is gone from the redacted text.
fn assert_password(input: &str, password: &str, confidence: Confidence) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(password).expect("the password is in the input");
    let range = findings[0].range();
    assert_eq!(
        (range.start(), range.end()),
        (start, start + password.len()),
        "{input:?}"
    );
    assert_eq!(findings[0].type_name(), "connection_string_password");
    assert_eq!(findings[0].confidence(), confidence, "{input:?}");
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(password), "{input:?}: {text:?}");
}

fn body(len: usize, seed: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|index| {
            ALPHABET[(index * 29 + seed * 17 + index * index * 7) % ALPHABET.len()] as char
        })
        .collect()
}

const SRV_HOST: &str = "cluster0.example.test";
const SEED_HOSTS: &str = "db0.example.test:27017,db1.example.test:27018";

fn uris(userinfo: &str) -> Vec<String> {
    vec![
        format!("mongodb+srv://{userinfo}@{SRV_HOST}/admin?retryWrites=true\n"),
        format!("mongodb://{userinfo}@{SEED_HOSTS}/admin\n"),
        format!("MONGODB://{userinfo}@localhost:27017\n"),
        format!("uri = \"mongodb+srv://{userinfo}@{SRV_HOST}/db\"\r\n"),
    ]
}

#[test]
fn a_malformed_percent_escape_is_read_over_the_password_slot() {
    for password in [
        format!("{}%", body(14, 1)),
        format!("ab%zz{}", body(10, 2)),
        format!("100%{}", body(10, 3)),
        "100%%".to_owned(),
        format!("{}%2", body(12, 4)),
        format!("%{}", body(12, 5)),
        format!("{}%G1{}", body(8, 6), body(8, 7)),
    ] {
        for input in uris(&format!("app:{password}")) {
            assert_password(&input, &password, Confidence::Medium);
        }
    }
}

#[test]
fn a_raw_at_sign_ends_the_userinfo_at_the_last_at_sign() {
    let password = format!("{}@{}", body(9, 8), body(9, 9));
    for input in uris(&format!("app:{password}")) {
        assert_password(&input, &password, Confidence::Medium);
    }
    let two = format!("{}@{}@{}", body(5, 10), body(5, 11), body(5, 12));
    for input in uris(&format!("app:{two}")) {
        assert_password(&input, &two, Confidence::Medium);
    }
}

#[test]
fn a_raw_slash_question_mark_or_hash_stays_inside_the_password() {
    for separator in ["/", "?", "#"] {
        let password = format!("{}{separator}{}", body(10, 13), body(10, 14));
        for input in uris(&format!("app:{password}")) {
            assert_password(&input, &password, Confidence::Medium);
        }
    }
}

#[test]
fn well_formed_uris_keep_their_span_and_confidence() {
    let password = body(20, 15);
    assert_password(
        &format!("mongodb+srv://app:{password}@{SRV_HOST}/db\n"),
        &password,
        Confidence::High,
    );
    let escaped = format!("{}%2B{}%40", body(8, 16), body(8, 17));
    assert_password(
        &format!("mongodb://app:{escaped}@{SEED_HOSTS}/db\n"),
        &escaped,
        Confidence::High,
    );
    // The strict reading owns the URI: no second or wider span.
    let query = format!("mongodb://app:{password}@localhost:27017/db?appname=a@b.example\n");
    assert_password(&query, &password, Confidence::High);
}

#[test]
fn host_only_and_benign_neighbours_stay_silent() {
    for input in [
        "mongodb://localhost:27017/db?appname=a@b.example\n",
        "mongodb://localhost:27017/db?contact=a:b@c.example\n",
        "mongodb+srv://cluster0.example.test/db?x=y:z@w.example\n",
        "mongodb://db0.example.test,db1.example.test/db#frag@host.example\n",
        "mongodb://app@localhost:27017/db\n",
        "mongodb://app:@localhost:27017/db\n",
        "mongodb://:secretvalue1@localhost:27017/db\n",
        "contact me@example.test about mongodb://localhost\n",
        "see mongodb://app:%@ and move on\n",
    ] {
        assert_clean(input);
    }
}

#[test]
fn placeholders_and_references_stay_silent_in_the_relaxed_forms() {
    for password in [
        "password",
        "<password>",
        "${MONGO_PASSWORD}",
        "your_password_here",
    ] {
        assert_clean(&format!(
            "mongodb://app:{password}@localhost:27017/db?x=a@b.example\n"
        ));
        assert_clean(&format!("mongodb+srv://app:{password}@{SRV_HOST}/db\n"));
    }
}

#[test]
fn a_digit_password_before_a_raw_slash_reads_as_host_and_port_and_stays_unread() {
    // Pinned residual: `app:123/x@host` is `host:port` plus a path to every
    // reader of the grammar.
    assert_clean("mongodb://app:123/x@localhost:27017/db\n");
}

#[test]
fn other_schemes_keep_the_strict_grammar() {
    let password = format!("{}%", body(14, 18));
    for scheme in ["postgres", "mysql", "redis", "https", "amqp"] {
        assert_clean(&format!("{scheme}://app:{password}@localhost:5432/db\n"));
    }
    assert_clean("postgres://fixture:SYNTHETIC%GGREVOKED@localhost/example\n");
    let raw_at = format!("{}@{}", body(9, 19), body(9, 20));
    assert_clean(&format!("postgres://app:{raw_at}@localhost:5432/db\n"));
}
