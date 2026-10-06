//! The Group C format-conflict boundaries (redact-secret#1228), driven through
//! the public default pipeline.
//!
//! The contract adopted in [`docs/audits/evidence/1228/README.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1228/README.md) makes no row
//! covered. It decides four boundaries that are cheap to pin and that no
//! detector, registry or vocabulary change touches:
//!
//! * a distinctive prefix alone does not make a bare value a finding (no bare
//!   detector is adopted for any of the 11 rows);
//! * the same shapes in a credential slot are read as the generic type with the
//!   exact value as the span, whatever the provider's prefix or width, so an
//!   opaque provider statement is never overridden by a scanner width;
//! * a form `client_secret` ends at its delimiter and keeps `org_id` and the
//!   public client id outside;
//! * an `Authorization: Basic` envelope is one span over the whole undecoded
//!   value, the public client id half included.
//!
//! These are policy pins, not coverage claims: they say what the product does
//! today under the adopted contract so that a change is visible. Every value
//! is synthetic and built at runtime from a fixed pseudo-random alphabet walk.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence, Finding};
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

/// Exactly one finding of `type_name`, `redact`, high confidence, spanning
/// exactly `value` (found once in `input`).
fn assert_one(input: &str, value: &str, type_name: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    assert_eq!(input.matches(value).count(), 1, "{input:?}");
    let start = input.find(value).expect("the value is in the input");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    assert_eq!(findings[0].type_name(), type_name, "{input:?}");
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    assert_eq!(findings[0].confidence(), Confidence::High, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

const ALNUM: &[u8; 62] = b"Qf7Lm2Zp9TrW4vKc8NbYxJdH6sAeGuwR5tykMXnPaUoVhCiBDgEjFlIqOSTz03";
const HEX: &[u8; 16] = b"3f9a07c2e5b8d146";

/// A deterministic mixed-class run of `len` bytes; `seed` makes runs differ.
fn run_of(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| ALNUM[(i * 7 + seed * 13 + 3) % ALNUM.len()] as char)
        .collect()
}

fn hex_of(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| HEX[(i * 5 + seed * 3 + 1) % HEX.len()] as char)
        .collect()
}

fn uuid_of(seed: usize) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex_of(8, seed),
        hex_of(4, seed + 1),
        hex_of(4, seed + 2),
        hex_of(4, seed + 3),
        hex_of(12, seed + 4)
    )
}

/// The prefix shapes that scanner rules or sample code attach to a row, built
/// with no width or alphabet taken from a provider statement. None is in the
/// shape of any real credential: the bodies are a fixed walk over a 62-byte
/// alphabet.
fn prefixed_shapes() -> Vec<(&'static str, String)> {
    vec![
        ("adobe p8e", format!("p8e-{}", run_of(32, 1))),
        (
            "airtable pat",
            format!("pat{}.{}", run_of(14, 2), hex_of(64, 2)),
        ),
        ("dropbox sl 136", format!("sl.{}", run_of(136, 3))),
        ("dropbox sl.u", format!("sl.u.{}", run_of(136, 4))),
        ("dropbox sl 400", format!("sl.{}", run_of(400, 5))),
        ("hubspot pat-na1", format!("pat-na1-{}", uuid_of(6))),
        ("hubspot pat-eu1", format!("pat-eu1-{}", uuid_of(7))),
        ("contentful CFPAT", format!("CFPAT-{}", run_of(43, 8))),
        ("salesforce 5Aep861", format!("5Aep861{}", run_of(80, 9))),
        ("meta 32 hex", hex_of(32, 10)),
        ("x 50 alnum", run_of(50, 11)),
    ]
}

#[test]
fn a_distinctive_prefix_alone_does_not_make_a_bare_value_a_finding() {
    for (_label, value) in prefixed_shapes() {
        assert_clean(&format!("see {value} here"));
        assert_clean(&format!("{value}\n"));
    }
}

#[test]
fn the_same_shapes_in_a_credential_slot_are_generic_with_the_exact_value() {
    for (_label, value) in prefixed_shapes() {
        // A named field: the generic contextual type, exactly the value.
        assert_one(
            &format!("access_token={value}&token_type=bearer"),
            &value,
            "contextual_secret",
        );
        // An explicit Bearer header: the generic Bearer type, exactly the value.
        assert_one(
            &format!("Authorization: Bearer {value}"),
            &value,
            "bearer_token",
        );
    }
}

#[test]
fn a_scanner_width_never_bounds_an_opaque_token() {
    // Airtable and Dropbox state the token is opaque and of variable length
    // (Dropbox: it may exceed 1 KB). The product reads the whole value at any
    // length, so no tool maximum or minimum above the 8-byte floor is adopted.
    for len in [20, 64, 100, 130, 135, 152, 153, 400, 1500] {
        let value = format!("sl.{}", run_of(len, 12));
        assert_one(
            &format!("{{\"access_token\":\"{value}\",\"expires_in\":14400}}"),
            &value,
            "contextual_secret",
        );
    }
}

#[test]
fn a_form_client_secret_ends_at_its_delimiter_and_keeps_the_public_halves_outside() {
    let value = format!("p8e-{}", run_of(32, 13));
    let client_id = hex_of(32, 14);
    let org = format!("{}@AdobeOrg", hex_of(24, 15));
    // The S2S shape: a client secret beside the public client id and scope.
    assert_one(
        &format!(
            "client_id={client_id}&client_secret={value}&grant_type=client_credentials&scope=openid"
        ),
        &value,
        "contextual_secret",
    );
    // The Enterprise shape: no prefix is needed, and `org_id` stays outside.
    let plain = run_of(32, 16);
    assert_one(
        &format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret={plain}&org_id={org}"
        ),
        &plain,
        "contextual_secret",
    );
}

#[test]
fn a_basic_envelope_is_one_span_over_the_whole_undecoded_value() {
    // The Web App shape: Basic over client id and client secret. The envelope
    // is never decoded and never split, so the public client id half is inside
    // the span. The value below is an arbitrary base64-alphabet run, not an
    // encoding of anything.
    let envelope = format!("{}{}==", run_of(46, 17), "AB");
    let input = format!("POST /ims/token/v3 HTTP/1.1\nAuthorization: Basic {envelope}\n");
    assert_one(&input, &envelope, "authorization_credential");
}
