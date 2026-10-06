//! The Group E current and historical claim boundaries (redact-secret#1230),
//! driven through the public default pipeline.
//!
//! `docs/audits/evidence/1230/README.md` adopts a conditional contract and
//! claims no row covered. The decision record
//! `decision-keep-credential-lifecycle-era-out-of-detection-and-preserve-backward-redaction`
//! and the contract freeze boundaries that are cheap to pin and need no code
//! change:
//!
//! * a retired, deprecated or superseded credential is read exactly like a
//!   current one in the same carrier: no era word near it makes it silent;
//! * a generic PEM private key is one `private_key` finding over the whole
//!   block with the `block` default and no provider type, a public certificate
//!   is silent, and a signed JWT assertion is its own `jwt` finding;
//! * a Basic envelope is one span over the whole encoded value whatever it
//!   holds, so the email and token components of a Zendesk credential string,
//!   the client id and secret of a Reddit app, and a Reddit installed-app
//!   envelope with an empty password are all inside the span;
//! * the Reddit OAuth carriers (a lower-case `bearer` scheme, an implicit-grant
//!   URL fragment, a `refresh_token` body field) are read generically.
//!
//! These are policy pins, not coverage claims. Every value is synthetic and
//! built at runtime from a fixed pseudo-random alphabet walk.
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

/// Exactly one finding spanning exactly `value` (found once in `input`).
fn one_finding(input: &str, value: &str) -> Finding {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    assert_eq!(input.matches(value).count(), 1, "{input:?}");
    let start = input.find(value).expect("the value is in the input");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    findings[0].clone()
}

fn assert_redacted(input: &str, value: &str, type_name: &str) {
    let finding = one_finding(input, value);
    assert_eq!(finding.type_name(), type_name, "{input:?}");
    assert_eq!(finding.action(), Action::Redact, "{input:?}");
    assert_eq!(finding.confidence(), Confidence::High, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

const ALNUM: &[u8; 62] = b"Qf7Lm2Zp9TrW4vKc8NbYxJdH6sAeGuwR5tykMXnPaUoVhCiBDgEjFlIqOSTz03";

fn run_of(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| ALNUM[(i * 7 + seed * 13 + 3) % ALNUM.len()] as char)
        .collect()
}

/// Standard base64 with padding, so an envelope can be built from a plain
/// composition without a dependency. The product never decodes it.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn pem(label: &str, lines: usize, seed: usize) -> String {
    let body: Vec<String> = (0..lines).map(|i| run_of(64, seed + i)).collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----",
        body.join("\n")
    )
}

#[test]
fn an_era_word_near_a_credential_never_silences_it() {
    // Deprecation, end of life, a creation block and a sunset are provider
    // lifecycle statements. None says authentication stopped, and a retired
    // credential still leaks from a log, a configuration or a backup.
    let value = run_of(40, 1);
    for era in [
        "legacy",
        "deprecated",
        "retired in 2024",
        "end of life reached",
        "sunset 2022-11-30",
        "no longer issued",
    ] {
        assert_redacted(
            &format!("# {era}\naccess_token={value}\n"),
            &value,
            "contextual_secret",
        );
        assert_redacted(
            &format!("{era}: Authorization: Bearer {value}"),
            &value,
            "bearer_token",
        );
    }
}

#[test]
fn a_generic_pem_key_is_one_block_finding_with_no_provider_type() {
    // The retired Adobe Service Account (JWT) credential is a locally
    // generated RSA key with no Adobe-specific marker, so the existing PEM
    // reading is the contract: the whole block, the `block` default.
    for label in ["PRIVATE KEY", "RSA PRIVATE KEY"] {
        let key = pem(label, 4, 2);
        let input = format!("key file:\n{key}\nend\n");
        let finding = one_finding(&input, &key);
        assert_eq!(finding.type_name(), "private_key", "{label}");
        assert_eq!(finding.action(), Action::Block, "{label}");
        assert_eq!(finding.confidence(), Confidence::High, "{label}");
    }
    // The public certificate that is uploaded instead is not a secret.
    assert_clean(&format!("{}\n", pem("CERTIFICATE", 6, 3)));
}

#[test]
fn a_signed_assertion_is_its_own_jwt_finding_beside_the_client_secret() {
    let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    let payload = "eyJzdWIiOiJzeW50aGV0aWMiLCJleHAiOjF9";
    let assertion = format!("{header}.{payload}.{}", run_of(43, 4));
    let input = format!("client_id=pub1&jwt_token={assertion}\n");
    let finding = one_finding(&input, &assertion);
    assert_eq!(finding.type_name(), "jwt");
    assert_eq!(finding.action(), Action::Redact);
}

#[test]
fn a_basic_envelope_is_one_span_whatever_it_holds() {
    // Zendesk: the credential string is `{email}/token` as the user and the
    // token as the password. The envelope is never decoded, so the email and
    // the token are both inside the one span; a component-level span is
    // conditional on a raw layout and is not read from an encoded one.
    let zendesk = base64(format!("agent@example.test/token:{}", run_of(40, 5)).as_bytes());
    // Reddit: the client id is the user and the client secret the password.
    let reddit = base64(format!("{}:{}", run_of(14, 6), run_of(27, 7)).as_bytes());
    // Reddit installed app: the same envelope with an empty password. It is
    // not a credential once decoded, but nothing is decoded, so it is redacted;
    // an accepted false positive under the defer-encoded-decoding decision.
    let installed = base64(format!("{}:", run_of(14, 8)).as_bytes());
    for envelope in [zendesk, reddit, installed] {
        assert_redacted(
            &format!("GET /api/v2/users/me.json HTTP/1.1\nAuthorization: Basic {envelope}\n"),
            &envelope,
            "authorization_credential",
        );
        assert_redacted(
            &format!("curl -H 'Authorization: Basic {envelope}' https://api.example.test/x"),
            &envelope,
            "authorization_credential",
        );
    }
}

#[test]
fn the_reddit_oauth_carriers_are_read_generically() {
    let token = format!("{}-{}", run_of(10, 9), run_of(25, 10));
    // A lower-case `bearer` scheme, as the archived documentation writes it.
    assert_redacted(
        &format!("Authorization: bearer {token}"),
        &token,
        "bearer_token",
    );
    // The implicit-grant URL fragment.
    assert_redacted(
        &format!("https://app.example.test/cb#access_token={token}&token_type=bearer&state=x"),
        &token,
        "contextual_secret",
    );
    // The refresh request body field.
    assert_redacted(
        &format!("grant_type=refresh_token&refresh_token={token}"),
        &token,
        "contextual_secret",
    );
}
