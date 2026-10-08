//! Issue #1110: the Ory session and `OAuth2` token detector (`ory-token`)
//! through the public API with the full default registry.
//!
//! Every token is built at run time from a literal prefix plus a seeded
//! low-entropy synthetic filler, so no realistic key literal is committed.
//! The filler was never derived from an issued credential.
//!
//! Against the whole built-in registry rather than the detector alone:
//!
//! - every probe context yields exactly one finding, of the provider type, at
//!   exactly the token's UTF-8 byte span, redacted (so no `jwt`,
//!   `bearer_token` or `contextual_secret` finding survives beside it);
//! - one-property twins and the excluded admin-key prefixes yield no finding
//!   of `ory-token`;
//! - the whole input, every two-chunk UTF-8 byte partition and a per-line
//!   incremental session agree on text, spans, detector and type.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

const DETECTOR: &str = "ory-token";
const SESSION: &str = "ory_session_token";
const OAUTH2: &str = "ory_oauth2_token";

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// Deterministic low-entropy synthetic filler over `alphabet`.
fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
        .collect()
}

fn session(len: usize, seed: usize) -> String {
    format!("ory_st_{}", filler(ALNUM, len, seed))
}

fn oauth2(prefix: &str, key: usize, signature: usize, seed: usize) -> String {
    format!(
        "{prefix}{}.{}",
        filler(B64URL, key, seed),
        filler(B64URL, signature, seed + 1)
    )
}

fn contexts(token: &str) -> Vec<String> {
    vec![
        token.to_owned(),
        format!("X-Session-Token: {token}\n"),
        format!("PROVIDER_TOKEN={token}\n"),
        format!("ORY_ACCESS_TOKEN={token}\n"),
        format!("export ORY_SESSION_TOKEN=\"{token}\"\n"),
        format!("Authorization: Bearer {token}\n"),
        format!("{{\"token\": \"{token}\"}}"),
        format!("{{\"access_token\": \"{token}\", \"token_type\": \"bearer\"}}"),
        format!("client = Ory(access_token=\"{token}\")\n"),
        format!("Here is my token {token} can you debug why it fails?"),
        format!("config:\n  token: {token}\n"),
        format!("```\n{token}\n```"),
        format!("The token is {token}."),
        format!("\u{d0a4}\u{d0a4}\u{1f511} 키: {token}\n"),
    ]
}

fn detector_findings<'a>(findings: &'a [Finding], detector: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.detector() == detector)
        .collect()
}

fn assert_sole_finding_in(input: &str, type_name: &str, token: &str) {
    let (text, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{type_name}: {input}: {findings:?}");
    let finding = &findings[0];
    let start = input.find(token).unwrap();
    assert_eq!(finding.detector(), DETECTOR, "{input}");
    assert_eq!(finding.type_name(), type_name, "{input}");
    assert_eq!(finding.action(), Action::Redact, "{input}");
    assert_eq!(
        (finding.range().start(), finding.range().end()),
        (start, start + token.len()),
        "{input}"
    );
    assert!(!text.contains(token), "{input}");
}

fn assert_unclaimed(input: &str) {
    let (_, findings) = whole_input(input);
    assert!(
        detector_findings(&findings, DETECTOR).is_empty(),
        "{DETECTOR} claimed {input}: {findings:?}"
    );
}

/// The whole input, every two-chunk UTF-8 byte partition and a per-line
/// incremental session produce the same text and the same findings.
fn assert_parity(input: &str) {
    let (expected_text, expected) = whole_input(input);
    assert!(!expected.is_empty(), "{input}");
    let same = |label: &str, text: String, findings: &[Finding]| {
        assert_eq!(text, expected_text, "{label}");
        assert_eq!(findings.len(), expected.len(), "{label}: {findings:?}");
        for (got, want) in findings.iter().zip(&expected) {
            assert_eq!(got.range(), want.range(), "{label}");
            assert_eq!(got.detector(), want.detector(), "{label}");
            assert_eq!(got.type_name(), want.type_name(), "{label}");
            assert_eq!(got.action(), want.action(), "{label}");
        }
    };
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        same(&format!("{pieces:?}"), session.text(), &session.findings());
    }
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let session = run(&lines);
    same("per line", session.text(), &session.findings());
}

#[test]
fn the_session_token_wins_every_context_as_the_sole_finding() {
    let token = session(32, 1);
    for input in contexts(&token) {
        assert_sole_finding_in(&input, SESSION, &token);
    }
}

#[test]
fn every_oauth2_prefix_and_key_width_wins_every_context() {
    for prefix in ["ory_at_", "ory_rt_", "ory_ac_"] {
        for key in [43, 44, 48] {
            let token = oauth2(prefix, key, 43, key);
            for input in contexts(&token) {
                assert_sole_finding_in(&input, OAUTH2, &token);
            }
        }
    }
}

#[test]
fn twins_and_excluded_shapes_are_unclaimed() {
    let signature = filler(B64URL, 43, 4);
    let twins = [
        session(31, 1),
        session(33, 1),
        format!("ory_st_{}-{}", filler(ALNUM, 15, 1), filler(ALNUM, 16, 1)),
        format!("ory_st_{}_{}", filler(ALNUM, 15, 1), filler(ALNUM, 16, 1)),
        session(32, 1).replacen("ory_st_", "ORY_ST_", 1),
        format!("x{}", session(32, 1)),
        format!("{}_backup", session(32, 1)),
        oauth2("ory_at_", 42, 43, 2),
        oauth2("ory_rt_", 43, 42, 2),
        oauth2("ory_ac_", 43, 44, 2),
        format!("ory_at_{}{}", filler(B64URL, 43, 2), signature),
        format!(
            "ory_at_{}.{}.{}",
            filler(B64URL, 43, 2),
            signature,
            filler(B64URL, 43, 5)
        ),
        format!(
            "ory_at_{}+{}.{}",
            filler(B64URL, 20, 2),
            filler(B64URL, 22, 2),
            signature
        ),
        format!("x{}", oauth2("ory_at_", 43, 43, 2)),
        oauth2("ory_at_", 43, 43, 2).replacen("ory_at_", "ORY_AT_", 1),
        // Excluded: admin keys, the logout flow token, cookie names.
        format!("ory_pat_{}", filler(ALNUM, 40, 1)),
        format!("ory_apikey_{}", filler(ALNUM, 40, 1)),
        format!("ory_wak_{}", filler(ALNUM, 40, 1)),
        format!("ory_lo_{}", filler(ALNUM, 32, 1)),
        format!("ory_session_{}", filler(ALNUM, 32, 1)),
        "ory_kratos_session=value".to_owned(),
        "ORY_SESSION_TOKEN=${ORY_SESSION_TOKEN}".to_owned(),
        "ory_st_<your-session-token>".to_owned(),
    ];
    for twin in &twins {
        for input in contexts(twin) {
            assert_unclaimed(&input);
        }
    }
}

#[test]
fn a_jwt_that_mentions_the_prefix_stays_with_jwt() {
    let input =
        "eyJhbGciOiJub25lIn0.SYNTHETIC-ory_at_-PAYLOAD.SYNTHETIC-NON-DECODABLE-SIGNATURE-MARKER";
    assert_unclaimed(input);
}

#[test]
fn a_repetition_line_stays_bounded_and_exact() {
    let token = oauth2("ory_at_", 43, 43, 1);
    let line = format!("{token} ").repeat(50);
    let (text, findings) = whole_input(&line);
    assert_eq!(detector_findings(&findings, DETECTOR).len(), 50);
    assert_eq!(findings.len(), 50, "{findings:?}");
    assert!(!text.contains(&token));
}

#[test]
fn whole_input_chunked_and_incremental_sessions_agree() {
    for token in [session(32, 1), oauth2("ory_rt_", 43, 43, 1)] {
        let input = format!("# \u{d0a4}\u{1f511} 키\n{token}\nAuthorization: Bearer {token}\n");
        assert_parity(&input);
    }
}
