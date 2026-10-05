//! Issue #1014 second-wave provider families (#1102 Xata, #1103 Sourcegraph,
//! #1104 Unkey, #1105 Buildkite) through the public API with the full
//! default registry.
//!
//! Every key is built at run time from a literal prefix plus a seeded
//! low-entropy synthetic filler, so no realistic key literal is committed.
//! The filler was never derived from an issued credential.
//!
//! Each family checks, against the whole built-in registry rather than its
//! own detector alone:
//!
//! - every probe context (bare in prose, env, `export`, Bearer, `X-API-Key`,
//!   JSON `token`/`api_key`, SDK keyword argument, chat sentence, YAML,
//!   fenced block, sentence punctuation, a multibyte lead) yields exactly one
//!   finding, of the provider type, at exactly the key's UTF-8 byte span,
//!   redacted;
//! - one-property twins yield no finding of the provider's detector;
//! - benign siblings stay unclaimed by the provider's detector;
//! - a repetition line stays bounded and exact;
//! - the whole input, every two-chunk UTF-8 byte partition and a per-line
//!   incremental session agree on text, spans, detector and type.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Deterministic low-entropy synthetic filler over `alphabet`.
fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
        .collect()
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The probe contexts plus a few host forms, including a multibyte lead so a
/// byte offset differs from a character offset.
fn contexts(key: &str) -> Vec<String> {
    vec![
        key.to_owned(),
        format!("PROVIDER_TOKEN={key}\n"),
        format!("export PROVIDER_TOKEN=\"{key}\"\n"),
        format!("Authorization: Bearer {key}\n"),
        format!("X-API-Key: {key}\n"),
        format!("{{\"token\": \"{key}\"}}"),
        format!("{{\"api_key\": \"{key}\"}}"),
        format!("client = Client(api_key=\"{key}\")\n"),
        format!("Here is my key {key} can you debug why it fails?"),
        format!("config:\n  token: {key}\n"),
        format!("```\n{key}\n```"),
        format!("The key is {key}."),
        format!("\u{d0a4}\u{d0a4}\u{1f511} 키: {key}\n"),
    ]
}

fn detector_findings<'a>(findings: &'a [Finding], detector: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.detector() == detector)
        .collect()
}

/// Exactly one finding in `input`: `detector`/`type_name` at the key's span,
/// redacted, and the key gone from the output.
fn assert_sole_finding_in(input: &str, detector: &str, type_name: &str, key: &str) {
    let (text, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{type_name}: {input}: {findings:?}");
    let finding = &findings[0];
    let start = input.find(key).unwrap();
    assert_eq!(finding.detector(), detector, "{input}");
    assert_eq!(finding.type_name(), type_name, "{input}");
    assert_eq!(finding.action(), Action::Redact, "{input}");
    assert_eq!(
        (finding.range().start(), finding.range().end()),
        (start, start + key.len()),
        "{input}"
    );
    assert!(!text.contains(key), "{input}");
}

fn assert_sole_provider_finding(detector: &str, type_name: &str, key: &str) {
    for input in contexts(key) {
        assert_sole_finding_in(&input, detector, type_name, key);
    }
}

fn assert_unclaimed(detector: &str, input: &str) {
    let (_, findings) = whole_input(input);
    assert!(
        detector_findings(&findings, detector).is_empty(),
        "{detector} claimed {input}: {findings:?}"
    );
}

fn assert_twins_unclaimed(detector: &str, twins: &[String]) {
    for twin in twins {
        for input in contexts(twin) {
            assert_unclaimed(detector, &input);
        }
    }
}

/// `count` space-separated copies of `key` yield exactly `count` findings of
/// `detector` and nothing else, and no copy survives redaction.
fn assert_repetition_line(detector: &str, key: &str, count: usize) {
    let line = format!("{key} ").repeat(count);
    let (text, findings) = whole_input(&line);
    assert_eq!(detector_findings(&findings, detector).len(), count);
    assert_eq!(findings.len(), count, "{findings:?}");
    assert!(!text.contains(key));
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

/// A three-line input: a multibyte comment, the key on its own line, and the
/// key behind a Bearer scheme.
fn parity_input(key: &str) -> String {
    format!("# \u{d0a4}\u{1f511} 키\n{key}\nAuthorization: Bearer {key}\n")
}

mod xata {
    use super::*;

    pub(super) const DETECTOR: &str = "xata-api-key";
    const USER: &str = "xata_user_api_key";
    const ORGANIZATION: &str = "xata_organization_api_key";

    pub(super) fn key(prefix: &str, len: usize, seed: usize) -> String {
        format!("{prefix}{}", filler(ALNUM, len, seed))
    }

    #[test]
    fn both_roles_win_every_context_as_the_sole_finding() {
        for (prefix, type_name) in [("xau_", USER), ("xao_", ORGANIZATION)] {
            for len in [32, 33, 34, 36] {
                assert_sole_provider_finding(DETECTOR, type_name, &key(prefix, len, len));
            }
        }
        let key = key("xau_", 33, 1);
        for input in [
            format!("XATA_API_KEY={key}\n"),
            format!("# .env\nXATA_API_KEY={key}\nXATA_BRANCH=main\n"),
            format!(
                "{{\"mcpServers\":{{\"xata\":{{\"command\":\"xata-mcp\",\"env\":{{\"XATA_API_KEY\":\"{key}\"}}}}}}}}\n"
            ),
            format!("curl -H 'Authorization: Bearer {key}' https://api.xata.example/v1\n"),
        ] {
            assert_sole_finding_in(&input, DETECTOR, USER, &key);
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 33, 2);
        let base = format!("xau_{body}");
        let mut dashed = body.clone();
        dashed.replace_range(10..11, "-");
        let mut underscored = body.clone();
        underscored.replace_range(10..11, "_");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("xau_{}", &body[..31]),
                format!("xao_{}", &body[..31]),
                format!("xau_{}", filler(ALNUM, 37, 3)),
                format!("xao_{}", filler(ALNUM, 37, 3)),
                format!("xau_{dashed}"),
                format!("xau_{underscored}"),
                format!("XAU_{body}"),
                format!("xat_{body}"),
                format!("xau-{body}"),
                format!("maxau_{body}"),
                format!("x{base}"),
                format!("_{base}"),
                format!("{base}_"),
                format!("{base}-x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "xau_test xau_redacted xau_some_key xau_test123\n".to_owned(),
            "XATA_API_KEY=${XATA_API_KEY}\n".to_owned(),
            format!("XATA_API_KEY=xau_{}\n", "*".repeat(33)),
            "xau_snake_case_identifier_name_that_is_long\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"xau_".repeat(10_000));
        assert_unclaimed(DETECTOR, &key("xau_", 33, 4).repeat(200));
        assert_repetition_line(DETECTOR, &key("xao_", 34, 4), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        assert_parity(&parity_input(&key("xau_", 33, 5)));
        assert_parity(&parity_input(&key("xao_", 36, 6)));
    }
}
