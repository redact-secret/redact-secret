//! Issue #1012 READY outcomes and product gaps through the public API with
//! the full default registry.
//!
//! Every value is built at run time from a literal prefix plus a seeded,
//! low-entropy synthetic filler, so no realistic credential literal is
//! committed. None was derived from an issued credential.
//!
//! Each family checks, against the whole built-in registry rather than its
//! own detector alone: the exact span of the one finding in every context,
//! one-property twins, benign siblings, isolation from neighbouring
//! families, a repetition line, and whole-input versus two-chunk
//! incremental parity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Deterministic synthetic filler over `alphabet`.
fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
        .collect()
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

fn detector_findings<'a>(findings: &'a [Finding], detector: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.detector() == detector)
        .collect()
}

/// Exactly one finding in `input`: `detector`/`type_name` at the value's
/// span, redacted, and the value gone from the output.
fn assert_sole_finding_in(input: &str, detector: &str, type_name: &str, value: &str) {
    let (text, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{type_name}: {input}: {findings:?}");
    let finding = &findings[0];
    let start = input.find(value).unwrap();
    assert_eq!(finding.detector(), detector, "{input}");
    assert_eq!(finding.type_name(), type_name, "{input}");
    assert_eq!(finding.action(), Action::Redact, "{input}");
    assert_eq!(
        (finding.range().start(), finding.range().end()),
        (start, start + value.len()),
        "{input}"
    );
    assert!(!text.contains(value), "{input}");
}

fn assert_unclaimed(detector: &str, input: &str) {
    let (_, findings) = whole_input(input);
    assert!(
        detector_findings(&findings, detector).is_empty(),
        "{detector} claimed {input}: {findings:?}"
    );
}

/// Every two-chunk (and every byte) partition of `input` yields the whole
/// input's text and findings.
fn assert_partition_parity(input: &str) {
    let (expected_text, expected) = whole_input(input);
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), expected_text, "{pieces:?}");
        let findings = session.findings();
        assert_eq!(findings.len(), expected.len(), "{pieces:?}");
        for (got, want) in findings.iter().zip(&expected) {
            assert_eq!(got.range(), want.range());
            assert_eq!(got.detector(), want.detector());
            assert_eq!(got.type_name(), want.type_name());
        }
    }
}

mod gitlab_routable {
    use super::*;

    const DETECTOR: &str = "gitlab-token";
    const TYPE: &str = "gitlab_token";

    /// IEEE CRC-32, as GitLab's generator computes it.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn base36(mut value: u64, width: usize) -> String {
        let mut digits = Vec::new();
        while value > 0 {
            digits.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[(value % 36) as usize]);
            value /= 36;
        }
        digits.resize(width, b'0');
        digits.reverse();
        String::from_utf8(digits).unwrap()
    }

    /// `glpat-<payload>.<version>.<length><crc>` with a verifying length
    /// holder and CRC-32, built at run time.
    fn token_with(prefix: &str, payload: &str, version: &str) -> String {
        let head = format!(
            "{prefix}{payload}.{version}.{}",
            base36(payload.len() as u64, 2)
        );
        let crc = base36(u64::from(crc32(head.as_bytes())), 7);
        format!("{head}{crc}")
    }

    fn token(width: usize, seed: usize) -> String {
        token_with("glpat-", &filler(BASE64URL, width, seed), "01")
    }

    fn contexts(value: &str) -> Vec<String> {
        vec![
            value.to_owned(),
            format!("GITLAB_TOKEN={value}\n"),
            format!("export GITLAB_TOKEN=\"{value}\"\n"),
            format!("Authorization: Bearer {value}\n"),
            format!("curl --header \"PRIVATE-TOKEN: {value}\" https://gitlab.com/api/v4/user\n"),
            format!("{{\"token\": \"{value}\"}}"),
            format!("{{\"api_key\": \"{value}\"}}"),
            format!("gl = gitlab.Gitlab(private_token=\"{value}\")\n"),
            format!("Here is my token {value} can you debug why it fails?"),
            format!("The token is {value}."),
            format!("```\n{value}\n```"),
        ]
    }

    #[test]
    fn every_width_is_one_whole_finding_in_every_context() {
        for value in [token(27, 1), token(64, 2), token(235, 3), token(300, 4)] {
            for input in contexts(&value) {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &value);
            }
        }
    }

    #[test]
    fn a_git_remote_url_releases_no_byte_of_the_token() {
        let value = token(64, 5);
        let input = format!("git clone https://oauth2:{value}@gitlab.com/group/repo.git\n");
        let (text, findings) = whole_input(&input);
        assert!(!text.contains(&value), "{findings:?}");
        let start = input.find(&value).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| { f.range().start() <= start && f.range().end() >= start + value.len() }),
            "{findings:?}"
        );
    }

    /// The regression of #1022: no byte of the tail survives redaction.
    #[test]
    fn the_span_ends_at_the_last_crc_byte() {
        let value = token(64, 6);
        let tail = &value[value.find('.').unwrap()..];
        let (text, findings) = whole_input(&format!("token: {value}\n"));
        assert!(!text.contains(tail), "{text}");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].range().end(), "token: ".len() + value.len());
    }

    /// A one-property twin is not reported whole. Where its payload run is
    /// 20 bytes or more, the legacy `glpat-` finding over that run stays
    /// (unchanged since before #1022); it never extends into the tail.
    #[test]
    fn one_property_twins_are_not_reported_whole() {
        let value = token(64, 7);
        let payload_end = value.find('.').unwrap();
        let mut bad_crc = value.clone();
        let last = bad_crc.pop().unwrap();
        bad_crc.push(if last == '0' { '1' } else { '0' });
        let length_field = &value[payload_end + 4..payload_end + 6];
        let bad_length = value.replacen(&format!(".01.{length_field}"), ".01.1r", 1);
        let twins = [
            bad_crc,
            bad_length,
            token_with("glpat-", &filler(BASE64URL, 64, 7), "1"),
            token_with("glpat-", &filler(BASE64URL, 64, 7), "001"),
            value.replacen(".01.", "01.", 1),
            value.replacen(".01.", ".0A.", 1),
            format!("{}{}", &value[..value.len() - 1], "Z"),
            token(26, 7),
            token_with("inst-glpat-", &filler(BASE64URL, 64, 7), "01"),
        ];
        for twin in &twins {
            let input = format!("token: {twin}\n");
            let (_, findings) = whole_input(&input);
            for finding in detector_findings(&findings, DETECTOR) {
                assert!(
                    finding.range().end() <= input.find('.').unwrap(),
                    "{input}: {findings:?}"
                );
            }
        }
        for glued in [
            format!("x{value}"),
            format!("{value}x"),
            format!("{value}_"),
        ] {
            let (_, findings) = whole_input(&format!("{glued}\n"));
            assert!(
                detector_findings(&findings, DETECTOR)
                    .iter()
                    .all(|f| f.range().len() < value.len()),
                "{glued}: {findings:?}"
            );
        }
    }

    #[test]
    fn benign_siblings_keep_their_own_behavior() {
        // The legacy 20-byte PAT keeps its finding.
        let legacy = format!("glpat-{}", filler(ALNUM, 20, 8));
        assert_sole_finding_in(&format!("{legacy}\n"), DETECTOR, TYPE, &legacy);
        // A routable runner token stays the runner detector's.
        let runner = token_with("glrt-", &filler(BASE64URL, 40, 8), "01");
        assert_sole_finding_in(
            &format!("{runner}\n"),
            "gitlab-runner-authentication-token",
            "gitlab_runner_authentication_token",
            &runner,
        );
        // The prefix in prose is not a token.
        assert_unclaimed(
            DETECTOR,
            "Personal access tokens start with glpat- today.\n",
        );
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"glpat-.01.".repeat(10_000));
        let value = token(64, 9);
        let line = format!("{value} ").repeat(200);
        let (text, findings) = whole_input(&line);
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 200);
        assert_eq!(findings.len(), 200);
        assert!(findings.iter().all(|f| f.range().len() == value.len()));
        assert!(!text.contains(&value));
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("PRIVATE-TOKEN: {}\n", token(40, 10)));
    }
}
