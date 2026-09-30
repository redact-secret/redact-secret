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

mod npmrc_credential_keys {
    use super::*;

    const DETECTOR: &str = "generic-token";
    const TYPE: &str = "contextual_secret";
    const LOWER_HEX: &[u8] = b"0123456789abcdef";
    const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// A UUID-shaped legacy value built from filler.
    fn uuid(seed: usize) -> String {
        let hex = filler(LOWER_HEX, 32, seed);
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    }

    fn values() -> Vec<String> {
        vec![
            uuid(1),
            format!("{}==", filler(BASE64, 30, 2)),
            filler(ALNUM, 40, 3),
            format!("cmVmdGtu{}", filler(ALNUM, 56, 4)),
        ]
    }

    #[test]
    fn every_credential_key_is_one_redacted_finding() {
        for value in values() {
            for input in [
                format!("//registry.npmjs.org/:_authToken={value}\n"),
                format!(
                    "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={value}\n"
                ),
                format!(
                    "@acme:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken={value}\n"
                ),
                format!(
                    "//artifactory.example.invalid/artifactory/api/npm/npm/:_auth={value}\nalways-auth=true\n"
                ),
                format!(
                    "//nexus.example.invalid/repository/npm/:_password=\"{value}\"\n//nexus.example.invalid/repository/npm/:username=ci\n"
                ),
                format!("_authToken={value}\n"),
                format!("_auth = {value}\r\n"),
                format!("RUN echo \"//registry.npmjs.org/:_authToken={value}\" > .npmrc\n"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &value);
            }
        }
    }

    #[test]
    fn a_current_npm_token_stays_the_provider_finding() {
        let token = format!("npm_{}", filler(ALNUM, 36, 5));
        assert_sole_finding_in(
            &format!("//registry.npmjs.org/:_authToken={token}\n"),
            "npm-token",
            "npm_access_token",
            &token,
        );
    }

    #[test]
    fn references_placeholders_and_other_keys_stay_silent() {
        for input in [
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n".to_owned(),
            "//registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }}\n".to_owned(),
            "//registry.npmjs.org/:_authToken=<your-token>\n".to_owned(),
            "//registry.npmjs.org/:_authToken=YOUR_NPM_TOKEN\n".to_owned(),
            "//registry.npmjs.org/:_authToken=\n".to_owned(),
            "//registry.npmjs.org/:username=synthetic-user\n".to_owned(),
            "//registry.npmjs.org/:email=someone@example.invalid\n".to_owned(),
            "registry=https://registry.npmjs.org/\nalways-auth=true\n".to_owned(),
            format!("the _authToken={} in prose\n", uuid(6)),
            format!("x:_authToken={}\n", uuid(6)),
        ] {
            let (_, findings) = whole_input(&input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        let (_, findings) = whole_input(&"//r/:_auth=".repeat(10_000));
        assert!(findings.len() <= 1, "{}", findings.len());
        let value = uuid(7);
        let text = format!("//registry.npmjs.org/:_authToken={value}\n").repeat(300);
        let (redacted, findings) = whole_input(&text);
        assert_eq!(findings.len(), 300);
        assert!(!redacted.contains(&value));
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!(
            "//npm.example.invalid/:_auth={}==\n",
            filler(BASE64, 30, 8)
        ));
    }
}

mod aws_secret_access_key_names {
    use super::*;

    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// The API member names every width: a 41-byte temporary secret too.
    #[test]
    fn the_secret_access_key_member_is_redacted_in_every_casing() {
        for width in [40, 41, 44] {
            let value = filler(B64, width, width);
            for input in [
                format!("{{\"SecretAccessKey\": \"{value}\"}}"),
                format!(
                    "{{\"Credentials\": {{\"AccessKeyId\": \"ASIA{}\", \"SecretAccessKey\": \"{value}\", \"Expiration\": \"2026-09-29T00:00:00Z\"}}}}",
                    filler(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16, 1)
                ),
                format!("const creds = {{ secretAccessKey: \"{value}\" }};\n"),
                format!("secret_access_key: {value}\n"),
                format!("  SecretAccessKey: '{value}'\n"),
            ] {
                let (text, findings) = whole_input(&input);
                assert!(!text.contains(&value), "{input}: {findings:?}");
                let start = input.find(&value).unwrap();
                assert!(
                    findings.iter().any(|f| f.action() == Action::Redact
                        && f.range().start() == start
                        && f.range().end() == start + value.len()),
                    "{input}: {findings:?}"
                );
            }
        }
    }

    #[test]
    fn references_under_the_name_stay_silent() {
        for input in [
            "{\"SecretAccessKey\": \"${AWS_SECRET_ACCESS_KEY}\"}",
            "SecretAccessKey: !Ref SecretParameter\n",
            "secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,\n",
            "{\"SecretAccessKey\": \"<secret>\"}",
        ] {
            let (_, findings) = whole_input(input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!(
            "{{\"SecretAccessKey\": \"{}\"}}\n",
            filler(B64, 41, 2)
        ));
    }
}

mod aws_sts_temporary_access_key_id {
    use super::*;

    const DETECTOR: &str = "aws-access-key";
    const TYPE: &str = "aws_access_key_id";
    /// `[A-Z0-9]`, deliberately including `0 1 8 9` outside Base32: the
    /// contract is the wider class (#1012 contradiction 1).
    const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    fn id(prefix: &str, seed: usize) -> String {
        format!("{prefix}{}", filler(UPPER_ALNUM, 16, seed))
    }

    #[test]
    fn asia_is_typed_and_actioned_exactly_like_akia_in_every_context() {
        for prefix in ["ASIA", "AKIA"] {
            let value = id(prefix, 1);
            for input in [
                value.clone(),
                format!("AWS_ACCESS_KEY_ID={value}\n"),
                format!("export AWS_ACCESS_KEY_ID=\"{value}\"\n"),
                format!("[default]\naws_access_key_id = {value}\n"),
                format!("{{\"Credentials\": {{\"AccessKeyId\": \"{value}\"}}}}"),
                format!("Here are my temporary credentials: {value} why is it denied?"),
                format!("({value})."),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &value);
            }
        }
    }

    #[test]
    fn one_property_twins_are_unclaimed() {
        let value = id("ASIA", 2);
        let mut lower = value.clone();
        lower.replace_range(10..11, "q");
        for twin in [
            format!("ASIA{}", filler(UPPER_ALNUM, 15, 2)),
            format!("ASIA{}", filler(UPPER_ALNUM, 17, 2)),
            lower,
            value.replacen("ASIA", "ASIB", 1),
            value.replacen("ASIA", "asia", 1),
            format!("x{value}"),
            format!("{value}0"),
            format!("9{value}"),
        ] {
            for input in [twin.clone(), format!("AWS_ACCESS_KEY_ID={twin}\n")] {
                assert_unclaimed(DETECTOR, &input);
            }
        }
    }

    #[test]
    fn other_iam_identifiers_are_unclaimed() {
        for prefix in ["AIDA", "AROA", "ABIA", "ACCA", "AGPA", "ANPA"] {
            assert_unclaimed(DETECTOR, &format!("{}\n", id(prefix, 3)));
        }
        assert_unclaimed(DETECTOR, &"A".repeat(20));
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"ASIA".repeat(20_000));
        let value = id("ASIA", 4);
        let (text, findings) = whole_input(&format!("{value} ").repeat(300));
        assert_eq!(findings.len(), 300);
        assert!(!text.contains(&value));
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("aws_access_key_id = {}\n", id("ASIA", 5)));
    }
}

mod aws_secret_access_key {
    use super::*;

    const DETECTOR: &str = "aws-secret-access-key";
    const TYPE: &str = "aws_secret_access_key";
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    fn secret(seed: usize) -> String {
        filler(B64, 40, seed)
    }

    fn id(prefix: &str, seed: usize) -> String {
        format!("{prefix}{}", filler(UPPER_ALNUM, 16, seed))
    }

    /// The one finding over `value` is `aws_secret_access_key`, redacted,
    /// at exactly its span; every other finding is elsewhere.
    fn assert_secret_finding(input: &str, value: &str) {
        let (text, findings) = whole_input(input);
        let start = input.find(value).unwrap();
        let over: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.range().start() < start + value.len() && f.range().end() > start)
            .collect();
        assert_eq!(over.len(), 1, "{input}: {findings:?}");
        assert_eq!(over[0].detector(), DETECTOR, "{input}");
        assert_eq!(over[0].type_name(), TYPE, "{input}");
        assert_eq!(over[0].action(), Action::Redact, "{input}");
        assert_eq!(
            (over[0].range().start(), over[0].range().end()),
            (start, start + value.len()),
            "{input}"
        );
        assert!(!text.contains(value), "{input}");
    }

    #[test]
    fn named_and_id_adjacent_forms_are_one_provider_finding() {
        for seed in [1, 2, 3] {
            let value = secret(seed);
            let akia = id("AKIA", seed);
            let temporary_id = id("ASIA", seed);
            for input in [
                format!("AWS_SECRET_ACCESS_KEY={value}\n"),
                format!("export AWS_SECRET_ACCESS_KEY=\"{value}\"\n"),
                format!("[default]\naws_access_key_id = {akia}\naws_secret_access_key = {value}\n"),
                format!(
                    "{{\"AccessKey\": {{\"AccessKeyId\": \"{akia}\", \"Status\": \"Active\", \"SecretAccessKey\": \"{value}\"}}}}"
                ),
                format!(
                    "{{\"Credentials\": {{\"AccessKeyId\": \"{temporary_id}\", \"SecretAccessKey\": \"{value}\"}}}}"
                ),
                format!(
                    "Outputs:\n  SecretAccessKey:\n    Value: !GetAtt Key.SecretAccessKey\n  Plain:\n    SecretAccessKey: {value}\n"
                ),
                format!(
                    "AWS Access Key ID [None]: {akia}\nAWS Secret Access Key [None]: {value}\n"
                ),
                format!("Access key ID,Secret access key\n{akia},{value}\n"),
                format!("here are my keys\n{akia}\n{value}\n"),
                format!("Set-AWSCredential -AccessKey {akia} -SecretKey {value}\n"),
                format!(
                    "const s3 = new S3Client({{ credentials: {{ accessKeyId: \"{akia}\", secretAccessKey: \"{value}\" }} }});\n"
                ),
                format!("My AWS keys are {temporary_id} and {value}, what is wrong?"),
            ] {
                assert_secret_finding(&input, &value);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed_and_named_ones_stay_redacted_by_generic_token() {
        let value = secret(4);
        let mut twins = vec![
            value[..39].to_owned(),
            format!("{value}A"),
            format!("{}={}", &value[..20], &value[21..]),
            format!("{}-{}", &value[..20], &value[21..]),
            format!("{}_{}", &value[..20], &value[21..]),
            format!("{value}="),
            value.to_ascii_uppercase(),
            value.to_ascii_lowercase(),
        ];
        twins.push(format!("x{}", &value[1..]).replace('x', "\u{e9}"));
        for twin in &twins {
            let named = format!("AWS_SECRET_ACCESS_KEY={twin}\n");
            assert_unclaimed(DETECTOR, &named);
            let adjacent = format!("{}\n{twin}\n", id("AKIA", 4));
            assert_unclaimed(DETECTOR, &adjacent);
        }
        // Security-first: the name still redacts the 41-byte twin.
        let (text, _) = whole_input(&format!("AWS_SECRET_ACCESS_KEY={value}A\n"));
        assert!(!text.contains(&value));
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        let sha = filler(b"0123456789abcdef", 40, 5);
        let value = secret(5);
        for input in [
            format!("{value}\n"),
            format!("commit {sha}\n{}\n", id("AKIA", 5)),
            format!("{}\n{sha}\n", id("AKIA", 5)),
            format!("etag: {value}\n"),
            format!("sha256={value}\n"),
            format!("{value}\n{}\n", id("AKIA", 5)),
            format!("{}\n\n{value}\n", id("AKIA", 5)),
            format!("{}\n{value}\n", id("AIDA", 5)),
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn neighbouring_aws_families_keep_their_own_findings() {
        let akia = id("AKIA", 6);
        let value = secret(6);
        let bedrock = format!("ABSK{}", "U3ludGhldGljUmV2b2tlZA".repeat(6));
        let input = format!("{akia},{value}\nAWS_BEARER_TOKEN_BEDROCK={bedrock}\n");
        let (_, findings) = whole_input(&input);
        for detector in [DETECTOR, "aws-access-key", "aws-bedrock-long-term-api-key"] {
            assert_eq!(
                detector_findings(&findings, detector).len(),
                1,
                "{detector}: {findings:?}"
            );
        }
        assert_unclaimed(DETECTOR, &format!("{bedrock}\n"));
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &format!("{} ", secret(7)).repeat(10_000));
        let line = format!("{},{} ", id("AKIA", 7), secret(7)).repeat(300);
        let (text, findings) = whole_input(&line);
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 300);
        assert!(!text.contains(&secret(7)));
        let ids = format!("{}\n", id("ASIA", 8)).repeat(500);
        assert_eq!(whole_input(&ids).1.len(), 500);
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("aws_secret_access_key = {}\n", secret(9)));
        assert_partition_parity(&format!("{}\n{}\n", id("AKIA", 9), secret(9)));
        assert_partition_parity(&format!("{}\r\n{}\r\nnext\n", id("ASIA", 9), secret(9)));
    }

    /// Issue #1040: a closed line carrying an access key ID is released, with
    /// its `aws-access-key` finding, by the `append` that closes it; the
    /// line below it is still scanned with the ID line above it.
    #[test]
    fn an_access_key_id_line_is_released_when_it_closes() {
        let akia = id("AKIA", 10);
        let value = secret(10);
        let line = format!("deploy log: AWS_ACCESS_KEY_ID={akia} region=us-east-1\n");
        let split = line.find(&akia).unwrap() + 7;
        let mut session =
            redact_secret::IncrementalSanitizer::new(support::generous_limits()).unwrap();
        assert_eq!(session.append(&line[..split]).unwrap().text(), "");
        let closed = session.append(&line[split..]).unwrap();
        assert_eq!(
            closed.text().len(),
            line.len() - akia.len() + "<SECRET_1>".len()
        );
        assert!(!closed.text().contains(&akia));
        assert_eq!(closed.findings().len(), 1);
        assert_eq!(closed.findings()[0].detector(), "aws-access-key");

        // The secret on the next line is claimed through the released ID line.
        let below = session.append(&format!("{value}\n")).unwrap();
        assert_eq!(below.findings().len(), 1);
        assert_eq!(below.findings()[0].detector(), DETECTOR);
        assert_eq!(below.findings()[0].range().start(), line.len());
        assert!(!below.text().contains(&value));
        assert!(session.finalize().unwrap().text().is_empty());
    }

    /// Issue #1040: consecutive ID lines never accumulate; each is released
    /// by its own `append`, and every line below one still reads it.
    #[test]
    fn consecutive_access_key_id_lines_are_each_released() {
        let ids: Vec<String> = (0..50)
            .map(|seed| format!("{}\n", id("ASIA", seed)))
            .collect();
        let mut session =
            redact_secret::IncrementalSanitizer::new(support::generous_limits()).unwrap();
        for line in &ids {
            let released = session.append(line).unwrap();
            assert_eq!(
                released.text(),
                format!(
                    "<SECRET_{}>\n",
                    released.findings()[0].id().trim_start_matches("finding-")
                )
            );
            assert_eq!(released.findings().len(), 1);
        }
        let input = format!("{}{}\n", ids.concat(), secret(11));
        assert_partition_parity(&input);
        let (_, findings) = whole_input(&input);
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 1);
    }
}

mod google_oauth_client_secret {
    use super::*;

    const DETECTOR: &str = "google-oauth-client-secret";
    const TYPE: &str = "google_oauth_client_secret";

    fn secret(len: usize, seed: usize) -> String {
        format!("GOCSPX-{}", filler(BASE64URL, len, seed))
    }

    #[test]
    fn the_secret_is_the_sole_finding_in_every_context() {
        for seed in [1, 2, 3] {
            let value = secret(28, seed);
            for input in [
                value.clone(),
                format!("GOOGLE_CLIENT_SECRET={value}\n"),
                format!("export GOOGLE_CLIENT_SECRET=\"{value}\"\n"),
                format!(
                    "{{\"installed\":{{\"client_id\":\"000000000000-synthetic.apps.googleusercontent.com\",\"client_secret\":\"{value}\"}}}}"
                ),
                format!("client_secret={value}&grant_type=authorization_code"),
                format!("flow = Flow.from_client_config(cfg, client_secret=\"{value}\")\n"),
                format!("Authorization: Bearer {value}\n"),
                format!("{{\"token\": \"{value}\"}}"),
                format!("Here is my OAuth secret {value} can you check it?"),
                format!("The secret is {value}."),
                format!("```\n{value}\n```"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &value);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let value = secret(28, 4);
        let body = &value["GOCSPX-".len()..];
        for twin in [
            secret(27, 4),
            secret(29, 4),
            format!("gocspx-{body}"),
            format!("GOCSPX_{body}"),
            format!("GOCSPX-{}.{}", &body[..10], &body[11..]),
            format!("x{value}"),
            format!("{value}_"),
            format!("{value}-"),
        ] {
            for input in [twin.clone(), format!("GOOGLE_CLIENT_SECRET={twin}\n")] {
                assert_unclaimed(DETECTOR, &input);
            }
        }
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "\"client_id\": \"000000000000-syntheticrevokedclient.apps.googleusercontent.com\"\n",
            "\"client_secret\": \"GOCSPX-...\"\n",
            "Client secrets start with GOCSPX- today.\n",
            "GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}\n",
        ] {
            let (_, findings) = whole_input(input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
    }

    #[test]
    fn neighbouring_google_families_keep_their_own_findings() {
        let value = secret(28, 5);
        let api_key = format!("AIza{}", filler(BASE64URL, 35, 5));
        let (_, findings) = whole_input(&format!("{value} {api_key}\n"));
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 1);
        assert_eq!(detector_findings(&findings, "google-api-key").len(), 1);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert_unclaimed(DETECTOR, &format!("{api_key}\n"));
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"GOCSPX-".repeat(20_000));
        let value = secret(28, 6);
        let (text, findings) = whole_input(&format!("{value} ").repeat(300));
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 300);
        assert_eq!(findings.len(), 300);
        assert!(!text.contains(&value));
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("GOOGLE_CLIENT_SECRET={}\n", secret(28, 7)));
    }
}
