//! Issue #864: Amazon Bedrock long-term and short-term API keys through the
//! public API with the full default registry.
//!
//! Every key is built at runtime from a prefix plus generated Base64 filler,
//! so no realistic key literal is committed. The filler is deterministic
//! synthetic text and was never derived from a real key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{as_chunks, run, utf8_byte_partitions, whole_input};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEAD: &str = "YmVkcm9jay5hbWF6b25hd3MuY29tLz9BY3Rpb249Q2FsbFdpdGhCZWFyZXJUb2tlbiZYLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsP";

fn filler(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(ALPHABET[(i * 11 + seed * 5 + i / 3) % 64]))
        .collect()
}

fn long_key() -> String {
    format!("ABSK{}", filler(128, 1))
}

fn short_key() -> String {
    format!("bedrock-api-key-{HEAD}{}", filler(420, 2))
}

fn bedrock_findings(input: &str) -> Vec<(String, std::ops::Range<usize>)> {
    let (_, findings) = whole_input(input);
    findings
        .iter()
        .filter(|f| f.detector().starts_with("aws-bedrock-"))
        .map(|f| (f.detector().to_owned(), f.range().start()..f.range().end()))
        .collect()
}

fn contexts(key: &str) -> Vec<String> {
    vec![
        key.to_owned(),
        format!("AWS_BEARER_TOKEN_BEDROCK={key}\n"),
        format!("export AWS_BEARER_TOKEN_BEDROCK=\"{key}\"\n"),
        format!("AWS_BEARER_TOKEN_BEDROCK: {key}\n"),
        format!("{{\"AWS_BEARER_TOKEN_BEDROCK\": \"{key}\"}}"),
        format!("curl -H \"Authorization: Bearer {key}\" https://example.invalid/\n"),
        format!("client = Bedrock(api_key=\"{key}\")\n"),
        format!("{{\"tool\":\"run\",\"arguments\":{{\"env\":{{\"K\":\"{key}\"}}}}}}"),
    ]
}

#[test]
fn every_context_reports_exactly_the_key_and_redacts_it() {
    for (detector, key) in [
        ("aws-bedrock-long-term-api-key", long_key()),
        ("aws-bedrock-short-term-api-key", short_key()),
    ] {
        for input in contexts(&key) {
            let found = bedrock_findings(&input);
            let start = input.find(&key).unwrap();
            assert_eq!(
                found,
                vec![(detector.to_owned(), start..start + key.len())],
                "{detector}: {input}"
            );
            let (text, findings) = whole_input(&input);
            assert!(!text.contains(&key[8..]), "{detector}: {input}");
            assert_eq!(findings.len(), 1, "{detector}: {input}");
        }
    }
}

#[test]
fn twins_produce_no_bedrock_finding() {
    let long = long_key();
    let short = short_key();
    let twins = [
        format!("ABSX{}", &long[4..]),
        long[..long.len() - 40].to_owned(),
        format!("bedrock-api-key-{}{}", &HEAD[..100], filler(420, 2)),
        format!("bedrock-api-key-{HEAD}"),
        short.replace(&filler(420, 2)[10..11], "-"),
    ];
    for twin in twins {
        for input in contexts(&twin) {
            assert!(bedrock_findings(&input).is_empty(), "{input}");
        }
    }
}

#[test]
fn aws_access_key_ids_keep_their_own_finding() {
    let akia = format!("AKIA{}", "SYNTHETICEXAMPLE");
    let input = format!(
        "AWS_ACCESS_KEY_ID={akia}\nAWS_BEARER_TOKEN_BEDROCK={}\n",
        long_key()
    );
    let (_, findings) = whole_input(&input);
    let detectors: Vec<&str> = findings
        .iter()
        .map(redact_secret::Finding::detector)
        .collect();
    assert!(detectors.contains(&"aws-access-key"), "{detectors:?}");
    assert!(
        detectors.contains(&"aws-bedrock-long-term-api-key"),
        "{detectors:?}"
    );
}

#[test]
fn every_two_chunk_partition_matches_the_whole_input() {
    for key in [long_key(), short_key()] {
        let input = format!("Authorization: Bearer {key}\n");
        let (expected_text, expected) = whole_input(&input);
        for pieces in utf8_byte_partitions(&input) {
            let session = run(&as_chunks(&pieces));
            assert_eq!(session.text(), expected_text, "{pieces:?}");
            let findings = session.findings();
            assert_eq!(findings.len(), expected.len(), "{pieces:?}");
            for (got, want) in findings.iter().zip(&expected) {
                assert_eq!(got.range(), want.range());
                assert_eq!(got.detector(), want.detector());
            }
        }
    }
}
