//! Issue #1014 third-wave provider families (#1106 Pydantic Logfire, #1107
//! Square, #1108 Mapbox, #1109 Fly) through the public API with the full
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
const LOWER_HEX: &[u8] = b"0123456789abcdef";

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

mod pydantic_logfire {
    use super::*;

    pub(super) const DETECTOR: &str = "pydantic-logfire-token";
    const TYPE: &str = "pydantic_logfire_token";

    fn org(seed: usize) -> String {
        [8, 4, 4, 4, 12]
            .iter()
            .enumerate()
            .map(|(i, &len)| filler(LOWER_HEX, len, seed + i))
            .collect::<Vec<_>>()
            .join("-")
    }

    pub(super) fn v1(region: &str, len: usize, seed: usize) -> String {
        format!("pylf_v1_{region}_{}", filler(ALNUM, len, seed))
    }

    pub(super) fn v2(region: &str, len: usize, seed: usize) -> String {
        format!(
            "pylf_v2_{region}_{}_{}",
            org(seed),
            filler(ALNUM, len, seed + 7)
        )
    }

    #[test]
    fn every_role_and_region_wins_every_context_as_the_sole_finding() {
        for region in ["us", "eu", "ap", "stagingus"] {
            assert_sole_provider_finding(DETECTOR, TYPE, &v1(region, 44, 1));
        }
        assert_sole_provider_finding(DETECTOR, TYPE, &v2("us", 44, 2));
        assert_sole_provider_finding(
            DETECTOR,
            TYPE,
            &v2("eu", 44, 3).replace(&org(3), &org(3).to_uppercase()),
        );
        let write = v1("us", 44, 4);
        for input in [
            format!("LOGFIRE_TOKEN={write}\n"),
            format!("LOGFIRE_READ_TOKEN={write}\n"),
            format!("LOGFIRE_API_KEY={write}\n"),
            format!("PYDANTIC_AI_GATEWAY_API_KEY={write}\n"),
            format!("logfire.configure(token=\"{write}\")\n"),
            format!(
                "curl -H 'Authorization: Bearer {write}' https://logfire-us.example/v1/traces\n"
            ),
            format!(
                "{{\"mcpServers\":{{\"logfire\":{{\"env\":{{\"LOGFIRE_READ_TOKEN\":\"{write}\"}}}}}}}}\n"
            ),
        ] {
            assert_sole_finding_in(&input, DETECTOR, TYPE, &write);
        }
    }

    #[test]
    fn the_body_floor_is_20_and_there_is_no_cap() {
        assert_sole_provider_finding(DETECTOR, TYPE, &v1("us", 20, 5));
        assert_sole_provider_finding(DETECTOR, TYPE, &v1("us", 21, 5));
        assert_sole_provider_finding(DETECTOR, TYPE, &v1("us", 80, 5));
        assert_sole_provider_finding(DETECTOR, TYPE, &v2("us", 20, 6));
        assert_twins_unclaimed(
            DETECTOR,
            &[v1("us", 19, 5), v1("us", 1, 5), v2("us", 19, 6)],
        );
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 44, 7);
        let mut wrong_group = org(8);
        wrong_group.replace_range(0..1, "");
        let mut dashed = body.clone();
        dashed.replace_range(22..23, "-");
        let mut underscored = body.clone();
        underscored.replace_range(22..23, "_");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("pylf_v_us_{body}"),
                format!("pylf_v1__{body}"),
                format!("pylf_v1_US_{body}"),
                format!("pylf_v1_u_{body}"),
                format!("pylf_v1_{}_{body}", "a".repeat(17)),
                format!("pylf_v1234_us_{body}"),
                format!("PYLF_v1_us_{body}"),
                format!("pylf_v1-us_{body}"),
                format!("pylf_v1_us-{body}"),
                format!("pylf_v2_us_{wrong_group}_{body}"),
                format!("pylf_v1_us_{dashed}"),
                format!("pylf_v1_us_{underscored}"),
                format!("xpylf_v1_us_{body}"),
                format!("_pylf_v1_us_{body}"),
                format!("-pylf_v1_us_{body}"),
                format!("pylf_v1_us_{body}_"),
                format!("pylf_v1_us_{body}-x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "pylf_v1_us_... pylf_v1_us_xxx pylf_v1_us_token1 pylf_v1_us_fake\n".to_owned(),
            "the masked pylf_v1_us_0kYhc**** form\n".to_owned(),
            "default scrubbing pattern pylf_v\\d+_ in config text\n".to_owned(),
            "LOGFIRE_TOKEN=${LOGFIRE_TOKEN}\n".to_owned(),
            "https://logfire-us.pydantic.dev/\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"pylf_v".repeat(10_000));
        assert_unclaimed(DETECTOR, &"pylf_v1_us_".repeat(5_000));
        assert_unclaimed(DETECTOR, &v1("us", 44, 9).repeat(200));
        assert_repetition_line(DETECTOR, &v1("us", 44, 9), 200);
        assert_repetition_line(DETECTOR, &v2("eu", 44, 10), 200);
    }

    #[test]
    fn whole_input_every_two_chunk_partition_and_per_line_sessions_agree() {
        assert_parity(&parity_input(&v1("us", 44, 11)));
        assert_parity(&parity_input(&v2("eu", 30, 12)));
    }
}
