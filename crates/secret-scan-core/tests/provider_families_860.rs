//! Issue #860 Tier A provider families (#903–#909) through the public API
//! with the full default registry.
//!
//! Every key is built at run time from a literal prefix plus a seeded
//! synthetic filler, so no realistic key literal is committed. The filler
//! was never derived from an issued credential.
//!
//! Each family checks, against the whole built-in registry rather than its
//! own detector alone:
//!
//! - every handoff context (bare, env, `export`, Bearer, `X-API-Key`, JSON
//!   `token`/`api_key`, SDK keyword argument, chat sentence) yields exactly
//!   one finding, of the provider type, at exactly the key's span, redacted;
//!   the provider candidate wins the overlap with `contextual_secret`,
//!   `bearer_token` and any other built-in, so no duplicate or overlapping
//!   finding survives;
//! - one-property twins yield no finding of the provider's detector;
//! - benign siblings stay unclaimed by the provider's detector;
//! - every two-chunk partition of a Bearer line matches the whole input.
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

/// The nine #860 index contexts plus a few host forms.
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
    ]
}

fn detector_findings<'a>(findings: &'a [Finding], detector: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.detector() == detector)
        .collect()
}

/// Exactly one finding in every context: `detector`/`type_name` at the key's
/// span, redacted, and the key's body gone from the output.
fn assert_sole_provider_finding(detector: &str, type_name: &str, key: &str) {
    for input in contexts(key) {
        let (text, findings) = whole_input(&input);
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

fn assert_partition_parity(key: &str) {
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
            assert_eq!(got.type_name(), want.type_name());
        }
    }
}

mod doppler {
    use super::*;

    const DETECTOR: &str = "doppler-token";
    const TYPES: [(&str, &str); 7] = [
        ("st", "doppler_service_token"),
        ("pt", "doppler_personal_token"),
        ("ct", "doppler_cli_token"),
        ("sa", "doppler_service_account_token"),
        ("said", "doppler_service_account_identity_token"),
        ("scim", "doppler_scim_token"),
        ("audit", "doppler_audit_token"),
    ];

    fn key(literal: &str, segment: Option<&str>, len: usize) -> String {
        let segment = segment.map(|s| format!("{s}.")).unwrap_or_default();
        format!(
            "dp.{literal}.{segment}{}",
            filler(ALNUM, len, literal.len())
        )
    }

    #[test]
    fn every_type_wins_every_context_as_the_sole_finding() {
        for (literal, type_name) in TYPES {
            for len in [40, 43, 44] {
                assert_sole_provider_finding(DETECTOR, type_name, &key(literal, None, len));
            }
        }
        for segment in ["prd", "dev-us_east", "ci"] {
            assert_sole_provider_finding(
                DETECTOR,
                "doppler_service_token",
                &key("st", Some(segment), 43),
            );
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let base = key("st", None, 43);
        let body = &base["dp.st.".len()..];
        let mut dashed = body.to_owned();
        dashed.replace_range(10..11, "-");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                key("st", None, 39),
                key("st", None, 45),
                format!("dp.st.{dashed}"),
                format!("dp.xx.{body}"),
                format!("DP.ST.{body}"),
                format!("dp.st.P.{body}"),
                format!("dpst.{body}"),
                format!("x{base}"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "token dp.st\u{2026}Ab12Cd".to_owned(),
            "DOPPLER_TOKEN=${{ secrets.DOPPLER_TOKEN }}\n".to_owned(),
            "DOPPLER_TOKEN=dp.st.xxxx\n".to_owned(),
            "doppler run --token dp.st.... -- npm start\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key("st", Some("prd"), 43));
        assert_partition_parity(&key("said", None, 44));
    }
}

mod trigger_dev {
    use super::*;

    const DETECTOR: &str = "trigger-dev-token";
    const SECRET: &str = "trigger_dev_secret_api_key";
    const PAT_TYPE: &str = "trigger_dev_personal_access_token";
    const PAT_ALPHABET: &[u8] = b"123456789abcdefghijkmnopqrstuvwxyz";

    fn additional(env: &str) -> String {
        format!("tr_{env}_sk_{}", filler(ALNUM, 24, 1))
    }

    fn root(env: &str, len: usize) -> String {
        format!("tr_{env}_{}", filler(ALNUM, len, 2))
    }

    fn pat() -> String {
        format!("tr_pat_{}", filler(PAT_ALPHABET, 40, 3))
    }

    #[test]
    fn every_shape_wins_every_context_as_the_sole_finding() {
        for env in ["dev", "stg", "prod", "preview"] {
            assert_sole_provider_finding(DETECTOR, SECRET, &additional(env));
            assert_sole_provider_finding(DETECTOR, SECRET, &root(env, 24));
            assert_sole_provider_finding(DETECTOR, SECRET, &root(env, 20));
        }
        assert_sole_provider_finding(DETECTOR, PAT_TYPE, &pat());
    }

    #[test]
    fn no_stripe_or_elevenlabs_finding_fires_on_a_trigger_dev_key() {
        for key in [additional("prod"), additional("dev"), root("prod", 24)] {
            for input in contexts(&key) {
                let (_, findings) = whole_input(&input);
                assert!(
                    findings
                        .iter()
                        .all(|f| f.detector() != "stripe-token"
                            && f.detector() != "elevenlabs-api-key"),
                    "{input}: {findings:?}"
                );
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 24, 2);
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("tr_prod_sk_{}", filler(ALNUM, 21, 1)),
                format!("tr_prod_sk_{}", filler(ALNUM, 25, 1)),
                root("prod", 22),
                format!("tr_test_{body}"),
                format!("TR_PROD_{body}"),
                format!("str_prod_{body}"),
                format!("tr_pat_{}", filler(PAT_ALPHABET, 39, 3)),
                format!("tr_pat_0{}", filler(PAT_ALPHABET, 39, 3)),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        let public = filler(ALNUM, 20, 4);
        for input in [
            format!("pk_dev_{public}"),
            format!("TRIGGER_PUBLIC_KEY=pk_prod_{public}\n"),
            "TRIGGER_SECRET_KEY=tr_dev_sk_xxxxxxxxxx\n".to_owned(),
            "project ref tr_proj_abcdefghij\n".to_owned(),
            "if (tr_dev_mode) { start(); }\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&additional("preview"));
        assert_partition_parity(&pat());
    }
}

mod e2b {
    use super::*;

    const DETECTOR: &str = "e2b-api-key";
    const HEX: &[u8] = b"0123456789abcdef";

    fn key() -> String {
        format!("e2b_{}", filler(HEX, 40, 1))
    }

    #[test]
    fn the_key_wins_every_context_as_the_sole_finding() {
        assert_sole_provider_finding(DETECTOR, "e2b_api_key", &key());
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(HEX, 40, 1);
        let mut upper = body.clone();
        upper.replace_range(5..6, "A");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("e2b_{}", &body[..39]),
                format!("e2b_{body}0"),
                format!("e2b_{upper}"),
                format!("E2B_{body}"),
                format!("e2b-{body}"),
                format!("sk_e2b_{body}"),
                format!("xe2b_{body}"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "from e2b_code_interpreter import Sandbox\n".to_owned(),
            "E2B_API_KEY=e2b_...\n".to_owned(),
            "E2B_API_KEY=${E2B_API_KEY}\n".to_owned(),
            format!("commit {}\n", filler(HEX, 40, 2)),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key());
    }
}
