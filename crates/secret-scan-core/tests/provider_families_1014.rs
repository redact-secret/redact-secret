//! Issue #1014 broad-discovery provider families (#1019–#1025) through the
//! public API with the full default registry.
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
//!   fenced block, sentence punctuation) yields exactly one finding, of the
//!   provider type, at exactly the key's span, redacted; bare prose, the chat
//!   sentence and the JSON `"token"` value are the contexts generic
//!   detection misses today;
//! - one-property twins yield no finding of the provider's detector;
//! - benign siblings stay unclaimed by the provider's detector;
//! - each family keeps its own finding next to the others (isolation);
//! - a repetition line stays bounded and exact;
//! - every two-chunk partition of a Bearer line matches the whole input.
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
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The probe contexts plus a few host forms.
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

mod bitwarden {
    use super::*;

    pub(super) const DETECTOR: &str = "bitwarden-secrets-manager-access-token";
    const TYPE: &str = "bitwarden_secrets_manager_access_token";
    const UUID: &str = "5e7c0ded-0000-4000-8000-5e7c0ded0000";

    fn parts(seed: usize) -> (String, String) {
        (filler(ALNUM, 30, seed), filler(BASE64, 22, seed + 1))
    }

    pub(super) fn token(seed: usize) -> String {
        let (secret, key) = parts(seed);
        format!("0.{UUID}.{secret}:{key}==")
    }

    #[test]
    fn every_form_wins_every_context_as_the_sole_finding() {
        let (secret, key) = parts(1);
        let upper = format!("0.{}.{secret}:{key}==", UUID.to_uppercase());
        for token in [token(1), upper] {
            assert_eq!(token.len(), 94);
            assert_sole_provider_finding(DETECTOR, TYPE, &token);
            for input in [
                format!("BWS_ACCESS_TOKEN={token}\n"),
                format!("bws secret list --access-token {token}\n"),
                format!("- uses: bitwarden/sm-action@v2\n  with:\n    access_token: {token}\n"),
                format!(
                    "{{\"mcpServers\":{{\"bitwarden\":{{\"env\":{{\"BWS_ACCESS_TOKEN\":\"{token}\"}}}}}}}}"
                ),
                format!("docker run -e BWS_ACCESS_TOKEN={token} bitwarden/bws\n"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &token);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let (secret, key) = parts(2);
        let token = format!("0.{UUID}.{secret}:{key}==");
        let mut dashed = secret.clone();
        dashed.replace_range(4..5, "-");
        let mut underscored = secret.clone();
        underscored.replace_range(4..5, "_");
        let mut non_hex = UUID.to_owned();
        non_hex.replace_range(1..2, "g");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("0.{UUID}.{}:{key}==", &secret[..29]),
                format!("0.{UUID}.{secret}A:{key}=="),
                format!("0.{UUID}.{dashed}:{key}=="),
                format!("0.{UUID}.{underscored}:{key}=="),
                format!("0.{UUID}.{secret}:{}==", &key[..21]),
                format!("0.{UUID}.{secret}:{key}A=="),
                format!("0.{UUID}.{secret}:{key}="),
                format!("0.{UUID}.{secret}:{key}"),
                format!("1.{UUID}.{secret}:{key}=="),
                format!("0.{}0000.{secret}:{key}==", UUID.replace('-', "")),
                format!("0.{non_hex}.{secret}:{key}=="),
                format!("0.{UUID}.{secret}.{key}=="),
                format!("1{token}"),
                format!("v{token}"),
                format!("x{token}"),
                format!("{token}A"),
                format!("{token}="),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            format!("Released 0.{UUID} today\n"),
            format!("see 0.{UUID}.json\n"),
            format!("client_id: user.{UUID}\n"),
            format!("client_id: organization.{UUID}\n"),
            "BWS_ACCESS_TOKEN=${BWS_ACCESS_TOKEN}\n".to_owned(),
            "BWS_ACCESS_TOKEN=${{ secrets.BWS_ACCESS_TOKEN }}\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        for input in ["=".repeat(20_000), "0.".repeat(10_000)] {
            assert_unclaimed(DETECTOR, &input);
        }
        assert_repetition_line(DETECTOR, &token(3), 200);
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&token(4));
    }
}

mod polar {
    use super::*;

    pub(super) const DETECTOR: &str = "polar-token";
    const ORGANIZATION: &str = "polar_organization_access_token";
    const API: &str = "polar_api_credential";
    const URL_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const API_PREFIXES: [&str; 7] = [
        "polar_pat_",
        "polar_at_u_",
        "polar_at_o_",
        "polar_rt_u_",
        "polar_rt_o_",
        "polar_cs_",
        "polar_crt_",
    ];

    pub(super) fn oat(seed: usize) -> String {
        format!("polar_oat_{}", filler(ALNUM, 43, seed))
    }

    #[test]
    fn every_role_wins_every_context_as_the_sole_finding() {
        let oat = oat(1);
        assert_sole_provider_finding(DETECTOR, ORGANIZATION, &oat);
        for input in [
            format!("POLAR_ACCESS_TOKEN={oat}\n"),
            format!("polar = Polar(access_token=\"{oat}\")\n"),
            format!("const polar = new Polar({{ accessToken: \"{oat}\" }});\n"),
            format!(
                "{{\"mcpServers\":{{\"polar\":{{\"env\":{{\"POLAR_ACCESS_TOKEN\":\"{oat}\"}}}}}}}}"
            ),
        ] {
            assert_sole_finding_in(&input, DETECTOR, ORGANIZATION, &oat);
        }
        for (seed, prefix) in API_PREFIXES.iter().enumerate() {
            for body in [filler(URL_SAFE, 43, seed), filler(ALNUM, 43, seed)] {
                assert_sole_provider_finding(DETECTOR, API, &format!("{prefix}{body}"));
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 43, 2);
        let base = format!("polar_oat_{body}");
        let mut dashed = body.clone();
        dashed.replace_range(7..8, "-");
        let mut underscored = body.clone();
        underscored.replace_range(7..8, "_");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("polar_oat_{}", &body[..42]),
                format!("{base}A"),
                format!("polar_pat_{}", &body[..42]),
                format!("polar_pat_{body}A"),
                format!("polar_oat_{dashed}"),
                format!("polar_oat_{underscored}"),
                format!("polar_at_{body}"),
                format!("POLAR_OAT_{body}"),
                format!("xpolar_oat_{body}"),
                format!("_{base}"),
                format!("-{base}"),
                format!("{base}_"),
                format!("{base}-1"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        let body = filler(ALNUM, 43, 3);
        for input in [
            format!("POLAR_CLIENT_ID=polar_ci_{body}\n"),
            format!("client_secret: polar_c_{body}\n"),
            format!("checkout link polar_cl_{body}\n"),
            format!("session polar_us_{body}\n"),
            format!("POLAR_WEBHOOK_SECRET=whsec_{body}\n"),
            "POLAR_ACCESS_TOKEN=polar_oat_xxxxxxxx\n".to_owned(),
            "POLAR_ACCESS_TOKEN=${{ secrets.POLAR_ACCESS_TOKEN }}\n".to_owned(),
            "polar_access_token_id = 42\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_polar_webhook_secret_stays_with_stripe() {
        let secret = format!("whsec_{}", filler(ALNUM, 43, 4));
        let (_, findings) = whole_input(&format!("{secret}\n"));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].detector(), "stripe-token");
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        assert_unclaimed(DETECTOR, &"polar_oat_".repeat(20_000));
        assert_unclaimed(DETECTOR, &oat(5).repeat(200));
        assert_repetition_line(DETECTOR, &oat(5), 200);
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&oat(6));
        assert_partition_parity(&format!("polar_at_u_{}", filler(URL_SAFE, 43, 6)));
    }
}

/// Each #1014 family keeps its own finding on one line next to the others
/// and an existing prefixed family, and no family claims another's key.
mod isolation {
    use super::*;

    fn keys() -> Vec<(&'static str, String)> {
        vec![
            (bitwarden::DETECTOR, bitwarden::token(9)),
            (polar::DETECTOR, polar::oat(9)),
            (
                "e2b-api-key",
                format!("e2b_{}", filler(b"0123456789abcdef", 40, 9)),
            ),
        ]
    }

    #[test]
    fn each_family_keeps_its_own_finding() {
        let keys = keys();
        let line = keys
            .iter()
            .map(|(_, key)| key.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let (_, findings) = whole_input(&format!("{line}\n"));
        assert_eq!(findings.len(), keys.len(), "{findings:?}");
        for (detector, key) in &keys {
            let own = detector_findings(&findings, detector);
            assert_eq!(own.len(), 1, "{detector}: {findings:?}");
            let start = line.find(key.as_str()).unwrap();
            assert_eq!(own[0].range().start(), start);
            assert_eq!(own[0].range().end(), start + key.len());
            for (other, other_key) in &keys {
                if other != detector {
                    assert_unclaimed(detector, &format!("{other_key}\n"));
                }
            }
        }
    }

    #[test]
    fn a_jwt_stays_with_jwt() {
        let jwt = "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE";
        for (detector, _) in keys() {
            assert_unclaimed(detector, &format!("PROVIDER_TOKEN={jwt}\n"));
        }
    }
}
