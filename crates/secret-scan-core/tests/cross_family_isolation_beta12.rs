//! Cross-family isolation across the Beta.12 product batch.
//!
//! The batch integrates five branches that each proved isolation only among
//! their own families: #1014 ranks 1–5 (`provider_families_1014.rs`), #1014
//! ranks 6–10 (`provider_families_1014_b.rs`), the #1012 variants
//! (`unsupported_variants_1012.rs`) and the Vercel per-class split
//! (`vercel_per_class_1036.rs`). This file checks the prefixes that could
//! collide once they share one registry:
//!
//! - every new family's value, in each probe context, is exactly one finding
//!   of its own detector and type at exactly the value's span, so no other
//!   new (or pre-existing) detector claims or shifts it;
//! - Paddle `pdl_live_`/`pdl_sdbx_` keys, Polar `polar_*` credentials and
//!   Stripe-shaped `sk_live_`/`rk_live_`/`whsec_` values stay with their own
//!   owners;
//! - a 40-character AWS secret access key is not claimed by the Bitwarden or
//!   Dynatrace detectors, and neither of those tokens is claimed by the
//!   context-constrained AWS secret detector when it sits under an AWS
//!   secret name or directly below an access key ID line;
//! - a Google `GOCSPX-` client secret under a generic credential name is the
//!   Google type alone, never also `contextual_secret`.
//!
//! Every value is built at run time from a literal prefix plus the same
//! seeded low-entropy synthetic filler the family tests use; none was
//! derived from an issued credential.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::whole_input;

fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
        .collect()
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const LOWER_HEX: &[u8] = b"0123456789abcdef";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn uuid(seed: usize) -> String {
    [8, 4, 4, 4, 12]
        .iter()
        .enumerate()
        .map(|(i, &len)| filler(LOWER_HEX, len, seed + i))
        .collect::<Vec<_>>()
        .join("-")
}

fn vercel(prefix: &str) -> String {
    const STEM: &[u8] = b"SyntheticRevokedVercelFixture";
    let body: String = (0..56)
        .map(|i| char::from(*STEM.get(i).unwrap_or(&b'0')))
        .collect();
    format!("{prefix}{body}")
}

fn bitwarden(seed: usize) -> String {
    format!(
        "0.5e7c0ded-0000-4000-8000-5e7c0ded0000.{}:{}==",
        filler(ALNUM, 30, seed),
        filler(BASE64, 22, seed + 1)
    )
}

fn dynatrace(kind: &str, seed: usize) -> String {
    format!(
        "dt0{kind}.{}.{}",
        filler(BASE32, 24, seed),
        filler(BASE32, 64, seed + 1)
    )
}

fn paddle(env: &str, seed: usize) -> String {
    format!(
        "pdl_{env}_apikey_{}_{}_{}",
        filler(LOWER_ALNUM, 26, seed),
        filler(ALNUM, 22, seed + 1),
        filler(ALNUM, 3, seed + 2)
    )
}

fn aws_secret(seed: usize) -> String {
    filler(BASE64, 40, seed)
}

fn aws_id(prefix: &str, seed: usize) -> String {
    format!("{prefix}{}", filler(UPPER_ALNUM, 16, seed))
}

/// One synthetic value per new family in the batch, with the detector and
/// type that must own it. The AWS secret access key is context-constrained
/// and is checked separately below.
fn every_new_family_value() -> Vec<(&'static str, &'static str, String)> {
    let mut values = vec![
        (
            "bitwarden-secrets-manager-access-token",
            "bitwarden_secrets_manager_access_token",
            bitwarden(1),
        ),
        (
            "polar-token",
            "polar_organization_access_token",
            format!("polar_oat_{}", filler(ALNUM, 43, 1)),
        ),
        (
            "polar-token",
            "polar_api_credential",
            format!("polar_pat_{}", filler(BASE64URL, 43, 2)),
        ),
        (
            "sonarqube-token",
            "sonarqube_user_token",
            format!("squ_{}", filler(LOWER_HEX, 40, 1)),
        ),
        (
            "sonarqube-token",
            "sonarqube_analysis_token",
            format!("sqa_{}", filler(LOWER_HEX, 40, 2)),
        ),
        (
            "rubygems-api-key",
            "rubygems_api_key",
            format!("rubygems_{}", filler(LOWER_HEX, 48, 1)),
        ),
        (
            "clojars-deploy-token",
            "clojars_deploy_token",
            format!("CLOJARS_{}", filler(LOWER_HEX, 60, 1)),
        ),
        (
            "crates-io-token",
            "crates_io_api_token",
            format!("cio{}", filler(ALNUM, 32, 1)),
        ),
        (
            "crates-io-token",
            "crates_io_trusted_publishing_token",
            format!("cio_tp_{}", filler(ALNUM, 32, 2)),
        ),
        ("dynatrace-token", "dynatrace_token", dynatrace("c01", 1)),
        ("dynatrace-token", "dynatrace_token", dynatrace("s16", 2)),
        ("paddle-api-key", "paddle_api_key", paddle("live", 1)),
        ("paddle-api-key", "paddle_api_key", paddle("sdbx", 2)),
        (
            "honeycomb-api-key",
            "honeycomb_ingest_key",
            format!("hcxik_{}", filler(LOWER_ALNUM, 58, 1)),
        ),
        (
            "axiom-token",
            "axiom_api_token",
            format!("xaat-{}", uuid(1)),
        ),
        (
            "axiom-token",
            "axiom_personal_token",
            format!("xapt-{}", uuid(2)),
        ),
        (
            "google-oauth-client-secret",
            "google_oauth_client_secret",
            format!("GOCSPX-{}", filler(BASE64URL, 28, 1)),
        ),
        (
            "vercel-token",
            "vercel_personal_access_token",
            vercel("vcp_"),
        ),
        ("vercel-token", "vercel_app_access_token", vercel("vca_")),
        ("vercel-token", "vercel_app_refresh_token", vercel("vcr_")),
    ];
    values.extend(second_wave_family_values());
    values.extend(third_wave_family_values());
    values
}

/// The #1014 third wave (#1106 to #1109): one value per finding type.
fn third_wave_family_values() -> Vec<(&'static str, &'static str, String)> {
    vec![(
        "pydantic-logfire-token",
        "pydantic_logfire_token",
        format!("pylf_v1_us_{}", filler(ALNUM, 44, 1)),
    )]
}

/// The #1014 second wave (#1102 to #1105): one value per finding type.
fn second_wave_family_values() -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            "xata-api-key",
            "xata_user_api_key",
            format!("xau_{}", filler(ALNUM, 33, 1)),
        ),
        (
            "xata-api-key",
            "xata_organization_api_key",
            format!("xao_{}", filler(ALNUM, 34, 2)),
        ),
        (
            "sourcegraph-token",
            "sourcegraph_access_token",
            format!("sgp_local_{}", filler(LOWER_HEX, 40, 3)),
        ),
        (
            "unkey-root-key",
            "unkey_root_key",
            format!(
                "unkey_{}unkeyv1{}",
                filler(BASE58, 8, 1),
                filler(BASE58, 42, 2)
            ),
        ),
        (
            "unkey-root-key",
            "unkey_root_key",
            format!("unkey_3Z{}", filler(BASE58, 22, 3)),
        ),
        (
            "buildkite-token",
            "buildkite_api_access_token",
            format!("bkua_{}", filler(LOWER_HEX, 40, 1)),
        ),
        (
            "buildkite-token",
            "buildkite_oauth_token",
            format!("bkur_{}", filler(ALNUM, 40, 2)),
        ),
        (
            "buildkite-token",
            "buildkite_agent_token",
            format!("bkaa_{}.{}", filler(ALNUM, 12, 3), filler(ALNUM, 60, 4)),
        ),
        (
            "buildkite-token",
            "buildkite_job_token",
            format!(
                "bkjat_eyJ{}.eyJ{}.{}",
                filler(BASE64URL, 30, 5),
                filler(BASE64URL, 60, 6),
                filler(BASE64URL, 43, 7)
            ),
        ),
        (
            "buildkite-token",
            "buildkite_packages_token",
            format!("bkpt_{}", filler(ALNUM, 50, 8)),
        ),
        (
            "buildkite-token",
            "buildkite_pipeline_token",
            format!("bktr_{}", filler(ALNUM, 40, 9)),
        ),
        (
            "buildkite-token",
            "buildkite_portal_token",
            format!(
                "bkpat_{}_{}",
                filler(ALNUM, 12, 10),
                filler(LOWER_HEX, 40, 11)
            ),
        ),
    ]
}

/// Probe contexts shared by the family tests: bare, named, Bearer, JSON,
/// SDK keyword argument and chat sentence.
fn contexts(key: &str) -> Vec<String> {
    vec![
        key.to_owned(),
        format!("PROVIDER_TOKEN={key}\n"),
        format!("export PROVIDER_TOKEN=\"{key}\"\n"),
        format!("Authorization: Bearer {key}\n"),
        format!("{{\"token\": \"{key}\"}}"),
        format!("{{\"api_key\": \"{key}\"}}"),
        format!("client = Client(api_key=\"{key}\")\n"),
        format!("Here is my key {key} can you debug why it fails?"),
        format!("config:\n  token: {key}\n"),
    ]
}

/// Findings whose range overlaps `value`'s first occurrence in `input`.
fn findings_over<'a>(input: &str, value: &str, findings: &'a [Finding]) -> Vec<&'a Finding> {
    let start = input.find(value).unwrap();
    let end = start + value.len();
    findings
        .iter()
        .filter(|f| f.range().start() < end && f.range().end() > start)
        .collect()
}

/// Exactly one finding over `value`: `detector`/`type_name`, redacted, at
/// exactly the value's span, and the value gone from the output.
fn assert_owned_by(input: &str, value: &str, detector: &str, type_name: &str) {
    let (text, findings) = whole_input(input);
    let over = findings_over(input, value, &findings);
    assert_eq!(over.len(), 1, "{type_name}: {input:?}: {findings:?}");
    let start = input.find(value).unwrap();
    assert_eq!(over[0].detector(), detector, "{input:?}: {findings:?}");
    assert_eq!(over[0].type_name(), type_name, "{input:?}: {findings:?}");
    assert_eq!(over[0].action(), Action::Redact, "{input:?}");
    assert_eq!(
        (over[0].range().start(), over[0].range().end()),
        (start, start + value.len()),
        "{input:?}"
    );
    assert!(!text.contains(value), "{input:?}");
}

fn assert_not_claimed_by(input: &str, detector: &str) {
    let (_, findings) = whole_input(input);
    assert!(
        findings.iter().all(|f| f.detector() != detector),
        "{detector} claimed {input:?}: {findings:?}"
    );
}

#[test]
fn every_new_family_value_is_owned_by_its_own_detector_alone() {
    for (detector, type_name, value) in every_new_family_value() {
        for input in contexts(&value) {
            assert_owned_by(&input, &value, detector, type_name);
        }
    }
}

#[test]
fn two_new_families_on_one_line_keep_their_own_spans() {
    let values = every_new_family_value();
    for pair in values.windows(2) {
        let (first_detector, first_type, first) = &pair[0];
        let (second_detector, second_type, second) = &pair[1];
        let input = format!("first={first} second={second}\n");
        assert_owned_by(&input, first, first_detector, first_type);
        assert_owned_by(&input, second, second_detector, second_type);
    }
}

#[test]
fn paddle_polar_and_stripe_shaped_live_values_stay_with_their_owners() {
    let stripe_shaped = [
        format!("sk_live_{}", filler(ALNUM, 99, 3)),
        format!("rk_live_{}", filler(ALNUM, 99, 4)),
        format!("sk_test_{}", filler(ALNUM, 99, 5)),
        format!("whsec_{}", filler(ALNUM, 32, 6)),
    ];
    for value in &stripe_shaped {
        for input in contexts(value) {
            assert_not_claimed_by(&input, "paddle-api-key");
            assert_not_claimed_by(&input, "polar-token");
        }
    }
    for value in [paddle("live", 3), paddle("sdbx", 4)] {
        for input in contexts(&value) {
            assert_not_claimed_by(&input, "stripe-token");
            assert_not_claimed_by(&input, "polar-token");
        }
    }
    for value in [
        format!("polar_oat_{}", filler(ALNUM, 43, 3)),
        format!("polar_pat_{}", filler(BASE64URL, 43, 4)),
    ] {
        for input in contexts(&value) {
            assert_not_claimed_by(&input, "stripe-token");
            assert_not_claimed_by(&input, "paddle-api-key");
        }
    }
}

#[test]
fn vercel_class_values_are_not_claimed_by_other_prefixed_families() {
    for prefix in ["vcp_", "vca_", "vcr_", "vci_", "vck_"] {
        let value = vercel(prefix);
        for input in contexts(&value) {
            let (_, findings) = whole_input(&input);
            let over = findings_over(&input, &value, &findings);
            assert!(
                over.iter().all(|f| f.detector() == "vercel-token"),
                "{input:?}: {findings:?}"
            );
        }
    }
}

#[test]
fn a_40_character_aws_secret_is_not_claimed_by_bitwarden_or_dynatrace() {
    let id = aws_id("AKIA", 1);
    for seed in [1, 2, 3] {
        let secret = aws_secret(seed);
        for input in [
            format!("AWS_SECRET_ACCESS_KEY={secret}\n"),
            format!("aws_access_key_id = {id}\naws_secret_access_key = {secret}\n"),
            format!("{id}\n{secret}\n"),
            format!("{{\"AccessKeyId\": \"{id}\", \"SecretAccessKey\": \"{secret}\"}}"),
        ] {
            assert_owned_by(
                &input,
                &secret,
                "aws-secret-access-key",
                "aws_secret_access_key",
            );
            assert_not_claimed_by(&input, "bitwarden-secrets-manager-access-token");
            assert_not_claimed_by(&input, "dynatrace-token");
        }
    }
}

#[test]
fn bitwarden_and_dynatrace_tokens_beside_an_aws_id_stay_with_their_owners() {
    let id = aws_id("AKIA", 2);
    let temporary = aws_id("ASIA", 3);
    for (detector, type_name, value) in [
        (
            "bitwarden-secrets-manager-access-token",
            "bitwarden_secrets_manager_access_token",
            bitwarden(4),
        ),
        ("dynatrace-token", "dynatrace_token", dynatrace("c01", 5)),
        ("dynatrace-token", "dynatrace_token", dynatrace("s16", 6)),
    ] {
        for input in [
            format!("{id}\n{value}\n"),
            format!("{temporary}\n{value}\n"),
            format!("aws_access_key_id = {id}\naws_secret_access_key = {value}\n"),
            format!("AWS_SECRET_ACCESS_KEY={value}\n"),
            format!("{{\"AccessKeyId\": \"{id}\", \"SecretAccessKey\": \"{value}\"}}"),
        ] {
            assert_owned_by(&input, &value, detector, type_name);
            assert_not_claimed_by(&input, "aws-secret-access-key");
        }
    }
}

#[test]
fn a_gocspx_secret_under_a_generic_name_is_the_google_type_alone() {
    for seed in [1, 2, 3] {
        let value = format!("GOCSPX-{}", filler(BASE64URL, 28, seed));
        for input in [
            format!("client_secret={value}\n"),
            format!("GOOGLE_CLIENT_SECRET=\"{value}\"\n"),
            format!("{{\"client_secret\": \"{value}\"}}"),
            format!(
                "{{\"web\": {{\"client_id\": \"x.apps.googleusercontent.com\", \"client_secret\": \"{value}\"}}}}"
            ),
            format!("password: {value}\n"),
            format!("secret = \"{value}\"\n"),
        ] {
            assert_owned_by(
                &input,
                &value,
                "google-oauth-client-secret",
                "google_oauth_client_secret",
            );
        }
    }
}
