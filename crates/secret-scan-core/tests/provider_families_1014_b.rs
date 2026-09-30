//! Issue #1014 broad-discovery families, ranks 6 to 10 (#1031–#1035),
//! through the public API with the full default registry.
//!
//! Every value is built at run time from a literal prefix plus a seeded
//! low-entropy synthetic filler, so no realistic credential literal is
//! committed. The filler was never derived from an issued credential.
//!
//! Each family checks, against the whole built-in registry rather than its
//! own detector alone:
//!
//! - every handoff context (bare in prose, env, `export`, Bearer,
//!   `X-API-Key`, JSON `token`/`api_key`, SDK keyword argument, chat
//!   sentence, YAML, fenced block) plus the family's own host forms yields
//!   exactly one finding, of the provider type, at exactly the value's span,
//!   redacted; the provider candidate wins the overlap with
//!   `contextual_secret`, `bearer_token`, `authorization_credential` and any
//!   other built-in;
//! - one-property twins yield no finding of the provider's detector;
//! - benign siblings stay unclaimed by the provider's detector;
//! - the other families' values stay unclaimed by the provider's detector
//!   (cross-family isolation);
//! - an adversarial repetition line stays linear and claims nothing;
//! - every two-chunk partition of a Bearer line matches the whole input.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::time::{Duration, Instant};

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Deterministic synthetic filler over `alphabet`.
fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
        .collect()
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const LOWER_HEX: &[u8] = b"0123456789abcdef";

/// The #860 index contexts plus a few host forms.
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

/// A glued repetition of `unit` is one wider identifier: `detector` claims
/// nothing in it, and the whole scan stays well inside a linear budget.
fn assert_repetition_line_is_unclaimed(detector: &str, unit: &str) {
    let line = unit.repeat(4_096 / unit.len() + 1);
    let started = Instant::now();
    assert_unclaimed(detector, &line);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{detector}: repetition line took {:?}",
        started.elapsed()
    );
}

/// One synthetic value of every family in this file, for cross-family
/// isolation: each detector must leave every other family's value alone.
fn every_family_value() -> Vec<(&'static str, String)> {
    vec![
        ("crates-io-token", crates_io::api_token(1)),
        ("crates-io-token", crates_io::trusted_publishing_token(2)),
        ("dynatrace-token", dynatrace::token("c01", 24, 64, 1)),
        ("dynatrace-token", dynatrace::token("s16", 24, 64, 2)),
        ("paddle-api-key", paddle::key("live", 26, 22, 3, 1)),
        ("paddle-api-key", paddle::key("sdbx", 26, 22, 3, 2)),
        ("honeycomb-api-key", honeycomb::key('x', "ik", 58, 1)),
        ("honeycomb-api-key", honeycomb::key('a', "ic", 58, 2)),
        ("axiom-token", axiom::token("xaat-", 1)),
        ("axiom-token", axiom::token("xapt-", 2)),
    ]
}

fn assert_isolated(detector: &str) {
    for (owner, value) in every_family_value() {
        if owner != detector {
            for input in contexts(&value) {
                assert_unclaimed(detector, &input);
            }
        }
    }
}

mod crates_io {
    use super::*;

    const DETECTOR: &str = "crates-io-token";
    const API: &str = "crates_io_api_token";
    const TRUSTED: &str = "crates_io_trusted_publishing_token";

    pub(super) fn api_token(seed: usize) -> String {
        format!("cio{}", filler(ALNUM, 32, seed))
    }

    pub(super) fn trusted_publishing_token(seed: usize) -> String {
        format!("cio_tp_{}", filler(ALNUM, 32, seed))
    }

    #[test]
    fn both_shapes_win_every_context_as_the_sole_finding() {
        for seed in [1, 5, 9] {
            let api = api_token(seed);
            let trusted = trusted_publishing_token(seed + 1);
            assert_sole_provider_finding(DETECTOR, API, &api);
            assert_sole_provider_finding(DETECTOR, TRUSTED, &trusted);
            for (key, type_name) in [(&api, API), (&trusted, TRUSTED)] {
                for input in [
                    format!("CARGO_REGISTRY_TOKEN={key}\n"),
                    format!("env:\n  CARGO_REGISTRY_TOKEN: {key}\n"),
                    format!("[registry]\ntoken = \"{key}\"\n"),
                    format!("cargo publish --token {key}\n"),
                    format!(
                        "2026-09-29T12:00:00Z ##[debug] exchanged OIDC token for {key} (expires in 30m)\n"
                    ),
                ] {
                    assert_sole_finding_in(&input, DETECTOR, type_name, key);
                }
            }
        }
    }

    #[test]
    fn a_trusted_publishing_token_is_reported_whatever_its_check_character() {
        for last in ["A", "q", "0", "9"] {
            let key = format!("cio_tp_{}{last}", filler(ALNUM, 31, 3));
            assert_sole_finding_in(&key, DETECTOR, TRUSTED, &key);
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 32, 2);
        let mut dashed = body.clone();
        dashed.replace_range(10..11, "-");
        let mut underscored = body.clone();
        underscored.replace_range(10..11, "_");
        let api = api_token(2);
        let trusted = trusted_publishing_token(2);
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("cio{}", filler(ALNUM, 31, 2)),
                format!("cio{}", filler(ALNUM, 33, 2)),
                format!("cio{dashed}"),
                format!("cio{underscored}"),
                format!("CIO{body}"),
                format!("cio_tp_{}", filler(ALNUM, 31, 2)),
                format!("cio_tp_{}", filler(ALNUM, 33, 2)),
                format!("cio_tp-{body}"),
                format!("x{api}"),
                format!("_{api}"),
                format!("{api}x"),
                format!("x{trusted}"),
                format!("{trusted}_x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "the ciound buffer drains\n".to_owned(),
            "cio_config = load_config()\n".to_owned(),
            "CARGO_REGISTRY_TOKEN: ${{ secrets.CRATES_TOKEN }}\n".to_owned(),
            "cargo publish --token cio...\n".to_owned(),
            format!("sha={}\n", api_token(4) + &filler(ALNUM, 29, 4)),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn other_families_are_isolated() {
        assert_isolated(DETECTOR);
    }

    #[test]
    fn a_repetition_line_is_unclaimed() {
        assert_repetition_line_is_unclaimed(DETECTOR, &api_token(6));
        assert_repetition_line_is_unclaimed(DETECTOR, "cio_tp_");
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&api_token(7));
        assert_partition_parity(&trusted_publishing_token(8));
    }
}

mod dynatrace {
    use super::*;

    const DETECTOR: &str = "dynatrace-token";
    const TYPE: &str = "dynatrace_token";

    pub(super) fn token(kind: &str, public: usize, secret: usize, seed: usize) -> String {
        format!(
            "dt0{kind}.{}.{}",
            filler(BASE32, public, seed),
            filler(BASE32, secret, seed + 1)
        )
    }

    #[test]
    fn classic_and_platform_tokens_win_every_context_as_the_sole_finding() {
        for (kind, seed) in [("c01", 1), ("s01", 4), ("s16", 7)] {
            let key = token(kind, 24, 64, seed);
            assert_eq!(key.len(), 96);
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("DT_API_TOKEN={key}\n"),
                format!(
                    "curl -H 'Authorization: Api-Token {key}' https://example.invalid/api/v2/metrics\n"
                ),
                format!("Authorization: Api-Token {key}\n"),
                format!(
                    "apiVersion: v1\nkind: Secret\nmetadata:\n  name: dynakube\ndata:\n  apiToken: {key}\n"
                ),
                format!("OTEL_EXPORTER_OTLP_HEADERS=Authorization=Api-Token%20{key}\n"),
                format!(
                    "exporters:\n  otlphttp:\n    headers:\n      Authorization: \"Api-Token {key}\"\n"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let good = token("c01", 24, 64, 2);
        let mut lower = good.clone();
        lower.replace_range(10..11, "q");
        let mut digit = good.clone();
        digit.replace_range(50..51, "1");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                token("c01", 23, 64, 2),
                token("c01", 25, 64, 2),
                token("c01", 24, 63, 2),
                token("c01", 24, 65, 2),
                token("x01", 24, 64, 2),
                token("c1", 24, 64, 2),
                good.replacen("dt0", "dt1", 1),
                lower,
                digit,
                format!("{}-{}", &good[..31], &good[32..]),
                format!("x{good}"),
                format!("_{good}"),
                format!("{good}x"),
                format!("{good}.x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            format!(
                "INFO created token dt0s01.{} for ingest\n",
                filler(BASE32, 24, 3)
            ),
            "curl -H \"Authorization: Api-Token dt0c01.abc123.abcdefg\"\n".to_owned(),
            "DT_API_TOKEN=${DT_API_TOKEN}\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn other_families_are_isolated() {
        assert_isolated(DETECTOR);
    }

    #[test]
    fn a_repetition_line_is_unclaimed() {
        assert_repetition_line_is_unclaimed(DETECTOR, &token("s01", 24, 64, 5));
        assert_repetition_line_is_unclaimed(DETECTOR, "dt0c01.");
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&token("c01", 24, 64, 6));
    }
}

mod paddle {
    use super::*;

    const DETECTOR: &str = "paddle-api-key";
    const TYPE: &str = "paddle_api_key";

    pub(super) fn key(env: &str, id: usize, secret: usize, suffix: usize, seed: usize) -> String {
        format!(
            "pdl_{env}_apikey_{}_{}_{}",
            filler(LOWER_ALNUM, id, seed),
            filler(ALNUM, secret, seed + 1),
            filler(ALNUM, suffix, seed + 2)
        )
    }

    #[test]
    fn live_and_sandbox_keys_win_every_context_as_the_sole_finding() {
        for (env, seed) in [("live", 1), ("sdbx", 4), ("live", 7)] {
            let key = key(env, 26, 22, 3, seed);
            assert_eq!(key.len(), 69);
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("PADDLE_API_KEY={key}\n"),
                format!(
                    "const paddle = new Paddle('{key}', {{ environment: Environment.sandbox }});\n"
                ),
                format!("paddle = Client(\"{key}\")\n"),
                format!(
                    "curl -H 'Authorization: Bearer {key}' https://example.invalid/customers\n"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let good = key("sdbx", 26, 22, 3, 2);
        let mut upper_in_id = good.clone();
        upper_in_id.replace_range(20..21, "Q");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                key("sdbx", 25, 22, 3, 2),
                key("sdbx", 27, 22, 3, 2),
                key("sdbx", 26, 21, 3, 2),
                key("sdbx", 26, 23, 3, 2),
                key("sdbx", 26, 22, 2, 2),
                key("sdbx", 26, 22, 4, 2),
                key("test", 26, 22, 3, 2),
                good.replacen("apikey_", "", 1),
                format!("{}-{}", &good[..42], &good[43..]),
                upper_in_id,
                format!("x{good}"),
                format!("_{good}"),
                format!("{good}x"),
                format!("{good}_x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            format!(
                "{{\"event_type\": \"api_key.created\", \"data\": {{\"id\": \"apikey_{}\"}}}}",
                filler(LOWER_ALNUM, 26, 3)
            ),
            format!("legacy={}\n", filler(LOWER_ALNUM, 50, 4)),
            "PADDLE_API_KEY=${PADDLE_API_KEY}\n".to_owned(),
            "^pdl_(live|sdbx)_apikey_[a-z\\d]{26}_[a-zA-Z\\d]{22}_[a-zA-Z\\d]{3}$\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn other_families_are_isolated() {
        assert_isolated(DETECTOR);
    }

    #[test]
    fn a_repetition_line_is_unclaimed() {
        assert_repetition_line_is_unclaimed(DETECTOR, &key("live", 26, 22, 3, 5));
        assert_repetition_line_is_unclaimed(DETECTOR, "pdl_live_apikey_");
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key("sdbx", 26, 22, 3, 6));
    }
}

mod honeycomb {
    use super::*;

    const DETECTOR: &str = "honeycomb-api-key";
    const TYPE: &str = "honeycomb_ingest_key";

    pub(super) fn key(letter: char, kind: &str, len: usize, seed: usize) -> String {
        format!("hc{letter}{kind}_{}", filler(LOWER_ALNUM, len, seed))
    }

    #[test]
    fn ingest_keys_win_every_context_as_the_sole_finding() {
        for (letter, kind, seed) in [
            ('x', "ik", 1),
            ('x', "ic", 4),
            ('b', "ik", 7),
            ('z', "ic", 9),
        ] {
            let key = key(letter, kind, 58, seed);
            assert_eq!(key.len(), 64);
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("HONEYCOMB_API_KEY={key}\n"),
                format!("X-Honeycomb-Team: {key}\n"),
                format!("OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team={key}\n"),
                format!(
                    "exporters:\n  otlp:\n    endpoint: api.honeycomb.io:443\n    headers:\n      x-honeycomb-team: {key}\n"
                ),
                format!("libhoney.Init(libhoney.Config{{APIKey: \"{key}\", Dataset: \"ci\"}})\n"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let good = key('x', "ik", 58, 2);
        let mut upper = good.clone();
        upper.replace_range(30..31, "Q");
        let mut dashed = good.clone();
        dashed.replace_range(30..31, "-");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                key('x', "ik", 57, 2),
                key('x', "ik", 59, 2),
                upper,
                dashed,
                format!("hcik_{}", filler(LOWER_ALNUM, 59, 2)),
                format!("hcAik_{}", filler(LOWER_ALNUM, 58, 2)),
                key('x', "mk", 58, 2),
                format!("x{good}"),
                format!("_{good}"),
                format!("{good}x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_and_the_gated_management_key_are_unclaimed() {
        for input in [
            format!("{{\"id\": \"hcxik_{}\"}}", filler(LOWER_ALNUM, 26, 3)),
            format!("environment hcxen_{}\n", filler(LOWER_ALNUM, 26, 3)),
            format!("HONEYCOMB_API_KEY={}\n", filler(LOWER_ALNUM, 32, 4)),
            format!(
                "Authorization: Bearer hcxmk_{}:{}\n",
                filler(LOWER_ALNUM, 26, 5),
                filler(LOWER_ALNUM, 32, 6)
            ),
            "HONEYCOMB_API_KEY=${HONEYCOMB_API_KEY}\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn other_families_are_isolated() {
        assert_isolated(DETECTOR);
    }

    #[test]
    fn a_repetition_line_is_unclaimed() {
        assert_repetition_line_is_unclaimed(DETECTOR, &key('x', "ik", 58, 5));
        assert_repetition_line_is_unclaimed(DETECTOR, "hcxik_");
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key('x', "ic", 58, 6));
    }
}

mod axiom {
    use super::*;

    const DETECTOR: &str = "axiom-token";
    const API: &str = "axiom_api_token";
    const PERSONAL: &str = "axiom_personal_token";

    fn uuid_with(groups: [usize; 5], seed: usize) -> String {
        groups
            .iter()
            .enumerate()
            .map(|(i, &len)| filler(LOWER_HEX, len, seed + i))
            .collect::<Vec<_>>()
            .join("-")
    }

    pub(super) fn token(prefix: &str, seed: usize) -> String {
        format!("{prefix}{}", uuid_with([8, 4, 4, 4, 12], seed))
    }

    #[test]
    fn api_and_personal_tokens_win_every_context_as_the_sole_finding() {
        for seed in [1, 5, 9] {
            for (key, type_name) in [
                (token("xaat-", seed), API),
                (token("xapt-", seed + 1), PERSONAL),
            ] {
                assert_eq!(key.len(), 41);
                assert_sole_provider_finding(DETECTOR, type_name, &key);
                for input in [
                    format!("AXIOM_TOKEN={key}\n"),
                    format!(
                        "[sinks.axiom]\ntype = \"axiom\"\ndataset = \"logs\"\ntoken = \"{key}\"\n"
                    ),
                    format!("[OUTPUT]\n    Name  http\n    Header Authorization Bearer {key}\n"),
                    format!(
                        "OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer {key},X-Axiom-Dataset=logs\n"
                    ),
                    format!(
                        "datasources:\n  - name: axiom\n    secureJsonData:\n      password: {key}\n"
                    ),
                ] {
                    assert_sole_finding_in(&input, DETECTOR, type_name, &key);
                }
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = uuid_with([8, 4, 4, 4, 12], 3);
        let good = format!("xaat-{body}");
        let mut upper = good.clone();
        upper.replace_range(10..11, "A");
        let mut non_hex = good.clone();
        non_hex.replace_range(10..11, "g");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("xaat-{}", uuid_with([7, 4, 4, 4, 12], 3)),
                format!("xaat-{}", uuid_with([8, 4, 4, 4, 13], 3)),
                format!("xaat-{}", uuid_with([8, 5, 4, 4, 11], 3)),
                upper,
                non_hex,
                format!("xaat_{body}"),
                format!("xabt-{body}"),
                format!("x{good}"),
                format!("_{good}"),
                format!("{good}x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "AXIOM_TOKEN=xaat-your-api-token\n".to_owned(),
            "AXIOM_TOKEN=xaat-xxxxxxxxxx-xxxxxxxxx-xxxxxxx\n".to_owned(),
            format!("request id {}\n", uuid_with([8, 4, 4, 4, 12], 4)),
            "AXIOM_TOKEN=${AXIOM_TOKEN}\n".to_owned(),
            "AXIOM_ORG_ID=acme-corp-a1b2\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn other_families_are_isolated() {
        assert_isolated(DETECTOR);
    }

    #[test]
    fn a_repetition_line_is_unclaimed() {
        assert_repetition_line_is_unclaimed(DETECTOR, &token("xapt-", 5));
        assert_repetition_line_is_unclaimed(DETECTOR, "xaat-");
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&token("xaat-", 6));
        assert_partition_parity(&token("xapt-", 7));
    }
}
