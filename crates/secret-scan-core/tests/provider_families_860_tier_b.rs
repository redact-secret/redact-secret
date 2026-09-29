//! Issue #860 Tier B provider families (#912–#917) and the Beta.12
//! credential families (#970–#975) through the public API with the full
//! default registry.
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
//!   `bearer_token` and any other built-in;
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
const LOWER_HEX: &[u8] = b"0123456789abcdef";
const ALNUM_DASH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

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
    assert_input_partition_parity(&format!("Authorization: Bearer {key}\n"));
    assert_input_partition_parity(&format!("{key}\n"));
}

/// Every two-chunk partition of `input` reports the whole-input findings and
/// redacted text.
fn assert_input_partition_parity(input: &str) {
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

mod convex {
    use super::*;

    const DETECTOR: &str = "convex-deployment-key";
    const TYPE: &str = "convex_deployment_key";

    fn body(len: usize, seed: usize) -> String {
        format!("01{}", filler(LOWER_HEX, len - 2, seed))
    }

    fn keys() -> Vec<String> {
        vec![
            format!("convex-self-hosted|{}", body(74, 1)),
            format!("prod:happy-otter-123|{}", body(76, 2)),
            format!("dev:brave-lynx-7|{}", body(96, 3)),
            format!("preview:acme-team:web-app|{}", body(80, 4)),
            format!("project:acme:api|{}", body(90, 5)),
        ]
    }

    #[test]
    fn every_shape_wins_every_context_as_the_sole_finding() {
        for key in keys() {
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("CONVEX_DEPLOY_KEY={key}\n"),
                format!("CONVEX_SELF_HOSTED_ADMIN_KEY=\"{key}\"\n"),
                format!("curl -H 'Authorization: Convex {key}' https://example.invalid\n"),
                format!(
                    "services:\n  backend:\n    environment:\n      CONVEX_SELF_HOSTED_ADMIN_KEY: {key}\n"
                ),
                format!(
                    "{{\"mcpServers\":{{\"convex\":{{\"env\":{{\"CONVEX_DEPLOY_KEY\":\"{key}\"}}}}}}}}"
                ),
                format!(
                    "jobs:\n  deploy:\n    env:\n      CONVEX_DEPLOY_KEY: {key}\n    run: npx convex deploy\n"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let base = body(76, 6);
        let mut upper = base.clone();
        upper.replace_range(40..41, "A");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("convex-self-hosted|{}", body(72, 6)),
                format!("convex-self-hosted|{}", body(98, 6)),
                format!("convex-self-hosted|{}", body(75, 6)),
                format!("convex-self-hosted|02{}", &base[2..]),
                format!("convex-self-hosted|{upper}"),
                format!("convex-self-hosted||{base}"),
                format!("bold_hyena_681|{base}"),
                format!("xprod:happy-otter-123|{base}"),
                format!("convex-self-hosted|{base}x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "CONVEX_DEPLOYMENT=dev:happy-otter-123\n".to_owned(),
            "CONVEX_URL=https://happy-otter-123.convex.cloud\n".to_owned(),
            "CONVEX_DEPLOY_KEY=prod:your-deployment-name|your-admin-key\n".to_owned(),
            "prod:happy-otter-123|${CONVEX_BODY}\n".to_owned(),
            format!("| name | {} |\n", body(76, 7)),
            "prod:happy-otter-123|eyJ2SyntheticGatedCloudBodyNotClaimedYet0=\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("convex-self-hosted|{}", body(74, 8)));
        assert_partition_parity(&format!("preview:acme-team:web-app|{}", body(80, 9)));
    }
}

mod onepassword {
    use super::*;

    const DETECTOR: &str = "onepassword-service-account-token";
    const TYPE: &str = "onepassword_service_account_token";

    fn token(len: usize, seed: usize) -> String {
        format!("ops_eyJ{}", filler(ALNUM, len, seed))
    }

    #[test]
    fn every_width_wins_every_context_as_the_sole_finding() {
        let mut dashed = filler(ALNUM, 600, 4);
        dashed.replace_range(100..101, "-");
        dashed.replace_range(300..301, "_");
        for key in [
            token(250, 1),
            token(627, 2),
            token(866, 3),
            format!("ops_eyJ{dashed}"),
            format!("{}=", token(626, 5)),
            format!("{}==", token(625, 6)),
        ] {
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("OP_SERVICE_ACCOUNT_TOKEN={key}\n"),
                format!("jobs:\n  deploy:\n    env:\n      OP_SERVICE_ACCOUNT_TOKEN: {key}\n"),
                format!("OP_SERVICE_ACCOUNT_TOKEN={key} op item get deploy --vault ci\n"),
                format!(
                    "{{\"mcpServers\":{{\"op\":{{\"env\":{{\"OP_SERVICE_ACCOUNT_TOKEN\":\"{key}\"}}}}}}}}"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 600, 7);
        let mut plus = body.clone();
        plus.replace_range(200..201, "+");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                token(249, 7),
                format!("ops_eyj{body}"),
                format!("OPS_eyJ{body}"),
                format!("ops-eyJ{body}"),
                format!("ops_eyJ{plus}"),
                format!("xops_eyJ{body}"),
                format!("ops_eyJ{body}/"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        let connect_jwt = format!(
            "eyJ{}.eyJ{}.{}",
            filler(ALNUM, 40, 8),
            filler(ALNUM, 520, 9),
            filler(ALNUM, 43, 10)
        );
        for input in [
            "OP_SERVICE_ACCOUNT_TOKEN=ops_...\n".to_owned(),
            "op read op://Private/item/credential\n".to_owned(),
            "fn ops_function_name() {}\n".to_owned(),
            "OP_SERVICE_ACCOUNT_TOKEN=${{ secrets.OP_TOKEN }}\n".to_owned(),
            format!("OP_CONNECT_TOKEN={connect_jwt}\n"),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&token(260, 11));
        assert_partition_parity(&format!("{}==", token(300, 12)));
    }
}

mod inngest {
    use super::*;

    const DETECTOR: &str = "inngest-signing-key";
    const TYPE: &str = "inngest_signing_key";

    fn key(label: &str, len: usize, seed: usize) -> String {
        format!("signkey-{label}-{}", filler(LOWER_HEX, len, seed))
    }

    #[test]
    fn every_label_wins_every_context_as_the_sole_finding() {
        for (seed, label) in ["prod", "test", "branch"].into_iter().enumerate() {
            let key = key(label, 64, seed);
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("INNGEST_SIGNING_KEY={key}\n"),
                format!("INNGEST_SIGNING_KEY_FALLBACK={key}\n"),
                format!("export INNGEST_SIGNING_KEY={key}\n"),
                format!("new Inngest({{ id: \"app\", signingKey: \"{key}\" }});\n"),
                format!("curl -H \"Authorization: Bearer {key}\" https://example.invalid/v1\n"),
                format!("vercel env ls\n  INNGEST_SIGNING_KEY  {key}  Production\n"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(LOWER_HEX, 64, 4);
        let mut upper = body.clone();
        upper.replace_range(30..31, "A");
        let mut non_hex = body.clone();
        non_hex.replace_range(30..31, "g");
        let base = format!("signkey-prod-{body}");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                key("prod", 63, 4),
                key("prod", 65, 4),
                format!("signkey-prod-{upper}"),
                format!("signkey-prod-{non_hex}"),
                format!("signkey-preview-{body}"),
                format!("signkey_prod_{body}"),
                format!("SIGNKEY-prod-{body}"),
                format!("x{base}"),
                format!("{base}x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "INNGEST_SIGNING_KEY=signkey-prod-<YOUR-SIGNING-KEY>\n".to_owned(),
            "signingKey: \"signkey-test-12345\"\n".to_owned(),
            "INNGEST_SIGNING_KEY=${INNGEST_SIGNING_KEY}\n".to_owned(),
            format!("sha256 {}\n", filler(LOWER_HEX, 64, 5)),
            "INNGEST_EVENT_KEY=local\n".to_owned(),
            "eventKey = NO_EVENT_KEY_SET\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key("prod", 64, 6));
        assert_partition_parity(&key("branch", 64, 7));
    }
}

mod resend {
    use super::*;

    const DETECTOR: &str = "resend-api-key";
    const TYPE: &str = "resend_api_key";

    fn key(first: usize, second: usize, seed: usize) -> String {
        format!(
            "re_{}_{}",
            filler(ALNUM, first, seed),
            filler(ALNUM, second, seed + 1)
        )
    }

    #[test]
    fn the_documented_layout_wins_every_context_as_the_sole_finding() {
        for seed in [1, 5, 9] {
            let key = key(8, 24, seed);
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("RESEND_API_KEY={key}\n"),
                format!("const resend = new Resend(\"{key}\");\n"),
                format!("resend.api_key = \"{key}\"\n"),
                format!(
                    "{{\"mcpServers\":{{\"resend\":{{\"env\":{{\"RESEND_API_KEY\":\"{key}\"}}}}}}}}"
                ),
                format!("curl -H 'Authorization: Bearer {key}' https://example.invalid/emails\n"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let first = filler(ALNUM, 8, 2);
        let second = filler(ALNUM, 24, 3);
        let base = format!("re_{first}_{second}");
        let mut underscored = second.clone();
        underscored.replace_range(10..11, "_");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                key(7, 24, 2),
                key(9, 24, 2),
                key(8, 23, 2),
                key(8, 25, 2),
                format!("re_{first}-{second}"),
                format!("re_{first}_{underscored}"),
                format!("re_{}_{}", first.to_lowercase(), second.to_lowercase()),
                format!("RE_{first}_{second}"),
                format!("a{base}"),
                format!("_{base}"),
                format!("{base}x"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "RESEND_API_KEY=re_123456789\n",
            "RESEND_API_KEY=re_xxxxxxxxx\n",
            "RESEND_API_KEY=re_...\n",
            "pattern = re_compile(r'\\d+')\n",
            "re_pattern_cache = {}\n",
            "def pre_process_all_inputs_now(): pass\n",
            "RESEND_API_KEY=${RESEND_API_KEY}\n",
        ] {
            assert_unclaimed(DETECTOR, input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key(8, 24, 4));
    }
}

mod apify {
    use super::*;

    const DETECTOR: &str = "apify-api-token";
    const TYPE: &str = "apify_api_token";

    fn token(len: usize, seed: usize) -> String {
        format!("apify_api_{}", filler(ALNUM, len, seed))
    }

    #[test]
    fn every_width_wins_every_context_as_the_sole_finding() {
        for (seed, len) in [20, 36, 128].into_iter().enumerate() {
            let key = token(len, seed);
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("APIFY_TOKEN={key}\n"),
                format!("const client = new ApifyClient({{ token: '{key}' }});\n"),
                format!("client = ApifyClient(\"{key}\")\n"),
                format!(
                    "{{\"mcpServers\":{{\"apify\":{{\"env\":{{\"APIFY_TOKEN\":\"{key}\"}}}}}}}}"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 36, 4);
        let base = format!("apify_api_{body}");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                token(19, 4),
                token(129, 4),
                format!("{base}_x"),
                format!("{base}-1"),
                format!("APIFY_API_{body}"),
                format!("apify-api-{body}"),
                format!("x{base}"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "APIFY_TOKEN=apify_api_YOUR_TOKEN\n",
            "token: apify_api_test_token\n",
            "token: apify_api_invalid_token\n",
            "token: apify_api_dummy_for_smoke\n",
            "APIFY_TOKEN=apify_api_...\n",
            "if err == apify_api_error {}\n",
            "APIFY_API_BASE_URL=https://api.apify.com\n",
            "APIFY_TOKEN=apify_ui_test\n",
            "APIFY_TOKEN=${{ secrets.APIFY_TOKEN }}\n",
            "the prefix is apify_api_\n",
        ] {
            assert_unclaimed(DETECTOR, input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&token(36, 5));
    }
}

mod wandb {
    use super::*;

    const DETECTOR: &str = "wandb-api-key";
    const TYPE: &str = "wandb_api_key";

    fn key(len: usize, seed: usize) -> String {
        format!("wandb_v1_{}", filler(ALNUM, len, seed))
    }

    #[test]
    fn every_width_in_the_band_wins_every_context_as_the_sole_finding() {
        let body = filler(ALNUM, 77, 9);
        let split = format!("wandb_v1_{}_{}", &body[..27], &body[28..]);
        for key in [key(64, 1), key(77, 2), key(96, 3), split] {
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("WANDB_API_KEY={key}\n"),
                format!("wandb.login(key=\"{key}\")\n"),
                format!("machine api.wandb.ai\n  login user\n  password {key}\n"),
                format!("export WANDB_BASE=local-{key}\n"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn a_host_label_under_a_credential_name_leaves_no_part_of_the_key_in_clear() {
        let key = key(77, 4);
        let input = format!("WANDB_API_KEY=local-{key}\n");
        let (text, findings) = whole_input(&input);
        assert!(!findings.is_empty(), "{input}");
        assert!(!text.contains(&key), "{input}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.action() == Action::Redact),
            "{findings:?}"
        );
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 77, 5);
        let base = format!("wandb_v1_{body}");
        let mut dashed = body.clone();
        dashed.replace_range(30..31, "-");
        assert_twins_unclaimed(
            DETECTOR,
            &[
                key(63, 5),
                key(97, 5),
                format!("wandb_v1_{dashed}"),
                format!("WANDB_V1_{body}"),
                format!("wandb_v2_{body}"),
                format!("wandb-v1-{body}"),
                format!("x{base}"),
                format!("_{base}"),
                format!("{base}-1"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "WANDB_API_KEY=wandb_v1_...\n".to_owned(),
            format!("KEY = \"{}\"\n", key(35, 6)),
            "commit 0123456789abcdef0123456789abcdef01234567\n".to_owned(),
            "WANDB_API_KEY=${WANDB_API_KEY}\n".to_owned(),
            "def wandb_version_1_migration(): pass\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key(77, 7));
    }
}

mod daytona {
    use super::*;

    const DETECTOR: &str = "daytona-api-key";
    const TYPE: &str = "daytona_api_key";

    fn key(seed: usize) -> String {
        format!("dtn_{}", filler(LOWER_HEX, 64, seed))
    }

    #[test]
    fn the_exact_shape_wins_every_context_as_the_sole_finding() {
        for key in [key(1), key(2), format!("dtn_{}", "5e7c0ded".repeat(8))] {
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("DAYTONA_API_KEY={key}\n"),
                format!("daytona = Daytona(DaytonaConfig(api_key=\"{key}\"))\n"),
                format!("const daytona = new Daytona({{ apiKey: '{key}' }});\n"),
                format!("variable \"daytona_api_key\" {{\n  default = \"{key}\"\n}}\n"),
                format!(
                    "curl -H \"Authorization: Bearer {key}\" https://app.daytona.io/api/sandbox\n"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(LOWER_HEX, 64, 4);
        let upper = format!("{}A{}", &body[..30], &body[31..]);
        let non_hex = format!("{}g{}", &body[..30], &body[31..]);
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("dtn_{}", &body[..63]),
                format!("dtn_{body}0"),
                format!("dtn_{upper}"),
                format!("dtn_{non_hex}"),
                format!("dtn_{body}A"),
                format!("dtn_{body}g"),
                format!("DTN_{body}"),
                format!("dtn-{body}"),
                format!("xdtn_{body}"),
                format!("_dtn_{body}"),
                format!("dtn_{body}_"),
                format!("dtn_{body}-1"),
            ],
        );
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        let digest = filler(LOWER_HEX, 64, 5);
        for input in [
            "DAYTONA_API_KEY=dtn_***\n".to_owned(),
            "DAYTONA_API_KEY=dtn_...\n".to_owned(),
            "DAYTONA_API_KEY=dtn_1234567890\n".to_owned(),
            "secret: dtn_secret_SyntheticRevokedPlaceholder\n".to_owned(),
            "stdout marker dtn_artifact_SyntheticRevokedMarker\n".to_owned(),
            "DAYTONA_API_KEY=${{ secrets.DAYTONA_API_KEY }}\n".to_owned(),
            "the prefix is dtn_\n".to_owned(),
            format!("sha256: {digest}\n"),
            format!("DAYTONA_RUNNER_KEY={digest}\n"),
            format!("{digest}\n"),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_daytona_jwt_stays_with_the_jwt_detector() {
        let jwt = "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE";
        for input in [
            format!("DAYTONA_JWT_TOKEN={jwt}\n"),
            format!("Authorization: Bearer {jwt}\n"),
        ] {
            let (_, findings) = whole_input(&input);
            assert!(!findings.is_empty(), "{input}");
            assert!(
                detector_findings(&findings, DETECTOR).is_empty(),
                "{findings:?}"
            );
        }
    }

    #[test]
    fn other_hex_keys_are_not_claimed_and_a_key_draws_no_other_provider() {
        let other_hex = "5e7c0ded".repeat(8);
        for input in [
            format!("signkey-test-{other_hex}\n"),
            format!("INNGEST_SIGNING_KEY=signkey-prod-{other_hex}\n"),
            format!("sk-{other_hex}\n"),
            format!("fc-{}\n", "0123456789ab4def8123456789abcdef"),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
        // A key beside another provider's key: two findings, each its own.
        let daytona = key(6);
        let inngest = format!("signkey-test-{other_hex}");
        let input = format!("{daytona} {inngest}\n");
        let (_, findings) = whole_input(&input);
        assert_eq!(
            detector_findings(&findings, DETECTOR).len(),
            1,
            "{findings:?}"
        );
        assert_eq!(
            detector_findings(&findings, "inngest-signing-key").len(),
            1,
            "{findings:?}"
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        for input in [
            "dtn_".repeat(20_000),
            format!("dtn_{}", "5e7c0ded".repeat(2_500)),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
        let key = key(7);
        let line = format!("{key} ").repeat(200);
        let (text, findings) = whole_input(&line);
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 200);
        assert_eq!(findings.len(), 200, "{findings:?}");
        assert!(!text.contains(&key));
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key(8));
    }
}

mod clickhouse_cloud {
    use super::*;

    const DETECTOR: &str = "clickhouse-cloud-api-secret";
    const TYPE: &str = "clickhouse_cloud_api_secret";

    fn secret(seed: usize) -> String {
        format!("4b1d{}", filler(ALNUM, 38, seed))
    }

    #[test]
    fn the_exact_shape_wins_every_context_as_the_sole_finding() {
        for secret in [
            secret(1),
            secret(2),
            format!("4b1d{}", "SyntheticRevokedClickhouseSecret000000"),
        ] {
            assert_sole_provider_finding(DETECTOR, TYPE, &secret);
            for input in [
                format!("CLICKHOUSE_CLOUD_API_SECRET={secret}\n"),
                format!(
                    "resource \"clickhouse_service\" \"s\" {{\n  token_secret = \"{secret}\"\n}}\n"
                ),
                format!("provider \"clickhouse\" {{\n  token_secret = \"{secret}\"\n}}\n"),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &secret);
            }
        }
    }

    /// The provider type wins the secret's span over the connection-string
    /// password and authorization-credential candidates it overlaps, and the
    /// key ID beside it is not claimed as a provider secret.
    #[test]
    fn the_provider_type_wins_the_secret_span_in_basic_auth_forms() {
        let secret = secret(3);
        for input in [
            format!("curl --user $KEY_ID:{secret} https://api.clickhouse.cloud/v1/organizations\n"),
            format!("curl -u KEYID:{secret} https://api.clickhouse.cloud/v1/organizations\n"),
            format!("curl https://KEYID:{secret}@api.clickhouse.cloud/v1/organizations\n"),
            format!("CLICKHOUSE_CLOUD_API_URL=https://KEYID:{secret}@api.clickhouse.cloud\n"),
            format!("Authorization: Bearer {secret}\n"),
        ] {
            let (text, findings) = whole_input(&input);
            let start = input.find(&secret).unwrap();
            let span = (start, start + secret.len());
            let covering: Vec<&Finding> = findings
                .iter()
                .filter(|f| f.range().start() < span.1 && span.0 < f.range().end())
                .collect();
            assert_eq!(covering.len(), 1, "{input}: {findings:?}");
            assert_eq!(covering[0].detector(), DETECTOR, "{input}");
            assert_eq!(covering[0].type_name(), TYPE, "{input}");
            assert_eq!(covering[0].action(), Action::Redact, "{input}");
            assert_eq!(
                (covering[0].range().start(), covering[0].range().end()),
                span,
                "{input}"
            );
            assert!(!text.contains(&secret), "{input}");
        }
    }

    #[test]
    fn twins_are_unclaimed() {
        let body = filler(ALNUM, 38, 4);
        let lower = body.to_ascii_lowercase();
        let hex: String = body
            .bytes()
            .map(|byte| char::from(LOWER_HEX[usize::from(byte) % 16]))
            .collect();
        let dashed = format!("{}-{}", &body[..20], &body[21..]);
        assert_twins_unclaimed(
            DETECTOR,
            &[
                format!("4b1d{}", &body[..37]),
                format!("4b1d{body}a"),
                // The 39-byte knowledge-base shape: 35 bytes after the prefix.
                format!("4b1d{}", &body[..35]),
                format!("4b1d{lower}"),
                format!("4b1d{hex}"),
                format!("4b1d{dashed}"),
                format!("4B1D{body}"),
                format!("4b1c{body}"),
                format!("a4b1d{body}"),
                format!("_4b1d{body}"),
                format!("-4b1d{body}"),
                format!("4b1d{body}_"),
                format!("4b1d{body}-1"),
            ],
        );
    }

    #[test]
    fn hex_digests_uuids_and_placeholders_are_unclaimed() {
        let digest = "0123456789abcdef".repeat(4);
        let sha1 = format!("4b1d{}", &digest[..36]);
        let sha256 = format!("4b1d{}", &digest[..60]);
        let upper_sha256 = format!("4b1d{}", digest[..60].to_ascii_uppercase());
        assert_eq!((sha1.len(), sha256.len(), upper_sha256.len()), (40, 64, 64));
        for input in [
            format!("sha1: {sha1}\n"),
            format!("sha256: {sha256}\n"),
            format!("sha256: {upper_sha256}\n"),
            format!("{sha256}\n"),
            "id: 123e4567-4b1d-12d3-a456-426614174000\n".to_owned(),
            "id: 123e4567-e89b-4b1d-a456-426614174000\n".to_owned(),
            "urn:uuid:4b1d0000-0000-4000-8000-000000000000\n".to_owned(),
            "key_secret = \"mykeysecret\"\n".to_owned(),
            "key_id = \"mykeyid\"\n".to_owned(),
            "CLICKHOUSE_CLOUD_API_SECRET=${CLICKHOUSE_CLOUD_API_SECRET}\n".to_owned(),
            "the prefix is 4b1d\n".to_owned(),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn other_families_keys_are_not_claimed_and_a_secret_draws_no_other_provider() {
        // A Daytona key whose hex body embeds `4b1d` is one alphanumeric run,
        // so the leading boundary keeps ClickHouse out of it.
        let embedded = format!("dtn_{}4b1d{}", "0".repeat(20), "a".repeat(40));
        assert_eq!(embedded.len(), 68);
        let (_, findings) = whole_input(&format!("{embedded}\n"));
        assert!(
            detector_findings(&findings, DETECTOR).is_empty(),
            "{findings:?}"
        );
        assert_eq!(
            detector_findings(&findings, "daytona-api-key").len(),
            1,
            "{findings:?}"
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        // A ClickHouse secret beside a Daytona key: two findings, each its own.
        let daytona = format!("dtn_{}", "5e7c0ded".repeat(8));
        let (_, findings) = whole_input(&format!("{daytona} {}\n", secret(5)));
        assert_eq!(
            detector_findings(&findings, DETECTOR).len(),
            1,
            "{findings:?}"
        );
        assert_eq!(
            detector_findings(&findings, "daytona-api-key").len(),
            1,
            "{findings:?}"
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        for input in [
            "4b1d".repeat(20_000),
            format!("4b1d{}", "aB3".repeat(7_000)),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
        let secret = secret(6);
        let line = format!("{secret} ").repeat(200);
        let (text, findings) = whole_input(&line);
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 200);
        assert_eq!(findings.len(), 200, "{findings:?}");
        assert!(!text.contains(&secret));
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        let secret = secret(7);
        assert_partition_parity(&secret);
        assert_input_partition_parity(&format!(
            "curl --user $KEY_ID:{secret} https://api.clickhouse.cloud\n"
        ));
    }
}

mod nvidia {
    use super::*;

    const DETECTOR: &str = "nvidia-api-key";
    const TYPE: &str = "nvidia_api_key";

    /// `nvapi-` + a `len`-byte body over `[A-Za-z0-9_-]` that starts and
    /// ends alphanumeric.
    fn key(len: usize, seed: usize) -> String {
        let mut body = filler(ALNUM_DASH, len, seed).into_bytes();
        body[0] = b'N';
        body[len - 1] = b'z';
        format!("nvapi-{}", String::from_utf8(body).unwrap())
    }

    #[test]
    fn every_width_wins_every_context_as_the_sole_finding() {
        for (seed, len) in [60, 64, 70, 128].into_iter().enumerate() {
            let key = key(len, seed);
            assert_sole_provider_finding(DETECTOR, TYPE, &key);
            for input in [
                format!("NVIDIA_API_KEY={key}\n"),
                format!("NGC_API_KEY={key}\n"),
                format!("llm = ChatNVIDIA(api_key=\"{key}\")\n"),
                format!(
                    "client = OpenAI(base_url=\"https://integrate.api.nvidia.com/v1\", api_key=\"{key}\")\n"
                ),
                format!(
                    "curl -H \"Authorization: Bearer {key}\" https://integrate.api.nvidia.com/v1/models\n"
                ),
            ] {
                assert_sole_finding_in(&input, DETECTOR, TYPE, &key);
            }
        }
        assert!(key(64, 9).contains('_') || key(64, 9).contains('-'));
    }

    #[test]
    fn twins_are_unclaimed() {
        let base = key(64, 4);
        let body = &base["nvapi-".len()..];
        let dotted = format!("nvapi-{}.{}", &body[..30], &body[31..]);
        assert_twins_unclaimed(
            DETECTOR,
            &[
                key(59, 4),
                key(129, 4),
                dotted,
                format!("NVAPI-{body}"),
                format!("nvapi_{body}"),
                format!("xnvapi-{body}"),
                format!("_nvapi-{body}"),
                format!("-nvapi-{body}"),
            ],
        );
    }

    #[test]
    fn a_dot_after_the_floor_ends_the_run_and_leaves_the_tail() {
        let key = key(64, 5);
        assert_sole_finding_in(&format!("{key}.tail\n"), DETECTOR, TYPE, &key);
    }

    #[test]
    fn benign_siblings_are_unclaimed() {
        for input in [
            "NVIDIA_API_KEY=nvapi-...\n".to_owned(),
            "NVIDIA_API_KEY=nvapi-xxxx\n".to_owned(),
            "NVIDIA_API_KEY=nvapi-<your-key>\n".to_owned(),
            "use the nvapi-sys crate and the nvapi-rs bindings\n".to_owned(),
            "the prefix is nvapi-\n".to_owned(),
            "NVIDIA_API_KEY=${{ secrets.NVIDIA_API_KEY }}\n".to_owned(),
            format!("token: nvsk-{}\n", filler(ALNUM_DASH, 64, 6)),
            // The legacy prefixless 84-character NGC key is not a provider
            // shape and stays with generic context.
            format!("NGC_API_KEY={}\n", filler(ALNUM, 84, 7)),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
    }

    #[test]
    fn a_jwt_and_other_providers_keys_are_not_claimed_and_each_key_keeps_its_own_finding() {
        let jwt = "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE";
        assert_unclaimed(DETECTOR, &format!("NVIDIA_API_KEY={jwt}\n"));
        let nvidia = key(64, 8);
        let daytona = format!("dtn_{}", "5e7c0ded".repeat(8));
        let (_, findings) = whole_input(&format!("{daytona} {nvidia}\n"));
        assert_eq!(
            detector_findings(&findings, DETECTOR).len(),
            1,
            "{findings:?}"
        );
        assert_eq!(
            detector_findings(&findings, "daytona-api-key").len(),
            1,
            "{findings:?}"
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert_unclaimed(DETECTOR, &format!("{daytona}\n"));
    }

    #[test]
    fn a_repetition_line_stays_bounded_and_exact() {
        for input in [
            "nvapi-".repeat(20_000),
            format!("nvapi-{}", "aB3_-".repeat(4_000)),
        ] {
            assert_unclaimed(DETECTOR, &input);
        }
        let key = key(64, 10);
        let line = format!("{key} ").repeat(200);
        let (text, findings) = whole_input(&line);
        assert_eq!(detector_findings(&findings, DETECTOR).len(), 200);
        assert_eq!(findings.len(), 200, "{findings:?}");
        assert!(!text.contains(&key));
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&key(64, 11));
    }
}
