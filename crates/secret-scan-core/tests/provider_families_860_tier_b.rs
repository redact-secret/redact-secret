//! Issue #860 Tier B provider families (#912–#917) through the public API
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
