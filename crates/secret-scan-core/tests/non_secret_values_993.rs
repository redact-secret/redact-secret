//! Issue #993 through the public API with the full default registry: the
//! documentation placeholders, masked and elided key displays, Make-escaped
//! command substitutions, documented public keys and the Confluent public
//! key id that a credential-named assignment used to report. #948 made them
//! reachable under provider names too. Each is silent under a generic name
//! and under a provider name, and every real-shaped neighbour (random
//! material, a secret key prefix, a longer visible head) stays reported.
//!
//! Every value is synthetic and built at run time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// A 32-byte mixed-case alphanumeric body that no provider grammar claims.
fn random(len: usize) -> String {
    (0..len)
        .map(|i| char::from(b"q7Wm2XbK9vRt4LcN8zPd3HsF6gJy5TkA"[(i * 13 + 5) % 32]))
        .collect()
}

fn mask(ch: char, len: usize) -> String {
    std::iter::repeat_n(ch, len).collect()
}

/// `name=value` under a generic and a provider name, dotenv and quoted.
fn under_names(names: &[&str], value: &str) -> Vec<String> {
    names
        .iter()
        .flat_map(|name| {
            [
                format!("{name}={value}\n"),
                format!("export {name}=\"{value}\"\n"),
            ]
        })
        .collect()
}

fn assert_silent(names: &[&str], values: &[String]) {
    for value in values {
        for input in under_names(names, value) {
            let (_, findings) = whole_input(&input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
    }
}

fn assert_reported(names: &[&str], values: &[String]) {
    for value in values {
        for input in under_names(names, value) {
            // A short value is reported at medium (warn), so only the
            // finding itself is asserted, not the redacted text.
            let (_, findings) = whole_input(&input);
            assert_eq!(findings.len(), 1, "{input}: {findings:?}");
        }
    }
}

const TOKEN_NAMES: &[&str] = &["MYAPP_TOKEN", "DISCORD_TOKEN", "TRAVIS_API_TOKEN"];
const KEY_NAMES: &[&str] = &["MYAPP_API_KEY", "MAILGUN_API_KEY", "POSTMAN_API_KEY"];
const SECRET_NAMES: &[&str] = &[
    "MYAPP_SECRET",
    "STRIPE_WEBHOOK_SECRET",
    "SUPABASE_SECRET_KEY",
];

#[test]
fn placeholders_with_qualifier_and_provider_words_are_silent() {
    let values = [
        "your-bot-token-here",
        "YOUR_SIGNING_SECRET",
        "whsec_YOUR_SIGNING_SECRET",
        "ntn_yourinternalintegrationtokenhere",
        "YOUR_MAILGUN_API_KEY",
        "your-travis-api-token",
        "your-webhook-signing-secret",
        "PMAK-<your-api-key>",
    ]
    .map(str::to_owned);
    assert_silent(TOKEN_NAMES, &values);
    assert_silent(KEY_NAMES, &values);
}

#[test]
fn a_placeholder_one_word_off_or_glued_to_material_stays_reported() {
    let values = [
        // A provider on neither list.
        "YOUR_ACMECLOUD_API_KEY".to_owned(),
        // Random material after listed words.
        format!("your-bot-token-{}", random(16)),
        format!("YOUR_SIGNING_SECRET_{}", random(12)),
        format!("whsec_YOUR_SIGNING_SECRET{}", random(8)),
        // A leftover letter in the glued form.
        "ntn_yourinternalintegrationtokenherex".to_owned(),
        // An uppercase prefix before an instructional word chain, not `<...>`.
        "KEY_YOUR_API_KEY".to_owned(),
        // `<...>` with material after it.
        format!("PMAK-<your-api-key>{}", random(16)),
    ];
    assert_reported(KEY_NAMES, &values);
}

#[test]
fn counting_run_bodies_behind_a_vendor_prefix_are_silent() {
    let values = [
        "ghp_abc123",
        "glpat-abc123",
        "npm_abc123",
        "xoxb-123-456-abc",
    ]
    .map(str::to_owned);
    assert_silent(&["MYAPP_TOKEN", "GITHUB_TOKEN", "SLACK_TOKEN"], &values);
}

#[test]
fn a_near_counting_body_or_random_body_stays_reported() {
    let values = [
        "ghp_abd123".to_owned(),
        "ghp_abc124".to_owned(),
        "xoxb-123-457-abd".to_owned(),
        // A full-length counting body is a synthetic key, not a stand-in.
        "key-abcdefghijklmnopqrstuvwxyz012345".to_owned(),
        format!("ghp_{}", random(36)),
        format!("glpat-{}", random(20)),
    ];
    assert_reported(&["MYAPP_TOKEN", "GITHUB_TOKEN"], &values);
}

#[test]
fn masked_key_displays_are_silent() {
    let star = |len| mask('*', len);
    let bullet = |len| mask('\u{2022}', len);
    let values = [
        format!(
            "{}-{}-{}-{}-{}",
            star(8),
            star(4),
            star(4),
            star(4),
            star(12)
        ),
        format!("PMAK-{}-{}", star(24), star(34)),
        format!("00{}", bullet(40)),
        format!("3518930973:AA{}", star(33)),
        format!("ATATT3xFfGF0{}={}", star(180), star(8)),
        format!("{}-us6", star(32)),
        format!("{}-usX", mask('x', 32)),
    ];
    assert_silent(KEY_NAMES, &values);
    assert_silent(TOKEN_NAMES, &values);
}

#[test]
fn a_mask_near_miss_stays_reported() {
    let star = |len| mask('*', len);
    let values = [
        // A short mask is a password echo, not a key display (#264).
        format!("{}x{}", random(4), star(8)),
        // A visible head longer than twelve characters.
        format!("{}{}", random(20), star(40)),
        // Visible material between two mask runs.
        format!("gsk_{}{}{}", star(20), random(6), star(20)),
        // A mixed mask.
        format!("{}{}", star(10), mask('\u{2022}', 10)),
        // A tail longer than a region label.
        format!("{}-{}", star(32), random(12)),
    ];
    assert_reported(KEY_NAMES, &values);
}

#[test]
fn ellipsis_truncated_displays_are_silent_and_longer_heads_are_not() {
    let values = ["ATATT3xFfGF0...", "sntrys_eyJ...", "sk-proj-\u{2026}"].map(str::to_owned);
    assert_silent(
        &["MYAPP_API_TOKEN", "JIRA_API_TOKEN", "SENTRY_AUTH_TOKEN"],
        &values,
    );
    let reported = [
        format!("{}...", random(24)),
        format!("ATATT3xFfGF0...{}", random(16)),
    ];
    assert_reported(&["MYAPP_API_TOKEN", "JIRA_API_TOKEN"], &reported);
}

#[test]
fn make_escaped_command_substitutions_are_silent() {
    for input in [
        "deploy:\n\tHEROKU_API_KEY=$$(heroku auth:token) ./scripts/release.sh\n",
        "deploy:\n\tMYAPP_API_KEY=$$(pass show myapp/api) ./scripts/release.sh\n",
        "deploy:\n\tMYAPP_API_KEY=$${MYAPP_API_KEY_FROM_VAULT} ./run\n",
        "deploy:\n\tMYAPP_API_KEY=$$MYAPP_API_KEY_FROM_VAULT ./run\n",
    ] {
        let (_, findings) = whole_input(input);
        assert!(findings.is_empty(), "{input}: {findings:?}");
    }
    // A single `$(` without its closing parenthesis stays detected, as
    // before #993.
    let input = format!("MYAPP_API_KEY=$({}", random(24));
    assert_eq!(whole_input(&input).1.len(), 1, "{input}");
}

#[test]
fn documented_public_keys_are_silent_and_secret_keys_are_not() {
    let body = random(32);
    let public: Vec<String> = [
        "pk_live_",
        "pk_test_",
        "sb_publishable_",
        "pk-lf-",
        "phc_",
        "pk_prod_",
    ]
    .iter()
    .map(|prefix| format!("{prefix}{body}"))
    .collect();
    assert_silent(SECRET_NAMES, &public);
    // A secret-key prefix of the same providers, or a public prefix glued
    // inside a longer value, is still reported under the generic name.
    let secret: Vec<String> = ["xpk_live_", "pk_livex", "sk-lf-"]
        .iter()
        .map(|prefix| format!("{prefix}{body}"))
        .collect();
    assert_reported(&["MYAPP_SECRET"], &secret);
}

#[test]
fn a_confluent_key_id_is_silent_only_under_a_confluent_name() {
    let id = "ABCD1234567890AB";
    for input in [
        format!("CONFLUENT_CLOUD_API_KEY={id}\n"),
        format!("confluent.cloud.api_key: {id}\n"),
        format!("{{\"confluentApiKey\": \"{id}\"}}"),
    ] {
        let (_, findings) = whole_input(&input);
        assert!(findings.is_empty(), "{input}: {findings:?}");
    }
    // The same shape under another name, and a longer or lowercase value
    // under the Confluent name, stay reported.
    for input in [
        format!("KAFKA_API_KEY={id}\n"),
        format!("CONFLUENT_CLOUD_API_KEY={id}CD\n"),
        format!("CONFLUENT_CLOUD_API_KEY={}\n", random(16)),
    ] {
        let (_, findings) = whole_input(&input);
        assert_eq!(findings.len(), 1, "{input}: {findings:?}");
    }
}

/// The secret half on the next line keeps its typed finding, and the id
/// half is no longer redacted beside it.
#[test]
fn a_confluent_pair_redacts_only_the_secret_half() {
    let input = "CONFLUENT_CLOUD_API_KEY=ABCD1234567890AB\n\
                 CONFLUENT_CLOUD_API_SECRET=cfltXW9PNjmquDmIrhVGD1Zs+AogFIKX+/JiNS4Xa0Dd5OHMfsIz5Xxx7pGOhO2g\n";
    let (text, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].detector(), "confluent-cloud-api-secret");
    assert!(text.contains("ABCD1234567890AB"));
}

#[test]
fn whole_input_and_incremental_sessions_agree() {
    for input in [
        "DISCORD_TOKEN=your-bot-token-here\nGITHUB_TOKEN=ghp_abc123\n".to_owned(),
        format!(
            "HEROKU_API_KEY={}\n",
            "********-****-****-****-************"
        ),
        "deploy:\n\tHEROKU_API_KEY=$$(heroku auth:token) ./scripts/release.sh\n".to_owned(),
        format!(
            "STRIPE_API_KEY: pk_live_{}\nSTRIPE_SECRET_KEY: {}\n",
            random(24),
            random(32)
        ),
    ] {
        let (expected_text, expected) = whole_input(&input);
        for pieces in utf8_byte_partitions(&input) {
            let session = run(&as_chunks(&pieces));
            assert_eq!(session.text(), expected_text, "{pieces:?}");
            let got = session.findings();
            assert_eq!(got.len(), expected.len(), "{pieces:?}");
            for (got, want) in got.iter().zip(&expected) {
                assert_eq!(got.range(), want.range(), "{pieces:?}");
                assert_eq!(got.detector(), want.detector(), "{pieces:?}");
            }
        }
    }
}
