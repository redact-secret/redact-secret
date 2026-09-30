//! Issue #774: provider-documented placeholders stay benign.
//!
//! The benchmarks' placeholder controls found `Bearer tvly-YOUR_API_KEY` and
//! provider-named instructional placeholders (`YOUR_DEEPGRAM_API_KEY`,
//! `your-mistral-api-key`) flagged by `bearer-token` and `generic-token`, not
//! by the typed provider detectors. These tests pin the shared instructional
//! placeholder rule across the assignment, SDK-argument and header forms, and
//! that real-shaped values and one-word-off twins are still reported. Every
//! value is locally constructed and never issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{DefaultPolicy, DetectorRegistry, scan};

const MISTRAL: &str = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9xC2Lq";
const COHERE: &str = "zY9xW7vU5tS3rQ1pO9nM7lK5jI3hG1fEaB3dE5gH";
const DEEPGRAM: &str = "q7w3e9r1t5y8u2i4o6p0a1s3d5f7g9h2j4k6l8z0";
const TAVILY_BODY: &str = "SyntheticRevokedTavilyFixture014";

fn findings(input: &str) -> Vec<String> {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan(input, &registry, &DefaultPolicy)
        .unwrap()
        .iter()
        .map(|finding| finding.detector().to_owned())
        .collect()
}

#[test]
fn provider_documented_placeholders_are_benign() {
    for input in [
        "Authorization: Bearer tvly-YOUR_API_KEY",
        "curl -H \"Authorization: Bearer tvly-YOUR_API_KEY\"",
        "Authorization: Bearer sk-your-api-key-here",
        "TAVILY_API_KEY=tvly-YOUR_API_KEY",
        "MISTRAL_API_KEY=your-key-here",
        "MISTRAL_API_KEY=YOUR_MISTRAL_KEY",
        "MISTRAL_API_KEY=\"replace-with-your-key\"",
        "client = Mistral(api_key=\"your-mistral-api-key\")",
        "client = Mistral(api_key=\"YOUR_MISTRAL_API_KEY\")",
        "COHERE_API_KEY=YOUR_COHERE_API_KEY",
        "COHERE_API_KEY=your_cohere_key_here",
        "co = cohere.ClientV2(api_key=\"your-cohere-api-key\")",
        "CO_API_KEY=<YOUR_API_KEY>",
        "AI21_API_KEY=your_ai21_api_key",
        "DEEPGRAM_API_KEY=YOUR_DEEPGRAM_API_KEY",
        "DEEPGRAM_API_KEY=your_deepgram_api_key_here",
        "DEEPGRAM_API_KEY=\"replace-with-your-deepgram-key\"",
        "Authorization: Token YOUR_DEEPGRAM_API_KEY",
        "Authorization: Bearer your-mistral-api-key",
    ] {
        assert!(findings(input).is_empty(), "{input}: {:?}", findings(input));
    }
}

#[test]
fn real_shaped_values_are_still_reported_by_their_detector() {
    for (detector, input) in [
        (
            "tavily-api-key",
            format!("Authorization: Bearer tvly-{TAVILY_BODY}"),
        ),
        ("mistral-api-key", format!("MISTRAL_API_KEY={MISTRAL}")),
        ("cohere-api-key", format!("CO_API_KEY={COHERE}")),
        (
            "deepgram-api-key",
            format!("dg = DeepgramClient(api_key=\"{DEEPGRAM}\")"),
        ),
    ] {
        assert_eq!(findings(&input), [detector], "{input}");
    }
}

#[test]
fn a_placeholder_glued_to_random_material_or_an_unlisted_word_stays_detected() {
    for input in [
        "MISTRAL_API_KEY=YOUR_MISTRAL_API_KEY_9f2cQ7xLm4Rt".to_owned(),
        "Authorization: Bearer tvly-YOUR_API_KEY_9f2cQ7xLm4Rt".to_owned(),
        "Authorization: Bearer tvly-your-9f2cQ7xLm4RtVb8N".to_owned(),
        "API_KEY=YOUR_ACMECLOUD_API_KEY".to_owned(),
        format!("MISTRAL_API_KEY=your-{MISTRAL}"),
    ] {
        assert!(!findings(&input).is_empty(), "{input}");
    }
}

/// Issue #949: the Inngest and Resend handoffs' documentation placeholders.
#[test]
fn a_vendor_prefix_before_an_ascending_digit_run_or_a_glued_your_word_is_benign() {
    for input in [
        "const inngest = new Inngest({ id: \"test\", signingKey: \"signkey-test-12345\" });\n",
        "RESEND_API_KEY=re_123456789\n",
        "resend.api_key = \"re_yourkey\"\n",
        "RESEND_API_KEY=re_YourApiKeyHere\n",
        "INNGEST_SIGNING_KEY=signkey-prod-7890123\n",
        "INNGEST_SIGNING_KEY=signkey-prod-yoursigningkey\n",
        "curl -H \"Authorization: Bearer signkey-prod-<YOUR-SIGNING-KEY>\" https://api.inngest.com/v1/events\n",
        "Authorization: Bearer re_123456789\n",
    ] {
        assert!(findings(input).is_empty(), "{input}: {:?}", findings(input));
    }
}

/// Issue #949's twins: a digit body that is not a counting run, a glued word
/// with material left over, a too-short run, and a bare glued word with no
/// vendor prefix are still reported, so a weak real value is not hidden.
#[test]
fn non_counting_digits_and_glued_words_with_leftovers_stay_detected() {
    for input in [
        "RESEND_API_KEY=re_193847562\n",
        "signingKey: \"signkey-test-12346\"\n",
        "RESEND_API_KEY=re_yourkeyqz7\n",
        "RESEND_API_KEY=re_yourkeyq\n",
        "DB_PASSWORD=pw_yourdog1987\n",
        "RESEND_API_KEY=yourkeyxq2Lm9Pz\n",
    ] {
        assert!(!findings(input).is_empty(), "{input}");
    }
    // A real-shaped Resend key keeps its provider finding.
    let body = "Zq3Lm9Pz";
    let tail = "Ab7Cd2Ef4Gh6Jk8Mn1Pq5Rs0";
    let input = format!("RESEND_API_KEY=re_{body}_{tail}\n");
    assert_eq!(findings(&input), ["resend-api-key"], "{input}");
}

/// Issue #1015: the Anthropic Admin prefix `sk-ant-admin01-` is 15 bytes, and
/// the vendor-placeholder rule used to strip only 12-byte prefixes, so its
/// documentation placeholders were redacted while the same bodies behind the
/// `sk-ant-api01-` / `sk-ant-api03-` siblings were silent. Parity only: a
/// well-formed admin key keeps its typed finding and an off-grammar,
/// non-placeholder body keeps the `generic-token` finding.
#[test]
fn anthropic_admin_placeholders_match_their_sibling_prefixes() {
    for prefix in ["sk-ant-admin01-", "sk-ant-api01-", "sk-ant-api03-"] {
        for body in ["<your-key>", "YOUR_KEY", "..."] {
            for input in [
                format!("curl -H \"x-api-key: {prefix}{body}\""),
                format!(
                    "curl -s https://api.anthropic.com/v1/organizations/api_keys -H \"x-api-key: {prefix}{body}\""
                ),
                format!("ANTHROPIC_ADMIN_KEY={prefix}{body}"),
                format!("api_key={prefix}{body}"),
            ] {
                assert!(
                    findings(&input).is_empty(),
                    "{input}: {:?}",
                    findings(&input)
                );
            }
        }
    }
}

#[test]
fn a_real_shaped_or_off_grammar_admin_value_is_still_reported() {
    // 93 body bytes plus the `AA` tail, built from low-entropy filler.
    let body = format!("{}AA", "Ab3".repeat(31));
    let input = format!("curl -H \"x-api-key: sk-ant-admin01-{body}\"");
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let found = scan(&input, &registry, &DefaultPolicy).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].type_name(), "anthropic_admin_api_key");
    assert_eq!(found[0].action(), redact_secret::Action::Redact);

    // Not a placeholder and not the admin grammar: `generic-token` keeps it.
    let off_grammar = format!("sk-ant-admin01-{}", "Ab3Cd4".repeat(3));
    for input in [
        format!("curl -H \"x-api-key: {off_grammar}\""),
        format!("api_key={off_grammar}"),
    ] {
        assert_eq!(findings(&input), ["generic-token"], "{input}");
    }
}

/// Issue #1041: a hyphenated phrase led by a distinctive placeholder word is
/// a placeholder like the single word, under every credential name,
/// including the bare `secret_access_key` that #1026 made high-signal.
#[test]
fn a_placeholder_led_phrase_is_benign_under_every_credential_name() {
    for input in [
        "[object_store]\nsecret_access_key = \"placeholder-not-a-key\"\n",
        "api_key = \"placeholder-not-a-key\"\n",
        "api_key = \"placeholder-value\"\n",
        "password: 'example-token'\n",
        "AWS_SECRET_ACCESS_KEY=sample_secret_access_key\n",
        "client_secret = \"REDACTED-NOT-A-REAL-SECRET\"\n",
    ] {
        assert!(findings(input).is_empty(), "{input}: {:?}", findings(input));
    }
}

/// Issue #1041's twins: a phrase with a digit, an unlisted word, or a lead
/// word that also opens real weak passwords (`secret`, `password`) is still
/// reported, and so is a real-shaped value behind a placeholder word.
#[test]
fn placeholder_phrases_with_material_or_an_unlisted_word_stay_detected() {
    for input in [
        "secret_access_key = \"placeholder-not-a-key7\"\n",
        "api_key = \"placeholder-hunter-horse\"\n",
        "api_key = \"secret-not-a-key\"\n",
        "api_key = \"password-value\"\n",
        "api_key = \"placeholder-Zq3Lm9PzAb7Cd2Ef4Gh6\"\n",
    ] {
        assert!(!findings(input).is_empty(), "{input}");
    }
}

/// Issue #1042: the placeholder controls the #860/#1013 evidence and the
/// benchmarks' T3 policy list as placeholders, each built at run time.
#[test]
fn listed_provider_placeholders_are_benign() {
    let x = |n: usize| "x".repeat(n);
    let bitwarden = format!(
        "0.{}-{}-{}-{}-{}.{}:{}==",
        x(8),
        x(4),
        x(4),
        x(4),
        x(12),
        x(30),
        x(22)
    );
    for input in [
        format!("VERCEL_TOKEN=vcp_{}\n", x(24)),
        format!("VERCEL_TOKEN=vca_{}\n", x(24)),
        format!("VERCEL_TOKEN=vcr_{}\n", x(24)),
        format!("Paste vcp_{} into the dashboard.\n", x(56)),
        "RUNPOD_API_KEY=rpa_your_key_for_ci_pipeline_test_fixture_only\n".to_owned(),
        "PADDLE_API_KEY=pdl_sdbx_apikey_...\n".to_owned(),
        "PADDLE_API_KEY=pdl_live_apikey_\u{2026}\n".to_owned(),
        format!("export BWS_ACCESS_TOKEN=\"{bitwarden}\"\n"),
        "KEY_ID=mykeyid\nKEY_SECRET=mykeysecret\ncurl --user $KEY_ID:$KEY_SECRET https://api.clickhouse.cloud/v1/organizations\n".to_owned(),
    ] {
        assert!(findings(&input).is_empty(), "{input}: {:?}", findings(&input));
    }
}

/// Issue #1042's twins: one leftover character, a digit, a mixed-case word,
/// a head that shows key material, and a single glued word stay reported.
#[test]
fn near_placeholder_twins_stay_detected() {
    let x = |n: usize| "x".repeat(n);
    for input in [
        format!("VERCEL_TOKEN=vcp_{}y\n", x(23)),
        format!("VERCEL_TOKEN=vcp_{}\n", "Zq3Lm9PzAb7Cd2Ef4Gh6Jk8M"),
        "RUNPOD_API_KEY=rpa_your_key_for_ci_pipeline_7\n".to_owned(),
        "RUNPOD_API_KEY=rpa_yourKey_for_ci_pipeline\n".to_owned(),
        "RUNPOD_API_KEY=rpa_Zq3Lm9Pz_Ab7Cd2Ef4Gh6Jk8Mn1Pq5Rs\n".to_owned(),
        "PADDLE_API_KEY=pdl_sdbx_apikey_01hq7zyx9...\n".to_owned(),
        "PADDLE_API_KEY=pdl_sdbx_apikey_Zq3Lm9PzAb...\n".to_owned(),
        format!(
            "export BWS_ACCESS_TOKEN=\"0.{}-{}:{}y==\"\n",
            x(8),
            x(4),
            x(21)
        ),
        "KEY_SECRET=mykeysecret7q\n".to_owned(),
        "KEY_SECRET=mysecretkeyZ\n".to_owned(),
    ] {
        assert!(!findings(&input).is_empty(), "{input}");
    }
}
