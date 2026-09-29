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
