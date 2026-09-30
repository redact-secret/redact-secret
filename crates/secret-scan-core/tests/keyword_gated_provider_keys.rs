//! Issue #868: keyword-gated contextual coverage for Mistral, Cohere, AI21
//! and Deepgram keys, driven through the public default pipeline.
//!
//! No provider documents the shapes, so this pins a contextual, unqualified
//! (T2-at-best) contract: exact-span findings only under provider context,
//! one finding per span (no double report with `generic-token`), and silence
//! for bare values. Every value is locally constructed and never issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{ByteRange, DefaultPolicy, DetectorRegistry, scan};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

const MISTRAL: &str = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9xC2Lq";
const COHERE: &str = "zY9xW7vU5tS3rQ1pO9nM7lK5jI3hG1fEaB3dE5gH";
const AI21: &str = "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp";
const DEEPGRAM: &str = "q7w3e9r1t5y8u2i4o6p0a1s3d5f7g9h2j4k6l8z0";

/// (detector, type, value, positive input).
fn positives() -> Vec<(&'static str, &'static str, &'static str, String)> {
    vec![
        (
            "mistral-api-key",
            "mistral_api_key",
            MISTRAL,
            format!("MISTRAL_API_KEY={MISTRAL}"),
        ),
        (
            "mistral-api-key",
            "mistral_api_key",
            MISTRAL,
            format!("client = Mistral(api_key=\"{MISTRAL}\")"),
        ),
        (
            "cohere-api-key",
            "cohere_api_key",
            COHERE,
            format!("CO_API_KEY={COHERE}"),
        ),
        (
            "cohere-api-key",
            "cohere_api_key",
            COHERE,
            format!("co = cohere.ClientV2(api_key=\"{COHERE}\")"),
        ),
        (
            "ai21-api-key",
            "ai21_api_key",
            AI21,
            format!("AI21_API_KEY={AI21}"),
        ),
        (
            "ai21-api-key",
            "ai21_api_key",
            AI21,
            format!("client = AI21Client(api_key='{AI21}')"),
        ),
        (
            "deepgram-api-key",
            "deepgram_api_key",
            DEEPGRAM,
            format!("DEEPGRAM_API_KEY={DEEPGRAM}"),
        ),
        (
            "deepgram-api-key",
            "deepgram_api_key",
            DEEPGRAM,
            format!("dg = DeepgramClient(api_key=\"{DEEPGRAM}\")"),
        ),
        (
            "deepgram-api-key",
            "deepgram_api_key",
            DEEPGRAM,
            format!(
                "curl -H 'Authorization: Token {DEEPGRAM}' https://api.deepgram.com/v1/projects"
            ),
        ),
    ]
}

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

#[test]
fn every_gated_positive_is_one_exact_span_finding_from_the_provider_detector() {
    let registry = registry();
    for (detector, type_name, value, input) in positives() {
        let findings = scan(&input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings.len(), 1, "{input}: {findings:?}");
        let start = input.find(value).unwrap();
        assert_eq!(findings[0].detector(), detector, "{input}");
        assert_eq!(findings[0].type_name(), type_name, "{input}");
        assert_eq!(
            findings[0].range(),
            ByteRange::new(start, start + value.len()).unwrap(),
            "{input}"
        );
    }
}

#[test]
fn bare_values_and_provider_free_call_arguments_are_not_reported() {
    let registry = registry();
    for input in [
        MISTRAL.to_owned(),
        COHERE.to_owned(),
        DEEPGRAM.to_owned(),
        format!("checksum {MISTRAL}"),
        format!("Mistral(model=\"{MISTRAL}\")"),
        format!("cohere.ClientV2(base_url=\"{COHERE}\")"),
        format!("dg = DeepgramClient(\"{}\")", "x".repeat(40)),
        format!("session_id={AI21}"),
    ] {
        let findings = scan(&input, &registry, &DefaultPolicy).unwrap();
        assert!(findings.is_empty(), "{input}: {findings:?}");
    }
}

/// Exa (#787) has no evidenced shape, so its SDK call stays with the generic
/// path (#866) and no `exa` detector exists.
#[test]
fn exa_has_no_provider_detector() {
    let registry = registry();
    assert!(registry.ids().all(|id| !id.contains("exa")));
}

#[test]
fn every_byte_partition_reproduces_the_whole_input_result() {
    for (_, _, _, input) in positives() {
        let (expected_text, expected_findings) = whole_input(&input);
        for pieces in utf8_byte_partitions(&input) {
            let session = run(&as_chunks(&pieces));
            assert_eq!(session.text(), expected_text, "{input}: {pieces:?}");
            assert_eq!(
                session.findings().len(),
                expected_findings.len(),
                "{input}: {pieces:?}"
            );
        }
    }
}

/// Issue #1018: a complete, unmasked Cohere key logged under `LiteLLM`'s
/// `masked_api_key=` beside a `cohere/<model>` route is `cohere_api_key` /
/// redact; the masked display of the same field stays silent, and the plain
/// `api_key=` form keeps its generic finding. The value is built at run time
/// from low-entropy filler.
#[test]
fn an_unmasked_key_under_a_litellm_masked_field_is_redacted() {
    let registry = registry();
    let key = "aB3dE5gH7j".repeat(4);
    let line = format!(
        "18:22:04 - LiteLLM Proxy:DEBUG: router.py:1841 - cohere/command-r-plus call failed; masked_api_key={key} reason=AuthenticationError"
    );
    let findings = scan(&line, &registry, &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].type_name(), "cohere_api_key");
    assert_eq!(findings[0].range(), ByteRange::new(99, 139).unwrap());
    assert_eq!(findings[0].action(), redact_secret::Action::Redact);
    for pieces in utf8_byte_partitions(&line) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), whole_input(&line).0, "{pieces:?}");
    }

    let plain = format!("cohere call failed; api_key={key}");
    let findings = scan(&plain, &registry, &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].action(), redact_secret::Action::Redact);

    let masked = format!(
        "cohere call failed; masked_api_key={}{}{}",
        &key[..4],
        "*".repeat(32),
        &key[36..]
    );
    assert!(scan(&masked, &registry, &DefaultPolicy).unwrap().is_empty());
}
