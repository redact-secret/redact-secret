//! Inngest signing key detection (issue #914, handoff
//! [`docs/audits/evidence/860/inngest.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/inngest.md)).
//!
//! inngest/inngest provider code (`pkg/authn/signing_key_strategy.go` at
//! `dabb03f`) defines the three prefixes `signkey-prod-`, `signkey-test-`
//! and `signkey-branch-`. The SDKs strip `^signkey-\w+-` and hex-decode the
//! rest, and the self-hosting docs generate the key with
//! `openssl rand -hex 32`: 64 lowercase hex characters, also the width of
//! every realistic SDK test fixture (ruling R5, re-checked 2026-09-28).
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `signkey-prod-`, `signkey-test-`, `signkey-branch-` | T1 (provider code constants) |
//! | Body | exactly 64 lowercase hex `[0-9a-f]` | T1 (docs generation command + SDK fixtures) |
//!
//! One finding type, `inngest_signing_key`, covers the raw key, the rotation
//! fallback (`INNGEST_SIGNING_KEY_FALLBACK`) and the hashed wire form the SDK
//! sends as `Authorization: Bearer` (`signkey-<env>-` + SHA-256 hex of the
//! key): they are lexically identical and each authenticates. Before this a
//! prefixed key under `INNGEST_SIGNING_KEY=` was only a medium, warned
//! `contextual_secret` (`signing_key` is an ambiguous name); the provider
//! finding now wins that overlap and is redacted.
//!
//! Other environment labels, an uppercase-hex body, a body of 63 or 65, a
//! glued value and placeholders (`signkey-test-12345`,
//! `signkey-prod-<YOUR-SIGNING-KEY>`) are intentional false negatives, never
//! a truncated match. A self-hosted bare-hex key has no prefix and stays
//! with generic context; `inngest` is therefore not added to
//! `generic-token`'s dedicated-provider deferral list.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 64;
const SIGNALS: [&str; 2] = ["inngest-code-constant-prefix", "inngest-hex-body-length"];

pub(super) const INNGEST_SIGNING_KEY: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "inngest-signing-key",
        "inngest_signing_key",
        &[
            PrefixShape::exact("signkey-prod-", BODY_LEN, pattern::is_lower_hex, &SIGNALS),
            PrefixShape::exact("signkey-test-", BODY_LEN, pattern::is_lower_hex, &SIGNALS),
            PrefixShape::exact("signkey-branch-", BODY_LEN, pattern::is_lower_hex, &SIGNALS),
        ],
        pattern::is_alnum_dash,
    );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic lowercase hex, never provider-issued.
    fn hex(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(b"0123456789abcdef"[(i * 7 + seed * 5 + i / 3) % 16]))
            .collect()
    }

    fn key(label: &str) -> String {
        format!("signkey-{label}-{}", hex(BODY_LEN, label.len()))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        INNGEST_SIGNING_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "inngest_signing_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(key: &str) -> Vec<String> {
        vec![
            key.to_owned(),
            format!("INNGEST_SIGNING_KEY={key}"),
            format!("INNGEST_SIGNING_KEY_FALLBACK={key}"),
            format!("export INNGEST_SIGNING_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("curl -H \"Authorization: Bearer {key}\" https://example.invalid/v1/events"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("new Inngest({{ id: \"app\", signingKey: \"{key}\" }});"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn every_label_is_detected_in_every_context() {
        for label in ["prod", "test", "branch"] {
            let key = key(label);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        assert_eq!(INNGEST_SIGNING_KEY.id(), "inngest-signing-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let body = hex(BODY_LEN, 1);
        let mut upper = body.clone();
        upper.replace_range(30..31, "A");
        let mut non_hex = body.clone();
        non_hex.replace_range(30..31, "g");
        for input in [
            format!("signkey-prod-{}", hex(BODY_LEN - 1, 1)),
            format!("signkey-prod-{}", hex(BODY_LEN + 1, 1)),
            format!("signkey-prod-{upper}"),
            format!("signkey-prod-{non_hex}"),
            format!("signkey-preview-{body}"),
            format!("signkey_prod_{body}"),
            format!("SIGNKEY-prod-{body}"),
            format!("xsignkey-prod-{body}"),
            format!("_signkey-prod-{body}"),
            format!("signkey-prod-{body}x"),
            format!("signkey-prod-{body}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_inngest_text_is_not_claimed() {
        for input in [
            "INNGEST_SIGNING_KEY=signkey-prod-<YOUR-SIGNING-KEY>".to_owned(),
            "signingKey: \"signkey-test-12345\"".to_owned(),
            "INNGEST_SIGNING_KEY=signkey-prod-000000".to_owned(),
            "INNGEST_SIGNING_KEY=${INNGEST_SIGNING_KEY}".to_owned(),
            format!("sha256 {}", hex(BODY_LEN, 2)),
            "INNGEST_EVENT_KEY=local".to_owned(),
            "eventKey: NO_EVENT_KEY_SET".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key("prod");
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(200)).is_empty());
    }
}
