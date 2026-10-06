//! Resend API key detection (issue #915, handoff
//! [`docs/audits/evidence/860/resend.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/resend.md)).
//!
//! The provider CLI rejects a key that does not start with `re_` (T1,
//! provider code and README). The create-API-key response example on
//! resend.com and three distinct provider-authored SDK test values all have
//! the layout `re_` + 8 + `_` + 24 (ruling R5 gives provider test fixtures
//! the weight of a docs example; re-checked 2026-09-28).
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `re_` | T1 |
//! | Segments | 8 `[A-Za-z0-9]`, `_`, 24 `[A-Za-z0-9]` (36 in total) | T1 by example |
//! | Guard | at least one uppercase and one lowercase letter in the 32 segment bytes | project policy |
//!
//! The alphabet is the alphanumeric superset of the examples' base58-looking
//! values: three samples prove what is present, not what is excluded (the
//! #655 precedent), and the exact 8/`_`/24 layout does the discriminating.
//!
//! `re_` is short and ends many identifiers (`are_`, `pre_`, `score_`) and
//! Python `re_` names, so the byte before it must not be `[A-Za-z0-9_-]`,
//! and the mixed-case guard (the Tier A Composio `ak_` guard) removes every
//! all-lowercase or all-uppercase snake/camel identifier of that layout. For
//! a uniform random body the guard costs about 6e-8 of real keys. A
//! mixed-case identifier of exactly that layout stays an accepted false
//! positive.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "re_";
const FIRST_SEGMENT: usize = 8;
const SECOND_SEGMENT: usize = 24;
/// Both segments plus the `_` between them.
const BODY_LEN: usize = FIRST_SEGMENT + 1 + SECOND_SEGMENT;
const SIGNALS: [&str; 2] = ["resend-cli-enforced-prefix", "resend-example-layout"];

/// The `_` sits exactly between the two segments, no other `_` appears,
/// and the segments carry both letter cases.
fn has_resend_layout(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body = &bytes[end - BODY_LEN..end];
    let (first, rest) = body.split_at(FIRST_SEGMENT);
    let Some((&b'_', second)) = rest.split_first() else {
        return false;
    };
    let segments = || first.iter().chain(second);
    segments().all(u8::is_ascii_alphanumeric)
        && segments().any(u8::is_ascii_uppercase)
        && segments().any(u8::is_ascii_lowercase)
}

pub(super) const RESEND_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "resend-api-key",
    "resend_api_key",
    &[
        PrefixShape::exact(PREFIX, BODY_LEN, pattern::is_alnum_underscore, &SIGNALS)
            .with_post_check(has_resend_layout),
    ],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic mixed-case filler, never provider-issued.
    fn segment(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()]))
            .collect()
    }

    fn key() -> String {
        format!(
            "{PREFIX}{}_{}",
            segment(FIRST_SEGMENT, 1),
            segment(SECOND_SEGMENT, 2)
        )
    }

    fn detect(input: &str) -> Vec<Candidate> {
        RESEND_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "resend_api_key");
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
            format!("RESEND_API_KEY={key}"),
            format!("export RESEND_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("const resend = new Resend(\"{key}\");"),
            format!("resend.api_key = \"{key}\""),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn the_documented_layout_is_detected_in_every_context() {
        let key = key();
        assert_eq!(key.len(), 36);
        for input in contexts(&key) {
            assert_single(&input, &key);
        }
        assert_eq!(RESEND_API_KEY.id(), "resend-api-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let first = segment(FIRST_SEGMENT, 1);
        let second = segment(SECOND_SEGMENT, 2);
        let mut underscored = second.clone();
        underscored.replace_range(10..11, "_");
        let key = key();
        for input in [
            format!("{PREFIX}{}_{second}", segment(7, 1)),
            format!("{PREFIX}{}_{second}", segment(9, 1)),
            format!("{PREFIX}{first}_{}", segment(23, 2)),
            format!("{PREFIX}{first}_{}", segment(25, 2)),
            format!("{PREFIX}{first}-{second}"),
            format!("{PREFIX}{first}_{underscored}"),
            format!("{PREFIX}{}_{}", first.to_lowercase(), second.to_lowercase()),
            format!("{PREFIX}{}_{}", first.to_uppercase(), second.to_uppercase()),
            format!("RE_{first}_{second}"),
            format!("a{key}"),
            format!("_{key}"),
            format!("{key}x"),
            format!("{key}_x"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_resend_text_is_not_claimed() {
        for input in [
            "RESEND_API_KEY=re_123456789",
            "RESEND_API_KEY=re_123",
            "RESEND_API_KEY=re_xxxxxxxxx",
            "RESEND_API_KEY=re_...",
            "RESEND_API_KEY=re_*********",
            "RESEND_API_KEY=${RESEND_API_KEY}",
            "pattern = re_compile(r'\\d+')",
            "re_pattern_cache = {}",
            "re_validate_all_inputs_nowplease_ok",
            "pre_process_all_inputs_now",
            "RESEND_WEBHOOK_SECRET=whsec_SyntheticRevokedWebhookSecret00",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key();
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(200)).is_empty());
    }
}
