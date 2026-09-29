//! Browserbase API key detection (issue #973, handoff
//! `docs/audits/evidence/860/browserbase.md`).
//!
//! The provider's own CI gate accepts `bb_live_` followed by at least 20
//! alphanumerics (provider-authored, ruling R2), and no provider source
//! states an exact width, so the contract uses that open-ended rule and adds
//! a cap as project policy, following the Apify precedent.
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `bb_live_` | T1 (provider docs and code) |
//! | Body | at least 20 `[A-Za-z0-9]` | T1 floor (provider CI gate, R2) |
//! | Upper bound | 128 | project policy: a bounded run for streaming |
//!
//! The body alphabet is narrower than the `[A-Za-z0-9_-]` boundary, so a `_`
//! or `-` glued after the run rejects the match: that is what keeps
//! `bb_live_session_...` identifiers and `bb_live_your_api_key_here`
//! placeholders unclaimed. A body over 128 bytes is rejected whole, never
//! truncated. `bb_test_` keys (still issuance-gated), `bb_<timestamp>`
//! cookie names and project-ID UUIDs are not this shape, and `browserbase`
//! is not added to `generic-token`'s dedicated-provider deferral list, so a
//! `bb_test_` key under `BROWSERBASE_API_KEY` keeps its contextual finding.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "bb_live_";
const BODY_MIN: usize = 20;
const BODY_MAX: usize = 128;
const SIGNALS: [&str; 2] = [
    "browserbase-documented-prefix",
    "browserbase-provider-gate-floor",
];

/// The open-ended run is capped at [`BODY_MAX`].
fn within_body_cap(_bytes: &[u8], start: usize, end: usize) -> bool {
    end - start - PREFIX.len() <= BODY_MAX
}

pub(super) const BROWSERBASE_API_KEY: KnownFormatProviderDetector =
    KnownFormatProviderDetector::new(
        "browserbase-api-key",
        "browserbase_api_key",
        &[
            PrefixShape::at_least(PREFIX, BODY_MIN, pattern::is_alnum, &SIGNALS)
                .with_post_check(within_body_cap),
        ],
        pattern::is_alnum_dash,
    );

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic alphanumeric filler, never provider-issued.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()]))
            .collect()
    }

    fn key(len: usize) -> String {
        format!("{PREFIX}{}", body(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        BROWSERBASE_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "browserbase_api_key");
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
            format!("BROWSERBASE_API_KEY={key}"),
            format!("export BROWSERBASE_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("X-BB-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("bb = Browserbase(api_key=\"{key}\")"),
            format!("const stagehand = new Stagehand({{ apiKey: \"{key}\" }});"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn keys_are_detected_at_every_width_in_every_context() {
        for len in [BODY_MIN, 32, BODY_MAX] {
            let key = key(len);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        assert_eq!(BROWSERBASE_API_KEY.id(), "browserbase-api-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(32, 1);
        for input in [
            key(BODY_MIN - 1),
            key(BODY_MAX + 1),
            format!("{PREFIX}{value}_x"),
            format!("{PREFIX}{value}-1"),
            format!("BB_LIVE_{value}"),
            format!("bb-live-{value}"),
            format!("x{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
            format!("-{PREFIX}{value}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_browserbase_text_is_not_claimed() {
        let value = body(32, 2);
        for input in [
            format!("BROWSERBASE_API_KEY=bb_test_{value}"),
            "BROWSERBASE_API_KEY=bb_live_...".to_owned(),
            "BROWSERBASE_API_KEY=bb_live_your_api_key_here".to_owned(),
            "session id bb_live_session_SyntheticRevokedIdentifier01".to_owned(),
            "cookie bb_1727612345 was set".to_owned(),
            "project 123e4567-e89b-42d3-a456-426614174000".to_owned(),
            "BROWSERBASE_API_KEY=${{ secrets.BROWSERBASE_API_KEY }}".to_owned(),
            "the prefix is bb_live_".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key(32);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&format!("{key}_{key}")).is_empty());
        assert!(detect(&PREFIX.repeat(20_000)).is_empty());
        assert!(detect(&format!("{PREFIX}{}", "aB3".repeat(7_000))).is_empty());
    }
}
