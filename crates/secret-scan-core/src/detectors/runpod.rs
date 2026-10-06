//! `RunPod` API key detection (issue #974, handoff
//! [`docs/audits/evidence/860/runpod.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/860/runpod.md)).
//!
//! The `RunPod` blog on scoped keys (2024-11) states that new keys carry an
//! `rpa_` prefix, and a provider-authored scrubber in `runpod/runpod-mcp`
//! (`src/alp/scrub.ts`, 2026-09-16, ruling R2) is `\brpa_[A-Za-z0-9]{16,}\b`.
//! A floor of 16 would claim Redirect.pizza's `rpa_` + 30 tokens, so ruling
//! R10 lets project policy fill the grammar: the alphabet stays the
//! provider's `[A-Za-z0-9]` and the floor rises to 31, the first width above
//! that other issuer's shape. Every `RunPod` width seen (46 empirical, a
//! withdrawn 48-character docs example) is above it; the 46-byte and
//! 40-uppercase-plus-6-mixed layout is a tool fact and not part of the
//! contract.
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `rpa_` | T1 (provider blog and scrubber) |
//! | Body | at least 31 `[A-Za-z0-9]` | alphabet T1 (R2); floor is policy (R10) |
//! | Upper bound | 128 | project policy: a bounded run for streaming |
//!
//! The body alphabet is narrower than the `[A-Za-z0-9_-]` boundary, so a `_`
//! or `-` glued after the run rejects the match, and `rpa_` word fixtures
//! with `_` stay unclaimed. A body over 128 bytes is rejected whole, never
//! truncated. `rpa_` + 16 to 30 is an accepted false negative (no `RunPod`
//! key of that width is known). `rps_` S3 secrets and unprefixed legacy keys
//! are other shapes, so `runpod` is not added to `generic-token`'s
//! dedicated-provider deferral list, which would silence them under
//! `RUNPOD_*` names. A Redirect.pizza token of 31 or more bytes would be
//! reported as `RunPod`: misattributed, still redacted.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "rpa_";
const BODY_MIN: usize = 31;
const BODY_MAX: usize = 128;
const SIGNALS: [&str; 2] = ["runpod-documented-prefix", "runpod-policy-floor"];

/// The open-ended run is capped at [`BODY_MAX`].
fn within_body_cap(_bytes: &[u8], start: usize, end: usize) -> bool {
    end - start - PREFIX.len() <= BODY_MAX
}

pub(super) const RUNPOD_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "runpod-api-key",
    "runpod_api_key",
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
        RUNPOD_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "runpod_api_key");
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
            format!("RUNPOD_API_KEY={key}"),
            format!("export RUNPOD_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("runpod.api_key = \"{key}\""),
            format!("runpodctl config --apiKey {key}"),
            format!(
                "{{\"mcpServers\":{{\"runpod\":{{\"env\":{{\"RUNPOD_API_KEY\":\"{key}\"}}}}}}}}"
            ),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn keys_are_detected_at_every_width_in_every_context() {
        for len in [BODY_MIN, 46, BODY_MAX] {
            let key = key(len);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        // The observed 46-byte layout is not part of the contract, and
        // neither is its absence.
        let layout = format!("{PREFIX}{}{}", "ABCDEFGHIJ".repeat(4), body(6, 3));
        for input in contexts(&layout) {
            assert_single(&input, &layout);
        }
        assert_eq!(RUNPOD_API_KEY.id(), "runpod-api-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(46, 1);
        for input in [
            key(BODY_MIN - 1),
            key(BODY_MAX + 1),
            format!("{PREFIX}{value}_x"),
            format!("{PREFIX}{value}-1"),
            format!("RPA_{value}"),
            format!("rpa-{value}"),
            format!("x{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
            format!("-{PREFIX}{value}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_runpod_text_is_not_claimed() {
        for input in [
            key(30),
            "RUNPOD_API_KEY=rpa_...".to_owned(),
            "RUNPOD_API_KEY=rpa_xxxx".to_owned(),
            "RUNPOD_API_KEY=rpa_your_key".to_owned(),
            "RUNPOD_API_KEY=rpa_your_runpod_api_key_goes_here_SyntheticRevoked".to_owned(),
            format!("AWS_SECRET_ACCESS_KEY=rps_{}", body(40, 2)),
            "RUNPOD_API_KEY=${{ secrets.RUNPOD_API_KEY }}".to_owned(),
            "the prefix is rpa_".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key(46);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&format!("{key}_{key}")).is_empty());
        assert!(detect(&PREFIX.repeat(20_000)).is_empty());
        assert!(detect(&format!("{PREFIX}{}", "aB3".repeat(7_000))).is_empty());
    }
}
