//! Weights & Biases `wandb_v1_` API key detection (issue #917, handoff
//! `docs/audits/evidence/860/wandb.md`).
//!
//! A W&B-authored test constant begins `wandb_v1_` (ruling R5). The docs say
//! W&B "now issues longer API keys (about 86 characters)", and the SDK and
//! Weave validator tests use 86-character keys. The SDK validator requires
//! the secret to fullmatch `[\w-]+`, and its error text says a key "may only
//! contain the letters A-Z, digits and underscores" (ruling R1).
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `wandb_v1_` | T1 (provider test constant) |
//! | Body | 64–96 `[A-Za-z0-9_]` (the documented example width is 77) | alphabet T1; width is a bounded tolerant range |
//!
//! **Tolerant width.** The docs state the length only as "about 86", so the
//! handoff's exact 77-byte body is widened to a bounded 64–96 range around
//! it (orchestrator decision on #917): the 9-byte prefix is itself specific,
//! and an exact width would turn any key that is not exactly 86 into a false
//! negative in the contexts generic detection misses. The floor stays far
//! above the 27-byte Key ID and the 44-character placeholder test constant,
//! and the cap bounds the run for streaming. Tighten after an issuance check
//! records the real width. The scanner-only 27/`_`/49 split is not required.
//!
//! **Boundaries.** The byte before the prefix must not be `[A-Za-z0-9_]`; a
//! `-` is allowed there, so a self-managed `<host>-wandb_v1_…` key is
//! claimed on the `wandb_v1_…` part and the public host label is left out.
//! After the body the next byte must not be `[A-Za-z0-9_-]`. A body outside
//! 64–96 is rejected whole, never truncated. The legacy 40-hex key has no
//! anchor and stays with generic context; `wandb` is therefore not added to
//! `generic-token`'s dedicated-provider deferral list.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "wandb_v1_";
const BODY_MIN: usize = 64;
const BODY_MAX: usize = 96;
const SIGNALS: [&str; 2] = ["wandb-fixture-prefix", "wandb-tolerant-length-band"];

/// The maximal body is at most [`BODY_MAX`] bytes and is not followed by a
/// `-`: the shared boundary check below deliberately admits `-` so that a
/// `<host>-` label may precede the prefix, so the trailing `-` is rejected
/// here instead.
fn within_band_and_not_dash_glued(bytes: &[u8], start: usize, end: usize) -> bool {
    end - start - PREFIX.len() <= BODY_MAX && bytes.get(end) != Some(&b'-')
}

pub(super) const WANDB_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "wandb-api-key",
    "wandb_api_key",
    &[
        PrefixShape::at_least(PREFIX, BODY_MIN, pattern::is_alnum_underscore, &SIGNALS)
            .with_post_check(within_band_and_not_dash_glued),
    ],
    pattern::is_alnum_underscore,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic filler over `[A-Za-z0-9]`, never provider-issued.
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
        WANDB_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "wandb_api_key");
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
            format!("WANDB_API_KEY={key}"),
            format!("export WANDB_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("wandb.login(key=\"{key}\")"),
            format!("machine api.wandb.ai\n  login user\n  password {key}\n"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
            format!("WANDB_API_KEY=local-{key}"),
        ]
    }

    #[test]
    fn keys_across_the_tolerant_band_are_detected_in_every_context() {
        for len in [BODY_MIN, 77, BODY_MAX] {
            let key = key(len);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        assert_eq!(WANDB_API_KEY.id(), "wandb-api-key");
    }

    #[test]
    fn inner_underscores_are_inside_the_span() {
        let value = body(77, 1);
        let split = format!("{PREFIX}{}_{}", &value[..27], &value[28..]);
        let doubled = format!(
            "{PREFIX}{}_{}_{}",
            &value[..20],
            &value[21..50],
            &value[51..]
        );
        for key in [split, doubled] {
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(77, 2);
        let mut dashed = value.clone();
        dashed.replace_range(30..31, "-");
        for input in [
            key(BODY_MIN - 1),
            key(BODY_MAX + 1),
            format!("{PREFIX}{dashed}"),
            format!("WANDB_V1_{value}"),
            format!("wandb_v2_{value}"),
            format!("wandb-v1-{value}"),
            format!("x{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
            format!("{PREFIX}{value}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_wandb_text_is_not_claimed() {
        for input in [
            "WANDB_API_KEY=wandb_v1_...".to_owned(),
            format!("KEY = \"{PREFIX}{}\"", body(35, 3)),
            format!("commit {}", "0123456789abcdef0123456789abcdef01234567"),
            "WANDB_API_KEY=${WANDB_API_KEY}".to_owned(),
            "def wandb_version_1_migration(): pass".to_owned(),
            format!("key id {PREFIX}{}", body(27, 4)),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key(77);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(200)).is_empty());
    }
}
