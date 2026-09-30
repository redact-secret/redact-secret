//! Paddle Billing API key detection (issue #1033, handoff
//! `docs/audits/evidence/1014/paddle.md`).
//!
//! Paddle's "API keys" page publishes the whole grammar as a regex,
//! `^pdl_(live|sdbx)_apikey_[a-z\d]{26}_[a-zA-Z\d]{22}_[a-zA-Z\d]{3}$`, and
//! states that keys are 69 characters long with five underscores (T1 for
//! every part, re-checked 2026-09-29).
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `pdl_live_apikey_` or `pdl_sdbx_apikey_` | T1 |
//! | Id segment | exactly 26 `[a-z0-9]` | T1 |
//! | Secret segment | `_` + exactly 22 `[A-Za-z0-9]` | T1 |
//! | Suffix | `_` + exactly 3 `[A-Za-z0-9]` | T1 |
//!
//! Live and sandbox keys are one type: a sandbox key still reads and changes
//! sandbox data. The `apikey_` + 26 key id is a non-secret identifier
//! returned by the API and in webhooks; it is never claimed on its own, and
//! inside a key it is part of the one span. Legacy keys from before
//! 2025-05-06 (50 unprefixed `[a-z0-9]`) have no distinctive shape and stay
//! with generic context. Boundary `[A-Za-z0-9_-]`: a glued key is an
//! accepted false negative; no false positive is known for this layout.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const ID_LEN: usize = 26;
const SECRET_LEN: usize = 22;
const SUFFIX_LEN: usize = 3;
/// The three segments and the two `_` between them.
const BODY_LEN: usize = ID_LEN + 1 + SECRET_LEN + 1 + SUFFIX_LEN;
const SIGNALS: [&str; 1] = ["paddle-documented-regex"];

/// The documented segment layout after the prefix.
fn has_paddle_layout(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body = &bytes[end - BODY_LEN..end];
    let (id, rest) = body.split_at(ID_LEN);
    let (secret, suffix) = rest.split_at(1 + SECRET_LEN);
    id.iter().copied().all(pattern::is_lower_alnum)
        && secret[0] == b'_'
        && secret[1..].iter().all(u8::is_ascii_alphanumeric)
        && suffix[0] == b'_'
        && suffix[1..].iter().all(u8::is_ascii_alphanumeric)
}

pub(super) const PADDLE_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "paddle-api-key",
    "paddle_api_key",
    &[
        PrefixShape::exact(
            "pdl_live_apikey_",
            BODY_LEN,
            pattern::is_alnum_underscore,
            &SIGNALS,
        )
        .with_post_check(has_paddle_layout),
        PrefixShape::exact(
            "pdl_sdbx_apikey_",
            BODY_LEN,
            pattern::is_alnum_underscore,
            &SIGNALS,
        )
        .with_post_check(has_paddle_layout),
    ],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    /// Synthetic low-entropy filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    fn key_with(env: &str, id: usize, secret: usize, suffix: usize) -> String {
        format!(
            "pdl_{env}_apikey_{}_{}_{}",
            filler(LOWER_ALNUM, id, 1),
            filler(ALNUM, secret, 2),
            filler(ALNUM, suffix, 3)
        )
    }

    fn key(env: &str) -> String {
        key_with(env, ID_LEN, SECRET_LEN, SUFFIX_LEN)
    }

    fn detect(input: &str) -> Vec<Candidate> {
        PADDLE_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "paddle_api_key");
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
            format!("PADDLE_API_KEY={key}"),
            format!("export PADDLE_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("const paddle = new Paddle('{key}');"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn live_and_sandbox_keys_are_detected_in_every_context() {
        for env in ["live", "sdbx"] {
            let key = key(env);
            assert_eq!(key.len(), 69);
            assert_eq!(key.matches('_').count(), 5);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        assert_eq!(PADDLE_API_KEY.id(), "paddle-api-key");
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let good = key("sdbx");
        let mut upper_in_id = good.clone();
        upper_in_id.replace_range(20..21, "Q");
        for input in [
            key_with("sdbx", ID_LEN - 1, SECRET_LEN, SUFFIX_LEN),
            key_with("sdbx", ID_LEN + 1, SECRET_LEN, SUFFIX_LEN),
            key_with("sdbx", ID_LEN, SECRET_LEN - 1, SUFFIX_LEN),
            key_with("sdbx", ID_LEN, SECRET_LEN + 1, SUFFIX_LEN),
            key_with("sdbx", ID_LEN, SECRET_LEN, SUFFIX_LEN - 1),
            key_with("sdbx", ID_LEN, SECRET_LEN, SUFFIX_LEN + 1),
            key("test"),
            good.replacen("apikey_", "", 1),
            good.replacen("pdl_", "PDL_", 1),
            format!("{}-{}", &good[..42], &good[43..]),
            upper_in_id,
            format!("x{good}"),
            format!("_{good}"),
            format!("{good}x"),
            format!("{good}_x"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_paddle_text_is_not_claimed() {
        for input in [
            format!("{{\"id\": \"apikey_{}\"}}", filler(LOWER_ALNUM, ID_LEN, 1)),
            filler(LOWER_ALNUM, 50, 4),
            "PADDLE_API_KEY=${PADDLE_API_KEY}".to_owned(),
            r"^pdl_(live|sdbx)_apikey_[a-z\d]{26}_[a-zA-Z\d]{22}_[a-zA-Z\d]{3}$".to_owned(),
            "PADDLE_API_KEY=pdl_sdbx_apikey_...".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key("live");
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(100)).is_empty());
        assert!(detect(&"pdl_live_apikey_".repeat(2_000)).is_empty());
    }
}
