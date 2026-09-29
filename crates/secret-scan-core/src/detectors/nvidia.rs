//! NVIDIA API key detection (issue #972, handoff
//! `docs/audits/evidence/860/nvidia.md`).
//!
//! NVIDIA documents that keys "typically start with nvapi-", and the `ngcsdk`
//! CLI constant `SCOPED_KEY_PREFIX = "nvapi-"` has an executing `startswith`
//! (rulings R1 and R6). A provider-authored secret-scanning rule in
//! `NVIDIA-NeMo/nemo-helix` (`pii_scan.py`, 2026-05-21, ruling R2) is
//! `\bnvapi-[A-Za-z0-9_\-]{60,}\b`. No provider source states an exact
//! width, so the contract uses that open-ended rule and adds a cap as project
//! policy, following the Apify precedent.
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `nvapi-` | T1 (provider docs and CLI constant) |
//! | Body | at least 60 `[A-Za-z0-9_-]` | T1 floor (provider-authored rule, R2) |
//! | Upper bound | 128 | project policy: a bounded run for streaming |
//!
//! The body alphabet is the same as the `[A-Za-z0-9_-]` boundary, so the
//! scan takes the whole maximal run and the run is rejected, never
//! truncated, when it is under 60 or over 128 bytes. A `.` is outside the
//! alphabet: a `.` inside the first 60 body bytes leaves both halves under
//! the floor, while a `.` after the 60th byte ends the run the way sentence
//! punctuation does.
//!
//! Left unclaimed: `nvapi-` + fewer than 60 bytes (the NVAPI SDK and crate
//! names and short fixtures), `nvapi-...`/`nvapi-xxxx` placeholders, and the
//! legacy prefixless 84-character NGC key (the `$oauthtoken` registry
//! password), which generic context covers under `NGC_API_KEY`. Neither
//! `nvidia` nor `ngc` is added to `generic-token`'s dedicated-provider
//! deferral list, because deferral would silence that legacy key.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "nvapi-";
const BODY_MIN: usize = 60;
const BODY_MAX: usize = 128;
const SIGNALS: [&str; 2] = ["nvidia-documented-prefix", "nvidia-provider-rule-floor"];

/// The open-ended run is capped at [`BODY_MAX`].
fn within_body_cap(_bytes: &[u8], start: usize, end: usize) -> bool {
    end - start - PREFIX.len() <= BODY_MAX
}

pub(super) const NVIDIA_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "nvidia-api-key",
    "nvidia_api_key",
    &[
        PrefixShape::at_least(PREFIX, BODY_MIN, pattern::is_alnum_dash, &SIGNALS)
            .with_post_check(within_body_cap),
    ],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic filler over `[A-Za-z0-9_-]`, never provider-issued. The
    /// first and last bytes are alphanumeric so a glued run stays visible.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
        let mut body: Vec<u8> = (0..len)
            .map(|i| ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()])
            .collect();
        body[0] = b'N';
        body[len - 1] = b'z';
        String::from_utf8(body).unwrap()
    }

    fn key(len: usize) -> String {
        format!("{PREFIX}{}", body(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        NVIDIA_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(key).unwrap();
        assert_eq!(candidates[0].type_name(), "nvidia_api_key");
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
            format!("NVIDIA_API_KEY={key}"),
            format!("NGC_API_KEY={key}"),
            format!("export NVIDIA_API_KEY=\"{key}\""),
            format!("Authorization: Bearer {key}"),
            format!("X-API-Key: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("{{\"api_key\": \"{key}\"}}"),
            format!("llm = ChatNVIDIA(api_key=\"{key}\")"),
            format!(
                "client = OpenAI(base_url=\"https://integrate.api.nvidia.com/v1\", api_key=\"{key}\")"
            ),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ]
    }

    #[test]
    fn keys_are_detected_at_every_width_in_every_context() {
        for len in [BODY_MIN, 64, 70, BODY_MAX] {
            let key = key(len);
            for input in contexts(&key) {
                assert_single(&input, &key);
            }
        }
        assert_eq!(NVIDIA_API_KEY.id(), "nvidia-api-key");
    }

    #[test]
    fn a_body_with_underscores_and_dashes_is_one_span() {
        let value = body(64, 3);
        assert!(value.contains('_') && value.contains('-'));
        let key = format!("{PREFIX}{value}");
        for input in contexts(&key) {
            assert_single(&input, &key);
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(64, 1);
        let dotted = format!("{}.{}", &value[..30], &value[31..]);
        for input in [
            key(BODY_MIN - 1),
            key(BODY_MAX + 1),
            format!("{PREFIX}{dotted}"),
            format!("NVAPI-{value}"),
            format!("nvapi_{value}"),
            format!("x{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
            format!("-{PREFIX}{value}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_dot_after_the_floor_ends_the_run_like_punctuation() {
        let key = key(64);
        let input = format!("{key}.tail");
        assert_single(&input, &key);
    }

    #[test]
    fn benign_nvidia_text_is_not_claimed() {
        for input in [
            "NVIDIA_API_KEY=nvapi-...",
            "NVIDIA_API_KEY=nvapi-xxxx",
            "NVIDIA_API_KEY=nvapi-<your-key>",
            "NVIDIA_API_KEY=nvapi-YOUR_KEY_HERE",
            "use the nvapi-sys crate and nvapi-rs bindings",
            "cargo add nvapi-sys",
            "the prefix is nvapi-",
            "NVIDIA_API_KEY=${{ secrets.NVIDIA_API_KEY }}",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // The legacy prefixless 84-character key is not a provider shape.
        assert!(detect(&format!("NGC_API_KEY={}", body(84, 2))).is_empty());
        // A 64-byte run under a different prefix.
        assert!(detect(&format!("nvsk-{}", body(64, 2))).is_empty());
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key(64);
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&PREFIX.repeat(20_000)).is_empty());
        assert!(detect(&format!("{PREFIX}{}", "aB3_-".repeat(4_000))).is_empty());
    }
}
