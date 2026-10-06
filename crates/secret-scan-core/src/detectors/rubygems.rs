//! `RubyGems.org` API key detection (issue #1023, handoff
//! [`docs/audits/evidence/1014/rubygems.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/rubygems.md)).
//!
//! The grammar is `rubygems_` + exactly 48 lowercase hex, all T1 under ruling
//! R1: rubygems.org's `generate_rubygems_key` returns
//! `"rubygems_#{SecureRandom.hex(24)}"` (`api_keyable.rb`, re-checked
//! 2026-09-29), and `SecureRandom.hex` emits lowercase hex. OIDC-exchanged
//! short-lived keys come from the same generator and are covered.
//!
//! Metadata keys such as `rubygems_version` and `rubygems_mfa_required`, the
//! `:rubygems_api_key:` YAML key and legacy unprefixed keys fail the exact
//! 48-lowercase-hex body. Boundary `[A-Za-z0-9_-]`: a 47- or 49-byte body,
//! an uppercase or non-hex byte, an uppercase prefix, a `rubygems-`
//! separator and a glued value are intentional false negatives.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const BODY_LEN: usize = 48;
const SIGNALS: [&str; 2] = ["rubygems-generator-prefix", "rubygems-generator-length"];

pub(super) const RUBYGEMS_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "rubygems-api-key",
    "rubygems_api_key",
    &[PrefixShape::exact(
        "rubygems_",
        BODY_LEN,
        pattern::is_lower_hex,
        &SIGNALS,
    )],
    pattern::is_alnum_dash,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Synthetic lowercase-hex filler, never provider-issued.
    fn hex(len: usize, seed: usize) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        (0..len)
            .map(|i| char::from(HEX[(i * 7 + seed * 3 + i / 5) % HEX.len()]))
            .collect()
    }

    fn key() -> String {
        format!("rubygems_{}", hex(BODY_LEN, 1))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        RUBYGEMS_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn the_generator_shape_is_detected_in_every_context() {
        let key = key();
        assert_eq!(key.len(), 57);
        for input in [
            key.clone(),
            format!("GEM_HOST_API_KEY={key}"),
            format!("---\n:rubygems_api_key: {key}\n"),
            format!("gem push pkg/demo-1.0.0.gem --key {key}"),
            format!("Authorization: {key}"),
            format!("{{\"token\": \"{key}\"}}"),
            format!("Here is my key {key} can you debug this?"),
            format!("The key is {key}."),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.find(&key).unwrap();
            assert_eq!(candidates[0].type_name(), "rubygems_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + key.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn near_miss_twins_and_metadata_keys_are_rejected() {
        let body = hex(BODY_LEN, 2);
        let key = format!("rubygems_{body}");
        let mut upper = body.clone();
        upper.replace_range(5..6, "A");
        let mut non_hex = body.clone();
        non_hex.replace_range(5..6, "g");
        for input in [
            format!("rubygems_{}", &body[..47]),
            format!("rubygems_{body}0"),
            format!("rubygems_{upper}"),
            format!("rubygems_{non_hex}"),
            format!("RUBYGEMS_{body}"),
            format!("rubygems-{body}"),
            format!("x{key}"),
            format!("{key}_"),
            format!("{key}-x"),
            "rubygems_version: 3.5.0".to_owned(),
            "rubygems_mfa_required: true".to_owned(),
            ":rubygems_api_key: YOUR_API_KEY".to_owned(),
            body.clone(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_keys_are_reported_once_each_and_a_glued_run_never() {
        let key = key();
        assert_eq!(detect(&format!("{key} {key}")).len(), 2);
        assert!(detect(&key.repeat(200)).is_empty());
    }
}
