//! Neon API key detection (issue #524).
//!
//! ## Evidence
//!
//! - **Prefix, provider-stated (T1).** Neon's changelog for 2025-01-31
//!   (`neon.com/docs/changelog/2025-01-31`, source
//!   `neondatabase/website` `content/changelog/2025-01-31.md`, observed
//!   2026-09-24) states: "Newly created Neon API keys are now prefixed with
//!   `napi_`. This change improves security by making it possible to use
//!   secret scanning mechanisms that rely on identifiable markers." Existing
//!   unprefixed keys stay valid.
//! - **Body, tool-corroborated (T2).** Neon states no length or alphabet.
//!   Its API-keys page calls a key "a randomly-generated 64-bit token", and
//!   its one written example (`napi_examplekey...`) is a word and two ordered
//!   runs, not a shape. betterleaks' `neon-api-key` rule reads
//!   `napi_[A-Za-z0-9]{64}` exactly, and mask-go's `neon-api-key` pattern
//!   reads the same alphabet with 64 as a floor. GitHub secret scanning
//!   lists the credential as partner pattern `neon_api_key` without
//!   publishing the expression. Neither pinned peer (gitleaks 8.30.1,
//!   trufflehog 3.97.4) has a Neon rule.
//!
//! ## Grammar
//!
//! `napi_` followed by at least 64 [`pattern::is_alnum`] bytes, read to the
//! end of the run, so a longer future body is redacted whole rather than
//! truncated. A run touching `_` or `-` on either side is part of a wider
//! identifier and is rejected. A body that is one repeated character
//! (`napi_000...`) is a placeholder. Detection is bare and high confidence:
//! the `napi_` prefix was introduced for secret scanning, and a 64-byte
//! random body after it is not an ordinary word.
//!
//! ## Scope
//!
//! - Personal, organization and project-scoped API keys share this one
//!   shape, so they share one finding type.
//! - Legacy unprefixed Neon API keys have no marker and are out of scope.
//! - A Neon Postgres connection URI's password
//!   (`postgresql://user:<password>@ep-...neon.tech/db`) stays with
//!   `connection-string`, which already reports the password span. A
//!   `napi_` key never sits in that position, so the two never report the
//!   same span.
//!
//! ## Trade-offs
//!
//! - **False negatives.** A key whose body is shorter than 64 bytes is missed
//!   entirely. The 64-byte floor rests on one scanner's rule and one
//!   library's pattern, not on a Neon statement. An unprefixed legacy key is
//!   missed as well.
//! - **False positives.** Any `napi_` + 64 alphanumeric run is reported,
//!   whether Neon issued it or not. That is the intended reading of a
//!   secret-scanning prefix.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "napi_";

/// The two-source body floor (betterleaks exact, mask-go floor).
const MIN_BODY_LEN: usize = 64;

const SIGNALS: [&str; 2] = ["neon-documented-prefix", "tool-corroborated-body-floor"];

/// `[A-Za-z0-9_-]`: a key is never a slice of a wider identifier.
fn is_boundary_byte(byte: u8) -> bool {
    pattern::is_alnum(byte) || matches!(byte, b'_' | b'-')
}

/// Rejects a body that is one repeated character, a placeholder.
fn body_is_not_filler(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[start + PREFIX.len()..end];
    body.iter().any(|&byte| byte != body[0])
}

/// The `neon-api-key` detector; see the module doc.
pub(super) const NEON: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "neon-api-key",
    "neon_api_key",
    &[
        PrefixShape::at_least(PREFIX, MIN_BODY_LEN, pattern::is_alnum, &SIGNALS)
            .with_post_check(body_is_not_filler),
    ],
    is_boundary_byte,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Exactly [`MIN_BODY_LEN`] bytes. Locally constructed synthetic value;
    /// never issued by Neon.
    const BODY: &str = "SyntheticRevokedNeonApiKey0000Fixture1111Body2222Padding33334444";
    const _: () = assert!(BODY.len() == MIN_BODY_LEN);

    fn key() -> String {
        format!("{PREFIX}{BODY}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        NEON.detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_key_at(input: &str, key: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        assert_eq!(candidates[0].type_name(), "neon_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.find(key).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key.len()).unwrap(),
            "{input}"
        );
    }

    #[test]
    fn detects_a_bare_key_and_a_key_in_common_contexts() {
        let key = key();
        for input in [
            key.clone(),
            format!("NEON_API_KEY={key}"),
            format!("{{\"apiKey\": \"{key}\"}}"),
            format!("Authorization: Bearer {key}"),
            format!("neonctl projects list --api-key {key}"),
        ] {
            assert_key_at(&input, &key);
        }
    }

    #[test]
    fn a_longer_body_is_read_to_the_end_of_its_run() {
        let key = format!("{}9Z", key());
        assert_key_at(&format!("NEON_API_KEY={key}"), &key);
    }

    #[test]
    fn a_body_one_byte_short_of_the_floor_is_not_reported() {
        let short = format!("{PREFIX}{}", &BODY[..MIN_BODY_LEN - 1]);
        assert!(detect(&short).is_empty());
    }

    #[test]
    fn a_key_inside_a_wider_identifier_is_not_reported() {
        for input in [
            format!("x{}", key()),
            format!("x_{}", key()),
            format!("{}_x", key()),
            format!("{}-x", key()),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn filler_placeholders_and_the_bare_prefix_are_not_reported() {
        for input in [
            format!("{PREFIX}{}", "0".repeat(MIN_BODY_LEN)),
            format!("{PREFIX}{}", "x".repeat(MIN_BODY_LEN)),
            "NEON_API_KEY=napi_".to_owned(),
            "NEON_API_KEY=napi_short".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_non_alphanumeric_byte_ends_the_body() {
        let broken = format!("{PREFIX}{}!{}", &BODY[..32], &BODY[32..]);
        assert!(detect(&broken).is_empty());
    }
}
