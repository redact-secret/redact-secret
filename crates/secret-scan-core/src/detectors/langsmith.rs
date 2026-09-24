//! `LangSmith` API key detection.
//!
//! ## Grammar (frozen before implementation, per #726 and #728)
//!
//! `lsv2_pt_` (personal access token) or `lsv2_sk_` (service key), then 32
//! lowercase hexadecimal bytes, a `_`, and 10 lowercase hexadecimal bytes --
//! 51 bytes total. The segment layout is tool-corroborated (an empirical,
//! T2 contract); `LangSmith`'s documentation establishes the roles and
//! contexts, not the lexical segments. Case-sensitive, always redacted,
//! `High` confidence with `Provider` specificity, bounded on both sides by a
//! byte outside `[A-Za-z0-9_-]` so a value glued to a wider identifier is
//! rejected rather than truncated.
//!
//! A body whose hexadecimal digits are one repeated character is a masked
//! placeholder and is excluded; the format has no checksum to reject one.
//!
//! ## Known unsupported variants
//!
//! The legacy `ls__` keys, license keys, SCIM and OAuth credentials,
//! deployment keys and the JWT-shaped `X-Service-Key` are separate secret
//! families that this grammar does not claim. They are not treated as
//! benign; a qualified assignment still reaches the generic-token path.
//! Workspace, organization and project IDs and endpoint URLs carry no
//! `lsv2_` prefix and never match.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIXES: [&str; 2] = ["lsv2_pt_", "lsv2_sk_"];
const SIGNALS: &[&str] = &[
    "langsmith-documented-role-prefix",
    "segmented-lowercase-hex-body",
];
const FIRST_SEGMENT_LEN: usize = 32;
const SECOND_SEGMENT_LEN: usize = 10;
const BODY_LEN: usize = FIRST_SEGMENT_LEN + 1 + SECOND_SEGMENT_LEN;

fn is_lower_hex_or_underscore(byte: u8) -> bool {
    pattern::is_lower_hex(byte) || byte == b'_'
}

fn boundary(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// `32 lowercase hex + '_' + 10 lowercase hex`, not one repeated digit.
fn segmented_body(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[end - BODY_LEN..end];
    let _ = start;
    if body[FIRST_SEGMENT_LEN] != b'_' {
        return false;
    }
    let (first, second) = (&body[..FIRST_SEGMENT_LEN], &body[FIRST_SEGMENT_LEN + 1..]);
    if !first
        .iter()
        .chain(second)
        .copied()
        .all(pattern::is_lower_hex)
    {
        return false;
    }
    !first.iter().chain(second).all(|&byte| byte == first[0])
}

/// Detects a `LangSmith` personal access token or service key.
pub(super) struct LangsmithApiKeyDetector;

impl Detector for LangsmithApiKeyDetector {
    fn id(&self) -> &'static str {
        "langsmith-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let shapes = PREFIXES.map(|prefix| {
            PrefixShape::exact(prefix, BODY_LEN, is_lower_hex_or_underscore, SIGNALS)
                .with_post_check(segmented_body)
        });
        let mut candidates = Vec::new();
        for (start, end, signals) in pattern::scan_prefixed_shapes(input, &shapes, boundary) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("langsmith_api_key", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locally constructed synthetic value; never provider-issued.
    const FIRST: &str = "0123456789abcdef0123456789abcdef";
    const SECOND: &str = "fedcba9876";

    fn key(prefix: &str) -> String {
        format!("{prefix}{FIRST}_{SECOND}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        LangsmithApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_both_roles_with_provider_specificity() {
        for prefix in PREFIXES {
            let value = key(prefix);
            let candidates = detect(&value);
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].type_name(), "langsmith_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, value.len()).unwrap()
            );
        }
    }

    #[test]
    fn rejects_a_wrong_segment_layout() {
        let short_second = &SECOND[..SECOND_SEGMENT_LEN - 1];
        assert!(detect(&format!("lsv2_pt_{FIRST}_{short_second}")).is_empty());
        assert!(detect(&format!("lsv2_pt_{FIRST}_{SECOND}a")).is_empty());
        assert!(detect(&format!("lsv2_pt_{FIRST}{SECOND}_")).is_empty());
        assert!(detect(&format!("lsv2_pt_{FIRST}-{SECOND}")).is_empty());
        assert!(detect(&format!("lsv2_pt_{}_{SECOND}", &FIRST[..31])).is_empty());
    }

    #[test]
    fn rejects_uppercase_and_non_hex_bodies() {
        assert!(detect(&format!("lsv2_pt_{}_{SECOND}", FIRST.to_uppercase())).is_empty());
        assert!(detect(&format!("lsv2_pt_{}g_{SECOND}", &FIRST[..31])).is_empty());
    }

    #[test]
    fn rejects_other_prefixes() {
        for prefix in ["lsv2_ak_", "lsv2_", "ls__", "lsv3_pt_", "LSV2_PT_"] {
            assert!(detect(&key(prefix)).is_empty());
        }
    }

    #[test]
    fn rejects_masked_placeholders() {
        let zeros = "0".repeat(FIRST_SEGMENT_LEN);
        let tail = "0".repeat(SECOND_SEGMENT_LEN);
        assert!(detect(&format!("lsv2_pt_{zeros}_{tail}")).is_empty());
        assert!(detect("lsv2_pt_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxx").is_empty());
        assert!(detect("lsv2_pt_${LANGSMITH_API_KEY}").is_empty());
    }

    #[test]
    fn rejects_a_wider_identifier() {
        let value = key("lsv2_pt_");
        assert!(detect(&format!("x{value}")).is_empty());
        assert!(detect(&format!("{value}_backup")).is_empty());
        assert!(detect(&format!("{value}-1")).is_empty());
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = key("lsv2_sk_");
        let candidates = detect(&format!("({value})."));
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn stays_bounded_over_near_miss_prefixes() {
        let input = format!("lsv2_pt_{FIRST}_{} ", &SECOND[..9]).repeat(10_000);
        assert!(detect(&input).is_empty());
    }
}
