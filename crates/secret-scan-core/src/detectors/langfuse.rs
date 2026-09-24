//! Langfuse secret key detection.
//!
//! ## Grammar (frozen before implementation, per #726 and #728)
//!
//! `sk-lf-` followed by a lowercase `UUIDv4` (`8-4-4-4-12` hexadecimal, version
//! nibble `4`, variant nibble `8`, `9`, `a` or `b`) -- 42 bytes total. This is
//! the shape Langfuse itself mints (an empirical, T2 contract: provider
//! documentation establishes the prefixes and roles, provider code the
//! minted shape). Always redacted, `High` confidence, `Provider` specificity,
//! bounded on both sides by a byte outside `[A-Za-z0-9_-]`.
//!
//! ## Separation from public and sibling values
//!
//! `pk-lf-` is the public key and carries a different prefix, so it never
//! matches. Requiring a valid `UUIDv4` body also keeps public-looking
//! identifiers, hosts, project/org/trace IDs and self-hosting placeholders
//! (`sk-lf-your-secret-key`) clean.
//!
//! ## Known unsupported variants
//!
//! Arbitrary self-hosted secret values (an operator may set any string) and
//! `sk-lf-gw-` gateway keys are outside the claim. Encoded Basic-auth blobs
//! are unclaimed.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &str = "sk-lf-";
const SIGNALS: &[&str] = &["langfuse-secret-prefix", "lowercase-uuid-v4-body"];
const UUID_LEN: usize = 36;

fn is_lower_hex_or_dash(byte: u8) -> bool {
    pattern::is_lower_hex(byte) || byte == b'-'
}

fn boundary(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// A lowercase RFC 4122 version-4 UUID at `end - 36..end`.
fn lowercase_uuid_v4(bytes: &[u8], _start: usize, end: usize) -> bool {
    let uuid = &bytes[end - UUID_LEN..end];
    uuid.iter().enumerate().all(|(index, &byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => pattern::is_lower_hex(byte),
    }) && uuid[14] == b'4'
        && matches!(uuid[19], b'8' | b'9' | b'a' | b'b')
}

/// Detects an issuer-minted Langfuse secret key.
pub(super) struct LangfuseSecretKeyDetector;

impl Detector for LangfuseSecretKeyDetector {
    fn id(&self) -> &'static str {
        "langfuse-secret-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let shapes = [
            PrefixShape::exact(PREFIX, UUID_LEN, is_lower_hex_or_dash, SIGNALS)
                .with_post_check(lowercase_uuid_v4),
        ];
        let mut candidates = Vec::new();
        for (start, end, signals) in pattern::scan_prefixed_shapes(input, &shapes, boundary) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("langfuse_secret_key", Confidence::High, range)
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

    /// Locally constructed synthetic `UUIDv4`; never provider-issued.
    const UUID: &str = "0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d";

    fn detect(input: &str) -> Vec<Candidate> {
        LangfuseSecretKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_minted_shape_with_provider_specificity() {
        let value = format!("{PREFIX}{UUID}");
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "langfuse_secret_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn accepts_every_variant_nibble() {
        for variant in ['8', '9', 'a', 'b'] {
            let uuid = UUID.replacen("-8c7d-", &format!("-{variant}c7d-"), 1);
            assert_eq!(detect(&format!("{PREFIX}{uuid}")).len(), 1);
        }
    }

    #[test]
    fn rejects_a_public_key_and_other_prefixes() {
        assert!(detect(&format!("pk-lf-{UUID}")).is_empty());
        assert!(detect(&format!("sk-lf-gw-{UUID}")).is_empty());
        assert!(detect(&format!("SK-LF-{UUID}")).is_empty());
        assert!(detect(&format!("sk-lf{UUID}")).is_empty());
    }

    #[test]
    fn rejects_a_body_that_is_not_a_lowercase_uuid_v4() {
        for uuid in [
            "0a1b2c3d-4e5f-1a6b-8c7d-0e1f2a3b4c5d", // version 1
            "0a1b2c3d-4e5f-4a6b-cc7d-0e1f2a3b4c5d", // variant c
            "0A1B2C3D-4E5F-4A6B-8C7D-0E1F2A3B4C5D", // uppercase
            "0a1b2c3d4e5f4a6b8c7d0e1f2a3b4c5d",     // no dashes
            "0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5",  // one short
        ] {
            assert!(detect(&format!("{PREFIX}{uuid}")).is_empty());
        }
        assert!(detect(&format!("{PREFIX}{UUID}0")).is_empty());
    }

    #[test]
    fn rejects_placeholders() {
        assert!(detect("sk-lf-your-secret-key").is_empty());
        assert!(detect("sk-lf-xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx").is_empty());
        assert!(detect("sk-lf-${LANGFUSE_SECRET_KEY}").is_empty());
    }

    #[test]
    fn rejects_a_wider_identifier() {
        let value = format!("{PREFIX}{UUID}");
        assert!(detect(&format!("x{value}")).is_empty());
        assert!(detect(&format!("{value}_backup")).is_empty());
        assert!(detect(&format!("{value}-1")).is_empty());
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = format!("{PREFIX}{UUID}");
        let candidates = detect(&format!("\"{value}\","));
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn stays_bounded_over_near_miss_prefixes() {
        let input = format!("{PREFIX}{} ", &UUID[..35]).repeat(10_000);
        assert!(detect(&input).is_empty());
    }
}
