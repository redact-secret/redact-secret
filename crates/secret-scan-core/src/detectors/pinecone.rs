//! Pinecone API key detection (issue #730, Beta.8 wave 2).
//!
//! Frozen by issue #726 (`docs/audits/evidence/726/README.md`): the current
//! key shape is `pcsk_<label>_<secret>` with a 5-6 byte `[A-Za-z0-9]` label
//! and an exact 63 byte `[A-Za-z0-9]` secret (T2: the prefix and segmenting
//! are provider code, the widths are tool-corroborated). It is one
//! [`PrefixShape`] on the shared [`KnownFormatProviderDetector`]: the body is
//! scanned as `[A-Za-z0-9_]` at the only two total widths the grammar admits
//! (69 or 70 bytes), and [`separator_is_at_the_label_end`] then requires the
//! single `_` to sit exactly after the 5- or 6-byte label, so the run cannot
//! be split any other way.
//!
//! Not claimed, on purpose: the documented `pckey_` prefix (contradicted by
//! every `pcsk_` observation, so neither positive nor negative), and the
//! legacy bare-UUID key, which is lexically identical to Pinecone's own
//! project, key and service-account identifiers and is only ever a
//! context-gated candidate. Index hosts, environment names and masked
//! `pcsk_***` values never reach the width and stay clean.
//!
//! Boundary: the value must not be a slice of a longer `[A-Za-z0-9_-]`
//! identifier.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, PrefixShape};

const PREFIX: &str = "pcsk_";
const SECRET_LEN: usize = 63;
/// Label 5 or 6, the separating `_`, then the secret.
const BODY_LENS: &[usize] = &[5 + 1 + SECRET_LEN, 6 + 1 + SECRET_LEN];
const SIGNALS: [&str; 2] = ["pinecone-provider-code-prefix", "segmented-suffix"];

/// `[A-Za-z0-9_-]`: a value is never a slice of a wider identifier.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// The body after `pcsk_` holds exactly one `_`, and it is the label
/// separator: at index `len - 64` (5 for a 69 byte body, 6 for a 70 byte one),
/// leaving an all-alphanumeric label and a 63 byte all-alphanumeric secret.
fn separator_is_at_the_label_end(bytes: &[u8], start: usize, end: usize) -> bool {
    let body = &bytes[start + PREFIX.len()..end];
    let separator = body.len() - SECRET_LEN - 1;
    body[separator] == b'_'
        && body
            .iter()
            .enumerate()
            .all(|(index, &byte)| index == separator || pattern::is_alnum(byte))
}

pub(super) const PINECONE: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "pinecone-api-key",
    "pinecone_api_key",
    &[
        PrefixShape::one_of(PREFIX, BODY_LENS, pattern::is_alnum_underscore, &SIGNALS)
            .with_post_check(separator_is_at_the_label_end),
    ],
    is_token_char,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    const LABEL: &str = "SynTh";
    const LONG_LABEL: &str = "SynThe";
    const SECRET: &str = "SyntheticRevokedPineconeSecretValue0000000000000000000000000001";
    const _: () = assert!(SECRET.len() == SECRET_LEN);

    fn detect(input: &str) -> Vec<Candidate> {
        PINECONE
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn token(label: &str) -> String {
        format!("pcsk_{label}_{SECRET}")
    }

    #[test]
    fn detects_both_label_widths_at_provider_specificity() {
        for label in [LABEL, LONG_LABEL] {
            let token = token(label);
            let candidates = detect(&token);
            assert_eq!(candidates.len(), 1, "{token}");
            assert_eq!(PINECONE.id(), "pinecone-api-key");
            assert_eq!(candidates[0].type_name(), "pinecone_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, token.len()).unwrap()
            );
        }
    }

    #[test]
    fn the_range_covers_exactly_the_key_inside_surrounding_text() {
        let token = token(LABEL);
        let input = format!("PINECONE_API_KEY=\"{token}\", next");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(18, 18 + token.len()).unwrap()
        );
    }

    #[test]
    fn a_label_or_secret_of_another_width_is_rejected() {
        for input in [
            token("Syn"),
            token("SynThes"),
            token(""),
            format!("pcsk_{LABEL}_{}", &SECRET[1..]),
            format!("pcsk_{LABEL}_{SECRET}0"),
            format!("pcsk_{LABEL}{SECRET}"),
            format!("pcsk_{LABEL}-{SECRET}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_second_separator_or_a_dash_inside_a_segment_is_rejected() {
        let mut secret = SECRET.to_owned();
        secret.replace_range(10..11, "_");
        let mut dashed = SECRET.to_owned();
        dashed.replace_range(10..11, "-");
        for input in [
            format!("pcsk_{LABEL}_{secret}"),
            format!("pcsk_{LABEL}_{dashed}"),
            format!("pcsk_Sy_Th_{}", &SECRET[..62]),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_glued_identifier_boundary_rejects_an_embedded_key() {
        let token = token(LABEL);
        for input in [
            format!("x{token}"),
            format!("-{token}"),
            format!("_{token}"),
            format!("{token}_backup"),
            format!("{token}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn near_miss_prefixes_and_the_unresolved_pckey_prefix_are_not_claimed() {
        for input in [
            format!("PCSK_{LABEL}_{SECRET}"),
            format!("pcsk-{LABEL}_{SECRET}"),
            format!("pckey_{LABEL}_{SECRET}"),
            format!("csk_{LABEL}_{SECRET}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn identifiers_hosts_and_masks_stay_clean() {
        for input in [
            "PINECONE_API_KEY=pcsk_***",
            "index host: my-index-1a2b3c4.svc.aped-4627-b74a.pinecone.io",
            "project id 123e4567-e89b-12d3-a456-426614174000",
            "environment: us-east-1-aws",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_repeated_key_is_reported_once_per_occurrence() {
        let token = token(LABEL);
        let candidates = detect(&format!("{token} {token}"));
        assert_eq!(candidates.len(), 2);
    }
}
