//! `SendGrid` API key detection.
//!
//! `SendGrid`'s documented API key shape is `SG.<22-byte id>.<43-byte secret>`,
//! both segments drawn from the URL-safe base64 alphabet `[A-Za-z0-9_-]`. The
//! two fixed-length segments joined by a literal `.` do not fit
//! [`super::pattern::scan_prefixed_runs`]'s single prefix-then-run shape (used
//! by every other known-format provider in `additional_providers.rs`), so
//! this detector walks the match by hand the way [`super::jwt`] does for its
//! own multi-segment shape.

use crate::detectors::pattern::{self, is_alnum_dash};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &[u8] = b"SG.";
const ID_LEN: usize = 22;
const SECRET_LEN: usize = 43;

/// Requires the exact `SG.<22>.<43>` shape. A shorter or longer segment, a
/// missing or misplaced separator, or an id/secret run embedded in a wider
/// identifier is an intentional false negative rather than a fuzzy match.
pub(super) struct SendgridTokenDetector;

impl Detector for SendgridTokenDetector {
    fn id(&self) -> &'static str {
        "sendgrid-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let ends = pattern::run_ends(bytes, is_alnum_dash);
        let mut candidates = Vec::new();
        let mut start = 0;
        while start < bytes.len() {
            if !bytes[start..].starts_with(PREFIX) {
                start += 1;
                continue;
            }

            let Some(end) = match_at(bytes, &ends, start) else {
                start += 1;
                continue;
            };

            if pattern::boundary_ok(bytes, start, end, is_alnum_dash)
                && let Some(range) = ByteRange::new(start, end)
            {
                candidates.push(
                    Candidate::new("sendgrid_api_key", Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(["sendgrid-documented-shape", "two-segment-exact-length"]),
                );
            }
            start = end;
        }
        Ok(candidates)
    }
}

/// Attempts an `SG.<22>.<43>` match anchored exactly at `start`, where
/// `bytes[start..]` is already known to begin with [`PREFIX`]. Returns the
/// exclusive end offset on success; the caller still applies the boundary
/// check.
///
/// `ends` is the precomputed maximal-run-end table from
/// [`pattern::run_ends`], so each segment's length is a table lookup rather
/// than a rescan, keeping the whole detector linear in the input length.
fn match_at(bytes: &[u8], ends: &[usize], start: usize) -> Option<usize> {
    let id_start = start + PREFIX.len();
    if ends[id_start] < id_start + ID_LEN {
        return None;
    }
    let dot = id_start + ID_LEN;
    if bytes.get(dot) != Some(&b'.') {
        return None;
    }

    let secret_start = dot + 1;
    if ends[secret_start] < secret_start + SECRET_LEN {
        return None;
    }

    Some(secret_start + SECRET_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "SYNTHETIC_REVOKED_0000";
    const SECRET: &str = "SYNTHETIC_REVOKED_SENDGRID_SECRET_000000000";

    fn token() -> String {
        format!("SG.{ID}.{SECRET}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        SendgridTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn fixture_segments_are_exactly_documented_length() {
        assert_eq!(ID.len(), ID_LEN);
        assert_eq!(SECRET.len(), SECRET_LEN);
    }

    #[test]
    fn detects_a_synthetic_key_with_provider_specificity() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_key_bare_in_env_and_control_contexts() {
        let value = token();
        for input in [
            value.clone(),
            format!("SENDGRID_TOKEN={value}"),
            format!("api_key={value}"),
            format!("{{\"apiKey\": \"{value}\"}}"),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = token();
        let input = format!("({value}).");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn rejects_a_truncated_id_segment() {
        let short_id = &ID[..ID_LEN - 1];
        assert!(detect(&format!("SG.{short_id}.{SECRET}")).is_empty());
    }

    #[test]
    fn rejects_a_truncated_secret_segment() {
        let short_secret = &SECRET[..SECRET_LEN - 1];
        assert!(detect(&format!("SG.{ID}.{short_secret}")).is_empty());
    }

    #[test]
    fn rejects_an_id_segment_longer_than_documented() {
        assert!(detect(&format!("SG.{ID}A.{SECRET}")).is_empty());
    }

    #[test]
    fn rejects_a_secret_segment_longer_than_documented() {
        assert!(detect(&format!("SG.{ID}.{SECRET}A")).is_empty());
    }

    #[test]
    fn rejects_a_malformed_separator() {
        assert!(detect(&format!("SG_{ID}.{SECRET}")).is_empty());
        assert!(detect(&format!("SG.{ID}_{SECRET}")).is_empty());
    }

    #[test]
    fn rejects_the_prefix_alone() {
        assert!(detect("SG.").is_empty());
        assert!(detect("SG.SYNTHETIC").is_empty());
    }

    #[test]
    fn rejects_the_id_or_secret_embedded_in_a_wider_identifier() {
        let value = token();
        assert!(detect(&format!("x{value}")).is_empty());
        assert!(detect(&format!("{value}x")).is_empty());
    }

    /// issue #321: a documentation placeholder built entirely from valid
    /// alphabet characters, at the exact documented segment lengths, is
    /// indistinguishable from a real key's shape and is classified — an
    /// accepted precision/recall tradeoff, mirroring
    /// `additional_providers::accepts_an_all_valid_alphabet_documentation_placeholder`.
    #[test]
    fn accepts_an_all_valid_alphabet_documentation_placeholder() {
        let value = format!("SG.{}.{}", "x".repeat(ID_LEN), "x".repeat(SECRET_LEN));
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    /// A percent-encoded rendering of the documented '.' separator does not
    /// literally match the prefix's own bytes.
    #[test]
    fn rejects_a_percent_encoded_separator_lookalike() {
        let value = format!("SG%2E{ID}.{SECRET}");
        assert!(detect(&value).is_empty());
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = token();
        let input = format!("{value} {value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2);
    }

    /// SendGrid's documented alphabet is URL-safe base64 ([A-Za-z0-9_-]); an
    /// id or secret segment ending in a literal '-' or '_' at the exact
    /// documented length is still matched in full.
    #[test]
    fn accepts_segments_with_trailing_url_safe_characters() {
        let id = format!("{}-", &ID[..ID_LEN - 1]);
        let secret = format!("{}_", &SECRET[..SECRET_LEN - 1]);
        assert_eq!(id.len(), ID_LEN);
        assert_eq!(secret.len(), SECRET_LEN);
        let value = format!("SG.{id}.{secret}");
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }
}
