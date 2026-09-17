//! Anthropic token detection.
//!
//! Mirrors `src/detectors/anthropic.ts`.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIXES: [&str; 1] = ["sk-ant-api03-"];

/// Requires the versioned Anthropic API-key prefix and a substantial
/// suffix. This prioritizes precision; older, shortened, or newly versioned
/// formats are intentionally false negatives until their exact shape is
/// supported.
pub(super) struct AnthropicTokenDetector;

impl Detector for AnthropicTokenDetector {
    fn id(&self) -> &'static str {
        "anthropic-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            &PREFIXES,
            RunLength::AtLeast(20),
            pattern::is_alnum_dash,
            pattern::is_alnum_dash,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("anthropic_api_key", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["anthropic-versioned-prefix", "opaque-suffix"]),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        AnthropicTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_synthetic_fixture() {
        let input = "sk-ant-api03-SYNTHETIC_REVOKED_ANTHROPIC_KEY";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "anthropic_api_key");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn rejects_an_unsupported_version_prefix() {
        assert_eq!(
            detect("sk-ant-api02-SYNTHETIC_REVOKED_ANTHROPIC_KEY").len(),
            0
        );
    }

    #[test]
    fn rejects_a_short_suffix() {
        assert_eq!(detect("sk-ant-api03-short").len(), 0);
    }

    #[test]
    fn accepts_a_doc_style_placeholder_built_from_valid_alphabet_characters() {
        let input = format!("sk-ant-api03-{}", "x".repeat(20));
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_prefix_embedded_in_a_wider_benign_identifier() {
        // A leading alnum/dash byte right before `sk-ant-api03-` means this
        // is a truncated slice of a longer identifier, not a
        // boundary-delimited credential.
        let input = format!("mysk-ant-api03-{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn a_trailing_comma_does_not_get_folded_into_or_suppress_the_match() {
        let token = format!("sk-ant-api03-{}", "SYNTHETIC_REVOKED_KEY_VALUE");
        let input = format!("Rotate {token}, then redeploy.");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "Rotate ".len();
        let end = start + token.len();
        assert_eq!(candidates[0].range(), ByteRange::new(start, end).unwrap());
    }

    #[test]
    fn an_unversioned_prefix_is_a_documented_false_negative() {
        // No detector claims this: openai-token excludes the whole
        // `sk-ant-` namespace and anthropic-token requires the versioned
        // prefix. See the module doc comment for the accepted tradeoff.
        let input = "sk-ant-SYNTHETIC_REVOKED_LEGACY_ANTHROPIC_KEY_VALUE";
        assert_eq!(detect(input).len(), 0);
    }

    #[test]
    fn rejects_a_future_version_marker_not_yet_documented() {
        // Only the exact `api03` segment is supported; a plausible future
        // version is not speculatively accepted alongside it.
        let input = format!("sk-ant-api04-{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn rejects_a_near_prefix_variant_using_underscore_instead_of_dash() {
        // Prose about the shape of the prefix, not the literal
        // dash-delimited prefix itself, must not be classified.
        let input = format!("sk_ant_api03_{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn reports_each_occurrence_of_a_repeated_value_independently() {
        let token = format!("sk-ant-api03-{}", "SYNTHETIC_REVOKED_KEY_VALUE");
        let input = format!("{token} {token}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, token.len()).unwrap()
        );
        let second_start = token.len() + 1;
        assert_eq!(
            candidates[1].range(),
            ByteRange::new(second_start, second_start + token.len()).unwrap()
        );
    }
}
