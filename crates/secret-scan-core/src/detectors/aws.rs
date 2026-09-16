//! AWS access-key detection.
//!
//! Mirrors `src/detectors/aws.ts`.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIXES: [&str; 2] = ["AKIA", "ASIA"];

/// Restricts matches to the two documented AWS access-key prefixes and their
/// fixed length. This intentionally excludes other AWS identifiers such as
/// role and user IDs; unknown or future prefixes are false negatives until
/// explicitly added.
pub(super) struct AwsAccessKeyDetector;

impl Detector for AwsAccessKeyDetector {
    fn id(&self) -> &'static str {
        "aws-access-key"
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
            RunLength::Exact(16),
            pattern::is_upper_alnum,
            pattern::is_alnum,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("aws_access_key_id", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["aws-prefix", "fixed-length"]),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        AwsAccessKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_synthetic_fixture() {
        let input = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "aws_access_key_id");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_asia_prefix() {
        let input = format!("ASIA{}", "SYNTHETICEXAMPLE");
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_short_lookalike() {
        assert_eq!(detect("AKIASYNTHETICSHORT").len(), 0);
    }

    #[test]
    fn rejects_a_longer_alphanumeric_run() {
        assert_eq!(detect("AKIASYNTHETICEXAMPLEEXTRA").len(), 0);
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let input = format!("({value}).");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn rejects_an_embedded_lookalike() {
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        assert_eq!(detect(&format!("X{value}Y")).len(), 0);
    }

    #[test]
    fn rejects_a_user_id_prefix() {
        // AIDA (IAM user) is not a documented access-key prefix, like the
        // AROA (IAM role) case already covered by the corpus.
        assert_eq!(detect("AIDASYNTHETICEXAMPLE").len(), 0);
    }

    #[test]
    fn rejects_a_bare_account_id() {
        assert_eq!(
            detect("AWS account 123456789012 owns this resource.").len(),
            0
        );
    }

    #[test]
    fn rejects_an_iam_role_arn() {
        assert_eq!(
            detect("arn:aws:iam::123456789012:role/SyntheticExampleRole").len(),
            0
        );
    }

    #[test]
    fn rejects_an_s3_resource_arn() {
        assert_eq!(
            detect("arn:aws:s3:::synthetic-example-bucket-2026").len(),
            0
        );
    }

    #[test]
    fn rejects_an_ordinary_uppercase_identifier() {
        assert_eq!(detect("MAX_CONNECTIONS_ALLOWED_SYNTHETIC_EXAMPLE").len(), 0);
    }

    #[test]
    fn accepts_a_key_shaped_value_inside_a_comment_naming_example() {
        // The detector is pure grammar match with no context awareness, so a
        // comment naming the field "example" must not suppress a genuinely
        // key-shaped value; only the exact vendor-documented literal is
        // exempted (see pipeline.rs's KNOWN_VENDOR_PLACEHOLDER_LITERALS).
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let input = format!("// example: {value} (rotate before deploying)");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "// example: ".len();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn accepts_a_value_adjacent_to_a_multibyte_unicode_character() {
        // "é" is 2 UTF-8 bytes; neither byte is ASCII-alnum, so both are
        // correctly treated as non-alnum boundary bytes rather than one of
        // them being mistaken for part of the run or splitting the offset.
        let value = format!("AKIA{}", "SYNTHETICEXAMPLE");
        let input = format!("caf\u{e9}{value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "caf\u{e9}".len();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }
}
