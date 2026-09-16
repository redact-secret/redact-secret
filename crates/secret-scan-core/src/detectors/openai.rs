//! `OpenAI` token detection.
//!
//! Mirrors `src/detectors/openai.ts`. The TypeScript oracle excludes
//! Anthropic's `sk-ant-` namespace with a negative lookahead
//! (`(?!ant-)`), which the Rust `regex` crate — and, more fundamentally,
//! this crate's dependency-free matcher — cannot express. [`scan`] replaces
//! it with an explicit, bounded (4-byte) literal check of the text right
//! after `sk-`.

use crate::detectors::pattern::{self, Alphabet};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &str = "sk-";
const PROJECT_PREFIX: &str = "proj-";
const SERVICE_ACCOUNT_PREFIX: &str = "svcacct-";
const ANTHROPIC_PREFIX: &str = "ant-";
const MIN_SUFFIX_LEN: usize = 20;
const ALPHABET: Alphabet = pattern::is_alnum_dash;

/// Requires a recognized `sk-` form and a substantial opaque suffix.
/// Anthropic's documented `sk-ant-` namespace is excluded so the more
/// specific provider detector owns it. Short examples and future prefixes
/// can still be missed.
pub(super) struct OpenAiTokenDetector;

impl Detector for OpenAiTokenDetector {
    fn id(&self) -> &'static str {
        "openai-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in scan(input) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("openai_api_key", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["openai-prefix", "opaque-suffix"]),
            );
        }
        Ok(candidates)
    }
}

/// Reproduces `sk-(?:(?:proj-|svcacct-)ALPHABET{20,}|(?!ant-)ALPHABET{20,})`
/// without lookahead: try the `proj-`/`svcacct-` branch first, and only fall
/// back to the bare branch — after checking the next 4 bytes are not
/// literally `ant-` — when it does not apply.
fn scan(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, ALPHABET);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start..].starts_with(PREFIX.as_bytes()) {
            start += 1;
            continue;
        }
        let rest_start = start + PREFIX.len();
        let Some(end) = branch_end(bytes, &ends, rest_start) else {
            start += 1;
            continue;
        };
        if pattern::boundary_ok(bytes, start, end, ALPHABET) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

fn branch_end(bytes: &[u8], ends: &[usize], rest_start: usize) -> Option<usize> {
    for literal in [PROJECT_PREFIX, SERVICE_ACCOUNT_PREFIX] {
        if bytes[rest_start..].starts_with(literal.as_bytes()) {
            let suffix_start = rest_start + literal.len();
            let available = ends[suffix_start] - suffix_start;
            return (available >= MIN_SUFFIX_LEN).then_some(suffix_start + available);
        }
    }

    if bytes[rest_start..].starts_with(ANTHROPIC_PREFIX.as_bytes()) {
        return None;
    }
    let available = ends[rest_start] - rest_start;
    (available >= MIN_SUFFIX_LEN).then_some(rest_start + available)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        OpenAiTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_project_prefixed_form() {
        let input = format!("sk-proj-{}", "SYNTHETIC_REVOKED_OPENAI_KEY");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "openai_api_key");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_service_account_prefixed_form() {
        let input = format!("sk-svcacct-{}", "SYNTHETIC_REVOKED_OPENAI_KEY");
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn detects_the_bare_form() {
        let input = format!("sk-{}", "SYNTHETIC_REVOKED_OPENAI_KEY_VALUE");
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_short_example() {
        assert_eq!(detect("sk-proj-short-example").len(), 0);
    }

    #[test]
    fn excludes_the_anthropic_namespace_even_when_long_enough() {
        let input = format!("sk-ant-{}", "SYNTHETIC_REVOKED_ANTHROPIC_LOOKALIKE");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn excludes_the_versioned_anthropic_token_too() {
        let input = format!("sk-ant-api03-{}", "SYNTHETIC_REVOKED_ANTHROPIC_KEY");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn does_not_exclude_a_bare_key_that_merely_starts_with_ant_without_the_dash() {
        // `ant` without the trailing `-` is not the excluded literal.
        let input = format!("sk-{}", "antSYNTHETIC_REVOKED_OPENAI_KEY_VALUE");
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn accepts_a_doc_style_placeholder_built_from_valid_alphabet_characters() {
        let input = format!("sk-proj-{}", "x".repeat(MIN_SUFFIX_LEN));
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_prefix_embedded_in_a_wider_benign_identifier() {
        // A leading alnum/dash byte right before `sk-` means this is a
        // truncated slice of a longer identifier, not a boundary-delimited
        // credential.
        let input = format!("legacysk-proj-{}", "SYNTHETIC_REVOKED_KEY_VALUE");
        assert_eq!(detect(&input).len(), 0);
    }

    #[test]
    fn a_trailing_comma_does_not_get_folded_into_or_suppress_the_match() {
        let token = format!("sk-proj-{}", "SYNTHETIC_REVOKED_KEY_VALUE");
        let input = format!("Rotate {token}, then redeploy.");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = "Rotate ".len();
        let end = start + token.len();
        assert_eq!(candidates[0].range(), ByteRange::new(start, end).unwrap());
    }
}
