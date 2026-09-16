//! Atlassian (Jira / Confluence) Cloud API token detection.
//!
//! Atlassian's own token-management documentation
//! (`https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/`)
//! publishes no character-class grammar for a token's value, and explicitly
//! warns integrators not to assume one shape: "We use a varied API token
//! length ... rather than fixed length ... If your script relies on fixed
//! API token length, check that it can handle a variable instead." It does
//! not document a literal prefix either; that came from an Atlassian Team
//! member's reply in the product's community forum (not the formal docs),
//! confirming three stable prefixes that distinguish credential families:
//! `ATAT` for API tokens (this detector's target), `ATCT` for access tokens
//! (workspace/project/repo), and `ATBB` for app passwords. Consulted only as
//! an external behavioral reference per `AGENTS.md`, gitleaks's
//! `atlassian-api-token` rule and trufflehog's `atlassian/v2` detector both
//! independently observe real-world API-token samples of the fuller shape
//! `ATATT3xFfGF0<...>`, totaling 192 bytes today; no code from either project
//! is reproduced here.
//!
//! Grammar: the literal `ATAT`, then a minimum-length run of
//! [`pattern::is_alnum_dash`] (`[A-Za-z0-9_-]`), bounded on both sides by a
//! byte outside that alphabet or the edge of input. The run is a documented
//! minimum ([`RunLength::AtLeast`]), not an exact length, precisely because
//! Atlassian's own guidance above disclaims a fixed length; a future token
//! shorter than every currently observed 188-byte sample is intentionally
//! still matched as long as it clears the minimum, while a future *longer*
//! token is matched unconditionally by construction.
//!
//! The body alphabet deliberately excludes `=`, even though both reference
//! scanners' patterns allow it appearing anywhere in the body (real samples
//! carry it once, near the end, as base64 padding ahead of a checksum
//! suffix): including it in the *boundary* alphabet would make the ubiquitous
//! `KEY=<token>` assignment delimiter immediately preceding a real token look
//! like a truncated slice of a longer run and reject the whole match, which
//! is a far worse outcome than the alternative -- a match that stops just
//! short of an embedded `=`, still well past [`MIN_BODY_LEN`] on every
//! observed sample, and still redacts the overwhelming majority of the
//! secret.
//!
//! Two variants are intentionally out of scope, not fuzzy-matched:
//!
//! - The legacy, pre-2022 unprefixed 24-character token (20 lowercase
//!   alphanumeric bytes followed by 4 lowercase-hex bytes, per gitleaks's
//!   context-gated alternative pattern) carries no distinguishing marker at
//!   all. It is indistinguishable from ordinary opaque text without reliable
//!   surrounding context, exactly the gap [`super::generic_token`]'s existing
//!   `name=value` contextual heuristic already covers at
//!   `Specificity::Contextual` -- the same tradeoff [`super::microsoft_entra`]
//!   makes for its own older, unmarked client-secret format.
//! - `ATCT`-prefixed access tokens and `ATBB`-prefixed app passwords are
//!   separate Atlassian credential families (the latter is also explicitly
//!   out of scope per issue #299: "Data Center and Bitbucket credentials are
//!   explicitly separate formats"), not variants of the API token this
//!   detector targets.

use crate::detectors::pattern::{self, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// The Atlassian-Team-confirmed stable prefix for API tokens, as distinct
/// from `ATCT` (access tokens) and `ATBB` (app passwords).
const PREFIX: &str = "ATAT";

/// Comfortably below every currently observed real-world sample (188 bytes
/// after [`PREFIX`], for a 192-byte token total), so a token Atlassian
/// shortens in the future -- which its own documentation explicitly reserves
/// the right to do -- is still matched. Still long enough that `ATAT`
/// followed by this many uninterrupted bytes from [`pattern::is_alnum_dash`]
/// is not something ordinary text produces by chance.
const MIN_BODY_LEN: usize = 100;

/// Detects an Atlassian Cloud API token by its documented-stable `ATAT`
/// prefix and a minimum-length opaque body.
pub(super) struct AtlassianApiTokenDetector;

impl Detector for AtlassianApiTokenDetector {
    fn id(&self) -> &'static str {
        "atlassian-api-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            &[PREFIX],
            RunLength::AtLeast(MIN_BODY_LEN),
            pattern::is_alnum_dash,
            pattern::is_alnum_dash,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("atlassian_api_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["atlassian-documented-prefix", "minimum-length-opaque-body"]),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY_100: &str = "SYNTHETIC_REVOKED_ATLASSIAN_API_TOKEN_BODY_SYNTHETIC_REVOKED_ATLASSIAN_API_TOKEN_BODY_SYNTHETIC_REVO";

    fn detect(input: &str) -> Vec<Candidate> {
        AtlassianApiTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn body_100_is_exactly_the_documented_minimum() {
        assert_eq!(BODY_100.len(), MIN_BODY_LEN);
    }

    #[test]
    fn detects_the_synthetic_fixture_at_the_minimum_length() {
        let input = format!("{PREFIX}{BODY_100}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "atlassian_api_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_a_body_longer_than_the_minimum() {
        let input = format!("{PREFIX}{BODY_100}EXTRA-TAIL-BYTES-PAST-THE-MINIMUM");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_body_one_byte_below_the_minimum() {
        let short = &BODY_100[..BODY_100.len() - 1];
        assert_eq!(detect(&format!("{PREFIX}{short}")).len(), 0);
    }

    #[test]
    fn rejects_a_body_broken_by_an_out_of_alphabet_byte_before_the_minimum() {
        let broken = format!("{} {}", &BODY_100[..10], &BODY_100[11..]);
        assert_eq!(detect(&format!("{PREFIX}{broken}")).len(), 0);
    }

    #[test]
    fn truncates_at_an_embedded_equals_sign_but_still_matches_past_the_minimum() {
        let input = format!("{PREFIX}{BODY_100}=CHECKSUMSUFFIX");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, PREFIX.len() + BODY_100.len()).unwrap()
        );
    }

    #[test]
    fn rejects_the_access_token_prefix() {
        assert_eq!(detect(&format!("ATCT{BODY_100}")).len(), 0);
    }

    #[test]
    fn rejects_the_app_password_prefix() {
        assert_eq!(detect(&format!("ATBB{BODY_100}")).len(), 0);
    }

    #[test]
    fn rejects_the_legacy_unprefixed_twenty_four_byte_token_with_no_context() {
        assert_eq!(detect("abcdefghijklmnopqrst1234").len(), 0);
    }

    #[test]
    fn rejects_a_placeholder_immediately_after_the_prefix() {
        assert_eq!(detect(&format!("{PREFIX}<YOUR_API_TOKEN_HERE>")).len(), 0);
    }

    #[test]
    fn rejects_a_masked_value() {
        assert_eq!(
            detect(&format!("{PREFIX}{}", "*".repeat(MIN_BODY_LEN))).len(),
            0
        );
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert_eq!(
            detect(&format!("{PREFIX}${{ATLASSIAN_API_TOKEN}}")).len(),
            0
        );
    }

    #[test]
    fn finds_a_qualified_match_immediately_after_an_assignment_delimiter() {
        let input = format!("ATLASSIAN_API_TOKEN={PREFIX}{BODY_100}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(PREFIX).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, input.len()).unwrap()
        );
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\n{PREFIX}{BODY_100}\r\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(PREFIX).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + PREFIX.len() + BODY_100.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("{PREFIX}{BODY_100}");
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_prefixes() {
        let input = format!("{PREFIX}{BODY_100}!{}", "ATAT!".repeat(10_000));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, PREFIX.len() + BODY_100.len()).unwrap()
        );
    }
}
