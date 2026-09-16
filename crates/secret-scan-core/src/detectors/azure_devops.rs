//! Azure DevOps personal access token (PAT) detection.
//!
//! Unlike most providers in this registry, Microsoft publishes the exact
//! grammar for the *current* PAT shape rather than leaving it to be
//! reverse-engineered:
//!
//! - Azure DevOps's own docs
//!   (`https://learn.microsoft.com/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate#pat-format`),
//!   updated 2026-09-04: "Tokens are 84 characters long... Tokens issued by
//!   Azure DevOps include a fixed `AZDO` signature at positions 76-80."
//! - Microsoft Purview's sensitive-information-type definition for this
//!   credential (`sit-defn-azure-devops-personal-access-token`) is more
//!   precise about the alphabet and the marker's exact placement: "Any
//!   combination of 84 characters consisting of: a-z or A-Z (case-sensitive),
//!   or 0-9, with a fixed signature `AZDO` at position 76-80", `Checksum:
//!   Yes` ("the service can make a positive detection based on the sensitive
//!   data alone"). Its worked example --
//!   `...abcdefghijklmnoAZDOabcd` -- has exactly 76 alphanumeric bytes before
//!   the marker and exactly 4 after it, which is the concrete grammar this
//!   module implements; "position 76-80" is that same 4-byte span written as
//!   an inclusive-looking range, not a 5th character.
//!
//! Grammar: 76 [`is_alnum`] bytes, the literal `AZDO`, then 4 more
//! [`is_alnum`] bytes (84 bytes total, exactly -- not a minimum), bounded on
//! both sides by a byte outside `[A-Za-z0-9]` or the edge of input. Because
//! the vendor documents this marker as a `Checksum: Yes` signal ("the
//! service can make a positive detection based on the sensitive data
//! alone"), no surrounding context (`PAT=`, `azure devops`, ...) is required
//! to classify a match, matching every other `Specificity::Provider`
//! detector in this module.
//!
//! Known unsupported variant: the legacy/pre-signature PAT shape (52 bytes
//! from a lowercase-alphanumeric-leaning charset, no embedded marker --
//! see trufflehog's `azuredevopspersonalaccesstoken` detector, consulted
//! here only as an external behavioral reference per `AGENTS.md`, no code
//! reproduced) carries no distinguishing structure of its own. trufflehog
//! only classifies it next to a nearby `azure`-family keyword for exactly
//! that reason. A bare, contextless 52-byte alphanumeric run is
//! indistinguishable from an ordinary build hash, commit SHA, or opaque
//! identifier -- precisely the false-positive shapes issue #298 calls out by
//! name -- so it is an intentional false negative here, not a dedicated or
//! contextual detection target.

use crate::detectors::pattern::{self, is_alnum};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// The fixed signature every current-format token carries.
const ANCHOR: &str = "AZDO";
/// Alphanumeric bytes required immediately before [`ANCHOR`].
const PREFIX_LEN: usize = 76;
/// Alphanumeric bytes required immediately after [`ANCHOR`].
const SUFFIX_LEN: usize = 4;

/// Detects an Azure DevOps personal access token by its documented
/// `<76 bytes>AZDO<4 bytes>` shape (84 bytes total).
pub(super) struct AzureDevOpsPersonalAccessTokenDetector;

impl Detector for AzureDevOpsPersonalAccessTokenDetector {
    fn id(&self) -> &'static str {
        "azure-devops-personal-access-token"
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
                Candidate::new(
                    "azure_devops_personal_access_token",
                    Confidence::High,
                    range,
                )
                .with_specificity(Specificity::Provider)
                .with_signals(["azdo-fixed-signature", "azdo-84-byte-length"]),
            );
        }
        Ok(candidates)
    }
}

/// Finds every non-overlapping match of `<76 bytes>AZDO<4 bytes>`, left to
/// right. There is no leading literal to anchor a forward scan on -- the
/// marker sits 76 bytes into the token -- so, exactly as
/// [`super::microsoft_entra`]'s scan does, this searches for the `AZDO`
/// anchor itself and validates outward from it; a successful match advances
/// the scan past its own end, and a rejected anchor advances by one byte.
///
/// An input with no `AZDO` substring at all -- the overwhelming majority of
/// scanned text, including every other provider's own token shapes -- returns
/// before paying for [`pattern::run_ends`]'s whole-input table, which is the
/// only allocation this detector would otherwise make regardless of whether
/// the literal is present; large adversarial inputs stay within their
/// declared runtime budget on this fast path.
fn scan(input: &str) -> Vec<(usize, usize)> {
    if input.len() < PREFIX_LEN + ANCHOR.len() + SUFFIX_LEN || !input.contains(ANCHOR) {
        return Vec::new();
    }
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, is_alnum);
    let mut matches = Vec::new();
    let mut anchor = 0;
    while anchor < bytes.len() {
        if !bytes[anchor..].starts_with(ANCHOR.as_bytes()) {
            anchor += 1;
            continue;
        }
        let Some((start, end)) = match_at(bytes, &ends, anchor) else {
            anchor += 1;
            continue;
        };
        matches.push((start, end));
        anchor = end;
    }
    matches
}

/// Validates the exact `<76 bytes>` immediately before `anchor` and the
/// exact `<4 bytes>` immediately after it, returning the full match span
/// when both hold and neither edge is a truncated slice of a longer
/// alphanumeric run.
///
/// Both spans are exact lengths, not minimums: a 77-byte run before the
/// marker is rejected (not read as a 76-byte prefix one byte late) because
/// the boundary check below sees an alphanumeric byte immediately before the
/// candidate `start`, the same way a `{76}` regex quantifier followed by a
/// boundary assertion would reject it.
fn match_at(bytes: &[u8], ends: &[usize], anchor: usize) -> Option<(usize, usize)> {
    let start = anchor.checked_sub(PREFIX_LEN)?;
    if ends[start] < anchor {
        return None;
    }

    let suffix_start = anchor + ANCHOR.len();
    let end = suffix_start.checked_add(SUFFIX_LEN)?;
    if end > bytes.len() || ends[suffix_start] < end {
        return None;
    }

    pattern::boundary_ok(bytes, start, end, is_alnum).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX_76: &str =
        "SYNTHETICREVOKEDAZUREDEVOPSPATVALUEFORCONFORMANCETESTINGPADDINGFIXTUREDATAZZ";
    const SUFFIX_4: &str = "abcd";

    fn detect(input: &str) -> Vec<Candidate> {
        AzureDevOpsPersonalAccessTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn token() -> String {
        format!("{PREFIX_76}AZDO{SUFFIX_4}")
    }

    #[test]
    fn detects_the_synthetic_fixture() {
        let input = token();
        assert_eq!(input.len(), 84);
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].type_name(),
            "azure_devops_personal_access_token"
        );
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_prefix_one_byte_below_the_required_length() {
        let short_prefix = &PREFIX_76[1..];
        assert_eq!(short_prefix.len(), 75);
        assert_eq!(detect(&format!("{short_prefix}AZDO{SUFFIX_4}")).len(), 0);
    }

    #[test]
    fn rejects_a_prefix_one_byte_above_the_required_length_rather_than_truncating() {
        // A 77-byte run of alphanumeric bytes before the marker is not
        // silently read as a 76-byte prefix one byte late.
        let long_prefix = format!("x{PREFIX_76}");
        assert_eq!(long_prefix.len(), 77);
        assert_eq!(detect(&format!("{long_prefix}AZDO{SUFFIX_4}")).len(), 0);
    }

    #[test]
    fn rejects_a_suffix_one_byte_below_the_required_length() {
        assert_eq!(detect(&format!("{PREFIX_76}AZDOabc")).len(), 0);
    }

    #[test]
    fn rejects_a_suffix_one_byte_above_the_required_length_rather_than_truncating() {
        assert_eq!(detect(&format!("{PREFIX_76}AZDOabcde")).len(), 0);
    }

    #[test]
    fn rejects_a_prefix_broken_by_an_out_of_alphabet_byte() {
        let broken = format!("{} {}", &PREFIX_76[..10], &PREFIX_76[11..]);
        assert_eq!(detect(&format!("{broken}AZDO{SUFFIX_4}")).len(), 0);
    }

    #[test]
    fn rejects_an_anchor_too_close_to_the_start_of_input() {
        assert_eq!(detect(&format!("AZDO{SUFFIX_4}")).len(), 0);
    }

    #[test]
    fn rejects_a_bare_legacy_length_value_with_no_marker() {
        // The known-unsupported legacy shape: 52 bytes, no `AZDO` signature.
        let legacy = "a".repeat(52);
        assert_eq!(detect(&legacy).len(), 0);
    }

    #[test]
    fn rejects_the_literal_azdo_with_no_qualifying_prefix_or_suffix() {
        assert_eq!(detect("our AZDO service tier covers this").len(), 0);
    }

    #[test]
    fn finds_a_qualified_match_inside_surrounding_context() {
        let input = format!("PAT={}", token());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(PREFIX_76).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, input.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = token();
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_anchors() {
        let input = format!("{}!{}", token(), "AZDO".repeat(10_000));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].range(), ByteRange::new(0, 84).unwrap());
    }
}
