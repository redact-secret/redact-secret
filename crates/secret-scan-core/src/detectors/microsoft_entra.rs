//! Microsoft Entra (Azure AD) application client-secret detection.
//!
//! Microsoft's own credential documentation
//! (`https://learn.microsoft.com/entra/identity-platform/how-to-add-credentials`)
//! publishes no grammar for a client secret's *Value* -- only that it must be
//! recorded immediately because it is never shown again. The shape matched
//! here is therefore not vendor-documented; it is the community-observed
//! structural marker (a single ASCII digit immediately followed by the
//! literal `Q~`) independently converged on by gitleaks's
//! `azure-ad-client-secret` rule and trufflehog's
//! `azure_entra/serviceprincipal/v2` detector, consulted here only as
//! external behavioral references, per `AGENTS.md`: no code from either
//! project is reproduced, and this module's matching logic is authored
//! independently against the shared shape they both describe.
//!
//! Grammar: 3 [`is_prefix_byte`] bytes, one ASCII digit, the literal `Q~`,
//! then 31-34 [`is_suffix_byte`] bytes (37-40 bytes total), bounded on both
//! sides by a byte outside the suffix alphabet (or the edge of input). There
//! is no leading literal to anchor on, unlike every other provider detector
//! in this module; the `digit` + `Q~` marker itself is specific enough that
//! no surrounding context (`client_secret=`, `clientSecret:`, ...) is
//! required to classify it, matching every other `Specificity::Provider`
//! detector here. A value using the older, unmarked client-secret format
//! Microsoft has since moved away from carries no such marker and is an
//! intentional false negative: it is indistinguishable from ordinary opaque
//! text without one.

use crate::detectors::pattern;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// The literal marker every observed current-format secret carries.
const ANCHOR: &str = "Q~";
/// Bytes required before the digit that itself precedes [`ANCHOR`].
const PREFIX_LEN: usize = 3;
const MIN_SUFFIX_LEN: usize = 31;
const MAX_SUFFIX_LEN: usize = 34;

/// `[A-Za-z0-9_.~]`: the 3 bytes before the digit, and every suffix byte
/// except `-`. Matches gitleaks's `azure-ad-client-secret` charset for that
/// leading run; trufflehog's `spv2.go` additionally allows `-` there, which
/// this detector does not, favoring precision over recall in an already
/// undocumented, community-inferred grammar.
fn is_prefix_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'~')
}

/// `[A-Za-z0-9_.~-]`: the suffix run, which both reference sources agree
/// also accepts `-`.
fn is_suffix_byte(byte: u8) -> bool {
    is_prefix_byte(byte) || byte == b'-'
}

/// Detects a Microsoft Entra application client secret by its undocumented
/// but widely-observed `<3 bytes><digit>Q~<31-34 bytes>` shape.
pub(super) struct MicrosoftEntraClientSecretDetector;

impl Detector for MicrosoftEntraClientSecretDetector {
    fn id(&self) -> &'static str {
        "microsoft-entra-client-secret"
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
                Candidate::new("microsoft_entra_client_secret", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["entra-digit-q-tilde-marker", "bounded-opaque-suffix"]),
            );
        }
        Ok(candidates)
    }
}

/// Finds every non-overlapping match of `<3 bytes><digit>Q~<31-34 bytes>`,
/// left to right. Unlike a prefixed grammar there is no leading literal to
/// search for, so the scan instead advances byte by byte looking for the
/// `Q~` anchor itself, then validates outward from it; a successful match
/// advances the scan past its own end, and a rejected anchor advances by one
/// byte, exactly as [`super::openai`]'s custom scan does for its excluded
/// namespace.
fn scan(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, is_suffix_byte);
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

/// Validates the `<3 bytes><digit>` immediately before `anchor` and the
/// `<31-34 bytes>` run immediately after it, returning the full match span
/// when both hold and neither edge is a truncated slice of a longer run.
///
/// The suffix quantifier is a bounded range, not a minimum: greedily
/// consuming the whole maximal run and rejecting when it falls outside
/// `31..=34` reproduces what a backtracking `{31,34}` regex quantifier does
/// at a boundary it cannot satisfy at any length in range -- it never
/// silently truncates a 40-byte run down to 34.
fn match_at(bytes: &[u8], ends: &[usize], anchor: usize) -> Option<(usize, usize)> {
    let digit_at = anchor.checked_sub(1)?;
    let start = anchor.checked_sub(PREFIX_LEN + 1)?;
    if !bytes[digit_at].is_ascii_digit() {
        return None;
    }
    if !bytes[start..digit_at].iter().copied().all(is_prefix_byte) {
        return None;
    }

    let suffix_start = anchor + ANCHOR.len();
    let available = ends[suffix_start] - suffix_start;
    if !(MIN_SUFFIX_LEN..=MAX_SUFFIX_LEN).contains(&available) {
        return None;
    }

    let end = suffix_start + available;
    pattern::boundary_ok(bytes, start, end, is_suffix_byte).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUFFIX_32: &str = "SYNTHETIC_REVOKED_ENTRA_SECRET_V";

    fn detect(input: &str) -> Vec<Candidate> {
        MicrosoftEntraClientSecretDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_synthetic_fixture() {
        let input = format!("abc8Q~{SUFFIX_32}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "microsoft_entra_client_secret");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn detects_at_the_minimum_and_maximum_suffix_length() {
        for len in [31usize, 34] {
            let suffix = "SYNTHETIC_REVOKED_ENTRA_SECRET_VALUE_PADDING_Z"
                .chars()
                .take(len)
                .collect::<String>();
            assert_eq!(suffix.len(), len);
            let input = format!("abc8Q~{suffix}");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "len={len}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, input.len()).unwrap(),
                "len={len}"
            );
        }
    }

    #[test]
    fn rejects_a_suffix_one_byte_below_the_minimum() {
        let suffix = "SYNTHETIC_REVOKED_ENTRA_SECRET";
        assert_eq!(suffix.len(), 30);
        assert_eq!(detect(&format!("abc8Q~{suffix}")).len(), 0);
    }

    #[test]
    fn rejects_a_suffix_one_byte_above_the_maximum_rather_than_truncating() {
        let suffix = "SYNTHETIC_REVOKED_ENTRA_SECRET_VALUE_PADDING_Z"
            .chars()
            .take(35)
            .collect::<String>();
        assert_eq!(suffix.len(), 35);
        assert_eq!(detect(&format!("abc8Q~{suffix}")).len(), 0);
    }

    #[test]
    fn rejects_a_non_digit_immediately_before_the_marker() {
        assert_eq!(detect(&format!("abcXQ~{SUFFIX_32}")).len(), 0);
    }

    #[test]
    fn rejects_an_anchor_too_close_to_the_start_of_input() {
        assert_eq!(detect(&format!("8Q~{SUFFIX_32}")).len(), 0);
    }

    #[test]
    fn rejects_a_suffix_broken_by_an_out_of_alphabet_byte() {
        let broken = format!("{} {}", &SUFFIX_32[..10], &SUFFIX_32[11..]);
        assert_eq!(detect(&format!("abc8Q~{broken}")).len(), 0);
    }

    #[test]
    fn rejects_the_literal_q_tilde_with_no_preceding_digit() {
        assert_eq!(detect("the Q~ notation is unrelated").len(), 0);
    }

    #[test]
    fn rejects_a_digit_followed_by_q_without_the_tilde() {
        assert_eq!(detect("build revision 8Qa2 shipped").len(), 0);
    }

    #[test]
    fn finds_a_qualified_match_inside_surrounding_context() {
        let input = format!("client_secret=abc8Q~{SUFFIX_32}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find("abc8Q~").unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, input.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("abc8Q~{SUFFIX_32}");
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_anchors() {
        let input = format!("abc8Q~{SUFFIX_32}!{}", "Q~".repeat(10_000));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, 6 + SUFFIX_32.len()).unwrap()
        );
    }
}
