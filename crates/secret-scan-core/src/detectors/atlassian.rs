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
//! token is matched unconditionally by construction. The run may be
//! followed by the fixed `=` + 8-hex tail described below, which then
//! belongs to the match.
//!
//! The body alphabet deliberately excludes `=`, even though both reference
//! scanners' patterns allow it appearing anywhere in the body: including it
//! in the *boundary* alphabet would make the ubiquitous `KEY=<token>`
//! assignment delimiter immediately preceding a real token look like a
//! truncated slice of a longer run and reject the whole match.
//!
//! Real 192-byte tokens do carry exactly one `=`, as a fixed tail: `=`
//! followed by 8 uppercase hexadecimal bytes (read as a CRC32 by
//! `CredSweeper`; the tail's *position and shape* is the consensus of issue
//! #643's research and the benchmark contract widened in
//! redact-secret-benchmarks#238). Issue #741: the run above stops at that
//! `=`, so a match that ended there left the 9-byte tail outside the
//! finding at `high`/`redact` -- a partial redaction. After the run, this
//! detector therefore extends the span over an immediately following
//! [`TAIL_SEPARATOR`] plus exactly [`TAIL_HEX_LEN`] bytes of `[0-9A-F]`,
//! provided the byte after them is neither a body byte nor another `=` (so
//! a longer or differently-shaped tail is never half-absorbed). The tail's
//! value is not validated -- only its shape extends the span. A token with
//! no such tail is matched exactly as before, and a tail that does not fit
//! (lowercase, 7 or 9 hex bytes) leaves the span at the body run rather
//! than guessing.
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

/// The byte that opens the fixed checksum-shaped tail of a 192-byte token.
const TAIL_SEPARATOR: u8 = b'=';

/// The number of uppercase hexadecimal bytes after [`TAIL_SEPARATOR`].
const TAIL_HEX_LEN: usize = 8;

/// `true` for `[0-9A-F]`.
fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

/// The end of the match that begins with a body run ending at `end`: `end`
/// extended past a `=` + 8-uppercase-hex tail when exactly that tail
/// follows and is itself bounded, otherwise `end` unchanged.
fn extend_over_tail(bytes: &[u8], end: usize) -> usize {
    let hex_start = end + 1;
    let tail_end = hex_start + TAIL_HEX_LEN;
    if bytes.get(end) != Some(&TAIL_SEPARATOR) || bytes.len() < tail_end {
        return end;
    }
    if !bytes[hex_start..tail_end].iter().copied().all(is_upper_hex) {
        return end;
    }
    match bytes.get(tail_end) {
        Some(&next) if pattern::is_alnum_dash(next) || next == TAIL_SEPARATOR => end,
        _ => tail_end,
    }
}

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
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            &[PREFIX],
            RunLength::AtLeast(MIN_BODY_LEN),
            pattern::is_alnum_dash,
            pattern::is_alnum_dash,
        ) {
            let end = extend_over_tail(bytes, end);
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
    fn stops_at_an_equals_sign_not_followed_by_the_documented_tail() {
        for tail in [
            "=CHECKSUMSUFFIX",
            "=0A1B2C3",
            "=0A1B2C3D4",
            "=0a1b2c3d",
            "=0A1B2C3D-",
            "=0A1B2C3D=",
        ] {
            let input = format!("{PREFIX}{BODY_100}{tail}");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{tail}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, PREFIX.len() + BODY_100.len()).unwrap(),
                "{tail}"
            );
        }
    }

    #[test]
    fn includes_the_equals_and_eight_uppercase_hex_tail_in_the_span() {
        // Issue #741: a 192-byte token ends in `=` + 8 uppercase hex.
        for (before, after) in [
            ("", ""),
            ("ATLASSIAN_API_TOKEN=", "\n"),
            ("{\"apiToken\": \"", "\"}"),
            ("user@example.test:", " "),
        ] {
            let token = format!("{PREFIX}{BODY_100}=0A1B2C3D");
            let input = format!("{before}{token}{after}");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(before.len(), before.len() + token.len()).unwrap(),
                "{input}"
            );
        }
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
