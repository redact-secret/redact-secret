//! Netlify personal access token detection.
//!
//! Netlify's own API-guide documentation
//! (`https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/`)
//! describes only how to generate a personal access token (PAT) through the
//! UI and how to send it (`Authorization: Bearer <token>`); it publishes no
//! character-class grammar. The grammar below instead comes from Netlify's
//! own token-format announcement
//! (`https://answers.netlify.com/t/change-to-the-netlify-authentication-token-format/106146`,
//! 2023-11-07), which states: "All Netlify authentication tokens will start
//! with a `nf` prefix followed by a single identifying character. They are:
//! `nfp` for Personal Access Tokens[, ...]" and that token storage
//! "capacity" needed to increase "to 40 characters." Consulted only as an
//! external behavioral reference per `AGENTS.md`, gitleaks 8.30.1's
//! `netlify-access-token` rule and trufflehog 3.97.4's independent
//! `netlify/v2` detector both converge on exactly `nfp_` followed by 36
//! bytes of `[A-Za-z0-9_]` -- 40 bytes total, matching Netlify's own stated
//! capacity; no code from either project is reproduced here, and this
//! module's matching logic is authored independently.
//!
//! ## Grammar (frozen before implementation, per issue #311)
//!
//! Personal Access Token: the literal `nfp_`, then exactly 36 bytes of
//! [`pattern::is_alnum_underscore`] (`[A-Za-z0-9_]`) -- 40 bytes total,
//! bounded on both sides by a byte outside `[A-Za-z0-9_-]` (wider than the
//! match alphabet, so a directly dash-joined wider identifier is rejected
//! outright rather than truncated to the documented shape, mirroring
//! [`super::linear`]'s own prefix/boundary-widening precedent). `High`
//! confidence, `Provider` specificity, always redacted -- the documented
//! prefix and exact length together are specific enough to be actionable on
//! their own, the same class every other exact-length prefixed detector in
//! this registry gets.
//!
//! A candidate that is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded: the alphabet
//! contains characters (`X`, `0`, `_`, ...) a masked placeholder commonly
//! repeats, and this format has no internal checksum to otherwise reject one.
//!
//! ## Known unsupported variants
//!
//! Per the issue's own scope note ("Cover documented PAT forms with
//! reliable provider context where shape is ambiguous... Exclude site/
//! account/deploy IDs and preview URLs. Build-hook URLs are a separate
//! bearer-secret format requiring an explicit scope decision."):
//!
//! - **Pre-format-change (pre-2023-11-07) unprefixed tokens.** The
//!   announcement itself states "existing authentication tokens remain
//!   unaffected," and no official grammar was ever published for them.
//!   trufflehog's own legacy `netlify/v1` detector (`[A-Za-z0-9_-]{43,45}`,
//!   keyword-gated on `netlify`) and gitleaks's `netlify-access-token` rule
//!   (a keyword-gated `[40,46]`-byte body) do not even agree with each
//!   other on the exact bounds, and — more importantly — that legacy shape
//!   is not specific to a personal access token at all: every pre-2023
//!   Netlify token class (CLI, OAuth, app, build, and personal access
//!   alike) shared the identical unprefixed shape. Emitting a
//!   `netlify_personal_access_token` finding for a value that is, by
//!   construction, equally likely to be one of those other four credential
//!   classes would mislabel the finding, so this is left a documented gap
//!   rather than implemented as a lower-confidence, context-gated shape the
//!   way [`super::twilio`] or [`super::new_relic`] handle their own
//!   genuinely ambiguous-but-single-credential-class formats. A qualified
//!   `name=value` assignment of one still gets a lower-confidence, lower-
//!   specificity contextual finding through the existing generic-token
//!   path.
//! - **The other four new-format Netlify token classes**: `nfc_` (Netlify
//!   CLI), `nfo_` (OAuth access), `nfu_` (app.netlify.com), and `nfb_`
//!   (build) tokens share this module's `nf` + identifying-character
//!   scheme but are not personal access tokens, and are out of this
//!   issue's explicit scope.
//! - **Build-hook URLs**: explicitly called out in the issue as "a separate
//!   bearer-secret format requiring an explicit scope decision," not
//!   implemented here.
//! - **Site ID / Project ID, account ID, and deploy preview URLs**:
//!   excluded per scope. Netlify's own API guide (linked above) documents
//!   these as unrelated identifiers (a `site_id` path segment, an
//!   `account_id` queried by slug, a deploy URL) with no `nfp_`-prefixed
//!   shape, so no additional exclusion logic is needed to keep them from
//!   matching this grammar.

use crate::detectors::pattern::{self, RunLength};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const PREFIX: &str = "nfp_";
/// The reviewed contract's exact body length (provider capacity statement +
/// tool agreement).
const BODY_LEN: usize = 36;

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, even
/// though the match alphabet itself excludes `-`: widening the boundary
/// check past the match alphabet is what rejects a directly dash-joined
/// wider identifier outright instead of truncating to the documented shape,
/// the same precedent [`super::linear`]'s own prefixed grammar sets.
fn boundary(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// Detects a Netlify personal access token by its documented `nfp_` prefix
/// and exact 36-byte alphanumeric-underscore body.
pub(super) struct NetlifyPersonalAccessTokenDetector;

impl Detector for NetlifyPersonalAccessTokenDetector {
    fn id(&self) -> &'static str {
        "netlify-token"
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
            RunLength::Exact(BODY_LEN),
            pattern::is_alnum_underscore,
            boundary,
        ) {
            if text::is_repeated_character_filler(&input[start + PREFIX.len()..end]) {
                continue;
            }
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("netlify_personal_access_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals([
                        "netlify-documented-prefix",
                        "exact-length-alnum-underscore-body",
                    ]),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly [`BODY_LEN`] bytes from `[A-Za-z0-9_]`: the documented `nfp_`
    /// body length (issue #311). Locally constructed synthetic value; never
    /// provider-issued.
    const BODY: &str = "SYNTHETIC_REVOKED_NETLIFY_PAT_BODY01";
    const _: () = assert!(BODY.len() == BODY_LEN);

    fn detect(input: &str) -> Vec<Candidate> {
        NetlifyPersonalAccessTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn token() -> String {
        format!("{PREFIX}{BODY}")
    }

    #[test]
    fn detects_the_token_with_provider_specificity() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "netlify_personal_access_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_body_one_byte_short_of_the_documented_length() {
        let short_body = &BODY[..BODY_LEN - 1];
        assert!(detect(&format!("{PREFIX}{short_body}")).is_empty());
    }

    /// A run one byte longer than the documented length is rejected via the
    /// boundary check rather than truncated to the documented shape, the
    /// same precedent `linear-token` and `new-relic-user-api-key` already
    /// set for their own exact-length grammars.
    #[test]
    fn rejects_a_body_one_byte_longer_than_the_documented_length() {
        assert!(detect(&format!("{PREFIX}{BODY}a")).is_empty());
    }

    #[test]
    fn rejects_a_body_containing_a_byte_outside_the_documented_alphabet() {
        for byte in ['-', '.', '+', '/'] {
            let mut body = BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            assert!(detect(&format!("{PREFIX}{body}")).is_empty());
        }
    }

    #[test]
    fn rejects_an_undocumented_prefix() {
        assert!(detect(&format!("nfc_{BODY}")).is_empty());
        assert!(detect(&format!("nfo_{BODY}")).is_empty());
        assert!(detect(&format!("nfu_{BODY}")).is_empty());
        assert!(detect(&format!("nfb_{BODY}")).is_empty());
        assert!(detect(&format!("nf_{BODY}")).is_empty());
    }

    #[test]
    fn rejects_a_bare_unprefixed_legacy_shaped_value() {
        // A 43-byte bare run: inside the legacy trufflehog v1 range, but
        // this module never emits for the undocumented legacy shape (see
        // the module doc's "Known unsupported variants").
        assert!(detect(&"a".repeat(43)).is_empty());
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(detect(&format!("legacy{}", token())).is_empty());
    }

    #[test]
    fn rejects_the_value_embedded_in_a_wider_identifier_leading_trailing_or_dash_joined() {
        let value = token();
        assert!(detect(&format!("legacy{value}")).is_empty());
        assert!(detect(&format!("{value}_backup")).is_empty());
        assert!(detect(&format!("{value}-1")).is_empty());
    }

    #[test]
    fn rejects_a_percent_encoded_delimiter_lookalike() {
        assert!(detect(&format!("nfp%5F{BODY}")).is_empty());
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
    fn rejects_a_masked_value() {
        assert!(detect(&format!("{PREFIX}{}", "X".repeat(BODY_LEN))).is_empty());
        assert!(detect(&format!("{PREFIX}${{NETLIFY_AUTH_TOKEN}}")).is_empty());
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = token();
        let input = format!("{value} {value}");
        assert_eq!(detect(&input).len(), 2);
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = token();
        assert_eq!(detect(&value), detect(&value));
    }

    /// A pathological run of near-miss prefixes must not make the scan
    /// quadratic: every occurrence has a body one byte short of the
    /// documented length, so none matches.
    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        let short_body = &BODY[..BODY_LEN - 1];
        let input = format!("{PREFIX}{short_body} ").repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
