//! Linear API key and OAuth access token detection.
//!
//! The reviewed API-key grammar (issue #374, following the frozen precision
//! contract from issue #367, `docs/audits/evidence/367/precision-contracts.json`,
//! `families.linear-token`) is `lin_api_[A-Za-z0-9]{40}`: gitleaks 8.30.1's
//! `linear-api-key` and trufflehog 3.97.4's `linearapi` rules independently
//! pin the body to an exact 40-byte alphanumeric run, with no `_`/`-`. A
//! body one byte short of 40 is an intentional false negative.
//!
//! Neither tool documents a `lin_oauth_` rule, and Linear's own OAuth
//! documentation shows only a bare 64-character hex access token with no
//! distinguishing prefix at all, so the 40-byte API-key length must not be
//! reused for it. `lin_oauth_` is instead a separate interim guard, pending
//! (T0) in the benchmark corpus: a documented prefix followed by a run of 20
//! or more `[A-Za-z0-9_-]` bytes.
//!
//! The two prefixes need different suffix alphabets and different finding
//! signals, both of which a [`PrefixShape`] carries per shape, so this is
//! the same table-driven
//! [`super::additional_providers::KnownFormatProviderDetector`] every other
//! provider in that module uses: `lin_api_` and `lin_oauth_` are matched in
//! the same left-to-right, longest-prefix pass instead of two passes merged
//! by position afterward.
//!
//! Issue #551: `lin_oauth_` used to keep beta.4's open floor
//! (`RunLength::AtLeast`, no documented maximum), matched against
//! `[A-Za-z0-9_-]` -- the identical alphabet [`BOUNDARY`] itself checks. A
//! run computed that way is already maximal by construction, so the byte
//! immediately past it can never belong to that same alphabet, and
//! `pattern::boundary_ok`'s trailing check is structurally unable to fire: a
//! directly-glued wider identifier (`..._backup`, `...-1`) was silently
//! absorbed into the match as "more opaque secret" rather than tripping the
//! boundary rule every other provider in this crate relies on. The same
//! defect affected every other still-open-floor Slack prefix
//! (`super::slack`). The shared fix is the one every reviewed-contract
//! sibling in `additional_providers.rs` already uses: an exact length, so
//! the boundary check has bytes left over to inspect. A body longer than
//! the unchanged 20-byte floor is now an intentional false negative until a
//! reviewed contract establishes a real maximum -- the same tradeoff
//! `docker-token` (#370), `openai-token` (#368), `huggingface-token`
//! (#372), and `cloudflare-token` (#373) each already accepted when they
//! moved off this identical open-floor shape.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, Alphabet, PrefixShape};

const API_PREFIX: &str = "lin_api_";
/// The reviewed contract's exact body length (tool-agreement).
const API_BODY_LEN: usize = 40;
/// Both tools agree the body excludes `_`/`-`, an evidence-backed exclusion.
const API_ALPHABET: Alphabet = pattern::is_alnum;
const API_SIGNALS: [&str; 2] = ["linear-documented-prefix", "base62-exact-length"];

/// `lin_oauth_`: no consulted provider or tool source shows this prefix's
/// grammar (the provider's own OAuth example is a bare hex string), so it
/// stays a support-policy interim guard rather than an evidence-backed
/// contract. Issue #551: the guard's beta.4 open floor is now an exact
/// length (see the module doc), so this is the guard's whole body length,
/// not merely its minimum.
const OAUTH_PREFIX: &str = "lin_oauth_";
const OAUTH_MIN_LEN: usize = 20;
const OAUTH_ALPHABET: Alphabet = pattern::is_alnum_dash;
const OAUTH_SIGNALS: [&str; 2] = ["linear-scannable-prefix", "opaque-suffix"];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier. Every
/// contract and the interim guard alike share this boundary rule.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// Requires the `lin_api_` API key to carry its full reviewed 40-byte body;
/// `lin_oauth_` keeps its interim guard, now at an exact 20-byte length
/// (issue #551). An undocumented segment name in place of `api`/`oauth` is
/// an intentional false negative.
pub(super) const LINEAR: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "linear-token",
    "linear_token",
    &[
        PrefixShape::exact(API_PREFIX, API_BODY_LEN, API_ALPHABET, &API_SIGNALS),
        PrefixShape::exact(OAUTH_PREFIX, OAUTH_MIN_LEN, OAUTH_ALPHABET, &OAUTH_SIGNALS),
    ],
    BOUNDARY,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

    /// Exactly [`API_BODY_LEN`] bytes from `[A-Za-z0-9]`: the documented
    /// `lin_api_` body length (issue #374). Locally constructed synthetic
    /// value; never provider-issued.
    const API_BODY: &str = "SYNTHETICREVOKEDLINEARAPITOKENVALUE01234";
    const _: () = assert!(API_BODY.len() == API_BODY_LEN);
    /// Exactly [`OAUTH_MIN_LEN`] bytes: the `lin_oauth_` interim guard's
    /// whole body length since issue #551 (previously just its floor).
    const OAUTH_BODY: &str = "SYNTHETICREVOKED0001";
    const _: () = assert!(OAUTH_BODY.len() == OAUTH_MIN_LEN);

    fn detect(input: &str) -> Vec<Candidate> {
        LINEAR
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn api_token() -> String {
        format!("{API_PREFIX}{API_BODY}")
    }

    fn oauth_token() -> String {
        format!("{OAUTH_PREFIX}{OAUTH_BODY}")
    }

    #[test]
    fn detects_the_api_key_with_provider_specificity() {
        let value = api_token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "linear_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_oauth_interim_guard_with_provider_specificity() {
        let value = oauth_token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "linear_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    /// Issue #374: the beta.4 `linear-token-api-plain-twin` regression -- a
    /// body one byte short of the documented 40-byte length.
    #[test]
    fn rejects_an_api_body_one_byte_short_of_the_documented_length() {
        let short_body = &API_BODY[..API_BODY_LEN - 1];
        assert!(detect(&format!("{API_PREFIX}{short_body}")).is_empty());
    }

    /// A run one byte longer than the documented length is rejected via the
    /// boundary check rather than truncated to the documented shape, the
    /// same precedent `docker-token` and `huggingface-token` already set for
    /// their own exact-length grammars.
    #[test]
    fn rejects_an_api_body_one_byte_longer_than_the_documented_length() {
        assert!(detect(&format!("{API_PREFIX}{API_BODY}a")).is_empty());
    }

    /// Both consulted sources agree the API-key body excludes `_`/`-`; a
    /// byte outside `[A-Za-z0-9]` breaks the alphanumeric run before the
    /// documented length is reached, rather than being tolerated as it would
    /// under the retired shared shape.
    #[test]
    fn rejects_an_api_body_containing_underscore_or_dash() {
        for byte in ['_', '-'] {
            let mut body = API_BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            assert!(detect(&format!("{API_PREFIX}{body}")).is_empty());
        }
    }

    /// The `lin_oauth_` interim guard keeps beta.4's underscore/dash-inclusive
    /// alphabet unchanged, but issue #551 turns its 20-byte floor into an
    /// exact length: a 19-byte body stays a false negative as before, and a
    /// body at exactly 20 bytes still matches in full.
    #[test]
    fn oauth_requires_exactly_the_beta4_twenty_byte_length() {
        assert!(detect(&format!("{OAUTH_PREFIX}{}", "x".repeat(19))).is_empty());
        let value = format!("{OAUTH_PREFIX}{}", "x_y-z".repeat(4));
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    /// Issue #551: before this fix, `lin_oauth_`'s open floor (`RunLength::
    /// AtLeast`) matched any run of 20 or more bytes in full, so a body
    /// longer than the floor was indistinguishable from a directly-glued
    /// wider identifier -- exactly the shared boundary defect this issue
    /// closes. A body past the now-exact 20-byte length is an intentional
    /// false negative until a reviewed contract establishes a real maximum.
    #[test]
    fn oauth_rejects_a_body_longer_than_the_exact_twenty_byte_length() {
        for body in ["x".repeat(21), "x".repeat(200), "x_y-z".repeat(5)] {
            assert!(detect(&format!("{OAUTH_PREFIX}{body}")).is_empty(), "{body}");
        }
    }

    #[test]
    fn detects_every_variant_in_the_same_input_without_one_suppressing_another() {
        let api = api_token();
        let oauth = oauth_token();
        let input = format!("{api}\n{oauth}\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].range(), ByteRange::new(0, api.len()).unwrap());
        let oauth_start = api.len() + 1;
        assert_eq!(
            candidates[1].range(),
            ByteRange::new(oauth_start, oauth_start + oauth.len()).unwrap()
        );
    }

    /// An undocumented segment name in place of `api`/`oauth` is an
    /// intentional false negative, not a fuzzy match on the shared `lin_`
    /// namespace.
    #[test]
    fn rejects_an_undocumented_segment_name() {
        assert!(detect(&format!("lin_scim_{API_BODY}")).is_empty());
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(detect(&format!("legacy{}", api_token())).is_empty());
        assert!(detect(&format!("legacy{}", oauth_token())).is_empty());
    }

    /// Issue #551: the shared boundary/delimiter regression set, mirrored
    /// from `digitalocean-token`'s existing leading/trailing/dash
    /// identifier-embedding fixtures, for both `linear-token` shapes. The
    /// API key already passed every one of these (its exact 40-byte
    /// alphanumeric body always leaves the boundary check something to
    /// inspect); `lin_oauth_` only passes now that its own floor is exact
    /// too (see the module doc).
    #[test]
    fn rejects_every_shape_embedded_in_a_wider_identifier_leading_trailing_or_dash_joined() {
        for value in [api_token(), oauth_token()] {
            assert!(detect(&format!("legacy{value}")).is_empty(), "{value}");
            assert!(detect(&format!("{value}_backup")).is_empty(), "{value}");
            assert!(detect(&format!("{value}-1")).is_empty(), "{value}");
        }
    }

    #[test]
    fn rejects_a_percent_encoded_delimiter_lookalike() {
        assert!(detect(&format!("lin%5Fapi_{API_BODY}")).is_empty());
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        for value in [api_token(), oauth_token()] {
            let input = format!("({value}).");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{value}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(1, value.len() + 1).unwrap(),
                "{value}"
            );
        }
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        for value in [api_token(), oauth_token()] {
            let input = format!("{value} {value}");
            assert_eq!(detect(&input).len(), 2, "{value}");
        }
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        for value in [api_token(), oauth_token()] {
            let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{value}");
            let start = input.find(&value).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap(),
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_a_masked_value() {
        assert!(detect(&format!("{API_PREFIX}{}", "*".repeat(API_BODY_LEN))).is_empty());
        assert!(detect(&format!("{OAUTH_PREFIX}${{LINEAR_OAUTH_TOKEN}}")).is_empty());
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = api_token();
        assert_eq!(detect(&value), detect(&value));
    }

    /// A pathological run of near-miss API prefixes must not make the scan
    /// quadratic: every occurrence has a body one byte short of the
    /// documented length, so none matches.
    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        let short_body = &API_BODY[..API_BODY_LEN - 1];
        let input = format!("{API_PREFIX}{short_body} ").repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
