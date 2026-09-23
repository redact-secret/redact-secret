//! Heroku API token detection.
//!
//! Heroku's own documentation
//! (`devcenter.heroku.com/articles/oauth`, observed 2026-09-22) documents
//! two token generations:
//!
//! - **Current (`HRKU-`-prefixed).** Per Heroku's OAuth access token
//!   changelog (`devcenter.heroku.com/changelog-items/2842`, observed
//!   2026-09-22), every OAuth access token granted on or after 2026-04-01 is
//!   prefixed. The `oauth` article states plainly: "Heroku OAuth access
//!   tokens are 65 characters long and prefixed with `HRKU-`", with the
//!   worked example
//!   `HRKU-AALJCYR7SRzPkj9_BGqhi1jAI1J5P4WfD6ITENvdVydAPCnNcAlrMMahHrTo`.
//!   Two independently maintained tools, consulted only as external
//!   behavioral references per `AGENTS.md`, corroborate this exact shape and
//!   additionally fix the two bytes right after the dash to a literal `AA`:
//!
//!   ```text
//!   gitleaks 8.30.1's heroku-api-key-v2 rule:
//!     \b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\x60'"\s;]|\\[nr]|$)
//!   trufflehog 3.97.4's heroku/v2 detector:
//!     \b(HRKU-AA[0-9a-zA-Z_-]{58})\b
//!   ```
//!
//!   The provider's own worked example and both tools agree: a literal
//!   `HRKU-AA` marker (7 bytes), then exactly 58 bytes of
//!   [`pattern::is_alnum_dash`] (`[A-Za-z0-9_-]`), 65 bytes total. This
//!   shape needs no surrounding context, matching every other documented
//!   exact-length literal-prefix shape in this crate
//!   ([`super::postman::POSTMAN`], [`super::additional_providers::NPM`]).
//!
//! - **Legacy (pre-`HRKU-`, a bare UUID).** The same changelog states
//!   existing tokens "continue to work and remain unchanged until
//!   regenerated", so the old, unprefixed shape stays live indefinitely. A
//!   standard `8-4-4-4-12` hex UUID carries no marker of its own -- it is
//!   indistinguishable by structure alone from a Heroku app id, a release
//!   id, or any unrelated UUID. Two independently maintained tools converge
//!   on requiring a case-insensitive `heroku` substring alongside this exact
//!   bare shape and never emit it unconditionally:
//!
//!   ```text
//!   gitleaks 8.30.1's heroku-api-key rule (keyword-gated):
//!     (?i)[\w.-]{0,50}?(?:heroku)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)
//!   trufflehog 3.97.4's heroku/v1 detector (keyword-gated,
//!   Keywords() == ["heroku"]):
//!     \b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b
//!   ```
//!
//!   This detector follows the same corroborated policy: a bare UUID-shaped
//!   run is reported only when its line also carries a case-insensitive
//!   `heroku` substring, at [`Confidence::Medium`] -- the same
//!   weaker-heuristic tier [`super::confluent`]'s own legacy path and
//!   [`super::new_relic`]'s License Key path use, and, like those,
//!   deliberately left out of [`policy::ALWAYS_REDACT_TYPES`] rather than
//!   promoted to an unconditional redact.
//!
//! No code from either tool is reproduced here; this module's matching and
//! context-gating logic is authored independently.
//!
//! ## Out of scope
//!
//! No other Heroku credential form (an app id, a dyno id, a release id, a
//! `netrc` machine-scoped token, an OAuth client secret) is documented or
//! tool-corroborated with its own grammar distinct from the two shapes
//! above, so none is given one here -- the issue's stated exclusion
//! boundary. An ordinary UUID -- an app id, a release id, or any other
//! identifier -- with no `heroku` keyword on the same line is never reported
//! by the legacy detector, and never by the current-format detector
//! regardless of context, since it carries no `HRKU-AA`-prefixed run.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const CURRENT_PREFIX: &str = "HRKU-AA";
/// The documented total length (65) minus the seven-byte [`CURRENT_PREFIX`].
const CURRENT_BODY_LEN: usize = 58;

const CURRENT_SIGNALS: [&str; 2] = ["heroku-documented-prefix", "heroku-documented-length"];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier -- the
/// alphabet is already the widest boundary class in this crate, matching
/// every other `[A-Za-z0-9_-]`-bodied provider shape's own boundary.
const CURRENT_BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// The current, `HRKU-`-prefixed OAuth access token: the literal `HRKU-AA`
/// marker plus exactly 58 bytes of `[A-Za-z0-9_-]`, 65 bytes total,
/// unconditionally [`Confidence::High`] and [`Specificity::Provider`] -- no
/// context needed.
pub(super) const HEROKU_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "heroku-api-key",
    "heroku_api_key",
    &[PrefixShape::exact(
        CURRENT_PREFIX,
        CURRENT_BODY_LEN,
        pattern::is_alnum_dash,
        &CURRENT_SIGNALS,
    )],
    CURRENT_BOUNDARY,
);

const CONTEXT_KEYWORD: &str = "heroku";

/// The legacy shape's total byte length: `8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12`.
const LEGACY_UUID_LEN: usize = 36;

/// The dash offsets a standard UUID fixes, counted from the run's own start.
const UUID_DASH_OFFSETS: [usize; 4] = [8, 13, 18, 23];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, matching
/// [`CURRENT_BOUNDARY`]'s own reasoning.
const LEGACY_BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// Every line of `input` as a byte range excluding the terminating `\n` (a
/// trailing `\r` stays part of the line). Mirrors [`super::confluent::lines`]
/// and [`super::twilio::lines`]; duplicated rather than shared, matching
/// those modules' own "keep context-gating logic self-contained" reasoning.
fn lines(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start > bytes.len() {
            return None;
        }
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        let line = (start, end);
        start = end + 1;
        Some(line)
    })
}

/// `true` when `needle` (ASCII, case-insensitive) occurs anywhere in `line`.
fn line_contains_ci(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    needle.len() <= bytes.len()
        && (0..=bytes.len() - needle.len()).any(|pos| text::starts_with_ci(line, pos, needle))
}

/// Every non-overlapping, boundary-checked bare run of exactly
/// [`LEGACY_UUID_LEN`] `alphabet` bytes, left to right.
fn scan_bare_legacy_runs(
    input: &str,
    alphabet: Alphabet,
    boundary: Alphabet,
) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, alphabet);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !alphabet(bytes[start]) {
            start += 1;
            continue;
        }
        let run_end = ends[start];
        if run_end - start == LEGACY_UUID_LEN
            && pattern::boundary_ok(bytes, start, run_end, boundary)
        {
            matches.push((start, run_end));
        }
        start = run_end;
    }
    matches
}

/// `true` when the matched run has a dash at exactly each of
/// [`UUID_DASH_OFFSETS`] and every other byte is hex -- the internal
/// structure a same-length [`pattern::is_hex_or_dash`] alphabet alone cannot
/// express, since that alphabet accepts a dash at any offset.
fn is_uuid_shape(bytes: &[u8], start: usize, end: usize) -> bool {
    (start..end).all(|index| {
        let offset = index - start;
        if UUID_DASH_OFFSETS.contains(&offset) {
            bytes[index] == b'-'
        } else {
            pattern::is_hex(bytes[index])
        }
    })
}

/// Detects a legacy (pre-`HRKU-`) Heroku API token: a bare UUID-shaped run
/// on the same line as a case-insensitive `heroku` substring. Never emitted
/// without that context; see the module doc.
pub(super) struct HerokuApiKeyLegacyDetector;

impl Detector for HerokuApiKeyLegacyDetector {
    fn id(&self) -> &'static str {
        "heroku-api-key-legacy"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (line_start, line_end) in lines(input) {
            let line = &input[line_start..line_end];
            let raw_matches = scan_bare_legacy_runs(line, pattern::is_hex_or_dash, LEGACY_BOUNDARY);
            if raw_matches.is_empty() || !line_contains_ci(line, CONTEXT_KEYWORD) {
                continue;
            }
            let bytes = line.as_bytes();
            for (relative_start, relative_end) in raw_matches {
                if !is_uuid_shape(bytes, relative_start, relative_end) {
                    continue;
                }
                let Some(range) =
                    ByteRange::new(line_start + relative_start, line_start + relative_end)
                else {
                    continue;
                };
                candidates.push(
                    Candidate::new("heroku_api_key_legacy", Confidence::Medium, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(["heroku-keyword-cooccurrence"]),
                );
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly [`CURRENT_BODY_LEN`] bytes of the documented alphabet.
    /// Locally constructed synthetic value; never provider-issued.
    const CURRENT_BODY: &str = "SYNTHETIC0REVOKED0HerokuOAuthAccessTokenBodyFixture0123456";
    const _: () = assert!(CURRENT_BODY.len() == CURRENT_BODY_LEN);

    /// A standard UUID shape with no `heroku` substring of its own so
    /// keyword-gating tests are clean. Locally constructed synthetic value;
    /// never provider-issued.
    const LEGACY_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const _: () = assert!(LEGACY_UUID.len() == LEGACY_UUID_LEN);

    fn current_token() -> String {
        format!("{CURRENT_PREFIX}{CURRENT_BODY}")
    }

    fn detect_current(input: &str) -> Vec<Candidate> {
        HEROKU_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_legacy(input: &str) -> Vec<Candidate> {
        HerokuApiKeyLegacyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    // -- Current (`HRKU-`-prefixed) detector --------------------------------

    #[test]
    fn detects_the_current_token_with_no_context_needed() {
        let value = current_token();
        let candidates = detect_current(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "heroku_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_current_body_one_byte_short_of_the_documented_length() {
        let short_body = &CURRENT_BODY[..CURRENT_BODY_LEN - 1];
        assert!(detect_current(&format!("{CURRENT_PREFIX}{short_body}")).is_empty());
    }

    #[test]
    fn rejects_a_current_body_one_byte_longer_than_the_documented_length() {
        assert!(detect_current(&format!("{CURRENT_PREFIX}{CURRENT_BODY}a")).is_empty());
    }

    #[test]
    fn rejects_undocumented_near_miss_prefixes() {
        for input in [
            format!("HRKU-AB{CURRENT_BODY}"),
            format!("hrku-aa{CURRENT_BODY}"),
            format!("HRKU{CURRENT_BODY}"),
            format!("HRKU-A{CURRENT_BODY}"),
        ] {
            assert!(detect_current(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(detect_current(&format!("legacy_{}", current_token())).is_empty());
        assert!(detect_current(&format!("{}_backup", current_token())).is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        assert!(
            detect_current(&format!("{CURRENT_PREFIX}{}", "*".repeat(CURRENT_BODY_LEN))).is_empty()
        );
        assert!(detect_current(&format!("{CURRENT_PREFIX}${{HEROKU_API_KEY}}")).is_empty());
    }

    /// The body alphabet is `[A-Za-z0-9_-]`, the same wide alnum-dash class
    /// every other infra-provider exact-length shape in this crate uses
    /// (`super::additional_providers`'s own
    /// `infra_providers_accept_a_doc_style_placeholder_built_from_valid_alphabet_characters`):
    /// an `x`-filled placeholder is built entirely from valid alphabet
    /// characters, so it is indistinguishable from a genuine token and is
    /// accepted, not rejected.
    #[test]
    fn accepts_a_doc_style_x_filled_placeholder_built_from_valid_alphabet_characters() {
        assert_eq!(
            detect_current(&format!("{CURRENT_PREFIX}{}", "x".repeat(CURRENT_BODY_LEN))).len(),
            1
        );
    }

    #[test]
    fn accepts_env_json_yaml_and_quoted_contexts() {
        let value = current_token();
        for input in [
            format!("HEROKU_API_KEY={value}"),
            format!("{{\"apiKey\": \"{value}\"}}"),
            format!("authorization: Bearer {value}"),
            format!("authorization=\"Bearer {value}\""),
        ] {
            let candidates = detect_current(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.rfind(&value).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = current_token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect_current(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = current_token();
        assert_eq!(detect_current(&value), detect_current(&value));
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = current_token();
        let input = format!("{value} {value}");
        assert_eq!(detect_current(&input).len(), 2);
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        let short_body = &CURRENT_BODY[..CURRENT_BODY_LEN - 1];
        let input = format!("{CURRENT_PREFIX}{short_body} ").repeat(10_000);
        assert_eq!(detect_current(&input).len(), 0);
    }

    // -- Legacy (bare UUID, keyword-gated) detector -------------------------

    #[test]
    fn detects_a_legacy_token_alongside_the_heroku_keyword_at_medium_confidence() {
        let input = format!("HEROKU_API_KEY={LEGACY_UUID}");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "heroku_api_key_legacy");
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.rfind(LEGACY_UUID).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LEGACY_UUID.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bare_legacy_token_with_no_context() {
        assert!(detect_legacy(LEGACY_UUID).is_empty());
    }

    #[test]
    fn rejects_an_ordinary_uuid_such_as_an_app_or_release_id() {
        // The issue's stated exclusion boundary: an ordinary UUID (an app
        // id, a release id, or any other identifier) stays clean without
        // provider context.
        for input in [
            format!("app_id={LEGACY_UUID}"),
            format!("release={LEGACY_UUID}"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_a_legacy_token_whose_context_is_on_a_different_line() {
        let input = format!("# heroku account token\n{LEGACY_UUID}\n");
        assert!(detect_legacy(&input).is_empty());
    }

    #[test]
    fn rejects_a_legacy_body_one_byte_short_or_long() {
        assert!(
            detect_legacy(&format!("heroku {}", &LEGACY_UUID[..LEGACY_UUID_LEN - 1])).is_empty()
        );
        assert!(detect_legacy(&format!("heroku {LEGACY_UUID}a")).is_empty());
    }

    #[test]
    fn rejects_a_uuid_with_a_dash_at_the_wrong_offset() {
        // The first dash lands one byte early; the run is still the
        // documented total length, but the structural post-check must
        // still reject it.
        let malformed = format!(
            "{}-{}0",
            &LEGACY_UUID[..UUID_DASH_OFFSETS[0] - 1],
            &LEGACY_UUID[UUID_DASH_OFFSETS[0] + 1..]
        );
        assert_eq!(malformed.len(), LEGACY_UUID_LEN);
        assert!(detect_legacy(&format!("heroku {malformed}")).is_empty());
    }

    #[test]
    fn rejects_a_non_hex_letter_in_the_uuid_body() {
        let mut malformed = LEGACY_UUID.to_string();
        malformed.replace_range(0..1, "g");
        assert!(detect_legacy(&format!("heroku {malformed}")).is_empty());
    }

    #[test]
    fn matches_heroku_keyword_case_insensitively() {
        for keyword in ["Heroku", "HEROKU", "heroku"] {
            let input = format!("{keyword}_API_KEY={LEGACY_UUID}");
            assert_eq!(detect_legacy(&input).len(), 1, "{keyword}");
        }
    }

    #[test]
    fn finds_a_qualified_legacy_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nheroku {LEGACY_UUID}\r\n");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(LEGACY_UUID).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LEGACY_UUID.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_legacy_findings_across_repeated_calls() {
        let input = format!("heroku {LEGACY_UUID}");
        assert_eq!(detect_legacy(&input), detect_legacy(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        let input = format!("{LEGACY_UUID} ").repeat(10_000);
        assert_eq!(detect_legacy(&input).len(), 0);
    }
}
