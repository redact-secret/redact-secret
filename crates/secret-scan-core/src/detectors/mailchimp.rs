//! Mailchimp Marketing API key detection.
//!
//! Mailchimp's own documentation
//! (`mailchimp.com/developer/marketing/docs/fundamentals/`, observed
//! 2026-09-23) states the key format only through a worked example: "if your
//! API key is `0123456789abcdef0123456789abcde-us6`, then the data center
//! subdomain is `us6`". The page never states an exact character count or
//! alphabet in prose, and the example body itself (31 hex bytes, one short
//! of the length below) is documentation-example noise, not a stated
//! contract -- the same category of gap `super::postman`'s own module doc
//! treats a silent or inconsistent provider page as. With the provider's
//! prose silent, the reviewed grammar rests on the two external tools the
//! issue names, consulted only as external behavioral references per
//! `AGENTS.md`; no code from either project is reproduced here:
//!
//! - gitleaks 8.30.1's `mailchimp-api-key` rule requires a `mailchimp`
//!   keyword within 50 bytes before an assignment operator, then
//!   `([a-f0-9]{32}-us\d\d)` -- a 32-byte hex body, a literal `-us`, and
//!   **exactly two** digits.
//! - trufflehog 3.97.4's `mailchimp` detector matches
//!   `[0-9a-f]{32}-us[0-9]{1,2}` anywhere, with no keyword requirement (its
//!   `-us` keyword is only a chunk pre-filter, not part of the matched
//!   grammar) and **one or two** digits.
//!
//! Both tools agree on the 32-byte lowercase-hex body and the literal `-us`
//! separator. They disagree on the digit count, and gitleaks' own
//! two-digit-only reading is contradicted by the provider's own worked
//! example above (`-us6`, one digit) -- so, per the "adopt the more
//! specific, evidence-backed shape" reasoning `super::postman`'s own module
//! doc already applies (there in the other direction, toward the narrower
//! tool), here the *broader* shape is the one the provider's own example
//! corroborates: trufflehog's one-or-two-digit range. Digit count is
//! therefore [`MIN_DATACENTER_DIGITS`]..=[`MAX_DATACENTER_DIGITS`], not
//! gitleaks' fixed two.
//!
//! ## Grammar (frozen before implementation, per issue #313)
//!
//! A bare run of exactly [`KEY_HEX_LEN`] [`is_lower_hex`] (`[0-9a-f]`) bytes,
//! immediately followed by the literal `-us`, then a run of
//! [`MIN_DATACENTER_DIGITS`] to [`MAX_DATACENTER_DIGITS`] ASCII digits
//! (greedily consumed, so a three-digit run never matches a two-digit
//! prefix of itself), bounded on both sides by a byte outside
//! [`pattern::is_alnum_dash`] -- wider than the match alphabet on the left so
//! an adjacent letter or a joining dash still rejects a truncated slice of a
//! longer identifier, and excluding a trailing dash on the right so a value
//! embedded in a longer dash-joined slug is not misread as standalone,
//! mirroring [`super::postman`]'s own `is_alnum_dash` boundary choice for
//! its own dash-containing shape.
//!
//! Unlike Postman's `PMAK-` prefix, neither the bare 32-byte hex body nor
//! its generic-looking `-us<N>` datacenter suffix names Mailchimp on its own
//! -- the same class of ambiguity `super::new_relic`'s License Key format
//! documents for its own bare hex value, and gitleaks' independent choice to
//! gate its rule on a same-line `mailchimp` keyword is corroborating
//! evidence that the shape alone is not considered specific enough in
//! practice. Per the issue's own "ambiguous unprefixed values require
//! reliable context" instruction, this detector requires a case-insensitive
//! `mailchimp` substring ([`CONTEXT_KEYWORD`]) anywhere on the same line --
//! the same "same line" scope [`super::new_relic`] and [`super::twilio`]
//! already use for their own bare-hex formats, for the same
//! incremental-consistency reason documented there. `Medium` confidence,
//! `Provider` specificity, confidence-gated (not in `ALWAYS_REDACT_TYPES`)
//! -- there is no paired-identifier signal available here the way
//! [`super::twilio`]'s Account SID/API Key SID give its own bare formats a
//! `High`-confidence tier, so this format never rises above `Medium`, the
//! same reasoning [`super::new_relic`]'s License Key already documents.
//!
//! A candidate whose hex body is a single repeated character
//! ([`text::is_repeated_character_filler`]) is excluded: the alphabet
//! contains characters (`0`, ...) a masked placeholder commonly repeats, and
//! this format has no structural marker of its own strong enough to keep a
//! value like `mailchimp 00000000000000000000000000000000-us1` from
//! matching the bare alphabet otherwise, the same precedent
//! [`super::new_relic`] and [`super::twilio`] already establish.
//!
//! ## Scope
//!
//! Per the issue's stated boundary ("Exclude audience/list/campaign IDs,
//! ordinary hex hashes, public URLs, and suffix-only strings"):
//!
//! - A Mailchimp audience/list/campaign id (a short alphanumeric id,
//!   documented as far shorter than 32 bytes) never satisfies the exact
//!   32-byte hex body and is not classified.
//! - A bare 32-byte hex value with no `-us<N>` suffix -- even alongside a
//!   `mailchimp` keyword -- is not classified: the suffix is part of the
//!   documented shape itself, not an optional decoration, so a value
//!   missing it is an intentional false negative, not a fuzzy match against
//!   a shorter shape (the same "no code from either project" class of
//!   discipline `super::postman`'s own module doc applies to its own
//!   internal-dash post-check).
//! - A bare `-us<N>` suffix with no preceding hex body ("suffix-only") is
//!   never classified: the grammar always anchors on the 32-byte hex run
//!   first.
//! - No Mandrill-specific grammar is given here: Mandrill's transactional
//!   email API is a separate product from Mailchimp Marketing, not named by
//!   this issue, and out of scope.
//!
//! ## Consequences and known gaps
//!
//! - A key with no `mailchimp` keyword anywhere on its own line goes
//!   undetected -- the same accepted tradeoff [`super::new_relic`]'s own
//!   License Key already carries.
//! - A benign 32-byte lowercase-hex value immediately followed by a
//!   coincidental `-us<N>` (for example a region-sharded resource id) that
//!   happens to share a line with the word "mailchimp" would false
//!   positive; this is the same class of risk every other keyword-gated
//!   bare-format detector in this registry already accepts.

use crate::detectors::pattern::{self, Alphabet};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const KEY_HEX_LEN: usize = 32;
const DATACENTER_LITERAL: &str = "-us";
const MIN_DATACENTER_DIGITS: usize = 1;
const MAX_DATACENTER_DIGITS: usize = 2;

/// Mailchimp's own product name, case-insensitively, the same substring
/// gitleaks' independent `mailchimp-api-key` rule keys its own keyword gate
/// on, for a same-line comment such as `# Mailchimp API key: <value>`.
const CONTEXT_KEYWORD: &str = "mailchimp";

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, the same
/// boundary rule [`super::postman`] uses for its own dash-containing shape.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// `[0-9a-f]`: the documented worked example's alphabet, lowercase only.
/// Matches [`super::new_relic`]'s own `is_lower_hex`, which documents the
/// same rationale: an uppercase-hex run is not a coincidental case variant
/// of this format, it is a structurally different value.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte <= b'f')
}

/// Every line of `input` as a byte range, excluding the terminating `\n`
/// itself (a trailing `\r` stays part of the line). Mirrors
/// [`super::new_relic`]'s own `lines` helper, which documents why "line" is
/// the right unit: it is the same processing unit the incremental sanitizer
/// hands a detector, so whole-input and incremental scanning stay
/// behaviorally identical.
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

/// `true` when [`CONTEXT_KEYWORD`] occurs (case-insensitively) anywhere in
/// `line`.
fn line_has_context_keyword(line: &str) -> bool {
    let bytes = line.as_bytes();
    let needle_len = CONTEXT_KEYWORD.len();
    needle_len <= bytes.len()
        && (0..=bytes.len() - needle_len)
            .any(|pos| text::starts_with_ci(line, pos, CONTEXT_KEYWORD))
}

/// Returns the end offset (relative to `bytes`) of a valid
/// `-us<MIN_DATACENTER_DIGITS..=MAX_DATACENTER_DIGITS digits>` datacenter
/// suffix starting at `hex_end`, or `None` if the literal is absent or the
/// digit run is the wrong length. The digit run is consumed greedily, so a
/// three-digit run (`-us123`) never matches as a two-digit suffix followed
/// by a stray digit.
fn match_datacenter_suffix(bytes: &[u8], hex_end: usize) -> Option<usize> {
    let literal = DATACENTER_LITERAL.as_bytes();
    let literal_end = hex_end + literal.len();
    if literal_end > bytes.len() || &bytes[hex_end..literal_end] != literal {
        return None;
    }
    let mut digits_end = literal_end;
    while digits_end < bytes.len() && bytes[digits_end].is_ascii_digit() {
        digits_end += 1;
    }
    let digit_count = digits_end - literal_end;
    (MIN_DATACENTER_DIGITS..=MAX_DATACENTER_DIGITS)
        .contains(&digit_count)
        .then_some(digits_end)
}

/// Detects a Mailchimp Marketing API key: a bare 32-byte lowercase-hex run
/// immediately followed by a `-us<1-2 digits>` datacenter suffix, on a line
/// that also carries [`CONTEXT_KEYWORD`].
pub(super) struct MailchimpMarketingApiKeyDetector;

impl Detector for MailchimpMarketingApiKeyDetector {
    fn id(&self) -> &'static str {
        "mailchimp-api-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (line_start, line_end) in lines(input) {
            let line = &input[line_start..line_end];
            if !line_has_context_keyword(line) {
                continue;
            }

            let bytes = line.as_bytes();
            let ends = pattern::run_ends(bytes, is_lower_hex);
            let mut start = 0usize;
            while start < bytes.len() {
                if !is_lower_hex(bytes[start]) {
                    start += 1;
                    continue;
                }
                let hex_end = ends[start];
                if hex_end - start == KEY_HEX_LEN
                    && let Some(full_end) = match_datacenter_suffix(bytes, hex_end)
                    && pattern::boundary_ok(bytes, start, full_end, BOUNDARY)
                    && !text::is_repeated_character_filler(&line[start..hex_end])
                    && let Some(range) = ByteRange::new(line_start + start, line_start + full_end)
                {
                    let (confidence, context_signal) =
                        if text::is_provider_named_assignment(line, start, &[CONTEXT_KEYWORD]) {
                            (Confidence::High, "mailchimp-named-assignment")
                        } else {
                            (Confidence::Medium, "mailchimp-keyword-cooccurrence")
                        };
                    candidates.push(
                        Candidate::new("mailchimp_api_key", confidence, range)
                            .with_specificity(Specificity::Provider)
                            .with_signals([context_signal, "documented-datacenter-suffix"]),
                    );
                }
                start = hex_end;
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "0123456789abcdef0123456789abcdef";
    const _: () = assert!(KEY_HEX.len() == KEY_HEX_LEN);

    fn key() -> String {
        format!("{KEY_HEX}-us6")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        MailchimpMarketingApiKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_the_key_alongside_a_mailchimp_keyword() {
        for input in [
            format!("MAILCHIMP_API_KEY={}", key()),
            format!("mailchimp.api_key: {}", key()),
            format!("# Mailchimp API key: {}", key()),
            format!("{{\"mailchimpApiKey\": \"{}\"}}", key()),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "mailchimp_api_key");
            let expected = if input.starts_with('#') {
                Confidence::Medium
            } else {
                Confidence::High
            };
            assert_eq!(candidates[0].confidence(), expected, "{input}");
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            let start = input.rfind(&key()).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + key().len()).unwrap()
            );
        }
    }

    #[test]
    fn accepts_a_two_digit_datacenter_suffix() {
        let value = format!("{KEY_HEX}-us21");
        let input = format!("mailchimp {value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bare_value_with_no_context() {
        assert!(detect(&key()).is_empty());
    }

    #[test]
    fn rejects_context_on_a_different_line() {
        let input = format!("# mailchimp\n{}\n", key());
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn matches_the_keyword_case_insensitively() {
        let input = format!("MailChimp {}", key());
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn rejects_a_bare_hex_body_with_no_datacenter_suffix() {
        assert!(detect(&format!("mailchimp {KEY_HEX}")).is_empty());
    }

    #[test]
    fn rejects_a_suffix_with_no_preceding_hex_body() {
        assert!(detect("mailchimp -us6").is_empty());
    }

    #[test]
    fn rejects_a_wrong_datacenter_literal() {
        assert!(detect(&format!("mailchimp {KEY_HEX}-eu6")).is_empty());
    }

    #[test]
    fn rejects_a_three_digit_datacenter_suffix() {
        assert!(detect(&format!("mailchimp {KEY_HEX}-us123")).is_empty());
    }

    #[test]
    fn rejects_a_hex_body_one_byte_short_of_the_required_length() {
        let short = &KEY_HEX[..KEY_HEX_LEN - 1];
        assert!(detect(&format!("mailchimp {short}-us6")).is_empty());
    }

    #[test]
    fn rejects_a_hex_body_one_byte_longer_than_the_required_length_rather_than_truncating() {
        let long = format!("{KEY_HEX}0");
        assert!(detect(&format!("mailchimp {long}-us6")).is_empty());
    }

    #[test]
    fn rejects_an_uppercase_hex_body() {
        let upper = KEY_HEX.to_ascii_uppercase();
        assert!(detect(&format!("mailchimp {upper}-us6")).is_empty());
    }

    #[test]
    fn rejects_a_masked_repeated_character_body() {
        assert!(detect(&format!("mailchimp {}-us1", "0".repeat(KEY_HEX_LEN))).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("mailchimp MAILCHIMP_API_KEY=${MAILCHIMP_API_KEY}").is_empty());
    }

    #[test]
    fn rejects_an_audience_id_reference() {
        // A Mailchimp audience/list id is documented as a short
        // alphanumeric id, far shorter than the 32-byte key body.
        assert!(detect("mailchimp list_id: a1b2c3d4e5").is_empty());
    }

    #[test]
    fn rejects_a_key_embedded_in_a_wider_identifier() {
        let value = key();
        assert!(detect(&format!("mailchimp x{value}")).is_empty());
        assert!(detect(&format!("mailchimp {value}x")).is_empty());
        assert!(detect(&format!("mailchimp {value}-1")).is_empty());
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nmailchimp {}\r\n", key());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(&key()).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + key().len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = format!("mailchimp {}", key());
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn every_candidate_on_a_context_bearing_line_is_reported() {
        let input = format!("mailchimp {} {}", key(), key());
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.confidence() == Confidence::Medium)
        );
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        let input = format!("{} ", key()).repeat(10_000);
        assert_eq!(detect(&input).len(), 0);
    }
}
