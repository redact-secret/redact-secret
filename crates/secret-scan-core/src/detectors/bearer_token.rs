//! Structural Bearer authorization detector.
//!
//! Requires the explicit `Bearer` scheme and a token of at least 16
//! characters. This keeps arbitrary identifiers out of scope but
//! intentionally misses short development tokens. Only the credential
//! value, not the header, is selected.

use super::text::{
    ascii_run_len, ends_with_ci, is_js_whitespace, prev_char, rskip_while_chars, starts_with_ci,
};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const MIN_TOKEN_LEN: usize = 16;
const MAX_TRAILING_EQUALS: usize = 2;

/// `true` for the token alphabet: `[A-Za-z0-9._~+/-]`.
fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'-')
}

/// `true` for `[A-Za-z0-9_-]`, the boundary charset that keeps a match from
/// starting inside a wider identifier.
fn is_boundary_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_space_or_tab(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Matches the optional `authorization\s*:\s*` prefix followed by the
/// mandatory `bearer` keyword, anchored exactly at `pos`. Returns the offset
/// right after the keyword.
///
/// The two alternatives never both start with the same literal text, so
/// there is nothing to backtrack: text at `pos` either spells
/// `authorization...bearer` or it spells `bearer` directly.
fn match_scheme_at(input: &str, pos: usize) -> Option<usize> {
    if starts_with_ci(input, pos, "authorization") {
        let mut cursor = super::text::skip_while_chars(
            input,
            pos + "authorization".len(),
            super::text::is_js_whitespace,
        );
        if super::text::char_at(input, cursor) != Some(':') {
            return None;
        }
        cursor += 1;
        cursor = super::text::skip_while_chars(input, cursor, super::text::is_js_whitespace);
        return starts_with_ci(input, cursor, "bearer").then(|| cursor + "bearer".len());
    }
    starts_with_ci(input, pos, "bearer").then(|| pos + "bearer".len())
}

fn trim_end_js_whitespace(input: &str) -> &str {
    &input[..rskip_while_chars(input, input.len(), is_js_whitespace)]
}

/// `true` for the identifier-boundary charset `[A-Za-z0-9_-]`, checked as a
/// `char` for use against a backward-scanned lookbehind character.
fn is_identifier_boundary_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
}

/// `true` when `s` ends with `authorization` (case-insensitive) and the
/// character immediately before it, if any, is outside the identifier
/// boundary charset.
fn ends_with_authorization_boundary(s: &str) -> bool {
    if !ends_with_ci(s, "authorization") {
        return false;
    }
    let prefix_len = s.len() - "authorization".len();
    prev_char(s, prefix_len).is_none_or(|ch| !is_identifier_boundary_char(ch))
}

/// Internal retention hint for the built-in incremental scanner: `true` when
/// `input` still looks like an in-progress `authorization` header name, so a
/// caller should keep holding the line open in case an explicit `Bearer`
/// scheme and credential follow. Mirrors `hasOpenBearerAuthorization` in
/// `src/detectors/bearer-token.ts` (`decision-govern-cross-language-conformance`).
pub(crate) fn has_open_bearer_authorization(input: &str) -> bool {
    let trimmed = trim_end_js_whitespace(input);
    match trimmed.strip_suffix(':') {
        Some(before_colon) => {
            ends_with_authorization_boundary(trim_end_js_whitespace(before_colon))
        }
        None => ends_with_authorization_boundary(trimmed),
    }
}

struct BearerTokenDetector;

impl Detector for BearerTokenDetector {
    fn id(&self) -> &'static str {
        "bearer-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut cursor = 0usize;

        while cursor < bytes.len() {
            let Some(scheme_end) = match_scheme_at(input, cursor) else {
                cursor += super::text::char_at(input, cursor).map_or(1, char::len_utf8);
                continue;
            };

            let ws_len = ascii_run_len(bytes, scheme_end, is_space_or_tab);
            if ws_len == 0 {
                cursor += super::text::char_at(input, cursor).map_or(1, char::len_utf8);
                continue;
            }
            let value_start = scheme_end + ws_len;

            let token_len = ascii_run_len(bytes, value_start, is_token_char);
            if token_len < MIN_TOKEN_LEN {
                cursor += super::text::char_at(input, cursor).map_or(1, char::len_utf8);
                continue;
            }
            let token_end = value_start + token_len;
            let trailing_equals = (0..MAX_TRAILING_EQUALS)
                .take_while(|&offset| bytes.get(token_end + offset) == Some(&b'='))
                .count();
            let value_end = token_end + trailing_equals;

            let boundary_blocked = cursor > 0 && is_boundary_identifier_char(bytes[cursor - 1]);
            if !boundary_blocked && let Some(range) = ByteRange::new(value_start, value_end) {
                candidates.push(
                    Candidate::new("bearer_token", Confidence::High, range)
                        .with_specificity(Specificity::Structural)
                        .with_signals(["bearer-scheme"]),
                );
            }

            // `matchAll` resumes scanning at the end of the raw regex match
            // regardless of the boundary check outcome.
            cursor = value_end.max(cursor + 1);
        }

        Ok(candidates)
    }
}

/// The structural Bearer authorization detector.
#[must_use]
pub fn bearer_token_detector() -> Box<dyn Detector> {
    Box::new(BearerTokenDetector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        BearerTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn only_range(candidates: &[Candidate]) -> (usize, usize) {
        assert_eq!(candidates.len(), 1);
        (candidates[0].range().start(), candidates[0].range().end())
    }

    #[test]
    fn explicit_bearer_scheme_is_detected() {
        let input = "Bearer SYNTHETIC_REVOKED_BEARER_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (7, input.len()));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Structural));
    }

    #[test]
    fn bearer_embedded_in_an_identifier_is_excluded() {
        assert!(detect("notbearer SYNTHETIC_REVOKED_IDENTIFIER").is_empty());
    }

    #[test]
    fn short_development_token_is_ignored() {
        assert!(detect("Bearer short-token").is_empty());
    }

    #[test]
    fn authorization_header_prefix_is_supported() {
        let input = "authorization: Bearer SYNTHETIC_REVOKED_HEADER_VALUE";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_HEADER_VALUE");
    }

    #[test]
    fn long_invalid_alphabet_terminates_without_a_finding() {
        let input = format!("Bearer {}", "!".repeat(100_000));
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn open_bearer_authorization_hint_recognizes_a_pending_header_name() {
        for open in [
            "authorization",
            "Authorization",
            "AUTHORIZATION",
            "authorization:",
            "authorization: ",
            "authorization \t: ",
            "line one\nauthorization:",
        ] {
            assert!(has_open_bearer_authorization(open), "{open:?}");
        }
    }

    #[test]
    fn open_bearer_authorization_hint_rejects_resolved_or_unrelated_text() {
        for closed in [
            "",
            "authorization: bearer",
            "authorizationx",
            "notauthorization",
            "x-authorization",
            "authorization: Bearer SYNTHETIC_REVOKED_VALUE",
            "plain text",
        ] {
            assert!(!has_open_bearer_authorization(closed), "{closed:?}");
        }
    }

    #[test]
    fn missing_value_after_scheme_is_ignored() {
        assert!(detect("Authorization: Bearer").is_empty());
    }

    #[test]
    fn newline_separator_is_not_accepted() {
        // Only a space or a tab separates the scheme from its credential;
        // a line break is deliberately outside that separator charset.
        assert!(detect("Bearer\nSYNTHETIC_REVOKED_BEARER_NEWLINE_VALUE").is_empty());
    }

    #[test]
    fn case_insensitive_scheme_and_tab_separator_are_accepted() {
        let input = "BEARER\tSYNTHETIC_REVOKED_BEARER_TAB_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (7, input.len()));
    }

    #[test]
    fn extra_whitespace_and_case_around_the_authorization_header_are_accepted() {
        let input = "AUTHORIZATION  :  BEARER   SYNTHETIC_REVOKED_BEARER_CASE_WS_VALUE";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_BEARER_CASE_WS_VALUE");
    }

    #[test]
    fn ordinary_prose_usage_of_bearer_is_safe_but_a_long_incidental_word_is_an_accepted_tradeoff() {
        // "bearer" used as an ordinary English noun followed by a short
        // word stays negative: the token-length floor, not any language
        // awareness, is what keeps this safe.
        assert!(
            detect("The bearer of this letter is authorized to collect the package.").is_empty()
        );
        // The same ordinary usage followed by an incidentally long
        // hyphenated word is indistinguishable from a real credential at
        // the character-grammar level and is classified: an accepted
        // precision/recall tradeoff, not a bug.
        let input =
            "Please note the bearer identification-verification-procedure must be followed.";
        let candidates = detect(input);
        assert_eq!(
            only_range(&candidates),
            (23, 23 + "identification-verification-procedure".len())
        );
    }

    #[test]
    fn trailing_padding_equals_are_included() {
        let input = "Bearer SYNTHETIC_REVOKED_BEARER_VALUE==";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_BEARER_VALUE==");
    }
}
