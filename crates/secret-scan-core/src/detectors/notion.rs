//! Notion integration token detection.
//!
//! Two supported shapes, both bounded on both sides by a byte outside
//! `[A-Za-z0-9_]` or the edge of input:
//!
//! - Legacy: `secret_` followed by an exact 43-byte run of `[A-Za-z0-9]`.
//! - Current (rolled out 2024-09-25 per Notion's own changelog): `ntn_`
//!   followed by exactly 11 ASCII digits, then an exact 35-byte run of
//!   `[A-Za-z0-9]`.
//!
//! Both total exactly 50 bytes including the prefix. See
//! `docs/decisions/2026-09-16-freeze-notion-integration-token-grammar.md`
//! for why these lengths are frozen and what is deliberately out of scope
//! (OAuth refresh/access tokens, page/database/block IDs, share URLs).

use crate::detectors::pattern::{self, RunLength, is_alnum, is_alnum_underscore};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const SECRET_PREFIX: &str = "secret_";
const SECRET_SUFFIX_LEN: usize = 43;

const NTN_PREFIX: &str = "ntn_";
const NTN_DIGIT_LEN: usize = 11;
const NTN_SUFFIX_LEN: usize = 35;

/// Recognizes Notion's documented and community-converged integration token
/// prefixes. No surrounding context (`NOTION_TOKEN=`, `Authorization:
/// Bearer`, ...) is required to classify a match: like every other
/// `Specificity::Provider` detector in this module, the prefixed exact-length
/// shape is treated as specific enough on its own.
pub(super) struct NotionTokenDetector;

impl Detector for NotionTokenDetector {
    fn id(&self) -> &'static str {
        "notion-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        push(
            &mut candidates,
            pattern::scan_prefixed_runs(
                input,
                &[SECRET_PREFIX],
                RunLength::Exact(SECRET_SUFFIX_LEN),
                is_alnum,
                is_alnum_underscore,
            ),
            ["notion-documented-prefix", "secret-legacy-format"],
        );
        push(
            &mut candidates,
            scan_ntn(input),
            ["notion-documented-prefix", "ntn-current-format"],
        );
        Ok(candidates)
    }
}

fn push(candidates: &mut Vec<Candidate>, ranges: Vec<(usize, usize)>, signals: [&'static str; 2]) {
    for (start, end) in ranges {
        let Some(range) = ByteRange::new(start, end) else {
            continue;
        };
        candidates.push(
            Candidate::new("notion_integration_token", Confidence::High, range)
                .with_specificity(Specificity::Provider)
                .with_signals(signals),
        );
    }
}

/// `ntn_` followed by an exact 11-digit run and an exact 35-byte alphanumeric
/// run, with no separator between the two: unlike [`super::github`]'s
/// fine-grained shape, there is no literal byte between the segments to
/// anchor on, so the digit run is checked directly against the precomputed
/// alphanumeric-run table the way [`super::sendgrid`] checks its own
/// fixed-length segments.
fn scan_ntn(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, is_alnum);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start..].starts_with(NTN_PREFIX.as_bytes()) {
            start += 1;
            continue;
        }

        let Some(end) = ntn_end(bytes, &ends, start + NTN_PREFIX.len()) else {
            start += 1;
            continue;
        };

        if pattern::boundary_ok(bytes, start, end, is_alnum_underscore) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

fn ntn_end(bytes: &[u8], ends: &[usize], suffix_start: usize) -> Option<usize> {
    if ends[suffix_start] < suffix_start + NTN_DIGIT_LEN + NTN_SUFFIX_LEN {
        return None;
    }
    let digits_ok = bytes[suffix_start..suffix_start + NTN_DIGIT_LEN]
        .iter()
        .all(u8::is_ascii_digit);
    if !digits_ok {
        return None;
    }
    Some(suffix_start + NTN_DIGIT_LEN + NTN_SUFFIX_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Notion's suffix alphabet is `[A-Za-z0-9]` only (no `_`/`-`), unlike
    // e.g. SendGrid's or Shopify's, so these synthetic fixtures must avoid
    // both to stay inside the alphabet the detector's run scan matches.
    const SECRET_SUFFIX: &str = "SYNTHETICREVOKEDNOTIONLEGACYTOKENVALUE00000";
    const NTN_DIGITS: &str = "00000000000";
    const NTN_SUFFIX: &str = "SYNTHETICREVOKEDNOTIONCURRENTVAL000";

    fn legacy_token() -> String {
        assert_eq!(SECRET_SUFFIX.len(), SECRET_SUFFIX_LEN);
        format!("{SECRET_PREFIX}{SECRET_SUFFIX}")
    }

    fn current_token() -> String {
        assert_eq!(NTN_DIGITS.len(), NTN_DIGIT_LEN);
        assert_eq!(NTN_SUFFIX.len(), NTN_SUFFIX_LEN);
        format!("{NTN_PREFIX}{NTN_DIGITS}{NTN_SUFFIX}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        NotionTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn detects_a_legacy_secret_prefixed_token() {
        let value = legacy_token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "notion_integration_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_a_current_ntn_prefixed_token() {
        let value = current_token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "notion_integration_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_token_bare_in_env_and_json_contexts() {
        for value in [legacy_token(), current_token()] {
            for input in [
                value.clone(),
                format!("NOTION_TOKEN={value}"),
                format!("{{\"apiKey\": \"{value}\"}}"),
            ] {
                let candidates = detect(&input);
                assert_eq!(candidates.len(), 1, "{input}");
                let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
                assert_eq!(&input[start..end], value, "{input}");
            }
        }
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        for value in [legacy_token(), current_token()] {
            let input = format!("({value}).");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(1, value.len() + 1).unwrap()
            );
        }
    }

    #[test]
    fn rejects_a_truncated_secret_suffix() {
        let short = &SECRET_SUFFIX[..SECRET_SUFFIX_LEN - 1];
        assert!(detect(&format!("{SECRET_PREFIX}{short}")).is_empty());
    }

    #[test]
    fn rejects_a_secret_suffix_longer_than_documented() {
        assert!(detect(&format!("{}A", legacy_token())).is_empty());
    }

    #[test]
    fn rejects_a_truncated_ntn_suffix() {
        let short = &NTN_SUFFIX[..NTN_SUFFIX_LEN - 1];
        assert!(detect(&format!("{NTN_PREFIX}{NTN_DIGITS}{short}")).is_empty());
    }

    #[test]
    fn rejects_an_ntn_suffix_longer_than_documented() {
        assert!(detect(&format!("{}A", current_token())).is_empty());
    }

    #[test]
    fn rejects_ntn_with_a_non_digit_in_the_digit_run() {
        let bad_digits = "0000000000A";
        assert_eq!(bad_digits.len(), NTN_DIGIT_LEN);
        assert!(detect(&format!("{NTN_PREFIX}{bad_digits}{NTN_SUFFIX}")).is_empty());
    }

    #[test]
    fn rejects_the_prefix_alone() {
        assert!(detect("secret_").is_empty());
        assert!(detect("secret_SYNTHETIC").is_empty());
        assert!(detect("ntn_").is_empty());
        assert!(detect("ntn_00000000000").is_empty());
    }

    #[test]
    fn rejects_the_oauth_refresh_token_prefix() {
        // `nrt_` (OAuth refresh token) is a deliberately unsupported variant:
        // see the frozen-grammar decision record.
        assert!(detect("nrt_4991090011501Ejc6Xn4sHguI7jZIN449mKe9PRhpMfNK").is_empty());
    }

    #[test]
    fn rejects_the_token_embedded_in_a_wider_identifier() {
        for value in [legacy_token(), current_token()] {
            assert!(detect(&format!("x{value}")).is_empty(), "{value}");
            assert!(detect(&format!("{value}x")).is_empty(), "{value}");
        }
    }

    #[test]
    fn rejects_wrong_case_and_near_miss_prefixes() {
        for input in [
            format!("Secret_{SECRET_SUFFIX}"),
            format!("SECRET_{SECRET_SUFFIX}"),
            format!("secrets_{SECRET_SUFFIX}"),
            format!("Ntn_{NTN_DIGITS}{NTN_SUFFIX}"),
            format!("ntnn_{NTN_DIGITS}{NTN_SUFFIX}"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn detects_the_token_in_a_yaml_and_log_line_context() {
        for value in [legacy_token(), current_token()] {
            for input in [
                format!("notion_token: {value}"),
                format!("2026-09-16T00:00:00Z INFO using token={value} for sync"),
            ] {
                let candidates = detect(&input);
                assert_eq!(candidates.len(), 1, "{input}");
                let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
                assert_eq!(&input[start..end], value, "{input}");
            }
        }
    }

    #[test]
    fn detects_the_token_after_a_unicode_prefix_and_around_crlf() {
        for value in [legacy_token(), current_token()] {
            let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn rejects_a_page_id_uuid_and_placeholder_text() {
        for input in [
            "e202e8c9-0990-40af-855f-ff8f872b1ec6",
            "secret_<YOUR_INTEGRATION_TOKEN>",
            "ntn_***********************************",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = legacy_token();
        assert_eq!(detect(&value), detect(&value));
    }
}
