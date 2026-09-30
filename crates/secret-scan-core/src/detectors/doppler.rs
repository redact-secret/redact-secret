//! Doppler token detection (issue #903, handoff
//! `docs/audits/evidence/860/doppler.md`).
//!
//! Doppler documents seven bearer token types under one `dp.<type>.` scheme
//! on one provider page (<https://docs.doppler.com/reference/auth-token-formats>,
//! a per-type regex; re-checked 2026-09-28, page dated 2025-05-29). Every
//! fact below is T1 from that page:
//!
//! | Prefix | Finding type |
//! | --- | --- |
//! | `dp.st.` | `doppler_service_token` |
//! | `dp.pt.` | `doppler_personal_token` |
//! | `dp.ct.` | `doppler_cli_token` |
//! | `dp.sa.` | `doppler_service_account_token` |
//! | `dp.said.` | `doppler_service_account_identity_token` |
//! | `dp.scim.` | `doppler_scim_token` |
//! | `dp.audit.` | `doppler_audit_token` |
//!
//! The body is 40–44 bytes of `[A-Za-z0-9]`. A service token (`dp.st.`) may
//! carry one optional environment segment, `[a-z0-9_-]{2,35}` followed by
//! `.`, between the prefix and the body; no other type has one. Each type
//! is its own finding type, following
//! `decision-map-github-token-families-onto-independent-finding-types`: the
//! roles differ in blast radius (a personal or CLI token acts for the user,
//! a service token reads one config).
//!
//! The optional segment is why this is a bespoke scan and not a
//! [`super::pattern::PrefixShape`] table: a segment followed by `.` cannot
//! be expressed as one bounded run.
//!
//! ## Boundaries
//!
//! The byte before `dp` must not be `[A-Za-z0-9_.-]`, and the byte after the
//! body must not be `[A-Za-z0-9_-]`. A following `.` is sentence punctuation
//! and stays outside the span. A body of 39 or 45+ bytes, a body containing
//! `_` or `-`, an undocumented type, an uppercase prefix, and a segment that
//! breaks the segment grammar are all intentional false negatives, never a
//! truncated match. `dp.said.` is never read as `dp.sa.` plus a body: the
//! body alphabet excludes `.`, and the type literal must be followed by `.`.
//!
//! The dashboard and CLI preview (`dp.st…` plus the last six body bytes)
//! fails the grammar by construction. The body scan is capped at 45 bytes
//! and the segment scan at 36, so each candidate costs O(1) and a whole scan
//! stays linear.

use crate::detectors::pattern;
use crate::detectors::prefilter::Literals;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const LEAD: &str = "dp.";
const BODY_MIN: usize = 40;
const BODY_MAX: usize = 44;
const SEGMENT_MIN: usize = 2;
const SEGMENT_MAX: usize = 35;

/// `(type literal, finding type)`. Each literal is followed by `.`.
const TYPES: [(&str, &str); 7] = [
    ("st", "doppler_service_token"),
    ("pt", "doppler_personal_token"),
    ("ct", "doppler_cli_token"),
    ("sa", "doppler_service_account_token"),
    ("said", "doppler_service_account_identity_token"),
    ("scim", "doppler_scim_token"),
    ("audit", "doppler_audit_token"),
];

const SIGNALS: [&str; 2] = [
    "doppler-documented-prefix",
    "doppler-documented-length-band",
];

/// `[A-Za-z0-9_.-]`: bytes that make `dp.` part of a wider identifier.
fn is_leading_glue(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_' || byte == b'.'
}

/// `[A-Za-z0-9_-]`: bytes that make the body part of a wider identifier.
fn is_trailing_glue(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// `[a-z0-9_-]`: the service-token environment segment alphabet.
fn is_segment_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
}

/// Length of the run of `alphabet` bytes at `from`, counting at most `cap`.
fn run_len(bytes: &[u8], from: usize, cap: usize, alphabet: fn(u8) -> bool) -> usize {
    bytes
        .get(from..)
        .unwrap_or_default()
        .iter()
        .take(cap)
        .take_while(|&&byte| alphabet(byte))
        .count()
}

/// End of a valid body starting at `from`, or `None`.
fn body_end(bytes: &[u8], from: usize) -> Option<usize> {
    let len = run_len(bytes, from, BODY_MAX + 1, pattern::is_alnum);
    if !(BODY_MIN..=BODY_MAX).contains(&len) {
        return None;
    }
    let end = from + len;
    match bytes.get(end) {
        Some(&next) if is_trailing_glue(next) => None,
        _ => Some(end),
    }
}

/// End of the service-token body after an optional environment segment.
fn service_token_end(bytes: &[u8], after_prefix: usize) -> Option<usize> {
    let segment = run_len(bytes, after_prefix, SEGMENT_MAX + 1, is_segment_byte);
    let segmented = ((SEGMENT_MIN..=SEGMENT_MAX).contains(&segment)
        && bytes.get(after_prefix + segment) == Some(&b'.'))
    .then(|| body_end(bytes, after_prefix + segment + 1))
    .flatten();
    segmented.or_else(|| body_end(bytes, after_prefix))
}

/// `(end, finding type)` of a token starting at `start` (which begins with
/// `dp.`), or `None`.
fn match_at(bytes: &[u8], start: usize) -> Option<(usize, &'static str)> {
    if start > 0 && is_leading_glue(bytes[start - 1]) {
        return None;
    }
    let type_start = start + LEAD.len();
    let rest = bytes.get(type_start..)?;
    let (literal, type_name) = TYPES.iter().copied().find(|(literal, _)| {
        rest.starts_with(literal.as_bytes()) && rest.get(literal.len()) == Some(&b'.')
    })?;
    let after_prefix = type_start + literal.len() + 1;
    let end = if literal == "st" {
        service_token_end(bytes, after_prefix)?
    } else {
        body_end(bytes, after_prefix)?
    };
    Some((end, type_name))
}

/// Recognizes the seven documented `dp.<type>.` Doppler token types.
pub(super) struct DopplerTokenDetector;

impl Detector for DopplerTokenDetector {
    fn id(&self) -> &'static str {
        "doppler-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut cursor = 0;
        while let Some(offset) = input[cursor..].find(LEAD) {
            let start = cursor + offset;
            let Some((end, type_name)) = match_at(bytes, start) else {
                cursor = start + 1;
                continue;
            };
            if let Some(range) = ByteRange::new(start, end) {
                candidates.push(
                    Candidate::built_in(type_name, Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(SIGNALS),
                );
            }
            cursor = end;
        }
        Ok(candidates)
    }
}

/// The literals one of which every `doppler-token` candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) const REQUIRED_LITERALS: &[Literals] = &[Literals::Strs(&[LEAD])];

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic filler, never provider-issued: a seeded walk over
    /// `[A-Za-z0-9]` so no realistic literal is committed.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()]))
            .collect()
    }

    fn token(literal: &str, len: usize) -> String {
        format!("{LEAD}{literal}.{}", body(len, literal.len()))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        DopplerTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str, type_name: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), type_name, "{input}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("DOPPLER_TOKEN={token}"),
            format!("export DOPPLER_TOKEN=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("X-API-Key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("client = Client(api_key=\"{token}\")"),
            format!("Here is my key {token} can you debug this?"),
            format!("doppler:\n  token: {token}\n"),
            format!("```\n{token}\n```"),
            format!("2026-09-28T00:00:00Z ci DOPPLER_TOKEN={token} set"),
            format!("stringData:\n  DOPPLER_TOKEN: \"{token}\"\n"),
            format!("The token is {token}."),
        ]
    }

    #[test]
    fn every_type_is_detected_at_every_width_in_every_context() {
        for (literal, type_name) in TYPES {
            for len in [BODY_MIN, 43, BODY_MAX] {
                let token = token(literal, len);
                for input in contexts(&token) {
                    assert_single(&input, &token, type_name);
                }
            }
        }
    }

    #[test]
    fn a_service_token_segment_is_inside_the_span() {
        for segment in ["pr", "prd", "dev-us_east", &"a".repeat(SEGMENT_MAX)] {
            let token = format!("{LEAD}st.{segment}.{}", body(43, 1));
            for input in contexts(&token) {
                assert_single(&input, &token, "doppler_service_token");
            }
        }
    }

    #[test]
    fn a_segment_is_only_accepted_on_service_tokens() {
        for (literal, _) in TYPES.iter().filter(|(literal, _)| *literal != "st") {
            let input = format!("{LEAD}{literal}.prd.{}", body(43, 2));
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn body_width_twins_are_rejected() {
        for (literal, _) in TYPES {
            for len in [BODY_MIN - 1, BODY_MAX + 1, 20, 64] {
                let input = token(literal, len);
                assert!(detect(&input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn a_dash_or_underscore_inside_the_body_is_rejected() {
        for byte in ["_", "-"] {
            let mut value = body(43, 3);
            value.replace_range(20..21, byte);
            let input = format!("{LEAD}st.{value}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn unknown_types_case_changes_and_missing_dots_are_rejected() {
        let value = body(43, 4);
        for prefix in [
            "dp.xx.", "dp.st2.", "DP.ST.", "dp.ST.", "Dp.st.", "dpst.", "dp.st", "dp..st.",
            "dp.sai.", "dp.scm.",
        ] {
            let input = format!("{prefix}{value}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn broken_segments_are_rejected() {
        let value = body(43, 5);
        for segment in ["a", "Prd", "prd!", &"a".repeat(SEGMENT_MAX + 1)] {
            let input = format!("{LEAD}st.{segment}.{value}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn said_is_never_read_as_sa() {
        let token = token("said", 43);
        let candidates = detect(&token);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].type_name(),
            "doppler_service_account_identity_token"
        );
        // `dp.sa.` followed by `id.` + body is not a service-account token.
        let input = format!("{LEAD}sa.id.{}", body(43, 4));
        assert!(detect(&input).is_empty(), "{input}");
    }

    #[test]
    fn glued_values_are_rejected() {
        // A 44-byte body, so a glued alphanumeric makes it 45, not a
        // different valid width.
        let token = token("st", BODY_MAX);
        for input in [
            format!("x{token}"),
            format!("_{token}"),
            format!("-{token}"),
            format!(".{token}"),
            format!("{token}a"),
            format!("{token}_x"),
            format!("{token}-1"),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_doppler_text_is_not_claimed() {
        let tail = &body(43, 6)[37..];
        for input in [
            format!("token: dp.st\u{2026}{tail}"),
            "DOPPLER_TOKEN=dp.st.xxxx".to_owned(),
            "DOPPLER_TOKEN=dp.st.<config>.*".to_owned(),
            "DOPPLER_TOKEN=${{ secrets.DOPPLER_TOKEN }}".to_owned(),
            "slug: 5d7c1a2e-8b4f-4c3a-9e6d-0f1b2c3d4e5f".to_owned(),
            "doppler run --token dp.st.... -- npm start".to_owned(),
            "doppler configs tokens create ci --plain".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn an_exact_width_placeholder_is_a_known_false_positive() {
        let input = format!("DOPPLER_TOKEN={LEAD}st.{}", "x".repeat(43));
        assert_eq!(detect(&input).len(), 1);
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = token("pt", 43);
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        let glued = token.repeat(200);
        assert!(detect(&glued).is_empty());
    }
}
