//! 1Password service-account token detection (issue #913, handoff
//! `docs/audits/evidence/860/onepassword.md`).
//!
//! 1Password's service-account security page states that the token "uses
//! `ops_` as the token prefix" (chosen "to help code analyzers find
//! accidental credential exposure") and that the rest is a serialized
//! object that is "Base64 URL encoded". The serialized object is JSON, so
//! the body begins `eyJ` (Base64 of `{"`); the page's one encoded example
//! begins `ops_eyJ` (re-checked 2026-09-28).
//!
//! | Part | Grammar | Tier |
//! | --- | --- | --- |
//! | Prefix | `ops_eyJ` | T1 (provider docs) |
//! | Body | Base64url `[A-Za-z0-9_-]`, at least 250 bytes after `ops_eyJ` | T1 alphabet; the floor is project policy |
//! | Padding | up to two trailing `=`, inside the span | T1 (Base64) |
//!
//! No fixed length exists: the token is serialized user data (the one T1
//! example is 634 bytes, observed tokens 634–870). The 250-byte floor only
//! has to reject identifiers and placeholders; the decoded JSON always
//! carries eight documented fields, so no real token is near it, and it is
//! the existing gitleaks floor. The alphabet is the provider's stated
//! Base64url class rather than the alphanumeric samples': a token containing
//! `-` or `_` must not be truncated, because that would leave its tail
//! readable.
//!
//! ## Boundaries
//!
//! The byte before `ops_` must not be `[A-Za-z0-9_-]`. After the body and at
//! most two `=`, the next byte must not be `[A-Za-z0-9_-]`, `+`, `/` or `=`:
//! a glued standard-Base64 tail rejects the match rather than truncating it.
//! A Connect server token is a three-segment JWT and stays with `jwt`;
//! `op://` secret references never begin `ops_eyJ`.
//!
//! Cost: one literal search, then one maximal run per occurrence. Every
//! later `ops_eyJ` inside the same run is glued, so the scan resumes after
//! the run and stays linear.

use crate::detectors::pattern;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const TYPE_NAME: &str = "onepassword_service_account_token";
const PREFIX: &str = "ops_eyJ";
/// Base64url bytes required after [`PREFIX`].
const BODY_MIN: usize = 250;
const MAX_PADDING: usize = 2;

const SIGNALS: [&str; 2] = ["onepassword-documented-prefix", "base64url-json-lead"];

/// `[A-Za-z0-9_-]` plus `+`, `/` and `=`: bytes that make the token part of
/// a wider Base64 run.
fn is_trailing_glue(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || matches!(byte, b'+' | b'/' | b'=')
}

/// Recognizes `ops_eyJ` 1Password service-account tokens.
pub(super) struct OnePasswordServiceAccountTokenDetector;

impl Detector for OnePasswordServiceAccountTokenDetector {
    fn id(&self) -> &'static str {
        "onepassword-service-account-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut cursor = 0;
        while let Some(offset) = input[cursor..].find(PREFIX) {
            let start = cursor + offset;
            let body_start = start + PREFIX.len();
            let body_len = bytes[body_start..]
                .iter()
                .take_while(|&&byte| pattern::is_alnum_dash(byte))
                .count();
            let run_end = body_start + body_len;
            // Any later prefix inside this run is glued; resume after it.
            cursor = run_end;
            if (start > 0 && pattern::is_alnum_dash(bytes[start - 1])) || body_len < BODY_MIN {
                continue;
            }
            let padding = bytes[run_end..]
                .iter()
                .take(MAX_PADDING)
                .take_while(|&&byte| byte == b'=')
                .count();
            let end = run_end + padding;
            if bytes.get(end).copied().is_some_and(is_trailing_glue) {
                continue;
            }
            if let Some(range) = ByteRange::new(start, end) {
                candidates.push(
                    Candidate::new(TYPE_NAME, Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(SIGNALS),
                );
            }
            cursor = end;
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic Base64url filler, never provider-issued.
    fn body(len: usize, seed: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| char::from(ALPHABET[(i * 7 + seed * 13 + i / 5) % ALPHABET.len()]))
            .collect()
    }

    fn token(len: usize) -> String {
        format!("{PREFIX}{}", body(len, len))
    }

    fn detect(input: &str) -> Vec<Candidate> {
        OnePasswordServiceAccountTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), TYPE_NAME);
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
            format!("OP_SERVICE_ACCOUNT_TOKEN={token}"),
            format!("export OP_SERVICE_ACCOUNT_TOKEN=\"{token}\""),
            format!("Authorization: Bearer {token}"),
            format!("X-API-Key: {token}"),
            format!("{{\"token\": \"{token}\"}}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("client = Client(api_key=\"{token}\")"),
            format!("Here is my key {token} can you debug this?"),
            format!("env:\n  OP_SERVICE_ACCOUNT_TOKEN: {token}\n"),
            format!("The token is {token}."),
        ]
    }

    #[test]
    fn tokens_are_detected_whole_at_every_width_in_every_context() {
        for len in [BODY_MIN, 623, 859] {
            let token = token(len);
            for input in contexts(&token) {
                assert_single(&input, &token);
            }
        }
    }

    #[test]
    fn dash_underscore_and_padding_stay_inside_the_span() {
        let mut value = body(600, 1);
        value.replace_range(100..101, "-");
        value.replace_range(300..301, "_");
        for token in [
            format!("{PREFIX}{value}"),
            format!("{PREFIX}{value}="),
            format!("{PREFIX}{value}=="),
        ] {
            for input in contexts(&token) {
                assert_single(&input, &token);
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let value = body(600, 2);
        let mut plus = value.clone();
        plus.replace_range(200..201, "+");
        for input in [
            token(BODY_MIN - 1),
            format!("ops_eyj{value}"),
            format!("OPS_eyJ{value}"),
            format!("ops-eyJ{value}"),
            format!("{PREFIX}{plus}"),
            format!("x{PREFIX}{value}"),
            format!("_{PREFIX}{value}"),
            format!("{PREFIX}{value}/"),
            format!("{PREFIX}{value}+abc"),
            format!("{PREFIX}{value}==="),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn benign_onepassword_text_is_not_claimed() {
        for input in [
            "OP_SERVICE_ACCOUNT_TOKEN=ops_...".to_owned(),
            "OP_SERVICE_ACCOUNT_TOKEN=ops_***".to_owned(),
            "op read op://Private/item/credential".to_owned(),
            "fn ops_function_name() {}".to_owned(),
            "OP_SERVICE_ACCOUNT_TOKEN=${{ secrets.OP_TOKEN }}".to_owned(),
            format!(
                "OP_CONNECT_TOKEN=eyJ{}.eyJ{}.{}",
                body(40, 3),
                body(500, 4),
                body(43, 5)
            ),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_tokens_are_reported_once_each_and_glued_runs_stay_linear() {
        let token = token(600);
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        // A glued repetition is one Base64url run: one finding over it all,
        // never a carved-out substring.
        let glued = token.repeat(50);
        let candidates = detect(&glued);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, glued.len()).unwrap()
        );
        // Short prefixed runs broken by a standard-Base64 byte never reach
        // the floor, and the scan reads each byte once.
        let broken = format!("{PREFIX}{}+", body(100, 6)).repeat(2_000);
        assert!(detect(&broken).is_empty());
    }
}
