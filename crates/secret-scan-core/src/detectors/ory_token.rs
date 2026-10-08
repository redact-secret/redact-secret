//! Ory session and `OAuth2` token detection (issue #1110, adoption ruling
//! 2026-10-07 in
//! `docs/audits/evidence/1110/README.md`,
//! reconciling the historical #1014 handoff
//! [`docs/audits/evidence/1014/ory.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/ory.md)).
//!
//! Two shapes, both T1 under rulings R1 and R9 from provider-authored code:
//!
//! | Shape | Grammar | Finding type |
//! | --- | --- | --- |
//! | Kratos session token | `ory_st_` + exactly 32 `[A-Za-z0-9]` (Kratos `randx.MustString(32, randx.AlphaNum)`) | `ory_session_token` |
//! | Hydra `OAuth2` access, refresh and authorization-code token | `ory_at_`, `ory_rt_` or `ory_ac_` + key `[A-Za-z0-9_-]{43,}` + `.` + signature `[A-Za-z0-9_-]{43}` (fosite HMAC strategy: `RawURLEncoding(key)` `.` `RawURLEncoding(HMAC-SHA512/256)`, entropy of at least 32 bytes) | `ory_oauth2_token` |
//!
//! ## Spans
//!
//! The session token is the prefix and its 32 body bytes. The `OAuth2` token is
//! one span from the prefix to the last signature byte; a trailing `.` that
//! ends a sentence is left outside.
//!
//! ## Boundaries and exclusions
//!
//! A byte of `[A-Za-z0-9_-]` before the prefix or after the body rejects the
//! match, so a glued run, a 33-byte session body and a 44-byte signature are
//! not claimed. A signature followed by `.` and another body byte is a third
//! segment, which is JWT-shaped, and is not claimed (the `jwt` detector owns
//! JWTs). The prefix is case-sensitive. The admin keys (`ory_pat_`,
//! `ory_apikey_`, `ory_wak_`), the `ory_lo_` logout token, cookie names such as
//! `ory_session_`, enterprise custom `OAuth2` prefixes and pre-2023 unprefixed
//! session tokens are not claimed. The accepted false positive is an unrelated
//! run with an `ory_(st|at|rt|ac)_` prefix and exactly this body grammar.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "ory-token";

const SESSION: &str = "ory_session_token";
const OAUTH2: &str = "ory_oauth2_token";
/// The finding types this detector emits; the inventory declares each one.
#[cfg(test)]
const TYPES: [&str; 2] = [SESSION, OAUTH2];

const SESSION_PREFIX: &str = "ory_st_";
const SESSION_BODY: usize = 32;
const KEY_MIN: usize = 43;
const SIGNATURE_LEN: usize = 43;

const SESSION_SIGNALS: [&str; 1] = ["ory-generator-prefix"];
const OAUTH2_SIGNALS: [&str; 1] = ["ory-hydra-hmac-shape"];

/// The session shape, then the three `OAuth2` prefixes with their key part (the
/// signature is checked in [`OryTokenDetector::detect`]); also the detector's
/// literals for the shared prefilter. No prefix is a prefix of another.
pub(super) const SHAPES: &[PrefixShape<'static>] = &[
    PrefixShape::exact(
        SESSION_PREFIX,
        SESSION_BODY,
        pattern::is_alnum,
        &SESSION_SIGNALS,
    ),
    PrefixShape::at_least("ory_at_", KEY_MIN, pattern::is_alnum_dash, &OAUTH2_SIGNALS),
    PrefixShape::at_least("ory_rt_", KEY_MIN, pattern::is_alnum_dash, &OAUTH2_SIGNALS),
    PrefixShape::at_least("ory_ac_", KEY_MIN, pattern::is_alnum_dash, &OAUTH2_SIGNALS),
];

/// The exclusive end of an `OAuth2` token whose key part ends at `key_end`, or
/// `None` when the rest is not `.` + exactly 43 base64url bytes, or when a
/// further `.` segment follows (a JWT-shaped three-part value).
fn oauth2_end(bytes: &[u8], key_end: usize) -> Option<usize> {
    if bytes.get(key_end) != Some(&b'.') {
        return None;
    }
    let signature_start = key_end + 1;
    let signature_end = signature_start + SIGNATURE_LEN;
    let signature = bytes.get(signature_start..signature_end)?;
    if !signature.iter().copied().all(pattern::is_alnum_dash) {
        return None;
    }
    match bytes.get(signature_end) {
        Some(&byte) if pattern::is_alnum_dash(byte) => None,
        Some(b'.')
            if bytes
                .get(signature_end + 1)
                .copied()
                .is_some_and(pattern::is_alnum_dash) =>
        {
            None
        }
        _ => Some(signature_end),
    }
}

/// Recognizes the Ory session token and the Ory `OAuth2` token.
pub(super) struct OryTokenDetector;

pub(super) const ORY_TOKEN: OryTokenDetector = OryTokenDetector;

impl Detector for OryTokenDetector {
    fn id(&self) -> &str {
        ID
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        for (start, run_end, signals) in
            pattern::scan_prefixed_shapes(input, SHAPES, pattern::is_alnum_dash)
        {
            let (type_name, end) = if bytes[start..].starts_with(SESSION_PREFIX.as_bytes()) {
                (SESSION, run_end)
            } else if let Some(end) = oauth2_end(bytes, run_end) {
                (OAUTH2, end)
            } else {
                continue;
            };
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::built_in(type_name, Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

    /// Synthetic filler, never provider-issued.
    fn filler(alphabet: &[u8], len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(alphabet[(i * 7 + seed * 13 + i / 5) % alphabet.len()]))
            .collect()
    }

    fn session(len: usize) -> String {
        format!("ory_st_{}", filler(ALNUM, len, 1))
    }

    fn oauth2(prefix: &str, key: usize, signature: usize) -> String {
        format!(
            "{prefix}{}.{}",
            filler(B64URL, key, 2),
            filler(B64URL, signature, 3)
        )
    }

    fn detect(input: &str) -> Vec<Candidate> {
        ORY_TOKEN
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
            format!("X-Session-Token: {token}"),
            format!("Authorization: Bearer {token}"),
            format!("ORY_ACCESS_TOKEN={token}"),
            format!("Ory(access_token=\"{token}\")"),
            format!("{{\"access_token\": \"{token}\", \"token_type\": \"bearer\"}}"),
            format!("Here is my token {token} can you debug this?"),
            format!("\u{d0a4}\u{1f511} 키: {token}"),
        ]
    }

    #[test]
    fn declares_both_finding_types() {
        assert_eq!(TYPES, [SESSION, OAUTH2]);
        assert_eq!(SHAPES.len(), 4);
    }

    #[test]
    fn session_token_is_one_span_in_every_context() {
        let token = session(32);
        assert_eq!(token.len(), 39);
        for input in contexts(&token) {
            assert_single(&input, &token, SESSION);
        }
    }

    #[test]
    fn oauth2_tokens_are_one_span_for_all_three_prefixes() {
        for prefix in ["ory_at_", "ory_rt_", "ory_ac_"] {
            // 43 is the default entropy; 44 and 48 are raised-entropy keys.
            for key in [43, 44, 48, 64] {
                let token = oauth2(prefix, key, 43);
                for input in contexts(&token) {
                    assert_single(&input, &token, OAUTH2);
                }
            }
        }
    }

    #[test]
    fn a_trailing_sentence_dot_stays_outside_the_span() {
        let token = oauth2("ory_at_", 43, 43);
        assert_single(&format!("The token is {token}."), &token, OAUTH2);
        let session = session(32);
        assert_single(&format!("The token is {session}."), &session, SESSION);
    }

    #[test]
    fn session_near_miss_twins_are_rejected() {
        assert!(detect(&session(31)).is_empty());
        assert!(detect(&session(33)).is_empty());
        let dash = format!("ory_st_{}-{}", filler(ALNUM, 15, 1), filler(ALNUM, 16, 1));
        assert!(detect(&dash).is_empty());
        let underscore = format!("ory_st_{}_{}", filler(ALNUM, 15, 1), filler(ALNUM, 16, 1));
        assert!(detect(&underscore).is_empty());
        let upper = session(32).replacen("ory_st_", "ORY_ST_", 1);
        assert!(detect(&upper).is_empty());
        let glued_before = format!("x{}", session(32));
        assert!(detect(&glued_before).is_empty());
        let glued_after = format!("{}x", session(32));
        assert!(detect(&glued_after).is_empty());
        let glued_underscore = format!("{}_backup", session(32));
        assert!(detect(&glued_underscore).is_empty());
    }

    #[test]
    fn oauth2_near_miss_twins_are_rejected() {
        let twins = [
            oauth2("ory_at_", 42, 43),
            oauth2("ory_at_", 43, 42),
            oauth2("ory_at_", 43, 44),
            format!("ory_at_{}", filler(B64URL, 86, 2)),
            format!(
                "ory_at_{}.{}.{}",
                filler(B64URL, 43, 2),
                filler(B64URL, 43, 3),
                filler(B64URL, 43, 4)
            ),
            format!("ory_at_{}.{}", filler(B64URL, 43, 2), filler(B64URL, 43, 3))
                .replacen("ory_at_", "ORY_AT_", 1),
            format!(
                "ory_at_{}+{}.{}",
                filler(B64URL, 20, 2),
                filler(B64URL, 22, 2),
                filler(B64URL, 43, 3)
            ),
            format!(
                "ory_at_{}/{}.{}",
                filler(B64URL, 20, 2),
                filler(B64URL, 22, 2),
                filler(B64URL, 43, 3)
            ),
            format!(
                "ory_at_{}.{}+{}",
                filler(B64URL, 43, 2),
                filler(B64URL, 20, 3),
                filler(B64URL, 22, 3)
            ),
            format!("x{}", oauth2("ory_at_", 43, 43)),
            format!("ory_ab_{}.{}", filler(B64URL, 43, 2), filler(B64URL, 43, 3)),
        ];
        for twin in twins {
            assert!(detect(&twin).is_empty(), "{twin}");
        }
    }

    #[test]
    fn benign_siblings_are_not_claimed() {
        let jwt_mention = format!(
            "eyJhbGciOiJub25lIn0.{}ory_at_{}.{}",
            filler(B64URL, 8, 1),
            filler(B64URL, 10, 2),
            "SYNTHETIC-NON-DECODABLE-SIGNATURE-MARKER"
        );
        let benign = [
            "ory_kratos_session=value".to_owned(),
            format!("ory_session_{}", filler(ALNUM, 32, 1)),
            "ory_st_placeholder".to_owned(),
            "ory_st_<your-session-token>".to_owned(),
            "ORY_SESSION_TOKEN=${ORY_SESSION_TOKEN}".to_owned(),
            format!("ory_pat_{}", filler(ALNUM, 40, 1)),
            format!("ory_apikey_{}", filler(ALNUM, 40, 1)),
            format!("ory_wak_{}", filler(ALNUM, 40, 1)),
            format!("ory_lo_{}", filler(ALNUM, 32, 1)),
            jwt_mention,
        ];
        for input in benign {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_prefixes_stay_bounded() {
        let input = "ory_at_ ".repeat(1000) + &"ory_st_".repeat(1000);
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn adjacent_tokens_on_one_line_are_each_claimed() {
        let first = session(32);
        let second = oauth2("ory_rt_", 43, 43);
        let input = format!("{first} {second}");
        assert_eq!(detect(&input).len(), 2);
    }
}
