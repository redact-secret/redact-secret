//! Baseten API key detection (issue #1111, evidence note
//! `docs/audits/evidence/1111/README.md`).
//!
//! | Prefix | Finding type |
//! | --- | --- |
//! | `b10_` | `baseten_api_key` |
//!
//! Body: exactly 8 `[A-Za-z0-9]` (the key id), one `.`, then exactly 32
//! `[A-Za-z0-9]` (the secret), 45 bytes in all. T1 (`provider-documented`):
//! Baseten's API key documentation publishes the scanner regex
//! `b10_[A-Za-z0-9]{8}\.[A-Za-z0-9]{32}` and the key-format changelog agrees.
//!
//! Keys created before 2026-10-01 15:00 GMT carry no prefix, have no
//! documented shape and still authenticate; they are an accepted false
//! negative, not part of this contract. The visible key prefix used for
//! revocation (`b10_` plus the 8-character id) lacks the secret half and is
//! not claimed. A value of any other length, a `-` or `_` in the body, an
//! uppercase `B10_` or a directly glued alphanumeric, `_` or `-` byte is
//! rejected. The provider's own documentation placeholder has the exact
//! shape and is redacted: a known false positive that costs nothing.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "baseten-api-key";
/// The finding types this detector emits; the inventory declares each one.
const TYPES: [&str; 1] = ["baseten_api_key"];

const PREFIX: &str = "b10_";
const ID_LEN: usize = 8;
const SECRET_LEN: usize = 32;
/// The id, the `.` and the secret.
const BODY_LEN: usize = ID_LEN + 1 + SECRET_LEN;
const SIGNALS: [&str; 2] = ["baseten-documented-prefix", "baseten-documented-regex"];

/// `[A-Za-z0-9_-]`: the boundary alphabet. A `.` is not glue, so a key at the
/// end of a sentence is still claimed.
fn is_token_char(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'_'
}

/// `[A-Za-z0-9.]`: the body run alphabet; the post check places the dot.
fn is_body_char(byte: u8) -> bool {
    pattern::is_alnum(byte) || byte == b'.'
}

/// Eight alphanumerics, a dot at offset 8, then 32 alphanumerics.
fn body_ok(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body = &bytes[end - BODY_LEN..end];
    body.iter().enumerate().all(|(index, &byte)| {
        if index == ID_LEN {
            byte == b'.'
        } else {
            pattern::is_alnum(byte)
        }
    })
}

/// The detector's literals for the shared prefilter.
pub(super) const SHAPES: &[PrefixShape<'static>] =
    &[PrefixShape::exact(PREFIX, BODY_LEN, is_body_char, &SIGNALS).with_post_check(body_ok)];

pub(super) struct BasetenApiKeyDetector;

pub(super) const BASETEN_API_KEY: BasetenApiKeyDetector = BasetenApiKeyDetector;

impl Detector for BasetenApiKeyDetector {
    fn id(&self) -> &str {
        ID
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end, signals) in pattern::scan_prefixed_shapes(input, SHAPES, is_token_char) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::built_in(TYPES[0], Confidence::High, range)
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

    /// Synthetic filler, never provider-issued: repeated letters and digits.
    fn id_part() -> String {
        "Synth000".to_owned()
    }

    fn secret_part() -> String {
        format!("{}{}", "Fixture".repeat(4), "0000")
    }

    fn token() -> String {
        format!("{PREFIX}{}.{}", id_part(), secret_part())
    }

    fn detect(input: &str) -> Vec<Candidate> {
        BASETEN_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn contexts(token: &str) -> Vec<String> {
        vec![
            token.to_owned(),
            format!("BASETEN_API_KEY={token}"),
            format!("export BASETEN_API_KEY=\"{token}\""),
            format!("Authorization: Api-Key {token}"),
            format!("Authorization: Bearer {token}"),
            format!("{{\"api_key\": \"{token}\"}}"),
            format!("baseten login --api-key {token}"),
            format!("Here is my key {token} can you debug this?"),
            format!("The key is {token}."),
            format!("({token})"),
        ]
    }

    #[test]
    fn the_documented_shape_is_claimed_whole_in_every_context() {
        let token = token();
        assert_eq!(token.len(), 45);
        for input in contexts(&token) {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.find(&token).unwrap();
            assert_eq!(candidates[0].type_name(), TYPES[0], "{input}");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + token.len()).unwrap(),
                "{input}"
            );
        }
        assert_eq!(BASETEN_API_KEY.id(), ID);
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        let id = id_part();
        let secret = secret_part();
        let twins = vec![
            format!("{PREFIX}{}.{secret}", &id[..7]),
            format!("{PREFIX}{id}0.{secret}"),
            format!("{PREFIX}{id}.{}", &secret[..31]),
            format!("{PREFIX}{id}.{secret}0"),
            format!("{PREFIX}{id}{secret}"),
            format!("{PREFIX}{id}-{secret}"),
            format!("{PREFIX}{id}_{secret}"),
            format!("{PREFIX}{id}..{}", &secret[..31]),
            format!("{PREFIX}{id}.{}-{}", &secret[..10], &secret[11..]),
            format!("{PREFIX}{id}.{}_{}", &secret[..10], &secret[11..]),
            format!("{PREFIX}{}-{}.{secret}", &id[..3], &id[4..]),
            format!("B10_{id}.{secret}"),
            format!("b1o_{id}.{secret}"),
            format!("b100_{id}.{secret}"),
            format!("b10-{id}.{secret}"),
            format!("bt10_{id}.{secret}"),
            format!("x{PREFIX}{id}.{secret}"),
            format!("{PREFIX}{id}.{secret}_x"),
            format!("{PREFIX}{id}.{secret}-1"),
        ];
        for input in twins {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn names_identifiers_and_references_are_not_claimed() {
        let id = id_part();
        for input in [
            "b10_".to_owned(),
            format!("{PREFIX}{id}"),
            format!("{PREFIX}{id}."),
            "BASETEN_API_KEY=${BASETEN_API_KEY}".to_owned(),
            format!(
                "BASETEN_API_KEY={PREFIX}{}.{}",
                "x".repeat(8),
                "x".repeat(8)
            ),
            "baseten org api-key delete --prefix".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repeated_values_are_reported_once_each_and_a_glued_run_never() {
        let token = token();
        assert_eq!(detect(&format!("{token} {token}")).len(), 2);
        assert!(detect(&token.repeat(200)).is_empty());
    }
}
