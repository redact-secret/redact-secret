//! Mapbox secret access token detection (issue #1108, handoff
//! `docs/audits/evidence/1014/mapbox.md`).
//!
//! A Mapbox access token is three dot-separated parts: a usage header (`pk`,
//! `sk` or `tk`), a base64url-encoded JSON payload and a signature. Only the
//! secret token (`sk.`) is claimed; it carries secret scopes (uploads,
//! tilesets, styles, datasets, token management, account reads). The grammar
//! is T1 under rulings R1 and R5 from the provider docs ("Tokens"), the
//! provider's `parse-mapbox-token` parser and its fixtures:
//!
//! | Part | Grammar |
//! | --- | --- |
//! | Header | `sk.` |
//! | Payload | `eyJ` + `[A-Za-z0-9_-]{20,}` (the base64url of `{"`) |
//! | Separator | `.` |
//! | Signature | exactly 22 `[A-Za-z0-9_-]` |
//!
//! The span is the whole `sk.<payload>.<signature>` token.
//!
//! ## Floor (ruling Q7, open)
//!
//! The payload has no provider-stated length: it grows with the account and
//! token contents (a Drupal module tracker records growth from 98 characters
//! in 2022). The floor of 20 characters after `eyJ` is derived from the
//! documented two-claim `{"u":...,"a":...}` object, not stated by Mapbox, and
//! the 22-character signature tail is the real anchor. Whether a derived floor
//! may serve as the T1 floor is ruling Q7 on #1014, which is open; this
//! follows its recommendation (yes). If it is refused the detector falls back
//! to a lead-pinned payload (`eyJ1Ijoi`, the documented `u` claim), which is
//! narrower.
//!
//! ## Exclusions (ruling Q9, open)
//!
//! `pk.` public tokens are designed to ship in client code and are never
//! claimed. `tk.` temporary tokens (expire within an hour, richer payload) are
//! unclaimed pending Q9, whose recommendation (stay unclaimed until a provider
//! source states their length) this follows; that is a bounded false negative.
//! A payload that does not start `eyJ`, a signature of any width other than
//! 22 and `SK.`, `sk_` and `sk-` separators are unclaimed.
//!
//! ## Overlap with `jwt`
//!
//! The `jwt` detector needs a three-segment `eyJ.eyJ.signature` shape and
//! rejects a match whose preceding byte is a token byte (`.` included), so it
//! cannot start inside `sk.eyJ...`; a Mapbox token has no second `eyJ`
//! segment. The provider type is the only finding for the span, and the same
//! JWT without an `sk.` header stays a plain `jwt` finding.
//!
//! ## Boundaries
//!
//! A byte of `[A-Za-z0-9_-]` before `sk.` (so `task.eyJ...` and `desk.`) and a
//! byte of `[A-Za-z0-9_-]` after the signature reject the match whole, never a
//! truncated one: a 23-byte signature is a false negative.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "mapbox-token";
const TYPE: &str = "mapbox_secret_access_token";

const PREFIX: &str = "sk.eyJ";
const PAYLOAD_TAIL_MIN: usize = 20;
const SIGNATURE_LEN: usize = 22;
const SIGNALS: [&str; 2] = ["mapbox-documented-prefix", "mapbox-parser-structure"];

/// The `sk.eyJ` literal and the payload tail run; the signature is checked by
/// [`has_signature`] and added to the span by the detector.
pub(super) const SHAPES: &[PrefixShape<'static>] =
    &[
        PrefixShape::at_least(PREFIX, PAYLOAD_TAIL_MIN, pattern::is_alnum_dash, &SIGNALS)
            .with_post_check(has_signature),
    ];

/// `bytes[end]` is the `.` that ends the payload run, followed by exactly
/// [`SIGNATURE_LEN`] base64url bytes that no further base64url byte continues.
fn has_signature(bytes: &[u8], _start: usize, end: usize) -> bool {
    let Some(signature) = bytes.get(end + 1..) else {
        return false;
    };
    bytes.get(end) == Some(&b'.')
        && signature.len() >= SIGNATURE_LEN
        && signature[..SIGNATURE_LEN]
            .iter()
            .all(|&byte| pattern::is_alnum_dash(byte))
        && signature
            .get(SIGNATURE_LEN)
            .is_none_or(|&byte| !pattern::is_alnum_dash(byte))
}

/// Recognizes `sk.eyJ<payload>.<22-byte signature>`.
pub(super) struct MapboxDetector;

pub(super) const MAPBOX: MapboxDetector = MapboxDetector;

impl Detector for MapboxDetector {
    fn id(&self) -> &str {
        ID
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, payload_end, signals) in
            pattern::scan_prefixed_shapes(input, SHAPES, pattern::is_alnum_dash)
        {
            // The scan stops at the payload's end and resumes there, so the
            // signature is never rescanned as a prefix (it holds no `.`).
            let end = payload_end + 1 + SIGNATURE_LEN;
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::built_in(TYPE, Confidence::High, range)
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

    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

    /// Synthetic filler, never provider-issued.
    fn filler(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(B64URL[(i * 7 + seed * 13 + i / 5) % B64URL.len()]))
            .collect()
    }

    fn token(header: &str, payload_tail: usize, signature: usize) -> String {
        format!(
            "{header}.eyJ{}.{}",
            filler(payload_tail, payload_tail),
            filler(signature, signature + 3)
        )
    }

    fn detect(input: &str) -> Vec<Candidate> {
        MAPBOX
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn assert_single(input: &str, token: &str) {
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1, "{input}");
        let start = input.find(token).unwrap();
        assert_eq!(candidates[0].type_name(), TYPE);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap(),
            "{input}"
        );
    }

    #[test]
    fn secret_tokens_are_claimed_whole_at_every_payload_width() {
        for payload in [20, 21, 55, 60, 100, 250, 2000] {
            let token = token("sk", payload, 22);
            for input in [
                token.clone(),
                format!("MAPBOX_SECRET_TOKEN={token}"),
                format!("Authorization: Bearer {token}"),
                format!("\u{d0a4}\u{1f511} \"{token}\"."),
                format!("{token}.next"),
            ] {
                assert_single(&input, &token);
            }
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        for input in [
            token("sk", 19, 22),
            token("sk", 60, 21),
            token("sk", 60, 23),
            token("pk", 60, 22),
            token("tk", 60, 22),
            token("SK", 60, 22),
            format!("sk_eyJ{}.{}", filler(60, 1), filler(22, 2)),
            format!("sk-eyJ{}.{}", filler(60, 1), filler(22, 2)),
            format!("sk.eyJ{}", filler(60, 1)),
            format!("sk.eyI{}.{}", filler(60, 1), filler(22, 2)),
            format!("sk.abc{}.{}", filler(60, 1), filler(22, 2)),
            format!("task.eyJ{}.{}", filler(60, 1), filler(22, 2)),
            format!("-sk.eyJ{}.{}", filler(60, 1), filler(22, 2)),
            format!("{}_", token("sk", 60, 22)),
            format!("{}-x", token("sk", 60, 22)),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repetition_stays_linear_and_exact() {
        assert!(detect(&"sk.eyJ".repeat(10_000)).is_empty());
        assert!(detect(&format!("sk.eyJ{}", filler(60_000, 1))).is_empty());
        let token = token("sk", 60, 22);
        assert_eq!(detect(&format!("{token} ").repeat(200)).len(), 200);
    }
}
