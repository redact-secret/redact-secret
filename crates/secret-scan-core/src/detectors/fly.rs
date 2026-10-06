//! Fly.io access token detection (issue #1109, handoff
//! [`docs/audits/evidence/1014/fly.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1014/fly.md)).
//!
//! Fly.io macaroon tokens authorize the Fly API and the Machines API; a
//! session bundle (`fm2_...,fo1_...`) from `fly auth login` acts as the user.
//! The grammar is T1 under rulings R1 and R2: the `superfly/macaroon` wire
//! format (`Parse` strips the `FlyV1` scheme, splits on `,`, decodes each
//! `fm*` member with `base64.StdEncoding` and skips `fo1` members) and
//! flyctl's own log redaction rule,
//! `(fo1_|fm1[ar]_|fm2_)[a-zA-Z0-9/+_-]+=*`, which is the prefix set, an
//! alphabet that covers both standard and URL-safe Base64, optional `=`
//! padding and no upper length bound.
//!
//! | Part | Grammar |
//! | --- | --- |
//! | First member | `fm1r_`, `fm1a_` or `fm2_` + `[A-Za-z0-9+/_-]{64,}` + `={0,2}` |
//! | Further members | `,` + `fm1r_`, `fm1a_`, `fm2_` or `fo1_` + `[A-Za-z0-9+/_-]+` + `={0,2}` |
//! | Scheme | an optional `FlyV1 ` before the first member, outside the span |
//!
//! The span starts at the first `fm` member prefix and ends at the last body
//! or `=` byte of the last member, so the `FlyV1 ` scheme and its space stay in
//! place and the whole comma-joined bundle is one finding. A decoded macaroon
//! holds at least a 16-byte nonce and a 32-byte HMAC-SHA256 tail, 48 bytes, or
//! 64 standard-Base64 characters.
//!
//! ## Floor (ruling Q7, open)
//!
//! The 64-character floor is derived from that wire-format minimum, not stated
//! by Fly; the redaction rule has no floor and the scanners' 100 (gitleaks)
//! and 500 (trufflehog) are scanner choices. Whether a derived floor may serve
//! as the T1 floor is ruling Q7 on #1014, which is open; this follows its
//! recommendation (yes). A floor of 100 is a one-constant change if it is
//! refused. The floor applies to the first member only: a further member joins
//! an already claimed bundle, so it needs only a prefix and one body byte, and
//! a bare `,` followed by a member prefix with no body ends the bundle.
//!
//! ## Standalone `fo1_` (ruling Q9, open)
//!
//! A `fo1_` token with no `fm` member before it is not claimed: its length is
//! not provider-stated (43 URL-safe bytes rests on one scanner), so it stays
//! with generic coverage until Q9 is ruled, whose recommendation this follows.
//! That is a bounded false negative; a `fo1_` member that precedes the first
//! `fm` member is likewise outside the span.
//!
//! ## Boundaries
//!
//! A byte of `[A-Za-z0-9_-]` before the first prefix rejects the match (so
//! `config_fm2_...` and `xfm2_...` are not claimed). The first member's run is
//! the maximal `[A-Za-z0-9+/_-]` run, so a longer run is claimed in full, never
//! truncated; a padded member followed by another body byte is rejected whole.
//! `FM2_`, `fm3_`, `fm2-`, a non-comma separator between members, a comma
//! followed by anything but a member prefix, bodies under 64 and tiny fixtures
//! such as `fm2_hi` are unclaimed.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "fly-token";
const TYPE: &str = "fly_access_token";

const BODY_MIN: usize = 64;
const PADDING_MAX: usize = 2;
const SIGNALS: [&str; 2] = ["fly-macaroon-prefix", "fly-macaroon-floor"];

/// `[A-Za-z0-9+/_-]`: standard and URL-safe Base64, excluding the padding.
fn is_body(byte: u8) -> bool {
    pattern::is_alnum_dash(byte) || byte == b'+' || byte == b'/'
}

/// The first-member prefixes, each with the 64-byte floor; also the detector's
/// literals for the shared prefilter (`super::prefilter`, issue #983).
pub(super) const SHAPES: &[PrefixShape<'static>] = &[
    PrefixShape::at_least("fm1r_", BODY_MIN, is_body, &SIGNALS),
    PrefixShape::at_least("fm1a_", BODY_MIN, is_body, &SIGNALS),
    PrefixShape::at_least("fm2_", BODY_MIN, is_body, &SIGNALS),
];

/// Every member prefix a bundle may continue with.
const MEMBER_PREFIXES: [&[u8]; 4] = [b"fm1r_", b"fm1a_", b"fm2_", b"fo1_"];

/// Consumes up to [`PADDING_MAX`] `=` bytes at `at` and returns the new end,
/// or `None` when padding was present and a body byte follows it (a padded
/// member never continues into an identifier).
fn after_padding(bytes: &[u8], mut at: usize) -> Option<usize> {
    let padded_from = at;
    while at - padded_from < PADDING_MAX && bytes.get(at) == Some(&b'=') {
        at += 1;
    }
    if at > padded_from && bytes.get(at).is_some_and(|&byte| is_body(byte)) {
        return None;
    }
    Some(at)
}

/// The end of the bundle after the first member ended at `end`: every
/// following `,` + member prefix + at least one body byte, with padding.
fn extend_bundle(bytes: &[u8], mut end: usize) -> usize {
    loop {
        if bytes.get(end) != Some(&b',') {
            return end;
        }
        let member = end + 1;
        let Some(prefix) = MEMBER_PREFIXES
            .iter()
            .find(|prefix| bytes[member..].starts_with(prefix))
        else {
            return end;
        };
        let body_start = member + prefix.len();
        let body_end = pattern::run_end(bytes, body_start, is_body);
        if body_end == body_start {
            return end;
        }
        let Some(member_end) = after_padding(bytes, body_end) else {
            return end;
        };
        end = member_end;
    }
}

/// Recognizes a Fly macaroon token run: the first `fm` member and any
/// comma-joined members after it.
pub(super) struct FlyDetector;

pub(super) const FLY: FlyDetector = FlyDetector;

impl Detector for FlyDetector {
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
        // Members the scan finds inside an already claimed bundle are skipped.
        let mut claimed_until = 0;
        for (start, run_end, signals) in
            pattern::scan_prefixed_shapes(input, SHAPES, pattern::is_alnum_dash)
        {
            if start < claimed_until {
                continue;
            }
            let Some(padded_end) = after_padding(bytes, run_end) else {
                continue;
            };
            let end = extend_bundle(bytes, padded_end);
            claimed_until = end;
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

    const BODY: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-";

    /// Synthetic filler, never provider-issued; the last byte is alphanumeric.
    fn body(len: usize, seed: usize) -> String {
        let mut bytes: Vec<u8> = (0..len)
            .map(|i| BODY[(i * 7 + seed * 13 + i / 5) % BODY.len()])
            .collect();
        bytes[len - 1] = b'z';
        String::from_utf8(bytes).unwrap()
    }

    fn detect(input: &str) -> Vec<Candidate> {
        FLY.detect(input, &DetectorContext::new(input.len()))
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
    fn single_members_and_bundles_are_one_span_without_the_scheme() {
        let first = format!("fm2_{}", body(100, 1));
        let bundle = format!("{first},fm2_{},fo1_{}", body(200, 2), body(43, 3));
        for token in [
            format!("fm1r_{}", body(64, 4)),
            format!("fm1a_{}=", body(64, 5)),
            format!("fm2_{}==", body(700, 6)),
            first,
            bundle,
        ] {
            for input in [
                token.clone(),
                format!("FLY_API_TOKEN={token}"),
                format!("FLY_API_TOKEN=FlyV1 {token}"),
                format!("Authorization: FlyV1 {token}"),
                format!("\u{d0a4}\u{1f511} \"{token}\"."),
            ] {
                assert_single(&input, &token);
            }
        }
    }

    #[test]
    fn a_comma_not_followed_by_a_member_ends_the_bundle() {
        let first = format!("fm2_{}", body(64, 7));
        for tail in [",x", ", fm2_x", ",fm3_x", ",fo1_", ",fm2_", ",,fm2_x"] {
            assert_single(&format!("{first}{tail}"), &first);
        }
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        for input in [
            format!("fm2_{}", body(63, 8)),
            format!("fm3_{}", body(100, 8)),
            format!("fm2-{}", body(100, 8)),
            format!("FM2_{}", body(100, 8)),
            format!("xfm2_{}", body(100, 8)),
            format!("_fm2_{}", body(100, 8)),
            format!("-fm2_{}", body(100, 8)),
            format!("fo1_{}", body(100, 8)),
            format!("fo1_{}", body(43, 8)),
            format!("fm2_{}==x", body(100, 8)),
            "fm2_hi".to_owned(),
            "fm2_config_path".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn repetition_stays_linear_and_exact() {
        assert!(detect(&"fm2_ ".repeat(10_000)).is_empty());
        let long = detect(&"fm2_".repeat(10_000));
        assert_eq!(long.len(), 1);
        assert!(detect(&"+fm2_".repeat(10_000)).len() <= 1);
        let token = format!("fm2_{}", body(64, 9));
        assert_eq!(detect(&format!("{token} ").repeat(200)).len(), 200);
    }
}
