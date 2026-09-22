//! Structural JWT detector.
//!
//! Requires three non-empty base64url-looking segments and JSON-object-style
//! prefixes (`eyJ`) for both header and payload. This avoids generic dotted
//! identifiers but misses valid JWTs whose encoded payload does not begin
//! with `eyJ`.
//!
//! One narrow, deliberate exception to the "structural only, claims never
//! evaluated" rule above (issue #472): a match is dropped when its payload
//! segment base64url-decodes to text containing both `"iss":"supabase"` and
//! `"role":"anon"`. Supabase's legacy JWT-format `anon` key is a *public*
//! identifier — it ships in browser bundles and `NEXT_PUBLIC_*` variables by
//! design, the same treatment [`super::additional_providers::SUPABASE`]
//! already gives the new-format `sb_publishable_` key. Every other claim
//! (`alg`, `exp`, an absent or fabricated signature, a `service_role` or any
//! other `role`) is still ignored; see
//! `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`
//! (Supabase legacy-anon-JWT row) for the full rationale, including the accepted false-negative risk of
//! trusting an unverified payload claim.

use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const MIN_SEGMENT_TAIL_LEN: usize = 5;
const MIN_SIGNATURE_LEN: usize = 16;

/// `true` for the base64url alphabet used by every JWT segment.
fn is_base64_url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// `true` for a byte this detector treats as part of a wider token, used to
/// keep a match from starting or ending mid-identifier.
fn is_token_byte(byte: u8) -> bool {
    is_base64_url(byte) || byte == b'.'
}

/// Length of the maximal run of base64url bytes starting at `start`.
fn base64_url_run(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && is_base64_url(bytes[end]) {
        end += 1;
    }
    end - start
}

/// A successful three-segment match: the exclusive end offset, and the
/// payload segment's byte range (including its `eyJ` prefix) for the
/// narrow Supabase legacy-anon payload check.
struct JwtMatch {
    end: usize,
    payload: std::ops::Range<usize>,
}

/// Attempts a three-segment JWT match anchored exactly at `start`.
///
/// Each segment's base64url run is bounded by the next literal (`.` or end
/// of input), which is outside the base64url alphabet, so the run length is
/// unambiguous and no backtracking is needed.
fn match_jwt_at(bytes: &[u8], start: usize) -> Option<JwtMatch> {
    let header_prefix_end = start.checked_add(3)?;
    if bytes.get(start..header_prefix_end)? != b"eyJ" {
        return None;
    }
    let header_tail_len = base64_url_run(bytes, header_prefix_end);
    if header_tail_len < MIN_SEGMENT_TAIL_LEN {
        return None;
    }
    let dot_one = header_prefix_end + header_tail_len;
    if bytes.get(dot_one) != Some(&b'.') {
        return None;
    }

    let payload_prefix_start = dot_one + 1;
    let payload_prefix_end = payload_prefix_start.checked_add(3)?;
    if bytes.get(payload_prefix_start..payload_prefix_end)? != b"eyJ" {
        return None;
    }
    let payload_tail_len = base64_url_run(bytes, payload_prefix_end);
    if payload_tail_len < MIN_SEGMENT_TAIL_LEN {
        return None;
    }
    let dot_two = payload_prefix_end + payload_tail_len;
    if bytes.get(dot_two) != Some(&b'.') {
        return None;
    }

    let signature_start = dot_two + 1;
    let signature_len = base64_url_run(bytes, signature_start);
    if signature_len < MIN_SIGNATURE_LEN {
        return None;
    }

    Some(JwtMatch {
        end: signature_start + signature_len,
        payload: payload_prefix_start..dot_two,
    })
}

/// Maps one base64url alphabet byte to its 6-bit value.
fn base64_url_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes `segment` as unpadded base64url. `None` for an invalid-alphabet
/// byte (never reached by a caller here, since every caller's `segment` was
/// already validated against the base64url alphabet) or a one-sextet
/// remainder, which unpadded base64 can never legitimately produce.
fn base64_url_decode(segment: &[u8]) -> Option<Vec<u8>> {
    let low_byte = |value: u32| u8::try_from(value & 0xFF).unwrap_or(0);
    let (chunks, remainder) = segment.as_chunks::<4>();
    let mut out = Vec::with_capacity(segment.len() / 4 * 3);
    for chunk in chunks {
        let mut sextets = [0u8; 4];
        for (slot, &byte) in sextets.iter_mut().zip(chunk) {
            *slot = base64_url_sextet(byte)?;
        }
        let combined = (u32::from(sextets[0]) << 18)
            | (u32::from(sextets[1]) << 12)
            | (u32::from(sextets[2]) << 6)
            | u32::from(sextets[3]);
        out.push(low_byte(combined >> 16));
        out.push(low_byte(combined >> 8));
        out.push(low_byte(combined));
    }
    match remainder {
        [] => {}
        [a, b] => {
            let combined = (u32::from(base64_url_sextet(*a)?) << 18)
                | (u32::from(base64_url_sextet(*b)?) << 12);
            out.push(low_byte(combined >> 16));
        }
        [a, b, c] => {
            let combined = (u32::from(base64_url_sextet(*a)?) << 18)
                | (u32::from(base64_url_sextet(*b)?) << 12)
                | (u32::from(base64_url_sextet(*c)?) << 6);
            out.push(low_byte(combined >> 16));
            out.push(low_byte(combined >> 8));
        }
        _ => return None,
    }
    Some(out)
}

/// `true` when `payload` (the JWT payload segment's raw bytes, `eyJ` prefix
/// included) decodes as unpadded base64url to UTF-8 text carrying both
/// `"iss":"supabase"` and `"role":"anon"` — Supabase's own legacy-JWT anon
/// key, a public identifier by the provider's design. Undecodable base64,
/// invalid UTF-8, a non-Supabase `iss`, or any `role` other than `anon`
/// (including `service_role`) all fall through to `false`, so the
/// structural match stands. This is a deliberately narrow, exact carve-out,
/// not general JSON parsing — see the module docs.
fn is_supabase_legacy_anon_claim(payload: &[u8]) -> bool {
    let Some(decoded) = base64_url_decode(payload) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    text.contains("\"iss\":\"supabase\"") && text.contains("\"role\":\"anon\"")
}

struct JwtDetector;

impl Detector for JwtDetector {
    fn id(&self) -> &'static str {
        "jwt"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let mut candidates = Vec::new();
        let mut cursor = 0usize;

        while cursor + 3 <= bytes.len() {
            if &bytes[cursor..cursor + 3] != b"eyJ" {
                cursor += 1;
                continue;
            }

            let Some(JwtMatch { end, payload }) = match_jwt_at(bytes, cursor) else {
                cursor += 1;
                continue;
            };

            let before_is_token = cursor > 0 && is_token_byte(bytes[cursor - 1]);
            let after_is_token = end < bytes.len() && is_token_byte(bytes[end]);
            if !before_is_token
                && !after_is_token
                && !is_supabase_legacy_anon_claim(&bytes[payload])
                && let Some(range) = ByteRange::new(cursor, end)
            {
                candidates.push(
                    Candidate::new("jwt", Confidence::High, range)
                        .with_specificity(Specificity::Structural)
                        .with_signals(["three-segments", "encoded-json-prefixes"]),
                );
            }

            // `matchAll` resumes scanning at the end of the raw regex match
            // regardless of the boundary check outcome.
            cursor = end;
        }

        Ok(candidates)
    }
}

/// The structural JWT detector.
#[must_use]
pub fn jwt_detector() -> Box<dyn Detector> {
    Box::new(JwtDetector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        JwtDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn only_range(candidates: &[Candidate]) -> (usize, usize) {
        assert_eq!(candidates.len(), 1);
        (candidates[0].range().start(), candidates[0].range().end())
    }

    #[test]
    fn structured_three_segment_token_is_detected() {
        let input =
            "eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (0, input.len()));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Structural));
    }

    #[test]
    fn arbitrary_dotted_identifier_is_excluded() {
        assert!(detect("header.payload.signature").is_empty());
    }

    #[test]
    fn short_signature_is_ignored() {
        assert!(detect("eyJTWU5USEVU.eyJTWU5USEVU.short").is_empty());
    }

    #[test]
    fn token_embedded_after_a_bearer_scheme_keeps_original_offsets() {
        let input = "Authorization: Bearer eyJTWU5USEVUSUNfSEVBREVS.eyJTWU5USEVUSUNfUEFZTE9BRA.SYNTHETIC_REVOKED_SIGNATURE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (22, 101));
    }

    #[test]
    fn long_incomplete_shape_terminates_without_a_finding() {
        let input = format!("eyJ{}.missing", "A".repeat(100_000));
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn ordinary_base64_without_a_delimiter_is_excluded() {
        // Starts with the literal header prefix and is otherwise a valid,
        // long base64url run, but never reaches the required dot delimiter.
        assert!(
            detect("eyJordinaryBase64TextWithNoDelimitersAnywhereInTheRun").is_empty(),
            "the eyJ prefix alone is not sufficient without the three-segment shape"
        );
    }

    #[test]
    fn structural_match_ignores_decoded_claims_semantics() {
        // An alg:none header and an already-expired exp claim are policy and
        // structural questions the decoded JSON would answer; outside the
        // one narrow Supabase legacy-anon carve-out below, this detector
        // never decodes or evaluates claims, so the shape alone still
        // matches.
        let input = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeW50aGV0aWMtcmV2b2tlZC1zdWJqZWN0IiwiZXhwIjoxfQ.SYNTHETIC_REVOKED_UNSIGNED_PLACEHOLDER";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (0, input.len()));
    }

    #[test]
    fn adjacent_identifier_characters_reject_the_boundary() {
        assert!(
            detect("xeyJAAAAA.eyJAAAAA.AAAAAAAAAAAAAAAAAAAA").is_empty(),
            "a leading identifier character must block the match"
        );
        // The trailing base64url run is greedy, so a following identifier
        // character is simply absorbed into the signature; only a following
        // token character outside that alphabet (like `.`) can trigger the
        // boundary check.
        assert!(
            detect("eyJAAAAA.eyJAAAAA.AAAAAAAAAAAAAAAAAAAA.x").is_empty(),
            "a trailing dot must block the match"
        );
    }

    // -- Supabase legacy-anon carve-out (issue #472) ------------------------
    //
    // A real Supabase legacy JWT payload's `{"..."` opening always
    // base64url-encodes to an `eyJ`-prefixed run (any JSON object does; it
    // is why every JWT payload segment satisfies this detector's own `eyJ`
    // requirement), so `base64_url_encode` applied to ordinary JSON text
    // below needs no special-casing to build a structurally valid fixture.

    /// Test-only unpadded base64url encoder, the mirror of the production
    /// `base64_url_decode` above, so these fixtures are built from readable
    /// JSON rather than opaque literals.
    fn base64_url_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let sextet = |value: u32| ALPHABET[usize::try_from(value & 0x3F).unwrap_or(0)] as char;
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        let (chunks, remainder) = bytes.as_chunks::<3>();
        for chunk in chunks {
            let combined =
                (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            out.push(sextet(combined >> 18));
            out.push(sextet(combined >> 12));
            out.push(sextet(combined >> 6));
            out.push(sextet(combined));
        }
        match remainder {
            [] => {}
            [a] => {
                let combined = u32::from(*a) << 16;
                out.push(sextet(combined >> 18));
                out.push(sextet(combined >> 12));
            }
            [a, b] => {
                let combined = (u32::from(*a) << 16) | (u32::from(*b) << 8);
                out.push(sextet(combined >> 18));
                out.push(sextet(combined >> 12));
                out.push(sextet(combined >> 6));
            }
            _ => unreachable!(),
        }
        out
    }

    const HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;
    const SIGNATURE: &str = "SYNTHETIC_REVOKED_SUPABASE_LEGACY_JWT_SIGNATURE";

    fn jwt(payload_json: &str) -> String {
        format!(
            "{}.{}.{SIGNATURE}",
            base64_url_encode(HEADER.as_bytes()),
            base64_url_encode(payload_json.as_bytes()),
        )
    }

    #[test]
    fn a_legacy_supabase_anon_jwt_produces_no_finding() {
        let token = jwt(
            r#"{"iss":"supabase","ref":"synthproj","role":"anon","iat":1700000000,"exp":1799999999}"#,
        );
        assert!(
            detect(&token).is_empty(),
            "a public Supabase anon key must not be reported"
        );
    }

    #[test]
    fn a_legacy_supabase_anon_jwt_is_excluded_regardless_of_claim_order() {
        // The two claims are checked independently, not as one ordered
        // substring, so a payload that carries `role` before `iss` is
        // excluded exactly the same as the canonical field order.
        let token = jwt(r#"{"role":"anon","ref":"synthproj","iss":"supabase"}"#);
        assert!(detect(&token).is_empty());
    }

    #[test]
    fn a_legacy_supabase_service_role_jwt_is_still_reported_at_high_confidence() {
        let token = jwt(
            r#"{"iss":"supabase","ref":"synthproj","role":"service_role","iat":1700000000,"exp":1799999999}"#,
        );
        let candidates = detect(&token);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(only_range(&candidates), (0, token.len()));
    }

    #[test]
    fn an_anon_role_claim_under_a_non_supabase_issuer_is_still_reported() {
        let token = jwt(r#"{"iss":"not-supabase","ref":"synthproj","role":"anon"}"#);
        assert_eq!(detect(&token).len(), 1);
    }

    #[test]
    fn a_supabase_issuer_without_an_anon_role_is_still_reported() {
        for payload in [
            r#"{"iss":"supabase","role":"authenticated"}"#,
            r#"{"iss":"supabase"}"#,
        ] {
            let token = jwt(payload);
            assert_eq!(detect(&token).len(), 1, "{payload}");
        }
    }

    #[test]
    fn a_non_decodable_payload_is_still_reported() {
        // The structural matcher only bounds the payload's minimum tail
        // length (`MIN_SEGMENT_TAIL_LEN`); it does not require the segment's
        // total length to be a multiple of 4. A 9-byte payload segment
        // (`eyJ` plus 6 further base64url bytes) leaves a 1-sextet
        // remainder, which unpadded base64 can never legitimately produce,
        // so `base64_url_decode` returns `None` and the exclusion does not
        // apply.
        let payload = "eyJAAAAAA";
        assert_eq!(payload.len() % 4, 1);
        let token = format!(
            "{}.{payload}.{SIGNATURE}",
            base64_url_encode(HEADER.as_bytes())
        );
        assert_eq!(detect(&token).len(), 1);
    }

    #[test]
    fn a_payload_that_decodes_to_invalid_utf8_is_still_reported() {
        // Valid base64url, cleanly divisible into 4-byte groups, but the
        // decoded bytes are not valid UTF-8 (a lone continuation byte),
        // so the claim text can never be inspected and the exclusion does
        // not apply.
        let mut raw_payload = b"{\"x".to_vec();
        raw_payload.extend_from_slice(&[0xFF, 0xFE]);
        raw_payload.extend_from_slice(b"\"}");
        assert!(std::str::from_utf8(&raw_payload).is_err());
        let payload = base64_url_encode(&raw_payload);
        assert!(payload.starts_with("eyJ"), "{payload}");
        let token = format!(
            "{}.{payload}.{SIGNATURE}",
            base64_url_encode(HEADER.as_bytes())
        );
        assert_eq!(detect(&token).len(), 1);
    }

    #[test]
    fn base64_url_round_trips_every_remainder_length() {
        for bytes in [
            b"".as_slice(),
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"abcde",
            b"abcdef",
        ] {
            let encoded = base64_url_encode(bytes);
            assert_eq!(base64_url_decode(encoded.as_bytes()).unwrap(), bytes);
        }
    }
}
