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

use crate::detectors::prefilter::Literals;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// The base64url encoding of `{"`, which every JWT header starts with.
const HEADER_LEAD: &str = "eyJ";
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
#[cfg(test)]
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
    let mut buf = [0u8; DECODE_BUFFER];
    let mut len = 0usize;
    let mut found = (false, false);
    let (chunks, remainder) = payload.as_chunks::<4>();
    for chunk in chunks {
        let mut combined = 0u32;
        let mut invalid = 0u8;
        for &byte in chunk {
            let sextet = SEXTET_TABLE[usize::from(byte)];
            invalid |= sextet;
            combined = (combined << 6) | u32::from(sextet & 0x3F);
        }
        if invalid & 0x80 != 0 {
            return false;
        }
        let [_, b0, b1, b2] = combined.to_be_bytes();
        if let Some(slot) = buf.get_mut(len..len + 3) {
            slot.copy_from_slice(&[b0, b1, b2]);
        }
        len += 3;
        if len > DECODE_BUFFER - 3 && !flush_decoded(&mut buf, &mut len, false, &mut found) {
            return false;
        }
    }
    if remainder.len() == 1 {
        return false;
    }
    if !remainder.is_empty() {
        let mut combined = 0u32;
        for &byte in remainder {
            let Some(sextet) = base64_url_sextet(byte) else {
                return false;
            };
            combined = (combined << 6) | u32::from(sextet);
        }
        combined <<= 6 * (4 - remainder.len());
        buf[len] = u8::try_from((combined >> 16) & 0xFF).unwrap_or(0);
        len += 1;
        if remainder.len() == 3 {
            buf[len] = u8::try_from((combined >> 8) & 0xFF).unwrap_or(0);
            len += 1;
        }
    }
    flush_decoded(&mut buf, &mut len, true, &mut found) && found.0 && found.1
}

/// Sextet value per byte; `0x80` marks a byte outside the base64url alphabet.
const SEXTET_TABLE: [u8; 256] = {
    let mut table = [0x80u8; 256];
    let mut byte = 0u8;
    loop {
        table[byte as usize] = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => 0x80,
        };
        if byte == u8::MAX {
            break;
        }
        byte += 1;
    }
    table
};

const ISS_MARKER: &str = "\"iss\":\"supabase\"";
const ROLE_MARKER: &str = "\"role\":\"anon\"";
/// Decoded text kept between flushes: one less than the longest marker, so
/// a marker split across two flushes is still found whole.
const MARKER_CARRY: usize = if ISS_MARKER.len() > ROLE_MARKER.len() {
    ISS_MARKER.len()
} else {
    ROLE_MARKER.len()
} - 1;
/// Bounded stack buffer for decoded payload bytes (no heap copy).
const DECODE_BUFFER: usize = 2048;

/// Validates the buffered decoded prefix as UTF-8 and records marker hits.
/// With `last == false`, an incomplete trailing sequence is held back (it
/// may complete in the next flush) and the buffer is trimmed to the marker
/// carry plus that tail. Returns `false` on invalid UTF-8; validation never
/// stops early on a marker hit, so later invalid UTF-8 still fails closed.
fn flush_decoded(
    buf: &mut [u8; DECODE_BUFFER],
    len: &mut usize,
    last: bool,
    found: &mut (bool, bool),
) -> bool {
    let valid = match std::str::from_utf8(&buf[..*len]) {
        Ok(text) => text.len(),
        Err(error) if !last && error.error_len().is_none() => error.valid_up_to(),
        Err(_) => return false,
    };
    let Ok(text) = std::str::from_utf8(&buf[..valid]) else {
        return false;
    };
    found.0 |= text.contains(ISS_MARKER);
    found.1 |= text.contains(ROLE_MARKER);
    if !last {
        let mut keep = valid.saturating_sub(MARKER_CARRY);
        while keep < valid && !text.is_char_boundary(keep) {
            keep += 1;
        }
        buf.copy_within(keep..*len, 0);
        *len -= keep;
    }
    true
}

/// Test-only oracle: the original heap-decoding implementation.
#[cfg(test)]
fn oracle_is_supabase_legacy_anon_claim(payload: &[u8]) -> bool {
    let Some(decoded) = base64_url_decode(payload) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    text.contains("\"iss\":\"supabase\"") && text.contains("\"role\":\"anon\"")
}

/// The structural JWT detector.
pub(super) struct JwtDetector;

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

        while cursor + HEADER_LEAD.len() <= bytes.len() {
            if &bytes[cursor..cursor + HEADER_LEAD.len()] != HEADER_LEAD.as_bytes() {
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
                    Candidate::built_in("jwt", Confidence::High, range)
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

/// The literals one of which every `jwt` candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
pub(super) const REQUIRED_LITERALS: &[Literals] = &[Literals::Strs(&[HEADER_LEAD])];

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

    // -- Streaming exception check vs. the heap-decoding oracle (#1132) -----

    fn assert_matches_oracle(payload: &[u8]) {
        assert_eq!(
            is_supabase_legacy_anon_claim(payload),
            oracle_is_supabase_legacy_anon_claim(payload),
            "payload of {} bytes",
            payload.len()
        );
    }

    fn assert_decoded_matches_oracle(decoded: &[u8]) {
        let encoded = base64_url_encode(decoded);
        assert_matches_oracle(encoded.as_bytes());
    }

    #[test]
    fn streaming_check_matches_oracle_for_markers_at_every_offset() {
        const ISS: &str = "\"iss\":\"supabase\"";
        const ROLE: &str = "\"role\":\"anon\"";
        // Fillers of 1-, 2-, 3- and 4-byte scalars so sequences straddle
        // flushes at every alignment around the 2048-byte buffer.
        for filler in ["a", "\u{e9}", "\u{20ac}", "\u{1f600}"] {
            for lead in 0..40usize {
                for gap in [
                    0usize, 1, 2, 3, 7, 480, 511, 512, 513, 1500, 2030, 2040, 2044, 2045, 2046,
                    2047, 2048, 2049, 2100,
                ] {
                    let mut text = String::new();
                    for _ in 0..(lead * 13) {
                        text.push_str(filler);
                    }
                    text.push_str(ISS);
                    for _ in 0..gap {
                        text.push_str(filler);
                    }
                    text.push_str(ROLE);
                    assert_decoded_matches_oracle(text.as_bytes());
                    let reversed = text.replace(ISS, "X").replace(ROLE, ISS) + ROLE;
                    assert_decoded_matches_oracle(reversed.as_bytes());
                    let only_iss = text.replace(ROLE, "");
                    assert_decoded_matches_oracle(only_iss.as_bytes());
                }
            }
        }
    }

    #[test]
    fn streaming_check_matches_oracle_for_trailing_and_inner_invalid_utf8() {
        const BOTH: &str = "{\"iss\":\"supabase\",\"role\":\"anon\"}";
        for pad in [
            0usize, 1, 100, 511, 512, 513, 2030, 2040, 2043, 2044, 2045, 2046, 2047, 2048, 2049,
            4090, 4100,
        ] {
            for tail in [
                &[0xFFu8][..],
                &[0xC3],
                &[0xE2, 0x82],
                &[0xF0, 0x9F, 0x98],
                &[0xC0, 0x80],
                &[0xED, 0xA0, 0x80],
                &[0x80],
            ] {
                let mut raw = vec![b' '; pad];
                raw.extend_from_slice(BOTH.as_bytes());
                raw.extend_from_slice(tail);
                assert_decoded_matches_oracle(&raw);
                let mut inner = vec![b' '; pad];
                inner.extend_from_slice(tail);
                inner.extend_from_slice(BOTH.as_bytes());
                assert_decoded_matches_oracle(&inner);
                let mut head = BOTH.as_bytes().to_vec();
                head.extend(vec![b' '; pad]);
                head.extend_from_slice(tail);
                assert_decoded_matches_oracle(&head);
            }
        }
    }

    #[test]
    fn streaming_check_matches_oracle_for_invalid_alphabet_and_remainders() {
        let anon = base64_url_encode(b"{\"iss\":\"supabase\",\"role\":\"anon\"}");
        for len in 0..=anon.len() {
            assert_matches_oracle(&anon.as_bytes()[..len]);
        }
        let mut bytes = anon.into_bytes();
        for index in 0..bytes.len() {
            let saved = bytes[index];
            for bad in [b'=', b'+', b'/', b'.', b' ', 0xFFu8] {
                bytes[index] = bad;
                assert_matches_oracle(&bytes);
            }
            bytes[index] = saved;
        }
        let mut long = base64_url_encode(
            format!(
                "{}{{\"iss\":\"supabase\",\"role\":\"anon\"}}",
                " ".repeat(5000)
            )
            .as_bytes(),
        )
        .into_bytes();
        assert_matches_oracle(&long);
        let last = long.len() - 1;
        long[last] = b'=';
        assert_matches_oracle(&long);
    }

    #[test]
    fn streaming_check_matches_oracle_for_pseudo_random_payloads() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let pieces: [&[u8]; 9] = [
            b"\"iss\":\"supabase\"",
            b"\"role\":\"anon\"",
            b"\"role\":\"service_role\"",
            "\u{20ac}".as_bytes(),
            "\u{1f600}".as_bytes(),
            b"\xFF",
            b"\xE2\x82",
            b"{\"a\":1,",
            b"                ",
        ];
        for _ in 0..4000 {
            let mut raw = Vec::new();
            let count = usize::try_from(next() % 120).unwrap_or(0);
            for _ in 0..count {
                let pick = usize::try_from(next() % 12).unwrap_or(0);
                match pieces.get(pick) {
                    Some(piece) if (pick != 5 && pick != 6) || next() % 40 == 0 => {
                        raw.extend_from_slice(piece);
                    }
                    _ => raw.push(b'a' + u8::try_from(next() % 26).unwrap_or(0)),
                }
            }
            assert_decoded_matches_oracle(&raw);
        }
    }
}
