//! Structural JWT detector.
//!
//! Requires three non-empty base64url-looking segments and JSON-object-style
//! prefixes (`eyJ`) for both header and payload. This avoids generic dotted
//! identifiers but misses valid JWTs whose encoded payload does not begin
//! with `eyJ`.

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

/// Attempts a three-segment JWT match anchored exactly at `start`. Returns
/// the exclusive end offset on success.
///
/// Each segment's base64url run is bounded by the next literal (`.` or end
/// of input), which is outside the base64url alphabet, so the run length is
/// unambiguous and no backtracking is needed.
fn match_jwt_at(bytes: &[u8], start: usize) -> Option<usize> {
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

    Some(signature_start + signature_len)
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

            let Some(end) = match_jwt_at(bytes, cursor) else {
                cursor += 1;
                continue;
            };

            let before_is_token = cursor > 0 && is_token_byte(bytes[cursor - 1]);
            let after_is_token = end < bytes.len() && is_token_byte(bytes[end]);
            if !before_is_token
                && !after_is_token
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
        // structural questions the decoded JSON would answer; this detector
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
}
