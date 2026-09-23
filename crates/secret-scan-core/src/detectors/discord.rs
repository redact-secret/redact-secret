//! Discord bot token detection.
//!
//! Three dot-separated segments, each an exact-length run of
//! `[A-Za-z0-9_-]` (unpadded base64url). The first segment is 24 bytes (an
//! 18-decimal-digit snowflake) or 26 bytes (a 19-decimal-digit snowflake,
//! the shape every bot ID takes once it passes 2^63/10^18 -- in practice
//! IDs created on or after 2022-07-22). The third segment is 27 bytes,
//! matching Discord's own single documented example in
//! `https://docs.discord.com/developers/reference`, or 38 bytes, the shape
//! every token has taken since Discord widened it (~May 2022), whichever
//! bot's token it is. A 26-byte first segment never pairs with a 27-byte
//! third segment: by the time an ID reaches 19 digits, the third segment had
//! already widened. These lengths are corroborated, consulted only as an
//! external behavioral reference per `AGENTS.md` (no code copied from either
//! project), by gitleaks's and trufflehog's independent Discord bot-token
//! rules, and by issue #670's evidence run.
//!
//! A three-dot-segment base64url shape alone is indistinguishable from a
//! JWT (see [`super::jwt`]), so this detector requires the first segment to
//! decode, as unpadded base64url, to a run of ASCII digit bytes only -- the
//! shape of a Discord snowflake ID rendered as its decimal string. A JWT's
//! first segment decodes to JSON (`{"..."`), never to an all-digit string,
//! so this requirement anchors the detector to Discord's specific token
//! shape without overlapping the JWT detector's grammar. See
//! `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`
//! (Discord row) for the full rationale and what is deliberately out of scope (webhook URL
//! tokens, `OAuth2` client secrets, `mfa.`-prefixed user/self-bot tokens).

use crate::detectors::pattern::{self, is_alnum_dash};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const SEGMENT_ONE_LEN_LEGACY: usize = 24;
const SEGMENT_ONE_LEN_CURRENT: usize = 26;
const SEGMENT_TWO_LEN: usize = 6;
const SEGMENT_THREE_LEN_LEGACY: usize = 27;
const SEGMENT_THREE_LEN_CURRENT: usize = 38;

/// Recognizes a Discord bot token by its documented three-segment shape and
/// a digit-decoding first segment. No surrounding context (`DISCORD_TOKEN=`,
/// `Authorization: Bot`, ...) is required to classify a match: like every
/// other `Specificity::Provider` detector in this module, the shape is
/// treated as specific enough on its own.
pub(super) struct DiscordBotTokenDetector;

impl Detector for DiscordBotTokenDetector {
    fn id(&self) -> &'static str {
        "discord-bot-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in scan(input) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("discord_bot_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(["three-segment-shape", "digit-decoding-snowflake"]),
            );
        }
        Ok(candidates)
    }
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

/// `true` when `segment` (every caller passes exactly
/// [`SEGMENT_ONE_LEN_LEGACY`] or [`SEGMENT_ONE_LEN_CURRENT`] bytes, so the
/// length is always a multiple of 4 or leaves a 2-byte remainder) decodes,
/// as unpadded base64url, to a byte sequence containing only ASCII digits.
/// No intermediate buffer is allocated: each 4-byte group decodes directly
/// to its 3 raw bytes, and a trailing 2-byte group (the shape an unpadded
/// base64url encoding of a length-not-divisible-by-3 byte string leaves,
/// which the 19-decimal-digit snowflake case is) decodes to its 1 raw byte.
fn decodes_to_ascii_digits(segment: &[u8]) -> bool {
    debug_assert!(segment.len().is_multiple_of(4) || segment.len() % 4 == 2);
    let (chunks, remainder) = segment.as_chunks::<4>();
    let low_byte = |value: u32| u8::try_from(value & 0xFF).unwrap_or(0);
    let chunks_are_digits = chunks.iter().all(|chunk| {
        let mut sextets = [0u8; 4];
        for (slot, &byte) in sextets.iter_mut().zip(chunk) {
            match base64_url_sextet(byte) {
                Some(value) => *slot = value,
                None => return false,
            }
        }
        let combined = (u32::from(sextets[0]) << 18)
            | (u32::from(sextets[1]) << 12)
            | (u32::from(sextets[2]) << 6)
            | u32::from(sextets[3]);
        [
            low_byte(combined >> 16),
            low_byte(combined >> 8),
            low_byte(combined),
        ]
        .into_iter()
        .all(|byte| byte.is_ascii_digit())
    });
    if !chunks_are_digits {
        return false;
    }
    match remainder {
        [] => true,
        [first, second] => {
            let (Some(a), Some(b)) = (base64_url_sextet(*first), base64_url_sextet(*second)) else {
                return false;
            };
            let combined = (u32::from(a) << 6) | u32::from(b);
            low_byte(combined >> 4).is_ascii_digit()
        }
        _ => false,
    }
}

/// The exclusive end of an exact-length alphabet run starting at `start`,
/// using the precomputed maximal-run table so the check is a single bounds
/// comparison rather than a rescan.
fn segment_end(ends: &[usize], start: usize, len: usize) -> Option<usize> {
    let end = start.checked_add(len)?;
    if ends[start] < end { None } else { Some(end) }
}

/// Attempts a three-segment match anchored exactly at `start`. Returns the
/// exclusive end offset on success.
///
/// Tries each documented first-segment length; a 26-byte (19-digit
/// snowflake) first segment only pairs with a 38-byte third segment, while a
/// 24-byte (18-digit snowflake) first segment pairs with either third-segment
/// length, since a legacy bot's token grows its third segment on reset
/// without its ID gaining a digit.
fn match_at(bytes: &[u8], ends: &[usize], start: usize) -> Option<usize> {
    for (seg1_len, seg3_lens) in [
        (
            SEGMENT_ONE_LEN_CURRENT,
            [SEGMENT_THREE_LEN_CURRENT].as_slice(),
        ),
        (
            SEGMENT_ONE_LEN_LEGACY,
            [SEGMENT_THREE_LEN_CURRENT, SEGMENT_THREE_LEN_LEGACY].as_slice(),
        ),
    ] {
        let Some(seg1_end) = segment_end(ends, start, seg1_len) else {
            continue;
        };
        if bytes.get(seg1_end) != Some(&b'.') {
            continue;
        }
        if !decodes_to_ascii_digits(&bytes[start..seg1_end]) {
            continue;
        }

        let seg2_start = seg1_end + 1;
        let Some(seg2_end) = segment_end(ends, seg2_start, SEGMENT_TWO_LEN) else {
            continue;
        };
        if bytes.get(seg2_end) != Some(&b'.') {
            continue;
        }

        let seg3_start = seg2_end + 1;
        for &seg3_len in seg3_lens {
            if let Some(seg3_end) = segment_end(ends, seg3_start, seg3_len) {
                return Some(seg3_end);
            }
        }
    }
    None
}

/// Finds every non-overlapping match, left to right, the way a global regex
/// would: a failed attempt advances by one byte, and a successful one
/// advances past the whole match regardless of whether the boundary check
/// below keeps it -- the same shape `pattern::scan_prefixed_runs` uses, but
/// without a literal prefix to anchor on.
fn scan(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, is_alnum_dash);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let Some(end) = match_at(bytes, &ends, start) else {
            start += 1;
            continue;
        };
        if pattern::boundary_ok(bytes, start, end, is_alnum_dash) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    // The base64url encoding of eighteen ASCII '0' bytes: an obviously
    // synthetic, non-existent snowflake ID (Discord's snowflake epoch means
    // no real ID is ever all zero).
    const SEGMENT_ONE: &str = "MDAwMDAwMDAwMDAwMDAwMDAw";
    const SEGMENT_TWO: &str = "REVOKE";
    const SEGMENT_THREE: &str = "SYNTHETICREVOKEDBOTTOKENFIX";

    // The base64url encoding of nineteen ASCII '0' bytes: a synthetic
    // 19-decimal-digit snowflake, the shape every bot ID takes once it
    // passes 2^63/10^18 (IDs created on or after 2022-07-22).
    const SEGMENT_ONE_CURRENT: &str = "MDAwMDAwMDAwMDAwMDAwMDAwMA";
    // The 38-byte third-segment shape every Discord bot token has taken
    // since Discord widened it (~May 2022), regardless of ID length.
    const SEGMENT_THREE_CURRENT: &str = "SYNTHETICREVOKEDBOTTOKENCURRENTSHAPE38";

    fn token() -> String {
        assert_eq!(SEGMENT_ONE.len(), SEGMENT_ONE_LEN_LEGACY);
        assert_eq!(SEGMENT_TWO.len(), SEGMENT_TWO_LEN);
        assert_eq!(SEGMENT_THREE.len(), SEGMENT_THREE_LEN_LEGACY);
        format!("{SEGMENT_ONE}.{SEGMENT_TWO}.{SEGMENT_THREE}")
    }

    /// A currently-issued reset-bot token: an 18-digit-ID bot (24-byte first
    /// segment) whose token was reset after Discord widened the third
    /// segment (~May 2022), so it carries the 38-byte third segment.
    fn token_current_reset_bot() -> String {
        assert_eq!(SEGMENT_ONE.len(), SEGMENT_ONE_LEN_LEGACY);
        assert_eq!(SEGMENT_THREE_CURRENT.len(), SEGMENT_THREE_LEN_CURRENT);
        format!("{SEGMENT_ONE}.{SEGMENT_TWO}.{SEGMENT_THREE_CURRENT}")
    }

    /// A currently-issued new-bot token: a 19-digit-ID bot (26-byte first
    /// segment, created on or after 2022-07-22) paired with the 38-byte
    /// third segment every token has carried since it widened.
    fn token_current_new_bot() -> String {
        assert_eq!(SEGMENT_ONE_CURRENT.len(), SEGMENT_ONE_LEN_CURRENT);
        assert_eq!(SEGMENT_THREE_CURRENT.len(), SEGMENT_THREE_LEN_CURRENT);
        format!("{SEGMENT_ONE_CURRENT}.{SEGMENT_TWO}.{SEGMENT_THREE_CURRENT}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        DiscordBotTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn segment_one_decodes_to_all_zero_digits() {
        assert!(decodes_to_ascii_digits(SEGMENT_ONE.as_bytes()));
    }

    #[test]
    fn detects_the_documented_reference_example() {
        // The literal example from Discord's own developer reference
        // (`https://docs.discord.com/developers/reference`); a published
        // documentation placeholder, not a real credential.
        let value = "MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs";
        let candidates = detect(value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "discord_bot_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_synthetic_fixture() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "discord_bot_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_current_reset_bot_shape_24_6_38() {
        let value = token_current_reset_bot();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "discord_bot_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_current_new_bot_shape_26_6_38() {
        let value = token_current_new_bot();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "discord_bot_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_current_shapes_bare_in_env_and_json_contexts() {
        for value in [token_current_reset_bot(), token_current_new_bot()] {
            for input in [
                value.clone(),
                format!("DISCORD_TOKEN={value}"),
                format!("{{\"token\": \"{value}\"}}"),
            ] {
                let candidates = detect(&input);
                assert_eq!(candidates.len(), 1, "{input}");
                let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
                assert_eq!(&input[start..end], value, "{input}");
            }
        }
    }

    #[test]
    fn rejects_a_19_digit_snowflake_paired_with_the_legacy_27_byte_third_segment() {
        // By the time a bot ID reaches 19 digits (2022-07-22 onward), the
        // third segment had already widened to 38 bytes (~May 2022), so
        // this combination never occurs for a real token.
        let input = format!("{SEGMENT_ONE_CURRENT}.{SEGMENT_TWO}.{SEGMENT_THREE}");
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn detects_the_token_bare_in_env_and_json_contexts() {
        let value = token();
        for input in [
            value.clone(),
            format!("DISCORD_TOKEN={value}"),
            format!("{{\"token\": \"{value}\"}}"),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn detects_the_token_in_a_yaml_and_log_line_context() {
        let value = token();
        for input in [
            format!("discord_token: {value}"),
            format!("2026-09-16T00:00:00Z INFO logging in with token={value}"),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        let value = token();
        let input = format!("({value}).");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1, "{input}");
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(1, value.len() + 1).unwrap()
        );
    }

    #[test]
    fn detects_the_token_after_a_unicode_prefix_and_around_crlf() {
        let value = token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1, "{input}");
        let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
        assert_eq!(&input[start..end], value, "{input}");
    }

    #[test]
    fn finds_a_qualified_match_immediately_after_an_assignment_delimiter() {
        let value = token();
        let input = format!("discord_bot_token={value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(SEGMENT_ONE).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, input.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_segment_one_one_byte_short() {
        let short = &SEGMENT_ONE[..SEGMENT_ONE_LEN_LEGACY - 4];
        assert!(detect(&format!("{short}.{SEGMENT_TWO}.{SEGMENT_THREE}")).is_empty());
    }

    #[test]
    fn rejects_a_segment_two_one_byte_short() {
        let short = &SEGMENT_TWO[..SEGMENT_TWO_LEN - 1];
        assert!(detect(&format!("{SEGMENT_ONE}.{short}.{SEGMENT_THREE}")).is_empty());
    }

    #[test]
    fn rejects_a_segment_three_one_byte_short() {
        let short = &SEGMENT_THREE[..SEGMENT_THREE_LEN_LEGACY - 1];
        assert!(detect(&format!("{SEGMENT_ONE}.{SEGMENT_TWO}.{short}")).is_empty());
    }

    #[test]
    fn rejects_a_current_third_segment_one_byte_short() {
        let short = &SEGMENT_THREE_CURRENT[..SEGMENT_THREE_LEN_CURRENT - 1];
        assert!(detect(&format!("{SEGMENT_ONE}.{SEGMENT_TWO}.{short}")).is_empty());
        assert!(detect(&format!("{SEGMENT_ONE_CURRENT}.{SEGMENT_TWO}.{short}")).is_empty());
    }

    #[test]
    fn rejects_a_segment_one_that_does_not_decode_to_digits() {
        // Same shape as a JWT header segment: valid base64url, but decodes
        // to JSON, not an all-digit snowflake.
        let jwt_like = "eyJhbGciOiJIUzI1NiJ9";
        let padded = format!("{jwt_like}AAAA"); // pad to exactly 24 bytes
        assert_eq!(padded.len(), SEGMENT_ONE_LEN_LEGACY);
        assert!(!decodes_to_ascii_digits(padded.as_bytes()));
        assert!(detect(&format!("{padded}.{SEGMENT_TWO}.{SEGMENT_THREE}")).is_empty());
    }

    #[test]
    fn rejects_a_jwt_shaped_token_without_overlap() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SYNTHETICREVOKEDSIGNATUREVALUEFIXTURE";
        assert!(detect(jwt).is_empty());
    }

    #[test]
    fn rejects_the_token_embedded_in_a_wider_identifier() {
        let value = token();
        assert!(detect(&format!("x{value}")).is_empty(), "{value}");
        assert!(detect(&format!("{value}x")).is_empty(), "{value}");
    }

    #[test]
    fn rejects_a_webhook_url_token() {
        // A Discord webhook URL's trailing path segment is a single opaque
        // token, not three dot-joined segments; explicitly out of scope
        // per issue #301.
        assert!(detect(
            "https://discord.com/api/webhooks/198622483471925248/SYNTHETIC_REVOKED_WEBHOOK_TOKEN_VALUE"
        )
        .is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        let masked = format!(
            "{}.{}.{}",
            "*".repeat(SEGMENT_ONE_LEN_LEGACY),
            "*".repeat(SEGMENT_TWO_LEN),
            "*".repeat(SEGMENT_THREE_LEN_LEGACY)
        );
        assert!(detect(&masked).is_empty());
        let masked_current = format!(
            "{}.{}.{}",
            "*".repeat(SEGMENT_ONE_LEN_CURRENT),
            "*".repeat(SEGMENT_TWO_LEN),
            "*".repeat(SEGMENT_THREE_LEN_CURRENT)
        );
        assert!(detect(&masked_current).is_empty());
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect("${DISCORD_BOT_TOKEN}").is_empty());
    }

    #[test]
    fn rejects_a_bare_public_application_id() {
        // A bare snowflake (application/client ID) is a public identifier,
        // not a secret, and shares no shape with the three-segment grammar.
        assert!(detect("198622483471925248").is_empty());
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = token();
        assert_eq!(detect(&value), detect(&value));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_dotted_segments() {
        let value = token();
        let input = format!("{value}!{}", format!("{SEGMENT_ONE}.a.b!").repeat(10_000));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }
}
