//! Telegram Bot API token detection.
//!
//! Telegram's own documentation (`https://core.telegram.org/bots/api`,
//! "Authorizing your bot") gives exactly one example token,
//! `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`, and states that every
//! request to the Bot API is served as
//! `https://api.telegram.org/bot<token>/METHOD_NAME` -- an example request
//! URL, `https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe`,
//! is given immediately after. The docs do not publish a character-class or
//! length grammar for either segment beyond that one example, so, per
//! [`super::atlassian`]'s precedent for an undocumented-length vendor format,
//! this detector treats both segment lengths as documented minimums
//! ([`MIN_ID_LEN`], [`MIN_SECRET_LEN`]) rather than exact lengths: a shorter
//! id or a longer secret than the one example remains matched, while
//! anything shorter than the example is treated as too little evidence.
//! Consulted only as an external behavioral reference per `AGENTS.md`,
//! gitleaks's `telegram-bot-token` rule and trufflehog's `telegram` detector
//! both independently expect a wider secret alphabet than the docs' own
//! example alone evidences (the example never happens to use an underscore),
//! so [`is_alnum_dash`] (`[A-Za-z0-9_-]`) is used for the secret segment
//! rather than the narrower `[A-Za-z0-9-]` the example alone would justify;
//! no code from either project is reproduced here.
//!
//! Grammar: `<digits>:<secret>`, where `digits` is a run of ASCII digits at
//! least [`MIN_ID_LEN`] bytes long (the documented example's own "123456" is
//! six), the next byte is a literal `:`, and `secret` is a run of
//! [`is_alnum_dash`] at least [`MIN_SECRET_LEN`] bytes long (the documented
//! example's own secret segment is 34 bytes). Both runs are matched
//! maximally, so a token longer than the one published example is matched
//! unconditionally by construction.
//!
//! A token can appear bare (an environment variable, a config value, or
//! plain prose) or glued directly onto the documented Bot API URL's `/bot`
//! path segment with no separator, e.g.
//! `https://api.telegram.org/bot123456:ABC-.../getMe`. The general identifier
//! boundary check ([`is_alnum_dash`] immediately before the id) would reject
//! that second case outright, because the `t` in `bot` is itself an
//! identifier byte -- so this detector additionally admits an id run whose
//! immediately preceding bytes spell the literal path segment `/bot`
//! ([`URL_PATH_PREFIX`]), matching only Telegram's own documented URL shape
//! rather than loosening the boundary check generally. Per the issue's
//! "select only token bytes in URLs" scope note, the emitted range starts at
//! the digits, never at `/bot`.
//!
//! Two variants are intentionally out of scope, not fuzzy-matched:
//!
//! - A bare numeric chat, user, or bot id with no `:<secret>` suffix carries
//!   no secret material at all and is not a credential; this detector's
//!   grammar structurally excludes it (there is nothing to redact).
//! - A public bot username handle (e.g. `@ExampleBot`) is a public identifier
//!   Telegram itself displays and shares, an entirely different shape from
//!   the `id:secret` token grammar, and is out of scope for the same reason.
//! - A `<digits>:<uuid>` value whose secret segment is exactly a canonical
//!   8-4-4-4-12 hexadecimal UUID (issue #747). This is the shape of an
//!   Atlassian account id (`557058:<uuid>`), a public identifier every
//!   Jira/Confluence user API returns, and it otherwise satisfies this
//!   grammar's floors (36 bytes of `[A-Za-z0-9_-]`). A Telegram secret
//!   segment is not UUID-shaped: tools and community sources (issue #660)
//!   describe it as 35 bytes, one shorter than a UUID, and nothing in
//!   Telegram's documentation or example places hyphens at the UUID's fixed
//!   offsets 8/13/18/23. Only that exact layout is excluded, so a secret
//!   that merely contains hex bytes or hyphens is still matched, and a
//!   secret run that continues past the UUID is not a UUID and is matched.
//! - Telegram's separate `MTProto` client API credentials (`api_id`/`api_hash`,
//!   issued at <https://my.telegram.org> for building a Telegram *client*,
//!   not a bot) are a distinct credential family with no `id:secret` shape
//!   and are out of scope for this detector.

use crate::detectors::pattern::{self, is_alnum_dash};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// One byte below the six ASCII digits in the documented example's bot-id
/// segment (`123456`), so a shorter id than Telegram's own illustration is
/// still matched. There is no documented upper bound, so the id run is
/// matched maximally rather than to an exact length.
const MIN_ID_LEN: usize = 5;

/// Exactly the byte length of the documented example's secret segment
/// (`ABC-DEF1234ghIkl-zyx57W2v1u123ew11`), used as a floor rather than an
/// exact length because Telegram documents no length constraint on it at
/// all.
const MIN_SECRET_LEN: usize = 34;

/// The literal path segment of Telegram's own documented request URL
/// (`https://api.telegram.org/bot<token>/METHOD_NAME`), which glues directly
/// onto the token with no separator. Recognizing this one documented literal
/// admits that specific case without loosening the identifier-boundary check
/// for anything else.
const URL_PATH_PREFIX: &[u8] = b"/bot";

/// `true` for an ASCII digit, as a byte predicate for [`pattern::run_ends`].
fn is_ascii_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

/// Detects a Telegram Bot API token by its documented `<digits>:<secret>`
/// shape, bare or embedded in the documented Bot API request URL.
pub(super) struct TelegramBotTokenDetector;

impl Detector for TelegramBotTokenDetector {
    fn id(&self) -> &'static str {
        "telegram-bot-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let bytes = input.as_bytes();
        let digit_ends = pattern::run_ends(bytes, is_ascii_digit);
        let secret_ends = pattern::run_ends(bytes, is_alnum_dash);
        let mut candidates = Vec::new();
        let mut start = 0usize;

        while start < bytes.len() {
            let is_digit_run_start =
                bytes[start].is_ascii_digit() && (start == 0 || !bytes[start - 1].is_ascii_digit());
            if !is_digit_run_start {
                start += 1;
                continue;
            }

            let Some(end) = match_at(bytes, &digit_ends, &secret_ends, start) else {
                start += 1;
                continue;
            };

            if boundary_ok(bytes, start, end)
                && let Some(range) = ByteRange::new(start, end)
            {
                candidates.push(
                    Candidate::new("telegram_bot_token", Confidence::High, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals(["telegram-documented-id-colon-secret-shape"]),
                );
            }
            start = end.max(start + 1);
        }

        Ok(candidates)
    }
}

/// Attempts an `<digits>:<secret>` match anchored exactly at `start`, where
/// `bytes[start]` is already known to begin a maximal digit run. Returns the
/// exclusive end offset on success; the caller still applies the boundary
/// check.
///
/// `digit_ends` and `secret_ends` are the precomputed maximal-run-end tables
/// from [`pattern::run_ends`], so each segment's length is a table lookup
/// rather than a rescan, keeping the whole detector linear in the input
/// length.
fn match_at(
    bytes: &[u8],
    digit_ends: &[usize],
    secret_ends: &[usize],
    start: usize,
) -> Option<usize> {
    let id_end = digit_ends[start];
    if id_end - start < MIN_ID_LEN {
        return None;
    }
    if bytes.get(id_end) != Some(&b':') {
        return None;
    }

    let secret_start = id_end + 1;
    let secret_end = secret_ends[secret_start];
    if secret_end - secret_start < MIN_SECRET_LEN {
        return None;
    }
    if is_canonical_uuid(&bytes[secret_start..secret_end]) {
        return None;
    }

    Some(secret_end)
}

/// Byte offsets of the four hyphens in a canonical 8-4-4-4-12 UUID.
const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];

/// The length of a canonical 8-4-4-4-12 UUID.
const UUID_LEN: usize = 36;

/// `true` when `segment` is exactly a canonical 8-4-4-4-12 hexadecimal UUID
/// (either case): the secret segment of an Atlassian account id, not of a
/// Telegram bot token (issue #747).
fn is_canonical_uuid(segment: &[u8]) -> bool {
    segment.len() == UUID_LEN
        && segment.iter().enumerate().all(|(index, &byte)| {
            if UUID_HYPHENS.contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// `true` when the id run starting at `start` is not a truncated slice of a
/// wider identifier: either the byte immediately before it is outside
/// [`is_alnum_dash`], or the bytes immediately before it spell the
/// documented `/bot` URL path segment. The end of `secret` never needs this
/// check: it is already the end of a maximal [`is_alnum_dash`] run by
/// construction.
fn boundary_ok(bytes: &[u8], start: usize, end: usize) -> bool {
    let start_ok =
        start == 0 || !is_alnum_dash(bytes[start - 1]) || bytes[..start].ends_with(URL_PATH_PREFIX);
    let end_ok = end >= bytes.len() || !is_alnum_dash(bytes[end]);
    start_ok && end_ok
}

/// The Telegram Bot API token detector.
#[must_use]
pub fn telegram_bot_token_detector() -> Box<dyn Detector> {
    Box::new(TelegramBotTokenDetector)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123456";
    const SECRET: &str = "ABC-DEF1234ghIkl-zyx57W2v1u123ew11";

    fn token() -> String {
        format!("{ID}:{SECRET}")
    }

    fn detect(input: &str) -> Vec<Candidate> {
        TelegramBotTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn documented_example_segments_match_their_own_minimums() {
        assert_eq!(ID.len(), MIN_ID_LEN + 1);
        assert_eq!(SECRET.len(), MIN_SECRET_LEN);
    }

    #[test]
    fn detects_the_documented_example_bare() {
        let value = token();
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "telegram_bot_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_the_token_bare_in_env_and_control_contexts() {
        let value = token();
        for input in [
            value.clone(),
            format!("TELEGRAM_BOT_TOKEN={value}"),
            format!("bot_token={value}"),
            format!("{{\"botToken\": \"{value}\"}}"),
        ] {
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn detects_the_token_embedded_in_the_documented_bot_api_url_and_selects_only_the_token() {
        let value = token();
        let input = format!("https://api.telegram.org/bot{value}/getMe");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let (start, end) = (candidates[0].range().start(), candidates[0].range().end());
        assert_eq!(&input[start..end], value);
        assert_eq!(&input[..start], "https://api.telegram.org/bot");
    }

    #[test]
    fn detects_an_id_shorter_than_the_documented_example_at_the_minimum() {
        let short_id = &ID[1..];
        assert_eq!(short_id.len(), MIN_ID_LEN);
        let value = format!("{short_id}:{SECRET}");
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn detects_a_secret_longer_than_the_documented_example() {
        let input = format!("{ID}:{SECRET}EXTRA-TAIL-BYTES-PAST-THE-MINIMUM");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn rejects_an_id_one_byte_below_the_minimum() {
        let too_short = &ID[2..];
        assert_eq!(too_short.len(), MIN_ID_LEN - 1);
        assert!(detect(&format!("{too_short}:{SECRET}")).is_empty());
    }

    #[test]
    fn rejects_a_secret_one_byte_below_the_minimum() {
        let short_secret = &SECRET[..SECRET.len() - 1];
        assert!(detect(&format!("{ID}:{short_secret}")).is_empty());
    }

    #[test]
    fn rejects_a_missing_separator() {
        assert!(detect(&format!("{ID}-{SECRET}")).is_empty());
        assert!(detect(&format!("{ID}{SECRET}")).is_empty());
    }

    #[test]
    fn rejects_a_secret_broken_by_an_out_of_alphabet_byte_before_the_minimum() {
        let broken = format!("{} {}", &SECRET[..10], &SECRET[11..]);
        assert!(detect(&format!("{ID}:{broken}")).is_empty());
    }

    #[test]
    fn rejects_the_id_embedded_in_a_wider_identifier() {
        // A leading identifier byte defeats the id's boundary check. A
        // trailing one does not reject the match -- it extends the secret's
        // maximal run instead, exactly like `detects_a_secret_longer_than_the_documented_example`.
        assert!(detect(&format!("x{}", token())).is_empty());
    }

    #[test]
    fn rejects_an_atlassian_account_id_with_a_uuid_secret_segment() {
        for input in [
            "557058:0f3c9a4e-7b21-4d8e-9a6c-2e5b8d1f7c30".to_string(),
            "{\"accountId\": \"557058:0F3C9A4E-7B21-4D8E-9A6C-2E5B8D1F7C30\"}\n".to_string(),
            "assignee=712020:0f3c9a4e-7b21-4d8e-9a6c-2e5b8d1f7c30\r\n".to_string(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn detects_a_secret_that_is_near_but_not_exactly_a_uuid() {
        for secret in [
            // A hyphen moved one byte off the UUID layout.
            "0f3c9a4e7-b21-4d8e-9a6c-2e5b8d1f7c30",
            // A non-hex byte in a UUID-shaped layout.
            "0f3c9a4e-7b21-4d8e-9a6c-2e5b8d1f7c3g",
            // A UUID with more secret bytes glued on.
            "0f3c9a4e-7b21-4d8e-9a6c-2e5b8d1f7c30ab",
        ] {
            let value = format!("{ID}:{secret}");
            let candidates = detect(&value);
            assert_eq!(candidates.len(), 1, "{secret}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, value.len()).unwrap(),
                "{secret}"
            );
        }
    }

    #[test]
    fn rejects_a_bare_numeric_id_with_no_secret() {
        assert!(detect("chat_id: 123456789").is_empty());
    }

    #[test]
    fn rejects_a_public_bot_handle() {
        assert!(detect("Message @ExampleBot to get started").is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        assert_eq!(
            detect(&format!("{ID}:{}", "*".repeat(MIN_SECRET_LEN))).len(),
            0
        );
    }

    #[test]
    fn rejects_an_environment_variable_reference() {
        assert!(detect(&format!("{ID}:${{TELEGRAM_BOT_TOKEN}}")).is_empty());
    }

    #[test]
    fn rejects_a_malformed_numeric_colon_string() {
        assert!(detect("1694812800:0").is_empty());
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let input = token();
        assert_eq!(detect(&input), detect(&input));
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_rejected_near_misses() {
        let input = format!("{}!{}", token(), "1:x!".repeat(10_000));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, token().len()).unwrap()
        );
    }
}
