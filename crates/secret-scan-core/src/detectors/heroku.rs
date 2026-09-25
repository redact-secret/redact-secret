//! Heroku API token detection.
//!
//! Heroku's own documentation (`devcenter.heroku.com/articles/oauth`,
//! observed 2026-09-24) documents one OAuth access token that has been
//! issued in three shapes over time. Every shape stays valid "until they're
//! regenerated", so all three are live:
//!
//! 1. A bare UUID, granted before 2024-04-01 (the legacy detector below).
//! 2. `HRKU-` plus a lower-case `8-4-4-4-12` hex UUID, 41 characters,
//!    granted 2024-04-01 through 2025-04-22 (`HEROKU_API_KEY`, issue #740).
//! 3. `HRKU-AA` plus 58 characters, 65 in total, granted from 2025-04-23
//!    (`HEROKU_API_KEY`).
//!
//! - **`HRKU-`-prefixed (shapes 2 and 3).** Heroku's OAuth access token
//!   changelog (`devcenter.heroku.com/changelog-items/2842`, observed
//!   2026-09-24) introduced the `HRKU-` prefix for every token granted on or
//!   after 2024-04-01, in front of the existing UUID: `HRKU-<uuid>`, 41
//!   characters. A later changelog
//!   (`devcenter.heroku.com/changelog-items/3175`, observed 2026-09-24)
//!   announces the token length "increasing from 41 characters to 65
//!   characters" from 2025-04-23, and repeats that current tokens "remain
//!   unchanged until they're regenerated". The prefix is a documented literal marker, so the 41-character shape
//!   needs no surrounding context either. Its body is exactly a lower-case
//!   `8-4-4-4-12` hex UUID (36 bytes), checked by [`is_lower_uuid_after`];
//!   a 35-byte body, a longer run, an upper-case body, or an `HRKU_`
//!   separator is not this shape.
//!
//!   For the 65-character shape, the `oauth` article states: "Heroku OAuth
//!   access tokens are 65 characters long and prefixed with `HRKU-`", with
//!   the worked example
//!   `HRKU-AALJCYR7SRzPkj9_BGqhi1jAI1J5P4WfD6ITENvdVydAPCnNcAlrMMahHrTo`.
//!   Two independently maintained tools, consulted only as external
//!   behavioral references per `AGENTS.md`, corroborate this exact shape and
//!   additionally fix the two bytes right after the dash to a literal `AA`:
//!
//!   ```text
//!   gitleaks 8.30.1's heroku-api-key-v2 rule:
//!     \b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\x60'"\s;]|\\[nr]|$)
//!   trufflehog 3.97.4's heroku/v2 detector:
//!     \b(HRKU-AA[0-9a-zA-Z_-]{58})\b
//!   ```
//!
//!   The provider's own worked example and both tools agree: a literal
//!   `HRKU-AA` marker (7 bytes), then exactly 58 bytes of
//!   [`pattern::is_alnum_dash`] (`[A-Za-z0-9_-]`), 65 bytes total. This
//!   shape needs no surrounding context, matching every other documented
//!   exact-length literal-prefix shape in this crate
//!   ([`super::postman::POSTMAN`], [`super::additional_providers::NPM`]).
//!
//! - **Legacy (pre-`HRKU-`, a bare UUID).** The same changelog states
//!   existing tokens "continue to work and remain unchanged until
//!   regenerated", so the old, unprefixed shape stays live indefinitely. A
//!   standard `8-4-4-4-12` hex UUID carries no marker of its own -- it is
//!   indistinguishable by structure alone from a Heroku app id, a release
//!   id, or any unrelated UUID. Two independently maintained tools converge
//!   on requiring a case-insensitive `heroku` substring alongside this exact
//!   bare shape and never emit it unconditionally:
//!
//!   ```text
//!   gitleaks 8.30.1's heroku-api-key rule (keyword-gated):
//!     (?i)[\w.-]{0,50}?(?:heroku)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)
//!   trufflehog 3.97.4's heroku/v1 detector (keyword-gated,
//!   Keywords() == ["heroku"]):
//!     \b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b
//!   ```
//!
//!   This detector follows the same corroborated policy: a bare UUID-shaped
//!   run is reported only when its line also carries a case-insensitive
//!   `heroku` substring, at [`Confidence::Medium`] -- the same
//!   weaker-heuristic tier [`super::confluent`]'s own legacy path and
//!   [`super::new_relic`]'s License Key path use, and, like those,
//!   deliberately left out of [`policy::ALWAYS_REDACT_TYPES`] rather than
//!   promoted to an unconditional redact.
//!
//!   The keyword gate alone cannot tell the token from a Heroku app id: a
//!   line such as `HEROKU_APP_ID=<uuid>` names heroku too, and both tools
//!   above flag it. This detector departs from them there (issue #714): a
//!   UUID assigned to an identifier-shaped key -- one whose last word is
//!   `id` or `uuid`, e.g. `HEROKU_APP_ID`, `app_id`, `release-id`,
//!   `appId`, `id` -- is a public identifier, not a credential, and is
//!   never reported. The tradeoff is a false negative for a legacy token
//!   stored under such a key name, which no Heroku tooling documents.
//!
//!   For the same reason, a UUID that is a URL path segment (the byte
//!   before it is `/`, as in `https://api.heroku.com/apps/<uuid>/dynos`) is
//!   a Platform API resource id and is never reported (issue #743). The
//!   token itself never appears as a path segment of a Heroku URL.
//!
//!   Two documented places put the `heroku` context on a different line
//!   from the token, and the same-line gate alone would miss both (issue
//!   #743). Each is accepted only in its exact documented layout:
//!
//!   - **A multi-line `.netrc` entry**, as the Heroku CLI writes it: a line
//!     `machine <host>` whose host contains `heroku`, at most
//!     [`NETRC_MAX_CONTINUATION_LINES`] `login`/`account` lines, then a line
//!     where the UUID is the value of a `password` token. Another `machine`
//!     line, any other line, or a longer gap ends the entry.
//!   - **`heroku auth:token` output**: the UUID is the whole line (surrounding
//!     whitespace aside) and the line right before it ends with the
//!     `heroku auth:token` command.
//!
//!   A bare UUID after any other line stays clean, so the wider window never
//!   turns into an unconditional UUID match. Both layouts cross a line
//!   terminator, so the incremental session keeps such a unit open until
//!   the line that can carry the token arrives
//!   ([`has_open_heroku_legacy_context`]).
//!
//! No code from either tool is reproduced here; this module's matching and
//! context-gating logic is authored independently.
//!
//! ## Out of scope
//!
//! No other Heroku credential form (an app id, a dyno id, a release id, a
//! `netrc` machine-scoped token, an OAuth client secret) is documented or
//! tool-corroborated with its own grammar distinct from the two shapes
//! above, so none is given one here -- the issue's stated exclusion
//! boundary. An ordinary UUID -- an app id, a release id, or any other
//! identifier -- with no `heroku` keyword on the same line is never reported
//! by the legacy detector outside the two multi-line layouts above, and
//! never by the current-format detector regardless of context, since it
//! carries no `HRKU-` prefix.

use crate::detectors::additional_providers::KnownFormatProviderDetector;
use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::detectors::text;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const CURRENT_PREFIX: &str = "HRKU-AA";
/// The documented total length (65) minus the seven-byte [`CURRENT_PREFIX`].
const CURRENT_BODY_LEN: usize = 58;

const CURRENT_SIGNALS: [&str; 2] = ["heroku-documented-prefix", "heroku-documented-length"];

/// The 41-character generation's literal prefix (issue #740).
const UUID_PREFIX: &str = "HRKU-";

/// `true` when the 36 bytes after the `HRKU-` prefix of `bytes[start..end]`
/// are a lower-case `8-4-4-4-12` hex UUID: a dash at each of
/// [`UUID_DASH_OFFSETS`], [`pattern::is_lower_hex`] everywhere else.
fn is_lower_uuid_after(bytes: &[u8], start: usize, end: usize) -> bool {
    let body_start = start + UUID_PREFIX.len();
    end - body_start == LEGACY_UUID_LEN
        && is_uuid_shape(bytes, body_start, end, pattern::is_lower_hex)
}

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier -- the
/// alphabet is already the widest boundary class in this crate, matching
/// every other `[A-Za-z0-9_-]`-bodied provider shape's own boundary.
const CURRENT_BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// The `HRKU-`-prefixed OAuth access token in both documented generations:
/// the literal `HRKU-AA` marker plus exactly 58 bytes of `[A-Za-z0-9_-]`,
/// 65 bytes total, or the literal `HRKU-` plus a lower-case `8-4-4-4-12` hex
/// UUID, 41 bytes total (issue #740). Both are unconditionally
/// [`Confidence::High`] and [`Specificity::Provider`] -- no context needed.
/// The longer `HRKU-AA` prefix wins at a shared position, and a lower-case
/// UUID body can never start with `AA`, so the two shapes never compete.
pub(super) const HEROKU_API_KEY: KnownFormatProviderDetector = KnownFormatProviderDetector::new(
    "heroku-api-key",
    "heroku_api_key",
    &[
        PrefixShape::exact(
            CURRENT_PREFIX,
            CURRENT_BODY_LEN,
            pattern::is_alnum_dash,
            &CURRENT_SIGNALS,
        ),
        PrefixShape::exact(
            UUID_PREFIX,
            LEGACY_UUID_LEN,
            pattern::is_hex_or_dash,
            &CURRENT_SIGNALS,
        )
        .with_post_check(is_lower_uuid_after),
    ],
    CURRENT_BOUNDARY,
);

const CONTEXT_KEYWORD: &str = "heroku";

/// The legacy shape's total byte length: `8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12`.
const LEGACY_UUID_LEN: usize = 36;

/// The dash offsets a standard UUID fixes, counted from the run's own start.
const UUID_DASH_OFFSETS: [usize; 4] = [8, 13, 18, 23];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier, matching
/// [`CURRENT_BOUNDARY`]'s own reasoning.
const LEGACY_BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// Every line of `input` as a byte range excluding the terminating `\n` (a
/// trailing `\r` stays part of the line). Mirrors [`super::confluent::lines`]
/// and [`super::twilio::lines`]; duplicated rather than shared, matching
/// those modules' own "keep context-gating logic self-contained" reasoning.
fn lines(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start > bytes.len() {
            return None;
        }
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(bytes.len(), |offset| start + offset);
        let line = (start, end);
        start = end + 1;
        Some(line)
    })
}

/// `true` when `needle` (ASCII, case-insensitive) occurs anywhere in `line`.
fn line_contains_ci(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    needle.len() <= bytes.len()
        && (0..=bytes.len() - needle.len()).any(|pos| text::starts_with_ci(line, pos, needle))
}

/// Every non-overlapping, boundary-checked bare run of exactly
/// [`LEGACY_UUID_LEN`] `alphabet` bytes, left to right.
fn scan_bare_legacy_runs(
    input: &str,
    alphabet: Alphabet,
    boundary: Alphabet,
) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = pattern::run_ends(bytes, alphabet);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !alphabet(bytes[start]) {
            start += 1;
            continue;
        }
        let run_end = ends[start];
        if run_end - start == LEGACY_UUID_LEN
            && pattern::boundary_ok(bytes, start, run_end, boundary)
        {
            matches.push((start, run_end));
        }
        start = run_end;
    }
    matches
}

/// `true` when the matched run has a dash at exactly each of
/// [`UUID_DASH_OFFSETS`] and every other byte is in `hex` -- the internal
/// structure a same-length [`pattern::is_hex_or_dash`] alphabet alone cannot
/// express, since that alphabet accepts a dash at any offset.
fn is_uuid_shape(bytes: &[u8], start: usize, end: usize, hex: Alphabet) -> bool {
    (start..end).all(|index| {
        let offset = index - start;
        if UUID_DASH_OFFSETS.contains(&offset) {
            bytes[index] == b'-'
        } else {
            hex(bytes[index])
        }
    })
}

/// `true` for a byte an assignment may place between a key and its value:
/// whitespace, a quote, or a byte of `=`, `:`, `:=`, `=>`, `?=`, `||`, `,`.
fn is_assignment_gap(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'"' | b'\'' | b'`' | b'=' | b':' | b'>' | b'?' | b'|' | b','
    )
}

/// `true` for a byte of a key name: `[A-Za-z0-9_.-]`.
fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

/// The key a value starting at `value_start` is assigned to: the run of
/// [`is_key_byte`] bytes left of any [`is_assignment_gap`] bytes before the
/// value. Empty when the value has no key (a `/` or line start before it).
fn assigned_key(bytes: &[u8], value_start: usize) -> &[u8] {
    let mut end = value_start;
    while end > 0 && is_assignment_gap(bytes[end - 1]) {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_key_byte(bytes[start - 1]) {
        start -= 1;
    }
    &bytes[start..end]
}

/// The last words that make a key name an identifier rather than a secret.
const IDENTIFIER_WORDS: [&[u8]; 2] = [b"id", b"uuid"];

/// `true` when `key`'s last word is one of [`IDENTIFIER_WORDS`]: the whole
/// key (`id`, `UUID`), the segment after its last `_`, `.` or `-`
/// (`HEROKU_APP_ID`, `release-id`), or a camelCase tail after a lowercase
/// letter or digit (`appId`, `appID`, `releaseUuid`).
fn is_identifier_key(key: &[u8]) -> bool {
    let segment_start = key
        .iter()
        .rposition(|&byte| matches!(byte, b'_' | b'.' | b'-'))
        .map_or(0, |index| index + 1);
    let segment = &key[segment_start..];
    IDENTIFIER_WORDS.iter().any(|word| {
        if segment.eq_ignore_ascii_case(word) {
            return true;
        }
        let Some(split) = segment
            .len()
            .checked_sub(word.len())
            .filter(|&split| split > 0)
        else {
            return false;
        };
        let (head, tail) = segment.split_at(split);
        tail.eq_ignore_ascii_case(word)
            && tail[0].is_ascii_uppercase()
            && head
                .last()
                .is_some_and(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}

/// `true` when the value starting at `value_start` is a URL path segment:
/// the byte right before it is `/` (issue #743).
fn is_url_path_segment(bytes: &[u8], value_start: usize) -> bool {
    value_start > 0 && bytes[value_start - 1] == b'/'
}

/// `true` for the horizontal whitespace that separates `.netrc` tokens and
/// shell words; a trailing `\r` of a CRLF line counts too.
fn is_token_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r')
}

/// The whitespace-separated tokens of one line.
fn tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split([' ', '\t', '\r'])
        .filter(|token| !token.is_empty())
}

/// The most `login`/`account` lines a multi-line `.netrc` entry may carry
/// between its `machine` line and its `password` line: one of each.
const NETRC_MAX_CONTINUATION_LINES: usize = 2;

/// `true` when `line` opens a `.netrc` entry for a Heroku host (`machine
/// api.heroku.com`) and does not already carry its `password`.
fn is_heroku_netrc_machine(line: &str) -> bool {
    let mut words = tokens(line);
    words.next() == Some("machine")
        && words
            .next()
            .is_some_and(|host| line_contains_ci(host, CONTEXT_KEYWORD))
        && !tokens(line).any(|token| token == "password")
}

/// `true` when `line` continues a `.netrc` entry (starts with `login` or
/// `account`) and does not already carry its `password`.
fn is_netrc_continuation(line: &str) -> bool {
    matches!(tokens(line).next(), Some("login" | "account"))
        && !tokens(line).any(|token| token == "password")
}

/// `true` when `previous` (the lines before the value's line, oldest first)
/// ends with a Heroku `.netrc` `machine` line followed by at most
/// [`NETRC_MAX_CONTINUATION_LINES`] continuation lines.
fn ends_inside_heroku_netrc_entry(previous: &[&str]) -> bool {
    for (gap, line) in previous.iter().rev().enumerate() {
        if is_heroku_netrc_machine(line) {
            return true;
        }
        if gap >= NETRC_MAX_CONTINUATION_LINES || !is_netrc_continuation(line) {
            return false;
        }
    }
    false
}

/// `true` when the value starting at `value_start` of `line` is the value
/// of a `.netrc` `password` token: horizontal whitespace, then `password`
/// as a whole token.
fn follows_netrc_password_token(line: &[u8], value_start: usize) -> bool {
    let mut end = value_start;
    while end > 0 && is_token_space(line[end - 1]) {
        end -= 1;
    }
    let keyword = b"password";
    end < value_start
        && end >= keyword.len()
        && &line[end - keyword.len()..end] == keyword
        && (end == keyword.len() || is_token_space(line[end - keyword.len() - 1]))
}

/// `true` when `line` ends with the `heroku auth:token` command, after any
/// shell prompt (`$ heroku auth:token`).
fn is_heroku_auth_token_command(line: &str) -> bool {
    let words: Vec<&str> = tokens(line).collect();
    words.ends_with(&["heroku", "auth:token"])
}

/// `true` when the matched run is the whole of `line`, surrounding
/// whitespace aside, as `heroku auth:token` prints it.
fn is_whole_line(line: &[u8], start: usize, end: usize) -> bool {
    line[..start].iter().all(|&byte| is_token_space(byte))
        && line[end..].iter().all(|&byte| is_token_space(byte))
}

/// Internal retention hint for the built-in incremental scanner: `true`
/// when the last complete line of `input` leaves a multi-line legacy-token
/// layout open -- a Heroku `.netrc` entry still waiting for its `password`
/// line, or a `heroku auth:token` command still waiting for its output
/// line -- so the session keeps the unit open rather than closing the
/// context line away from the token (issue #743). The window it holds is
/// exactly the one [`HerokuApiKeyLegacyDetector`] reads back, so the unit
/// always contains the context line whenever the whole-input scan would use
/// it.
pub(crate) fn has_open_heroku_legacy_context(input: &str) -> bool {
    let complete = input.strip_suffix('\n').unwrap_or(input);
    let mut tail: Vec<&str> = complete
        .rsplit('\n')
        .take(NETRC_MAX_CONTINUATION_LINES + 1)
        .collect();
    tail.reverse();
    tail.last()
        .is_some_and(|last| is_heroku_auth_token_command(last))
        || ends_inside_heroku_netrc_entry(&tail)
}

/// Detects a legacy (pre-`HRKU-`) Heroku API token: a bare UUID-shaped run
/// on the same line as a case-insensitive `heroku` substring, or in one of
/// the two documented multi-line layouts (a Heroku `.netrc` entry's
/// `password`, `heroku auth:token` output). A UUID assigned to an
/// identifier-shaped key ([`is_identifier_key`]) or in a URL path
/// ([`is_url_path_segment`]) is never reported. Never emitted without that
/// context; see the module doc.
pub(super) struct HerokuApiKeyLegacyDetector;

impl Detector for HerokuApiKeyLegacyDetector {
    fn id(&self) -> &'static str {
        "heroku-api-key-legacy"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        let all_lines: Vec<(usize, usize)> = lines(input).collect();
        for (index, &(line_start, line_end)) in all_lines.iter().enumerate() {
            let line = &input[line_start..line_end];
            let raw_matches = scan_bare_legacy_runs(line, pattern::is_hex_or_dash, LEGACY_BOUNDARY);
            if raw_matches.is_empty() {
                continue;
            }
            let same_line = line_contains_ci(line, CONTEXT_KEYWORD);
            let previous: Vec<&str> = all_lines
                [index.saturating_sub(NETRC_MAX_CONTINUATION_LINES + 1)..index]
                .iter()
                .map(|&(start, end)| &input[start..end])
                .collect();
            let bytes = line.as_bytes();
            for (relative_start, relative_end) in raw_matches {
                let in_context = same_line
                    || (follows_netrc_password_token(bytes, relative_start)
                        && ends_inside_heroku_netrc_entry(&previous))
                    || (is_whole_line(bytes, relative_start, relative_end)
                        && previous
                            .last()
                            .is_some_and(|line| is_heroku_auth_token_command(line)));
                if !in_context
                    || !is_uuid_shape(bytes, relative_start, relative_end, pattern::is_hex)
                    || is_identifier_key(assigned_key(bytes, relative_start))
                    || is_url_path_segment(bytes, relative_start)
                {
                    continue;
                }
                let Some(range) =
                    ByteRange::new(line_start + relative_start, line_start + relative_end)
                else {
                    continue;
                };
                let (confidence, signal) = if same_line
                    && text::is_provider_named_assignment(line, relative_start, &[CONTEXT_KEYWORD])
                {
                    (Confidence::High, "heroku-named-assignment")
                } else {
                    (Confidence::Medium, "heroku-keyword-cooccurrence")
                };
                candidates.push(
                    Candidate::new("heroku_api_key_legacy", confidence, range)
                        .with_specificity(Specificity::Provider)
                        .with_signals([signal]),
                );
            }
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly [`CURRENT_BODY_LEN`] bytes of the documented alphabet.
    /// Locally constructed synthetic value; never provider-issued.
    const CURRENT_BODY: &str = "SYNTHETIC0REVOKED0HerokuOAuthAccessTokenBodyFixture0123456";
    const _: () = assert!(CURRENT_BODY.len() == CURRENT_BODY_LEN);

    /// A standard UUID shape with no `heroku` substring of its own so
    /// keyword-gating tests are clean. Locally constructed synthetic value;
    /// never provider-issued.
    const LEGACY_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const _: () = assert!(LEGACY_UUID.len() == LEGACY_UUID_LEN);

    fn current_token() -> String {
        format!("{CURRENT_PREFIX}{CURRENT_BODY}")
    }

    fn detect_current(input: &str) -> Vec<Candidate> {
        HEROKU_API_KEY
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn detect_legacy(input: &str) -> Vec<Candidate> {
        HerokuApiKeyLegacyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    // -- Current (`HRKU-`-prefixed) detector --------------------------------

    #[test]
    fn detects_the_current_token_with_no_context_needed() {
        let value = current_token();
        let candidates = detect_current(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "heroku_api_key");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_current_body_one_byte_short_of_the_documented_length() {
        let short_body = &CURRENT_BODY[..CURRENT_BODY_LEN - 1];
        assert!(detect_current(&format!("{CURRENT_PREFIX}{short_body}")).is_empty());
    }

    #[test]
    fn rejects_a_current_body_one_byte_longer_than_the_documented_length() {
        assert!(detect_current(&format!("{CURRENT_PREFIX}{CURRENT_BODY}a")).is_empty());
    }

    #[test]
    fn rejects_undocumented_near_miss_prefixes() {
        for input in [
            format!("HRKU-AB{CURRENT_BODY}"),
            format!("hrku-aa{CURRENT_BODY}"),
            format!("HRKU{CURRENT_BODY}"),
            format!("HRKU-A{CURRENT_BODY}"),
        ] {
            assert!(detect_current(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        assert!(detect_current(&format!("legacy_{}", current_token())).is_empty());
        assert!(detect_current(&format!("{}_backup", current_token())).is_empty());
    }

    #[test]
    fn rejects_a_masked_value() {
        assert!(
            detect_current(&format!("{CURRENT_PREFIX}{}", "*".repeat(CURRENT_BODY_LEN))).is_empty()
        );
        assert!(detect_current(&format!("{CURRENT_PREFIX}${{HEROKU_API_KEY}}")).is_empty());
    }

    /// The body alphabet is `[A-Za-z0-9_-]`, the same wide alnum-dash class
    /// every other infra-provider exact-length shape in this crate uses
    /// (`super::additional_providers`'s own
    /// `infra_providers_accept_a_doc_style_placeholder_built_from_valid_alphabet_characters`):
    /// an `x`-filled placeholder is built entirely from valid alphabet
    /// characters, so it is indistinguishable from a genuine token and is
    /// accepted, not rejected.
    #[test]
    fn accepts_a_doc_style_x_filled_placeholder_built_from_valid_alphabet_characters() {
        assert_eq!(
            detect_current(&format!("{CURRENT_PREFIX}{}", "x".repeat(CURRENT_BODY_LEN))).len(),
            1
        );
    }

    #[test]
    fn accepts_env_json_yaml_and_quoted_contexts() {
        let value = current_token();
        for input in [
            format!("HEROKU_API_KEY={value}"),
            format!("{{\"apiKey\": \"{value}\"}}"),
            format!("authorization: Bearer {value}"),
            format!("authorization=\"Bearer {value}\""),
        ] {
            let candidates = detect_current(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            let start = input.rfind(&value).unwrap();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + value.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn finds_a_match_across_crlf_and_a_unicode_prefix() {
        let value = current_token();
        let input = format!("# \u{1F511} caf\u{e9}\r\n{value}\r\n");
        let candidates = detect_current(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.find(&value).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + value.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let value = current_token();
        assert_eq!(detect_current(&value), detect_current(&value));
    }

    #[test]
    fn reports_a_repeated_identical_value_once_per_occurrence() {
        let value = current_token();
        let input = format!("{value} {value}");
        assert_eq!(detect_current(&input).len(), 2);
    }

    #[test]
    fn stays_bounded_over_a_long_run_of_near_miss_prefixes() {
        let short_body = &CURRENT_BODY[..CURRENT_BODY_LEN - 1];
        let input = format!("{CURRENT_PREFIX}{short_body} ").repeat(10_000);
        assert_eq!(detect_current(&input).len(), 0);
    }

    // -- 41-character `HRKU-<uuid>` generation (issue #740) -----------------

    /// A lower-case UUID with no `heroku` substring. Locally constructed
    /// synthetic value; never provider-issued.
    const UUID_GENERATION: &str = "HRKU-5e7e71c0-0000-4000-8000-00000000fa11";
    const _: () = assert!(UUID_GENERATION.len() == 41);

    #[test]
    fn detects_the_41_character_uuid_generation_with_no_context_needed() {
        for (input, start) in [
            (UUID_GENERATION.to_string(), 0),
            (format!("HEROKU_API_KEY={UUID_GENERATION}\n"), 15),
            (format!("Token: {UUID_GENERATION}\n"), 7),
            (format!("{{\"access_token\": \"{UUID_GENERATION}\"}}"), 18),
            (format!("app_id={UUID_GENERATION}"), 7),
        ] {
            let candidates = detect_current(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "heroku_api_key");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + UUID_GENERATION.len()).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_near_misses_of_the_uuid_generation() {
        let body = &UUID_GENERATION[UUID_PREFIX.len()..];
        for input in [
            // One byte short and one byte long.
            format!("HEROKU_API_KEY={}\n", &UUID_GENERATION[..40]),
            format!("HEROKU_API_KEY={UUID_GENERATION}0\n"),
            // Undocumented separator and prefix case.
            format!("HEROKU_API_KEY=HRKU_{body}\n"),
            format!("hrku-{body}"),
            // Upper-case body, dash at the wrong offset, non-hex letter.
            format!("HRKU-{}", body.to_ascii_uppercase()),
            "HRKU-5e7e71c00-000-4000-8000-00000000fa11".to_string(),
            "HRKU-5e7e71g0-0000-4000-8000-00000000fa11".to_string(),
            // Embedded in a wider identifier.
            format!("legacy_{UUID_GENERATION}"),
            format!("{UUID_GENERATION}_backup"),
        ] {
            assert!(detect_current(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn keeps_both_generations_apart_on_one_line() {
        let current = current_token();
        let input = format!("{UUID_GENERATION} {current}");
        let candidates = detect_current(&input);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].range(), ByteRange::new(0, 41).unwrap());
        assert_eq!(candidates[1].range(), ByteRange::new(42, 42 + 65).unwrap());
    }

    #[test]
    fn the_legacy_detector_never_reports_the_uuid_inside_the_prefixed_generation() {
        for input in [
            format!("HEROKU_API_KEY={UUID_GENERATION}"),
            format!("heroku {UUID_GENERATION}"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input}");
        }
    }

    // -- Legacy (bare UUID, keyword-gated) detector -------------------------

    #[test]
    fn detects_a_legacy_token_under_a_heroku_named_key_at_high_confidence() {
        let input = format!("HEROKU_API_KEY={LEGACY_UUID}");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "heroku_api_key_legacy");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        let start = input.rfind(LEGACY_UUID).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LEGACY_UUID.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bare_legacy_token_with_no_context() {
        assert!(detect_legacy(LEGACY_UUID).is_empty());
    }

    #[test]
    fn rejects_an_ordinary_uuid_such_as_an_app_or_release_id() {
        // The issue's stated exclusion boundary: an ordinary UUID (an app
        // id, a release id, or any other identifier) stays clean without
        // provider context.
        for input in [
            format!("app_id={LEGACY_UUID}"),
            format!("release={LEGACY_UUID}"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn rejects_a_uuid_assigned_to_an_identifier_key_on_a_heroku_line() {
        // Issue #714: the benchmark's public-id control. The line names
        // heroku, but the key says the value is an identifier.
        for input in [
            format!("HEROKU_APP_ID={LEGACY_UUID}\n"),
            format!("heroku_app_id: {LEGACY_UUID}"),
            format!("HEROKU_RELEASE_ID = \"{LEGACY_UUID}\""),
            format!("heroku-app-uuid={LEGACY_UUID}"),
            format!("heroku.app.id={LEGACY_UUID}"),
            format!("{{\"herokuAppId\": \"{LEGACY_UUID}\"}}"),
            format!("{{\"herokuAppID\": \"{LEGACY_UUID}\"}}"),
            format!("{{\"id\": \"{LEGACY_UUID}\", \"stack\": \"heroku-24\"}}"),
            format!("heroku apps:info --json # UUID: {LEGACY_UUID}"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn keeps_a_token_assigned_to_a_key_whose_last_word_only_resembles_id() {
        // `PAID`, `Paid`, `HEROKU_IDENTITY_KEY` and `valid` end in or
        // contain "id" without it being their own last word.
        for key in [
            "HEROKU_PAID",
            "herokuPaid",
            "HEROKU_IDENTITY_KEY",
            "heroku_valid",
        ] {
            let input = format!("{key}={LEGACY_UUID}");
            assert_eq!(detect_legacy(&input).len(), 1, "{input}");
        }
    }

    #[test]
    fn judges_each_value_by_its_own_key_on_a_shared_line() {
        let token = "fedcba98-7654-3210-fedc-ba9876543210";
        let input = format!("HEROKU_APP_ID={LEGACY_UUID} HEROKU_API_KEY={token}");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(token).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + token.len()).unwrap()
        );
    }

    #[test]
    fn keeps_every_keyword_context_positive_shape() {
        for input in [
            format!("HEROKU_API_KEY={LEGACY_UUID}"),
            format!("heroku_api_key: {LEGACY_UUID}\n"),
            format!("heroku {LEGACY_UUID}"),
            format!("password {LEGACY_UUID} # api.heroku.com\n"),
            format!("secret_key={LEGACY_UUID} # heroku"),
            format!("{{\"herokuApiKey\": \"{LEGACY_UUID}\"}}"),
        ] {
            assert_eq!(detect_legacy(&input).len(), 1, "{input}");
        }
    }

    #[test]
    fn rejects_a_legacy_token_whose_context_is_on_a_different_line() {
        let input = format!("# heroku account token\n{LEGACY_UUID}\n");
        assert!(detect_legacy(&input).is_empty());
    }

    #[test]
    fn rejects_a_legacy_body_one_byte_short_or_long() {
        assert!(
            detect_legacy(&format!("heroku {}", &LEGACY_UUID[..LEGACY_UUID_LEN - 1])).is_empty()
        );
        assert!(detect_legacy(&format!("heroku {LEGACY_UUID}a")).is_empty());
    }

    #[test]
    fn rejects_a_uuid_with_a_dash_at_the_wrong_offset() {
        // The first dash lands one byte early; the run is still the
        // documented total length, but the structural post-check must
        // still reject it.
        let malformed = format!(
            "{}-{}0",
            &LEGACY_UUID[..UUID_DASH_OFFSETS[0] - 1],
            &LEGACY_UUID[UUID_DASH_OFFSETS[0] + 1..]
        );
        assert_eq!(malformed.len(), LEGACY_UUID_LEN);
        assert!(detect_legacy(&format!("heroku {malformed}")).is_empty());
    }

    #[test]
    fn rejects_a_non_hex_letter_in_the_uuid_body() {
        let mut malformed = LEGACY_UUID.to_string();
        malformed.replace_range(0..1, "g");
        assert!(detect_legacy(&format!("heroku {malformed}")).is_empty());
    }

    #[test]
    fn matches_heroku_keyword_case_insensitively() {
        for keyword in ["Heroku", "HEROKU", "heroku"] {
            let input = format!("{keyword}_API_KEY={LEGACY_UUID}");
            assert_eq!(detect_legacy(&input).len(), 1, "{keyword}");
        }
    }

    #[test]
    fn finds_a_qualified_legacy_match_across_crlf_and_a_unicode_prefix() {
        let input = format!("# \u{1F511} caf\u{e9}\r\nheroku {LEGACY_UUID}\r\n");
        let candidates = detect_legacy(&input);
        assert_eq!(candidates.len(), 1);
        let start = input.rfind(LEGACY_UUID).unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(start, start + LEGACY_UUID.len()).unwrap()
        );
    }

    #[test]
    fn finds_deterministic_legacy_findings_across_repeated_calls() {
        let input = format!("heroku {LEGACY_UUID}");
        assert_eq!(detect_legacy(&input), detect_legacy(&input));
    }

    // -- Multi-line layouts and URL paths (issue #743) ----------------------

    fn legacy_ranges(input: &str) -> Vec<(usize, usize)> {
        detect_legacy(input)
            .iter()
            .map(|candidate| (candidate.range().start(), candidate.range().end()))
            .collect()
    }

    #[test]
    fn detects_the_password_of_a_multi_line_heroku_netrc_entry() {
        let input = format!(
            "machine api.heroku.com\n  login someone@example.invalid\n  password {LEGACY_UUID}\n"
        );
        assert_eq!(legacy_ranges(&input), [(66, 102)]);
        for input in [
            format!("machine git.heroku.com\npassword {LEGACY_UUID}\n"),
            format!(
                "machine api.heroku.com\r\n\tlogin a@example.invalid\r\n\tpassword {LEGACY_UUID}\r\n"
            ),
            format!(
                "machine api.heroku.com\n  login a@example.invalid\n  account x\n  password {LEGACY_UUID}\n"
            ),
            format!("machine api.heroku.com\n  login a@example.invalid password {LEGACY_UUID}\n"),
        ] {
            assert_eq!(detect_legacy(&input).len(), 1, "{input:?}");
        }
    }

    #[test]
    fn rejects_a_netrc_password_outside_a_heroku_entry() {
        for input in [
            // Another host.
            format!("machine example.com\n  login a@example.invalid\n  password {LEGACY_UUID}\n"),
            // A later non-Heroku entry closes the Heroku one.
            format!(
                "machine api.heroku.com\n  login a\nmachine example.com\n  password {LEGACY_UUID}\n"
            ),
            // A Heroku entry that already carried its password.
            format!("machine api.heroku.com password x\n  password {LEGACY_UUID}\n"),
            // Too many lines between the machine line and the password.
            format!(
                "machine api.heroku.com\n  login a\n  account b\n  login c\n  password {LEGACY_UUID}\n"
            ),
            // An unrelated line in between.
            format!("machine api.heroku.com\n# note\n  password {LEGACY_UUID}\n"),
            // Not the value of a password token.
            format!("machine api.heroku.com\n  login {LEGACY_UUID}\n"),
            format!("machine api.heroku.com\n  mypassword {LEGACY_UUID}\n"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn detects_heroku_auth_token_output_on_the_next_line() {
        let input = format!("$ heroku auth:token\n{LEGACY_UUID}\n");
        assert_eq!(legacy_ranges(&input), [(20, 56)]);
        for input in [
            format!("heroku auth:token\r\n{LEGACY_UUID}\r\n"),
            format!("user@host:~$ heroku auth:token\n  {LEGACY_UUID}"),
        ] {
            assert_eq!(detect_legacy(&input).len(), 1, "{input:?}");
        }
    }

    #[test]
    fn rejects_a_uuid_line_after_anything_but_the_auth_token_command() {
        for input in [
            format!("$ heroku apps:info\n{LEGACY_UUID}\n"),
            format!("$ heroku auth:token --help\n{LEGACY_UUID}\n"),
            format!("$ heroku auth:token\n\n{LEGACY_UUID}\n"),
            format!("$ heroku auth:token\nid: {LEGACY_UUID}\n"),
            format!("deploy notes\n{LEGACY_UUID}\n"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn rejects_a_uuid_in_a_heroku_api_url_path() {
        for input in [
            format!("GET https://api.heroku.com/apps/{LEGACY_UUID}/dynos\n"),
            format!("curl https://api.heroku.com/apps/{LEGACY_UUID}"),
            format!("heroku url: /releases/{LEGACY_UUID}?x=1"),
        ] {
            assert!(detect_legacy(&input).is_empty(), "{input:?}");
        }
        assert_eq!(
            legacy_ranges(&format!(
                "GET https://api.heroku.com/apps/{LEGACY_UUID}/dynos\n"
            )),
            []
        );
        // A same-line token that is not a path segment is still reported.
        let input = format!("curl -u :{LEGACY_UUID} https://api.heroku.com/apps");
        assert_eq!(detect_legacy(&input).len(), 1);
    }

    #[test]
    fn the_retention_hint_holds_exactly_the_multi_line_layouts_open() {
        for open in [
            "machine api.heroku.com\n",
            "machine api.heroku.com\n  login a@example.invalid\n",
            "machine api.heroku.com\n  login a\n  account b\n",
            "x\nmachine api.heroku.com\r\n",
            "$ heroku auth:token\n",
        ] {
            assert!(has_open_heroku_legacy_context(open), "{open:?}");
        }
        for closed in [
            "",
            "machine example.com\n",
            "machine api.heroku.com password x\n",
            "machine api.heroku.com\n  login a\n  account b\n  login c\n",
            "machine api.heroku.com\n  password x\n",
            "$ heroku auth:token\nx\n",
            "heroku apps\n",
        ] {
            assert!(!has_open_heroku_legacy_context(closed), "{closed:?}");
        }
    }

    #[test]
    fn stays_bounded_over_a_long_context_free_line_packed_with_candidates() {
        let input = format!("{LEGACY_UUID} ").repeat(10_000);
        assert_eq!(detect_legacy(&input).len(), 0);
    }
}
