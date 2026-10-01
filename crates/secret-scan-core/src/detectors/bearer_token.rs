//! Structural Bearer authorization detector.
//!
//! Requires the explicit `Bearer` scheme and a token of at least 16
//! characters, or 12 after an explicit `Authorization:` or
//! `Proxy-Authorization:` header name (issue #818). This keeps arbitrary
//! identifiers out of scope but intentionally misses short development
//! tokens. Only the credential value, not the header, is selected.
//!
//! A value that is classic redaction filler or built entirely from
//! recognized placeholder vocabulary is excluded
//! ([`is_non_secret_bearer_value`]), the same two exclusions
//! `generic-token` applies to the `Basic`/`Token` schemes -- see issue #468
//! and `docs/specs/contextual-detection.md`. An instructional placeholder
//! (`YOUR_ACCESS_TOKEN`, `INSERT_ACCESS_TOKEN`) is excluded as well
//! ([`is_instructional_token_placeholder`], issue #745).
//!
//! A value made of token runs joined by `:` or `|` (`<id>:<secret>`,
//! `<name>|<secret>`) is selected whole, through the last joined run
//! (issue #918). Stopping at the first byte outside the RFC 6750 alphabet
//! used to redact the non-secret left half and leave the secret right half
//! readable. See [`joined_value_end`]. A join is not taken onto the key of
//! a delimited record's next field (`<tok>|email=<addr>`), `=` is padding
//! only at the end of a body, and a `name@host` value is selected whole,
//! host included (issue #939).

use super::generic_token::is_vendor_prefixed_placeholder;
use super::text::{
    ascii_run_len, ends_with_ci, find_ci, is_instructional_token_placeholder, is_js_whitespace,
    is_repeated_character_filler, matches_placeholder_vocabulary, prev_char, rskip_while_chars,
    starts_with_ci,
};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const MIN_TOKEN_LEN: usize = 16;
/// The floor after an explicit `Authorization:`/`Proxy-Authorization:`
/// header, where the header name already rules out prose. Matches the
/// `Basic`/`Token` floor in `generic-token` (issue #818).
const MIN_HEADER_TOKEN_LEN: usize = 12;
const MAX_TRAILING_EQUALS: usize = 2;

/// Mirrors `generic_token::PLACEHOLDER_WORDS`: the same whole-value
/// placeholder vocabulary `authorization_candidates` already applies to the
/// `Basic`/`Token` schemes (issue #468). Kept as a local copy rather than a
/// cross-module import, matching how `connection_string.rs` keeps its own
/// placeholder-word list rather than depending on `generic_token`.
const PLACEHOLDER_WORDS: &[&str] = &[
    "example",
    "sample",
    "placeholder",
    "redacted",
    "changeme",
    "password",
    "secret",
    "replaceme",
];

/// Mirrors `generic_token::DIGIT_SUFFIX_PLACEHOLDER_WORDS`.
const DIGIT_SUFFIX_PLACEHOLDER_WORDS: &[&str] = &[
    "example",
    "sample",
    "placeholder",
    "redacted",
    "changeme",
    "replaceme",
];

/// `true` when `value` -- the credential run before any trailing `=`
/// padding -- is classic redaction filler (`xxxxxxxxxxxxxxxxxxxx`,
/// `00000000000000000000`) or is built entirely from recognized placeholder
/// vocabulary (`PASSWORD_SECRET_EXAMPLE`), the same two exclusions
/// `generic-token` already applies to `Basic`/`Token` authorization values
/// (issue #468, following the #264 pattern). Compound placeholder forms that
/// mix a listed word with an unlisted one (`EXAMPLE_TOKEN_VALUE`) are a
/// documented, out-of-scope false negative here, same as for `generic-token`.
fn is_non_secret_bearer_value(value: &str) -> bool {
    is_repeated_character_filler(value)
        || matches_placeholder_vocabulary(value, PLACEHOLDER_WORDS, DIGIT_SUFFIX_PLACEHOLDER_WORDS)
        || is_instructional_token_placeholder(value)
        || is_vendor_prefixed_placeholder(value)
}

/// `true` for the token alphabet: `[A-Za-z0-9._~+/-]`.
fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'-')
}

/// `true` for `[A-Za-z0-9_-]`, the boundary charset that keeps a match from
/// starting inside a wider identifier.
fn is_boundary_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

/// `:` and `|`: the joins of a composite credential, `<id>:<secret>` (fal,
/// Basic-style pairs) and `<name>|<secret>` (Convex admin and deploy keys).
fn is_value_join(byte: u8) -> bool {
    byte == b':' || byte == b'|'
}

/// The number of `=` padding bytes (at most [`MAX_TRAILING_EQUALS`]) at
/// `at`, or 0 when the `=` opens a field value instead of ending a body
/// ([`opens_field_value`]): RFC 6750 allows `=` only at the end of a
/// `b64token`, so `x=1` is a `key=value` field, not padding (issue #939).
fn trailing_equals_at(bytes: &[u8], at: usize) -> usize {
    let count = (0..MAX_TRAILING_EQUALS)
        .take_while(|&offset| bytes.get(at + offset) == Some(&b'='))
        .count();
    if count > 0 && opens_field_value(bytes, at + count) {
        0
    } else {
        count
    }
}

/// `true` when the byte at `at`, right after an `=`, starts a field value
/// rather than ending a padded body: a token byte, `@`, `$`, `<`, `{` or
/// `[` (`email=alice@...`, `x=1`, `v=${X}`), or a quote that opens one
/// (`note="..."`). A quote that closes the value (`"Bearer <b64>=="`) is
/// followed by a terminator instead.
fn opens_field_value(bytes: &[u8], at: usize) -> bool {
    let opens = |byte: u8| is_token_char(byte) || matches!(byte, b'@' | b'$' | b'<' | b'{' | b'[');
    match bytes.get(at) {
        Some(&byte) if opens(byte) => true,
        Some(b'"' | b'\'') => bytes.get(at + 1).copied().is_some_and(opens),
        _ => false,
    }
}

/// `true` when the run ending at `run_end` is the key of a delimited-record
/// field rather than a credential body (issue #939): it is followed by `=`
/// that opens a field value (`|email=alice@...`, `|x=1`). `=` before
/// whitespace is read as padding, so `|ts= <value>` stays a joined run: a
/// padded body before a space is the far more common reading.
///
/// A run followed by `:` and whitespace (`|user: alice`) is deliberately
/// *not* a field key: the same bytes end the secret half of
/// `<id>:<secret>: see docs`, and dropping that run would leave the secret
/// readable. The cost is a span that also covers the label (`<tok>|user`).
fn is_field_key(bytes: &[u8], run_end: usize) -> bool {
    if bytes.get(run_end) != Some(&b'=') {
        return false;
    }
    let equals = bytes[run_end..]
        .iter()
        .take_while(|&&byte| byte == b'=')
        .count();
    opens_field_value(bytes, run_end + equals)
}

/// `[A-Za-z0-9.-]`: the bytes of a host after `@` in a `name@host` value.
fn is_host_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

/// The end of a `@host` tail at `at` (`Bearer name@host`, issue #939): `@`,
/// then a host that starts alphanumeric, with a trailing sentence `.`
/// excluded. `None` when there is no such tail.
fn host_tail_end(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'@') || !bytes.get(at + 1).is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }
    let mut end = at + 1 + ascii_run_len(bytes, at + 1, is_host_char);
    while bytes[end - 1] == b'.' {
        end -= 1;
    }
    Some(end)
}

/// The end of a Bearer value whose first token run ends at `first_end`
/// (padding included): each directly following `:` or `|` plus a non-empty
/// token run (and its own padding) is part of the same value (issue #918).
///
/// Returns `(value_end, segment_ends)`: the end of the whole value, and the
/// padding-excluded end of every run, first included, so the caller can
/// judge the floor and the placeholder exclusions on the runs. A join with
/// nothing after it (`<token>:` at a line end, `<token>: prose`) and a
/// `://` URL separator are not part of the value, so ordinary headers and
/// prose keep today's span. A join whose run is the key of a delimited
/// record's next field (`<tok>|email=<addr>`, `<tok>|x=1`) is not taken
/// either ([`is_field_key`], issue #939).
///
/// A `name@host` value (`Bearer svc-deploy@example.test`) is selected whole,
/// host included (issue #939): `@` is outside the RFC 6750 alphabet, and
/// stopping at it used to redact only the local part. The host is not a
/// run, so the floor and the placeholder exclusions still judge the
/// credential part.
///
/// The cost is linear: every byte is read at most once, and the scan never
/// crosses whitespace.
fn joined_value_end(
    bytes: &[u8],
    value_start: usize,
    first_run_end: usize,
) -> (usize, Vec<(usize, usize)>) {
    let mut runs = vec![(value_start, first_run_end)];
    let mut end = first_run_end + trailing_equals_at(bytes, first_run_end);
    while bytes.get(end).copied().is_some_and(is_value_join) {
        let run_start = end + 1;
        let run_len = ascii_run_len(bytes, run_start, is_token_char);
        // `scheme://` is a URL, not a joined credential: `Bearer https://…`
        // in prose keeps today's (floor-rejected) reading.
        if run_len == 0 || bytes[run_start..].starts_with(b"//") {
            break;
        }
        let run_end = run_start + run_len;
        if is_field_key(bytes, run_end) {
            break;
        }
        runs.push((run_start, run_end));
        end = run_end + trailing_equals_at(bytes, run_end);
    }
    let last_run_end = runs.last().map_or(first_run_end, |&(_, run_end)| run_end);
    if end == last_run_end
        && let Some(host_end) = host_tail_end(bytes, end)
    {
        end = host_end;
    }
    (end, runs)
}

/// `true` when the value ending at `value_end` is glued, directly or through
/// one `:`/`|` join, to a placeholder or reference it cannot read: an
/// `<ANGLE>` placeholder (`signkey-prod-<YOUR-SIGNING-KEY>`), a `$VAR` /
/// `${VAR}` reference (`prod:<name>|${CONVEX_BODY}`) or a `{{ }}` template.
/// The run before it is then the public lead of a placeholder, and reporting
/// it would be a partial span over a non-secret (issue #918 follow-up).
///
/// An HTML tag after a real token (`</td>`, `<br>`) is not a placeholder:
/// the angle content must be `[A-Za-z0-9_-]+`, closed by `>` within 64
/// bytes, and carry an uppercase letter, `_` or `-`.
fn is_glued_to_placeholder(bytes: &[u8], value_end: usize) -> bool {
    let mut at = value_end;
    if bytes.get(at).copied().is_some_and(is_value_join) {
        at += 1;
    }
    match bytes.get(at) {
        Some(b'$') => bytes
            .get(at + 1)
            .is_some_and(|&next| next == b'{' || next == b'_' || next.is_ascii_alphabetic()),
        Some(b'{') => bytes.get(at + 1) == Some(&b'{'),
        Some(b'<') => {
            let inner_len = bytes[at + 1..]
                .iter()
                .take(64)
                .take_while(|&&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                .count();
            let inner = &bytes[at + 1..at + 1 + inner_len];
            inner_len > 0
                && bytes.get(at + 1 + inner_len) == Some(&b'>')
                && inner
                    .iter()
                    .any(|&byte| byte.is_ascii_uppercase() || matches!(byte, b'_' | b'-'))
        }
        _ => false,
    }
}

fn is_space_or_tab(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Matches the optional `authorization\s*:\s*` prefix followed by the
/// mandatory `bearer` keyword, anchored exactly at `pos`. Returns the offset
/// right after the keyword and whether the `authorization` header name was
/// part of the match.
///
/// The two alternatives never both start with the same literal text, so
/// there is nothing to backtrack: text at `pos` either spells
/// `authorization...bearer` or it spells `bearer` directly.
fn match_scheme_at(input: &str, pos: usize) -> Option<(usize, bool)> {
    if starts_with_ci(input, pos, "authorization") {
        let mut cursor = super::text::skip_while_chars(
            input,
            pos + "authorization".len(),
            super::text::is_js_whitespace,
        );
        if super::text::char_at(input, cursor) != Some(':') {
            return None;
        }
        cursor += 1;
        cursor = super::text::skip_while_chars(input, cursor, super::text::is_js_whitespace);
        return starts_with_ci(input, cursor, "bearer").then(|| (cursor + "bearer".len(), true));
    }
    starts_with_ci(input, pos, "bearer").then(|| (pos + "bearer".len(), false))
}

/// `true` when `proxy-` (case-insensitive) sits directly before `pos` at an
/// identifier boundary: the `authorization` match is the tail of a
/// `Proxy-Authorization` header, not of a wider identifier (issue #818).
fn preceded_by_proxy_prefix(bytes: &[u8], pos: usize) -> bool {
    const PROXY: &[u8] = b"proxy-";
    pos >= PROXY.len()
        && bytes[pos - PROXY.len()..pos].eq_ignore_ascii_case(PROXY)
        && (pos == PROXY.len() || !is_boundary_identifier_char(bytes[pos - PROXY.len() - 1]))
}

fn trim_end_js_whitespace(input: &str) -> &str {
    &input[..rskip_while_chars(input, input.len(), is_js_whitespace)]
}

/// `true` for the identifier-boundary charset `[A-Za-z0-9_-]`, checked as a
/// `char` for use against a backward-scanned lookbehind character.
fn is_identifier_boundary_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
}

/// `true` when `s` ends with an `authorization` (case-insensitive) that the
/// detector reads as a header name: the character before it, if any, is
/// outside the identifier boundary charset, or it is the tail of a
/// `Proxy-Authorization` header ([`preceded_by_proxy_prefix`], issue #990).
fn ends_with_authorization_boundary(s: &str) -> bool {
    if !ends_with_ci(s, "authorization") {
        return false;
    }
    let prefix_len = s.len() - "authorization".len();
    prev_char(s, prefix_len).is_none_or(|ch| !is_identifier_boundary_char(ch))
        || preceded_by_proxy_prefix(s.as_bytes(), prefix_len)
}

/// Internal retention hint for the built-in incremental scanner: `true` when
/// `input` still looks like an in-progress `authorization` header name, so a
/// caller should keep holding the line open in case an explicit `Bearer`
/// scheme and credential follow. Mirrors `hasOpenBearerAuthorization` in
/// `src/detectors/bearer-token.ts` (`decision-govern-cross-language-conformance`).
pub(crate) fn has_open_bearer_authorization(input: &str) -> bool {
    let trimmed = trim_end_js_whitespace(input);
    match trimmed.strip_suffix(':') {
        Some(before_colon) => {
            ends_with_authorization_boundary(trim_end_js_whitespace(before_colon))
        }
        None => ends_with_authorization_boundary(trimmed),
    }
}

/// The RFC 8959 scheme, matched case-insensitively (RFC 3986 section 3.1).
const SECRET_TOKEN_SCHEME: &[u8] = b"secret-token:";

/// The shortest `secret-token:` body reported. RFC 8959 allows one byte;
/// documentation that names the scheme with a stub (`secret-token:abc`)
/// is not a credential (issue #819).
const MIN_SECRET_TOKEN_BODY_LEN: usize = 8;

/// A `secret-token:` body byte: RFC 3986 `pchar` minus the sub-delimiters
/// that close a value in running text or code (`'`, `(`, `)`, `,`, `;`).
/// `%` is accepted here and its two hex digits are checked by the caller.
fn is_secret_token_body_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'%'
                | b'!'
                | b'$'
                | b'&'
                | b'*'
                | b'+'
                | b'='
                | b':'
                | b'@'
        )
}

/// Every RFC 8959 `secret-token:` URI, scheme included (issue #819). The
/// whole URI is the secret: RFC 8959 defines it as a bearer token whose
/// scheme exists so it can be recognized and redacted. A `%` must start a
/// valid percent-encoding, trailing `.`/`:` (sentence punctuation) are not
/// part of the body, and a body of placeholder vocabulary or filler is
/// excluded like a `Bearer` value.
fn secret_token_uri_candidates(input: &str) -> Vec<Candidate> {
    secret_token_uri_candidates_from(input, |bytes, from| {
        find_ci(bytes, from, SECRET_TOKEN_SCHEME)
    })
}

/// [`secret_token_uri_candidates`] over the offsets `next` yields: the next
/// offset at or after `from` that can start a scheme (`None` when none can).
/// Each yielded offset is still checked in full, so `next` only has to skip
/// offsets that cannot match.
fn secret_token_uri_candidates_from(
    input: &str,
    mut next: impl FnMut(&[u8], usize) -> Option<usize>,
) -> Vec<Candidate> {
    let bytes = input.as_bytes();
    let mut candidates = Vec::new();
    let mut cursor = 0usize;
    while cursor + SECRET_TOKEN_SCHEME.len() <= bytes.len() {
        let Some(at) = next(bytes, cursor) else { break };
        cursor = at;
        if cursor + SECRET_TOKEN_SCHEME.len() > bytes.len() {
            break;
        }
        if !bytes[cursor..cursor + SECRET_TOKEN_SCHEME.len()]
            .eq_ignore_ascii_case(SECRET_TOKEN_SCHEME)
            || (cursor > 0 && is_boundary_identifier_char(bytes[cursor - 1]))
        {
            cursor += 1;
            continue;
        }
        let body_start = cursor + SECRET_TOKEN_SCHEME.len();
        let mut end = body_start;
        while end < bytes.len() && is_secret_token_body_byte(bytes[end]) {
            if bytes[end] == b'%'
                && !(end + 2 < bytes.len()
                    && bytes[end + 1].is_ascii_hexdigit()
                    && bytes[end + 2].is_ascii_hexdigit())
            {
                break;
            }
            end += if bytes[end] == b'%' { 3 } else { 1 };
        }
        while end > body_start && matches!(bytes[end - 1], b'.' | b':') {
            end -= 1;
        }
        let body = &input[body_start..end];
        if body.len() >= MIN_SECRET_TOKEN_BODY_LEN
            && !is_non_secret_bearer_value(body)
            && let Some(range) = ByteRange::new(cursor, end)
        {
            candidates.push(
                Candidate::built_in("bearer_token", Confidence::High, range)
                    .with_specificity(Specificity::Structural)
                    .with_signal_pack(crate::types::signal_pack!("secret-token-uri")),
            );
        }
        cursor = end.max(body_start);
    }
    candidates
}

/// The structural Bearer authorization detector.
pub(super) struct BearerTokenDetector;

impl Detector for BearerTokenDetector {
    fn id(&self) -> &'static str {
        "bearer-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        // A scheme starts with `authorization` or `bearer` (any case), so
        // the next attempt is at the nearer of the two keywords. Each
        // keyword's next position is kept until the cursor passes it, so the
        // input is searched once per keyword.
        let mut next_authorization: Option<Option<usize>> = None;
        let mut next_bearer: Option<Option<usize>> = None;
        let mut candidates = bearer_scheme_candidates(input, |bytes, from| {
            for (slot, keyword) in [
                (&mut next_authorization, b"authorization".as_slice()),
                (&mut next_bearer, b"bearer".as_slice()),
            ] {
                if slot.is_none_or(|found| found.is_some_and(|at| at < from)) {
                    *slot = Some(find_ci(bytes, from, keyword));
                }
            }
            match (next_authorization.flatten(), next_bearer.flatten()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        });
        candidates.extend(secret_token_uri_candidates(input));
        Ok(candidates)
    }
}

/// The `Bearer` scheme pass over the offsets `next` yields (as for
/// [`secret_token_uri_candidates_from`]); every yielded offset is attempted
/// in full.
fn bearer_scheme_candidates(
    input: &str,
    mut next: impl FnMut(&[u8], usize) -> Option<usize>,
) -> Vec<Candidate> {
    let bytes = input.as_bytes();
    let mut candidates = Vec::new();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let Some(at) = next(bytes, cursor) else { break };
        cursor = at;
        let Some((scheme_end, header)) = match_scheme_at(input, cursor) else {
            cursor += super::text::char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        };

        let ws_len = ascii_run_len(bytes, scheme_end, is_space_or_tab);
        if ws_len == 0 {
            cursor += super::text::char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        }
        let value_start = scheme_end + ws_len;

        let token_len = ascii_run_len(bytes, value_start, is_token_char);
        if token_len == 0 {
            cursor += super::text::char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        }
        let (value_end, runs) = joined_value_end(bytes, value_start, value_start + token_len);
        // The floor is judged on the whole joined value, padding and the
        // final run's `=` excluded: a short id before a long secret is
        // still one credential (issue #918).
        let last_run_end = runs.last().map_or(value_start + token_len, |&(_, end)| end);
        if last_run_end - value_start
            < if header {
                MIN_HEADER_TOKEN_LEN
            } else {
                MIN_TOKEN_LEN
            }
        {
            cursor += super::text::char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        }

        let boundary_blocked = cursor > 0
            && is_boundary_identifier_char(bytes[cursor - 1])
            && !(header && preceded_by_proxy_prefix(bytes, cursor));
        // An `authorization` that ends a wider header name
        // (`X-Authorization:`) is not the header this grammar reads, but
        // the `Bearer` credential after it is still a bare `Bearer`
        // match. Resuming past the value here hid it, on its own line
        // and on the next one alike (issue #990).
        if boundary_blocked && header {
            cursor += 1;
            continue;
        }
        // A joined value is excluded only when every run is filler or
        // placeholder vocabulary: `YOUR_ID:<real secret>` stays
        // detected, so a placeholder half never hides a real half.
        let non_secret = runs
            .iter()
            .all(|&(start, end)| is_non_secret_bearer_value(&input[start..end]));
        if !boundary_blocked
            && !non_secret
            && !is_glued_to_placeholder(bytes, value_end)
            && let Some(range) = ByteRange::new(value_start, value_end)
        {
            candidates.push(
                Candidate::built_in("bearer_token", Confidence::High, range)
                    .with_specificity(Specificity::Structural)
                    .with_signal_pack(crate::types::signal_pack!("bearer-scheme")),
            );
        }

        // `matchAll` resumes scanning at the end of the raw regex match
        // regardless of the boundary check outcome.
        cursor = value_end.max(cursor + 1);
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every offset, the way the pre-#1073 loops walked the input.
    fn every_offset(bytes: &[u8], from: usize) -> Option<usize> {
        (from < bytes.len()).then_some(from)
    }

    #[test]
    fn keyword_jumps_equal_the_per_offset_scan() {
        let pieces = [
            "Bearer",
            "bearer",
            "BEARER",
            "Authorization",
            "authorization",
            "Proxy-Authorization",
            "X-Authorization",
            "secret-token:",
            "Secret-Token:",
            " ",
            "  ",
            "\t",
            ":",
            "\n",
            "\r\n",
            "\u{e9}",
            "\u{2003}",
            "-",
            "_",
            "a",
            "b",
            "%",
            "%4A",
            "Bearer U1lOVEhFVElDX1JFVk9LRUQ=",
            "Authorization: Bearer SYNTHETICREVOKED0123",
            "secret-token:SYNTHETICREVOKED0123",
            "SYNTHETICREVOKED0123",
            ".",
        ];
        let mut state: u64 = 0x0F1E_2D3C_4B5A_6978;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize
        };
        let mut matched = 0usize;
        for _ in 0..6000 {
            let mut input = String::new();
            for _ in 0..next() % 24 {
                input.push_str(pieces[next() % pieces.len()]);
            }
            let fast = detect(&input);
            matched += fast.len();
            let mut oracle = bearer_scheme_candidates(&input, every_offset);
            oracle.extend(secret_token_uri_candidates_from(&input, every_offset));
            assert_eq!(fast, oracle, "{input:?}");
        }
        assert!(
            matched > 100,
            "the generator must exercise real matches: {matched}"
        );
    }

    fn detect(input: &str) -> Vec<Candidate> {
        BearerTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn only_range(candidates: &[Candidate]) -> (usize, usize) {
        assert_eq!(candidates.len(), 1);
        (candidates[0].range().start(), candidates[0].range().end())
    }

    #[test]
    fn explicit_bearer_scheme_is_detected() {
        let input = "Bearer SYNTHETIC_REVOKED_BEARER_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (7, input.len()));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Structural));
    }

    #[test]
    fn bearer_embedded_in_an_identifier_is_excluded() {
        assert!(detect("notbearer SYNTHETIC_REVOKED_IDENTIFIER").is_empty());
    }

    #[test]
    fn short_development_token_is_ignored() {
        assert!(detect("Bearer short-token").is_empty());
    }

    #[test]
    fn a_secret_token_uri_is_reported_whole_with_its_scheme() {
        // Issue #819 (RFC 8959).
        const URI: &str = "secret-token:SYNTHETIC-7F3A-4C2B%20fixture";
        for (input, value) in [
            (URI.to_owned(), URI),
            (format!("token = {URI}"), URI),
            (
                "token = SECRET-TOKEN:SYNTHETIC-7F3A-4C2B%20fixture".to_owned(),
                "SECRET-TOKEN:SYNTHETIC-7F3A-4C2B%20fixture",
            ),
            (format!("Authorization: Bearer\n  {URI}"), URI),
            (format!("Use the URI {URI}."), URI),
            // A broken percent-encoding ends the body.
            (
                "url = \"secret-token:SYNTHETIC-7F3A-4C2B%2\"".to_owned(),
                "secret-token:SYNTHETIC-7F3A-4C2B",
            ),
        ] {
            let candidates = detect(&input);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], value, "{input}");
            assert_eq!(candidates[0].type_name(), "bearer_token");
        }
        for input in [
            "token_uri_prefix = \"secret-token:\"",
            "secret-token:abc",
            "secret-token:placeholder",
            "mysecret-token:SYNTHETIC-7F3A-4C2B%20fixture",
            "x-secret-token:SYNTHETIC-7F3A-4C2B%20fixture",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn an_explicit_authorization_header_lowers_the_floor_to_twelve() {
        // Issue #818: 15- and 12-byte values after the header name.
        for (input, value) in [
            ("Authorization: Bearer SYNTH.q8v-N3xR7", "SYNTH.q8v-N3xR7"),
            ("Proxy-Authorization: Bearer SYNTHq8vN3xR", "SYNTHq8vN3xR"),
            (
                "curl -H 'authorization: bearer SYNTH.q8v-N3xR7'",
                "SYNTH.q8v-N3xR7",
            ),
        ] {
            let candidates = detect(input);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], value, "{input}");
        }
        for input in [
            // Without the header, the 16-byte floor stands.
            "Bearer SYNTH.q8v-N3xR7",
            "the Bearer SYNTH.q8v-N3xR7 value",
            // 11 bytes after the header.
            "Authorization: Bearer SYNTHq8vN3x",
            "Authorization: Bearer YOUR_TOKEN_HERE",
            // A wider identifier before `authorization`.
            "reverse_proxy-authorization: Bearer SYNTH.q8v-N3xR7",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn authorization_header_prefix_is_supported() {
        let input = "authorization: Bearer SYNTHETIC_REVOKED_HEADER_VALUE";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_HEADER_VALUE");
    }

    #[test]
    fn long_invalid_alphabet_terminates_without_a_finding() {
        let input = format!("Bearer {}", "!".repeat(100_000));
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn open_bearer_authorization_hint_recognizes_a_pending_header_name() {
        for open in [
            "authorization",
            "Authorization",
            "AUTHORIZATION",
            "authorization:",
            "authorization: ",
            "authorization \t: ",
            "line one\nauthorization:",
            // Issue #990: the detector reads a `Proxy-Authorization` header.
            "Proxy-Authorization:",
            "proxy-authorization \n",
            "x: Proxy-Authorization\n:\n",
        ] {
            assert!(has_open_bearer_authorization(open), "{open:?}");
        }
    }

    #[test]
    fn open_bearer_authorization_hint_rejects_resolved_or_unrelated_text() {
        for closed in [
            "",
            "authorization: bearer",
            "authorizationx",
            "notauthorization",
            "x-authorization",
            "xproxy-authorization:",
            "authorization: Bearer SYNTHETIC_REVOKED_VALUE",
            "plain text",
        ] {
            assert!(!has_open_bearer_authorization(closed), "{closed:?}");
        }
    }

    #[test]
    fn a_bearer_value_after_a_wider_authorization_header_name_is_a_bare_match() {
        // Issue #990: `X-Authorization` is not the header, so the header
        // floor does not apply, but the `Bearer` value after it is still a
        // bare match at the bare floor, on the same line or the next.
        for input in [
            "X-Authorization: Bearer SYNTHETIC_REVOKED_WIDER_HEADER",
            "X-Authorization:\nBearer SYNTHETIC_REVOKED_WIDER_HEADER",
            "HTTP_AUTHORIZATION: bearer SYNTHETIC_REVOKED_WIDER_HEADER",
        ] {
            let candidates = detect(input);
            let (start, end) = only_range(&candidates);
            assert_eq!(
                &input[start..end],
                "SYNTHETIC_REVOKED_WIDER_HEADER",
                "{input:?}"
            );
        }
        // Below the bare floor it stays silent: only a real header name
        // lowers the floor to 12.
        assert!(detect("X-Authorization: Bearer SYNTHrevoked7").is_empty());
        assert_eq!(detect("Proxy-Authorization: Bearer SYNTHrevoked7").len(), 1);
    }

    #[test]
    fn missing_value_after_scheme_is_ignored() {
        assert!(detect("Authorization: Bearer").is_empty());
    }

    #[test]
    fn newline_separator_is_not_accepted() {
        // Only a space or a tab separates the scheme from its credential;
        // a line break is deliberately outside that separator charset.
        assert!(detect("Bearer\nSYNTHETIC_REVOKED_BEARER_NEWLINE_VALUE").is_empty());
    }

    #[test]
    fn case_insensitive_scheme_and_tab_separator_are_accepted() {
        let input = "BEARER\tSYNTHETIC_REVOKED_BEARER_TAB_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (7, input.len()));
    }

    #[test]
    fn extra_whitespace_and_case_around_the_authorization_header_are_accepted() {
        let input = "AUTHORIZATION  :  BEARER   SYNTHETIC_REVOKED_BEARER_CASE_WS_VALUE";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_BEARER_CASE_WS_VALUE");
    }

    #[test]
    fn ordinary_prose_usage_of_bearer_is_safe_but_a_long_incidental_word_is_an_accepted_tradeoff() {
        // "bearer" used as an ordinary English noun followed by a short
        // word stays negative: the token-length floor, not any language
        // awareness, is what keeps this safe.
        assert!(
            detect("The bearer of this letter is authorized to collect the package.").is_empty()
        );
        // The same ordinary usage followed by an incidentally long
        // hyphenated word is indistinguishable from a real credential at
        // the character-grammar level and is classified: an accepted
        // precision/recall tradeoff, not a bug.
        let input =
            "Please note the bearer identification-verification-procedure must be followed.";
        let candidates = detect(input);
        assert_eq!(
            only_range(&candidates),
            (23, 23 + "identification-verification-procedure".len())
        );
    }

    #[test]
    fn a_mid_value_alphabet_break_or_an_embedded_narrower_provider_shape_still_clears_the_length_floor()
     {
        const SENDGRID_ID: &str = "SYNTHETIC_REVOKED_0000";
        const SENDGRID_SECRET: &str = "SYNTHETIC_REVOKED_SENDGRID_SECRET_000000000";

        // issue #553, docs/decisions/2026-09-21-accept-truncated-and-nested-
        // shapes-under-bearer-token-length-grammar.md: a single
        // alphabet-violating byte partway through a longer value only ends
        // the token run early -- it does not defeat detection when the
        // truncated prefix alone still clears `MIN_TOKEN_LEN`. Split at
        // byte 20 of a 40-byte value: the 20-byte prefix (>= 16) is
        // classified, and the 19-byte suffix is never independently
        // considered because it is not preceded by a `Bearer` scheme.
        let left = "SYNTHETIC_REVOKED_AB"; // 20 bytes
        let right = "SYNTHETIC_TAIL_WXYZ"; // 19 bytes
        assert_eq!(left.len(), 20);
        assert_eq!(right.len(), 19);
        let input = format!("Authorization: Bearer {left}!{right}");
        let candidates = detect(&input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], left);

        // A one-byte-short SendGrid-shaped value (`sendgrid.rs`'s own
        // exact-length grammar correctly declines it) is still a 68-byte
        // run of `is_token_char` bytes, well over the floor, so
        // `bearer-token` classifies it on its own, unrelated terms.
        let sendgrid_shaped = format!(
            "SG.{SENDGRID_ID}.{}",
            &SENDGRID_SECRET[..SENDGRID_SECRET.len() - 1]
        );
        let input = format!("Authorization: Bearer {sendgrid_shaped}");
        let candidates = detect(&input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], sendgrid_shaped);
    }

    /// Synthetic `<uuid>:<hex32>` (fal shape) and `<name>|01<hex>` (Convex
    /// self-hosted shape) values, built at run time; never issued.
    fn joined_values() -> Vec<(String, usize)> {
        let hex = |len: usize| -> String {
            (0..len)
                .map(|i| char::from(b"0123456789abcdef"[(i * 7 + i / 3) % 16]))
                .collect()
        };
        let uuid = "5f0c2a9e-1b3d-4c7e-9a8f-0d6e4b2c1a7f";
        vec![
            (format!("{uuid}:{}", hex(32)), uuid.len()),
            (
                format!("convex-self-hosted|01{}", hex(74)),
                "convex-self-hosted".len(),
            ),
            (format!("prod:happy-otter-123|01{}", hex(76)), "prod".len()),
            (format!("{uuid}:{}==", hex(31)), uuid.len()),
            (
                "SYNTHID:SYNTHETIC_REVOKED_SECRET_A|SYNTHETIC_TAIL_B".to_owned(),
                7,
            ),
        ]
    }

    #[test]
    fn a_colon_or_pipe_joined_value_is_selected_whole() {
        // Issue #918: the span used to end at the first `:`/`|`, leaving the
        // secret half of `<id>:<secret>` / `<name>|<secret>` in clear.
        for (value, _) in joined_values() {
            for input in [
                format!("Authorization: Bearer {value}"),
                format!("Authorization: Bearer {value}\r\n"),
                format!("curl -H \"Authorization: Bearer {value}\" https://example.invalid"),
                format!("curl -H 'authorization: bearer {value}'"),
                format!("{{\"Authorization\": \"Bearer {value}\"}}"),
                format!("Bearer {value}"),
                format!("use Bearer {value}, then retry"),
            ] {
                let candidates = detect(&input);
                assert_eq!(candidates.len(), 1, "{input}");
                let (start, end) = only_range(&candidates);
                assert_eq!(&input[start..end], value, "{input}");
            }
        }
    }

    #[test]
    fn a_short_left_half_no_longer_hides_a_long_joined_value() {
        // The floor is judged on the whole joined value: a 4-byte type lead
        // before a long secret is one credential.
        let input = "Bearer dev:SYNTHETIC_REVOKED_TAIL";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (7, input.len()));
        // Still below the floor as a whole.
        assert!(detect("Bearer ab:cd|ef").is_empty());
        assert!(detect("Authorization: Bearer ab:cdef:gh").is_empty());
    }

    #[test]
    fn a_dangling_join_url_or_prose_colon_keeps_the_single_run_span() {
        for (input, value) in [
            // A join with nothing (or whitespace) after it is not a value.
            (
                "Authorization: Bearer SYNTHETIC_REVOKED_VALUE:",
                "SYNTHETIC_REVOKED_VALUE",
            ),
            (
                "Authorization: Bearer SYNTHETIC_REVOKED_VALUE: see docs",
                "SYNTHETIC_REVOKED_VALUE",
            ),
            (
                "| Bearer SYNTHETIC_REVOKED_VALUE | header |",
                "SYNTHETIC_REVOKED_VALUE",
            ),
            (
                "Authorization: Bearer SYNTHETIC_REVOKED_VALUE|",
                "SYNTHETIC_REVOKED_VALUE",
            ),
            // A `://` URL is not joined onto a preceding token.
            (
                "Bearer SYNTHETIC_REVOKED_VALUE://example.invalid/x",
                "SYNTHETIC_REVOKED_VALUE",
            ),
        ] {
            let candidates = detect(input);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], value, "{input}");
        }
        // A URL after a prose `bearer` stays below the floor, as before.
        assert!(detect("an OAuth bearer https://example.invalid/rfc6750").is_empty());
        assert!(detect("The bearer of: this letter").is_empty());
        assert!(detect("The bearer 10:30 train").is_empty());
    }

    #[test]
    fn a_join_never_absorbs_the_next_field_of_a_delimited_record() {
        // Issue #939: `|email=` used to be read as a joined run plus `=`
        // padding, redacting `<tok>|email=` and leaving the address.
        const TOKEN: &str = "SYNTHETIC_REVOKED_BEARER_VALUE";
        for tail in [
            "|email=fixture@example.test",
            "|x=1",
            "|x==1",
            "|note=\"see docs\"",
            "|v=${NEXT}",
            ":scope=read",
        ] {
            for input in [
                format!("Authorization: Bearer {TOKEN}{tail}"),
                format!("level=info auth=\"Bearer {TOKEN}{tail}\""),
            ] {
                let candidates = detect(&input);
                let (start, end) = only_range(&candidates);
                assert_eq!(&input[start..end], TOKEN, "{input}");
            }
        }
        // Padding that ends a base64 body is still part of the value, before
        // a closing quote, a join or the end of the line.
        for value in [
            "SYNTHETICq8vN3xR7tLm2Qw==",
            "SYNTHETICq8vN3xR7tLm2Qw=",
            "SYNTHID|SYNTHETICq8vN3xR7tLm2Qw==",
            "SYNTHETICq8vN3xR7==:SYNTHETICtLm2Qw",
        ] {
            for input in [
                format!("Authorization: Bearer {value}"),
                format!("{{\"Authorization\": \"Bearer {value}\"}}"),
                format!("Authorization: Bearer {value} next"),
            ] {
                let candidates = detect(&input);
                assert_eq!(candidates.len(), 1, "{input}");
                let (start, end) = only_range(&candidates);
                assert_eq!(&input[start..end], value, "{input}");
            }
        }
        // `=` that opens a value after the first run is not padding either.
        let input = format!("Bearer {TOKEN}=1");
        let candidates = detect(&input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], TOKEN);
    }

    #[test]
    fn a_colon_label_after_a_joined_secret_never_drops_the_secret() {
        // `<id>:<secret>: note` must keep the secret half inside the span
        // (#939 follow-up): `:` plus whitespace is not a field-key signal.
        let input = "Authorization: Bearer SYNTHID:SYNTHETIC_REVOKED_SECRET: see docs";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHID:SYNTHETIC_REVOKED_SECRET");
        let input = "Authorization: Bearer SYNTHETIC_REVOKED_BEARER_VALUE|user: alice";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_BEARER_VALUE|user");
    }

    #[test]
    fn a_name_at_host_value_is_selected_whole() {
        // Issue #939: the span used to stop at `@`, redacting only the local
        // part and leaving the host.
        for (input, value) in [
            (
                "Authorization: Bearer svc-deploy-bot@example.test",
                "svc-deploy-bot@example.test",
            ),
            (
                "Authorization: Bearer svc-deploy-bot@example.test.",
                "svc-deploy-bot@example.test",
            ),
            (
                "curl -H 'Authorization: Bearer svc-deploy-bot@ci.example.test' https://x.invalid",
                "svc-deploy-bot@ci.example.test",
            ),
            (
                "Bearer SYNTHETIC_REVOKED_VALUE@example.test",
                "SYNTHETIC_REVOKED_VALUE@example.test",
            ),
        ] {
            let candidates = detect(input);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], value, "{input}");
        }
        // The floor still judges the part before `@`, so a short local part
        // is no finding rather than a partial one; a bare `@` is not a host.
        for input in [
            "Authorization: Bearer ops@example.test",
            "Bearer alice@example.test",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        let input = "Authorization: Bearer SYNTHETIC_REVOKED_VALUE@ trailing";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_VALUE");
    }

    #[test]
    fn a_joined_value_is_excluded_only_when_every_run_is_a_placeholder() {
        for input in [
            "Authorization: Bearer YOUR_ACCESS_TOKEN:xxxxxxxxxxxx",
            "Authorization: Bearer xxxxxxxxxxxxxxxx|0000000000000000",
            "Authorization: Bearer PASSWORD_SECRET_EXAMPLE:YOUR_ACCESS_TOKEN",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // One real run keeps the whole value detected.
        for input in [
            "Authorization: Bearer YOUR_ACCESS_TOKEN:SYNTHETIC_REVOKED_SECRET",
            "Authorization: Bearer SYNTHETIC_REVOKED_ID|xxxxxxxxxxxxxxxx",
        ] {
            let candidates = detect(input);
            assert_eq!(only_range(&candidates), (22, input.len()), "{input}");
        }
    }

    #[test]
    fn a_lead_glued_to_a_placeholder_or_reference_is_not_a_partial_span() {
        for input in [
            "Authorization: Bearer signkey-prod-<YOUR-SIGNING-KEY>",
            "Authorization: Bearer signkey-prod-<your-signing-key>",
            "Authorization: Bearer prod:happy-otter-123|${CONVEX_BODY}",
            "Authorization: Bearer convex-self-hosted|$ADMIN_KEY",
            "Authorization: Bearer SYNTHETIC_REVOKED_LEAD_{{ token }}",
            "Authorization: Bearer 5e7c0ded-feed-4bad-9ace-0ddba11c0de5:<FAL_KEY_SECRET>",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // A real token before an HTML tag, a `$` price or a lone `<` stays.
        for (input, value) in [
            (
                "<td>Bearer SYNTHETIC_REVOKED_BEARER_VALUE</td>",
                "SYNTHETIC_REVOKED_BEARER_VALUE",
            ),
            (
                "Bearer SYNTHETIC_REVOKED_BEARER_VALUE<br>",
                "SYNTHETIC_REVOKED_BEARER_VALUE",
            ),
            (
                "Bearer SYNTHETIC_REVOKED_BEARER_VALUE<3",
                "SYNTHETIC_REVOKED_BEARER_VALUE",
            ),
            (
                "Bearer SYNTHETIC_REVOKED_BEARER_VALUE$5",
                "SYNTHETIC_REVOKED_BEARER_VALUE",
            ),
        ] {
            let candidates = detect(input);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], value, "{input}");
        }
    }

    #[test]
    fn a_long_join_chain_stays_linear() {
        let input = format!("Bearer {}", "ab:".repeat(50_000));
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(only_range(&candidates), (7, input.len() - 1));
    }

    #[test]
    fn trailing_padding_equals_are_included() {
        let input = "Bearer SYNTHETIC_REVOKED_BEARER_VALUE==";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_BEARER_VALUE==");
    }

    #[test]
    fn repeated_character_filler_values_are_excluded() {
        // issue #468: matches generic-token's exclusion of the same values
        // under the Basic/Token schemes.
        for filler in [
            "xxxxxxxxxxxxxxxxxxxx",
            "00000000000000000000",
            "aaaaaaaaaaaaaaaaaaaa",
            "--------------------",
        ] {
            let input = format!("Authorization: Bearer {filler}");
            assert!(detect(&input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn a_near_miss_of_repeated_character_filler_is_still_detected() {
        // A trailing, distinct character breaks the uniform run.
        assert!(!detect("Bearer xxxxxxxxxxxxxxxxxxxxy").is_empty());
    }

    #[test]
    fn whole_value_placeholder_vocabulary_is_excluded() {
        // issue #468: every token is itself a word on the shared
        // placeholder vocabulary, mirroring `is_generic_placeholder_word`.
        assert!(detect("Authorization: Bearer PASSWORD_SECRET_EXAMPLE").is_empty());
    }

    #[test]
    fn compound_placeholder_forms_are_not_excluded() {
        // Documented, out-of-scope false negative (issue #468): a value
        // mixing a listed placeholder word with an unlisted one is not
        // whole-value placeholder vocabulary and stays detected, same as
        // `generic-token`'s `is_generic_placeholder_word`.
        assert!(!detect("Bearer EXAMPLE_TOKEN_VALUE").is_empty());
    }

    #[test]
    fn a_real_looking_value_is_still_detected_at_high_confidence() {
        let candidates = detect("Bearer SYNTHETIC_REVOKED_BEARER_VALUE");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn instructional_placeholders_of_sixteen_or_more_bytes_are_excluded() {
        // Issue #745.
        for value in [
            "YOUR_ACCESS_TOKEN",
            "YOUR_OAUTH_TOKEN",
            "YOUR_SECRET_TOKEN",
            "INSERT_ACCESS_TOKEN",
            "your_access_token",
            "your-oauth-token-here",
            "ENTER_YOUR_ACCESS_TOKEN_HERE",
            "YOUR_PERSONAL_ACCESS_TOKEN",
            "PASTE_API_KEY_HERE",
        ] {
            let input = format!("Authorization: Bearer {value}");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn values_that_only_resemble_an_instructional_placeholder_stay_detected() {
        for value in [
            "YOUR_ACCESS_TOKEN9f2c",
            "YOUR_ACCESS_TOKEN_Zx81Qp",
            "YOUR_PERSONAL_ACCESS_VALUE",
            "TOKEN_YOUR_ACCESS_TOKEN",
            "yourAccessTokenAbcdef",
            "YOUR_PERSONAL_ACCESS",
            "SYNTHETIC_REVOKED_BEARER_VALUE",
        ] {
            let input = format!("Authorization: Bearer {value}");
            let candidates = detect(&input);
            assert_eq!(only_range(&candidates), (22, input.len()), "{input}");
        }
    }
}
