//! Name-scoped contextual readers (issues #1228, #1229 and #1230).
//!
//! The contextual vocabulary (`generic_token.rs`) reads a value by the name it
//! is assigned to. A few documented credential fields are named too plainly to
//! join that vocabulary as a name on their own: the bare `token`, which stays
//! unmatched by the accepted rule of
//! `decision-redact-provider-named-credential-assignments` and #1241, and
//! `encoded`. This module reads such a name **only** where the carrier or the
//! surrounding text carries the context the evidence Case names, and judges the
//! value under an existing high-signal name (the alias), so every other rule
//! (the 8-byte floor, the entropy tiers, the placeholder, reference and mask
//! exclusions) applies unchanged. It adds no name to the vocabulary and widens
//! no bare-name rule.
//!
//! | Name | Carrier | Required context | Alias |
//! | --- | --- | --- | --- |
//! | `token_key` | quoted JSON member | none (the quoted member is the carrier) | `access_token` |
//! | `encoded` | quoted JSON member | an `api_key` member within the sibling window | `api_key` |
//! | `token` | quoted JSON member | a `sys` or `scopes` member within the sibling window | `access_token` |
//! | `token` | `token=` form or curl parameter | a revoke or introspect endpoint within the request window, or a `token_type_hint` parameter | `access_token` |
//!
//! # The window
//!
//! A sibling line counts when it lies within [`JSON_WINDOW_LINES`] lines of the
//! name's line (the same line always counts), and a request line when it lies
//! within [`REQUEST_WINDOW_LINES`] lines above it, and the text from the first
//! of the two lines through the last is at most [`MAX_WINDOW_BYTES`] bytes. The rule
//! reads only text, so a whole-input scan and an incremental session agree once
//! the session holds the lines of a possible window: [`has_open_scoped_context_in`]
//! is the retention hint that does it, true while a line that can open a window
//! sits among the last lines. A sibling is any quoted member of the named
//! partners, in the same object or a neighbouring one: the window is positional,
//! not a parse, which keeps whole-input and incremental scans equal.

use super::text;

/// The most lines apart (the name's line included) a JSON sibling member may be:
/// a partner on any of the next `JSON_WINDOW_LINES - 1` lines or the previous
/// `JSON_WINDOW_LINES - 1` counts.
pub(crate) const JSON_WINDOW_LINES: usize = 6;
/// The most lines above a `token=` parameter (its own line included) that may
/// carry the revoke or introspect endpoint of its request: a raw HTTP request
/// with several headers and a blank line is up to about eight lines.
pub(crate) const REQUEST_WINDOW_LINES: usize = 10;
/// The most complete lines the retention hint reads back.
pub(crate) const SCOPED_LOOKBACK_LINES: usize = REQUEST_WINDOW_LINES;
/// The most bytes from the first line of a window through its last. A longer
/// stretch is not a window, which also bounds what the session holds.
pub(crate) const MAX_WINDOW_BYTES: usize = 2_048;

/// JSON member names that can open or complete a sibling window.
const JSON_TRIGGER_MEMBERS: &[&str] = &["api_key", "encoded", "sys", "scopes", "token"];

/// What a scoped name is judged as, and the extra guard it carries.
pub(super) struct ScopedRead {
    /// The high-signal name the value is judged under.
    pub(super) alias: &'static str,
    /// A value that is itself the name of a credential (`accessToken`,
    /// `auth_token_key`) is a reference, not a value: the scoped name also
    /// names the storage key an application saves a token under.
    pub(super) name_phrase_is_reference: bool,
}

impl ScopedRead {
    const fn alias(alias: &'static str) -> Self {
        Self {
            alias,
            name_phrase_is_reference: false,
        }
    }
}

/// `true` when the name at `name_start..name_end` is a quoted JSON member name
/// (`"tokenKey":`, also inside an escaped JSON string, `\"tokenKey\":`).
pub(super) fn is_quoted_member(input: &str, name_start: usize, name_end: usize) -> bool {
    let before = &input[..name_start];
    let after = &input[name_end..];
    before.ends_with('"') && (after.starts_with('"') || after.starts_with("\\\""))
}

/// How the assignment at `name_start..name_end` is read, when `normalized` (the
/// normalized name) is a scoped name whose context is present.
pub(super) fn scoped_alias(
    input: &str,
    name_start: usize,
    name_end: usize,
    normalized: &str,
) -> Option<ScopedRead> {
    match normalized {
        "token_key" if is_quoted_member(input, name_start, name_end) => Some(ScopedRead {
            alias: "access_token",
            name_phrase_is_reference: true,
        }),
        "encoded"
            if is_quoted_member(input, name_start, name_end)
                && json_partner(input, name_start, &["api_key"]) =>
        {
            Some(ScopedRead::alias("api_key"))
        }
        "token" => {
            if is_quoted_member(input, name_start, name_end) {
                json_partner(input, name_start, &["sys", "scopes"])
                    .then(|| ScopedRead::alias("access_token"))
            } else if input[name_end..].starts_with('=') && revocation_context(input, name_start) {
                Some(ScopedRead::alias("access_token"))
            } else {
                None
            }
        }
        _ => None,
    }
}

// --- lines ---------------------------------------------------------------

/// The line (`start`, `end`) holding byte `position`.
fn line_around(input: &str, position: usize) -> (usize, usize) {
    let start = text::line_start_before(input, position);
    let end = text::line_end_from(input.as_bytes(), start)
        .0
        .min(input.len());
    (start, end)
}

/// Calls `visit` with every line within `window - 1` lines of the line
/// (`line_start`, `line_end`), above it first and then, unless `above_only`,
/// below it, nearest first on each side, whose span with that line is at most [`MAX_WINDOW_BYTES`];
/// stops at the first line for which `visit` returns `true`.
fn any_line_in_window(
    input: &str,
    (line_start, line_end): (usize, usize),
    window: usize,
    above_only: bool,
    mut visit: impl FnMut(&str) -> bool,
) -> bool {
    let mut start = line_start;
    for _ in 1..window {
        let Some((above_start, above_end)) = text::previous_line(input, start) else {
            break;
        };
        start = above_start;
        if line_end - start > MAX_WINDOW_BYTES {
            break;
        }
        if visit(&input[above_start..above_end]) {
            return true;
        }
    }
    if above_only {
        return false;
    }
    let mut end = line_end;
    for _ in 1..window {
        let Some((below_start, below_end)) = text::next_line(input, end) else {
            break;
        };
        end = below_end;
        if end - line_start > MAX_WINDOW_BYTES {
            break;
        }
        if visit(&input[below_start..below_end]) {
            return true;
        }
    }
    false
}

// --- JSON siblings ---------------------------------------------------------

/// `true` when `line` holds a quoted JSON member named one of `names`
/// (`"api_key":`, or the escaped `\"api_key\":`), with an `:` after it. Each
/// name is searched for itself rather than by pairing quotes, so an enclosing
/// quoted string (`"text": "{\"api_key\":...}"`) cannot shift the pairing.
fn line_has_member(line: &str, names: &[&str]) -> bool {
    let bytes = line.as_bytes();
    names.iter().any(|name| {
        line.match_indices(name).any(|(start, _)| {
            let end = start + name.len();
            if start == 0 || bytes[start - 1] != b'"' {
                return false;
            }
            // The closing quote, plain or escaped.
            let mut after = match (bytes.get(end), bytes.get(end + 1)) {
                (Some(b'"'), _) => end + 1,
                (Some(b'\\'), Some(b'"')) => end + 2,
                _ => return false,
            };
            while bytes
                .get(after)
                .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
            {
                after += 1;
            }
            bytes.get(after) == Some(&b':')
        })
    })
}

/// `true` when a member named one of `partners` sits on the name's line or
/// within the sibling window around it.
fn json_partner(input: &str, name_start: usize, partners: &[&str]) -> bool {
    let line = line_around(input, name_start);
    line_has_member(&input[line.0..line.1], partners)
        || any_line_in_window(input, line, JSON_WINDOW_LINES, false, |other| {
            line_has_member(other, partners)
        })
}

// --- revocation and introspection requests -------------------------------

/// `true` when `line` carries a revoke or introspect endpoint (`/revoke`,
/// `/revoke_token`, `/introspect`, any letter case) as a whole path segment, or
/// the `token_type_hint` parameter of RFC 7009 and RFC 7662.
fn line_is_revocation_context(line: &str) -> bool {
    let bytes = line.as_bytes();
    if text::find_ci(bytes, 0, b"token_type_hint=").is_some() {
        return true;
    }
    for needle in [&b"/revoke"[..], &b"/introspect"[..]] {
        let mut from = 0usize;
        while let Some(at) = text::find_ci(bytes, from, needle) {
            let mut end = at + needle.len();
            if bytes.len() >= end + 6 && bytes[end..end + 6].eq_ignore_ascii_case(b"_token") {
                end += 6;
            }
            if bytes.get(end).is_none_or(|&byte| {
                matches!(
                    byte,
                    b' ' | b'\t' | b'?' | b'"' | b'\'' | b'&' | b'#' | b'\\' | b'\r' | b')'
                )
            }) {
                return true;
            }
            from = at + 1;
        }
    }
    false
}

/// `true` when the `token=` parameter at `name_start` belongs to a revocation
/// or introspection request: its own line, or a line within the request window
/// above it, carries the endpoint or the `token_type_hint` parameter.
fn revocation_context(input: &str, name_start: usize) -> bool {
    let line = line_around(input, name_start);
    line_is_revocation_context(&input[line.0..line.1])
        || any_line_in_window(input, line, REQUEST_WINDOW_LINES, true, |above| {
            line_is_revocation_context(above)
        })
}

// --- the incremental retention hint --------------------------------------

/// `true` when `line` can open a sibling window: a trigger member, on a line
/// short enough to be inside one.
fn line_opens_json_window(line: &str) -> bool {
    line.len() <= MAX_WINDOW_BYTES && line_has_member(line, JSON_TRIGGER_MEMBERS)
}

/// `true` when `line` can open a request window: a revocation context, on a
/// line short enough to be inside one.
fn line_opens_request_window(line: &str) -> bool {
    line.len() <= MAX_WINDOW_BYTES && line_is_revocation_context(line)
}

/// Whether the last of `lines` (complete lines, oldest first) are inside a
/// window that a later line can still complete: some line among the last
/// `window_lines - 1` opens one and the text from it through the last line is
/// within [`MAX_WINDOW_BYTES`]. The byte total counts line lengths only, which
/// is at most the exact span, so the hint never releases a window the reader
/// would still use.
fn open_window(lines: &[&str], window_lines: usize, opens: fn(&str) -> bool) -> bool {
    let recent = text::tail_lines(lines, window_lines - 1);
    let mut total = 0usize;
    // Newest first: the total grows towards the oldest candidate opener.
    for line in recent.iter().rev() {
        total += line.len();
        if total > MAX_WINDOW_BYTES {
            return false;
        }
        if opens(line) {
            return true;
        }
    }
    false
}

/// Internal retention hint (issues #1228 to #1230): `true` while the last
/// complete lines of the unit hold a line that can open a [`scoped_alias`]
/// window and fewer lines than the window have followed it, so a sibling member
/// or a `token=` parameter on a later line can still be read with it. Holding a
/// line that never pairs only delays its output by up to
/// [`REQUEST_WINDOW_LINES`] lines.
pub(crate) fn has_open_scoped_context_in(tail: &[&str]) -> bool {
    open_window(tail, JSON_WINDOW_LINES, line_opens_json_window)
        || open_window(tail, REQUEST_WINDOW_LINES, line_opens_request_window)
}

/// [`has_open_scoped_context_in`] over a [`super::lookback_tail`].
#[cfg(test)]
pub(crate) fn has_open_scoped_context(input: &str) -> bool {
    has_open_scoped_context_in(&super::lookback_tail(input))
}
