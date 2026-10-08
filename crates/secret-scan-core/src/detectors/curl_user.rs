//! The password of a `curl` credential argument (issue #1247,
//! `decision-read-the-curl-user-password-argument-as-a-contextual-secret`).
//!
//! The argument of `-u`, `-U`, `--user` and `--proxy-user` of a `curl`
//! command is `user:password`: curl splits it at the first colon. This
//! reader claims exactly the password bytes as written, `High`
//! `contextual_secret`; the user, an email and a literal `/token` stay
//! unclaimed. The carrier, not the value, makes the span a credential, so
//! only the shared non-secret exclusions apply.
//!
//! # Grammar
//!
//! - A *curl word* is `curl` or `curl.exe`, optionally path-qualified,
//!   preceded by line start, whitespace or one of `` ( ` " ' ; & | = { @ `` and
//!   followed by whitespace. A wrapper word before it changes nothing.
//! - Its *window* runs from the end of the curl word to the first unquoted
//!   `;`, `&` or `|`, a newline that is not a backslash continuation (a
//!   quote does not carry a window over a newline), the end of the input, or
//!   [`WINDOW_BYTES`].
//! - The window is read as shell words: unquoted bytes up to unescaped
//!   whitespace (a backslash escapes the next byte and stays in the span),
//!   `'...'` literally, `"..."` with the `\"`, `\\`, `\$` and `` \` `` escapes.
//! - A word that spells an option (`-u`, `-sSfLku`, `--user`, `--user=`,
//!   `--proxy-user`, `-U`, `-uARG`) takes the next word, or its own
//!   remainder, as the argument. An argument without a colon, with an empty
//!   password, with an unterminated quote, longer than
//!   [`MAX_PASSWORD_BYTES`], or starting with an escaped quote (a command
//!   held inside another quoted string) is not read.
//!
//! # Streaming
//!
//! A window that is still open at the end of a closed line (a backslash
//! continuation) holds the incremental session's unit open ([`has_open_curl_command`]), so the unit that is scanned always
//! contains whole windows and the result does not depend on the chunking.

use super::connection_string::is_placeholder;
use super::generic_token::{
    is_backtick_reference, is_brace_placeholder_reference, is_generic_placeholder_word,
};
use super::pattern::{LeadBytes, find_literal_with};
use crate::types::{ByteRange, Candidate, Confidence, Specificity, signal_pack};

/// The most bytes a window spans after its curl word.
const WINDOW_BYTES: usize = 8_192;
/// The longest password read; the shared connection-string bound.
const MAX_PASSWORD_BYTES: usize = 4_096;
/// The longest path before `curl` in a path-qualified curl word.
const MAX_PATH_PREFIX_BYTES: usize = 256;
const CURL: &[u8] = b"curl";
const EXE: &[u8] = b".exe";
/// Argument-less short options that may precede `u` or `U` in one cluster.
const CLUSTER_OPTIONS: &[u8] = b"sSfLkvgiIOJRNZ#";

const fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | 0x0B | 0x0C)
}

const fn is_line_end(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r')
}

const fn is_command_end(byte: u8) -> bool {
    matches!(byte, b';' | b'&' | b'|')
}

/// The bytes that may stand right before a curl word. `@` is the `Makefile`
/// recipe prefix that silences the echo of a command (`@curl ...`).
const fn precedes_curl_word(byte: u8) -> bool {
    is_blank(byte)
        || is_line_end(byte)
        || matches!(
            byte,
            b'(' | b'`' | b'"' | b'\'' | b';' | b'&' | b'|' | b'=' | b'{' | b'@'
        )
}

/// The end of the curl word whose `curl` starts at `at`, or `None` when it
/// is not a curl word.
fn curl_word_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut start = at;
    while start > 0 && !precedes_curl_word(bytes[start - 1]) {
        start -= 1;
        if at - start > MAX_PATH_PREFIX_BYTES {
            return None;
        }
    }
    if start < at && !matches!(bytes[at - 1], b'/' | b'\\') {
        return None;
    }
    let mut end = at + CURL.len();
    if bytes[end..].starts_with(EXE) {
        end += EXE.len();
    }
    bytes
        .get(end)
        .is_some_and(|&byte| is_blank(byte) || is_line_end(byte))
        .then_some(end)
}

/// The length of the backslash line continuation at `at` (`\` + LF or `\` +
/// CRLF), or 0.
fn continuation(bytes: &[u8], at: usize) -> usize {
    if bytes.get(at) != Some(&b'\\') {
        return 0;
    }
    match (bytes.get(at + 1), bytes.get(at + 2)) {
        (Some(b'\n'), _) => 2,
        (Some(b'\r'), Some(b'\n')) => 3,
        _ => 0,
    }
}

/// `\` + CR at the very end of the text: a continuation only if an LF
/// follows, which is not known yet, so the window stays open.
fn pending_continuation(bytes: &[u8], at: usize) -> bool {
    bytes.get(at) == Some(&b'\\') && bytes.get(at + 1) == Some(&b'\r') && at + 2 == bytes.len()
}

/// How a window ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// At a command end, a newline, or [`WINDOW_BYTES`].
    Closed,
    /// At the end of the text, before any of those.
    Open,
}

/// One shell word of a window.
struct Word {
    start: usize,
    end: usize,
    /// The first `:` of the word, escaped or quoted ones included.
    colon: Option<usize>,
    /// Whether that colon sits inside a quoted segment.
    colon_quoted: bool,
    /// The closing quote of the last quoted segment.
    last_close: Option<usize>,
    /// Every quote closed and the word ended before the window did.
    complete: bool,
}

struct Walk<'a> {
    bytes: &'a [u8],
    pos: usize,
    limit: usize,
}

impl Walk<'_> {
    fn exhausted(&self) -> Stop {
        if self.limit == self.bytes.len() {
            Stop::Open
        } else {
            Stop::Closed
        }
    }

    fn next_word(&mut self) -> Result<Word, Stop> {
        loop {
            let byte = match self.bytes.get(self.pos) {
                Some(&byte) if self.pos < self.limit => byte,
                _ => return Err(self.exhausted()),
            };
            if is_blank(byte) {
                self.pos += 1;
                continue;
            }
            let skipped = continuation(self.bytes, self.pos);
            if skipped > 0 {
                self.pos += skipped;
                continue;
            }
            if pending_continuation(self.bytes, self.pos) {
                return Err(Stop::Open);
            }
            if is_line_end(byte) || is_command_end(byte) {
                return Err(Stop::Closed);
            }
            return Ok(self.read_word());
        }
    }

    fn read_word(&mut self) -> Word {
        let mut word = Word {
            start: self.pos,
            end: self.pos,
            colon: None,
            colon_quoted: false,
            last_close: None,
            complete: true,
        };
        while self.pos < self.limit {
            let byte = self.bytes[self.pos];
            if is_blank(byte) || is_line_end(byte) || is_command_end(byte) {
                break;
            }
            match byte {
                b'\\' => {
                    if continuation(self.bytes, self.pos) > 0
                        || pending_continuation(self.bytes, self.pos)
                    {
                        break;
                    }
                    match self.bytes.get(self.pos + 1) {
                        Some(b'\r') | None => self.pos += 1,
                        Some(&escaped) => {
                            if escaped == b':' && word.colon.is_none() {
                                word.colon = Some(self.pos + 1);
                            }
                            self.pos += 2;
                        }
                    }
                }
                b'\'' | b'"' => self.quoted(&mut word, byte),
                b':' => {
                    if word.colon.is_none() {
                        word.colon = Some(self.pos);
                    }
                    self.pos += 1;
                }
                _ => self.pos += 1,
            }
        }
        word.end = self.pos.min(self.limit);
        // A word that reaches a window cut short by the cap has no known end.
        if self.pos >= self.limit && self.limit < self.bytes.len() {
            word.complete = false;
        }
        word
    }

    /// Reads the quoted segment opened at `self.pos` into `word`.
    fn quoted(&mut self, word: &mut Word, quote: u8) {
        let mut at = self.pos + 1;
        while at < self.limit {
            let byte = self.bytes[at];
            // A newline ends the window even inside a quote, so the quote is
            // unterminated and a window never reaches into the next line
            // unless a backslash continues it (this also bounds what the
            // incremental session must retain).
            if is_line_end(byte) {
                word.complete = false;
                self.pos = at;
                return;
            }
            if byte == quote {
                word.last_close = Some(at);
                self.pos = at + 1;
                return;
            }
            if quote == b'"'
                && byte == b'\\'
                && matches!(self.bytes.get(at + 1), Some(b'"' | b'\\' | b'$' | b'`'))
            {
                at += 2;
                continue;
            }
            if byte == b':' && word.colon.is_none() {
                word.colon = Some(at);
                word.colon_quoted = true;
            }
            at += 1;
        }
        word.complete = false;
        self.pos = self.limit;
    }

    /// Reads the window: calls `on_password` for the span of every password
    /// argument. `visited` holds the starts of the option words earlier
    /// windows of this scan read: a window that reaches one of them would
    /// read the rest as that window did, so it stops there (this keeps a
    /// run of curl words linear). Returns whether the window ended open.
    fn run(&mut self, visited: &mut Vec<usize>, on_password: &mut dyn FnMut(usize, usize)) -> bool {
        loop {
            let word = match self.next_word() {
                Ok(word) => word,
                Err(stop) => return stop == Stop::Open,
            };
            match visited.binary_search(&word.start) {
                Ok(_) => return false,
                Err(at) => visited.insert(at, word.start),
            }
            let Some(spelling) = option_spelling(&self.bytes[word.start..word.end]) else {
                continue;
            };
            let (argument, argument_start) = match spelling {
                Spelling::NextWord => match self.next_word() {
                    Ok(argument) => {
                        let start = argument.start;
                        (argument, start)
                    }
                    Err(stop) => return stop == Stop::Open,
                },
                Spelling::Attached(offset) => {
                    let start = word.start + offset;
                    (word, start)
                }
            };
            if let Some((start, end)) = password_span(self.bytes, &argument, argument_start) {
                on_password(start, end);
            }
        }
    }
}

/// Where the argument of an option word starts.
enum Spelling {
    /// The next word of the window.
    NextWord,
    /// The remainder of the option word itself, from this offset.
    Attached(usize),
}

/// The spelling of the option `word` is, if it is one that carries a
/// credential argument.
fn option_spelling(word: &[u8]) -> Option<Spelling> {
    for name in [&b"--user"[..], &b"--proxy-user"[..]] {
        if word.starts_with(name) {
            return match word.get(name.len()) {
                None => Some(Spelling::NextWord),
                Some(b'=') => Some(Spelling::Attached(name.len() + 1)),
                Some(_) => None,
            };
        }
    }
    if word.len() >= 2 && word[0] == b'-' && word[1] != b'-' {
        let mut at = 1;
        while at < word.len() && CLUSTER_OPTIONS.contains(&word[at]) {
            at += 1;
        }
        if matches!(word.get(at), Some(b'u' | b'U')) {
            return Some(if at + 1 == word.len() {
                Spelling::NextWord
            } else {
                Spelling::Attached(at + 1)
            });
        }
    }
    None
}

/// The password span of `argument`, whose argument text starts at
/// `argument_start`: everything after the first colon, without the quote
/// characters that enclose it.
fn password_span(bytes: &[u8], argument: &Word, argument_start: usize) -> Option<(usize, usize)> {
    let colon = argument.colon.filter(|&colon| colon >= argument_start)?;
    if !argument.complete {
        return None;
    }
    // `\"user:password\"`: a command line held inside another quoted string
    // needs a second shell pass, which this reader does not perform.
    if bytes.get(argument_start) == Some(&b'\\')
        && matches!(bytes.get(argument_start + 1), Some(b'"' | b'\''))
    {
        return None;
    }
    let mut start = colon + 1;
    if !argument.colon_quoted && matches!(bytes.get(start), Some(b'"' | b'\'')) {
        start += 1;
    }
    let mut end = argument.end;
    if end > 0 && argument.last_close == Some(end - 1) {
        end -= 1;
    }
    (end > start && end - start <= MAX_PASSWORD_BYTES).then_some((start, end))
}

/// Walks the window of every curl word at or after `from`, reporting
/// password spans to `on_password`. Returns whether any window is still open
/// at the end of `input`.
fn scan(input: &str, from: usize, on_password: &mut dyn FnMut(usize, usize)) -> bool {
    let bytes = input.as_bytes();
    let lead = LeadBytes::of(std::iter::once(CURL));
    let mut visited = Vec::new();
    let mut open = false;
    let mut search = from;
    while let Some(at) = find_literal_with(&lead, bytes, CURL, search) {
        search = at + 1;
        let Some(end) = curl_word_end(bytes, at) else {
            continue;
        };
        let mut walk = Walk {
            bytes,
            pos: end,
            limit: end.saturating_add(WINDOW_BYTES).min(bytes.len()),
        };
        open |= walk.run(&mut visited, on_password);
    }
    open
}

/// `${{ ... }}`: a workflow expression, resolved when the command runs.
fn is_expression_reference(value: &str) -> bool {
    value
        .strip_prefix("${{")
        .is_some_and(|rest| rest.ends_with("}}") && rest.len() >= 2)
}

/// Candidates for the password of every curl credential argument.
pub(super) fn candidates(input: &str) -> Vec<Candidate> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    scan(input, 0, &mut |start, end| {
        let Some(value) = input.get(start..end) else {
            return;
        };
        if is_placeholder(value)
            || is_generic_placeholder_word(value)
            || is_backtick_reference(value)
            || is_expression_reference(value)
            || is_brace_placeholder_reference(value)
        {
            return;
        }
        if let Err(at) = spans.binary_search(&(start, end)) {
            spans.insert(at, (start, end));
        }
    });
    spans
        .into_iter()
        .filter_map(|(start, end)| {
            let range = ByteRange::new(start, end)?;
            Some(
                Candidate::built_in("contextual_secret", Confidence::High, range)
                    .with_specificity(Specificity::Contextual)
                    .with_signal_pack(signal_pack!(
                        "curl-user-argument",
                        "credential-by-construction"
                    )),
            )
        })
        .collect()
}

/// `true` when `text`, the incremental session's current unit, ends inside a
/// curl window that has not closed: the unit must stay open until it does.
/// Only a curl word within [`WINDOW_BYTES`] of the end can have an open
/// window, so only that tail is searched.
pub(crate) fn has_open_curl_command(text: &str) -> bool {
    let from = text
        .len()
        .saturating_sub(WINDOW_BYTES + CURL.len() + EXE.len() + 1);
    scan(text, from, &mut |_, _| {})
}

/// How many password spans the reader claims in `input`.
#[cfg(test)]
pub(crate) fn candidate_count(input: &str) -> usize {
    candidates(input).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(input: &str) -> Vec<String> {
        candidates(input)
            .iter()
            .map(|candidate| input[candidate.range().start()..candidate.range().end()].to_owned())
            .collect()
    }

    fn flag() -> String {
        ["-", "u"].concat()
    }

    #[test]
    fn option_spellings_are_exact() {
        for word in [&b"-u"[..], b"-U", b"--user", b"--proxy-user", b"-sSfLku"] {
            assert!(matches!(option_spelling(word), Some(Spelling::NextWord)));
        }
        for word in [&b"-uARG"[..], b"--user=ARG", b"--proxy-user=A", b"-sSuARG"] {
            assert!(matches!(option_spelling(word), Some(Spelling::Attached(_))));
        }
        for word in [
            &b"--user-agent"[..],
            b"--us",
            b"--users",
            b"-A",
            b"-xu",
            b"--",
            b"-",
            b"u",
        ] {
            assert!(option_spelling(word).is_none(), "{word:?}");
        }
    }

    #[test]
    fn a_curl_word_needs_a_boundary_before_and_whitespace_after() {
        let ends = |text: &str| curl_word_end(text.as_bytes(), text.find("curl").unwrap());
        assert_eq!(ends("curl x"), Some(4));
        assert_eq!(ends("curl.exe x"), Some(8));
        assert_eq!(ends("/usr/bin/curl x"), Some(13));
        assert_eq!(ends("@curl x"), Some(5));
        assert_eq!(ends("mycurl x"), None);
        assert_eq!(ends("curl-config x"), None);
        assert_eq!(ends("curl"), None);
        assert_eq!(ends("curlimages/curl:1 x"), None);
    }

    #[test]
    fn the_password_is_the_text_after_the_first_colon() {
        let pw = ["Synthetic", "Revoked", "Pw01"].concat();
        let u = flag();
        assert_eq!(
            read(&format!("curl {u} a:{pw}:{pw} h\n")),
            [format!("{pw}:{pw}")]
        );
        assert_eq!(read(&format!("curl {u} \"a:{pw}\" h\n")), vec![pw.clone()]);
        assert_eq!(read(&format!("curl {u} a:\"{pw}\" h\n")), vec![pw.clone()]);
        assert!(read(&format!("curl {u} a h\n")).is_empty());
        assert!(read(&format!("curl {u} a: h\n")).is_empty());
    }

    #[test]
    fn only_a_continuation_leaves_the_window_open() {
        let u = flag();
        assert!(has_open_curl_command(&format!("curl {u} a:b \\\n")));
        assert!(has_open_curl_command(&format!("curl {u} a:b \\\r\n")));
        assert!(has_open_curl_command(&format!("curl {u} a:b \\\r")));
        assert!(!has_open_curl_command(&format!("curl {u} a:b\n")));
        assert!(!has_open_curl_command(&format!("curl {u} \"a:b\n")));
        assert!(!has_open_curl_command(&format!("curl {u} a:b; x \\\n")));
        assert!(!has_open_curl_command("no command here \\\n"));
    }
}
