//! Shared low-level scanning helpers for hand-written detector grammars.
//!
//! The core crate depends on nothing outside `std`
//! (`workspace.metadata.redact-secret.allowed-dependencies` is empty), so every
//! detector parses its grammar by hand instead of through a regex engine.
//! These helpers centralize the small pieces of ECMAScript character-class
//! semantics that more than one ported grammar depends on, operating on
//! UTF-8 byte offsets throughout ([`crate::RANGE_UNIT`]).

/// `true` for a character ECMAScript's `\s` class matches outside Unicode
/// mode: `WhiteSpace` or `LineTerminator`. Rust's `char::is_whitespace`
/// covers the same `White_Space` code points except the byte-order-mark,
/// which ECMAScript's `WhiteSpace` production also includes.
pub(super) fn is_js_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ch == '\u{FEFF}'
}

/// `true` for a character ECMAScript treats as a `LineTerminator`.
pub(super) fn is_js_line_terminator(ch: char) -> bool {
    matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// `true` for [`is_js_whitespace`] excluding [`is_js_line_terminator`]:
/// horizontal whitespace only. Unlike the ECMAScript `\s` class this mirrors
/// elsewhere, a contextual assignment's name-operator-value grammar must not
/// treat a line terminator as ordinary filler, or an operator with no value
/// on its own line reads the next physical line's first token as the value
/// (see `docs/specs/contextual-detection.md`).
pub(super) fn is_horizontal_js_whitespace(ch: char) -> bool {
    is_js_whitespace(ch) && !is_js_line_terminator(ch)
}

/// The character starting at byte offset `pos`, or `None` past the end of
/// `input` or when `pos` is not on a character boundary.
pub(super) fn char_at(input: &str, pos: usize) -> Option<char> {
    input.get(pos..)?.chars().next()
}

/// The character immediately before byte offset `pos`, or `None` at the
/// start of `input` or when `pos` is not on a character boundary.
pub(super) fn prev_char(input: &str, pos: usize) -> Option<char> {
    input.get(..pos)?.chars().next_back()
}

/// `true` when `pos` is a multiline-mode `^` position: the start of `input`
/// or immediately after a [`is_js_line_terminator`] character.
pub(super) fn is_line_start(input: &str, pos: usize) -> bool {
    pos == 0 || prev_char(input, pos).is_some_and(is_js_line_terminator)
}

/// Where the line that starts at `start` ends, and where the next one
/// starts (`bytes.len() + 1` when there is none).
///
/// A line ends at `\n`, which belongs to neither line, or after a lone `\r`
/// (one followed by anything but `\n`), which stays at the end of its line
/// the way the `\r` of a CRLF pair does. These are the line ends the
/// incremental session closes a unit at, so a detector that reads context
/// from "the same line" or from a bounded number of earlier lines sees the
/// same lines whether it scans one unit or the whole input (issue #990).
/// A `\r` that ends the input stays in its line, as it did before, so on
/// input with only LF or CRLF line endings the lines are unchanged.
fn line_end_from(bytes: &[u8], start: usize) -> (usize, usize) {
    let mut at = start;
    while at < bytes.len() {
        match bytes[at] {
            b'\n' => return (at, at + 1),
            b'\r' if bytes.get(at + 1).is_some_and(|&next| next != b'\n') => {
                return (at + 1, at + 1);
            }
            _ => at += 1,
        }
    }
    (bytes.len(), bytes.len() + 1)
}

/// Every line of `input` as a byte range, per [`line_end_from`]: without its
/// `\n`, with a trailing `\r` (of a CRLF pair or a lone one) kept. Each byte
/// belongs to at most one range, so bounded work per line is bounded work
/// overall. An input ending in `\n` yields a final empty line.
///
/// Every keyword-gated detector walks the whole input through this, so the
/// search for the next `\n` or `\r` reads eight bytes per step
/// ([`next_line_byte`]).
pub(super) fn lines(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let bytes = input.as_bytes();
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start > bytes.len() {
            return None;
        }
        let at = next_line_byte(bytes, start);
        let (end, next) = match (bytes.get(at), bytes.get(at + 1)) {
            (Some(b'\n'), _) => (at, at + 1),
            // The `\r` of a CRLF pair stays in its line.
            (Some(_), Some(b'\n')) => (at + 1, at + 2),
            // A lone `\r` ends its line after itself.
            (Some(_), Some(_)) => (at + 1, at + 1),
            // No terminator left, or a `\r` that ends the input.
            (Some(_), None) | (None, _) => (bytes.len(), bytes.len() + 1),
        };
        let line = (start, end);
        start = next;
        Some(line)
    })
}

/// The index of the first `\n` or `\r` at or after `from`, or `bytes.len()`.
///
/// Eight bytes are tested per step with the word-at-a-time zero-byte test:
/// in `v - 0x01..01 & !v & 0x80..80` the lowest set bit marks the first zero
/// byte of `v` exactly (a borrow can only mark bytes above it), so XOR-ing the
/// word with each terminator and taking the lowest mark of either finds the
/// first terminator. This keeps the per-line search as cheap for a short
/// line as a byte loop and several times cheaper for a long one.
fn next_line_byte(bytes: &[u8], from: usize) -> usize {
    const ONES: u64 = u64::from_le_bytes([0x01; 8]);
    const HIGHS: u64 = u64::from_le_bytes([0x80; 8]);
    const NEWLINES: u64 = u64::from_le_bytes([b'\n'; 8]);
    const RETURNS: u64 = u64::from_le_bytes([b'\r'; 8]);
    let mut at = from;
    while let Some(chunk) = bytes.get(at..at + 8) {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        let word = u64::from_le_bytes(word);
        let newline = word ^ NEWLINES;
        let carriage_return = word ^ RETURNS;
        let found = ((newline.wrapping_sub(ONES) & !newline)
            | (carriage_return.wrapping_sub(ONES) & !carriage_return))
            & HIGHS;
        if found != 0 {
            return at + (found.trailing_zeros() / 8) as usize;
        }
        at += 8;
    }
    bytes[at.min(bytes.len())..]
        .iter()
        .position(|&byte| byte == b'\n' || byte == b'\r')
        .map_or(bytes.len(), |offset| at + offset)
}

/// The line ([`lines`]) that holds `start..end`, a span with no line break
/// inside it, as a byte range. Only that line is read.
pub(super) fn line_around(input: &str, start: usize, end: usize) -> (usize, usize) {
    let bytes = input.as_bytes();
    // A lone `\r` right before `start` ends the previous line.
    let line_start = if start > 0 && bytes[start - 1] == b'\r' && bytes.get(start) != Some(&b'\n') {
        start
    } else {
        line_start_before(input, start)
    };
    (line_start, line_end_from(bytes, end).0)
}

/// Where the line that ends at `end` starts: after the last line break
/// before it, a `\n` or a lone `\r` ([`line_end_from`]). A `\r` at
/// `end - 1` is not a break here: it is followed by `\n`, by the end of the
/// input, or it is the break that ends this line's predecessor at `end`.
/// Both searches are `memrchr` scans over this line alone.
fn line_start_before(input: &str, end: usize) -> usize {
    let head = &input[..end];
    let after_newline = head.rfind('\n').map_or(0, |at| at + 1);
    // No `\n` lies between `after_newline` and `end`, so every `\r` there
    // but the last byte is followed by another byte of the line: a lone one.
    let line = &input[after_newline..end];
    let line = line.strip_suffix('\r').unwrap_or(line);
    line.rfind('\r')
        .map_or(after_newline, |offset| after_newline + offset + 1)
}

/// The last `count` lines of `input` per [`lines`], oldest first, after
/// dropping one trailing `\n`: the complete lines a retention hint reads
/// back over. Only the tail is read, so the cost is the length of those
/// lines, not of `input`.
pub(super) fn last_lines(input: &str, count: usize) -> Vec<&str> {
    let complete = input.strip_suffix('\n').unwrap_or(input);
    let bytes = complete.as_bytes();
    let mut tail = Vec::with_capacity(count);
    let mut end = bytes.len();
    while tail.len() < count {
        let start = line_start_before(complete, end);
        tail.push(&complete[start..end]);
        if start == 0 {
            break;
        }
        end = if bytes[start - 1] == b'\n' {
            start - 1
        } else {
            start
        };
    }
    tail.reverse();
    tail
}

/// The last `count` lines of `tail`, a [`last_lines`] result for a count at
/// least `count`: exactly `last_lines(input, count)` over the same input,
/// since both walk back from the same end and stop at the same first line.
/// The incremental session computes one tail for every lookback hint and
/// each hint reads its own window from it (issue #1060).
pub(super) fn tail_lines<'t, 'a>(tail: &'t [&'a str], count: usize) -> &'t [&'a str] {
    &tail[tail.len().saturating_sub(count)..]
}

/// Advances `start` past every consecutive character matching `pred`.
pub(super) fn skip_while_chars(input: &str, start: usize, pred: fn(char) -> bool) -> usize {
    let mut cursor = start;
    while let Some(ch) = char_at(input, cursor) {
        if pred(ch) {
            cursor += ch.len_utf8();
        } else {
            break;
        }
    }
    cursor
}

/// Retreats `end` past every consecutive character matching `pred`, scanning
/// backward from byte offset `end`.
pub(super) fn rskip_while_chars(input: &str, end: usize, pred: fn(char) -> bool) -> usize {
    let mut cursor = end;
    while let Some(ch) = prev_char(input, cursor) {
        if pred(ch) {
            cursor -= ch.len_utf8();
        } else {
            break;
        }
    }
    cursor
}

/// Length in bytes of the maximal run of `pred`-matching bytes starting at
/// `start`. Every predicate used with this helper matches ASCII bytes only,
/// so byte and character boundaries coincide.
pub(super) fn ascii_run_len(bytes: &[u8], start: usize, pred: fn(u8) -> bool) -> usize {
    let mut end = start;
    while end < bytes.len() && pred(bytes[end]) {
        end += 1;
    }
    end - start
}

/// Case-insensitive ASCII literal match at byte offset `pos`. Byte
/// comparison never requires `pos` to be on a character boundary.
pub(super) fn starts_with_ci(input: &str, pos: usize, literal: &str) -> bool {
    let literal = literal.as_bytes();
    input
        .as_bytes()
        .get(pos..pos + literal.len())
        .is_some_and(|window| window.eq_ignore_ascii_case(literal))
}

/// The first offset at or after `from` where the ASCII `needle` occurs
/// case-insensitively in `bytes`, or `None`. An empty needle matches at
/// `from` when `from <= bytes.len()`.
///
/// The first needle byte is searched eight bytes at a time (the word-at-a-time
/// zero-byte test of [`next_line_byte`]) in both its cases when it is a
/// letter, and each candidate window is then compared in full, so the result
/// equals a per-offset [`starts_with_ci`] scan. Byte comparison never needs a
/// character boundary; a found offset starts with an ASCII byte when the
/// needle does.
pub(super) fn find_ci(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    const ONES: u64 = u64::from_le_bytes([0x01; 8]);
    const HIGHS: u64 = u64::from_le_bytes([0x80; 8]);
    let Some(&first) = needle.first() else {
        return (from <= bytes.len()).then_some(from);
    };
    let last_start = bytes.len().checked_sub(needle.len())?;
    let lower = first.to_ascii_lowercase();
    let upper = first.to_ascii_uppercase();
    let lower_word = u64::from_le_bytes([lower; 8]);
    let upper_word = u64::from_le_bytes([upper; 8]);
    let mut at = from;
    while at <= last_start {
        // Skip to the next candidate first byte.
        let mut found = None;
        while at <= last_start {
            if let Some(chunk) = bytes.get(at..at + 8) {
                let mut word = [0u8; 8];
                word.copy_from_slice(chunk);
                let word = u64::from_le_bytes(word);
                let lo = word ^ lower_word;
                let up = word ^ upper_word;
                let marks = ((lo.wrapping_sub(ONES) & !lo) | (up.wrapping_sub(ONES) & !up)) & HIGHS;
                if marks == 0 {
                    at += 8;
                    continue;
                }
                at += (marks.trailing_zeros() / 8) as usize;
                found = Some(at);
                break;
            }
            if bytes[at] == lower || bytes[at] == upper {
                found = Some(at);
                break;
            }
            at += 1;
        }
        let candidate = found?;
        if candidate > last_start {
            return None;
        }
        if bytes[candidate..candidate + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(candidate);
        }
        at = candidate + 1;
    }
    None
}

/// `true` when the ASCII `needle` occurs anywhere in `haystack`,
/// case-insensitively ([`find_ci`]).
pub(super) fn contains_ci(haystack: &str, needle: &str) -> bool {
    find_ci(haystack.as_bytes(), 0, needle.as_bytes()).is_some()
}

/// Case-insensitive ASCII literal suffix match.
pub(super) fn ends_with_ci(value: &str, suffix: &str) -> bool {
    let bytes = value.as_bytes();
    let suffix = suffix.as_bytes();
    bytes.len() >= suffix.len() && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// `true` when `value` is entirely built from words already on `exact_words`
/// (case-insensitively), closing trivial lexical variants of an
/// already-excluded word — a leading/trailing separator, an appended digit
/// to a word on `digit_suffix_words`, or two listed words joined with
/// `-`/`_` — without falling back to raw substring containment (see
/// `docs/specs/contextual-detection.md`).
///
/// `value` is split into maximal runs of ASCII alphanumeric characters
/// (every other byte is a separator). Two independent checks then apply:
///
/// - the tokens, concatenated in order with no separator, spell out exactly
///   one word on `exact_words` (`replace_me`, `my-secret-password` ->
///   `replaceme`, `mysecretpassword`); or
/// - every token is itself a word on `exact_words`, or, once a trailing run
///   of ASCII digits is stripped, a word on `digit_suffix_words`
///   (`changeme2` -> `changeme`; `REDACTED-EXAMPLE` -> `redacted` +
///   `example`).
///
/// `digit_suffix_words` must be a subset of `exact_words` restricted to
/// words distinctive enough that an appended digit is still unambiguously a
/// placeholder — generic role names such as `secret` or `password` belong
/// only on `exact_words`, since `password1` or `secret01` are common real
/// (if weak) credential shapes, not placeholder text, and must keep being
/// reported.
///
/// A value with no alphanumeric characters at all never matches. Digit
/// stripping only trims the end of a token, so a word embedded in a larger
/// alphanumeric run (`mySecretKeyAbc123`) is never split out and stays a
/// false negative by design, not an exclusion.
pub(super) fn matches_placeholder_vocabulary(
    value: &str,
    exact_words: &[&str],
    digit_suffix_words: &[&str],
) -> bool {
    fn strip_trailing_digits(token: &str) -> &str {
        token.trim_end_matches(|ch: char| ch.is_ascii_digit())
    }
    let is_listed =
        |token: &str, words: &[&str]| words.iter().any(|word| token.eq_ignore_ascii_case(word));
    let token_is_placeholder = |token: &str| {
        is_listed(token, exact_words) || {
            let core = strip_trailing_digits(token);
            core.len() < token.len() && is_listed(core, digit_suffix_words)
        }
    };

    let tokens: Vec<&str> = value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.is_empty() {
        return false;
    }

    let joined: String = tokens.concat();
    is_listed(&joined, exact_words) || tokens.iter().all(|token| token_is_placeholder(token))
}

/// `true` for a value made of the same character repeated three or more
/// times (`xxxxxxxxxxxx`, `00000000000`, `••••••••`) -- classic
/// redaction-style filler used in documentation and masked terminal/UI
/// echoes to mean "value omitted", structurally unlike a real secret.
///
/// Compares by Unicode scalar value, not raw byte, so a multi-byte filler
/// character (`•`, U+2022) is recognized the same as a single-byte one
/// (`*`). Shared by the connection-string and generic-token detectors so
/// the exclusion stays consistent between them (see #256, #264).
pub(super) fn is_repeated_character_filler(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let mut count = 1usize;
    for ch in chars {
        if ch != first {
            return false;
        }
        count += 1;
    }
    count >= 3
}

/// Words that open a documentation placeholder asking the reader to supply
/// their own credential (`YOUR_ACCESS_TOKEN`, `INSERT_API_KEY`).
const PLACEHOLDER_LEAD_WORDS: &[&str] = &["your", "insert", "enter", "paste", "replace"];

/// Words that name the kind of credential a placeholder stands for. Every
/// word after the lead word must come from this list.
///
/// Issue #993 adds the qualifiers provider documentation puts in front of a
/// credential noun (`your-bot-token-here`, `whsec_YOUR_SIGNING_SECRET`,
/// `ntn_yourinternalintegrationtokenhere`): `account`, `admin`, `bot`,
/// `deploy`, `integration`, `internal`, `org`, `project`, `signing` and
/// `webhook`.
const PLACEHOLDER_CREDENTIAL_WORDS: &[&str] = &[
    "access",
    "account",
    "admin",
    "api",
    "app",
    "auth",
    "bearer",
    "bot",
    "client",
    "deploy",
    "id",
    "integration",
    "internal",
    "jwt",
    "key",
    "oauth",
    "oauth2",
    "org",
    "personal",
    "project",
    "refresh",
    "secret",
    "service",
    "session",
    "signing",
    "token",
    "user",
    "webhook",
    "here",
    "with",
];

/// Provider names a documentation placeholder may carry between its lead word
/// and the credential words (`YOUR_DEEPGRAM_API_KEY`,
/// `replace-with-your-mistral-key`). A closed list of the AI-inference and
/// developer-credential providers the built-in detectors name, not a
/// vocabulary. Issue #774; `convex` and `fal` were added with their exact
/// credential names in issue #919 (`FAL_KEY=your_fal_key`). Since issue
/// #993 every provider segment of `generic-token`'s rule-2 list
/// ([`is_placeholder_provider_word`]) also counts (`YOUR_MAILGUN_API_KEY`,
/// `your-travis-api-token`); a provider outside both lists
/// (`YOUR_ACMECLOUD_API_KEY`) is one word off and stays detected.
const PLACEHOLDER_PROVIDER_WORDS: &[&str] = &[
    "ai",
    "ai21",
    "anthropic",
    "cohere",
    "convex",
    "deepgram",
    "deepseek",
    "elevenlabs",
    "fal",
    "fireworks",
    "gemini",
    "groq",
    "huggingface",
    "mistral",
    "openai",
    "openrouter",
    "perplexity",
    "replicate",
    "tavily",
    "together",
    "xai",
];

/// `true` for a [`PLACEHOLDER_CREDENTIAL_WORDS`] entry, case-insensitively.
pub(super) fn is_placeholder_credential_word(word: &str) -> bool {
    PLACEHOLDER_CREDENTIAL_WORDS
        .iter()
        .any(|listed| word.eq_ignore_ascii_case(listed))
}

/// Credential nouns a placeholder must name at least once, so a lead word
/// followed only by qualifiers (`YOUR_PERSONAL_ACCESS`) is not enough.
const PLACEHOLDER_CREDENTIAL_NOUNS: &[&str] = &["jwt", "key", "secret", "token"];

/// `true` for a provider word a placeholder may carry
/// ([`PLACEHOLDER_PROVIDER_WORDS`] or a segment of `generic-token`'s
/// provider list), case-insensitively.
fn is_placeholder_provider_word(word: &str) -> bool {
    PLACEHOLDER_PROVIDER_WORDS
        .iter()
        .chain(super::generic_token::DEDICATED_PROVIDER_SEGMENTS)
        .any(|listed| word.eq_ignore_ascii_case(listed))
}

/// `true` for an instructional placeholder written as one glued word, such
/// as `yourkey`, `yourapikey` or `YourSigningKeyHere` (issue #949): ASCII
/// letters only, opening with a [`PLACEHOLDER_LEAD_WORDS`] entry, and the
/// rest splitting exactly into [`PLACEHOLDER_CREDENTIAL_WORDS`],
/// [`PLACEHOLDER_PROVIDER_WORDS`], provider segments or lead words, with at least
/// one [`PLACEHOLDER_CREDENTIAL_NOUNS`] entry, all case-insensitively.
///
/// Without separators the word boundaries are ambiguous, so this is only
/// applied behind a vendor prefix (`re_yourkey`), never to a bare value. A
/// letter left over (`yourkeyq`) or any digit keeps the value detected.
pub(super) fn is_glued_instructional_placeholder(value: &str) -> bool {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    let Some(rest) = PLACEHOLDER_LEAD_WORDS
        .iter()
        .find_map(|lead| lower.strip_prefix(lead))
    else {
        return false;
    };
    let words = || {
        PLACEHOLDER_CREDENTIAL_WORDS
            .iter()
            .chain(PLACEHOLDER_PROVIDER_WORDS)
            .chain(super::generic_token::DEDICATED_PROVIDER_SEGMENTS)
            .chain(PLACEHOLDER_LEAD_WORDS)
    };
    // reachable[i]: rest[..i] splits into listed words; with_noun[i]: one
    // such split names a credential noun. Bounded by the value's length
    // times the fixed word lists.
    let len = rest.len();
    let mut reachable = vec![false; len + 1];
    let mut with_noun = vec![false; len + 1];
    reachable[0] = true;
    for start in 0..len {
        if !reachable[start] {
            continue;
        }
        for word in words() {
            if rest[start..].starts_with(word) {
                let end = start + word.len();
                reachable[end] = true;
                with_noun[end] |= with_noun[start] || PLACEHOLDER_CREDENTIAL_NOUNS.contains(word);
            }
        }
    }
    len > 0 && reachable[len] && with_noun[len]
}

/// `true` for an instructional placeholder written as a phrase of plain
/// words (issue #1042): `your_key_for_ci_pipeline_test_fixture_only`, the
/// word fixture the #860 evidence lists behind the `rpa_` prefix. Two or more
/// words split on `_` or `-`, each ASCII letters only and in one case, the
/// first a [`PLACEHOLDER_LEAD_WORDS`] entry and at least one a
/// [`PLACEHOLDER_CREDENTIAL_NOUNS`] entry; the other words may be any
/// letters. Unlike [`is_instructional_token_placeholder`] the later words are
/// not listed, so this is applied only behind a vendor prefix, never to a
/// bare value. A digit, a mixed-case word, or a missing lead word or noun
/// keeps the value detected.
pub(super) fn is_lead_word_phrase_placeholder(value: &str) -> bool {
    let words: Vec<&str> = value.split(['_', '-']).collect();
    let one_case = |word: &str| {
        !word.is_empty()
            && (word.bytes().all(|byte| byte.is_ascii_lowercase())
                || word.bytes().all(|byte| byte.is_ascii_uppercase()))
    };
    let listed =
        |word: &str, words: &[&str]| words.iter().any(|listed| word.eq_ignore_ascii_case(listed));
    words.len() >= 2
        && words.iter().all(|word| one_case(word))
        && listed(words[0], PLACEHOLDER_LEAD_WORDS)
        && words[1..]
            .iter()
            .any(|word| listed(word, PLACEHOLDER_CREDENTIAL_NOUNS))
}

/// `true` for a documentation placeholder glued as `my` + credential words
/// (issue #1042): `mykeysecret` and `mykeyid`, the `ClickHouse` Cloud docs'
/// `KEY_SECRET`/`KEY_ID` examples the #860 evidence lists. Lowercase ASCII
/// letters only, `my`, then an exact split into two or more
/// [`PLACEHOLDER_CREDENTIAL_WORDS`] with at least one
/// [`PLACEHOLDER_CREDENTIAL_NOUNS`] entry. One word after `my` (`mysecret`,
/// `mykey`) is a common weak real password and stays reported, as does any
/// leftover letter, digit or uppercase letter.
pub(super) fn is_glued_my_placeholder(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("my") else {
        return false;
    };
    if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return false;
    }
    // reached[i][many][noun]: rest[..i] splits into listed words, `many`
    // when two or more, `noun` when one is a credential noun. Bounded by the
    // value's length times the fixed word list.
    let len = rest.len();
    let mut reached = vec![[[false; 2]; 2]; len + 1];
    reached[0][0][0] = true;
    for start in 0..len {
        for word in PLACEHOLDER_CREDENTIAL_WORDS {
            if !rest[start..].starts_with(word) {
                continue;
            }
            let end = start + word.len();
            let is_noun = PLACEHOLDER_CREDENTIAL_NOUNS.contains(word);
            for many in 0..2 {
                for noun in 0..2 {
                    if reached[start][many][noun] {
                        let next_many = usize::from(many == 1 || start > 0);
                        reached[end][next_many][usize::from(noun == 1 || is_noun)] = true;
                    }
                }
            }
        }
    }
    reached[len][1][1]
}

/// `true` for an instructional placeholder such as `YOUR_ACCESS_TOKEN`,
/// `INSERT_ACCESS_TOKEN`, `YOUR_API_KEY`, or `your-oauth-token-here`: the
/// value splits on `_`, `-`, and `.` into two or more words, the first is a
/// [`PLACEHOLDER_LEAD_WORDS`] entry, every later word is a
/// [`PLACEHOLDER_CREDENTIAL_WORDS`], [`PLACEHOLDER_PROVIDER_WORDS`] or
/// lead-word entry (`ENTER_YOUR_ACCESS_TOKEN_HERE`), and at least one later word is a
/// [`PLACEHOLDER_CREDENTIAL_NOUNS`] entry, all matched case-insensitively.
///
/// Shared by `bearer-token` (issue #745) and `generic-token` (issue #756,
/// `apiKey: "YOUR_API_KEY"`), so both detectors agree on what an
/// instructional placeholder is. Any byte outside `[A-Za-z0-9._-]`, any word off the lists, or a word
/// glued to random material (`YOUR_ACCESS_TOKEN9f2c`) keeps the value
/// detected, so a real token is never excluded for merely starting with
/// `your`.
pub(super) fn is_instructional_token_placeholder(value: &str) -> bool {
    let is_listed =
        |word: &str, words: &[&str]| words.iter().any(|listed| word.eq_ignore_ascii_case(listed));
    let mut words = value.split(['_', '-', '.']);
    let Some(lead) = words.next() else {
        return false;
    };
    if !is_listed(lead, PLACEHOLDER_LEAD_WORDS) {
        return false;
    }
    let mut saw_noun = false;
    let mut count = 0usize;
    for word in words {
        if !is_listed(word, PLACEHOLDER_CREDENTIAL_WORDS)
            && !is_listed(word, PLACEHOLDER_LEAD_WORDS)
            && !is_placeholder_provider_word(word)
        {
            return false;
        }
        saw_noun |= is_listed(word, PLACEHOLDER_CREDENTIAL_NOUNS);
        count += 1;
    }
    count > 0 && saw_noun
}

/// Hash-algorithm names that, written directly in front of an opaque value
/// with a `=` or `:` separator, label that value as a digest (issue #744).
/// Matched case-insensitively.
const DIGEST_ALGORITHM_LABELS: &[&str] = &[
    "md5", "sha1", "sha-1", "sha224", "sha-224", "sha256", "sha-256", "sha384", "sha-384",
    "sha512", "sha-512", "sha3-256", "sha3-512", "blake2b", "blake2s", "blake3",
];

/// `true` when `value` itself opens with a hash-algorithm label and `:` or
/// `=`, optionally behind `hmac-` (`hmac-sha256:<hex>`, `sha256:<hex>`): an
/// audit-log HMAC or content digest, not a credential (issue #702).
pub(super) fn starts_with_digest_label(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let rest = lower.strip_prefix("hmac-").unwrap_or(&lower);
    DIGEST_ALGORITHM_LABELS.iter().any(|label| {
        rest.strip_prefix(label)
            .is_some_and(|after| after.starts_with(':') || after.starts_with('='))
    })
}

/// `true` when the value starting at byte offset `start` of `input` is
/// introduced by a hash-algorithm label: one of [`DIGEST_ALGORITHM_LABELS`],
/// then `=` or `:`, then optional spaces or tabs, directly before the value
/// (`md5=<hex>`, `image@sha256:<hex>`, `sha256: <hex>`). The label itself
/// must not continue a wider identifier on its left (`xmd5=` does not
/// count), though a `_`, `-`, `@`, or any other non-alphanumeric byte may
/// precede it.
///
/// A value introduced this way is a published checksum or content digest,
/// not a credential, so the keyword-gated bare-value detectors
/// (`twilio-auth-token`, `twilio-api-key-secret`,
/// `confluent-cloud-api-secret-legacy`) skip it even when their provider's
/// name is on the same line. The label must sit immediately in front of the
/// value: a digest label elsewhere on the line proves nothing about an
/// unrelated value.
pub(super) fn is_labelled_digest(input: &str, start: usize) -> bool {
    let bytes = input.as_bytes();
    let mut cursor = start;
    while cursor > 0 && matches!(bytes[cursor - 1], b' ' | b'\t') {
        cursor -= 1;
    }
    if cursor == 0 || !matches!(bytes[cursor - 1], b'=' | b':') {
        return false;
    }
    let label_end = cursor - 1;
    DIGEST_ALGORITHM_LABELS.iter().any(|label| {
        label_end >= label.len()
            && starts_with_ci(input, label_end - label.len(), label)
            && (label_end == label.len()
                || !bytes[label_end - label.len() - 1].is_ascii_alphanumeric())
    })
}

// --- interpolation / environment-reference exclusions -------------------
//
// Shared by `generic_token` and `connection_string` (issue #279, #292,
// #469) so a value that is a pointer to a runtime-resolved secret --
// rather than the secret itself -- is treated the same way regardless of
// which detector's grammar reaches it.

/// `true` when `value` is exactly `open` followed by anything followed by
/// `close` -- the whole-value delimiter shape `is_template_reference` uses,
/// generalized to an arbitrary delimiter pair. A value that only starts
/// with `open`, or that carries the pair embedded inside a larger string,
/// does not satisfy this and stays detected.
pub(super) fn is_fully_delimited(value: &str, open: &str, close: &str) -> bool {
    value.starts_with(open) && value.ends_with(close) && value.len() >= open.len() + close.len()
}

/// `true` when the whole value is delimited by `{{` and `}}`
/// (`^\{\{.*\}\}$`) -- the idiomatic Jinja/Helm/Go-template reference syntax
/// Ansible, Helm, Salt, and Go templates use for a vaulted or injected value
/// (`{{ vault_db_password }}`, `{{ .Values.postgresql.auth.password }}`).
pub(super) fn is_template_reference(value: &str) -> bool {
    is_fully_delimited(value, "{{", "}}")
}

/// `true` for a POSIX/shell, `Makefile`, or Kustomize variable or
/// command-substitution reference (`$(registryPassword)`,
/// `$(pass show db/prod)`): the value names a variable or command to
/// resolve at runtime, not a secret.
pub(super) fn is_command_substitution_reference(value: &str) -> bool {
    is_fully_delimited(value, "$(", ")")
}

/// `true` for a Ruby string-interpolation reference
/// (`#{ENV['DB_PASSWORD']}`).
pub(super) fn is_ruby_interpolation_reference(value: &str) -> bool {
    is_fully_delimited(value, "#{", "}")
}

/// Openers of the opencode config substitutions, `{env:...}` and
/// `{file:...}`, resolved from the environment or a file at load time rather
/// than containing a secret directly. Static, so a check allocates nothing
/// (issue #984).
pub(super) const OPENCODE_REFERENCE_OPENERS: &[&str] = &["{env:", "{file:"];

/// `true` for an opencode `{env:VAR}` or `{file:path}` substitution.
pub(super) fn is_opencode_reference(value: &str) -> bool {
    OPENCODE_REFERENCE_OPENERS
        .iter()
        .any(|open| is_fully_delimited(value, open, "}"))
}

/// `true` for a bare shell or PowerShell environment-variable reference:
/// `$` immediately followed by an identifier-start character
/// (`$DB_PASSWORD`, `$env:DB_PASSWORD` -- PowerShell's drive-qualified
/// `env:` provider, itself a valid identifier-start run). Unlike
/// [`is_fully_delimited`]'s whole-value checks, this is intentionally a
/// prefix match: a shell variable reference consumes to the right for as
/// long as the identifier continues, so the entire captured value is the
/// reference regardless of what trails the identifier.
pub(super) fn starts_with_bare_dollar_reference(value: &str) -> bool {
    value.as_bytes().first() == Some(&b'$')
        && char_at(value, 1).is_some_and(|second| second.is_ascii_alphabetic() || second == '_')
}

/// `true` for a byte allowed inside an environment-variable identifier:
/// ASCII letter, digit, or `_`, matching shell/POSIX identifier rules.
pub(super) fn is_env_var_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// `true` for a cmd.exe/batch-style Windows environment-variable reference
/// (`%DB_PASSWORD%`): the whole value is `%` + an identifier + `%`, expanded
/// by the shell at runtime rather than a secret. `%` is common enough
/// punctuation on its own (a percentage-bounded range) that a bare
/// delimiter-pair check like [`is_fully_delimited`] would exclude values
/// that merely start and end with one, so the content between the
/// delimiters must itself look like an identifier.
pub(super) fn is_windows_env_reference(value: &str) -> bool {
    value
        .strip_prefix('%')
        .and_then(|rest| rest.strip_suffix('%'))
        .is_some_and(is_env_var_identifier)
}

/// Last key-name segments that name a public identifier, a location or an
/// account attribute rather than the credential itself (`OKTA_ORG_URL`,
/// `MAILGUN_DOMAIN`, `TWILIO_ACCOUNT_SID`).
const NON_CREDENTIAL_KEY_SEGMENTS: &[&str] = &[
    "id", "ids", "uuid", "sid", "name", "url", "uri", "host", "hostname", "domain", "region",
    "org", "site", "endpoint", "email", "user", "username", "account", "project", "version",
    "slug", "commit", "sha", "branch", "tag", "number",
];

/// `true` for a byte of an assignment key name: `[A-Za-z0-9_.-]`.
fn is_assignment_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

/// The key a value starting at `value_start` of `line` is assigned to: the
/// run of [`is_assignment_key_byte`] bytes left of a gap of spaces, tabs,
/// quotes and at least one `=` or `:`. `None` when no operator joins them.
pub(super) fn assignment_key(line: &[u8], value_start: usize) -> Option<&[u8]> {
    let mut end = value_start.min(line.len());
    let mut has_operator = false;
    while end > 0 && matches!(line[end - 1], b' ' | b'\t' | b'"' | b'\'' | b'=' | b':') {
        has_operator |= matches!(line[end - 1], b'=' | b':');
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_assignment_key_byte(line[start - 1]) {
        start -= 1;
    }
    (has_operator && start < end).then_some(&line[start..end])
}

/// `true` when the value starting at byte `value_start` of `line` is
/// assigned to a key whose last normalized segment names an identifier, a
/// location or an account attribute ([`NON_CREDENTIAL_KEY_SEGMENTS`]):
/// `TRAVIS_REPO_SLUG=`, `build_id:`, `"projectUrl":`.
pub(super) fn is_non_credential_assignment(line: &str, value_start: usize) -> bool {
    assignment_key(line.as_bytes(), value_start)
        .and_then(|key| std::str::from_utf8(key).ok())
        .is_some_and(|key| {
            super::generic_token::normalize_name(key)
                .rsplit('_')
                .next()
                .is_some_and(|segment| NON_CREDENTIAL_KEY_SEGMENTS.contains(&segment))
        })
}

/// `true` when the value starting at byte `value_start` of `line` is the
/// value of an assignment that names the provider's credential (issue #702):
///
/// - the key, after [`super::generic_token::normalize_name`], contains one
///   of `keywords` (`MAILCHIMP_API_KEY`, `okta.api_token`,
///   `"mailgunApiKey"`), unless its last segment is one of
///   [`NON_CREDENTIAL_KEY_SEGMENTS`]; or
/// - the key is a generic high-signal name (`api_key`, `auth_token`,
///   `secret`) and `line` also names one of `keywords`.
///
/// Context-gated detectors report such a value at high confidence. The name
/// is the same evidence `generic-token` already redacts at high confidence,
/// so without this the provider's own medium finding would lose the span to
/// the generic one, or leave it at `warn`. `keywords` are lowercase and
/// already in normalized form (`new_relic`, `newrelic`).
pub(super) fn is_provider_named_assignment(
    line: &str,
    value_start: usize,
    keywords: &[&str],
) -> bool {
    let Some(key) = assignment_key(line.as_bytes(), value_start) else {
        return false;
    };
    let Ok(key) = std::str::from_utf8(key) else {
        return false;
    };
    let normalized = super::generic_token::normalize_name(key);
    if normalized
        .rsplit('_')
        .next()
        .is_some_and(|segment| NON_CREDENTIAL_KEY_SEGMENTS.contains(&segment))
    {
        return false;
    }
    if keywords.iter().any(|keyword| normalized.contains(keyword)) {
        return true;
    }
    super::generic_token::is_high_signal_name(&normalized)
        && keywords.iter().any(|keyword| contains_ci(line, keyword))
}

// --- Keyed environment stores (issue #1038) ---------------------------------

/// Last callee segments that store `(name, value)` into an environment:
/// Python `os.environ.setdefault` and `os.putenv`, and `setenv`.
const ENV_STORE_CALLEES: &[&str] = &["setdefault", "putenv", "setenv"];

/// Most bytes between a value and the `[` or `(` that opens its keyed store
/// (`["` + a 128-byte name + `"] = "`).
const MAX_STORE_PREFIX: usize = 160;

/// A keyed-store prefix: the name span and the offset where the value
/// starts, which is its opening quote.
pub(super) struct StorePrefix {
    pub(super) name_start: usize,
    pub(super) name_end: usize,
    pub(super) value_start: usize,
    /// The prefix is a `(name, value)` call, where only a quoted literal
    /// value counts.
    pub(super) call: bool,
}

/// Parses a keyed store opening at byte `open` of `input` (issue #1038),
/// read as the assignment `NAME = <value>`:
///
/// - `<target>["NAME"] = ` (single quotes too): `os.environ["NAME"] =`,
///   `process.env['NAME'] =`, Ruby `ENV["NAME"] =`, `settings["api_key"] =`.
///   The `[` follows an identifier byte or a closing `)`/`]`, and the `=`
///   is not part of `==`.
/// - `<callee>("NAME", ` where the callee's last segment is one of
///   [`ENV_STORE_CALLEES`]: `os.environ.setdefault("NAME", `,
///   `os.putenv("NAME", `.
///
/// The name is `[A-Za-z_][A-Za-z0-9_.-]*`, at most 128 bytes, between
/// matching quotes. `value_start` must hold a quote for the caller to read
/// a literal; the prefix never crosses a line end.
pub(super) fn keyed_store_prefix(input: &str, open: usize) -> Option<StorePrefix> {
    let bytes = input.as_bytes();
    let call = match bytes.get(open)? {
        b'[' => {
            let target = *bytes.get(open.checked_sub(1)?)?;
            if !(target.is_ascii_alphanumeric() || matches!(target, b'_' | b')' | b']')) {
                return None;
            }
            false
        }
        b'(' => {
            let callee_end = open;
            let callee_start = callee_end
                - bytes[..callee_end]
                    .iter()
                    .rev()
                    .take_while(|&&byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    .count();
            if !ENV_STORE_CALLEES.contains(&&input[callee_start..callee_end]) {
                return None;
            }
            true
        }
        _ => return None,
    };
    let horizontal = |byte: u8| matches!(byte, b' ' | b'\t');
    let mut at = open + 1;
    if call {
        at += ascii_run_len(bytes, at, horizontal);
    }
    let quote = *bytes
        .get(at)
        .filter(|&&byte| matches!(byte, b'"' | b'\''))?;
    at += 1;
    let name_start = at;
    if !bytes
        .get(at)
        .is_some_and(|&byte| byte.is_ascii_alphabetic() || byte == b'_')
    {
        return None;
    }
    at += ascii_run_len(bytes, at, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
    });
    let name_end = at;
    if name_end - name_start > 128 || bytes.get(at) != Some(&quote) {
        return None;
    }
    at += 1;
    at += ascii_run_len(bytes, at, horizontal);
    if call {
        if bytes.get(at) != Some(&b',') {
            return None;
        }
        at += 1;
    } else {
        if bytes.get(at) != Some(&b']') {
            return None;
        }
        at += 1;
        at += ascii_run_len(bytes, at, horizontal);
        if bytes.get(at) != Some(&b'=') || bytes.get(at + 1) == Some(&b'=') {
            return None;
        }
        at += 1;
    }
    at += ascii_run_len(bytes, at, horizontal);
    Some(StorePrefix {
        name_start,
        name_end,
        value_start: at,
        call,
    })
}

/// The name of the keyed store (issue #1038, [`keyed_store_prefix`]) whose
/// quoted literal value opens at byte `value_start` of `line`, the byte
/// after the opening quote.
pub(super) fn keyed_store_name(line: &str, value_start: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    let quote_at = value_start.checked_sub(1)?;
    if !matches!(bytes.get(quote_at), Some(b'"' | b'\'')) {
        return None;
    }
    let floor = quote_at.saturating_sub(MAX_STORE_PREFIX);
    for open in (floor..quote_at).rev() {
        if !matches!(bytes[open], b'[' | b'(') {
            continue;
        }
        if let Some(prefix) = keyed_store_prefix(line, open)
            && prefix.value_start == quote_at
        {
            return Some(&line[prefix.name_start..prefix.name_end]);
        }
    }
    None
}

// --- YAML list-item `name:`/`value:` pairs (issue #1016) -------------------

/// One `key:` line of a YAML block sequence or mapping, as
/// [`list_item_paired_name`] reads it.
pub(super) struct ItemKeyLine<'a> {
    /// Byte column of the key within its line.
    pub(super) column: usize,
    /// The key follows the `- ` that opens a sequence item.
    pub(super) item_start: bool,
    pub(super) key: &'a str,
    /// Where the text after the `:` starts, within the line.
    pub(super) rest: usize,
}

/// Parses `^ *(- +)?[A-Za-z_][A-Za-z0-9_]*:( |\t|$)`: spaces only for the
/// indentation (YAML forbids tabs there), an optional sequence-item dash,
/// a plain key and its `:` indicator. A trailing `\r` counts as the line end.
pub(super) fn item_key_line(line: &str) -> Option<ItemKeyLine<'_>> {
    let bytes = line.as_bytes();
    let mut at = bytes.iter().take_while(|&&byte| byte == b' ').count();
    let mut item_start = false;
    if bytes.get(at) == Some(&b'-') && bytes.get(at + 1) == Some(&b' ') {
        item_start = true;
        at += 1;
        at += bytes[at..].iter().take_while(|&&byte| byte == b' ').count();
    }
    let column = at;
    if !bytes
        .get(at)
        .is_some_and(|&byte| byte.is_ascii_alphabetic() || byte == b'_')
    {
        return None;
    }
    at += bytes[at..]
        .iter()
        .take_while(|&&byte| byte.is_ascii_alphanumeric() || byte == b'_')
        .count();
    let key = &line[column..at];
    if bytes.get(at) != Some(&b':') {
        return None;
    }
    at += 1;
    match bytes.get(at) {
        None | Some(b' ' | b'\t' | b'\r') => Some(ItemKeyLine {
            column,
            item_start,
            key,
            rest: at,
        }),
        _ => None,
    }
}

/// The plain or quoted scalar after `name:` when it is a whole environment-
/// style name (`[A-Za-z_][A-Za-z0-9_.-]*`, at most 128 bytes), optionally
/// followed by a `#` comment.
pub(super) fn item_name_scalar(line: &str, rest: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut at = rest + ascii_run_len(bytes, rest, |byte| matches!(byte, b' ' | b'\t'));
    let quote = bytes
        .get(at)
        .copied()
        .filter(|&byte| matches!(byte, b'"' | b'\''));
    if quote.is_some() {
        at += 1;
    }
    let start = at;
    if !bytes
        .get(at)
        .is_some_and(|&byte| byte.is_ascii_alphabetic() || byte == b'_')
    {
        return None;
    }
    at += ascii_run_len(bytes, at, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
    });
    let end = at;
    if end - start > 128 {
        return None;
    }
    if let Some(quote) = quote {
        if bytes.get(at) != Some(&quote) {
            return None;
        }
        at += 1;
    }
    let tail = line[at..].trim_start_matches([' ', '\t']);
    (tail.is_empty() || tail == "\r" || tail.starts_with('#')).then_some(&line[start..end])
}

/// The line ([`lines`]) before the one starting at `line_start`.
pub(super) fn previous_line(input: &str, line_start: usize) -> Option<(usize, usize)> {
    if line_start == 0 {
        return None;
    }
    // A `\n` ends the previous line outside it; a lone `\r` stays in it.
    let end = if input.as_bytes()[line_start - 1] == b'\n' {
        line_start - 1
    } else {
        line_start
    };
    Some((line_start_before(input, end), end))
}

/// The line ([`lines`]) after the one ending at `line_end`.
fn next_line(input: &str, line_end: usize) -> Option<(usize, usize)> {
    let bytes = input.as_bytes();
    let start = match bytes.get(line_end) {
        Some(b'\n') => line_end + 1,
        // A lone `\r` ended the line inside it: the next one starts here.
        Some(_) if line_end > 0 && bytes[line_end - 1] == b'\r' => line_end,
        _ => return None,
    };
    Some((start, line_end_from(bytes, start).0.min(bytes.len())))
}

/// Issue #1016: the credential name a Kubernetes-style `env` entry gives
/// the value on `line` (a [`lines`] range), when that line is the
/// `value:` key of a YAML sequence item whose sibling `name:` key sits on
/// the adjacent line at the same key column:
///
/// ```yaml
/// env:
///   - name: DEEPGRAM_API_KEY
///     value: "..."
/// ```
///
/// Either order is read (`- value:` then `name:`), but only the two keys of
/// one item: exactly one of the two lines opens the item with `- `, the
/// other continues it, and nothing else sits between them. A later
/// unrelated key, a value on a separate item, another indentation, a flow
/// mapping (`- {name: A, value: b}`) or a JSON document are not paired.
/// `valueFrom:` is a different key and never pairs. The detectors read the
/// pair as the one-line assignment `<name>=<value>`, so every value
/// exclusion of that form still applies.
pub(super) fn list_item_paired_name(input: &str, line: (usize, usize)) -> Option<&str> {
    let value_line = item_key_line(&input[line.0..line.1])?;
    if value_line.key != "value" {
        return None;
    }
    let other = if value_line.item_start {
        next_line(input, line.1)?
    } else {
        previous_line(input, line.0)?
    };
    let other_text = &input[other.0..other.1];
    let name_line = item_key_line(other_text)?;
    (name_line.key == "name"
        && name_line.item_start != value_line.item_start
        && name_line.column == value_line.column)
        .then(|| item_name_scalar(other_text, name_line.rest))
        .flatten()
}

/// Internal retention hint for [`list_item_paired_name`] (issue #1016):
/// `true` when the last complete line of `input` opens a YAML sequence item
/// with a `name:` or `value:` key, so the incremental session holds it open
/// for the one following line that can complete the pair. Holding a line
/// that never pairs only delays its output by one line.
#[cfg(test)]
pub(crate) fn has_open_list_item_pair(input: &str) -> bool {
    has_open_list_item_pair_in(&super::lookback_tail(input))
}

/// [`has_open_list_item_pair`] over a [`super::lookback_tail`].
pub(crate) fn has_open_list_item_pair_in(tail: &[&str]) -> bool {
    tail_lines(tail, 1).first().is_some_and(|line| {
        item_key_line(line)
            .is_some_and(|parsed| parsed.item_start && matches!(parsed.key, "name" | "value"))
    })
}

#[cfg(test)]
mod provider_named_assignment_tests {
    use super::is_provider_named_assignment;

    const VALUE: &str = "SYNTHETIC_REVOKED_VALUE";

    fn value_start(line: &str) -> usize {
        line.find(VALUE).unwrap()
    }

    #[test]
    fn a_key_naming_the_provider_qualifies() {
        for line in [
            format!("MAILCHIMP_API_KEY={VALUE}"),
            format!("mailchimp.api_key: {VALUE}"),
            format!("{{\"mailchimpApiKey\": \"{VALUE}\"}}"),
            format!("export MAILCHIMP_KEY='{VALUE}'"),
        ] {
            assert!(
                is_provider_named_assignment(&line, value_start(&line), &["mailchimp"]),
                "{line}"
            );
        }
    }

    #[test]
    fn a_high_signal_key_on_a_line_naming_the_provider_qualifies() {
        let line = format!("mailchimp.setConfig({{ apiKey: \"{VALUE}\" }})");
        assert!(is_provider_named_assignment(
            &line,
            value_start(&line),
            &["mailchimp"]
        ));
    }

    #[test]
    fn identifier_keys_prose_and_other_keys_do_not_qualify() {
        for line in [
            format!("MAILCHIMP_LIST_ID={VALUE}"),
            format!("MAILCHIMP_SERVER_URL={VALUE}"),
            format!("# Mailchimp API key {VALUE}"),
            format!("list_id: {VALUE} # mailchimp"),
            format!("MAILCHIMP_API_KEY {VALUE}"),
            format!("SENDGRID_API_KEY={VALUE}"),
        ] {
            assert!(
                !is_provider_named_assignment(&line, value_start(&line), &["mailchimp"]),
                "{line}"
            );
        }
    }
}

#[cfg(test)]
mod line_tests {
    use super::{last_lines, line_around, lines};

    fn split(input: &str) -> Vec<&str> {
        lines(input)
            .map(|(start, end)| &input[start..end])
            .collect()
    }

    #[test]
    fn lines_end_at_a_newline_and_after_a_lone_carriage_return() {
        assert_eq!(split("a\nb"), ["a", "b"]);
        assert_eq!(split("a\r\nb\r\n"), ["a\r", "b\r", ""]);
        assert_eq!(split("a\rb\rc"), ["a\r", "b\r", "c"]);
        assert_eq!(split("a\r\rb"), ["a\r", "\r", "b"]);
        // A `\r` that ends the input stays in its line.
        assert_eq!(split("a\r"), ["a\r"]);
        assert_eq!(split(""), [""]);
    }

    /// Every string of up to six symbols over `a`, `\r`, `\n` and a
    /// three-byte code point, each also with a run of `a` in the middle so
    /// the terminators fall on both sides of the short-line walk's window.
    fn generated_inputs() -> Vec<String> {
        let alphabet = ["a", "\r", "\n", "\u{597D}"];
        let mut inputs = Vec::new();
        for len in 0..=6u32 {
            for mut code in 0..4usize.pow(len) {
                let mut symbols = Vec::new();
                for _ in 0..len {
                    symbols.push(alphabet[code % 4]);
                    code /= 4;
                }
                let (head, tail) = symbols.split_at(symbols.len() / 2);
                for padding in [0, 28, 31, 32, 33, 40] {
                    inputs.push(format!(
                        "{}{}{}",
                        head.concat(),
                        "a".repeat(padding),
                        tail.concat()
                    ));
                }
            }
        }
        inputs
    }

    #[test]
    fn lines_agree_with_the_byte_by_byte_line_end_over_generated_inputs() {
        for input in generated_inputs() {
            let mut expected = Vec::new();
            let mut start = 0;
            while start <= input.len() {
                let (end, next) = super::line_end_from(input.as_bytes(), start);
                expected.push((start, end));
                start = next;
            }
            assert_eq!(lines(&input).collect::<Vec<_>>(), expected, "{input:?}");
        }
    }

    #[test]
    fn the_last_lines_are_the_tail_of_lines_over_generated_inputs() {
        for input in generated_inputs() {
            let complete = input.strip_suffix('\n').unwrap_or(&input);
            let all = split(complete);
            for count in 1..=4 {
                let expected = &all[all.len().saturating_sub(count)..];
                assert_eq!(last_lines(&input, count), expected, "{input:?} {count}");
            }
        }
    }

    #[test]
    fn every_hint_window_of_the_shared_lookback_tail_is_its_own_last_lines() {
        // Issue #1060: the session computes one tail and each lookback hint
        // reads its own window of it.
        for input in generated_inputs() {
            let tail = crate::detectors::lookback_tail(&input);
            for count in 1..=super::super::MAX_LOOKBACK_LINES {
                assert_eq!(
                    super::tail_lines(&tail, count),
                    last_lines(&input, count),
                    "{input:?} {count}"
                );
            }
        }
    }

    #[test]
    fn the_line_around_a_span_is_the_line_that_holds_it() {
        let input = "x\ra \"k\" b\r\ny";
        let at = input.find("\"k\"").unwrap();
        let (start, end) = line_around(input, at, at + 3);
        assert_eq!(&input[start..end], "a \"k\" b\r");
    }
}

#[cfg(test)]
mod list_item_pair_tests {
    use super::{has_open_list_item_pair, lines, list_item_paired_name};

    /// The paired name for the last non-empty line of `input`.
    fn paired(input: &str) -> Option<&str> {
        let line = lines(input)
            .filter(|&(start, end)| start < end && !input[start..end].trim().is_empty())
            .last()?;
        list_item_paired_name(input, line)
    }

    #[test]
    fn the_value_key_pairs_with_the_adjacent_name_of_its_item() {
        assert_eq!(
            paired("  - name: API_TOKEN\n    value: x\n"),
            Some("API_TOKEN")
        );
        assert_eq!(
            paired("- name: 'CO_API_KEY'\r\n  value: x\r\n"),
            Some("CO_API_KEY")
        );
        assert_eq!(paired("- name: A\r  value: x\r"), Some("A"));
        let reverse = "- value: x\n  name: B # c\n";
        assert_eq!(list_item_paired_name(reverse, (0, 10)), Some("B"));
    }

    #[test]
    fn anything_but_the_two_keys_of_one_item_is_not_a_pair() {
        for input in [
            "- name: A\n- value: x\n",
            "- name: A\n    value: x\n",
            "- name: A\n  image: b\n  value: x\n",
            "name: A\nvalue: x\n",
            "- {name: A, value: x}\n",
            "- name: A\n  valueFrom: x\n",
            "- name: two words\n  value: x\n",
            "- name: A\n\t value: x\n",
        ] {
            assert_eq!(paired(input), None, "{input:?}");
        }
    }

    #[test]
    fn the_retention_hint_holds_exactly_an_item_opening_name_or_value_line() {
        for open in [
            "- name: A\n",
            "env:\n  - name: A\n",
            "  - value: x\r\n",
            "- name: A\r",
        ] {
            assert!(has_open_list_item_pair(open), "{open:?}");
        }
        for closed in [
            "",
            "- name: A\n  value: x\n",
            "- name: A\n\n",
            "  name: A\n",
            "- image: A\n",
            "- {name: A}\n",
        ] {
            assert!(!has_open_list_item_pair(closed), "{closed:?}");
        }
    }
}

#[cfg(test)]
mod keyed_store_tests {
    use super::{keyed_store_name, keyed_store_prefix};

    #[test]
    fn subscript_and_call_stores_name_their_value() {
        let line = "os.environ[\"API_TOKEN\"] = \"v\"";
        let prefix = keyed_store_prefix(line, 10).unwrap();
        assert_eq!(&line[prefix.name_start..prefix.name_end], "API_TOKEN");
        assert_eq!(prefix.value_start, line.len() - 3);
        assert!(!prefix.call);
        assert_eq!(keyed_store_name(line, line.len() - 2), Some("API_TOKEN"));
        let call = "os.putenv( 'API_TOKEN' , 'v')";
        assert_eq!(keyed_store_name(call, call.len() - 3), Some("API_TOKEN"));
        assert!(keyed_store_prefix(call, 9).unwrap().call);
    }

    #[test]
    fn comparisons_reads_and_other_callees_are_not_stores() {
        for (line, open) in [
            ("x[\"A\"] == \"v\"", 1),
            ("x[\"A\"]", 1),
            (" [\"A\"] = \"v\"", 1),
            ("x[A] = \"v\"", 1),
            ("x[\"A'] = \"v\"", 1),
            ("x[\"1A\"] = \"v\"", 1),
            ("get(\"A\", \"v\")", 3),
            ("setdefault(\"A\" \"v\")", 10),
        ] {
            assert!(keyed_store_prefix(line, open).is_none(), "{line}");
        }
        assert_eq!(keyed_store_name("x = \"v\"", 5), None);
    }
}

#[cfg(test)]
mod find_ci_tests {
    use super::{contains_ci, find_ci, starts_with_ci};

    /// The pre-#1073 per-offset scan every detector used to carry.
    fn find_oracle(haystack: &str, from: usize, needle: &str) -> Option<usize> {
        let len = haystack.len();
        if needle.len() > len {
            return None;
        }
        (from..=len - needle.len()).find(|&pos| starts_with_ci(haystack, pos, needle))
    }

    #[test]
    fn find_ci_equals_the_per_offset_oracle_on_random_and_boundary_inputs() {
        let pieces = [
            "a",
            "K",
            "e",
            "y",
            "KEY",
            "api",
            "Token",
            "tOkEn",
            "twilio",
            "TWILIO",
            "-",
            "_",
            " ",
            "\u{e9}",
            "\u{1F511}",
            "\n",
            "0",
            "\u{212A}",
            "secret",
        ];
        let needles = [
            "key",
            "token",
            "twilio",
            "api-key",
            "secret",
            "a",
            "k",
            "0",
            "dd-app-key",
            "-x",
            "",
        ];
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize
        };
        for _ in 0..4000 {
            let mut input = String::new();
            for _ in 0..next() % 40 {
                input.push_str(pieces[next() % pieces.len()]);
            }
            for needle in needles {
                let from = if input.is_empty() {
                    0
                } else {
                    next() % (input.len() + 1)
                };
                assert_eq!(
                    find_ci(input.as_bytes(), from, needle.as_bytes()),
                    find_oracle(&input, from, needle),
                    "{input:?} {needle:?} {from}"
                );
                assert_eq!(
                    contains_ci(&input, needle),
                    find_oracle(&input, 0, needle).is_some()
                );
            }
        }
    }

    #[test]
    fn find_ci_handles_short_empty_and_out_of_range_inputs() {
        assert_eq!(find_ci(b"", 0, b"key"), None);
        assert_eq!(find_ci(b"", 0, b""), Some(0));
        assert_eq!(find_ci(b"ab", 5, b"a"), None);
        assert_eq!(find_ci(b"xxxxxxxxxxxxxxxKEY", 0, b"key"), Some(15));
        assert_eq!(find_ci(b"xxxxxxxxxxxxxxxKE", 0, b"key"), None);
    }
}
