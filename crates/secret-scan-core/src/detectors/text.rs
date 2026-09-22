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

/// opencode config substitution kinds resolved from the environment or a
/// file at load time rather than containing a secret directly.
pub(super) const OPENCODE_REFERENCE_KINDS: &[&str] = &["env", "file"];

/// `true` for an opencode `{env:VAR}` or `{file:path}` substitution.
pub(super) fn is_opencode_reference(value: &str) -> bool {
    OPENCODE_REFERENCE_KINDS.iter().any(|kind| {
        let open = format!("{{{kind}:");
        is_fully_delimited(value, &open, "}")
    })
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
