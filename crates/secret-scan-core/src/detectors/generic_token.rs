//! Contextual assignment and structural `Basic`/`Token` authorization
//! detector.
//!
//! Combines explicit credential names or authorization syntax with bounded
//! entropy. A plain `token` name and entropy-only text intentionally produce
//! no candidates. Values above 4 KiB are left to more specific detectors.

use super::text::{
    ascii_run_len, char_at, ends_with_ci, is_horizontal_js_whitespace, is_js_whitespace,
    is_line_start, is_repeated_character_filler, matches_placeholder_vocabulary, prev_char,
    rskip_while_chars, skip_while_chars, starts_with_ci,
};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const HIGH_SIGNAL_NAMES: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "access_token",
    "refresh_token",
    "session_token",
    "aws_secret_access_key",
    "aws_session_token",
    "password",
    "passwd",
    "private_key",
    "client_secret",
    "webhook_secret",
];

const AMBIGUOUS_NAMES: &[&str] = &[
    "auth",
    "auth_token",
    "credential",
    "credentials",
    "signing_key",
];

const MIN_CONTEXT_VALUE_LENGTH: usize = 8;
const MIN_HIGH_ENTROPY_LENGTH: usize = 16;
const HIGH_ENTROPY_THRESHOLD: f64 = 3.0;
const AMBIGUOUS_ENTROPY_THRESHOLD: f64 = 3.5;
const MAX_CONTEXT_VALUE_LENGTH: usize = 4_096;
const MIN_AUTHORIZATION_VALUE_LENGTH: usize = 12;

// --- name normalization -----------------------------------------------

/// Mirrors `name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().replace(/[.-]/g, "_")`.
///
/// Capture names are `[A-Za-z][A-Za-z0-9_.-]*`, so this operates on ASCII
/// bytes only.
fn normalize_name(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = String::with_capacity(name.len() + 4);
    for (index, &byte) in bytes.iter().enumerate() {
        if index > 0 {
            let previous = bytes[index - 1];
            let previous_is_lower_or_digit =
                previous.is_ascii_lowercase() || previous.is_ascii_digit();
            if previous_is_lower_or_digit && byte.is_ascii_uppercase() {
                out.push('_');
            }
        }
        out.push(match byte {
            b'.' | b'-' => '_',
            other => other.to_ascii_lowercase() as char,
        });
    }
    out
}

fn is_open_assignment_boundary_char(ch: char) -> bool {
    is_js_whitespace(ch) || matches!(ch, '{' | ',' | ';')
}

/// Internal retention hint for the built-in incremental scanner: `true` when
/// the tail of `input` still looks like an in-progress contextual assignment
/// whose name is high-signal or ambiguous, so a caller should keep holding
/// the line open in case a bounded-entropy value follows. Mirrors
/// `hasOpenContextualAssignment` in `src/detectors/generic-token.ts`
/// (`decision-govern-cross-language-conformance`).
///
/// Unlike `ASSIGNMENT_PREFIX_PATTERN`'s multiline `^`, the boundary
/// alternation here has no `m` flag in the TypeScript oracle: `^` anchors to
/// the absolute start of `input`, which is exactly byte offset `0` of the
/// slice this function receives.
pub(crate) fn has_open_contextual_assignment(input: &str) -> bool {
    let mut end = rskip_while_chars(input, input.len(), is_js_whitespace);

    if let Some(ch) = prev_char(input, end)
        && (ch == '=' || ch == ':')
    {
        end -= ch.len_utf8();
        end = rskip_while_chars(input, end, is_js_whitespace);
    }

    if let Some(ch @ ('"' | '\'')) = prev_char(input, end) {
        end -= ch.len_utf8();
    }

    let name_end = end;
    let mut name_start = end;
    while let Some(ch) = prev_char(input, name_start) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            name_start -= ch.len_utf8();
        } else {
            break;
        }
    }
    if name_start == name_end {
        return false;
    }
    let Some(first) = char_at(input, name_start) else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }

    let mut boundary_pos = name_start;
    if let Some(ch @ ('"' | '\'')) = prev_char(input, boundary_pos) {
        boundary_pos -= ch.len_utf8();
    }
    let boundary_ok = boundary_pos == 0
        || prev_char(input, boundary_pos).is_some_and(is_open_assignment_boundary_char);
    if !boundary_ok {
        return false;
    }

    let normalized = normalize_name(&input[name_start..name_end]);
    HIGH_SIGNAL_NAMES.contains(&normalized.as_str())
        || AMBIGUOUS_NAMES.contains(&normalized.as_str())
}

// --- non-secret reference exclusions -----------------------------------

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

/// The subset of [`PLACEHOLDER_WORDS`] distinctive enough to tolerate an
/// appended digit (`changeme2`) without also swallowing common real (if
/// weak) credentials like `password1` or `secret01` — see
/// `matches_placeholder_vocabulary`'s doc comment.
const DIGIT_SUFFIX_PLACEHOLDER_WORDS: &[&str] = &[
    "example",
    "sample",
    "placeholder",
    "redacted",
    "changeme",
    "replaceme",
];

fn is_generic_placeholder_word(value: &str) -> bool {
    matches_placeholder_vocabulary(value, PLACEHOLDER_WORDS, DIGIT_SUFFIX_PLACEHOLDER_WORDS)
}

fn is_boolean_null_or_digits(lower: &str) -> bool {
    matches!(lower, "true" | "false" | "null" | "undefined")
        || (!lower.is_empty() && lower.bytes().all(|byte| byte.is_ascii_digit()))
}

fn starts_with_env_reference(value: &str) -> bool {
    if value.starts_with("${") {
        return true;
    }
    if value.as_bytes().first() == Some(&b'$')
        && let Some(second) = char_at(value, 1)
        && (second.is_ascii_alphabetic() || second == '_')
    {
        return true;
    }
    starts_with_ci(value, 0, "process.env.") || starts_with_ci(value, 0, "import.meta.env.")
}

/// `true` for a value starting with `<` followed by at least one non-`>`
/// byte and then a `>` (`^<[^>]+>`).
fn starts_with_angle_bracket_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'<') {
        return false;
    }
    matches!(bytes[1..].iter().position(|&byte| byte == b'>'), Some(index) if index > 0)
}

fn starts_with_path_like(value: &str) -> bool {
    starts_with_angle_bracket_reference(value)
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
}

fn ends_with_key_or_pem(value: &str) -> bool {
    ends_with_ci(value, ".key") || ends_with_ci(value, ".pem")
}

/// `true` when the whole value is delimited by `{{` and `}}`
/// (`^\{\{.*\}\}$`) — the idiomatic Jinja/Helm/Go-template reference syntax
/// Ansible, Helm, Salt, and Go templates use for a vaulted or injected
/// value (`{{ vault_db_password }}`, `{{ .Values.postgresql.auth.password }}`).
/// A value that only starts with `{{`, or that carries `{{...}}` inside a
/// larger string, does not satisfy this and stays detected: only a value
/// fully bounded by the delimiters is a bare reference rather than
/// suspicious content the delimiters happen to appear in.
fn is_template_reference(value: &str) -> bool {
    value.starts_with("{{") && value.ends_with("}}") && value.len() >= 4
}

fn is_non_secret_reference(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    is_generic_placeholder_word(&lower)
        || is_boolean_null_or_digits(&lower)
        || starts_with_env_reference(value)
        || starts_with_path_like(value)
        || ends_with_key_or_pem(value)
        || is_template_reference(value)
        || is_repeated_character_filler(value)
}

// --- confidence -----------------------------------------------------------

fn assignment_confidence(name: &str, value: &str) -> Option<Confidence> {
    if value.len() < MIN_CONTEXT_VALUE_LENGTH
        || value.len() > MAX_CONTEXT_VALUE_LENGTH
        || is_non_secret_reference(value)
    {
        return None;
    }

    let entropy = crate::shannon_entropy(value);
    if HIGH_SIGNAL_NAMES.contains(&name) {
        return Some(
            if value.len() >= MIN_HIGH_ENTROPY_LENGTH && entropy >= HIGH_ENTROPY_THRESHOLD {
                Confidence::High
            } else {
                Confidence::Medium
            },
        );
    }

    if AMBIGUOUS_NAMES.contains(&name)
        && value.len() >= MIN_HIGH_ENTROPY_LENGTH
        && entropy >= AMBIGUOUS_ENTROPY_THRESHOLD
    {
        return Some(Confidence::Medium);
    }

    None
}

// --- assignment value spans ------------------------------------------------

fn is_quoted_value_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => matches!(
            c,
            ' ' | '\t' | '\u{0B}' | '\u{0C}' | '\r' | '\n' | ',' | ';' | '}' | ']'
        ),
    }
}

fn is_unquoted_value_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => matches!(
            c,
            ' ' | '\t' | '\u{0B}' | '\u{0C}' | '\r' | '\n' | ',' | ';' | '}' | ']' | '"' | '\''
        ),
    }
}

/// Scans a `"..."` or `'...'` value starting at the opening quote, honoring
/// backslash-escaped quotes by parity, and returns its interior span.
/// Rejects values that cross a physical line or exceed the shared bound.
fn quoted_assignment_value(input: &str, opening_quote: usize) -> Option<(usize, usize)> {
    let quote = char_at(input, opening_quote)?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let start = opening_quote + quote.len_utf8();
    let mut cursor = start;
    let mut backslash_run: u32 = 0;

    while let Some(ch) = char_at(input, cursor) {
        if ch == '\r' || ch == '\n' {
            return None;
        }
        if cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
        if ch == '\\' {
            backslash_run += 1;
            cursor += ch.len_utf8();
            continue;
        }
        if ch == quote && backslash_run.is_multiple_of(2) {
            let after = char_at(input, cursor + ch.len_utf8());
            return is_quoted_value_boundary(after).then_some((start, cursor));
        }
        backslash_run = 0;
        cursor += ch.len_utf8();
    }
    None
}

/// Scans an unquoted value up to the next boundary character, rejecting
/// values that exceed the shared bound.
fn unquoted_assignment_value(input: &str, start: usize) -> Option<(usize, usize)> {
    let mut cursor = start;
    while let Some(ch) = char_at(input, cursor) {
        if is_unquoted_value_boundary(Some(ch)) {
            break;
        }
        cursor += ch.len_utf8();
        if cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
    }
    (cursor > start).then_some((start, cursor))
}

fn assignment_value(input: &str, start: usize) -> Option<(usize, usize)> {
    match char_at(input, start) {
        Some('"' | '\'') => quoted_assignment_value(input, start),
        _ => unquoted_assignment_value(input, start),
    }
}

// --- `ASSIGNMENT_PREFIX_PATTERN`: (?:^|[\s{,;])["']?([A-Za-z][A-Za-z0-9_.-]*)["']?\s*(?:=|:)\s* ---

fn is_prefix_boundary_char(ch: char) -> bool {
    is_js_whitespace(ch) || matches!(ch, '{' | ',' | ';')
}

/// Parses `["']?([A-Za-z][A-Za-z0-9_.-]*)["']?\s*(?:=|:)\s*` starting at
/// `start`, returning the captured name span and the offset right after the
/// trailing whitespace.
///
/// The optional quotes are pure lookahead in effect: a quote character can
/// never satisfy `[A-Za-z]`, so greedily consuming an optional quote when
/// present never forecloses a match that skipping it would have found.
///
/// The `\s*` run after the operator stops at a line terminator instead of
/// crossing it, unlike the ECMAScript oracle's `\s` class (and unlike the
/// `\s*` run before the operator, which is unchanged: a name legitimately
/// arrives on one physical line and its operator on the next when an
/// incremental caller's chunk boundary falls between them). A value belongs
/// on the operator's own line, so a key with no value before end-of-line
/// (`secret:\n  nested: ...`, an interactive `Password:\n` prompt) never
/// walks onto the next line's first token as if it were the value. See
/// `docs/decisions/2026-09-15-contextual-assignment-stops-at-the-line.md`.
fn parse_name_and_operator(input: &str, start: usize) -> Option<(usize, usize, usize)> {
    let mut cursor = start;
    if let Some(ch @ ('"' | '\'')) = char_at(input, cursor) {
        cursor += ch.len_utf8();
    }

    let name_start = cursor;
    let first = char_at(input, cursor)?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    cursor += 1;
    while let Some(ch) = char_at(input, cursor) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            cursor += 1;
        } else {
            break;
        }
    }
    let name_end = cursor;

    if let Some(ch @ ('"' | '\'')) = char_at(input, cursor) {
        cursor += ch.len_utf8();
    }
    cursor = skip_while_chars(input, cursor, is_js_whitespace);
    match char_at(input, cursor) {
        Some('=' | ':') => cursor += 1,
        _ => return None,
    }
    cursor = skip_while_chars(input, cursor, is_horizontal_js_whitespace);

    Some((name_start, name_end, cursor))
}

/// Tries the `(?:^|[\s{,;])` prefix alternative at `pos` (line start first,
/// per regex alternation order) followed by the rest of the pattern.
fn try_match_assignment_prefix(input: &str, pos: usize) -> Option<(usize, usize, usize)> {
    if is_line_start(input, pos)
        && let Some(m) = parse_name_and_operator(input, pos)
    {
        return Some(m);
    }
    let ch = char_at(input, pos)?;
    if is_prefix_boundary_char(ch) {
        return parse_name_and_operator(input, pos + ch.len_utf8());
    }
    None
}

fn assignment_candidates(input: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut cursor = 0usize;

    while cursor < input.len() {
        let Some((name_start, name_end, prefix_end)) = try_match_assignment_prefix(input, cursor)
        else {
            cursor += char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        };

        if let Some((value_start, value_end)) = assignment_value(input, prefix_end) {
            let value = &input[value_start..value_end];
            let normalized = normalize_name(&input[name_start..name_end]);
            if let Some(confidence) = assignment_confidence(&normalized, value)
                && let Some(range) = ByteRange::new(value_start, value_end)
            {
                let name_signal = if HIGH_SIGNAL_NAMES.contains(&normalized.as_str()) {
                    "high-signal-name"
                } else {
                    "ambiguous-name"
                };
                let entropy_signal = if confidence == Confidence::High {
                    "bounded-entropy"
                } else {
                    "context-only"
                };
                candidates.push(
                    Candidate::new("contextual_secret", confidence, range)
                        .with_specificity(Specificity::Contextual)
                        .with_signals([name_signal, entropy_signal]),
                );
            }
        }

        cursor = prefix_end;
    }

    candidates
}

// --- `AUTHORIZATION_PATTERN`: (?:^|[\r\n])[ \t]*authorization[ \t]*:[ \t]*(basic|token)[ \t]+([A-Za-z0-9+/=_-]{12,}) ---

fn is_space_or_tab_byte(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn is_authorization_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
}

struct AuthorizationMatch {
    scheme: &'static str,
    value_start: usize,
    value_end: usize,
}

fn parse_authorization_from(input: &str, start: usize) -> Option<AuthorizationMatch> {
    let bytes = input.as_bytes();
    let mut cursor = start + ascii_run_len(bytes, start, is_space_or_tab_byte);
    if !starts_with_ci(input, cursor, "authorization") {
        return None;
    }
    cursor += "authorization".len();
    cursor += ascii_run_len(bytes, cursor, is_space_or_tab_byte);
    if bytes.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    cursor += ascii_run_len(bytes, cursor, is_space_or_tab_byte);

    let scheme = if starts_with_ci(input, cursor, "basic") {
        cursor += "basic".len();
        "basic"
    } else if starts_with_ci(input, cursor, "token") {
        cursor += "token".len();
        "token"
    } else {
        return None;
    };

    let ws_len = ascii_run_len(bytes, cursor, is_space_or_tab_byte);
    if ws_len == 0 {
        return None;
    }
    let value_start = cursor + ws_len;
    let value_len = ascii_run_len(bytes, value_start, is_authorization_value_byte);
    if value_len < MIN_AUTHORIZATION_VALUE_LENGTH {
        return None;
    }

    Some(AuthorizationMatch {
        scheme,
        value_start,
        value_end: value_start + value_len,
    })
}

fn try_match_authorization_at(input: &str, pos: usize) -> Option<AuthorizationMatch> {
    if is_line_start(input, pos)
        && let Some(m) = parse_authorization_from(input, pos)
    {
        return Some(m);
    }
    match char_at(input, pos) {
        Some(ch @ ('\r' | '\n')) => parse_authorization_from(input, pos + ch.len_utf8()),
        _ => None,
    }
}

fn authorization_candidates(input: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut cursor = 0usize;

    while cursor < input.len() {
        let Some(m) = try_match_authorization_at(input, cursor) else {
            cursor += char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        };

        let value = &input[m.value_start..m.value_end];
        if !is_non_secret_reference(value)
            && let Some(range) = ByteRange::new(m.value_start, m.value_end)
        {
            let confidence = if value.len() >= MIN_HIGH_ENTROPY_LENGTH
                && crate::shannon_entropy(value) >= HIGH_ENTROPY_THRESHOLD
            {
                Confidence::High
            } else {
                Confidence::Medium
            };
            candidates.push(
                Candidate::new("authorization_credential", confidence, range)
                    .with_specificity(Specificity::Structural)
                    .with_signals([format!("authorization-{}-scheme", m.scheme)]),
            );
        }

        cursor = m.value_end.max(cursor + 1);
    }

    candidates
}

struct GenericTokenDetector;

impl Detector for GenericTokenDetector {
    fn id(&self) -> &'static str {
        "generic-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = assignment_candidates(input);
        candidates.extend(authorization_candidates(input));
        Ok(candidates)
    }
}

/// The contextual assignment and `Basic`/`Token` authorization detector.
#[must_use]
pub fn generic_token_detector() -> Box<dyn Detector> {
    Box::new(GenericTokenDetector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        GenericTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn only_range(candidates: &[Candidate]) -> (usize, usize) {
        assert_eq!(candidates.len(), 1);
        (candidates[0].range().start(), candidates[0].range().end())
    }

    #[test]
    fn nested_assignments_emit_overlapping_contextual_candidates() {
        let input = "client_secret=\"SYNTHETIC_REVOKED_OUTER_MARKER; api_key=SYNTHETIC_REVOKED_CONTEXT_OVERLAP_1234\"";
        let candidates = detect(input);

        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.type_name() == "contextual_secret")
        );
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].range(), ByteRange::new(15, 93).unwrap());
        assert_eq!(candidates[1].confidence(), Confidence::High);
        assert_eq!(candidates[1].range(), ByteRange::new(55, 93).unwrap());
        assert!(candidates[0].range().overlaps(candidates[1].range()));
    }

    #[test]
    fn high_signal_assignment_with_bounded_entropy_is_high_confidence() {
        let input = "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (8, input.len()));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    #[test]
    fn escaped_quote_stays_inside_one_structured_value_span() {
        let input = "{\"api_key\":\"SYNTHETIC_REVOKED_\\\"QUOTED_VALUE\"}";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (12, 44));
    }

    #[test]
    fn documented_aws_secret_access_key_name_is_high_signal() {
        let input = "AWS_SECRET_ACCESS_KEY=SYNTHETIC_REVOKED_AWS_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (22, 57));
    }

    #[test]
    fn documented_aws_session_token_name_is_high_signal() {
        let input = "aws_session_token=SYNTHETIC_REVOKED_AWS_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (18, 53));
    }

    #[test]
    fn generic_token_name_is_an_explicit_exclusion() {
        assert!(detect("token=SYNTHETIC_REVOKED_CONTEXT_VALUE").is_empty());
    }

    #[test]
    fn value_below_the_minimum_length_is_ignored() {
        assert!(detect("api_key=abcdefg").is_empty());
    }

    #[test]
    fn value_above_the_detector_bound_is_ignored_deterministically() {
        let input = format!("api_key={}", "A".repeat(100_008));
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn common_high_entropy_or_identifier_like_values_stay_unchanged() {
        for input in [
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "checksum=9e107d9d372bb6826bd81d3542a419d6",
            "550e8400-e29b-41d4-a716-446655440000",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "request_01_SYNTHETIC_GENERATED_IDENTIFIER_987654321",
            "styles.module.css?hash=7f3a9c2d1e",
            "//# sourceMappingURL=app.7f3a9c2d1e.js.map",
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
            "header.payload.signature",
            "sha512-SYNTHETICPACKAGEINTEGRITYBASE64VALUE==",
            "model=gpt-5.6-codex-2026-08-31",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_bounded_entropy_value_never_overrides_an_unrecognized_name() {
        for input in [
            "id=SYNTHETIC_UNQUALIFIED_HIGH_ENTROPY_VALUE",
            "note=SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "Reminder: SYNTHETIC_REVOKED_CONTEXT_VALUE was already rotated last week.",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn additional_placeholder_words_are_excluded_at_the_minimum_length() {
        for input in ["webhook_secret=redacted", "client_secret=replaceme"] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    // --- issue #264: masked values are excluded as repeated-character
    // filler, the same exclusion #256 gave the connection-string detector.

    #[test]
    fn masked_values_are_excluded_as_repeated_character_filler() {
        for input in ["Password: ********", "Password: \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}"] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_near_miss_of_repeated_character_filler_is_still_detected() {
        // A trailing, distinct character breaks the uniform run.
        assert!(!detect("Password: ********x").is_empty());
    }

    // --- issue #257: placeholder-word exclusion is exact-string equality --
    //
    // `is_generic_placeholder_word` used to require the whole value to equal
    // one listed word. `matches_placeholder_vocabulary` (super::text) closes
    // the trivial lexical variants below while still requiring every token
    // in the value to reduce to a listed word, so a listed word merely
    // embedded in a larger, unrelated value is not swept in for free (see
    // `a_placeholder_word_embedded_in_a_larger_high_entropy_value_is_still_detected`
    // below).

    #[test]
    fn a_leading_separator_inside_the_value_does_not_defeat_the_exclusion() {
        assert!(detect("secret=\" changeme\"").is_empty());
    }

    #[test]
    fn an_appended_digit_does_not_defeat_the_exclusion() {
        assert!(detect("secret_key=\"changeme2\"").is_empty());
    }

    #[test]
    fn hyphenating_two_listed_words_does_not_defeat_the_exclusion() {
        // The issue's own reproduction hyphenates three words
        // (`REDACTED-EXAMPLE-VALUE`); `value` is not itself a listed
        // placeholder word, so it is dropped here per the issue's "or the
        // maintainers' chosen equivalent minimal set" allowance -- every
        // token in the value must reduce to a listed word, which keeps a
        // value like `secret-CFj9...` (a real high-entropy secret hyphenated
        // after an unrelated leading word) from being excluded for free.
        assert!(detect("secret_key: \"REDACTED-EXAMPLE\"").is_empty());
    }

    #[test]
    fn a_placeholder_word_embedded_in_a_larger_high_entropy_value_is_still_detected() {
        let input = "api_key=SecretSyntheticRevokedContextValue9fQ";
        assert!(
            !detect(input).is_empty(),
            "expected a finding for {input:?}"
        );
    }

    #[test]
    fn a_listed_word_followed_by_unrelated_tokens_is_still_detected() {
        // Same shape as the hyphenation bypass above, but the extra token
        // (`over`, `there`) is not itself a listed word, so the value must
        // not be excluded -- a token-boundary fix must not degrade into
        // "any token is a listed word".
        assert!(!detect("client_secret=password_over_there").is_empty());
    }

    #[test]
    fn documented_aws_names_retain_classification_with_a_colon_separator_and_quoting() {
        let input = "AWS_SECRET_ACCESS_KEY: \"SYNTHETIC_REVOKED_AWS_CONTEXT_VALUE\"";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (24, 59));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    #[test]
    fn basic_and_token_authorization_schemes_are_detected() {
        let basic_input = "Authorization: Basic U1lOVEhFVElDX1JFVk9LRUQ=";
        let basic = detect(basic_input);
        let (start, end) = only_range(&basic);
        assert_eq!(&basic_input[start..end], "U1lOVEhFVElDX1JFVk9LRUQ=");
        assert_eq!(basic[0].type_name(), "authorization_credential");
        assert_eq!(basic[0].confidence(), Confidence::High);
        assert_eq!(basic[0].specificity(), Some(Specificity::Structural));

        let token_input = "Authorization: Token SYNTHETIC_REVOKED_TOKEN_VALUE_1234";
        let token = detect(token_input);
        let (start, end) = only_range(&token);
        assert_eq!(
            &token_input[start..end],
            "SYNTHETIC_REVOKED_TOKEN_VALUE_1234"
        );
        assert_eq!(token[0].type_name(), "authorization_credential");
        assert_eq!(token[0].confidence(), Confidence::High);
        assert_eq!(token[0].specificity(), Some(Specificity::Structural));
    }

    #[test]
    fn token_authorization_and_nested_assignment_emit_overlapping_candidates() {
        let input = "Authorization: Token api_key=SYNTHETIC_REVOKED_AUTHORIZATION_OVERLAP_1234";
        let candidates = detect(input);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].type_name(), "contextual_secret");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
        assert_eq!(candidates[0].range(), ByteRange::new(29, 73).unwrap());
        assert_eq!(candidates[1].type_name(), "authorization_credential");
        assert_eq!(candidates[1].confidence(), Confidence::High);
        assert_eq!(candidates[1].specificity(), Some(Specificity::Structural));
        assert_eq!(candidates[1].range(), ByteRange::new(21, 73).unwrap());
        assert!(candidates[0].range().overlaps(candidates[1].range()));
    }

    #[test]
    fn authorization_value_at_the_minimum_accepted_length_is_medium_confidence() {
        let input = "Authorization: Token TOKENVALUE12";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "TOKENVALUE12");
        assert_eq!(candidates[0].type_name(), "authorization_credential");
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Structural));
    }

    #[test]
    fn authorization_value_below_the_minimum_accepted_length_is_ignored() {
        assert!(detect("Authorization: Basic short-value").is_empty());
    }

    #[test]
    fn authorization_scheme_other_than_basic_or_token_is_ignored() {
        assert!(detect("Authorization: Digest SYNTHETIC_REVOKED_DIGEST_VALUE_1234").is_empty());
    }

    // --- issue #263: a value fully delimited by `{{ ... }}` is a template
    // reference (Ansible/Helm/Salt Jinja, Go templates), not a secret -------

    #[test]
    fn a_quoted_jinja_template_reference_is_excluded() {
        for input in [
            "password: \"{{ vault_db_password }}\"",
            "password: \"{{ lookup('env', 'DB_PASSWORD') }}\"",
            "password: '{{ pillar[\"postgres\"][\"password\"] }}'",
            "\"password\": \"{{ vault_db_password }}\"",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_quoted_helm_or_go_template_reference_is_excluded() {
        for input in [
            "password: \"{{ .Values.postgresql.auth.password }}\"",
            "client_secret: \"{{ .ClientSecretRef }}\"",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_value_only_starting_with_a_template_delimiter_is_still_detected() {
        let input = "password=\"{{ SYNTHETIC_REVOKED_CONTEXT_VALUE\"";
        assert!(
            !detect(input).is_empty(),
            "expected a finding for {input:?}"
        );
    }

    #[test]
    fn a_template_delimiter_pair_embedded_in_a_larger_value_is_still_detected() {
        let input = "password=SYNTHETIC_REVOKED_{{ x }}_CONTEXT_VALUE";
        assert!(
            !detect(input).is_empty(),
            "expected a finding for {input:?}"
        );
    }

    // --- issue #262: a contextual-assignment operator with no value before
    // end-of-line does not cross into the next physical line ---------------

    #[test]
    fn operator_with_no_value_before_end_of_line_does_not_cross_into_the_next_line() {
        for input in [
            // A Kubernetes-style YAML key opening a nested mapping.
            "secret:\n  secretName: web-tls-cert",
            // An interactive prompt with no value at all.
            "Password:\nPermission denied, please try again.",
            // An ssh transcript: prompt line, then the program's own denial.
            "fixture@db.example.test's password:\nfixture@db.example.test: Permission denied (publickey,password).",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn password_value_on_the_same_line_is_still_detected() {
        let input = "password: SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    /// The paired recall regression (issue #265): the outer `database:`
    /// key's failed value scan used to advance the cursor past the nested
    /// `password:` key's own boundary character, so it was never matched.
    #[test]
    fn a_nested_credential_under_an_unrelated_parent_key_is_still_detected() {
        let input = "database:\n  password: SYNTHETIC_REVOKED_FIXTURE_VALUE";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_FIXTURE_VALUE");
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn open_contextual_assignment_hint_recognizes_a_pending_high_signal_or_ambiguous_name() {
        for open in [
            "api_key",
            "api_key=",
            "api_key: ",
            "\"api_key\"=",
            "'api_key' = ",
            "{api_key=",
            "line one\napi_key:",
            "AWS_SECRET_ACCESS_KEY=",
            "auth",
            "credential:",
        ] {
            assert!(has_open_contextual_assignment(open), "{open:?}");
        }
    }

    #[test]
    fn open_contextual_assignment_hint_rejects_resolved_or_low_signal_text() {
        for closed in [
            "",
            "token=",
            "xapi_key=",
            "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "plain text",
        ] {
            assert!(!has_open_contextual_assignment(closed), "{closed:?}");
        }
    }
}
