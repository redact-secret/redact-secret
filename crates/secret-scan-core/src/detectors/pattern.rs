//! A small hand-rolled matching engine shared by the known-format provider
//! detectors.
//!
//! The core crate may not depend on any external crate
//! (`[workspace.metadata.redact-secret] allowed-dependencies = []`), so this
//! module reimplements just enough of "literal prefix, then a bounded run of
//! an alphabet, then a byte-adjacent boundary check" to reproduce the
//! TypeScript oracle's `RegExp` + `TOKEN_CHARACTER` guard idiom without a
//! regex engine. Every provider pattern in `src/detectors/*.ts` reduced to
//! this shape except `OpenAI`'s, which [`super::openai`] composes directly
//! from the same primitives (two exact-length segments around a literal
//! marker, plus the Anthropic namespace exclusion).

/// A byte-membership predicate for a token alphabet, e.g. `[A-Za-z0-9_-]`.
pub(super) type Alphabet = fn(u8) -> bool;

/// `[A-Za-z0-9]`.
pub(super) fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

/// `[A-Z0-9]`.
pub(super) fn is_upper_alnum(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

/// `[A-Za-z0-9_]`.
pub(super) fn is_alnum_underscore(byte: u8) -> bool {
    is_alnum(byte) || byte == b'_'
}

/// `[A-Za-z0-9_-]`.
pub(super) fn is_alnum_dash(byte: u8) -> bool {
    is_alnum(byte) || byte == b'_' || byte == b'-'
}

/// `[A-Za-z0-9_.-]`.
pub(super) fn is_alnum_dash_dot(byte: u8) -> bool {
    is_alnum_dash(byte) || byte == b'.'
}

/// `[A-Za-z0-9+/]`: the standard (non-URL-safe) base64 body alphabet,
/// excluding the `=` padding character. A run matched against this alphabet
/// stops before any trailing padding rather than trying to bound it to
/// exactly 0-2 bytes; the padding carries no secret entropy of its own, so
/// excluding it from the match still captures the whole secret value.
pub(super) fn is_base64_body(byte: u8) -> bool {
    is_alnum(byte) || byte == b'+' || byte == b'/'
}

/// Whether a matched run must be an exact length or a documented minimum,
/// mirroring a regex quantifier of `{n}` or `{n,}`.
#[derive(Clone, Copy, Debug)]
pub(super) enum RunLength {
    /// `{n}`: the run consumes exactly `n` alphabet bytes, however many more
    /// are available. A candidate is still rejected if a boundary-alphabet
    /// byte follows, so a longer run of the same shape is not misread as a
    /// short one.
    Exact(usize),
    /// `{n,}`: the run consumes the maximal available run, which must be at
    /// least `n` bytes.
    AtLeast(usize),
}

/// For every offset, the exclusive end of the maximal run of `alphabet`
/// bytes starting there.
///
/// A detector may see the same alphabet run touched by several candidate
/// prefixes (a prefix's own bytes are often themselves alphabet members), so
/// computing this table once per scan — rather than rescanning forward from
/// each candidate position — keeps a whole scan linear in the input length
/// instead of quadratic on adversarial input.
pub(super) fn run_ends(bytes: &[u8], alphabet: Alphabet) -> Vec<usize> {
    let mut ends = vec![0usize; bytes.len() + 1];
    ends[bytes.len()] = bytes.len();
    for index in (0..bytes.len()).rev() {
        ends[index] = if alphabet(bytes[index]) {
            ends[index + 1]
        } else {
            index
        };
    }
    ends
}

/// `true` when neither the byte immediately before `start` nor the byte
/// immediately at `end` belongs to `boundary`, i.e. the span is not a
/// truncated slice of a longer run of the same or a wider alphabet.
pub(super) fn boundary_ok(bytes: &[u8], start: usize, end: usize, boundary: Alphabet) -> bool {
    let before_ok = start == 0 || !boundary(bytes[start - 1]);
    let after_ok = end >= bytes.len() || !boundary(bytes[end]);
    before_ok && after_ok
}

/// Finds every non-overlapping `(prefix, run)` match, left to right, the way
/// a global regex of `(?:prefix1|prefix2|...)run{...}` would: at each
/// position, the longest literal prefix that matches wins (the prefix sets
/// used here never let two distinct prefixes match the same position with
/// different lengths in a way that changes the outcome), a failed attempt
/// advances by one byte, and a successful one advances past the whole match
/// regardless of whether the boundary check below keeps it.
///
/// Returns already boundary-filtered `(start, end)` byte ranges.
pub(super) fn scan_prefixed_runs(
    input: &str,
    prefixes: &[&str],
    run: RunLength,
    alphabet: Alphabet,
    boundary: Alphabet,
) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let ends = run_ends(bytes, alphabet);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let Some(prefix) = prefixes
            .iter()
            .filter(|prefix| bytes[start..].starts_with(prefix.as_bytes()))
            .max_by_key(|prefix| prefix.len())
        else {
            start += 1;
            continue;
        };

        let suffix_start = start + prefix.len();
        let available = ends[suffix_start] - suffix_start;
        let matched_len = match run {
            RunLength::Exact(len) if available >= len => len,
            RunLength::AtLeast(len) if available >= len => available,
            _ => {
                start += 1;
                continue;
            }
        };

        let end = suffix_start + matched_len;
        if boundary_ok(bytes, start, end, boundary) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabets_match_documented_classes() {
        assert!(is_alnum(b'a') && is_alnum(b'9') && !is_alnum(b'_'));
        assert!(is_upper_alnum(b'A') && is_upper_alnum(b'0') && !is_upper_alnum(b'a'));
        assert!(is_alnum_underscore(b'_') && !is_alnum_underscore(b'-'));
        assert!(is_alnum_dash(b'-') && is_alnum_dash(b'_') && !is_alnum_dash(b'.'));
        assert!(is_alnum_dash_dot(b'.') && is_alnum_dash_dot(b'-'));
        assert!(
            is_base64_body(b'+')
                && is_base64_body(b'/')
                && !is_base64_body(b'=')
                && !is_base64_body(b'_')
        );
    }

    #[test]
    fn exact_run_rejects_a_longer_alphabet_span() {
        let matches = scan_prefixed_runs(
            "AKIA0123456789ABCDEFG",
            &["AKIA"],
            RunLength::Exact(16),
            is_upper_alnum,
            is_alnum,
        );
        assert_eq!(matches, Vec::new());
    }

    #[test]
    fn at_least_run_takes_the_maximal_span() {
        let input = "hf_0123456789012345678901234";
        let matches = scan_prefixed_runs(
            input,
            &["hf_"],
            RunLength::AtLeast(20),
            is_alnum_dash,
            is_alnum_dash,
        );
        assert_eq!(matches, vec![(0, input.len())]);
    }

    #[test]
    fn longest_matching_prefix_wins_at_a_shared_position() {
        let input = "glrtr-0123456789012345678901234";
        let matches = scan_prefixed_runs(
            input,
            &["glrt-", "glrtr-"],
            RunLength::AtLeast(20),
            is_alnum_dash,
            is_alnum_dash,
        );
        assert_eq!(matches, vec![(0, input.len())]);
    }

    #[test]
    fn a_run_that_never_reaches_the_minimum_finds_nothing() {
        // `!` is outside the alphabet, so each "hf_" prefix is immediately
        // followed by a zero-length run and never reaches the minimum.
        let input = "hf_!".repeat(8);
        let matches = scan_prefixed_runs(
            &input,
            &["hf_"],
            RunLength::AtLeast(20),
            is_alnum_dash,
            is_alnum_dash,
        );
        assert_eq!(matches, Vec::new());
    }

    /// A pathological run built entirely from repeated prefix bytes must not
    /// make the scan quadratic: each repetition should cost the scan a
    /// bounded amount of work, not a rescan of the remaining input.
    #[test]
    fn repeated_embedded_prefixes_in_one_run_stay_linear() {
        let input = "AKIA".repeat(20_000);
        let matches = scan_prefixed_runs(
            &input,
            &["AKIA", "ASIA"],
            RunLength::Exact(16),
            is_upper_alnum,
            is_alnum,
        );
        // The first match consumes the first 20 bytes; nothing after it can
        // start a new "AKIA"/"ASIA" occurrence because the whole remainder
        // is a single run that already extends past every later boundary
        // check, so no further candidate is proposed.
        assert_eq!(matches, Vec::new());
        assert!(input.len() > 79_000);
    }
}
