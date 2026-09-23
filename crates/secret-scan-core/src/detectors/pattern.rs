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

/// `[0-9]`.
pub(super) fn is_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

/// `[A-Za-z0-9_.-]`.
pub(super) fn is_alnum_dash_dot(byte: u8) -> bool {
    is_alnum_dash(byte) || byte == b'.'
}

/// `[0-9a-f]`: a lowercase hexadecimal body. Uppercase `A-F` is deliberately
/// outside the class, so a provider whose reviewed contract is lowercase hex
/// rejects a case-mangled twin instead of matching it.
pub(super) fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// `[0-9a-fA-F]`: a case-insensitive hexadecimal body, for a provider whose
/// reviewed contract explicitly allows both cases (e.g. `super::postman`'s
/// gitleaks-corroborated `PMAK-` shape).
pub(super) fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// `[0-9a-fA-F-]`: [`is_hex`] plus a literal dash, for a run that carries one
/// internal dash-delimited hex-hex structure a [`PostCheck`] validates the
/// exact position of (`super::postman`).
pub(super) fn is_hex_or_dash(byte: u8) -> bool {
    is_hex(byte) || byte == b'-'
}

/// `[a-z0-9]`: a lowercase-only alphanumeric body. Uppercase `A-Z` is
/// deliberately outside the class, mirroring [`is_lower_hex`]'s reasoning,
/// for a provider whose reviewed external-tool contract is this narrower
/// alphabet rather than the mixed-case [`is_alnum`].
pub(super) fn is_lower_alnum(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_lowercase()
}

/// `[A-Za-z0-9+/]`: the standard (non-URL-safe) base64 body alphabet,
/// excluding the `=` padding character. A run matched against this alphabet
/// stops before any trailing padding rather than trying to bound it to
/// exactly 0-2 bytes; the padding carries no secret entropy of its own, so
/// excluding it from the match still captures the whole secret value.
pub(super) fn is_base64_body(byte: u8) -> bool {
    is_alnum(byte) || byte == b'+' || byte == b'/'
}

/// Whether a matched run must be an exact length, a documented minimum, or
/// an open-ended minimum guarded against the boundary defect below,
/// mirroring a regex quantifier of `{n}` or `{n,}`.
#[derive(Clone, Copy, Debug)]
pub(super) enum RunLength {
    /// `{n}`: the run consumes exactly `n` alphabet bytes, however many more
    /// are available. A candidate is still rejected if a boundary-alphabet
    /// byte follows, so a longer run of the same shape is not misread as a
    /// short one.
    Exact(usize),
    /// `{n,}`: the run consumes the maximal available run, which must be at
    /// least `n` bytes. When this shape's `alphabet` is the same as the
    /// scan's `boundary` (an interim guard with no narrower reviewed
    /// alphabet), [`boundary_ok`]'s trailing half can never fire — a
    /// maximal run is, by construction, never followed by another byte of
    /// its own alphabet — so a directly-glued wider identifier
    /// (`..._backup`, `...-1`) is silently absorbed as "more opaque
    /// secret". [`RunLength::OpenFloor`] is the fix for that case; reach
    /// for plain `AtLeast` only when `alphabet` is already narrower than
    /// `boundary`, where the trailing check works unaided (see the bot and
    /// user secret sections in `super::slack`).
    AtLeast(usize),
    /// `{n,}`, but capped back to `n` when the byte immediately at the
    /// floor is a dash or underscore: see [`open_floor_run_end`]. The fix
    /// for the same-alphabet defect described on [`RunLength::AtLeast`],
    /// used by the Slack and Linear interim guards that must accept an
    /// unreviewed open-ended body without also swallowing a directly-glued
    /// wider identifier.
    OpenFloor(usize),
}

/// An extra structural check a matched run must pass, applied after the
/// boundary check: `(bytes, start, end)` of the whole match, e.g.
/// Cloudflare's checksum-shaped tail.
pub(super) type PostCheck = fn(&[u8], usize, usize) -> bool;

/// One literal prefix paired with the run length its own documented grammar
/// requires, for detectors whose prefixes do not all share a single length
/// (Docker Hub's `dckr_pat_` is followed by exactly 27 bytes, `dckr_oat_` by
/// exactly 32). A detector whose prefixes do share one length can keep using
/// [`scan_prefixed_runs`], which is this shape with the same `run` repeated.
///
/// `alphabet` and `signals` are carried per shape, not per scan, so
/// [`scan_prefixed_shapes`] can combine prefixes that need different
/// alphabets or different finding signals into the one left-to-right,
/// longest-prefix-wins pass a single combined regex alternation would give —
/// the same pass every other shape already gets — instead of a detector
/// scanning each such group separately and merging the results by position,
/// which is easy to get wrong exactly when one group's prefix is a literal
/// substring of another's.
#[derive(Clone, Copy, Debug)]
pub(super) struct PrefixShape<'a> {
    pub(super) prefix: &'a str,
    pub(super) run: RunLength,
    pub(super) alphabet: Alphabet,
    pub(super) signals: &'static [&'static str],
    pub(super) post_check: Option<PostCheck>,
}

impl<'a> PrefixShape<'a> {
    /// `prefix` followed by exactly `len` alphabet bytes (`{n}`).
    pub(super) const fn exact(
        prefix: &'a str,
        len: usize,
        alphabet: Alphabet,
        signals: &'static [&'static str],
    ) -> Self {
        Self {
            prefix,
            run: RunLength::Exact(len),
            alphabet,
            signals,
            post_check: None,
        }
    }

    /// `prefix` followed by at least `len` alphabet bytes (`{n,}`).
    pub(super) const fn at_least(
        prefix: &'a str,
        len: usize,
        alphabet: Alphabet,
        signals: &'static [&'static str],
    ) -> Self {
        Self {
            prefix,
            run: RunLength::AtLeast(len),
            alphabet,
            signals,
            post_check: None,
        }
    }

    /// `prefix` followed by an open floor of `len` alphabet bytes (see
    /// [`RunLength::OpenFloor`]): at least `len`, capped back to `len` when
    /// a directly-glued wider identifier starts right there.
    pub(super) const fn open_floor(
        prefix: &'a str,
        len: usize,
        alphabet: Alphabet,
        signals: &'static [&'static str],
    ) -> Self {
        Self {
            prefix,
            run: RunLength::OpenFloor(len),
            alphabet,
            signals,
            post_check: None,
        }
    }

    /// Attaches a [`PostCheck`] a match under this shape must also pass.
    pub(super) const fn with_post_check(mut self, post_check: PostCheck) -> Self {
        self.post_check = Some(post_check);
        self
    }
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

/// The end of a [`RunLength::OpenFloor`] run: at least `floor` bytes
/// starting at `cursor`, extended to the full `available` run unless the
/// byte immediately at the floor is a dash or underscore, in which case the
/// run is capped at the floor instead.
///
/// This is the fix for a shape whose alphabet is the same as its own
/// trailing boundary check, where plain [`RunLength::AtLeast`] can never
/// reject a directly-glued wider identifier: a maximal run is, by
/// construction, never followed by another byte of its own alphabet, so
/// [`boundary_ok`]'s trailing half is vacuously true at every such match. A
/// directly-glued wider identifier (`..._backup`, `...-1`) always starts
/// with a dash or underscore at that exact position, so capping the run
/// there leaves that byte for the ordinary boundary check to reject on,
/// while a plain alphanumeric extension — a longer opaque secret with no
/// reviewed maximum — is still read in full.
pub(super) fn open_floor_run_end(
    bytes: &[u8],
    cursor: usize,
    floor: usize,
    available: usize,
) -> usize {
    let floor_end = cursor + floor;
    if available > floor && matches!(bytes.get(floor_end), Some(b'-' | b'_')) {
        floor_end
    } else {
        cursor + available
    }
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
    let shapes: Vec<PrefixShape<'_>> = prefixes
        .iter()
        .map(|prefix| PrefixShape {
            prefix,
            run,
            alphabet,
            signals: &[],
            post_check: None,
        })
        .collect();
    scan_prefixed_shapes(input, &shapes, boundary)
        .into_iter()
        .map(|(start, end, _signals)| (start, end))
        .collect()
}

/// [`scan_prefixed_runs`] generalized to one run length, alphabet, and
/// signal set per prefix: the regex equivalent is
/// `(?:prefix1run1|prefix2run2|...)`, still matched left to right with the
/// longest literal prefix winning at each position, and each prefix's own
/// `{n}` / `{n,}` quantifier and alphabet applied to the run that follows
/// it. A shape's [`PostCheck`], when set, is applied after the boundary
/// check.
///
/// Because each shape carries its own alphabet, prefixes that need
/// different suffix alphabets are matched in the same left-to-right pass
/// instead of one pass per alphabet merged afterward by position — the
/// merge-by-position approach a caller could otherwise reach for, and get
/// wrong, when one group's prefix is a literal substring of another's.
///
/// Returns already boundary- and post-check-filtered `(start, end,
/// signals)` triples.
pub(super) fn scan_prefixed_shapes(
    input: &str,
    shapes: &[PrefixShape<'_>],
    boundary: Alphabet,
) -> Vec<(usize, usize, &'static [&'static str])> {
    let bytes = input.as_bytes();
    // Function-pointer identity (`std::ptr::fn_addr_eq`, not `==`, whose
    // result the compiler does not guarantee is meaningful) is enough here:
    // grouping and lookup both use it, so a same-address false positive
    // between two distinct `Alphabet` functions would only make this scan
    // share a run-ends table those functions' identical code already makes
    // interchangeable. `shape_table[i]` records, once, which table each
    // `shapes[i]` resolved to, so matching a shape later is a plain index
    // rather than a fallible re-lookup.
    let mut alphabets: Vec<Alphabet> = Vec::new();
    let shape_table: Vec<usize> = shapes
        .iter()
        .map(|shape| {
            if let Some(index) = alphabets
                .iter()
                .position(|&a| std::ptr::fn_addr_eq(a, shape.alphabet))
            {
                index
            } else {
                alphabets.push(shape.alphabet);
                alphabets.len() - 1
            }
        })
        .collect();
    let tables: Vec<Vec<usize>> = alphabets.iter().map(|&a| run_ends(bytes, a)).collect();

    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let Some((shape_index, shape)) = shapes
            .iter()
            .enumerate()
            .filter(|(_, shape)| bytes[start..].starts_with(shape.prefix.as_bytes()))
            .max_by_key(|(_, shape)| shape.prefix.len())
        else {
            start += 1;
            continue;
        };

        let ends = &tables[shape_table[shape_index]];
        let suffix_start = start + shape.prefix.len();
        let available = ends[suffix_start] - suffix_start;
        let matched_len = match shape.run {
            RunLength::Exact(len) if available >= len => len,
            RunLength::AtLeast(len) if available >= len => available,
            RunLength::OpenFloor(len) if available >= len => {
                open_floor_run_end(bytes, suffix_start, len, available) - suffix_start
            }
            _ => {
                start += 1;
                continue;
            }
        };

        let end = suffix_start + matched_len;
        let post_check_ok = match shape.post_check {
            Some(check) => check(bytes, start, end),
            None => true,
        };
        if post_check_ok && boundary_ok(bytes, start, end, boundary) {
            matches.push((start, end, shape.signals));
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
        assert!(is_digit(b'0') && is_digit(b'9') && !is_digit(b'a') && !is_digit(b'-'));
        assert!(
            is_lower_alnum(b'0')
                && is_lower_alnum(b'a')
                && is_lower_alnum(b'z')
                && !is_lower_alnum(b'A')
                && !is_lower_alnum(b'_')
                && !is_lower_alnum(b'-')
        );
        assert!(
            is_lower_hex(b'0')
                && is_lower_hex(b'f')
                && !is_lower_hex(b'g')
                && !is_lower_hex(b'F')
                && !is_lower_hex(b'_')
        );
        assert!(
            is_hex(b'0')
                && is_hex(b'f')
                && is_hex(b'F')
                && !is_hex(b'g')
                && !is_hex(b'G')
                && !is_hex(b'-')
        );
        assert!(is_hex_or_dash(b'-') && is_hex_or_dash(b'a') && !is_hex_or_dash(b'g'));
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

    /// A body past the floor with no dash or underscore right there is more
    /// opaque secret, taken in full — the fix's whole point is that this no
    /// longer requires an exact length.
    #[test]
    fn open_floor_run_extends_past_the_floor_when_not_delimited() {
        let input = "hf_0123456789012345678901234";
        let matches = scan_prefixed_runs(
            input,
            &["hf_"],
            RunLength::OpenFloor(20),
            is_alnum_dash,
            is_alnum_dash,
        );
        assert_eq!(matches, vec![(0, input.len())]);
    }

    /// A dash or underscore landing exactly at the floor is a directly-glued
    /// wider identifier (`..._backup`, `...-1`); the run is capped at the
    /// floor instead of absorbing it, which then leaves that byte for
    /// `boundary_ok` to reject the whole match on.
    #[test]
    fn open_floor_run_is_capped_and_rejected_when_delimited_at_the_floor() {
        for suffix in ["_backup", "-1"] {
            let input = format!("hf_{}{suffix}", "0".repeat(20));
            let matches = scan_prefixed_runs(
                &input,
                &["hf_"],
                RunLength::OpenFloor(20),
                is_alnum_dash,
                is_alnum_dash,
            );
            assert_eq!(matches, Vec::new(), "{suffix}");
        }
    }

    #[test]
    fn open_floor_run_end_extends_past_a_plain_alphanumeric_continuation() {
        let bytes = b"01234567890123456789extra";
        assert_eq!(open_floor_run_end(bytes, 0, 20, bytes.len()), bytes.len());
    }

    #[test]
    fn open_floor_run_end_caps_at_the_floor_when_delimited() {
        let bytes = b"01234567890123456789_backup";
        assert_eq!(open_floor_run_end(bytes, 0, 20, bytes.len()), 20);
        let bytes = b"01234567890123456789-1";
        assert_eq!(open_floor_run_end(bytes, 0, 20, bytes.len()), 20);
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
