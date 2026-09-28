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

/// Whether a matched run must be an exact length, one of a few exact
/// lengths, a documented minimum, or an open-ended minimum guarded against
/// the boundary defect below, mirroring a regex quantifier of `{n}`,
/// `(?:{a}|{b})` or `{n,}`.
#[derive(Clone, Copy, Debug)]
pub(super) enum RunLength {
    /// `{n}`: the run consumes exactly `n` alphabet bytes, however many more
    /// are available. A candidate is still rejected if a boundary-alphabet
    /// byte follows, so a longer run of the same shape is not misread as a
    /// short one.
    Exact(usize),
    /// `(?:{a}|{b}|...)`: each listed length is tried as [`RunLength::Exact`],
    /// longest first, and the first one that also passes the shape's post
    /// check and the scan's boundary wins. Used when a provider documents
    /// one prefix with more than one exact body width (Docker's `dckr_oat_`,
    /// issue #708); a width between the listed ones is still rejected, never
    /// truncated.
    OneOf(&'static [usize]),
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

    /// `prefix` followed by exactly one of `lens` alphabet bytes
    /// (`(?:{a}|{b})`, see [`RunLength::OneOf`]).
    pub(super) const fn one_of(
        prefix: &'a str,
        lens: &'static [usize],
        alphabet: Alphabet,
        signals: &'static [&'static str],
    ) -> Self {
        Self {
            prefix,
            run: RunLength::OneOf(lens),
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

/// The offset of the first occurrence of `needle` in `bytes` that starts at
/// or after `from`, or `None` when there is none (or `needle` is empty).
///
/// A left-to-right scan that tests `bytes[start..].starts_with(needle)` at
/// every offset and advances by one byte on a miss visits exactly the
/// offsets this returns, in the same order, so replacing that inner miss
/// loop with this search leaves the scan's result unchanged; it only skips
/// the offsets whose first byte already rules them out (issue #950).
pub(super) fn find_literal(bytes: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    let last_start = bytes.len().checked_sub(needle.len())?;
    let lead = LeadBytes::of(std::iter::once(needle));
    let candidates = &bytes[..=last_start];
    let mut at = from;
    while at <= last_start {
        at = lead.find(candidates, at)?;
        debug_assert_eq!(bytes[at], first);
        if bytes[at + 1..at + needle.len()] == *rest {
            return Some(at);
        }
        at += 1;
    }
    None
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

/// The most distinct lead bytes [`LeadBytes::find`] searches for a word at
/// a time; a set with more falls back to a byte-at-a-time table scan.
const WORD_SEARCH_LEADS: usize = 4;

/// `0x01` in every byte of a `u64`.
const LOW_BITS: u64 = u64::from_le_bytes([0x01; 8]);
/// `0x80` in every byte of a `u64`.
const HIGH_BITS: u64 = u64::from_le_bytes([0x80; 8]);

/// The bytes that can begin one of a scan's literal prefixes, and a search
/// for the next input offset holding one.
///
/// A prefixed scan spends most of its time looking for a byte that can start
/// a prefix, once per detector over the whole input. Most prefix sets start
/// with one to four distinct bytes, so [`find`](Self::find) tests eight
/// input bytes per step for equality with each of them (the "has a zero
/// byte" word trick) instead of one table lookup per byte; a larger set, or
/// an empty prefix, which can begin anywhere, uses the table. Both searches
/// return the same offset (issue #950).
pub(super) struct LeadBytes {
    table: [bool; 256],
    leads: [u8; WORD_SEARCH_LEADS],
    /// How many of `leads` are set, or `None` when the set is too large for
    /// the word search (or is every byte).
    lead_count: Option<usize>,
}

impl LeadBytes {
    /// Every prefix's first byte, or every byte when a prefix is empty (an
    /// empty prefix matches everywhere).
    pub(super) fn of<'a>(prefixes: impl Iterator<Item = &'a [u8]>) -> Self {
        let mut lead_bytes = Self {
            table: [false; 256],
            leads: [0; WORD_SEARCH_LEADS],
            lead_count: Some(0),
        };
        for prefix in prefixes {
            let Some(&byte) = prefix.first() else {
                lead_bytes.table = [true; 256];
                lead_bytes.lead_count = None;
                return lead_bytes;
            };
            if lead_bytes.table[usize::from(byte)] {
                continue;
            }
            lead_bytes.table[usize::from(byte)] = true;
            lead_bytes.lead_count = lead_bytes
                .lead_count
                .filter(|&count| count < WORD_SEARCH_LEADS)
                .map(|count| {
                    lead_bytes.leads[count] = byte;
                    count + 1
                });
        }
        lead_bytes
    }

    /// The first offset at or after `from` whose byte is in the set.
    pub(super) fn find(&self, bytes: &[u8], from: usize) -> Option<usize> {
        let mut at = from;
        if let Some(count) = self.lead_count {
            let leads = &self.leads[..count];
            while let Some(word) = bytes.get(at..at + 8) {
                let word = u64::from_le_bytes(word.try_into().ok()?);
                let mut hits = 0u64;
                for &lead in leads {
                    let difference = word ^ (u64::from(lead) * LOW_BITS);
                    hits |= difference.wrapping_sub(LOW_BITS) & !difference & HIGH_BITS;
                }
                // The lowest flagged byte is always a true match: a
                // borrow can only flag bytes above the first equal one.
                if hits != 0 {
                    return Some(at + (hits.trailing_zeros() / 8) as usize);
                }
                at += 8;
            }
        }
        bytes
            .get(at..)?
            .iter()
            .position(|&byte| self.table[usize::from(byte)])
            .map(|offset| at + offset)
    }
}

/// `bytes[at..].starts_with(prefix)`, compared a byte at a time so a
/// mismatch in the first byte or two, the usual outcome, returns without a
/// `memcmp` call.
fn has_prefix_at(bytes: &[u8], at: usize, prefix: &[u8]) -> bool {
    bytes.len() - at >= prefix.len() && bytes[at..].iter().zip(prefix).all(|(a, b)| a == b)
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
    // A call over input with no byte that can begin a prefix returns before
    // building the shape list (issue #950); see `scan_prefixed_shapes`.
    if LeadBytes::of(prefixes.iter().map(|prefix| prefix.as_bytes()))
        .find(input.as_bytes(), 0)
        .is_none()
    {
        return Vec::new();
    }
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
    // Bytes that can begin some prefix. A position outside this set cannot
    // match any shape, so it skips the per-shape comparison entirely. An
    // empty prefix matches everywhere and disables the filter.
    let lead_bytes = LeadBytes::of(shapes.iter().map(|shape| shape.prefix.as_bytes()));
    // The scan starts at the first byte that can begin a prefix. Input with
    // none, the common case, returns here, before the per-scan tables below
    // are allocated: a whole scan pays that setup once, but an incremental
    // session calls every detector once per closed line (issue #950).
    let Some(mut start) = lead_bytes.find(bytes, 0) else {
        return Vec::new();
    };
    // Run-end tables are built on first use, one per distinct alphabet:
    // most inputs contain no prefix at all, and an eager table costs a pass
    // and an allocation per alphabet. Function-pointer identity
    // (`std::ptr::fn_addr_eq`, not `==`, whose result the compiler does not
    // guarantee is meaningful) is enough to share a table: a same-address
    // false positive between two distinct `Alphabet` functions would only
    // share a table those functions' identical code already makes
    // interchangeable. `Vec::new` does not allocate, so a scan that finds no
    // prefix never allocates here (issue #950).
    let mut tables: Vec<(Alphabet, Vec<usize>)> = Vec::new();

    let mut matches = Vec::new();
    while start < bytes.len() {
        // Offsets whose byte cannot begin a prefix are skipped in one search;
        // they could only have advanced the scan by one byte each.
        let Some(lead) = lead_bytes.find(bytes, start) else {
            break;
        };
        start = lead;
        let Some(shape) = shapes
            .iter()
            .filter(|shape| has_prefix_at(bytes, start, shape.prefix.as_bytes()))
            .max_by_key(|shape| shape.prefix.len())
        else {
            start += 1;
            continue;
        };

        let table_index = if let Some(index) = tables
            .iter()
            .position(|&(alphabet, _)| std::ptr::fn_addr_eq(alphabet, shape.alphabet))
        {
            index
        } else {
            tables.push((shape.alphabet, run_ends(bytes, shape.alphabet)));
            tables.len() - 1
        };
        let ends = &tables[table_index].1;
        let suffix_start = start + shape.prefix.len();
        let available = ends[suffix_start] - suffix_start;
        let matched_len = match shape.run {
            RunLength::Exact(len) if available >= len => len,
            RunLength::OneOf(lens) => {
                let accepted = |len: usize| {
                    let end = suffix_start + len;
                    available >= len
                        && shape
                            .post_check
                            .is_none_or(|check| check(bytes, start, end))
                        && boundary_ok(bytes, start, end, boundary)
                };
                let Some(len) = lens.iter().copied().filter(|&len| accepted(len)).max() else {
                    start += 1;
                    continue;
                };
                len
            }
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
    fn lead_bytes_find_the_same_offset_as_a_byte_at_a_time_scan() {
        // Bytes around the word trick's edges (0x00, 0x01, 0x7f, 0x80,
        // 0xff), at every alignment, for lead sets on both sides of the
        // word-search limit and an empty prefix.
        let mut haystack: Vec<u8> = Vec::new();
        for round in 0u8..40 {
            haystack.extend_from_slice(&[0x00, 0x01, 0x7f, 0x80, 0xff, b'a', b's', b'k', b'_']);
            haystack.extend(std::iter::repeat_n(
                round.wrapping_mul(37),
                usize::from(round % 11),
            ));
        }
        let prefix_sets: [&[&[u8]]; 7] = [
            &[b"s"],
            &[b"sk_", b"sk-", b"rk_"],
            &[b"\x00", b"\x01"],
            &[b"\x80\x81", b"\xff"],
            &[b"a", b"k", b"s", b"_"],
            &[b"a", b"k", b"s", b"_", b"\x7f"],
            &[b"x", b""],
        ];
        for prefixes in prefix_sets {
            let lead_bytes = LeadBytes::of(prefixes.iter().copied());
            for end in [0, 1, 7, 8, 9, 63, haystack.len()] {
                let bytes = &haystack[..end];
                for from in 0..=end + 1 {
                    let expected = (from..end).find(|&at| {
                        prefixes
                            .iter()
                            .any(|prefix| prefix.first().is_none_or(|&lead| lead == bytes[at]))
                    });
                    assert_eq!(
                        lead_bytes.find(bytes, from),
                        expected,
                        "{prefixes:?} end {end} from {from}"
                    );
                }
            }
        }
    }

    #[test]
    fn find_literal_returns_the_first_occurrence_at_or_after_the_offset() {
        let haystacks: [&[u8]; 6] = [
            b"",
            b"x",
            b"xoxb-xoxb",
            b"aaaa",
            b"xoxxoxbxoxb-",
            b"://:/://",
        ];
        let needles: [&[u8]; 5] = [b"x", b"xoxb-", b"aa", b"://", b"aaaaa"];
        for haystack in haystacks {
            for needle in needles {
                for from in 0..=haystack.len() + 1 {
                    let expected =
                        (from..haystack.len()).find(|&at| haystack[at..].starts_with(needle));
                    assert_eq!(
                        find_literal(haystack, needle, from),
                        expected,
                        "{haystack:?} {needle:?} {from}"
                    );
                }
            }
        }
        assert_eq!(find_literal(b"abc", b"", 0), None);
    }

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
