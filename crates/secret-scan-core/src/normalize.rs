//! The scan copy: the input with zero-rendering and format code points
//! removed, plus the map back to original offsets
//! (`decision-normalize-invisible-characters-before-detection`).
//!
//! Detectors match contiguous bytes, so one invisible code point inside a
//! credential would otherwise defeat every one of them. They run against
//! [`NormalizedInput::text`] instead, and every range they report is
//! translated back so public ranges keep indexing the original input.
//!
//! The removed set is [`INVISIBLE_RANGES`]: `Default_Ignorable_Code_Point ∪
//! Cf`, generated from a pinned UCD snapshot. Nothing else changes: no case
//! folding, no NFKC, no decoding, no unescaping. No removed code point is
//! ASCII, `\n`, or `\r`, which is what makes the ASCII fast path exact and
//! leaves every line boundary where it was.

use std::borrow::Cow;

use crate::invisible_table::INVISIBLE_RANGES;
use crate::types::ByteRange;

/// Whether `ch` is removed from the scan copy: a governed invisible code
/// point. Everything below the first range (ASCII and most Latin-1) returns
/// before the binary search.
pub(crate) fn is_invisible(ch: char) -> bool {
    let code_point = u32::from(ch);
    if code_point < INVISIBLE_RANGES[0].0 {
        return false;
    }
    let following = INVISIBLE_RANGES.partition_point(|&(first, _)| first <= code_point);
    following
        .checked_sub(1)
        .and_then(|index| INVISIBLE_RANGES.get(index))
        .is_some_and(|&(_, last)| code_point <= last)
}

/// Bytes walked character by character between two looks for an ASCII
/// stretch to skip.
///
/// The look is a single word load per window, so dense non-ASCII text pays
/// about one such load per window on top of the plain per-character walk, and
/// text with a long ASCII stretch skips it a word at a time (issue #1134).
const WALK_WINDOW: usize = 4096;

/// The offset of the first non-ASCII byte at or after `from` (or the length),
/// when the eight bytes at `from` are all ASCII; `None` otherwise, including
/// when fewer than eight bytes remain.
///
/// `from` is a character boundary, and so is the result: every byte before it
/// is a whole ASCII character.
#[inline(never)]
fn ascii_stretch_end(bytes: &[u8], from: usize) -> Option<usize> {
    const HIGH_BITS: u64 = 0x8080_8080_8080_8080;
    let word = |position: usize| -> Option<u64> {
        let chunk = bytes.get(position..position + 8)?;
        Some(u64::from_le_bytes(<[u8; 8]>::try_from(chunk).ok()?))
    };
    if word(from)? & HIGH_BITS != 0 {
        return None;
    }
    let mut position = from + 8;
    // Four words per step while they are all ASCII, then one word at a time
    // to find the exact byte.
    while let (Some(a), Some(b), Some(c), Some(d)) = (
        word(position),
        word(position + 8),
        word(position + 16),
        word(position + 24),
    ) {
        if (a | b | c | d) & HIGH_BITS != 0 {
            break;
        }
        position += 32;
    }
    while let Some(next) = word(position) {
        let high = next & HIGH_BITS;
        if high != 0 {
            // Little-endian: the lowest set bit is the first non-ASCII byte.
            return Some(position + usize::try_from(high.trailing_zeros() / 8).ok()?);
        }
        position += 8;
    }
    while bytes.get(position).is_some_and(u8::is_ascii) {
        position += 1;
    }
    Some(position)
}

/// The end of the next walk window starting at the character boundary
/// `position`: at least [`WALK_WINDOW`] bytes on, moved forward to a character
/// boundary so no character is split.
fn walk_window_end(input: &str, position: usize) -> usize {
    let mut end = (position + WALK_WINDOW).min(input.len());
    while !input.is_char_boundary(end) {
        end += 1;
    }
    end
}

/// Offset of the first removed code point, if any.
///
/// The walk decodes characters exactly as a plain `char_indices` scan would.
/// The only dispatch, at the start of each [`WALK_WINDOW`], is to jump over an
/// ASCII stretch (which holds no removed code point).
fn first_invisible(input: &str, skip_ascii: bool) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut position = 0;
    while position < input.len() {
        if skip_ascii && let Some(after) = ascii_stretch_end(bytes, position) {
            position = after;
            continue;
        }
        let end = walk_window_end(input, position);
        if let Some(offset) = input[position..end]
            .char_indices()
            .find_map(|(offset, ch)| is_invisible(ch).then_some(offset + position))
        {
            return Some(offset);
        }
        position = end;
    }
    None
}

/// One maximal run of removed code points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seam {
    /// Offset in the scan copy at which the run was removed.
    normalized: usize,
    /// Offset in the original input just after the run.
    original_after: usize,
}

/// The scan copy and seams of `input`, whose first removed code point is at
/// `first_removed`.
#[inline(never)]
fn strip_removed(input: &str, first_removed: usize, skip_ascii: bool) -> (String, Vec<Seam>) {
    let mut text = String::with_capacity(input.len());
    text.push_str(&input[..first_removed]);
    let mut seams = Vec::new();
    let mut kept_from = first_removed;
    let mut in_run = false;
    let bytes = input.as_bytes();
    let mut position = first_removed;
    while position < input.len() {
        // Outside a run an ASCII stretch changes neither `text` nor `seams`
        // (no ASCII code point is removed, and `kept_from` stays put to copy
        // it later). Inside a run the next character must be seen: the first
        // kept one, ASCII or not, closes the run.
        if skip_ascii
            && !in_run
            && let Some(after) = ascii_stretch_end(bytes, position)
        {
            position = after;
            continue;
        }
        let end = walk_window_end(input, position);
        for (relative, ch) in input[position..end].char_indices() {
            let offset = relative + position;
            if is_invisible(ch) {
                if !in_run {
                    text.push_str(&input[kept_from..offset]);
                    in_run = true;
                }
            } else if in_run {
                seams.push(Seam {
                    normalized: text.len(),
                    original_after: offset,
                });
                kept_from = offset;
                in_run = false;
            }
        }
        position = end;
    }
    if in_run {
        seams.push(Seam {
            normalized: text.len(),
            original_after: input.len(),
        });
    } else {
        text.push_str(&input[kept_from..]);
    }
    (text, seams)
}

/// The scan copy of one input and the seams that map it back.
///
/// Removal is monotonic and order-preserving, so one seam per removed run is
/// enough: `O(k)` memory and `O(log k)` translation for `k` runs. With no
/// removal the text is borrowed and there is no map at all.
#[derive(Debug)]
pub(crate) struct NormalizedInput<'a> {
    text: Cow<'a, str>,
    /// Ascending by `normalized`, which is unique per seam: two runs are
    /// always separated by at least one kept character.
    seams: Vec<Seam>,
}

impl<'a> NormalizedInput<'a> {
    /// Builds the scan copy of `input`.
    pub(crate) fn new(input: &'a str) -> Self {
        Self::build(input, true)
    }

    /// [`new`](Self::new) with the ASCII-stretch dispatch selectable. The
    /// dispatch decides only which bytes are *examined*, never which code
    /// points are removed: with `skip_ascii` false every character goes
    /// through the same per-character walk the dispatch falls back to.
    fn build(input: &'a str, skip_ascii: bool) -> Self {
        let borrowed = Self {
            text: Cow::Borrowed(input),
            seams: Vec::new(),
        };
        // No removed code point is ASCII, so the common case is settled by
        // one vectorizable pass with no allocation.
        if input.is_ascii() {
            return borrowed;
        }
        let Some(first_removed) = first_invisible(input, skip_ascii) else {
            return borrowed;
        };

        let (text, seams) = strip_removed(input, first_removed, skip_ascii);
        Self {
            text: Cow::Owned(text),
            seams,
        }
    }

    /// The text detectors scan.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Consumes the view, keeping only the scan copy.
    pub(crate) fn into_text(self) -> Cow<'a, str> {
        self.text
    }

    /// Bytes removed by the first `seam_count` seams together.
    fn removed_before(&self, seam_count: usize) -> usize {
        seam_count
            .checked_sub(1)
            .and_then(|index| self.seams.get(index))
            .map_or(0, |seam| seam.original_after - seam.normalized)
    }

    /// Translates a char-aligned range of [`text`](Self::text) into the
    /// original input.
    ///
    /// `start` maps to the original offset of the same character and `end`
    /// to the original offset just after the last included character. A
    /// removed run strictly inside the range is therefore part of the
    /// translated span, while a run merely adjacent to either boundary is
    /// not absorbed.
    pub(crate) fn to_original(&self, range: ByteRange) -> Option<ByteRange> {
        self.translate(range).map(|(original, _)| original)
    }

    /// [`to_original`](Self::to_original) and
    /// [`contains_removed_run`](Self::contains_removed_run) from one pair of
    /// seam searches: the translated range, and whether a removed run lies
    /// strictly inside `range`.
    ///
    /// Both questions partition the seams at the same two points (`<= start`
    /// and `< end`), so the second is the difference of the two counts. This
    /// is not [`touches_removed_run`](Self::touches_removed_run), which uses
    /// different boundaries and stays separate (issue #1133).
    pub(crate) fn translate(&self, range: ByteRange) -> Option<(ByteRange, bool)> {
        if self.seams.is_empty() {
            return Some((range, false));
        }
        // A run removed exactly at `start` precedes the first character, so
        // it counts; one removed exactly at `end` follows the last, so it
        // does not.
        let through_start = self
            .seams
            .partition_point(|seam| seam.normalized <= range.start());
        let before_end = self
            .seams
            .partition_point(|seam| seam.normalized < range.end());
        let original = ByteRange::new(
            range.start() + self.removed_before(through_start),
            range.end() + self.removed_before(before_end),
        )?;
        Some((original, before_end > through_start))
    }

    /// Translates `original`, an offset in the original input that is not
    /// inside a removed run, into [`text`](Self::text): every run that ends
    /// at or before it is subtracted.
    pub(crate) fn to_scanned_offset(&self, original: usize) -> usize {
        let runs_before = self
            .seams
            .partition_point(|seam| seam.original_after <= original);
        original - self.removed_before(runs_before)
    }

    /// Whether a removed run lies inside `range` or immediately touches
    /// either normalized boundary.
    pub(crate) fn touches_removed_run(&self, range: ByteRange) -> bool {
        if self.seams.is_empty() {
            return false;
        }
        let before_start = self
            .seams
            .partition_point(|seam| seam.normalized < range.start());
        let through_end = self
            .seams
            .partition_point(|seam| seam.normalized <= range.end());
        through_end > before_start
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::invisible_table::UCD_VERSION;

    const ZWSP: char = '\u{200B}';
    const ZWNJ: char = '\u{200C}';

    fn range(start: usize, end: usize) -> ByteRange {
        ByteRange::new(start, end).unwrap()
    }

    /// The original text a normalized range selects.
    fn selected<'a>(input: &'a str, view: &NormalizedInput<'_>, normalized: ByteRange) -> &'a str {
        let original = view.to_original(normalized).unwrap();
        assert!(original.is_char_aligned_in(input));
        &input[original.start()..original.end()]
    }

    /// The pre-#1133 `to_original`: its own pair of seam searches. Kept as the
    /// oracle for [`NormalizedInput::translate`].
    fn oracle_to_original(view: &NormalizedInput<'_>, range: ByteRange) -> Option<ByteRange> {
        if view.seams.is_empty() {
            return Some(range);
        }
        let through_start = view
            .seams
            .partition_point(|seam| seam.normalized <= range.start());
        let before_end = view
            .seams
            .partition_point(|seam| seam.normalized < range.end());
        ByteRange::new(
            range.start() + view.removed_before(through_start),
            range.end() + view.removed_before(before_end),
        )
    }

    /// The pre-#1133 `contains_removed_run`, likewise an independent oracle.
    fn oracle_contains_removed_run(view: &NormalizedInput<'_>, range: ByteRange) -> bool {
        if view.seams.is_empty() {
            return false;
        }
        let through_start = view
            .seams
            .partition_point(|seam| seam.normalized <= range.start());
        let before_end = view
            .seams
            .partition_point(|seam| seam.normalized < range.end());
        before_end > through_start
    }

    fn contained(view: &NormalizedInput<'_>, range: ByteRange) -> bool {
        view.translate(range).unwrap().1
    }

    #[test]
    fn translate_equals_the_two_separate_searches_for_every_range() {
        let inputs = [
            String::new(),
            "plain text".to_owned(),
            format!("{ZWSP}"),
            format!("{ZWSP}ab{ZWNJ}cd{ZWSP}"),
            format!("x={ZWSP}abcd{ZWSP};"),
            format!("a{ZWSP}{ZWNJ}{ZWSP}b{ZWSP}c{ZWNJ}"),
            format!("é{ZWSP}한\u{E0067}😀{ZWNJ}\u{FE0F}z\u{00AD}"),
            format!("{ZWSP}가🙂\u{2060}abc{ZWNJ}끝"),
            "naïve café 한국어 😀".to_owned(),
        ];
        let mut checked = 0;
        for input in &inputs {
            let view = NormalizedInput::new(input);
            let text = view.text().to_owned();
            for start in 0..=text.len() {
                for end in start..=text.len() {
                    let Some(candidate) = ByteRange::new(start, end) else {
                        continue;
                    };
                    let fused = view.translate(candidate);
                    assert_eq!(
                        fused.map(|pair| pair.0),
                        oracle_to_original(&view, candidate),
                        "{input:?} {start}..{end}"
                    );
                    assert_eq!(
                        fused.map(|pair| pair.1),
                        Some(oracle_contains_removed_run(&view, candidate)),
                        "{input:?} {start}..{end}"
                    );
                    assert_eq!(view.to_original(candidate), fused.map(|pair| pair.0));
                    checked += 1;
                }
            }
        }
        assert!(checked > 300);
    }

    #[test]
    fn the_pipeline_boundary_rules_keep_their_distinct_search_points() {
        // `touches_removed_run` (`< start`, `<= end`) is deliberately not
        // part of the fused result: a run exactly at a boundary touches but
        // is neither interior nor absorbed.
        let input = format!("x={ZWSP}abcd{ZWSP};");
        let view = NormalizedInput::new(&input);
        let boundary = range(2, 6);
        assert!(view.touches_removed_run(boundary));
        assert_eq!(view.translate(boundary).map(|pair| pair.1), Some(false));
    }

    /// The pre-#1134 `NormalizedInput::new`, verbatim: one `char_indices`
    /// walk with no ASCII-block dispatch. The oracle for
    /// [`NormalizedInput::build`].
    fn oracle_new(input: &str) -> (Cow<'_, str>, Vec<Seam>) {
        oracle_new_copy::<0>(input)
    }

    /// The same body monomorphized once more, so the timing harness can show
    /// how far two builds of identical code differ by layout alone.
    fn oracle_new_copy<const COPY: u8>(input: &str) -> (Cow<'_, str>, Vec<Seam>) {
        std::hint::black_box(COPY);
        if input.is_ascii() {
            return (Cow::Borrowed(input), Vec::new());
        }
        let Some(first_removed) = input
            .char_indices()
            .find_map(|(offset, ch)| is_invisible(ch).then_some(offset))
        else {
            return (Cow::Borrowed(input), Vec::new());
        };
        let mut text = String::with_capacity(input.len());
        text.push_str(&input[..first_removed]);
        let mut seams = Vec::new();
        let mut kept_from = first_removed;
        let mut in_run = false;
        for (offset, ch) in input[first_removed..]
            .char_indices()
            .map(|(offset, ch)| (offset + first_removed, ch))
        {
            if is_invisible(ch) {
                if !in_run {
                    text.push_str(&input[kept_from..offset]);
                    in_run = true;
                }
            } else if in_run {
                seams.push(Seam {
                    normalized: text.len(),
                    original_after: offset,
                });
                kept_from = offset;
                in_run = false;
            }
        }
        if in_run {
            seams.push(Seam {
                normalized: text.len(),
                original_after: input.len(),
            });
        } else {
            text.push_str(&input[kept_from..]);
        }
        (Cow::Owned(text), seams)
    }

    fn assert_dispatch_matches_oracle(input: &str) {
        let (oracle_text, oracle_seams) = oracle_new(input);
        for skip_ascii in [true, false] {
            let view = NormalizedInput::build(input, skip_ascii);
            assert_eq!(view.text, oracle_text, "skip_ascii={skip_ascii} {input:?}");
            assert_eq!(
                view.seams, oracle_seams,
                "skip_ascii={skip_ascii} {input:?}"
            );
            assert_eq!(
                matches!(view.text, Cow::Borrowed(_)),
                matches!(oracle_text, Cow::Borrowed(_)),
                "skip_ascii={skip_ascii} {input:?}"
            );
        }
    }

    #[test]
    fn dispatch_equals_the_plain_walk_for_every_scalar_at_every_block_alignment() {
        // Every governed boundary character plus a stride over the rest, each
        // after ASCII prefixes that put it before, on and past the block
        // edges, followed by ASCII (a removed run must close at the right
        // offset) and by a second removed character.
        let mut characters: Vec<char> = INVISIBLE_RANGES
            .iter()
            .flat_map(|&(first, last)| {
                [
                    first.checked_sub(1),
                    Some(first),
                    Some(last),
                    Some(last + 1),
                ]
            })
            .flatten()
            .filter_map(char::from_u32)
            .collect();
        characters.extend((0..=0x10_FFFF).step_by(251).filter_map(char::from_u32));
        for ch in characters {
            for prefix in 0..=140 {
                let ascii = "x".repeat(prefix);
                assert_dispatch_matches_oracle(&format!("{ascii}{ch}tail-{ZWSP}"));
                assert_dispatch_matches_oracle(&format!("{ascii}{ch}{ZWSP}"));
            }
        }
    }

    #[test]
    fn dispatch_equals_the_plain_walk_on_generated_mixed_text() {
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap()
        };
        let pieces: [&str; 14] = [
            "ordinary request\n",
            "한글 문장",
            "🙂",
            "é",
            "\u{200B}",
            "\u{200C}\u{2060}",
            "\u{E0041}",
            "\u{00AD}",
            "\u{FE0F}",
            "\u{3000}",
            "token_abcdefghijklmnopqrstuvwxyz0123456789",
            " ",
            "\r\n",
            "\u{FFA0}",
        ];
        for _ in 0..4000 {
            let mut input = String::new();
            for _ in 0..(next() % 40) {
                let piece = pieces[next() % pieces.len()];
                for _ in 0..=(next() % 6) {
                    input.push_str(piece);
                }
                if next() % 3 == 0 {
                    input.push_str(&"a".repeat(next() % 200));
                }
                if next() % 25 == 0 {
                    // Long enough to cross walk windows and four-word steps.
                    input.push_str(&"b".repeat(next() % 9000));
                }
            }
            assert_dispatch_matches_oracle(&input);
        }
    }

    #[test]
    fn dispatch_equals_the_plain_walk_around_walk_window_edges() {
        let mixed_dense = "한글🙂é ".repeat(2000);
        for prefix in
            (WALK_WINDOW - 12..=WALK_WINDOW + 12).chain(2 * WALK_WINDOW - 12..=2 * WALK_WINDOW + 12)
        {
            let ascii = "x".repeat(prefix);
            for edge in ["한", "🙂", "é", ZWSP.to_string().as_str(), "a"] {
                assert_dispatch_matches_oracle(&format!("{ascii}{edge}{ZWSP}{ZWNJ}tail"));
                assert_dispatch_matches_oracle(&format!("{ascii}{edge}tail{ZWSP}"));
                assert_dispatch_matches_oracle(&format!("{ZWSP}{ascii}{edge}{ZWNJ}"));
                assert_dispatch_matches_oracle(&format!("{mixed_dense}{ascii}{edge}{ZWSP}x"));
            }
        }
        // A removed run in the middle of dense non-ASCII text, at every
        // alignment of the window.
        for skew in 0..8 {
            let input = format!("{}{ZWSP}{mixed_dense}", "x".repeat(skew));
            assert_dispatch_matches_oracle(&input);
        }
    }

    #[test]
    fn dispatch_handles_the_named_boundary_shapes() {
        let long = "ordinary request processed successfully\n".repeat(40);
        for input in [
            format!("{long}한글"),
            format!("{long}{ZWSP}"),
            format!("{ZWSP}{long}"),
            format!("{long}{ZWSP}{long}"),
            format!("{ZWSP}{ZWNJ}{long}{ZWSP}"),
            format!("한{ZWSP}{long}{ZWSP}한"),
            format!("{long}한{ZWSP}{ZWSP}{long}한"),
            format!("{}{ZWSP}x", "a".repeat(63)),
            format!("{}{ZWSP}x", "a".repeat(64)),
            format!("{}é{ZWSP}x", "a".repeat(63)),
            format!("{}é{ZWSP}x", "a".repeat(62)),
        ] {
            assert_dispatch_matches_oracle(&input);
        }
    }

    #[test]
    fn the_table_is_pinned_to_the_decided_ucd_version() {
        // Bumping the UCD is a decision change: this, the generator's pins,
        // and the ADR move together.
        assert_eq!(UCD_VERSION, "17.0.0");
    }

    #[test]
    fn the_table_is_sorted_disjoint_non_adjacent_and_never_ascii() {
        assert!(INVISIBLE_RANGES.iter().all(|&(first, last)| first <= last));
        assert!(
            INVISIBLE_RANGES
                .windows(2)
                .all(|pair| pair[0].1 + 1 < pair[1].0)
        );
        assert!(INVISIBLE_RANGES[0].0 >= 0x80);
    }

    #[test]
    fn is_invisible_equals_a_linear_table_scan_at_every_code_point() {
        for character in (0..=0x10_FFFF).filter_map(char::from_u32) {
            let code_point = u32::from(character);
            assert_eq!(
                is_invisible(character),
                INVISIBLE_RANGES
                    .iter()
                    .any(|&(first, last)| (first..=last).contains(&code_point)),
                "U+{code_point:04X}"
            );
        }
    }

    #[test]
    fn every_decided_class_is_removed() {
        let classes: [(&str, &[char]); 7] = [
            (
                "zero-width parity set",
                &['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}'],
            ),
            (
                "bidi controls",
                &['\u{061C}', '\u{200E}', '\u{202E}', '\u{2066}', '\u{2069}'],
            ),
            (
                "soft hyphen, CGJ, Mongolian",
                &['\u{00AD}', '\u{034F}', '\u{180E}'],
            ),
            (
                "Hangul fillers",
                &['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}'],
            ),
            (
                "variation selectors",
                &['\u{FE00}', '\u{FE0F}', '\u{E0100}', '\u{E01EF}'],
            ),
            ("tags block", &['\u{E0001}', '\u{E0041}', '\u{E007F}']),
            (
                "Cf added back by the union",
                &['\u{FFF9}', '\u{FFFB}', '\u{13430}', '\u{0600}'],
            ),
        ];
        for (class, members) in classes {
            for &ch in members {
                assert!(is_invisible(ch), "{class}: U+{:04X}", u32::from(ch));
            }
        }
    }

    #[test]
    fn excluded_and_ordinary_code_points_are_kept() {
        let classes: [(&str, &[char]); 5] = [
            (
                "ASCII, controls included",
                &['a', '\n', '\r', '\t', ' ', '\u{7F}'],
            ),
            (
                "renders as space",
                &['\u{00A0}', '\u{2000}', '\u{200A}', '\u{3000}'],
            ),
            ("BRAILLE PATTERN BLANK: blank but `So`", &['\u{2800}']),
            (
                "range neighbours",
                &['\u{00AC}', '\u{00AE}', '\u{2010}', '\u{2070}', '\u{E1000}'],
            ),
            ("ordinary text", &['é', '한', '😀']),
        ];
        for (class, members) in classes {
            for &ch in members {
                assert!(!is_invisible(ch), "{class}: U+{:04X}", u32::from(ch));
            }
        }
    }

    #[test]
    fn ascii_and_clean_non_ascii_input_is_borrowed_with_no_map() {
        for input in ["", "api_key = value", "naïve café 한국어 😀"] {
            let view = NormalizedInput::new(input);
            assert!(matches!(view.text, Cow::Borrowed(_)));
            assert!(view.seams.is_empty());
            assert_eq!(view.text(), input);
        }
        let view = NormalizedInput::new("plain");
        assert_eq!(view.to_original(range(1, 4)), Some(range(1, 4)));
    }

    #[test]
    fn an_interior_run_is_inside_the_translated_span() {
        let input = format!("x=ab{ZWNJ}{ZWSP}cd;");
        let view = NormalizedInput::new(&input);
        assert_eq!(view.text(), "x=abcd;");
        assert_eq!(view.seams.len(), 1);
        assert_eq!(
            selected(&input, &view, range(2, 6)),
            format!("ab{ZWNJ}{ZWSP}cd")
        );
    }

    #[test]
    fn a_run_adjacent_to_either_boundary_is_not_absorbed() {
        let input = format!("x={ZWSP}abcd{ZWSP};");
        let view = NormalizedInput::new(&input);
        assert_eq!(view.text(), "x=abcd;");
        assert_eq!(selected(&input, &view, range(2, 6)), "abcd");
        // The neighbours on each side still translate to themselves.
        assert_eq!(selected(&input, &view, range(0, 2)), "x=");
        assert_eq!(selected(&input, &view, range(6, 7)), ";");
    }

    #[test]
    fn contains_removed_run_matches_the_interior_definition() {
        let input = format!("x=ab{ZWNJ}{ZWSP}cd;");
        let view = NormalizedInput::new(&input);
        assert!(contained(&view, range(2, 6)));
        assert!(!contained(&view, range(0, 2)));
        // The run sits exactly at this range's start, so it is adjacent, not
        // interior.
        assert!(!contained(&view, range(4, 6)));

        let input = format!("x={ZWSP}abcd{ZWSP};");
        let view = NormalizedInput::new(&input);
        // Both runs are adjacent to this range's boundaries, not interior.
        assert!(!contained(&view, range(2, 6)));
        assert!(contained(&view, range(0, 7)));

        let view = NormalizedInput::new("plain");
        assert!(!contained(&view, range(1, 4)));
    }

    #[test]
    fn touches_removed_run_includes_both_boundaries() {
        let input = format!("x={ZWSP}abcd{ZWSP};");
        let view = NormalizedInput::new(&input);
        assert!(view.touches_removed_run(range(2, 6)));
        assert!(view.touches_removed_run(range(0, 2)));
        assert!(view.touches_removed_run(range(6, 7)));
        assert!(!view.touches_removed_run(range(0, 1)));
    }

    #[test]
    fn leading_and_trailing_runs_are_mapped() {
        let input = format!("{ZWSP}ab{ZWNJ}cd{ZWSP}");
        let view = NormalizedInput::new(&input);
        assert_eq!(view.text(), "abcd");
        assert_eq!(view.seams.len(), 3);
        assert_eq!(selected(&input, &view, range(0, 4)), format!("ab{ZWNJ}cd"));
        assert_eq!(selected(&input, &view, range(0, 2)), "ab");
        assert_eq!(selected(&input, &view, range(2, 4)), "cd");
    }

    #[test]
    fn input_made_only_of_removed_code_points_normalizes_to_empty() {
        let input = format!("{ZWSP}{ZWNJ}\u{E0041}");
        let view = NormalizedInput::new(&input);
        assert_eq!(view.text(), "");
        assert_eq!(view.seams.len(), 1);
    }

    #[test]
    fn every_kept_character_translates_to_itself_among_multibyte_neighbours() {
        let input = format!("é{ZWSP}한\u{E0067}😀{ZWNJ}\u{FE0F}z\u{00AD}");
        let view = NormalizedInput::new(&input);
        assert_eq!(view.text(), "é한😀z");
        let text = view.text().to_owned();
        for (offset, ch) in text.char_indices() {
            let normalized = range(offset, offset + ch.len_utf8());
            assert_eq!(selected(&input, &view, normalized), ch.to_string());
        }
    }

    #[test]
    fn into_text_yields_the_scan_copy() {
        let input = format!("api{ZWSP}_key=");
        assert_eq!(NormalizedInput::new(&input).into_text(), "api_key=");
    }
}
