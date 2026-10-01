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

/// One maximal run of removed code points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seam {
    /// Offset in the scan copy at which the run was removed.
    normalized: usize,
    /// Offset in the original input just after the run.
    original_after: usize,
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
        let borrowed = Self {
            text: Cow::Borrowed(input),
            seams: Vec::new(),
        };
        // No removed code point is ASCII, so the common case is settled by
        // one vectorizable pass with no allocation.
        if input.is_ascii() {
            return borrowed;
        }
        let Some(first_removed) = input
            .char_indices()
            .find_map(|(offset, ch)| is_invisible(ch).then_some(offset))
        else {
            return borrowed;
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

    /// Median nanoseconds per call of `f`, over `samples` batches of `reps`.
    fn median_ns(samples: usize, reps: usize, mut f: impl FnMut() -> usize) -> f64 {
        use std::hint::black_box;
        use std::time::Instant;
        let mut times: Vec<f64> = (0..samples)
            .map(|_| {
                let started = Instant::now();
                for _ in 0..reps {
                    black_box(f());
                }
                started.elapsed().as_secs_f64() * 1e9 / reps as f64
            })
            .collect();
        times.sort_by(f64::total_cmp);
        times[times.len() / 2]
    }

    /// Stage measurement for #1133 (maintainer-only):
    /// `cargo test --release -p redact-secret --lib -- --ignored --nocapture measure_translate`.
    /// Translates 4,096 ranges per call with the old pair of searches and the
    /// fused one, alternating A/B.
    #[test]
    #[ignore = "timing harness, run with --release --nocapture"]
    fn measure_translate_1133() {
        use std::hint::black_box;
        for (name, text) in [
            ("no-seams", "a".repeat(32_768)),
            ("4096-seams", format!("ab{ZWSP}cdEFGH").repeat(4096)),
        ] {
            let view = NormalizedInput::new(&text);
            let ranges: Vec<ByteRange> = (0..4096)
                .map(|i| {
                    let start = i * 7 % (view.text().len() - 8);
                    range(start, start + 8)
                })
                .collect();
            let old = || {
                let mut sum = 0;
                for &r in black_box(&ranges) {
                    let original = black_box(oracle_to_original(&view, r).unwrap());
                    let interior = black_box(oracle_contains_removed_run(&view, r));
                    sum += original.start() + original.end() + usize::from(interior);
                }
                sum
            };
            let fused = || {
                let mut sum = 0;
                for &r in black_box(&ranges) {
                    let (original, interior) = black_box(view.translate(r).unwrap());
                    sum += original.start() + original.end() + usize::from(interior);
                }
                sum
            };
            assert_eq!(old(), fused());
            let (mut olds, mut news) = (Vec::new(), Vec::new());
            for round in 0..15 {
                if round % 2 == 0 {
                    olds.push(median_ns(1, 200, old));
                    news.push(median_ns(1, 200, fused));
                } else {
                    news.push(median_ns(1, 200, fused));
                    olds.push(median_ns(1, 200, old));
                }
            }
            olds.sort_by(f64::total_cmp);
            news.sort_by(f64::total_cmp);
            eprintln!(
                "{name}: {:.1} -> {:.1} us per 4096 ranges ({:+.1}%)",
                olds[7] / 1e3,
                news[7] / 1e3,
                (news[7] / olds[7] - 1.0) * 100.0
            );
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
