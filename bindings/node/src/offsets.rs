//! UTF-8 byte offset <-> UTF-16 code-unit offset conversion
//! (`decision-define-runtime-bindings`).
//!
//! JavaScript strings index by UTF-16 code units; the core reports ranges as
//! UTF-8 byte offsets ([`redact_secret::RANGE_UNIT`]). These functions convert
//! between the two without changing the selected span
//! (`decision-govern-cross-language-conformance`).
//!
//! Every conversion over one input goes through a single forward-only
//! [`Utf16Offsets`] (issue #1053): pipeline findings arrive in ascending,
//! disjoint order, so converting a whole call's findings is one pass over the
//! input instead of one prefix rescan per offset.

use redact_secret::{SecretScanError, SecretScanErrorCode};

/// Converts UTF-8 byte offsets into one `text` to UTF-16 code-unit offsets,
/// resuming each conversion from the previous one.
///
/// An offset before the previous one restarts from the beginning of `text`,
/// so any query order is correct; ascending order costs one pass in total.
/// An all-ASCII `text` skips the walk entirely: there, UTF-8 bytes and
/// UTF-16 code units coincide.
pub struct Utf16Offsets<'a> {
    text: &'a str,
    ascii: bool,
    /// A character boundary of `text`, and its UTF-16 offset.
    byte: usize,
    utf16: usize,
    /// Bytes of `text` walked so far, for the linear-cost test.
    #[cfg(test)]
    walked: usize,
}

impl<'a> Utf16Offsets<'a> {
    #[must_use]
    pub fn new(text: &'a str) -> Self {
        Self {
            text,
            ascii: text.is_ascii(),
            byte: 0,
            utf16: 0,
            #[cfg(test)]
            walked: 0,
        }
    }

    /// Converts a UTF-8 byte offset into `text` to the UTF-16 code-unit
    /// offset at the same logical position.
    ///
    /// `byte_offset` is assumed to already be a valid, character-aligned
    /// offset into `text` — every caller in this crate converts offsets the
    /// core pipeline has already validated. An invalid one panics exactly as
    /// the pre-#1053 `text[..byte_offset]` slice did.
    pub fn utf16_at(&mut self, byte_offset: usize) -> u32 {
        let units = if self.ascii {
            // Every offset up to `text.len()` is a character boundary of an
            // ASCII string; the slice keeps the out-of-bounds panic.
            self.text[..byte_offset].len()
        } else {
            if byte_offset < self.byte {
                self.byte = 0;
                self.utf16 = 0;
            }
            self.utf16 += self.text[self.byte..byte_offset]
                .chars()
                .map(char::len_utf16)
                .sum::<usize>();
            #[cfg(test)]
            {
                self.walked += byte_offset - self.byte;
            }
            self.byte = byte_offset;
            self.utf16
        };
        u32::try_from(units).unwrap_or(u32::MAX)
    }
}

/// Converts UTF-16 code-unit offsets supplied by a JavaScript caller back to
/// UTF-8 byte offsets into `text`, in one walk over `text` however many
/// offsets there are and in whatever order they arrive.
///
/// The result has one entry per requested offset, in the requested order:
/// the byte offset, or [`SecretScanErrorCode::InvalidFindings`] when that
/// offset is out of bounds or falls inside a surrogate pair rather than on a
/// code point boundary. Entries are independent, so a caller still reports
/// the first failure in its own order.
#[must_use]
pub fn utf16_offsets_to_bytes(
    text: &str,
    utf16_offsets: &[usize],
) -> Vec<Result<usize, SecretScanError>> {
    let invalid = || Err(SecretScanErrorCode::InvalidFindings.into());
    if text.is_ascii() {
        return utf16_offsets
            .iter()
            .map(|&offset| {
                if offset <= text.len() {
                    Ok(offset)
                } else {
                    invalid()
                }
            })
            .collect();
    }
    let mut order: Vec<usize> = (0..utf16_offsets.len()).collect();
    order.sort_unstable_by_key(|&index| utf16_offsets[index]);
    let mut resolved: Vec<Result<usize, SecretScanError>> = Vec::new();
    resolved.resize_with(utf16_offsets.len(), invalid);
    let mut chars = text.chars();
    // `units` is the UTF-16 offset of the character boundary at `byte`.
    let mut byte = 0usize;
    let mut units = 0usize;
    for index in order {
        let wanted = utf16_offsets[index];
        while units < wanted {
            let Some(ch) = chars.next() else { break };
            units += ch.len_utf16();
            byte += ch.len_utf8();
        }
        if units == wanted {
            resolved[index] = Ok(byte);
        }
    }
    resolved
}

/// The pre-#1053 per-offset conversion, kept as the test oracle for
/// [`Utf16Offsets`].
#[cfg(test)]
pub(crate) fn byte_to_utf16(text: &str, byte_offset: usize) -> u32 {
    let units: usize = text[..byte_offset].chars().map(char::len_utf16).sum();
    u32::try_from(units).unwrap_or(u32::MAX)
}

/// The pre-#1053 per-offset conversion, kept as the test oracle for
/// [`utf16_offsets_to_bytes`].
#[cfg(test)]
pub(crate) fn utf16_to_byte(text: &str, utf16_offset: usize) -> Result<usize, SecretScanError> {
    let mut units = 0usize;
    for (byte_offset, ch) in text.char_indices() {
        if units == utf16_offset {
            return Ok(byte_offset);
        }
        if units > utf16_offset {
            break;
        }
        units += ch.len_utf16();
    }
    if units == utf16_offset {
        return Ok(text.len());
    }
    Err(SecretScanErrorCode::InvalidFindings.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `conformance/fixtures/unicode-conversion-corpus.json` fixture: an
    /// input and the single canonical UTF-8 byte span it declares.
    struct RangeFixture {
        id: String,
        input: String,
        start: usize,
        end: usize,
    }

    /// Reads `conformance/fixtures/unicode-conversion-corpus.json` directly
    /// rather than copying its values into Rust, which
    /// `decision-govern-cross-language-conformance` rejects: "Copying
    /// fixtures into each binding was rejected because copies can diverge."
    fn unicode_conversion_fixtures() -> Vec<RangeFixture> {
        const CORPUS: &str =
            include_str!("../../../conformance/fixtures/unicode-conversion-corpus.json");
        let document: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
        assert_eq!(document["offsetUnit"], "utf8-byte");
        let fixtures = document["fixtures"].as_array().unwrap();
        assert!(!fixtures.is_empty());
        fixtures
            .iter()
            .map(|fixture| {
                let id = fixture["id"].as_str().unwrap().to_owned();
                let expected = fixture["expected"].as_array().unwrap();
                assert_eq!(expected.len(), 1, "{id}: expected exactly one expectation");
                RangeFixture {
                    input: fixture["input"].as_str().unwrap().to_owned(),
                    start: usize::try_from(expected[0]["start"].as_u64().unwrap()).unwrap(),
                    end: usize::try_from(expected[0]["end"].as_u64().unwrap()).unwrap(),
                    id,
                }
            })
            .collect()
    }

    /// An astral (supplementary-plane) character positioned before, within,
    /// and after a finding's UTF-8 byte span, asserting the same canonical
    /// `start`/`end` byte offsets convert to the UTF-16 code-unit offsets
    /// every JavaScript consumer of this binding actually sees, checked
    /// against `str::encode_utf16`'s count -- an independent reference
    /// conversion, not `byte_to_utf16` under test.
    #[test]
    fn unicode_conversion_corpus_converts_to_utf16_offsets() {
        for fixture in unicode_conversion_fixtures() {
            for byte_offset in [fixture.start, fixture.end] {
                let count = fixture.input[..byte_offset].encode_utf16().count();
                let reference = u32::try_from(count).unwrap();
                assert_eq!(
                    byte_to_utf16(&fixture.input, byte_offset),
                    reference,
                    "{}",
                    fixture.id,
                );
            }
        }
    }

    #[test]
    fn round_trips_through_both_conversions() {
        let input = "TOKEN_\u{1F511}_SYNTHETIC_REVOKED";
        for byte_offset in [0, 6, 10, 28] {
            let utf16 = byte_to_utf16(input, byte_offset);
            assert_eq!(
                utf16_to_byte(input, utf16 as usize).unwrap(),
                byte_offset,
                "byte_offset={byte_offset}"
            );
        }
    }

    #[test]
    fn rejects_a_utf16_offset_that_splits_a_surrogate_pair() {
        let input = "\u{1F511}key";
        // The astral character occupies UTF-16 code units 0 and 1 (a
        // surrogate pair); offset 1 lands inside it.
        assert!(utf16_to_byte(input, 1).is_err());
        assert_eq!(utf16_to_byte(input, 2).unwrap(), 4);
    }

    #[test]
    fn rejects_an_out_of_bounds_utf16_offset() {
        assert!(utf16_to_byte("abc", 4).is_err());
        assert!(utf16_offsets_to_bytes("abc", &[4])[0].is_err());
        assert!(utf16_offsets_to_bytes("\u{1F511}", &[3])[0].is_err());
    }

    /// Deterministic generated inputs: ASCII-only, BMP, astral (surrogate
    /// pairs in UTF-16), invisible code points, and the empty string.
    fn generated_inputs() -> Vec<String> {
        const POOL: [char; 10] = [
            'a',
            'Z',
            '\n',
            '\u{E9}',
            '\u{4E2D}',
            '\u{1F511}',
            '\u{200B}',
            '\u{FEFF}',
            '\u{E0041}',
            '\u{AD}',
        ];
        let mut inputs = vec![String::new(), "a".to_owned(), "abc def".to_owned()];
        inputs.extend(
            unicode_conversion_fixtures()
                .into_iter()
                .map(|fixture| fixture.input),
        );
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for length in 0..48 {
            for ascii_only in [false, true] {
                let mut input = String::new();
                for _ in 0..length {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let pick = usize::try_from(state >> 33).unwrap();
                    let pool = if ascii_only { 3 } else { POOL.len() };
                    input.push(POOL[pick % pool]);
                }
                inputs.push(input);
            }
        }
        inputs
    }

    /// A deterministic, repeating, non-monotonic permutation of `values`.
    fn scrambled(values: &[usize]) -> Vec<usize> {
        let mut out: Vec<usize> = values
            .iter()
            .enumerate()
            .map(|(index, _)| values[(index * 7 + 3) % values.len()])
            .collect();
        out.extend(values.iter().rev().copied());
        out.extend(values.iter().copied());
        out
    }

    #[test]
    fn forward_converter_matches_the_per_offset_oracle_in_any_order() {
        for input in generated_inputs() {
            let boundaries: Vec<usize> = (0..=input.len())
                .filter(|&offset| input.is_char_boundary(offset))
                .collect();
            let mut converter = Utf16Offsets::new(&input);
            for &offset in boundaries.iter().chain(scrambled(&boundaries).iter()) {
                assert_eq!(
                    converter.utf16_at(offset),
                    byte_to_utf16(&input, offset),
                    "{input:?} {offset}"
                );
            }
        }
    }

    #[test]
    fn forward_converter_walks_each_byte_once_for_ascending_offsets() {
        let input = "a\u{1F511}\u{E9}\u{4E2D}b\u{200B}".repeat(64);
        let mut converter = Utf16Offsets::new(&input);
        for offset in (0..=input.len()).filter(|&offset| input.is_char_boundary(offset)) {
            converter.utf16_at(offset);
            converter.utf16_at(offset);
        }
        assert_eq!(converter.walked, input.len());
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn forward_converter_keeps_the_out_of_bounds_panic_for_ascii() {
        Utf16Offsets::new("abc").utf16_at(4);
    }

    #[test]
    fn batched_utf16_to_byte_matches_the_per_offset_oracle() {
        for input in generated_inputs() {
            let utf16_len = input.encode_utf16().count();
            let offsets: Vec<usize> = (0..=utf16_len + 2).collect();
            for queries in [offsets.clone(), scrambled(&offsets), Vec::new()] {
                let batched = utf16_offsets_to_bytes(&input, &queries);
                assert_eq!(batched.len(), queries.len());
                for (query, result) in queries.iter().zip(&batched) {
                    assert_eq!(
                        result.map_err(SecretScanError::code),
                        utf16_to_byte(&input, *query).map_err(SecretScanError::code),
                        "{input:?} {query}"
                    );
                }
            }
        }
    }
}
