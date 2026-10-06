//! Bounded input: a streaming UTF-8 decoder and a bounded whole-file read.
//!
//! Both fail closed. A byte sequence that is not valid UTF-8 stops the run
//! with [`Failure::NotUtf8`] and is dropped rather than reported, and a
//! source larger than [`MAX_INPUT_BYTES`] stops the run with the core's
//! `INPUT_LIMIT_EXCEEDED` code instead of being scanned in part.

use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use redact_secret::SecretScanErrorCode;

use crate::failure::Failure;
use crate::limits::MAX_INPUT_BYTES;

/// The longest incomplete trailing UTF-8 sequence a decoder can carry.
const MAX_CARRY_BYTES: usize = 3;

/// Decodes a byte stream that arrives in arbitrary chunks.
///
/// A multi-byte character may straddle any chunk boundary, so an incomplete
/// trailing sequence is carried into the next chunk instead of being rejected.
/// A sequence that is genuinely invalid is rejected as soon as it is seen.
#[derive(Debug, Default)]
pub struct Utf8Stream {
    carry: Vec<u8>,
}

impl Utf8Stream {
    /// Creates a decoder with nothing carried.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes `chunk`, returning every complete character it completes.
    ///
    /// When nothing is carried, the complete prefix of `chunk` is handed on
    /// borrowed and only an incomplete trailing sequence (at most
    /// [`MAX_CARRY_BYTES`] bytes) is copied into the carry. Only a chunk that
    /// follows a carried sequence is copied, once, and its text is moved out
    /// of that buffer rather than copied again.
    ///
    /// # Errors
    ///
    /// Returns [`Failure::NotUtf8`] when `chunk` contains a sequence that no
    /// continuation can complete.
    pub fn push<'a>(&mut self, chunk: &'a [u8]) -> Result<Cow<'a, str>, Failure> {
        if self.carry.is_empty() {
            let valid_up_to = match std::str::from_utf8(chunk) {
                Ok(text) => return Ok(Cow::Borrowed(text)),
                Err(error) if error.error_len().is_none() => error.valid_up_to(),
                Err(_) => return Err(Failure::NotUtf8),
            };
            let (complete, incomplete) = chunk.split_at(valid_up_to);
            if incomplete.len() > MAX_CARRY_BYTES {
                return Err(Failure::NotUtf8);
            }
            let text = std::str::from_utf8(complete).map_err(|_| Failure::NotUtf8)?;
            self.carry.extend_from_slice(incomplete);
            return Ok(Cow::Borrowed(text));
        }

        let mut buffer = std::mem::take(&mut self.carry);
        buffer.extend_from_slice(chunk);
        let valid_up_to = match std::str::from_utf8(&buffer) {
            Ok(_) => buffer.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(Failure::NotUtf8),
        };
        if buffer.len() - valid_up_to > MAX_CARRY_BYTES {
            return Err(Failure::NotUtf8);
        }
        self.carry = buffer.split_off(valid_up_to);
        // `buffer` now holds exactly the validated prefix, so this moves it.
        String::from_utf8(buffer)
            .map(Cow::Owned)
            .map_err(|_| Failure::NotUtf8)
    }

    /// Asserts that the stream ended on a character boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Failure::NotUtf8`] when the last chunk ended mid-sequence:
    /// at end of input an incomplete sequence is simply invalid.
    pub fn finish(&self) -> Result<(), Failure> {
        if self.carry.is_empty() {
            Ok(())
        } else {
            Err(Failure::NotUtf8)
        }
    }
}

/// Reads `path` whole, bounded by [`MAX_INPUT_BYTES`] and decoded as UTF-8.
///
/// The file is opened for reading only. No mode writes to its input.
///
/// # Errors
///
/// - [`Failure::ReadFailed`] when the file cannot be opened or read.
/// - `INPUT_LIMIT_EXCEEDED` when the file is larger than
///   [`MAX_INPUT_BYTES`]. The bound is applied to the bytes actually read,
///   not to reported metadata, so a file that grows during the read is still
///   rejected.
/// - [`Failure::NotUtf8`] when the bytes are not valid UTF-8.
pub fn read_file_text(path: &Path) -> Result<String, Failure> {
    let file = File::open(path).map_err(|_| Failure::ReadFailed)?;
    read_bounded_text(file, MAX_INPUT_BYTES)
}

/// Reads `path` whole as raw bytes, bounded by [`MAX_INPUT_BYTES`] — the
/// same generous cap [`read_file_text`] applies, well above the core's own
/// tighter ruleset size bound. Unlike [`read_file_text`], this never
/// decodes: the core, not the CLI, validates a `--ruleset` file's UTF-8 and
/// grammar (`redact_secret::load_ruleset`).
///
/// # Errors
///
/// The same failures as [`read_file_text`], minus [`Failure::NotUtf8`].
pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>, Failure> {
    let file = File::open(path).map_err(|_| Failure::ReadFailed)?;
    read_bounded_bytes(file, MAX_INPUT_BYTES)
}

/// Reads an action policy file, never more than
/// [`redact_secret::MAX_ACTION_POLICY_BYTES`] plus one byte. The extra byte is
/// what lets the core, not the CLI, report `ACTION_POLICY_TOO_LARGE` for a file
/// over the bound, so the size rule exists in one place and a huge or endless
/// file is never held in memory.
///
/// # Errors
///
/// [`Failure::ReadFailed`] when the file cannot be opened or read.
pub fn read_action_policy_bytes(path: &Path) -> Result<Vec<u8>, Failure> {
    let file = File::open(path).map_err(|_| Failure::ReadFailed)?;
    let ceiling = u64::try_from(redact_secret::MAX_ACTION_POLICY_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(ceiling)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::ReadFailed)?;
    Ok(bytes)
}

/// Reads `reader` to the end, bounded by `max_bytes` and decoded as UTF-8.
///
/// # Errors
///
/// The same failures as [`read_file_text`], against `max_bytes`.
fn read_bounded_text(reader: impl Read, max_bytes: usize) -> Result<String, Failure> {
    let bytes = read_bounded_bytes(reader, max_bytes)?;
    // The `FromUtf8Error` owns the undecodable bytes; discarding it here is
    // what keeps them out of the diagnostic.
    String::from_utf8(bytes).map_err(|_| Failure::NotUtf8)
}

/// Reads `reader` to the end, bounded by `max_bytes`.
///
/// The reader is capped at one byte past the bound, so exceeding it is
/// observable without ever holding more than the bound plus that byte.
///
/// # Errors
///
/// [`Failure::ReadFailed`] when the read itself fails, and
/// `INPUT_LIMIT_EXCEEDED` when more than `max_bytes` were read.
fn read_bounded_bytes(reader: impl Read, max_bytes: usize) -> Result<Vec<u8>, Failure> {
    let ceiling = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut reader = reader.take(ceiling.saturating_add(1));

    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::ReadFailed)?;
    if bytes.len() > max_bytes {
        return Err(Failure::Core(SecretScanErrorCode::InputLimitExceeded));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-#1088 decoder, kept as the oracle the fast path must match.
    #[derive(Default)]
    struct OracleStream {
        carry: Vec<u8>,
    }

    impl OracleStream {
        fn push(&mut self, chunk: &[u8]) -> Result<String, Failure> {
            let mut buffer = std::mem::take(&mut self.carry);
            buffer.extend_from_slice(chunk);
            let valid_up_to = match std::str::from_utf8(&buffer) {
                Ok(text) => return Ok(text.to_owned()),
                Err(error) if error.error_len().is_none() => error.valid_up_to(),
                Err(_) => return Err(Failure::NotUtf8),
            };
            let (complete, incomplete) = buffer.split_at(valid_up_to);
            if incomplete.len() > MAX_CARRY_BYTES {
                return Err(Failure::NotUtf8);
            }
            let text = std::str::from_utf8(complete)
                .map_err(|_| Failure::NotUtf8)?
                .to_owned();
            self.carry = incomplete.to_vec();
            Ok(text)
        }

        fn finish(&self) -> Result<(), Failure> {
            if self.carry.is_empty() {
                Ok(())
            } else {
                Err(Failure::NotUtf8)
            }
        }
    }

    /// Fixed-seed xorshift64*; every draw is reduced in `u32` so the
    /// generators behave identically on 32-bit `usize` targets.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        /// A value in `0..bound` (`bound` > 0, below 2^16).
        fn below(&mut self, bound: u32) -> usize {
            let draw = u32::try_from(self.next() >> 40).unwrap_or(0) % bound;
            usize::try_from(draw).unwrap_or(0)
        }
    }

    const FRAGMENTS: [&[u8]; 12] = [
        b"a",
        b"token ",
        b"\n",
        "\u{00e9}".as_bytes(),
        "\u{20ac}".as_bytes(),
        "\u{1f511}".as_bytes(),
        b"\xe2\x82",
        b"\xf0\x9f",
        b"\xc3",
        b"\xff",
        b"\x80",
        b"\xed\xa0\x80",
    ];

    fn run_new(input: &[u8], cuts: &[usize]) -> (Result<String, Failure>, Result<(), Failure>) {
        let mut decoder = Utf8Stream::new();
        let mut seen = String::new();
        let mut start = 0;
        for &end in cuts.iter().chain(std::iter::once(&input.len())) {
            match decoder.push(&input[start..end]) {
                Ok(text) => seen.push_str(&text),
                Err(failure) => return (Err(failure), Err(failure)),
            }
            start = end;
        }
        (Ok(seen), decoder.finish())
    }

    fn run_old(input: &[u8], cuts: &[usize]) -> (Result<String, Failure>, Result<(), Failure>) {
        let mut decoder = OracleStream::default();
        let mut seen = String::new();
        let mut start = 0;
        for &end in cuts.iter().chain(std::iter::once(&input.len())) {
            match decoder.push(&input[start..end]) {
                Ok(text) => seen.push_str(&text),
                Err(failure) => return (Err(failure), Err(failure)),
            }
            start = end;
        }
        (Ok(seen), decoder.finish())
    }

    #[test]
    fn the_fast_path_matches_the_old_decoder_on_random_chunkings() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..4000 {
            let mut input = Vec::new();
            for _ in 0..rng.below(12) {
                input.extend_from_slice(FRAGMENTS[rng.below(12)]);
            }
            let mut cuts: Vec<usize> = (0..rng.below(8))
                .map(|_| rng.below(u32::try_from(input.len() + 1).unwrap_or(1)))
                .collect();
            cuts.sort_unstable();
            assert_eq!(run_new(&input, &cuts), run_old(&input, &cuts));
        }
    }

    #[test]
    fn a_valid_input_split_at_every_offset_decodes_unchanged() {
        let input = "a\u{00e9}\u{20ac}\u{1f511}z".as_bytes();
        for first in 0..=input.len() {
            for second in first..=input.len() {
                let cuts = [first, second];
                assert_eq!(run_new(input, &cuts), run_old(input, &cuts));
                assert_eq!(
                    run_new(input, &cuts).0.as_deref(),
                    Ok("a\u{00e9}\u{20ac}\u{1f511}z")
                );
            }
        }
    }

    #[test]
    fn empty_chunks_and_a_truncated_tail_match_the_old_decoder() {
        let input = [b'a', 0xe2, 0x82];
        for cuts in [&[][..], &[0], &[1, 1], &[2], &[3]] {
            assert_eq!(run_new(&input, cuts), run_old(&input, cuts));
        }
        assert_eq!(run_new(&input, &[]).1, Err(Failure::NotUtf8));
    }

    #[test]
    fn a_chunk_with_nothing_carried_is_handed_on_borrowed() {
        let mut decoder = Utf8Stream::new();
        let chunk = "ab\u{20ac}".as_bytes();
        assert!(matches!(
            decoder.push(chunk),
            Ok(Cow::Borrowed("ab\u{20ac}"))
        ));
        let split = "x\u{20ac}".as_bytes();
        let head = decoder.push(&split[..2]).unwrap();
        assert!(
            matches!(head, Cow::Borrowed(_)),
            "the complete prefix must stay borrowed"
        );
        assert_eq!(head, "x");
        assert_eq!(decoder.push(&split[2..]).unwrap(), "\u{20ac}");
    }

    #[test]
    fn a_character_split_across_chunks_is_carried() {
        let mut decoder = Utf8Stream::new();
        let key = "\u{1f511}".as_bytes();
        assert_eq!(decoder.push(&key[..2]).unwrap(), "");
        assert_eq!(decoder.push(&key[2..]).unwrap(), "\u{1f511}");
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn a_chunk_boundary_does_not_split_a_reported_character() {
        let mut decoder = Utf8Stream::new();
        let input = "ab\u{00e9}cd";
        let mut seen = String::new();
        for byte in input.as_bytes() {
            seen.push_str(&decoder.push(std::slice::from_ref(byte)).unwrap());
        }
        decoder.finish().unwrap();
        assert_eq!(seen, input);
    }

    #[test]
    fn an_invalid_sequence_fails_closed() {
        let mut decoder = Utf8Stream::new();
        assert_eq!(decoder.push(&[0xff, 0xfe]), Err(Failure::NotUtf8));
    }

    #[test]
    fn a_continuation_that_never_arrives_fails_closed() {
        let mut decoder = Utf8Stream::new();
        assert_eq!(decoder.push(&[0xe2, 0x82]).unwrap(), "");
        assert_eq!(decoder.finish(), Err(Failure::NotUtf8));
    }

    #[test]
    fn a_source_at_the_bound_is_read_whole() {
        let text = read_bounded_text(&b"abcde"[..], 5).unwrap();
        assert_eq!(text, "abcde");
    }

    #[test]
    fn a_source_past_the_bound_is_rejected_rather_than_read_in_part() {
        assert_eq!(
            read_bounded_text(&b"abcdef"[..], 5),
            Err(Failure::Core(SecretScanErrorCode::InputLimitExceeded))
        );
    }

    #[test]
    fn a_whole_file_read_decodes_and_fails_closed_on_bad_bytes() {
        assert_eq!(
            read_bounded_text(&[0x41u8, 0xff][..], 64),
            Err(Failure::NotUtf8)
        );
    }

    #[test]
    fn a_decoding_failure_carries_no_input() {
        let failure = Failure::NotUtf8;
        assert_eq!(failure.code(), "NOT_UTF8");
        assert_eq!(failure.message(), "Input is not valid UTF-8.");
    }
}
