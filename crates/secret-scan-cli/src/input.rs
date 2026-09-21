//! Bounded input: a streaming UTF-8 decoder and a bounded whole-file read.
//!
//! Both fail closed. A byte sequence that is not valid UTF-8 stops the run
//! with [`Failure::NotUtf8`] and is dropped rather than reported, and a
//! source larger than [`MAX_INPUT_BYTES`] stops the run with the core's
//! `INPUT_LIMIT_EXCEEDED` code instead of being scanned in part.

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
    /// # Errors
    ///
    /// Returns [`Failure::NotUtf8`] when `chunk` contains a sequence that no
    /// continuation can complete.
    pub fn push(&mut self, chunk: &[u8]) -> Result<String, Failure> {
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
