//! Deterministic generators for the differential tests that compare a
//! detector's allocation-free case-insensitive check with the lowercasing
//! implementation it replaced (#1086).
//!
//! State is 32-bit, so the same seed yields the same cases on every target,
//! `wasm32` included, and no index conversion can overflow `usize`.

/// A xorshift32 stream.
pub(crate) struct XorShift32(u32);

impl XorShift32 {
    pub(crate) fn new(seed: u32) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }

    /// A value in `0..bound`; `bound` must be non-zero.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next()).unwrap_or(0) % bound
    }

    /// A string of `0..=max_pieces` pieces drawn from `pieces`.
    pub(crate) fn text(&mut self, pieces: &[&str], max_pieces: usize) -> String {
        let count = self.below(max_pieces + 1);
        (0..count)
            .map(|_| pieces[self.below(pieces.len())])
            .collect()
    }
}

/// Pieces that stress ASCII case folding and character boundaries: mixed and
/// upper case letters, multi-byte characters whose lowercase is not ASCII
/// (`K` Kelvin sign, dotted `I`), combining marks, invisible code points, a
/// line break, and separators.
pub(crate) const BOUNDARY_PIECES: &[&str] = &[
    "a",
    "Z",
    "k",
    "K",
    "\u{212a}",
    "\u{130}",
    "i",
    "I",
    "\u{e9}",
    "\u{c9}",
    "\u{3a3}",
    "\u{1f600}",
    "\u{200b}",
    "\u{feff}",
    "\u{301}",
    "0",
    "9",
    "_",
    "-",
    ".",
    ":",
    "=",
    "\"",
    "'",
    ",",
    "[",
    "]",
    " ",
    "\t",
    "\n",
    "*",
    "x",
    "X",
];
