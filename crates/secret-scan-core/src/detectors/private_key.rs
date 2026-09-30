//! PEM private-key delimiter parser.
//!
//! Complete, well-paired blocks require encoded body evidence. Nested,
//! repeated, or mismatched supported delimiters produce one conservative
//! candidate from the outermost header through resolution, or through end of
//! input when the delimiter stack never resolves. This prevents an inner
//! block from winning overlap resolution while surrounding key material is
//! left behind. A lone incomplete header is ignored so prose fragments are
//! not classified as a key. This mirrors `src/detectors/private-key.ts`
//! (`decision-govern-cross-language-conformance`).

use crate::detectors::prefilter::Literals;
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const LABELS: [&str; 6] = [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "DSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum DelimiterKind {
    Begin,
    End,
}

struct Delimiter {
    start: usize,
    end: usize,
    kind: DelimiterKind,
    label: usize,
}

/// The start of every `BEGIN` delimiter [`find_next_delimiter`] accepts.
const DELIMITER_BEGIN: &str = "-----BEGIN ";
/// The start of every `END` delimiter [`find_next_delimiter`] accepts.
const DELIMITER_END: &str = "-----END ";

/// Finds the next `-----BEGIN <label>-----` / `-----END <label>-----`
/// delimiter at or after `from`, scanning one byte at a time. `label` is an
/// index into [`LABELS`].
fn find_next_delimiter(input: &str, from: usize) -> Option<Delimiter> {
    let bytes = input.as_bytes();
    let mut position = from;
    // Every delimiter starts with `-`: jump between dashes (issue #1074).
    while let Some(offset) = bytes.get(position..)?.iter().position(|&byte| byte == b'-') {
        position += offset;
        if position + 5 > bytes.len() {
            return None;
        }
        if &bytes[position..position + 5] == b"-----" {
            for (kind, lead) in [
                (DelimiterKind::Begin, DELIMITER_BEGIN),
                (DelimiterKind::End, DELIMITER_END),
            ] {
                if bytes[position..].starts_with(lead.as_bytes()) {
                    let label_start = position + lead.len();
                    for (label, name) in LABELS.iter().enumerate() {
                        let label_end = label_start + name.len();
                        let suffix_end = label_end + 5;
                        if suffix_end <= bytes.len()
                            && bytes[label_start..label_end] == *name.as_bytes()
                            && bytes[label_end..suffix_end] == *b"-----"
                        {
                            return Some(Delimiter {
                                start: position,
                                end: suffix_end,
                                kind,
                                label,
                            });
                        }
                    }
                }
            }
        }
        position += 1;
    }
    None
}

/// Delimiter-stack state carried across a full scan of the input.
struct ParserState {
    stack: Vec<usize>,
    /// `true` once any `BEGIN` delimiter has been seen. Unused by
    /// [`PrivateKeyDetector::detect`], which discards its state after one
    /// scan; read by [`PrivateKeyRetentionTracker`] to decide whether
    /// retained plaintext is bound by the multiline limit instead of the
    /// token limit.
    has_begin: bool,
    malformed: bool,
    outer_start: Option<usize>,
    outer_body_start: Option<usize>,
}

impl ParserState {
    const fn new() -> Self {
        Self {
            stack: Vec::new(),
            has_begin: false,
            malformed: false,
            outer_start: None,
            outer_body_start: None,
        }
    }
}

struct CompletedSpan {
    start: usize,
    body_start: usize,
    footer_start: usize,
    end: usize,
    malformed: bool,
}

/// Advances `state` past one delimiter, returning the completed span once the
/// stack unwinds back to empty.
fn process_delimiter(state: &mut ParserState, delimiter: &Delimiter) -> Option<CompletedSpan> {
    if delimiter.kind == DelimiterKind::Begin {
        state.has_begin = true;
        if state.stack.is_empty() {
            state.outer_start = Some(delimiter.start);
            state.outer_body_start = Some(delimiter.end);
        } else {
            state.malformed = true;
        }
        state.stack.push(delimiter.label);
        return None;
    }

    let &top = state.stack.last()?;
    if top != delimiter.label {
        state.malformed = true;
        return None;
    }
    state.stack.pop();
    if !state.stack.is_empty() {
        return None;
    }

    let start = state.outer_start?;
    let body_start = state.outer_body_start?;
    let completed = CompletedSpan {
        start,
        body_start,
        footer_start: delimiter.start,
        end: delimiter.end,
        malformed: state.malformed,
    };
    state.malformed = false;
    state.outer_start = None;
    state.outer_body_start = None;
    Some(completed)
}

/// `true` when `input[start..end]` (with CR and LF ignored) contains a run of
/// at least 16 consecutive base64-alphabet bytes.
fn has_encoded_body(input: &str, start: usize, end: usize) -> bool {
    let mut run_length = 0u32;
    for &byte in &input.as_bytes()[start..end] {
        if byte == b'\n' || byte == b'\r' {
            continue;
        }
        if byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' {
            run_length += 1;
            if run_length >= 16 {
                return true;
            }
        } else {
            run_length = 0;
        }
    }
    false
}

/// Builds the candidate for a span, or `None` when `start == end` (never the
/// case for a delimiter-bounded span, but the pipeline validates ranges
/// rather than this detector trusting its own arithmetic).
fn candidate(start: usize, end: usize, malformed: bool) -> Option<Candidate> {
    let range = ByteRange::new(start, end)?;
    let signals: [&str; 2] = if malformed {
        ["pem-boundaries", "malformed-delimiters"]
    } else {
        ["pem-boundaries", "encoded-body"]
    };
    Some(
        Candidate::new("private_key", Confidence::High, range)
            .with_specificity(Specificity::PrivateKey)
            .with_signals(signals),
    )
}

/// `"-----BEGIN ".len() + longest label + "-----".len()"`: the longest
/// possible supported delimiter.
const fn max_label_len() -> usize {
    let mut max = 0;
    let mut index = 0;
    while index < LABELS.len() {
        let len = LABELS[index].len();
        if len > max {
            max = len;
        }
        index += 1;
    }
    max
}

const MAX_DELIMITER_LEN: usize = "-----BEGIN ".len() + max_label_len() + "-----".len();

/// The longest suffix of `input` that is at most `max_bytes` long and starts
/// on a UTF-8 character boundary. The returned suffix may be shorter than
/// `max_bytes` when the exact cut point falls inside a multi-byte character;
/// every supported delimiter is pure ASCII, so trimming a little further
/// into an unrelated character never drops part of a delimiter.
fn byte_suffix(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut start = input.len() - max_bytes;
    while !input.is_char_boundary(start) {
        start += 1;
    }
    &input[start..]
}

/// How many leading bytes of `piece` a delimiter that starts in the
/// lookbehind can reach into, rounded up to a character boundary.
fn junction_head_len(piece: &str) -> usize {
    let mut head = piece.len().min(MAX_DELIMITER_LEN - 1);
    while !piece.is_char_boundary(head) {
        head += 1;
    }
    head
}

/// Scans `input` from `from` for delimiters, advancing `state` and reporting
/// completed spans, while skipping any delimiter already accounted for by
/// `processed_bytes` (one already scanned in an earlier call whose text was
/// carried forward only as lookbehind). `input_offset` converts positions
/// local to `input` to positions absolute in the logical session input.
/// Returns where the search ended: the end of the last delimiter found
/// (skipped ones included), or `from` when it found none.
fn scan_delimiters(
    input: &str,
    from: usize,
    state: &mut ParserState,
    processed_bytes: usize,
    input_offset: usize,
    mut on_complete: impl FnMut(CompletedSpan),
) -> usize {
    let mut position = from;
    while let Some(delimiter) = find_next_delimiter(input, position) {
        position = delimiter.end;
        let absolute_end = input_offset + delimiter.end;
        if absolute_end <= processed_bytes {
            continue;
        }
        let absolute = Delimiter {
            start: input_offset + delimiter.start,
            end: absolute_end,
            kind: delimiter.kind,
            label: delimiter.label,
        };
        if let Some(span) = process_delimiter(state, &absolute) {
            on_complete(span);
        }
    }
    position
}

/// Tracks the supported PEM delimiter grammar incrementally for the
/// built-in incremental scanner. Each [`append`](Self::append) rescans only
/// a bounded lookbehind window plus the newly appended text, so chunk
/// boundaries and repeated headers never cause previously retained prefixes
/// to be rescanned. Mirrors `createPrivateKeyRetentionTracker` in
/// `src/detectors/private-key.ts` (`decision-govern-cross-language-conformance`).
pub(crate) struct PrivateKeyRetentionTracker {
    state: ParserState,
    processed_bytes: usize,
    lookbehind: String,
}

impl PrivateKeyRetentionTracker {
    /// Creates a tracker with no retained state.
    pub(crate) const fn new() -> Self {
        Self {
            state: ParserState::new(),
            processed_bytes: 0,
            lookbehind: String::new(),
        }
    }

    /// Advances past `piece`. Returns `(has_begin, has_open)`: whether any
    /// `BEGIN` delimiter has been seen since the last [`reset`](Self::reset),
    /// and whether a block is currently open (an unresolved `BEGIN` remains
    /// on the delimiter stack).
    ///
    /// The first piece after a [`reset`](Self::reset), which is every piece
    /// of a unit that arrives as one line, is scanned in place: with no
    /// lookbehind there is nothing to join it to. `lookbehind` only ever
    /// holds a bounded delimiter suffix, and its allocation is reused for the
    /// next one instead of reallocated (issue #1060).
    pub(crate) fn append(&mut self, piece: &str) -> (bool, bool) {
        self.append_reporting(piece, |_| {})
    }

    /// [`append`](Self::append), also reporting every span it completes.
    fn append_reporting(
        &mut self,
        piece: &str,
        mut on_complete: impl FnMut(CompletedSpan),
    ) -> (bool, bool) {
        let lookbehind_len = self.lookbehind.len();
        if lookbehind_len == 0 {
            // Nothing to join the piece to: scan it in place.
            scan_delimiters(
                piece,
                0,
                &mut self.state,
                self.processed_bytes,
                self.processed_bytes,
                on_complete,
            );
            self.processed_bytes += piece.len();
            self.set_lookbehind_from(piece);
            return (self.state.has_begin, !self.state.stack.is_empty());
        }

        // Only a delimiter that starts in the lookbehind can cross into the
        // piece, and it is at most `MAX_DELIMITER_LEN - 1` bytes into it. So
        // the junction, the lookbehind and that head of the piece, is
        // scanned joined, in the lookbehind's own allocation, and the rest
        // of the piece in place, from where the junction scan stopped.
        // A delimiter is matched by its own bytes alone, so this finds
        // exactly the delimiters, in the order, of scanning the whole join
        // (issue #1087).
        let head = junction_head_len(piece);
        self.lookbehind.push_str(&piece[..head]);
        let resume = scan_delimiters(
            &self.lookbehind,
            0,
            &mut self.state,
            self.processed_bytes,
            self.processed_bytes - lookbehind_len,
            &mut on_complete,
        );
        if head < piece.len() {
            scan_delimiters(
                piece,
                resume.saturating_sub(lookbehind_len),
                &mut self.state,
                self.processed_bytes,
                self.processed_bytes,
                on_complete,
            );
            self.lookbehind.clear();
            self.processed_bytes += piece.len();
            self.set_lookbehind_from(piece);
        } else {
            // The join is the whole input: its delimiter-bearing suffix is
            // the next lookbehind, trimmed in place.
            self.processed_bytes += piece.len();
            let keep = byte_suffix(&self.lookbehind, MAX_DELIMITER_LEN.saturating_sub(1));
            let from = self.lookbehind.len() - keep.len();
            let from = from + keep.find('-').unwrap_or(keep.len());
            self.lookbehind.drain(..from);
        }
        (self.state.has_begin, !self.state.stack.is_empty())
    }

    /// Replaces the lookbehind with the delimiter-bearing suffix of `input`,
    /// reusing its allocation. Every delimiter starts with `-`, so nothing
    /// before the suffix's first dash can be part of one; `input_offset`
    /// stays `processed_bytes - lookbehind.len()` (issue #1074).
    fn set_lookbehind_from(&mut self, input: &str) {
        let suffix = byte_suffix(input, MAX_DELIMITER_LEN.saturating_sub(1));
        let suffix = suffix.find('-').map_or("", |dash| &suffix[dash..]);
        self.lookbehind.clear();
        self.lookbehind.push_str(suffix);
    }

    /// Discards all retained parser state.
    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Recognizes complete and fail-safe malformed PEM private-key blocks.
pub struct PrivateKeyDetector;

impl Detector for PrivateKeyDetector {
    fn id(&self) -> &'static str {
        "private-key"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        let mut state = ParserState::new();
        let mut position = 0;

        while let Some(delimiter) = find_next_delimiter(input, position) {
            position = delimiter.end;
            if let Some(span) = process_delimiter(&mut state, &delimiter)
                && (span.malformed || has_encoded_body(input, span.body_start, span.footer_start))
                && let Some(found) = candidate(span.start, span.end, span.malformed)
            {
                candidates.push(found);
            }
        }

        if !state.stack.is_empty()
            && state.malformed
            && let Some(start) = state.outer_start
            && start < input.len()
            && let Some(found) = candidate(start, input.len(), true)
        {
            candidates.push(found);
        }

        Ok(candidates)
    }
}

/// The literals one of which every private-key candidate contains, for the
/// shared prefilter (`super::prefilter`, issue #983).
///
/// Every candidate span comes from a `-----BEGIN <label>-----` or
/// `-----END <label>-----` delimiter [`find_next_delimiter`] found.
pub(super) const REQUIRED_LITERALS: &[Literals] =
    &[Literals::Strs(&[DELIMITER_BEGIN, DELIMITER_END])];

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        PrivateKeyDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn spans(candidates: &[Candidate]) -> Vec<(usize, usize)> {
        candidates
            .iter()
            .map(|c| (c.range().start(), c.range().end()))
            .collect()
    }

    fn block(label: &str) -> String {
        format!(
            "-----BEGIN {label}-----\nU1lOVEhFVElDX1JFVk9LRURfRklYVFVSRQ==\n-----END {label}-----"
        )
    }

    #[test]
    fn detects_a_complete_block_with_encoded_body() {
        let input = block("PRIVATE KEY");
        let found = detect(&input);
        assert_eq!(spans(&found), [(0, input.len())]);
        assert_eq!(found[0].type_name(), "private_key");
        assert_eq!(found[0].confidence(), Confidence::High);
        assert_eq!(found[0].effective_specificity(), Specificity::PrivateKey);
    }

    #[test]
    fn every_supported_label_is_recognized() {
        for label in LABELS {
            let input = block(label);
            assert_eq!(spans(&detect(&input)), [(0, input.len())], "{label}");
        }
    }

    #[test]
    fn rejects_public_key_and_unsupported_labels() {
        for input in [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDX1JFVk9LRURfQ0VSVA==\n-----END CERTIFICATE-----",
            "----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRURfTk8=\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEYS-----\nU1lOVEhFVElDX1JFVk9LRURfTk8=\n-----END PRIVATE KEYS-----",
        ] {
            assert_eq!(detect(input), Vec::new(), "{input}");
        }
    }

    #[test]
    fn ignores_a_lone_incomplete_header() {
        assert_eq!(
            detect("-----BEGIN PRIVATE KEY-----\nSYNTHETIC_TRUNCATED"),
            Vec::new()
        );
    }

    #[test]
    fn rejects_a_complete_pair_without_enough_encoded_body() {
        assert_eq!(
            detect("-----BEGIN PRIVATE KEY-----\nSHORT\n-----END PRIVATE KEY-----"),
            Vec::new()
        );
    }

    #[test]
    fn returns_separate_spans_for_adjacent_complete_blocks() {
        let first = block("PRIVATE KEY");
        let second = block("EC PRIVATE KEY");
        let input = format!("{first}\n{second}");
        assert_eq!(
            spans(&detect(&input)),
            [(0, first.len()), (first.len() + 1, input.len())]
        );
    }

    #[test]
    fn blocks_one_outer_span_for_properly_nested_delimiters() {
        let input = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "U1lOVEhFVElDX1JFVk9LRURfT1VURVI=",
            "-----BEGIN EC PRIVATE KEY-----",
            "U1lOVEhFVElDX1JFVk9LRURfSU5ORVI=",
            "-----END EC PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
        ]
        .join("\n");
        let found = detect(&input);
        assert_eq!(spans(&found), [(0, input.len())]);
        assert_eq!(
            found[0].signals(),
            ["pem-boundaries", "malformed-delimiters"]
        );
    }

    #[test]
    fn blocks_unresolved_repeated_or_mismatched_delimiters_to_end_of_input() {
        let fixtures = [
            [
                "-----BEGIN PRIVATE KEY-----",
                "SYNTHETIC_REVOKED_OUTER_BODY",
                "-----BEGIN PRIVATE KEY-----",
                "SYNTHETIC_REVOKED_INNER_BODY",
            ]
            .join("\n"),
            [
                "-----BEGIN RSA PRIVATE KEY-----",
                "SYNTHETIC_REVOKED_MISMATCHED_BODY",
                "-----END EC PRIVATE KEY-----",
                "ordinary trailing text",
            ]
            .join("\n"),
            [
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
                "SYNTHETIC_REVOKED_TRAILING_INNER_BODY",
                "-----END EC PRIVATE KEY-----",
            ]
            .join("\n"),
        ];

        for input in fixtures {
            assert_eq!(spans(&detect(&input)), [(0, input.len())], "{input}");
        }
    }

    #[test]
    fn handles_many_unmatched_headers_in_bounded_time() {
        let input = "-----BEGIN PRIVATE KEY-----\n".repeat(10_000);
        let found = detect(&input);
        assert_eq!(spans(&found), [(0, input.len())]);
    }

    #[test]
    fn finds_one_full_span_for_a_large_complete_block() {
        let input = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            "U1lOVEhFVElDX1JFVk9LRURfQk9EWQ==".repeat(32_000)
        );
        assert_eq!(spans(&detect(&input)), [(0, input.len())]);
    }

    #[test]
    fn long_missing_footer_terminates_without_a_finding() {
        let input = format!("-----BEGIN PRIVATE KEY-----\n{}", "A".repeat(100_000));
        assert_eq!(detect(&input), Vec::new());
    }

    #[test]
    fn id_is_stable() {
        assert_eq!(PrivateKeyDetector.id(), "private-key");
    }

    #[test]
    fn retention_tracker_reports_open_only_between_begin_and_end() {
        let mut tracker = PrivateKeyRetentionTracker::new();
        assert_eq!(tracker.append("no header here\n"), (false, false));
        assert_eq!(
            tracker.append("-----BEGIN PRIVATE KEY-----\n"),
            (true, true)
        );
        assert_eq!(tracker.append("U1lOVEhFVElDX1JFVk9LRUQ=\n"), (true, true));
        assert_eq!(tracker.append("-----END PRIVATE KEY-----"), (true, false));
    }

    #[test]
    fn retention_tracker_detects_a_delimiter_split_across_appended_pieces() {
        let mut tracker = PrivateKeyRetentionTracker::new();
        let whole = "-----BEGIN PRIVATE KEY-----";
        let split = whole.len() / 2;
        assert_eq!(tracker.append(&whole[..split]), (false, false));
        assert_eq!(tracker.append(&whole[split..]), (true, true));
    }

    #[test]
    fn retention_tracker_reset_discards_state() {
        let mut tracker = PrivateKeyRetentionTracker::new();
        tracker.append("-----BEGIN PRIVATE KEY-----\n");
        tracker.reset();
        assert_eq!(tracker.append("ordinary text"), (false, false));
    }

    #[test]
    fn retention_tracker_does_not_reprocess_a_delimiter_carried_in_the_lookbehind() {
        // The lookbehind window is at most MAX_DELIMITER_LEN - 1 bytes, so a
        // short first piece is carried forward whole; appending more text
        // must not re-trigger `has_begin`/`has_open` bookkeeping for the same
        // delimiter twice in a way that would misreport state.
        let mut tracker = PrivateKeyRetentionTracker::new();
        assert_eq!(tracker.append("-----BEGIN PRIVATE KEY-----"), (true, true));
        assert_eq!(tracker.append("\nbody\n"), (true, true));
        assert_eq!(tracker.append("-----END PRIVATE KEY-----"), (true, false));
    }

    /// The scan-every-byte form of [`find_next_delimiter`] before #1074.
    fn oracle_find_next_delimiter(input: &str, from: usize) -> Option<Delimiter> {
        let bytes = input.as_bytes();
        let mut position = from;
        while position + 5 <= bytes.len() {
            if &bytes[position..position + 5] == b"-----" {
                for (kind, lead) in [
                    (DelimiterKind::Begin, DELIMITER_BEGIN),
                    (DelimiterKind::End, DELIMITER_END),
                ] {
                    if bytes[position..].starts_with(lead.as_bytes()) {
                        let label_start = position + lead.len();
                        for (label, name) in LABELS.iter().enumerate() {
                            let label_end = label_start + name.len();
                            let suffix_end = label_end + 5;
                            if suffix_end <= bytes.len()
                                && bytes[label_start..label_end] == *name.as_bytes()
                                && bytes[label_end..suffix_end] == *b"-----"
                            {
                                return Some(Delimiter {
                                    start: position,
                                    end: suffix_end,
                                    kind,
                                    label,
                                });
                            }
                        }
                    }
                }
            }
            position += 1;
        }
        None
    }

    /// The tracker before #1074: lookbehind is the untrimmed byte suffix.
    struct OracleTracker {
        state: ParserState,
        processed_bytes: usize,
        lookbehind: String,
    }

    impl OracleTracker {
        fn append(&mut self, piece: &str, spans: &mut Vec<(usize, usize)>) -> (bool, bool) {
            let input = [self.lookbehind.as_str(), piece].concat();
            let input_offset = self.processed_bytes - self.lookbehind.len();
            let mut found = |span: CompletedSpan| spans.push((span.start, span.end));
            let mut position = 0;
            while let Some(delimiter) = oracle_find_next_delimiter(&input, position) {
                position = delimiter.end;
                let absolute_end = input_offset + delimiter.end;
                if absolute_end <= self.processed_bytes {
                    continue;
                }
                let absolute = Delimiter {
                    start: input_offset + delimiter.start,
                    end: absolute_end,
                    kind: delimiter.kind,
                    label: delimiter.label,
                };
                if let Some(span) = process_delimiter(&mut self.state, &absolute) {
                    found(span);
                }
            }
            self.processed_bytes += piece.len();
            self.lookbehind = byte_suffix(&input, MAX_DELIMITER_LEN - 1).to_owned();
            (self.state.has_begin, !self.state.stack.is_empty())
        }
    }

    #[test]
    fn dash_jumping_delimiter_search_and_trimmed_lookbehind_match_the_oracles() {
        const PARTS: &[&str] = &[
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN ",
            "-----END ",
            "-----",
            "----",
            "-",
            "--",
            "PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "\n",
            "\r\n",
            "body",
            " ",
            "\u{e9}",
            "\u{1f511}",
        ];
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % u64::try_from(bound).unwrap()).unwrap()
        };
        for _ in 0..4_000 {
            let mut text = String::new();
            for _ in 0..next(14) {
                text.push_str(PARTS[next(PARTS.len())]);
            }
            for from in 0..=text.len().min(40) {
                if text.is_char_boundary(from) {
                    let new = find_next_delimiter(&text, from);
                    let old = oracle_find_next_delimiter(&text, from);
                    assert_eq!(
                        new.map(|d| (d.start, d.end, d.label)),
                        old.map(|d| (d.start, d.end, d.label)),
                        "{text:?} {from}"
                    );
                }
            }
            // Random chunking, per char boundary.
            let mut tracker = PrivateKeyRetentionTracker::new();
            let mut oracle = OracleTracker {
                state: ParserState::new(),
                processed_bytes: 0,
                lookbehind: String::new(),
            };
            let (mut new_spans, mut old_spans) = (Vec::new(), Vec::new());
            let mut rest = text.as_str();
            while !rest.is_empty() {
                let mut cut = (1 + next(30)).min(rest.len());
                while !rest.is_char_boundary(cut) {
                    cut += 1;
                }
                let (piece, tail) = rest.split_at(cut);
                let got = tracker.append_reporting(piece, |span| {
                    new_spans.push((span.start, span.end));
                });
                assert_eq!(got, oracle.append(piece, &mut old_spans), "{text:?}");
                assert_eq!(new_spans, old_spans, "{text:?}");
                assert!(tracker.lookbehind.is_empty() || tracker.lookbehind.starts_with('-'));
                rest = tail;
            }
        }
    }

    /// The tracker before #1087: the whole piece is joined to the lookbehind
    /// and the join scanned, then trimmed the same way.
    struct JoinTracker {
        state: ParserState,
        processed_bytes: usize,
        lookbehind: String,
    }

    impl JoinTracker {
        fn new() -> Self {
            Self {
                state: ParserState::new(),
                processed_bytes: 0,
                lookbehind: String::new(),
            }
        }

        fn append(&mut self, piece: &str, spans: &mut Vec<(usize, usize)>) -> (bool, bool) {
            let joined = [self.lookbehind.as_str(), piece].concat();
            let input_offset = self.processed_bytes - self.lookbehind.len();
            scan_delimiters(
                &joined,
                0,
                &mut self.state,
                self.processed_bytes,
                input_offset,
                |span| spans.push((span.start, span.end)),
            );
            self.processed_bytes += piece.len();
            let suffix = byte_suffix(&joined, MAX_DELIMITER_LEN.saturating_sub(1));
            let suffix = suffix.find('-').map_or("", |dash| &suffix[dash..]);
            self.lookbehind = suffix.to_owned();
            (self.state.has_begin, !self.state.stack.is_empty())
        }
    }

    fn assert_chunks_match_the_join_oracle(pieces: &[&str]) {
        let mut tracker = PrivateKeyRetentionTracker::new();
        let mut oracle = JoinTracker::new();
        let (mut new_spans, mut old_spans) = (Vec::new(), Vec::new());
        for piece in pieces {
            let got = tracker.append_reporting(piece, |span| {
                new_spans.push((span.start, span.end));
            });
            assert_eq!(got, oracle.append(piece, &mut old_spans), "{pieces:?}");
            assert_eq!(new_spans, old_spans, "{pieces:?}");
            assert_eq!(tracker.lookbehind, oracle.lookbehind, "{pieces:?}");
            assert_eq!(tracker.processed_bytes, oracle.processed_bytes);
        }
    }

    #[test]
    fn junction_scan_matches_the_whole_join_at_every_split_of_delimiters() {
        let texts = [
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "x-----BEGIN ENCRYPTED PRIVATE KEY-----\r\nAAAA\r\n-----END ENCRYPTED PRIVATE KEY-----",
            "\u{e9}-----BEGIN RSA PRIVATE KEY-----\u{1f511}-----END RSA PRIVATE KEY-----\u{e9}",
            "-----BEGIN PRIVATE KEY-----BEGIN PRIVATE KEY-----END PRIVATE KEY-----END PRIVATE KEY-----",
            "------BEGIN PRIVATE KEY------END PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----",
        ];
        for text in texts {
            let cuts: Vec<usize> = (0..=text.len())
                .filter(|&at| text.is_char_boundary(at))
                .collect();
            for &first in &cuts {
                assert_chunks_match_the_join_oracle(&[&text[..first], &text[first..]]);
                for &second in cuts.iter().filter(|&&at| at >= first) {
                    // A long middle piece crosses the junction head bound.
                    assert_chunks_match_the_join_oracle(&[
                        &text[..first],
                        &text[first..second],
                        &text[second..],
                    ]);
                }
            }
            // Pieces of one byte up to beyond the junction head.
            for size in [1, 2, 7, 35, 36, 37, 38, 40, 90] {
                let mut pieces = Vec::new();
                let mut rest = text;
                while !rest.is_empty() {
                    let mut cut = size.min(rest.len());
                    while !rest.is_char_boundary(cut) {
                        cut += 1;
                    }
                    let (piece, tail) = rest.split_at(cut);
                    pieces.push(piece);
                    rest = tail;
                }
                assert_chunks_match_the_join_oracle(&pieces);
            }
        }
    }

    #[test]
    fn junction_scan_matches_the_whole_join_on_random_chunks() {
        const PARTS: &[&str] = &[
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----END ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN ",
            "-----END ",
            "-----",
            "----",
            "-",
            "PRIVATE KEY",
            "\n",
            "\r\n",
            "body",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            " ",
            "\u{e9}",
            "\u{1f511}",
        ];
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % u64::try_from(bound).unwrap()).unwrap()
        };
        for _ in 0..4_000 {
            let mut text = String::new();
            for _ in 0..next(16) {
                text.push_str(PARTS[next(PARTS.len())]);
            }
            let mut pieces = Vec::new();
            let mut rest = text.as_str();
            while !rest.is_empty() {
                let mut cut = (1 + next(120)).min(rest.len());
                while !rest.is_char_boundary(cut) {
                    cut += 1;
                }
                let (piece, tail) = rest.split_at(cut);
                pieces.push(piece);
                rest = tail;
            }
            assert_chunks_match_the_join_oracle(&pieces);
        }
    }
}
