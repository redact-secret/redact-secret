//! Slack token detection.
//!
//! Slack's documentation describes every token as a set of `-`-separated
//! sections, the final section being the secret. Issue #371 froze the
//! `xoxb-` bot form's section grammar as the default contract
//! (`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`,
//! `docs/audits/evidence/367/precision-contracts.json`), replacing the
//! earlier "recognized prefix plus a 20-byte minimum suffix" rule that
//! accepted any long enough `xoxb-` value regardless of its internal
//! structure:
//!
//! ```text
//! xoxb-<10-13 [0-9]>-<10-13 [0-9]>-<18+ [A-Za-z0-9]>   bot
//! ```
//!
//! The two numeric section widths are tool-corroborated; the provider
//! establishes only that sections are `-`-separated, which is why a value
//! whose second numeric section runs straight into the secret with no
//! separator — accepted by both baseline scanners' bare `[a-zA-Z0-9-]*`
//! tail, and by beta.4's own minimum-length rule — is rejected here. The
//! secret's 18-byte floor is a support-policy choice (the smallest bot
//! secret width any consulted tool accepts); the provider documents no bot
//! secret length.
//!
//! Every other documented prefix (`xoxp-`, `xapp-`, `xwfp-`, `xoxe-`,
//! `xoxe.xoxb-`, `xoxe.xoxp-`) keeps beta.4's rule unchanged as a separate
//! interim guard, per prefix: none of them were measured flagging a
//! must-not-flag twin, and their own section grammars are recorded as
//! pending evidence, not adopted. The `regex` crate cannot be used here —
//! this crate is dependency-free — so [`scan_bot`] and the interim guard
//! compose the shape from the shared `pattern` primitives, the same way
//! [`super::openai`] does for its own segmented grammar.

use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const BOT_PREFIX: &str = "xoxb-";
/// Each numeric section's documented width (tool-agreement; the provider
/// establishes only that sections are `-`-separated).
const BOT_SECTION_MIN: usize = 10;
const BOT_SECTION_MAX: usize = 13;
/// Support-policy floor for the bot secret section: the smallest bot-secret
/// width any consulted tool accepts (gitleaks' legacy-bot rule, 18).
const BOT_SECRET_MIN: usize = 18;
const BOT_DIGIT_ALPHABET: Alphabet = pattern::is_digit;
/// The secret section's alphabet is `[A-Za-z0-9]`, narrower than the
/// `[A-Za-z0-9_-]` boundary: a trailing `_` or `-` still rejects a truncated
/// candidate instead of being folded into the secret.
const BOT_SECRET_ALPHABET: Alphabet = pattern::is_alnum;
const BOT_SIGNALS: [&str; 2] = ["slack-documented-prefix", "bot-section-grammar"];

/// Every other documented prefix, unchanged from beta.4.
const INTERIM_MIN_LEN: usize = 20;
const INTERIM_ALPHABET: Alphabet = pattern::is_alnum_dash;
const INTERIM_SHAPES: [PrefixShape<'static>; 6] = [
    PrefixShape::at_least("xoxp-", INTERIM_MIN_LEN),
    PrefixShape::at_least("xapp-", INTERIM_MIN_LEN),
    PrefixShape::at_least("xwfp-", INTERIM_MIN_LEN),
    PrefixShape::at_least("xoxe-", INTERIM_MIN_LEN),
    PrefixShape::at_least("xoxe.xoxb-", INTERIM_MIN_LEN),
    PrefixShape::at_least("xoxe.xoxp-", INTERIM_MIN_LEN),
];
const INTERIM_SIGNALS: [&str; 2] = ["slack-documented-prefix", "opaque-suffix"];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// Requires the `xoxb-` bot form to carry its full section grammar; every
/// other documented prefix keeps the beta.4 interim guard. A value that
/// merely starts with a documented prefix and is long enough, but whose
/// `xoxb-` body has no separator before the secret section, is not
/// classified; a contextual assignment carrying one can still surface
/// through `generic-token`.
pub(super) struct SlackTokenDetector;

impl Detector for SlackTokenDetector {
    fn id(&self) -> &'static str {
        "slack-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end, signals) in scan(input) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new("slack_token", Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

/// Every match, `xoxb-` bot values and interim-guarded prefixes together,
/// left to right by start offset. No two prefixes here share a leading
/// substring with another, so scanning each family independently and
/// merging by position reproduces the same left-to-right, longest-prefix
/// result a single combined scan would.
fn scan(input: &str) -> Vec<(usize, usize, &'static [&'static str; 2])> {
    let mut matches: Vec<(usize, usize, &'static [&'static str; 2])> = scan_bot(input)
        .into_iter()
        .map(|(start, end)| (start, end, &BOT_SIGNALS))
        .collect();
    matches.extend(
        pattern::scan_prefixed_shapes(input, &INTERIM_SHAPES, INTERIM_ALPHABET, BOUNDARY)
            .into_iter()
            .map(|(start, end)| (start, end, &INTERIM_SIGNALS)),
    );
    matches.sort_unstable_by_key(|&(start, _, _)| start);
    matches
}

/// Every boundary-delimited `xoxb-` bot value, left to right. A failed
/// attempt advances by one byte; a shape-complete attempt advances past the
/// whole value whether or not the boundary check keeps it, so a wider
/// identifier that embeds a bot prefix never yields a second, shorter
/// reading of the same bytes.
fn scan_bot(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let digit_ends = pattern::run_ends(bytes, BOT_DIGIT_ALPHABET);
    let secret_ends = pattern::run_ends(bytes, BOT_SECRET_ALPHABET);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start..].starts_with(BOT_PREFIX.as_bytes()) {
            start += 1;
            continue;
        }
        let Some(end) = bot_end(bytes, &digit_ends, &secret_ends, start + BOT_PREFIX.len()) else {
            start += 1;
            continue;
        };
        if pattern::boundary_ok(bytes, start, end, BOUNDARY) {
            matches.push((start, end));
        }
        start = end;
    }
    matches
}

/// `<10-13 digits>-<10-13 digits>-<18+ alnum>` starting at `body_start`: the
/// three `-`-separated sections the provider documents, the last being the
/// secret. Because each run is maximal, a section wider than its documented
/// range is rejected rather than truncated, and a missing separator before
/// the secret section — the beta.4 defect issue #371 fixes — is rejected
/// too, rather than being re-read as a longer second numeric section.
fn bot_end(
    bytes: &[u8],
    digit_ends: &[usize],
    secret_ends: &[usize],
    body_start: usize,
) -> Option<usize> {
    let section_1_end = digit_section_end(digit_ends, body_start)?;
    if bytes.get(section_1_end) != Some(&b'-') {
        return None;
    }
    let section_2_start = section_1_end + 1;
    let section_2_end = digit_section_end(digit_ends, section_2_start)?;
    if bytes.get(section_2_end) != Some(&b'-') {
        return None;
    }
    let secret_start = section_2_end + 1;
    let secret_end = secret_ends[secret_start];
    if secret_end - secret_start < BOT_SECRET_MIN {
        return None;
    }
    Some(secret_end)
}

/// The end of the maximal digit run starting at `start`, only when its
/// length falls within the documented `10..=13` width.
fn digit_section_end(digit_ends: &[usize], start: usize) -> Option<usize> {
    let end = digit_ends[start];
    let len = end - start;
    (BOT_SECTION_MIN..=BOT_SECTION_MAX)
        .contains(&len)
        .then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(benchmark id suffix, input, expected ranges)`.
    type Case = (&'static str, String, Vec<(usize, usize)>);

    fn detect(input: &str) -> Vec<Candidate> {
        SlackTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    fn ranges(input: &str) -> Vec<(usize, usize)> {
        detect(input)
            .iter()
            .map(|candidate| (candidate.range().start(), candidate.range().end()))
            .collect()
    }

    /// A synthetic, never-issued bot token at exactly the documented shape:
    /// two 13-digit sections and a 24-byte secret.
    const BOT_POSITIVE: &str = "xoxb-1234567890123-3210987654321-SYNTHETICREVOKEDBOTSECRET1";
    /// The same value with the separator before the secret section removed —
    /// the exact defect issue #371 fixes.
    const BOT_NO_SEPARATOR_TWIN: &str =
        "xoxb-1234567890123-3210987654321SYNTHETICREVOKEDBOTSECRET1";

    #[test]
    fn the_canonical_literal_is_the_documented_shape() {
        assert_eq!(BOT_POSITIVE.len(), 5 + 13 + 1 + 13 + 1 + 26);
        assert_ne!(BOT_POSITIVE, BOT_NO_SEPARATOR_TWIN);
        assert_eq!(BOT_NO_SEPARATOR_TWIN.len(), BOT_POSITIVE.len() - 1);
    }

    #[test]
    fn detects_the_bot_form_with_exact_metadata() {
        let candidates = detect(BOT_POSITIVE);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "slack_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, BOT_POSITIVE.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_bot_value_missing_the_dash_before_the_secret_section() {
        assert!(ranges(BOT_NO_SEPARATOR_TWIN).is_empty());
    }

    #[test]
    fn rejects_a_numeric_section_one_byte_off_from_the_documented_width() {
        for (first_len, second_len) in [(9, 13), (14, 13), (13, 9), (13, 14)] {
            let first = "1".repeat(first_len);
            let second = "2".repeat(second_len);
            let input = format!("xoxb-{first}-{second}-SYNTHETICREVOKEDBOTSECRET1");
            assert!(ranges(&input).is_empty(), "{first_len}/{second_len}");
        }
    }

    #[test]
    fn accepts_every_documented_numeric_width_from_ten_to_thirteen() {
        for len in BOT_SECTION_MIN..=BOT_SECTION_MAX {
            let section = "7".repeat(len);
            let input = format!("xoxb-{section}-{section}-SYNTHETICREVOKEDBOTSECRET1");
            assert_eq!(ranges(&input), vec![(0, input.len())], "{len}");
        }
    }

    #[test]
    fn rejects_a_secret_section_one_byte_short_of_the_eighteen_byte_floor() {
        let short_secret = "S".repeat(BOT_SECRET_MIN - 1);
        let input = format!("xoxb-1234567890123-3210987654321-{short_secret}");
        assert!(ranges(&input).is_empty());
    }

    #[test]
    fn accepts_a_secret_section_at_exactly_the_eighteen_byte_floor() {
        let secret = "S".repeat(BOT_SECRET_MIN);
        let input = format!("xoxb-1234567890123-3210987654321-{secret}");
        assert_eq!(ranges(&input), vec![(0, input.len())]);
    }

    #[test]
    fn rejects_a_secret_section_containing_a_dash_or_underscore() {
        // The secret alphabet is `[A-Za-z0-9]` only, narrower than the
        // interim guards' `[A-Za-z0-9_-]`.
        for byte in ['_', '-'] {
            let mut secret = "S".repeat(BOT_SECRET_MIN);
            secret.replace_range(5..6, &byte.to_string());
            let input = format!("xoxb-1234567890123-3210987654321-{secret}");
            assert!(ranges(&input).is_empty(), "{byte}");
        }
    }

    #[test]
    fn interim_prefixes_keep_the_beta4_minimum_length_rule_unchanged() {
        for (prefix, len) in [
            ("xoxp-", 20),
            ("xapp-", 20),
            ("xwfp-", 20),
            ("xoxe-", 20),
            ("xoxe.xoxb-", 20),
            ("xoxe.xoxp-", 20),
        ] {
            let body = "SYNTHETICREVOKEDINTERIMVALUE0123456789";
            let input = format!("{prefix}{}", &body[..len]);
            assert_eq!(ranges(&input), vec![(0, input.len())], "{prefix}");
            let one_short = format!("{prefix}{}", &body[..len - 1]);
            assert!(ranges(&one_short).is_empty(), "{prefix} one-short");
        }
    }

    /// Issue #321 dimensions, carried over from `additional_providers.rs`
    /// for Slack's interim-guarded prefixes now that Slack has moved to its
    /// own module (issue #371).
    #[test]
    fn interim_prefixes_accept_an_all_valid_alphabet_documentation_placeholder() {
        let value = format!("xoxp-{}", "x".repeat(20));
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn interim_prefixes_reject_the_prefix_embedded_in_a_wider_identifier() {
        let value = "legacyxoxp-SYNTHETIC_REVOKED_KEY_VALUE";
        assert!(ranges(value).is_empty());
    }

    #[test]
    fn interim_prefixes_reject_a_percent_encoded_delimiter_lookalike() {
        let value = "xoxp%2DSYNTHETIC_REVOKED_CONFORMANCE_KEY";
        assert!(ranges(value).is_empty());
    }

    #[test]
    fn interim_prefixes_report_a_repeated_identical_value_once_per_occurrence() {
        let value = "xoxp-SYNTHETIC_REVOKED_KEY_VALUE";
        let input = format!("{value} {value}");
        assert_eq!(detect(&input).len(), 2);
    }

    #[test]
    fn the_longest_matching_interim_prefix_wins_at_a_shared_position() {
        let body = "SYNTHETICREVOKEDINTERIMVALUE0123456789";
        for prefix in ["xoxe-", "xoxe.xoxb-", "xoxe.xoxp-"] {
            let input = format!("{prefix}{body}");
            assert_eq!(ranges(&input), vec![(0, input.len())], "{prefix}");
        }
    }

    #[test]
    fn a_bot_section_grammar_failure_never_falls_back_to_the_interim_guard() {
        // A long enough `xoxb-` body with no section grammar at all — the
        // exact beta.4 shape this issue retires for the bot prefix.
        let input = "xoxb-SYNTHETICREVOKEDPROVIDERVALUE00000000";
        assert!(ranges(input).is_empty());
    }

    #[test]
    fn detects_every_variant_in_the_same_input_without_one_suppressing_another() {
        let interim = "xoxp-SYNTHETICREVOKEDINTERIMVALUE01234567";
        let input = format!("{BOT_POSITIVE}\n{interim}");
        let second_start = BOT_POSITIVE.len() + 1;
        assert_eq!(
            ranges(&input),
            vec![
                (0, BOT_POSITIVE.len()),
                (second_start, second_start + interim.len())
            ]
        );
    }

    #[test]
    fn rejects_a_bot_value_embedded_in_a_wider_identifier_on_either_side() {
        // A trailing plain alnum byte is not tested here: the secret section
        // has no documented maximum, so it is simply absorbed as a longer
        // (still valid) secret rather than rejected.
        for input in [
            format!("legacy{BOT_POSITIVE}"),
            format!("{BOT_POSITIVE}-tail"),
            format!("{BOT_POSITIVE}_tail"),
        ] {
            assert!(ranges(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn punctuation_and_quotes_bound_the_match_without_being_folded_into_it() {
        let input = format!("Rotate {BOT_POSITIVE}, then redeploy.");
        assert_eq!(ranges(&input), vec![(7, 7 + BOT_POSITIVE.len())]);
        let quoted = format!("{{\"token\": \"{BOT_POSITIVE}\"}}");
        assert_eq!(ranges(&quoted), vec![(11, 11 + BOT_POSITIVE.len())]);
    }

    #[test]
    fn reports_each_occurrence_of_a_repeated_value_independently() {
        let input = format!("{BOT_POSITIVE} {BOT_POSITIVE}");
        let second = BOT_POSITIVE.len() + 1;
        assert_eq!(
            ranges(&input),
            vec![
                (0, BOT_POSITIVE.len()),
                (second, second + BOT_POSITIVE.len())
            ]
        );
    }

    #[test]
    fn unicode_and_crlf_surroundings_shift_only_the_byte_offsets() {
        let input = format!("# \u{1F511} reviewed format\r\n{BOT_POSITIVE}\n\r\n");
        let start = "# \u{1F511} reviewed format\r\n".len();
        assert_eq!(start, 24);
        assert_eq!(ranges(&input), vec![(start, start + BOT_POSITIVE.len())]);
    }

    /// The exact synthetic inputs issue #371 attached, with the ranges it
    /// expects: the negative twin differs from its paired positive in
    /// exactly one structural property — the dash before the secret
    /// section.
    #[test]
    fn issue_371_twins_are_rejected_and_their_paired_positives_preserved() {
        const UNICODE_CRLF: &str = "# \u{1F511} reviewed format\r\n";
        let bot_positive = "xoxb-535105338178-098272152943-YyL0MDH0GlAxLV9GoqXpfgI4";
        let bot_twin = "xoxb-535105338178-098272152943YyL0MDH0GlAxLV9GoqXpfgI4";

        let cases: [Case; 4] = [
            ("bot-plain", format!("{bot_positive}\n\n"), vec![(0, 55)]),
            ("bot-plain-twin", format!("{bot_twin}\n\n"), vec![]),
            (
                "bot-unicode-crlf",
                format!("{UNICODE_CRLF}{bot_positive}\n\r\n"),
                vec![(24, 79)],
            ),
            (
                "bot-unicode-crlf-twin",
                format!("{UNICODE_CRLF}{bot_twin}\n\r\n"),
                vec![],
            ),
        ];
        for (id, input, expected) in cases {
            assert_eq!(ranges(&input), expected, "slack-token-{id}");
        }
    }
}
