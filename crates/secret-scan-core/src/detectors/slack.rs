//! Slack token detection.
//!
//! Slack's documentation describes every token as a set of `-`-separated
//! sections, the final section being the secret. Issue #371 froze the
//! `xoxb-` bot form's section grammar as the default contract
//! (`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`,
//! `docs/audits/evidence/367/precision-contracts.json`), replacing the
//! earlier "recognized prefix plus a 20-byte minimum suffix" rule that
//! accepted any long enough `xoxb-` value regardless of its internal
//! structure. Issue #512 completes the family on the same evidentiary bar:
//!
//! ```text
//! xoxb-<10-13 [0-9]>-<10-13 [0-9]>-<18+ [A-Za-z0-9]>              bot
//! xoxp-<10-13 [0-9]>-<10-13 [0-9]>-<10-13 [0-9]>-<28+ [A-Za-z0-9]>  user
//! xoxe-<1 [0-9]>-<20 [A-Za-z0-9_-]>                              refresh
//! xoxe.xoxb-<1 [0-9]>-<20 [A-Za-z0-9_-]>                         rotating bot
//! xoxe.xoxp-<1 [0-9]>-<20 [A-Za-z0-9_-]>                         rotating user
//! ```
//!
//! (`docs/decisions/2026-09-20-freeze-slack-user-and-rotation-token-grammar.md`).
//! Every numeric section width above is tool-corroborated (gitleaks and
//! trufflehog both use `10-13` for every Slack `-`-separated numeric
//! section they recognize); the provider establishes only that sections are
//! `-`-separated. The user secret's 28-byte floor is gitleaks'
//! `slack-user-token` lower bound; the provider shows one full 32-byte
//! example (`d6bc768406e5c2e6958cfc399b438004`,
//! <https://docs.slack.dev/authentication/tokens>, observed 2026-09-20) but
//! states no length rule, and pre-2016 6/10-byte secrets are documented as
//! still rotatable. The rotation family's single-digit version section
//! reproduces every provider example verbatim (`xoxe-1-...`,
//! `xoxe.xoxb-1-...`, `xoxe.xoxp-1-1234-...`,
//! <https://docs.slack.dev/authentication/using-token-rotation/>, observed
//! 2026-09-20) and gitleaks' config-access/-refresh-token rules encode the
//! same single digit; the body that follows keeps beta.4's opaque
//! `[A-Za-z0-9_-]` interim guard, since neither source constrains it
//! (`xoxe.xoxp-`'s own extra `-1234-` section is a single uncorroborated
//! example and is not decomposed further). Issue #551 turns its 20-byte
//! floor into an exact length (see the module doc's boundary-defect
//! paragraph below).
//!
//! `xapp-` and `xwfp-` keep beta.4's alphabet unchanged as a plain interim
//! guard: `xapp-`'s only candidate structure is a single uncorroborated
//! tool source (gitleaks, case-insensitive) and `xwfp-` has no tool source
//! at all, so neither clears this project's two-source (or
//! provider-plus-tool) bar for a structural contract
//! (`docs/audits/evidence/367/precision-contracts.json`,
//! `slack-token.variants[app-level|workflow]`). Issue #551 turns their own
//! 20-byte floor into an exact length too, for the same reason. The `regex`
//! crate cannot be
//! used here — this crate is dependency-free — so [`scan_sectioned`] and the
//! interim guard compose every shape from the shared `pattern` primitives,
//! the same way [`super::openai`] does for its own segmented grammar.
//!
//! Issue #551: every prefix above whose tail kept beta.4's open floor
//! (`RunLength::AtLeast`, no documented maximum) matched against
//! `[A-Za-z0-9_-]` — the identical alphabet [`BOUNDARY`] itself checks. A
//! run computed that way is already maximal by construction, so the byte
//! immediately past it can never belong to that same alphabet, and
//! `pattern::boundary_ok`'s trailing check is structurally unable to fire: a
//! directly-glued wider identifier (`..._backup`, `...-1`) was silently
//! absorbed into the match as "more opaque secret" rather than tripping the
//! boundary rule the bot and user secret sections already enforce with
//! their own narrower [`SECRET_ALPHABET`]. The same defect affected
//! [`super::linear`]'s `lin_oauth_` guard. The shared fix, applied to the
//! rotation tail and both remaining interim prefixes, is the one every
//! reviewed-contract sibling in `additional_providers.rs` already uses: an
//! exact length, so the boundary check has bytes left over to inspect. A
//! body longer than the unchanged 20-byte floor is now an intentional false
//! negative until a reviewed contract establishes a real maximum — the same
//! tradeoff `docker-token` (#370), `openai-token` (#368), `huggingface-token`
//! (#372), and `cloudflare-token` (#373) each already accepted when they
//! moved off this identical open-floor shape.

use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const BOT_PREFIX: &str = "xoxb-";
const USER_PREFIX: &str = "xoxp-";
const REFRESH_PREFIX: &str = "xoxe-";
const ROTATING_BOT_PREFIX: &str = "xoxe.xoxb-";
const ROTATING_USER_PREFIX: &str = "xoxe.xoxp-";
/// What precedes `xoxb-` in the rotating `xoxe.xoxb-` prefix: the plain bot
/// scan skips a `xoxb-` occurrence here so it is left to the rotating-bot
/// scan instead of being read twice.
const ROTATING_LEAD: &str = "xoxe.";

const DIGIT_ALPHABET: Alphabet = pattern::is_digit;
/// Each numeric ID section's documented width, shared by the bot and user
/// grammars (tool-agreement: gitleaks and trufflehog both use `10-13` for
/// every Slack `-`-separated numeric section they recognize; the provider
/// establishes only that sections are `-`-separated).
const SECTION_MIN: usize = 10;
const SECTION_MAX: usize = 13;
/// Support-policy floor for the bot secret section: the smallest bot-secret
/// width any consulted tool accepts (gitleaks' legacy-bot rule, 18).
const BOT_SECRET_MIN: usize = 18;
/// Support-policy floor for the user secret section: gitleaks'
/// `slack-user-token` lower bound (`{28,34}`); see the module doc for why no
/// exact length is adopted.
const USER_SECRET_MIN: usize = 28;
/// `[A-Za-z0-9]`, narrower than the `[A-Za-z0-9_-]` boundary, shared by the
/// bot and user secret sections: a trailing `_` or `-` still rejects a
/// truncated candidate instead of being folded into the secret.
const SECRET_ALPHABET: Alphabet = pattern::is_alnum;
const BOT_SIGNALS: [&str; 2] = ["slack-documented-prefix", "bot-section-grammar"];
const USER_SIGNALS: [&str; 2] = ["slack-documented-prefix", "user-section-grammar"];

/// The rotation family's documented version section (see the module doc).
const ROTATION_DIGIT_WIDTH: usize = 1;
/// Issue #551: beta.4's floor, now the tail's exact length (see the module
/// doc's boundary-defect paragraph) rather than its minimum.
const ROTATION_TAIL_MIN: usize = 20;
const ROTATION_TAIL_ALPHABET: Alphabet = pattern::is_alnum_dash;
const ROTATION_SIGNALS: [&str; 2] = ["slack-documented-prefix", "rotation-version-section"];
const ROTATION_PREFIXES: [&str; 3] = [REFRESH_PREFIX, ROTATING_BOT_PREFIX, ROTATING_USER_PREFIX];

/// `xapp-` and `xwfp-`, unchanged from beta.4 (see the module doc for why
/// neither is promoted). Issue #551: beta.4's floor is now each guard's
/// exact length rather than its minimum (see the module doc's
/// boundary-defect paragraph).
const INTERIM_MIN_LEN: usize = 20;
const INTERIM_ALPHABET: Alphabet = pattern::is_alnum_dash;
const INTERIM_SIGNALS: [&str; 2] = ["slack-documented-prefix", "opaque-suffix"];
const INTERIM_SHAPES: [PrefixShape<'static>; 2] = [
    PrefixShape::exact("xapp-", INTERIM_MIN_LEN, INTERIM_ALPHABET, &INTERIM_SIGNALS),
    PrefixShape::exact("xwfp-", INTERIM_MIN_LEN, INTERIM_ALPHABET, &INTERIM_SIGNALS),
];

/// A value is never a slice of a wider `[A-Za-z0-9_-]` identifier.
const BOUNDARY: Alphabet = pattern::is_alnum_dash;

/// Requires `xoxb-`, `xoxp-`, and every `xoxe`-rooted rotation prefix to
/// carry their full documented section grammar; `xapp-` and `xwfp-` keep
/// the beta.4 interim guard. A value that merely starts with a documented
/// prefix and is long enough, but is missing a required section separator,
/// is not classified; a contextual assignment carrying one can still
/// surface through `generic-token`.
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

/// Every match, structural and interim-guarded prefixes together, left to
/// right by start offset. The only prefix that contains another is
/// `xoxe.xoxb-`, which [`scan_sectioned`]'s bot pass leaves to its own
/// rotating-bot pass (`ROTATING_LEAD`), so scanning each family
/// independently and merging by position reproduces the same left-to-right,
/// longest-prefix result a single combined scan would.
fn scan(input: &str) -> Vec<(usize, usize, &'static [&'static str])> {
    let mut matches: Vec<(usize, usize, &'static [&'static str])> = scan_bot(input)
        .into_iter()
        .map(|(start, end)| (start, end, BOT_SIGNALS.as_slice()))
        .collect();
    matches.extend(
        scan_user(input)
            .into_iter()
            .map(|(start, end)| (start, end, USER_SIGNALS.as_slice())),
    );
    let rotation_shape = SectionedShape {
        section_count: 1,
        digit_min: ROTATION_DIGIT_WIDTH,
        digit_max: ROTATION_DIGIT_WIDTH,
        tail_min: ROTATION_TAIL_MIN,
        tail_alphabet: ROTATION_TAIL_ALPHABET,
        tail_exact: true,
    };
    for prefix in ROTATION_PREFIXES {
        matches.extend(
            scan_sectioned(input, prefix, None, rotation_shape)
                .into_iter()
                .map(|(start, end)| (start, end, ROTATION_SIGNALS.as_slice())),
        );
    }
    matches.extend(pattern::scan_prefixed_shapes(
        input,
        &INTERIM_SHAPES,
        BOUNDARY,
    ));
    matches.sort_unstable_by_key(|&(start, _, _)| start);
    matches
}

/// Every boundary-delimited `xoxb-` bot value, left to right: two 10-13
/// digit sections then an 18+ byte alnum secret. A `xoxb-` that is the tail
/// of the rotating `xoxe.xoxb-` prefix belongs to that separate scan and is
/// skipped here.
fn scan_bot(input: &str) -> Vec<(usize, usize)> {
    scan_sectioned(
        input,
        BOT_PREFIX,
        Some(ROTATING_LEAD),
        SectionedShape {
            section_count: 2,
            digit_min: SECTION_MIN,
            digit_max: SECTION_MAX,
            tail_min: BOT_SECRET_MIN,
            tail_alphabet: SECRET_ALPHABET,
            tail_exact: false,
        },
    )
}

/// Every boundary-delimited `xoxp-` user value, left to right: three 10-13
/// digit sections then a 28+ byte alnum secret.
fn scan_user(input: &str) -> Vec<(usize, usize)> {
    scan_sectioned(
        input,
        USER_PREFIX,
        None,
        SectionedShape {
            section_count: 3,
            digit_min: SECTION_MIN,
            digit_max: SECTION_MAX,
            tail_min: USER_SECRET_MIN,
            tail_alphabet: SECRET_ALPHABET,
            tail_exact: false,
        },
    )
}

/// `section_count` `-`-separated digit sections (each within `[digit_min,
/// digit_max]` bytes) followed by a tail matching `tail_alphabet`: the shape
/// every documented Slack token family reduces to once its own section count
/// and widths are known. The tail is `tail_min`-or-more bytes when
/// `tail_exact` is `false` (the bot and user secret sections, whose own
/// alphabet is narrower than [`BOUNDARY`], so a trailing boundary byte
/// already rejects a directly-glued wider identifier); when `tail_exact` is
/// `true` (issue #551: the rotation tail, whose `[A-Za-z0-9_-]` alphabet
/// equals `BOUNDARY`), the tail is exactly `tail_min` bytes, the only shape
/// that leaves the boundary check something to inspect -- see the module
/// doc's boundary-defect paragraph.
#[derive(Clone, Copy)]
struct SectionedShape {
    section_count: usize,
    digit_min: usize,
    digit_max: usize,
    tail_min: usize,
    tail_alphabet: Alphabet,
    tail_exact: bool,
}

/// Every boundary-delimited `prefix` value whose body matches `shape`, left
/// to right. A failed attempt advances by one byte; a shape-complete
/// attempt advances past the whole value whether or not the boundary check
/// keeps it, so a wider identifier that embeds `prefix` never yields a
/// second, shorter reading of the same bytes. `skip_if_preceded_by`, when
/// set, skips a `prefix` occurrence that is itself the tail of a longer,
/// more specific prefix scanned separately.
fn scan_sectioned(
    input: &str,
    prefix: &str,
    skip_if_preceded_by: Option<&str>,
    shape: SectionedShape,
) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let digit_ends = pattern::run_ends(bytes, DIGIT_ALPHABET);
    let tail_ends = pattern::run_ends(bytes, shape.tail_alphabet);
    let mut matches = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let skip =
            skip_if_preceded_by.is_some_and(|lead| bytes[..start].ends_with(lead.as_bytes()));
        if skip || !bytes[start..].starts_with(prefix.as_bytes()) {
            start += 1;
            continue;
        }
        let Some(end) = sectioned_end(bytes, &digit_ends, &tail_ends, start + prefix.len(), shape)
        else {
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

/// The end of `shape`'s `-`-separated digit sections followed by its tail
/// run, starting at `cursor`. Because each run is maximal, a
/// section wider than `shape.digit_max` is rejected rather than truncated,
/// and a missing separator anywhere is rejected too, rather than being
/// re-read as part of a wider section or the tail.
fn sectioned_end(
    bytes: &[u8],
    digit_ends: &[usize],
    tail_ends: &[usize],
    mut cursor: usize,
    shape: SectionedShape,
) -> Option<usize> {
    for _ in 0..shape.section_count {
        let section_end = digit_section_end(digit_ends, cursor, shape.digit_min, shape.digit_max)?;
        if bytes.get(section_end) != Some(&b'-') {
            return None;
        }
        cursor = section_end + 1;
    }
    let available = tail_ends[cursor] - cursor;
    if available < shape.tail_min {
        return None;
    }
    Some(if shape.tail_exact {
        cursor + shape.tail_min
    } else {
        cursor + available
    })
}

/// The end of the maximal digit run starting at `start`, only when its
/// length falls within `[digit_min, digit_max]`.
fn digit_section_end(
    digit_ends: &[usize],
    start: usize,
    digit_min: usize,
    digit_max: usize,
) -> Option<usize> {
    let end = digit_ends[start];
    let len = end - start;
    (digit_min..=digit_max).contains(&len).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(benchmark id suffix, input, expected ranges)`.
    type Case = (&'static str, String, Vec<(usize, usize)>);

    /// Exactly [`ROTATION_TAIL_MIN`] (== [`INTERIM_MIN_LEN`]) bytes: since
    /// issue #551 turned both floors into exact lengths, every test below
    /// that expects a full match needs a body of exactly this length rather
    /// than merely at or above it.
    const OPAQUE_TWENTY_BYTE_BODY: &str = "SYNTHETICROTATION001";
    const _: () = assert!(OPAQUE_TWENTY_BYTE_BODY.len() == ROTATION_TAIL_MIN);
    const _: () = assert!(OPAQUE_TWENTY_BYTE_BODY.len() == INTERIM_MIN_LEN);

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
        for len in SECTION_MIN..=SECTION_MAX {
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
    fn a_bot_section_grammar_failure_never_falls_back_to_the_interim_guard() {
        // A long enough `xoxb-` body with no `-`-separated section grammar
        // at all.
        let input = "xoxb-SYNTHETICREVOKEDPROVIDERVALUE00000000";
        assert!(ranges(input).is_empty());
    }

    /// A synthetic, never-issued user token at exactly the documented shape:
    /// three 13-digit sections and a 32-byte secret, the length of the
    /// provider's own example secret
    /// (`d6bc768406e5c2e6958cfc399b438004`,
    /// <https://docs.slack.dev/authentication/tokens>, observed 2026-09-20).
    const USER_POSITIVE: &str =
        "xoxp-1234567890123-3210987654321-1112223334445-SYNTHETICREVOKEDUSERSECRETVALUE1";
    /// The same value with the separator before the secret section removed.
    const USER_NO_SEPARATOR_TWIN: &str =
        "xoxp-1234567890123-3210987654321-1112223334445SYNTHETICREVOKEDUSERSECRETVALUE1";

    #[test]
    fn the_user_canonical_literal_is_the_documented_shape() {
        assert_eq!(USER_POSITIVE.len(), 5 + 13 + 1 + 13 + 1 + 13 + 1 + 32);
        assert_ne!(USER_POSITIVE, USER_NO_SEPARATOR_TWIN);
        assert_eq!(USER_NO_SEPARATOR_TWIN.len(), USER_POSITIVE.len() - 1);
    }

    #[test]
    fn detects_the_user_form_with_exact_metadata() {
        let candidates = detect(USER_POSITIVE);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "slack_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, USER_POSITIVE.len()).unwrap()
        );
    }

    #[test]
    fn rejects_a_user_value_missing_the_dash_before_the_secret_section() {
        assert!(ranges(USER_NO_SEPARATOR_TWIN).is_empty());
    }

    #[test]
    fn rejects_a_user_numeric_section_one_byte_off_from_the_documented_width() {
        for bad_len in [9, 14] {
            let bad = "1".repeat(bad_len);
            let good = "1".repeat(SECTION_MIN);
            let input = format!("xoxp-{bad}-{good}-{good}-SYNTHETICREVOKEDUSERSECRETVALUE1");
            assert!(ranges(&input).is_empty(), "{bad_len}");
        }
    }

    #[test]
    fn accepts_every_documented_numeric_width_from_ten_to_thirteen_for_the_user_form() {
        for len in SECTION_MIN..=SECTION_MAX {
            let section = "7".repeat(len);
            let input =
                format!("xoxp-{section}-{section}-{section}-SYNTHETICREVOKEDUSERSECRETVALUE1");
            assert_eq!(ranges(&input), vec![(0, input.len())], "{len}");
        }
    }

    #[test]
    fn rejects_a_user_secret_section_one_byte_short_of_the_twenty_eight_byte_floor() {
        let short_secret = "S".repeat(USER_SECRET_MIN - 1);
        let input = format!("xoxp-1234567890123-3210987654321-1112223334445-{short_secret}");
        assert!(ranges(&input).is_empty());
    }

    #[test]
    fn accepts_a_user_secret_section_at_exactly_the_twenty_eight_byte_floor() {
        let secret = "S".repeat(USER_SECRET_MIN);
        let input = format!("xoxp-1234567890123-3210987654321-1112223334445-{secret}");
        assert_eq!(ranges(&input), vec![(0, input.len())]);
    }

    #[test]
    fn rejects_a_user_secret_section_containing_a_dash_or_underscore() {
        // The secret alphabet is `[A-Za-z0-9]` only, narrower than the
        // `[A-Za-z0-9_-]` boundary, the same choice the bot secret makes.
        for byte in ['_', '-'] {
            let mut secret = "S".repeat(USER_SECRET_MIN);
            secret.replace_range(5..6, &byte.to_string());
            let input = format!("xoxp-1234567890123-3210987654321-1112223334445-{secret}");
            assert!(ranges(&input).is_empty(), "{byte}");
        }
    }

    #[test]
    fn a_user_section_grammar_failure_never_falls_back_to_the_interim_guard() {
        // A long enough `xoxp-` body with no `-`-separated section grammar
        // at all: the shape the pre-#512 interim guard used to accept.
        let input = "xoxp-SYNTHETICREVOKEDINTERIMVALUE0123456789";
        assert!(ranges(input).is_empty());
    }

    #[test]
    fn detects_every_variant_in_the_same_input_without_one_suppressing_another() {
        let input = format!("{BOT_POSITIVE}\n{USER_POSITIVE}");
        let second_start = BOT_POSITIVE.len() + 1;
        assert_eq!(
            ranges(&input),
            vec![
                (0, BOT_POSITIVE.len()),
                (second_start, second_start + USER_POSITIVE.len())
            ]
        );
    }

    #[test]
    fn rotation_prefixes_require_the_documented_single_digit_version_section() {
        for prefix in ["xoxe-", "xoxe.xoxb-", "xoxe.xoxp-"] {
            let input = format!("{prefix}1-{OPAQUE_TWENTY_BYTE_BODY}");
            assert_eq!(ranges(&input), vec![(0, input.len())], "{prefix}");
        }
    }

    #[test]
    fn rotation_prefixes_reject_a_version_section_of_zero_or_two_digits() {
        let tail = "SYNTHETICREVOKEDROTATIONVALUE01234";
        for prefix in ["xoxe-", "xoxe.xoxb-", "xoxe.xoxp-"] {
            // Zero digits: the shape the pre-#512 interim guard used to
            // accept via its bare opaque-suffix rule.
            let no_digit = format!("{prefix}{tail}");
            assert!(ranges(&no_digit).is_empty(), "{prefix} zero-digit");
            // Two digits: every provider example shows exactly one.
            let two_digit = format!("{prefix}12-{tail}");
            assert!(ranges(&two_digit).is_empty(), "{prefix} two-digit");
        }
    }

    #[test]
    fn rotation_prefixes_keep_the_beta4_twenty_byte_body_floor_after_the_version_section() {
        let body = "SYNTHETICREVOKEDINTERIMVALUE0123456789";
        for prefix in ["xoxe-", "xoxe.xoxb-", "xoxe.xoxp-"] {
            let input = format!("{prefix}1-{}", &body[..ROTATION_TAIL_MIN]);
            assert_eq!(ranges(&input), vec![(0, input.len())], "{prefix}");
            let one_short = format!("{prefix}1-{}", &body[..ROTATION_TAIL_MIN - 1]);
            assert!(ranges(&one_short).is_empty(), "{prefix} one-short");
        }
    }

    /// Issue #551: before this fix, the rotation tail's open floor
    /// (`RunLength::AtLeast`-equivalent) matched any run of 20 or more bytes
    /// in full, so a body longer than the floor was indistinguishable from a
    /// directly-glued wider identifier -- exactly the shared boundary defect
    /// this issue closes. A body past the now-exact 20-byte length is an
    /// intentional false negative until a reviewed contract establishes a
    /// real maximum.
    #[test]
    fn rotation_prefixes_reject_a_tail_longer_than_the_exact_twenty_byte_length() {
        let body = "SYNTHETICREVOKEDINTERIMVALUE0123456789";
        for prefix in ["xoxe-", "xoxe.xoxb-", "xoxe.xoxp-"] {
            let input = format!("{prefix}1-{}", &body[..=ROTATION_TAIL_MIN]);
            assert!(ranges(&input).is_empty(), "{prefix}");
        }
    }

    /// Issue #551: the shared boundary/delimiter regression set, mirrored
    /// from `digitalocean-token`'s existing leading/trailing/dash
    /// identifier-embedding fixtures, for every rotation prefix.
    #[test]
    fn rotation_prefixes_reject_every_value_embedded_in_a_wider_identifier() {
        for prefix in ["xoxe-", "xoxe.xoxb-", "xoxe.xoxp-"] {
            let value = format!("{prefix}1-{OPAQUE_TWENTY_BYTE_BODY}");
            assert!(ranges(&format!("legacy{value}")).is_empty(), "{value}");
            assert!(ranges(&format!("{value}_backup")).is_empty(), "{value}");
            assert!(ranges(&format!("{value}-1")).is_empty(), "{value}");
        }
    }

    #[test]
    fn every_rotation_prefix_is_detected_independently_in_the_same_input() {
        let tail = OPAQUE_TWENTY_BYTE_BODY;
        let refresh = format!("xoxe-1-{tail}");
        let rotating_bot = format!("xoxe.xoxb-1-{tail}");
        let rotating_user = format!("xoxe.xoxp-1-{tail}");
        let input = format!("{refresh}\n{rotating_bot}\n{rotating_user}");
        let second_start = refresh.len() + 1;
        let third_start = second_start + rotating_bot.len() + 1;
        assert_eq!(
            ranges(&input),
            vec![
                (0, refresh.len()),
                (second_start, second_start + rotating_bot.len()),
                (third_start, third_start + rotating_user.len())
            ]
        );
    }

    #[test]
    fn a_bot_shaped_body_under_the_rotating_bot_prefix_is_not_reread_as_a_plain_bot_value() {
        // The `xoxb-` tail of this value is itself a structurally valid bot
        // token, but it is the tail of the more specific `xoxe.xoxb-`
        // prefix, whose own rotation grammar this body does not satisfy
        // (the version section is 13 digits, not the documented one), so it
        // must not fall back to being read as a standalone bot match.
        let input = "xoxe.xoxb-1234567890123-3210987654321-SYNTHETICREVOKEDBOTSECRET1";
        assert!(ranges(input).is_empty());
    }

    #[test]
    fn a_rotating_bot_value_matching_the_documented_shape_is_one_whole_value_match() {
        let input = format!("xoxe.xoxb-1-{OPAQUE_TWENTY_BYTE_BODY}");
        assert_eq!(ranges(&input), vec![(0, input.len())]);
        assert!(ranges(&format!("a{input}")).is_empty());
    }

    #[test]
    fn interim_prefixes_keep_the_beta4_minimum_length_rule_unchanged() {
        for prefix in ["xapp-", "xwfp-"] {
            let body = "SYNTHETICREVOKEDINTERIMVALUE0123456789";
            let input = format!("{prefix}{}", &body[..INTERIM_MIN_LEN]);
            assert_eq!(ranges(&input), vec![(0, input.len())], "{prefix}");
            let one_short = format!("{prefix}{}", &body[..INTERIM_MIN_LEN - 1]);
            assert!(ranges(&one_short).is_empty(), "{prefix} one-short");
        }
    }

    /// Issue #321 dimensions, carried over from `additional_providers.rs`
    /// for Slack's still-interim-guarded prefixes (issue #371 moved Slack
    /// to its own module; issue #512 promoted every other prefix to a
    /// structural contract, leaving only `xapp-`/`xwfp-` here).
    #[test]
    fn interim_prefixes_accept_an_all_valid_alphabet_documentation_placeholder() {
        let value = format!("xapp-{}", "x".repeat(20));
        let candidates = detect(&value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn interim_prefixes_reject_the_prefix_embedded_in_a_wider_identifier() {
        let value = "legacyxapp-SYNTHETIC_REVOKED_KEY_VALUE";
        assert!(ranges(value).is_empty());
    }

    /// Issue #551: before this fix, `xapp-`/`xwfp-`'s open floor matched any
    /// run of 20 or more bytes in full, so a body longer than the floor was
    /// indistinguishable from a directly-glued wider identifier -- the same
    /// shared boundary defect fixed for `xoxe-`/`xoxe.xoxb-`/`xoxe.xoxp-` and
    /// `lin_oauth_` (`super::linear`). A body past the now-exact 20-byte
    /// length is an intentional false negative until a reviewed contract
    /// establishes a real maximum. This is also the shared boundary/
    /// delimiter regression set, mirrored from `digitalocean-token`'s
    /// existing leading/trailing/dash identifier-embedding fixtures.
    #[test]
    fn interim_prefixes_reject_a_body_longer_than_exact_or_embedded_in_a_wider_identifier() {
        for prefix in ["xapp-", "xwfp-"] {
            let value = format!("{prefix}{OPAQUE_TWENTY_BYTE_BODY}");
            assert!(
                ranges(&format!("{prefix}{OPAQUE_TWENTY_BYTE_BODY}0")).is_empty(),
                "{value}"
            );
            assert!(ranges(&format!("legacy{value}")).is_empty(), "{value}");
            assert!(ranges(&format!("{value}_backup")).is_empty(), "{value}");
            assert!(ranges(&format!("{value}-1")).is_empty(), "{value}");
        }
    }

    #[test]
    fn interim_prefixes_reject_a_percent_encoded_delimiter_lookalike() {
        let value = "xapp%2DSYNTHETIC_REVOKED_CONFORMANCE_KEY";
        assert!(ranges(value).is_empty());
    }

    #[test]
    fn interim_prefixes_report_a_repeated_identical_value_once_per_occurrence() {
        let value = format!("xapp-{OPAQUE_TWENTY_BYTE_BODY}");
        let input = format!("{value} {value}");
        assert_eq!(detect(&input).len(), 2);
    }

    #[test]
    fn xapp_and_xwfp_are_not_promoted_to_a_digit_section_grammar() {
        // Issue #512: `xapp-`'s only candidate structure is a single
        // uncorroborated tool source and `xwfp-` has no tool source at all
        // (docs/audits/evidence/367/precision-contracts.json,
        // `slack-token.variants[app-level|workflow]`), so a value shaped
        // like the bot/user digit-section grammar is still accepted by the
        // plain opaque-suffix guard rather than being required to have one.
        // The dash-bearing body is exactly the 20-byte length issue #551
        // requires (a longer one is now rejected, below).
        for prefix in ["xapp-", "xwfp-"] {
            let input = format!("{prefix}1234567890123-321098");
            assert_eq!(ranges(&input), vec![(0, input.len())], "{prefix}");
        }
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

    /// The shape issue #371 attached, with the ranges it expects: the
    /// negative twin differs from its paired positive in exactly one
    /// structural property — the dash before the secret section. Issue #419
    /// replaced the original snapshot's real-looking random bytes with the
    /// same canonical digit sections and `SYNTHETIC…` secret marker used by
    /// [`BOT_POSITIVE`] above, keeping every byte length exactly as
    /// reviewed.
    #[test]
    fn issue_371_twins_are_rejected_and_their_paired_positives_preserved() {
        const UNICODE_CRLF: &str = "# \u{1F511} reviewed format\r\n";
        let bot_positive = "xoxb-1234567890123-3210987654321-SYNTHETICBOTSECRETSYNT";
        let bot_twin = "xoxb-1234567890123-3210987654321SYNTHETICBOTSECRETSYNT";

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
