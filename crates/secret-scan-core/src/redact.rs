//! Single-pass redaction: replaces `block` and `redact` findings with
//! placeholder text produced by a [`PlaceholderFormatter`], leaving `warn`
//! and `allow` findings untouched.
//!
//! Redaction never exposes a matched value: it does not accept the value
//! itself (only [`Finding`] metadata and the immutable `input`), and every
//! failure is a sanitized [`SecretScanError`].

use crate::error::{FormatterFailure, SecretScanError, SecretScanErrorCode};
use crate::limits::WholeInputLimits;
use crate::types::{ByteRange, Finding, PlaceholderContext, PlaceholderFormatter};

/// Maximum length in bytes of a placeholder a [`PlaceholderFormatter`] may
/// return.
pub const MAX_PLACEHOLDER_LENGTH: usize = 256;

/// The default formatter: `<SECRET_N>`, `N` one-based among replaced
/// findings.
///
/// `N` counts only findings whose action replaces text, so `warn` and
/// `allow` findings do not consume a number.
///
/// # Errors
///
/// Never fails.
pub fn default_placeholder_formatter(
    _finding: &Finding,
    context: &PlaceholderContext,
) -> Result<String, FormatterFailure> {
    Ok(format!("<SECRET_{}>", context.placeholder_index()))
}

/// A formatter that names the finding type: `<TYPE_NAME_N>`, upper-cased
/// with `.` and `-` mapped to `_`.
///
/// The type name is a validated identifier
/// ([`is_identifier`](crate::is_identifier)), never a matched value, so the
/// placeholder cannot carry input.
///
/// # Errors
///
/// Never fails.
pub fn typed_placeholder_formatter(
    finding: &Finding,
    context: &PlaceholderContext,
) -> Result<String, FormatterFailure> {
    let normalized = finding
        .type_name()
        .to_ascii_uppercase()
        .replace(['.', '-'], "_");
    Ok(format!("<{normalized}_{}>", context.placeholder_index()))
}

/// Matched values eligible to be reproduced by a placeholder, held as
/// borrowed slices of `input` (sorted, deduplicated) so no matched text is
/// copied. A formatter output is checked by walking an implicit trie over
/// the sorted slices.
///
/// Every finding in the call contributes its matched text, regardless of its
/// own action: a `warn`/`allow` finding's value must not reappear inside a
/// sibling `redact`/`block` finding's placeholder any more than a
/// `redact`/`block` finding's own value may. Only findings whose matched
/// text is no longer than [`MAX_PLACEHOLDER_LENGTH`] are eligible: a longer
/// matched value can never fit inside a valid placeholder, so indexing it
/// would be wasted work. (A `ByteRange` is never empty, so neither is an indexed value.)
struct ForbiddenMatchedText<'a> {
    values: Vec<&'a str>,
    /// Length of the shortest indexed value; windows shorter than this
    /// cannot match.
    shortest: usize,
}

impl<'a> ForbiddenMatchedText<'a> {
    fn build(input: &'a str, findings: &[&Finding]) -> Self {
        let mut values: Vec<&'a str> = findings
            .iter()
            .map(|finding| finding.range())
            .filter(|range| range.len() <= MAX_PLACEHOLDER_LENGTH)
            .map(|range| &input[range.start()..range.end()])
            .collect();
        values.sort_unstable();
        values.dedup();
        let shortest = values.iter().map(|value| value.len()).min().unwrap_or(0);
        Self { values, shortest }
    }

    /// `true` when `placeholder` contains any indexed matched value as a
    /// substring starting and ending on character boundaries.
    fn contains(&self, placeholder: &str) -> bool {
        if self.values.is_empty() {
            return false;
        }
        let shortest = self.shortest;
        let bytes = placeholder.as_bytes();
        for start in 0..bytes.len() {
            if bytes.len() - start < shortest {
                break;
            }
            if !placeholder.is_char_boundary(start) {
                continue;
            }
            let (mut lo, mut hi) = (0, self.values.len());
            let mut depth = 0;
            loop {
                // Sorted order puts the value exactly `depth` bytes long,
                // if any, first among those sharing this prefix.
                if self.values[lo].len() == depth {
                    if placeholder.is_char_boundary(start + depth) {
                        return true;
                    }
                    lo += 1;
                    if lo == hi {
                        break;
                    }
                }
                let Some(&byte) = bytes.get(start + depth) else {
                    break;
                };
                let window = &self.values[lo..hi];
                let below = window.partition_point(|value| value.as_bytes()[depth] < byte);
                let through = below
                    + window[below..].partition_point(|value| value.as_bytes()[depth] <= byte);
                (lo, hi) = (lo + below, lo + through);
                if lo == hi {
                    break;
                }
                depth += 1;
            }
        }
        false
    }
}

fn ordered_and_disjoint<'a>(
    findings: &'a [Finding],
    input: &str,
) -> Result<Vec<&'a Finding>, SecretScanError> {
    for finding in findings {
        if !finding.range().is_char_aligned_in(input) {
            return Err(SecretScanErrorCode::InvalidFindings.into());
        }
    }

    let mut ordered: Vec<&Finding> = findings.iter().collect();
    ordered.sort_by_key(|finding| (finding.range().start(), finding.range().end()));

    let mut previous_end = 0;
    for finding in &ordered {
        let range: ByteRange = finding.range();
        if range.start() < previous_end {
            return Err(SecretScanErrorCode::InvalidFindings.into());
        }
        previous_end = range.end();
    }

    Ok(ordered)
}

/// Reconstructs `input` in one ordered pass: `warn` and `allow` findings
/// pass their span through unchanged; `redact` and `block` findings have
/// their span replaced by `formatter`'s output.
///
/// `findings` need not be pre-sorted. This function sorts them and rejects
/// overlapping ranges before producing output; it does not resolve overlaps.
///
/// # Examples
///
/// ```
/// use redact_secret::{
///     DefaultPolicy, DetectorRegistry, default_placeholder_formatter, redact, scan,
///     typed_placeholder_formatter,
/// };
///
/// let registry = DetectorRegistry::with_built_in([])?;
/// let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
/// let findings = scan(input, &registry, &DefaultPolicy)?;
///
/// assert_eq!(redact(input, &findings, &default_placeholder_formatter)?, "API_KEY=<SECRET_1>");
/// assert_eq!(redact(input, &findings, &typed_placeholder_formatter)?, "API_KEY=<GITHUB_TOKEN_1>");
///
/// // A formatter is any `Fn(&Finding, &PlaceholderContext) -> Result<String, _>`.
/// let by_type = |finding: &redact_secret::Finding, _: &redact_secret::PlaceholderContext| {
///     Ok(format!("[{}]", finding.type_name()))
/// };
/// assert_eq!(redact(input, &findings, &by_type)?, "API_KEY=[github_token]");
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
///
/// # Errors
///
/// - [`SecretScanErrorCode::InputLimitExceeded`] when `input` exceeds the
///   default [`WholeInputLimits::max_input_bytes`](crate::WholeInputLimits::max_input_bytes).
/// - [`SecretScanErrorCode::FindingLimitExceeded`] when `findings.len()`
///   exceeds the default
///   [`WholeInputLimits::max_findings`](crate::WholeInputLimits::max_findings).
/// - [`SecretScanErrorCode::InvalidFindings`] when a finding's range falls
///   outside `input`, is not character-aligned, or overlaps another
///   finding.
/// - [`SecretScanErrorCode::PlaceholderFailure`] when `formatter` fails.
/// - [`SecretScanErrorCode::InvalidPlaceholder`] when `formatter` returns an
///   empty placeholder, a placeholder longer than
///   [`MAX_PLACEHOLDER_LENGTH`], or a placeholder that reproduces any
///   finding's matched value in `findings` (including a `warn`/`allow`
///   finding's), not only the finding the placeholder is for.
///
/// No error carries `input`, a matched value, or a placeholder. See
/// [`redact_with_limits`] to use a different limit set.
pub fn redact(
    input: &str,
    findings: &[Finding],
    formatter: &dyn PlaceholderFormatter,
) -> Result<String, SecretScanError> {
    redact_with_limits(input, findings, formatter, &WholeInputLimits::default())
}

/// Same as [`redact`], against `limits` instead of the default
/// [`WholeInputLimits`].
///
/// # Errors
///
/// Every [`redact`] error, checked against `limits` instead of the default.
pub fn redact_with_limits(
    input: &str,
    findings: &[Finding],
    formatter: &dyn PlaceholderFormatter,
    limits: &WholeInputLimits,
) -> Result<String, SecretScanError> {
    limits.check_input(input)?;
    limits.check_findings(findings.len())?;
    let ordered = ordered_and_disjoint(findings, input)?;
    let forbidden = ForbiddenMatchedText::build(input, &ordered);

    // Phase 1: format and validate every replaced finding in order, so the
    // formatter call order and the first error are unchanged and no partial
    // output exists when a placeholder fails.
    let mut placeholders: Vec<String> = Vec::new();
    let mut output_len = input.len();
    for finding in ordered
        .iter()
        .filter(|finding| finding.action().replaces_text())
    {
        let context = PlaceholderContext::new(placeholders.len() + 1);
        let placeholder = formatter
            .format(finding, &context)
            .map_err(|_| SecretScanError::new(SecretScanErrorCode::PlaceholderFailure))?;
        if placeholder.is_empty()
            || placeholder.len() > MAX_PLACEHOLDER_LENGTH
            || forbidden.contains(&placeholder)
        {
            return Err(SecretScanErrorCode::InvalidPlaceholder.into());
        }
        output_len = output_len - finding.range().len() + placeholder.len();
        placeholders.push(placeholder);
    }

    // Phase 2: copy into a buffer of exactly the final size.
    let mut output = String::with_capacity(output_len);
    let mut cursor = 0;
    let replaced = ordered
        .into_iter()
        .filter(|finding| finding.action().replaces_text());
    for (finding, placeholder) in replaced.zip(&placeholders) {
        let range = finding.range();
        output.push_str(&input[cursor..range.start()]);
        output.push_str(placeholder);
        cursor = range.end();
    }
    output.push_str(&input[cursor..]);
    debug_assert_eq!(output.len(), output_len);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, Confidence};

    fn finding(id: &str, start: usize, end: usize, action: Action) -> Finding {
        Finding::new(
            id,
            "synthetic-credential",
            "synthetic-detector",
            Confidence::High,
            action,
            ByteRange::new(start, end).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn reconstructs_repeated_and_adjacent_values_in_one_deterministic_pass() {
        let input = "SYNTHETIC_ONE|SYNTHETIC_ONE|SYNTHETIC_TWO";
        let findings = [
            finding("finding-3", 28, input.len(), Action::Block),
            finding("finding-1", 0, 13, Action::Redact),
            finding("finding-2", 14, 27, Action::Redact),
        ];
        let output = redact(input, &findings, &default_placeholder_formatter).unwrap();
        assert_eq!(output, "<SECRET_1>|<SECRET_2>|<SECRET_3>");
        assert_eq!(
            output,
            redact(input, &findings, &default_placeholder_formatter).unwrap()
        );
    }

    #[test]
    fn leaves_warn_and_allow_findings_unchanged_without_consuming_numbers() {
        let input = "WARN|ALLOW|REDACTED_VALUE";
        let findings = [
            finding("finding-1", 0, 4, Action::Warn),
            finding("finding-2", 5, 10, Action::Allow),
            finding("finding-3", 11, input.len(), Action::Redact),
        ];
        assert_eq!(
            redact(input, &findings, &default_placeholder_formatter).unwrap(),
            "WARN|ALLOW|<SECRET_1>"
        );
    }

    #[test]
    fn redacts_adjacent_findings_without_dropping_or_duplicating_text() {
        let input = "SYNTHETIC_ONESYNTHETIC_TWO";
        let findings = [
            finding("finding-1", 0, 13, Action::Redact),
            finding("finding-2", 13, 26, Action::Redact),
        ];
        assert_eq!(
            redact(input, &findings, &default_placeholder_formatter).unwrap(),
            "<SECRET_1><SECRET_2>"
        );
    }

    /// A placeholder shorter or longer than the text it replaces must not
    /// perturb the original byte span of a later finding: every span this
    /// function consults is a byte offset into `input`, never into the
    /// output being built, and multibyte characters around and between the
    /// findings must survive untouched (`decision-govern-cross-language-
    /// conformance`).
    #[test]
    fn redacts_correctly_around_multibyte_text_when_placeholder_length_differs_from_the_match() {
        let input = "键SYNTHETIC_ONE \u{1F511} SYNTHETIC_TWO";
        let findings = [
            finding("finding-1", 3, 16, Action::Redact),
            finding("finding-2", 22, 35, Action::Redact),
        ];
        let asymmetric = |_: &Finding, context: &PlaceholderContext| {
            Ok(if context.placeholder_index() == 1 {
                "X".to_string()
            } else {
                "REPLACED_WITH_MUCH_LONGER_TEXT".to_string()
            })
        };
        assert_eq!(
            redact(input, &findings, &asymmetric).unwrap(),
            "键X \u{1F511} REPLACED_WITH_MUCH_LONGER_TEXT"
        );
    }

    #[test]
    fn supports_typed_placeholders() {
        let input = "SYNTHETIC_REVOKED_VALUE";
        let findings = [finding("finding-1", 0, input.len(), Action::Redact)];
        assert_eq!(
            redact(input, &findings, &typed_placeholder_formatter).unwrap(),
            "<SYNTHETIC_CREDENTIAL_1>"
        );
    }

    #[test]
    fn sanitizes_formatter_failures() {
        let input = "SYNTHETIC_REVOKED_VALUE";
        let findings = [finding("finding-1", 0, input.len(), Action::Redact)];
        let failing = |_: &Finding, _: &PlaceholderContext| Err(FormatterFailure);
        let error = redact(input, &findings, &failing).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::PlaceholderFailure);
        assert!(!error.to_string().contains(input));
    }

    #[test]
    fn rejects_empty_and_oversized_placeholders() {
        let input = "SYNTHETIC_REVOKED_VALUE";
        let findings = [finding("finding-1", 0, input.len(), Action::Redact)];
        let empty = |_: &Finding, _: &PlaceholderContext| Ok(String::new());
        assert_eq!(
            redact(input, &findings, &empty).unwrap_err().code(),
            SecretScanErrorCode::InvalidPlaceholder
        );
        let oversized =
            |_: &Finding, _: &PlaceholderContext| Ok("x".repeat(MAX_PLACEHOLDER_LENGTH + 1));
        assert_eq!(
            redact(input, &findings, &oversized).unwrap_err().code(),
            SecretScanErrorCode::InvalidPlaceholder
        );
    }

    #[test]
    fn rejects_a_placeholder_containing_any_eligible_matched_value() {
        let input = "SYNTHETIC_ONE|SYNTHETIC_TWO|SYNTHETIC_ONE";
        let findings = [
            finding("finding-1", 0, 13, Action::Redact),
            finding("finding-2", 14, 27, Action::Redact),
            finding("finding-3", 28, input.len(), Action::Redact),
        ];
        let formatter = |_: &Finding, context: &PlaceholderContext| {
            Ok(if context.placeholder_index() == 1 {
                "<SYNTHETIC_TWO>".to_string()
            } else {
                format!("<REMOVED_{}>", context.placeholder_index())
            })
        };
        assert_eq!(
            redact(input, &findings, &formatter).unwrap_err().code(),
            SecretScanErrorCode::InvalidPlaceholder
        );
    }

    /// Regression for issue #887: `ForbiddenMatchedText` used to index only
    /// `redact`/`block` findings, so a formatter could embed a sibling
    /// `warn`/`allow` finding's matched value into an unrelated `redact`
    /// finding's placeholder without `redact()` rejecting it.
    #[test]
    fn rejects_a_placeholder_reproducing_a_warn_or_allow_findings_value() {
        let input = "SYNTHETIC_ONE|SYNTHETIC_TWO";
        let findings = [
            finding("finding-1", 0, 13, Action::Redact),
            finding("finding-2", 14, input.len(), Action::Warn),
        ];
        let formatter = |_: &Finding, _: &PlaceholderContext| Ok("<SYNTHETIC_TWO>".to_string());
        assert_eq!(
            redact(input, &findings, &formatter).unwrap_err().code(),
            SecretScanErrorCode::InvalidPlaceholder
        );
    }

    #[test]
    fn rejects_formatter_reproduction_of_a_short_caller_supplied_finding() {
        for input in ["x", "xy", "xyz"] {
            let findings = [finding("finding-1", 0, input.len(), Action::Redact)];
            let value = input.to_string();
            let formatter = move |_: &Finding, _: &PlaceholderContext| Ok(format!("<{value}>"));
            assert_eq!(
                redact(input, &findings, &formatter).unwrap_err().code(),
                SecretScanErrorCode::InvalidPlaceholder,
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_overlapping_findings() {
        let input = "SYNTHETIC_REVOKED_VALUE";
        let findings = [
            finding("finding-1", 0, 10, Action::Redact),
            finding("finding-2", 5, 15, Action::Redact),
        ];
        let error = redact(input, &findings, &default_placeholder_formatter).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidFindings);
        assert!(!error.to_string().contains(input));
    }

    #[test]
    fn rejects_out_of_range_findings() {
        let input = "SYNTHETIC_REVOKED_VALUE";
        let findings = [finding("finding-1", 0, input.len() + 1, Action::Redact)];
        assert_eq!(
            redact(input, &findings, &default_placeholder_formatter)
                .unwrap_err()
                .code(),
            SecretScanErrorCode::InvalidFindings
        );
    }

    #[test]
    fn returns_input_unchanged_when_no_findings_replace_text() {
        let input = "ordinary text";
        assert_eq!(
            redact(input, &[], &default_placeholder_formatter).unwrap(),
            input
        );
    }

    // ---- differential oracle: the pre-#1076 implementation, verbatim ----
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;

    struct OldForbidden {
        by_length: BTreeMap<usize, BTreeSet<String>>,
    }

    impl OldForbidden {
        fn build(input: &str, findings: &[&Finding]) -> Self {
            let mut by_length: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
            for finding in findings {
                let range = finding.range();
                if range.len() > MAX_PLACEHOLDER_LENGTH {
                    continue;
                }
                by_length
                    .entry(range.len())
                    .or_default()
                    .insert(input[range.start()..range.end()].to_string());
            }
            Self { by_length }
        }

        /// `true` when `placeholder` contains any indexed matched value as a
        /// substring.
        ///
        /// `by_length` iterates in ascending key order, so the scan stops as
        /// soon as a length exceeds what remains of `placeholder`.
        fn contains(&self, placeholder: &str) -> bool {
            for (&length, values) in &self.by_length {
                if length == 0 || length > placeholder.len() {
                    continue;
                }
                let mut start = 0;
                while start + length <= placeholder.len() {
                    if placeholder.is_char_boundary(start)
                        && placeholder.is_char_boundary(start + length)
                        && values.contains(&placeholder[start..start + length])
                    {
                        return true;
                    }
                    start += 1;
                }
            }
            false
        }
    }

    fn oracle_redact(
        input: &str,
        findings: &[Finding],
        formatter: &dyn PlaceholderFormatter,
    ) -> Result<String, SecretScanError> {
        let ordered = ordered_and_disjoint(findings, input)?;
        let forbidden = OldForbidden::build(input, &ordered);
        let mut output = String::with_capacity(input.len());
        let mut cursor = 0;
        let mut placeholder_index = 0;
        for finding in ordered {
            if !finding.action().replaces_text() {
                continue;
            }
            let range = finding.range();
            output.push_str(&input[cursor..range.start()]);
            placeholder_index += 1;
            let context = PlaceholderContext::new(placeholder_index);
            let placeholder = formatter
                .format(finding, &context)
                .map_err(|_| SecretScanError::new(SecretScanErrorCode::PlaceholderFailure))?;
            if placeholder.is_empty()
                || placeholder.len() > MAX_PLACEHOLDER_LENGTH
                || forbidden.contains(&placeholder)
            {
                return Err(SecretScanErrorCode::InvalidPlaceholder.into());
            }
            output.push_str(&placeholder);
            cursor = range.end();
        }
        output.push_str(&input[cursor..]);
        Ok(output)
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % n as u64).unwrap()
        }
    }

    /// Small alphabet with multibyte characters so that values, prefixes and
    /// char-boundary cases collide often.
    const ALPHABET: [&str; 8] = ["a", "b", "ab", "é", "键", "\u{1F511}", "a", "b"];

    fn random_text(rng: &mut Rng, max_units: usize) -> String {
        (0..rng.below(max_units + 1))
            .map(|_| ALPHABET[rng.below(ALPHABET.len())])
            .collect()
    }

    fn char_starts(text: &str) -> Vec<usize> {
        let mut starts: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
        starts.push(text.len());
        starts
    }

    #[test]
    fn differential_against_the_pre_1076_implementation() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for case in 0..6000 {
            let input = random_text(&mut rng, if case % 50 == 0 { 400 } else { 24 });
            let bounds = char_starts(&input);
            // Random disjoint findings, some empty, some long, mixed actions.
            let mut findings = Vec::new();
            let mut at = 0;
            while at < bounds.len() {
                if at + 1 < bounds.len() && rng.below(3) == 0 {
                    let end_index = (at + 1 + rng.below(if case % 50 == 0 { 300 } else { 5 }))
                        .min(bounds.len() - 1);
                    let action =
                        [Action::Redact, Action::Block, Action::Warn, Action::Allow][rng.below(4)];
                    findings.push(finding("finding-1", bounds[at], bounds[end_index], action));
                    at = end_index;
                }
                at += 1;
            }
            // Fixed placeholder pool: derived from input pieces, so some collide.
            let mut prng = Rng(rng.next() | 1);
            let pool: Vec<String> = (0..4)
                .map(|_| match prng.below(6) {
                    0 => String::new(),
                    1 => "x".repeat(MAX_PLACEHOLDER_LENGTH + 1),
                    2 | 3 => format!("<{}>", random_text(&mut prng, 6)),
                    4 => random_text(&mut prng, 300),
                    _ => format!("<R{}>", prng.below(100)),
                })
                .collect();
            let fail_at = prng.below(12);
            let build = |log: std::rc::Rc<std::cell::RefCell<Vec<usize>>>| {
                let pool = pool.clone();
                move |_: &Finding, context: &PlaceholderContext| {
                    log.borrow_mut().push(context.placeholder_index());
                    if context.placeholder_index() == fail_at {
                        return Err(FormatterFailure);
                    }
                    Ok(pool[context.placeholder_index() % pool.len()].clone())
                }
            };
            let old_log = std::rc::Rc::<std::cell::RefCell<Vec<usize>>>::default();
            let new_log = std::rc::Rc::<std::cell::RefCell<Vec<usize>>>::default();
            let old = oracle_redact(&input, &findings, &build(std::rc::Rc::clone(&old_log)));
            let new = redact(&input, &findings, &build(std::rc::Rc::clone(&new_log)));
            assert_eq!(
                old.as_ref().map_err(|e| e.code()),
                new.as_ref().map_err(|e| e.code()),
                "case {case}"
            );
            assert_eq!(
                *old_log.borrow(),
                *new_log.borrow(),
                "call order, case {case}"
            );
            if let Ok(output) = &new {
                assert_eq!(output.capacity(), output.len(), "case {case}");
            }
        }
    }

    #[test]
    fn index_matches_the_oracle_on_random_placeholders() {
        let mut rng = Rng(0xD1B5_4A32_C192_ED03);
        let mut hits = 0;
        for case in 0..4000 {
            let input = random_text(&mut rng, 40);
            let bounds = char_starts(&input);
            let mut findings = Vec::new();
            let mut at = 0;
            while at + 1 < bounds.len() {
                let end = (at + 1 + rng.below(4)).min(bounds.len() - 1);
                findings.push(finding("finding-1", bounds[at], bounds[end], Action::Warn));
                at = end;
            }
            let refs: Vec<&Finding> = findings.iter().collect();
            let old = OldForbidden::build(&input, &refs);
            let new = ForbiddenMatchedText::build(&input, &refs);
            for _ in 0..20 {
                let placeholder = random_text(&mut rng, 12);
                let expected = old.contains(&placeholder);
                hits += usize::from(expected);
                assert_eq!(expected, new.contains(&placeholder), "case {case}");
            }
        }
        assert!(hits > 1000, "generator must exercise the matching branch");
    }

    #[test]
    fn index_handles_empty_input_multibyte_and_boundary_edges() {
        let refs: Vec<&Finding> = Vec::new();
        assert!(!ForbiddenMatchedText::build("", &refs).contains("anything"));
        // A value of continuation-looking bytes never matches mid-character.
        let input = "é";
        let findings = [finding("finding-1", 0, 2, Action::Redact)];
        let refs: Vec<&Finding> = findings.iter().collect();
        let index = ForbiddenMatchedText::build(input, &refs);
        assert!(index.contains("<é>"));
        assert!(!index.contains("<e\u{301}>"));
        assert!(!index.contains(""));
        // Overlong values are not indexed; value equal to the maximum is.
        let long = "a".repeat(MAX_PLACEHOLDER_LENGTH + 1);
        let findings = [finding("finding-1", 0, long.len(), Action::Redact)];
        let refs: Vec<&Finding> = findings.iter().collect();
        assert!(!ForbiddenMatchedText::build(&long, &refs).contains(&"a".repeat(256)));
        let max = "a".repeat(MAX_PLACEHOLDER_LENGTH);
        let findings = [finding("finding-1", 0, max.len(), Action::Redact)];
        let refs: Vec<&Finding> = findings.iter().collect();
        assert!(ForbiddenMatchedText::build(&max, &refs).contains(&max));
    }

    #[test]
    fn output_capacity_equals_length_when_placeholders_grow_or_shrink() {
        let input = "aaa|SYNTHETIC_REVOKED_VALUE|é";
        let findings = [
            finding("finding-1", 0, 3, Action::Redact),
            finding("finding-2", 4, 27, Action::Redact),
        ];
        let output = redact(input, &findings, &default_placeholder_formatter).unwrap();
        assert_eq!(output.capacity(), output.len());
        let output = redact(input, &[], &default_placeholder_formatter).unwrap();
        assert_eq!(output.capacity(), output.len());
    }

    /// Invariant fuzz (fixed seed, 20000 cases) on the public `redact`
    /// contract: action gate, placeholder boundary, exact reconstruction,
    /// determinism, exact capacity, and forged-range rejection without panic.
    #[test]
    fn redact_invariants_hold_on_20000_random_cases() {
        let mut rng = Rng(0xA5A5_1076_0000_0001);
        for case in 0..20_000 {
            let input = random_text(&mut rng, 30);
            let bounds = char_starts(&input);
            let mut findings = Vec::new();
            let mut at = 0;
            while at + 1 < bounds.len() {
                if rng.below(3) == 0 {
                    let end = (at + 1 + rng.below(5)).min(bounds.len() - 1);
                    let action =
                        [Action::Redact, Action::Block, Action::Warn, Action::Allow][rng.below(4)];
                    findings.push(finding("finding-1", bounds[at], bounds[end], action));
                    at = end;
                }
                at += 1;
            }
            // Never reproduces any value: index-tagged placeholder.
            let safe = |_: &Finding, context: &PlaceholderContext| {
                Ok(format!("<#{}>", context.placeholder_index()))
            };
            let output = redact(&input, &findings, &safe).unwrap();
            assert_eq!(output, redact(&input, &findings, &safe).unwrap(), "{case}");
            assert_eq!(output.capacity(), output.len(), "{case}");
            let mut expected = String::new();
            let (mut cursor, mut n) = (0, 0);
            for f in &findings {
                let range = f.range();
                expected.push_str(&input[cursor..range.start()]);
                if f.action().replaces_text() {
                    n += 1;
                    let _ = write!(expected, "<#{n}>");
                } else {
                    expected.push_str(&input[range.start()..range.end()]);
                }
                cursor = range.end();
            }
            expected.push_str(&input[cursor..]);
            assert_eq!(output, expected, "{case}");

            // A placeholder embedding any finding's value is always rejected.
            if let Some(victim) = findings.get(rng.below(findings.len().max(1))) {
                let value = input[victim.range().start()..victim.range().end()].to_string();
                if findings.iter().any(|f| f.action().replaces_text()) {
                    let leaky = |_: &Finding, _: &PlaceholderContext| Ok(format!("<{value}>"));
                    assert_eq!(
                        redact(&input, &findings, &leaky).unwrap_err().code(),
                        SecretScanErrorCode::InvalidPlaceholder,
                        "{case}"
                    );
                }
            }

            // Forged ranges: out of bounds, mid-character, overlapping.
            let forged = match rng.below(3) {
                0 => vec![finding(
                    "finding-1",
                    0,
                    input.len() + 1 + rng.below(3),
                    Action::Redact,
                )],
                1 if input.chars().any(|c| c.len_utf8() > 1) => {
                    let mid = input
                        .char_indices()
                        .find(|(_, c)| c.len_utf8() > 1)
                        .unwrap()
                        .0
                        + 1;
                    vec![finding("finding-1", mid, mid + 1, Action::Redact)]
                }
                _ if input.len() >= 2 => vec![
                    finding("finding-1", 0, 2.min(input.len()), Action::Redact),
                    finding("finding-2", 1, input.len(), Action::Redact),
                ],
                _ => continue,
            };
            let code = redact(&input, &forged, &safe).map_err(SecretScanError::code);
            let old = oracle_redact(&input, &forged, &safe).map_err(SecretScanError::code);
            assert_eq!(code, old, "{case}");
        }
    }
}
