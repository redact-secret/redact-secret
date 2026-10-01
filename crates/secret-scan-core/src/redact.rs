//! Single-pass redaction: replaces `block` and `redact` findings with
//! placeholder text produced by a [`PlaceholderFormatter`], leaving `warn`
//! and `allow` findings untouched.
//!
//! Redaction never exposes a matched value: it does not accept the value
//! itself (only [`Finding`] metadata and the immutable `input`), and every
//! failure is a sanitized [`SecretScanError`].

use crate::error::{FormatterFailure, SecretScanError, SecretScanErrorCode};
use crate::limits::WholeInputLimits;
use crate::pii::heap_sort;
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
    /// `spans` are the findings' `(start, end)` byte offsets in `input`.
    fn build(input: &'a str, spans: impl Iterator<Item = (usize, usize)>) -> Self {
        let mut values: Vec<&'a str> = spans
            .filter(|(start, end)| end - start <= MAX_PLACEHOLDER_LENGTH)
            .map(|(start, end)| &input[start..end])
            .collect();
        heap_sort(&mut values);
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

/// Findings proven character-aligned in the input, ordered by start and
/// pairwise disjoint (issue #1124).
///
/// Redaction can only start from this type, so every caller gets the same
/// proof. Findings that already arrive ordered and disjoint (every pipeline
/// result) are borrowed in place; anything else is sorted into a reference
/// vector first, which is the only case that allocates.
///
/// The findings' ranges may sit `shift` bytes above `input` (issue #1125): the
/// incremental session passes a unit's global findings with the unit's global
/// start as the shift, so the view proves and exposes unit-local
/// [`span`](Self::span)s without a second, relocated list of findings. A range
/// that starts below `shift` is as invalid as one past the end of `input`.
struct OrderedFindings<'a> {
    findings: Findings<'a>,
    shift: usize,
}

enum Findings<'a> {
    InPlace(&'a [Finding]),
    Sorted(Vec<&'a Finding>),
}

impl<'a> OrderedFindings<'a> {
    fn new(findings: &'a [Finding], input: &str, shift: usize) -> Result<Self, SecretScanError> {
        let mut previous_end = 0;
        let mut in_place = true;
        for finding in findings {
            let (start, end) = Self::checked_span(finding, input, shift)?;
            in_place &= start >= previous_end;
            previous_end = end;
        }
        if in_place {
            return Ok(Self {
                findings: Findings::InPlace(findings),
                shift,
            });
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
        Ok(Self {
            findings: Findings::Sorted(ordered),
            shift,
        })
    }

    /// The span of `finding` in `input` when its range, less `shift`, lies in
    /// `input` on character boundaries.
    fn checked_span(
        finding: &Finding,
        input: &str,
        shift: usize,
    ) -> Result<(usize, usize), SecretScanError> {
        let range: ByteRange = finding.range();
        match (
            range.start().checked_sub(shift),
            range.end().checked_sub(shift),
        ) {
            (Some(start), Some(end))
                if end <= input.len()
                    && input.is_char_boundary(start)
                    && input.is_char_boundary(end) =>
            {
                Ok((start, end))
            }
            _ => Err(SecretScanErrorCode::InvalidFindings.into()),
        }
    }

    /// The span of a finding of this view in the input. Validated at
    /// construction, so the subtraction cannot underflow.
    fn span(&self, finding: &Finding) -> (usize, usize) {
        let range: ByteRange = finding.range();
        (range.start() - self.shift, range.end() - self.shift)
    }

    fn len(&self) -> usize {
        match &self.findings {
            Findings::InPlace(findings) => findings.len(),
            Findings::Sorted(ordered) => ordered.len(),
        }
    }

    fn get(&self, index: usize) -> &'a Finding {
        match &self.findings {
            Findings::InPlace(findings) => &findings[index],
            Findings::Sorted(ordered) => ordered[index],
        }
    }

    fn iter(&self) -> impl Iterator<Item = &'a Finding> + '_ {
        (0..self.len()).map(|index| self.get(index))
    }
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
    let mut output = String::new();
    redact_into(input, findings, formatter, limits, &mut output)?;
    Ok(output)
}

/// [`redact_with_limits`], appending the result to `output` instead of
/// returning a new string. Every check and every formatter call happens
/// before the first byte is appended, so on an error `output` is untouched
/// (issue #1087).
pub(crate) fn redact_into(
    input: &str,
    findings: &[Finding],
    formatter: &dyn PlaceholderFormatter,
    limits: &WholeInputLimits,
    output: &mut String,
) -> Result<(), SecretScanError> {
    redact_shifted_into(input, findings, 0, 0, formatter, limits, output).map(drop)
}

/// [`redact_into`] for findings whose ranges sit `shift` bytes above `input`,
/// numbering placeholders from `placeholders_before + 1`, and returning how
/// many text-replacing findings it formatted (issue #1125).
///
/// The incremental session redacts one closed unit of a longer logical
/// input: it passes the unit's text, the unit's findings in the logical
/// input's coordinates, the unit's start in those coordinates, and the count
/// of placeholders already issued. The formatter is handed the caller's own
/// findings and the logical placeholder numbers, so nothing is relocated or
/// mapped back.
pub(crate) fn redact_shifted_into(
    input: &str,
    findings: &[Finding],
    shift: usize,
    placeholders_before: usize,
    formatter: &dyn PlaceholderFormatter,
    limits: &WholeInputLimits,
    output: &mut String,
) -> Result<usize, SecretScanError> {
    limits.check_input(input)?;
    limits.check_findings(findings.len())?;
    let ordered = OrderedFindings::new(findings, input, shift)?;
    let forbidden =
        ForbiddenMatchedText::build(input, ordered.iter().map(|finding| ordered.span(finding)));

    // Phase 1: format and validate every replaced finding in order, so the
    // formatter call order and the first error are unchanged and no partial
    // output exists when a placeholder fails.
    let mut placeholders: Vec<String> = Vec::new();
    let mut output_len = input.len();
    for finding in ordered
        .iter()
        .filter(|finding| finding.action().replaces_text())
    {
        let context = PlaceholderContext::new(placeholders_before + placeholders.len() + 1);
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

    // Phase 2: copy into `output`, grown once to the final size (exactly, when empty).
    let start_len = output.len();
    output.reserve_exact(output_len);
    let mut cursor = 0;
    let replaced = ordered
        .iter()
        .filter(|finding| finding.action().replaces_text());
    for (finding, placeholder) in replaced.zip(&placeholders) {
        let (start, end) = ordered.span(finding);
        output.push_str(&input[cursor..start]);
        output.push_str(placeholder);
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    debug_assert_eq!(output.len() - start_len, output_len);
    Ok(placeholders.len())
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

    /// The pre-#1124 validation, verbatim: always a reference vector, always
    /// sorted.
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

    /// Issue #1124: findings in any order, including reversed, shuffled, with
    /// a forged overlap or a forged out-of-range or mid-character span, behave
    /// exactly as the pre-#1124 sort-always validation did: same result, same
    /// error, same formatter calls in the same order, and a prefilled output
    /// untouched on every failure.
    #[test]
    fn arbitrary_finding_order_matches_the_always_sorting_oracle() {
        let mut rng = Rng(0xA5A5_1124_0000_0001);
        let mut ok = 0;
        let mut invalid = 0;
        for case in 0..6000 {
            let input = random_text(&mut rng, 24);
            let bounds = char_starts(&input);
            let mut findings = Vec::new();
            let mut at = 0;
            while at + 1 < bounds.len() {
                if rng.below(2) == 0 {
                    let end = (at + 1 + rng.below(4)).min(bounds.len() - 1);
                    let action =
                        [Action::Redact, Action::Block, Action::Warn, Action::Allow][rng.below(4)];
                    findings.push(finding("finding-1", bounds[at], bounds[end], action));
                    at = end;
                }
                at += 1;
            }
            match rng.below(5) {
                0 => findings.reverse(),
                1 => {
                    for i in (1..findings.len()).rev() {
                        findings.swap(i, rng.below(i + 1));
                    }
                }
                2 if input.len() >= 2 => {
                    findings.push(finding("finding-9", 1, input.len(), Action::Redact));
                }
                3 => findings.push(finding("finding-9", 0, input.len() + 1, Action::Redact)),
                _ => {}
            }
            let build = |log: std::rc::Rc<std::cell::RefCell<Vec<usize>>>| {
                move |_: &Finding, context: &PlaceholderContext| {
                    log.borrow_mut().push(context.placeholder_index());
                    Ok(format!("<#{}>", context.placeholder_index()))
                }
            };
            let old_log = std::rc::Rc::<std::cell::RefCell<Vec<usize>>>::default();
            let new_log = std::rc::Rc::<std::cell::RefCell<Vec<usize>>>::default();
            let old = oracle_redact(&input, &findings, &build(std::rc::Rc::clone(&old_log)));
            let new = redact(&input, &findings, &build(std::rc::Rc::clone(&new_log)));
            assert_eq!(old.as_ref().ok(), new.as_ref().ok(), "case {case}");
            assert_eq!(
                old.as_ref().map_err(|e| e.code()),
                new.as_ref().map_err(|e| e.code()),
                "case {case}"
            );
            // Validation precedes every formatter call, so a rejected set
            // reaches the formatter zero times, in both implementations.
            if new.is_err()
                && new.as_ref().unwrap_err().code() == SecretScanErrorCode::InvalidFindings
            {
                assert!(new_log.borrow().is_empty(), "case {case}");
                invalid += 1;
            } else {
                assert_eq!(*old_log.borrow(), *new_log.borrow(), "case {case}");
                ok += 1;
            }
            let mut prefilled = String::from("prefix|");
            let into = redact_into(
                &input,
                &findings,
                &build(std::rc::Rc::default()),
                &WholeInputLimits::default(),
                &mut prefilled,
            );
            match into {
                Ok(()) => assert_eq!(prefilled, format!("prefix|{}", new.unwrap()), "{case}"),
                Err(_) => assert_eq!(prefilled, "prefix|", "{case}"),
            }
        }
        assert!(
            ok > 1000 && invalid > 500,
            "generator must reach both outcomes"
        );
    }

    fn spans<'f>(refs: &'f [&Finding]) -> impl Iterator<Item = (usize, usize)> + 'f {
        refs.iter()
            .map(|finding| (finding.range().start(), finding.range().end()))
    }

    /// Issue #1125: redacting a unit of a longer input through its findings in
    /// the longer input's coordinates is the unit-local redaction with the
    /// formatter seeing the caller's own findings and the logical placeholder
    /// numbers, and the same errors, including for a range that starts below
    /// the unit or runs past it.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn shifted_redaction_equals_local_redaction_with_offset_numbering() {
        let mut rng = Rng(0xA5A5_1125_0000_0001);
        let mut ok = 0;
        let mut invalid = 0;
        for case in 0..6000 {
            let prefix = random_text(&mut rng, 6);
            let unit = random_text(&mut rng, 24);
            let shift = prefix.len();
            let bounds = char_starts(&unit);
            let mut local = Vec::new();
            let mut at = 0;
            while at + 1 < bounds.len() {
                if rng.below(2) == 0 {
                    let end = (at + 1 + rng.below(4)).min(bounds.len() - 1);
                    let action =
                        [Action::Redact, Action::Block, Action::Warn, Action::Allow][rng.below(4)];
                    local.push(finding(
                        &format!("finding-{}", local.len() + 1),
                        bounds[at],
                        bounds[end],
                        action,
                    ));
                    at = end;
                }
                at += 1;
            }
            let mut global: Vec<Finding> = local
                .iter()
                .map(|f| {
                    finding(
                        f.id(),
                        f.range().start() + shift,
                        f.range().end() + shift,
                        f.action(),
                    )
                })
                .collect();
            match rng.below(6) {
                0 if shift > 0 => {
                    global.push(finding("finding-9", shift - 1, shift + 1, Action::Redact));
                }
                1 => global.push(finding(
                    "finding-9",
                    shift,
                    shift + unit.len() + 1,
                    Action::Redact,
                )),
                2 => global.reverse(),
                _ => {}
            }
            let before = rng.below(5);
            let seen = std::cell::RefCell::new(Vec::new());
            let formatter = |f: &Finding, context: &PlaceholderContext| {
                seen.borrow_mut()
                    .push((f.id().to_owned(), context.placeholder_index()));
                Ok(format!("<#{}>", context.placeholder_index()))
            };
            let mut shifted = String::from("out|");
            let result = redact_shifted_into(
                &unit,
                &global,
                shift,
                before,
                &formatter,
                &WholeInputLimits::default(),
                &mut shifted,
            );
            match result {
                Ok(count) => {
                    ok += 1;
                    let numbered = |_: &Finding, context: &PlaceholderContext| {
                        Ok(format!("<#{}>", context.placeholder_index() + before))
                    };
                    let expected = redact(&unit, &local, &numbered).unwrap();
                    assert_eq!(shifted, format!("out|{expected}"), "case {case}");
                    assert_eq!(
                        count,
                        local.iter().filter(|f| f.action().replaces_text()).count(),
                        "case {case}"
                    );
                    let mut ids: Vec<_> = seen.borrow().iter().map(|(id, _)| id.clone()).collect();
                    ids.sort();
                    let mut want: Vec<_> = local
                        .iter()
                        .filter(|f| f.action().replaces_text())
                        .map(|f| f.id().to_owned())
                        .collect();
                    want.sort();
                    assert_eq!(ids, want, "case {case}");
                    let indices: Vec<usize> = seen.borrow().iter().map(|(_, i)| *i).collect();
                    assert_eq!(
                        indices,
                        (before + 1..=before + count).collect::<Vec<_>>(),
                        "case {case}"
                    );
                }
                Err(error) => {
                    invalid += 1;
                    assert_eq!(error.code(), SecretScanErrorCode::InvalidFindings, "{case}");
                    assert!(seen.borrow().is_empty(), "case {case}");
                    assert_eq!(shifted, "out|", "case {case}");
                }
            }
        }
        assert!(
            ok > 1000 && invalid > 500,
            "generator must reach both outcomes"
        );
    }

    #[test]
    fn placeholder_length_boundary_is_exactly_the_maximum() {
        let input = "SYNTHETIC_ONE|SYNTHETIC_TWO";
        let findings = [
            finding("finding-2", 14, input.len(), Action::Redact),
            finding("finding-1", 0, 13, Action::Redact),
        ];
        let exact = |_: &Finding, _: &PlaceholderContext| Ok("x".repeat(MAX_PLACEHOLDER_LENGTH));
        let output = redact(input, &findings, &exact).unwrap();
        assert_eq!(output.len(), 2 * MAX_PLACEHOLDER_LENGTH + 1);
        assert_eq!(output.capacity(), output.len());
        let over = |_: &Finding, _: &PlaceholderContext| Ok("x".repeat(MAX_PLACEHOLDER_LENGTH + 1));
        assert_eq!(
            redact(input, &findings, &over).unwrap_err().code(),
            SecretScanErrorCode::InvalidPlaceholder
        );
    }

    /// `redact_into` (issue #1087) appends exactly what the pre-#1087 path
    /// returned and then copied into the released text, and leaves the
    /// buffer untouched on an error.
    #[test]
    fn redact_into_appends_what_redact_returns_and_is_untouched_on_error() {
        let mut rng = Rng(0xA5A5_1087_0000_0001);
        for case in 0..6000 {
            let input = random_text(&mut rng, if case % 50 == 0 { 400 } else { 24 });
            let bounds = char_starts(&input);
            let mut findings = Vec::new();
            let mut at = 0;
            while at < bounds.len() {
                if at + 1 < bounds.len() && rng.below(3) == 0 {
                    let end_index = (at + 1 + rng.below(5)).min(bounds.len() - 1);
                    let action =
                        [Action::Redact, Action::Block, Action::Warn, Action::Allow][rng.below(4)];
                    findings.push(finding("finding-1", bounds[at], bounds[end_index], action));
                    at = end_index;
                }
                at += 1;
            }
            let pool: Vec<String> = (0..3)
                .map(|_| match rng.below(4) {
                    0 => String::new(),
                    1 | 2 => format!("<{}>", random_text(&mut rng, 6)),
                    _ => format!("<R{}>", rng.below(100)),
                })
                .collect();
            let formatter = |_: &Finding, context: &PlaceholderContext| {
                Ok(pool[context.placeholder_index() % pool.len()].clone())
            };
            let prefix = random_text(&mut rng, 8);
            let mut output = prefix.clone();
            let into = redact_into(
                &input,
                &findings,
                &formatter,
                &WholeInputLimits::default(),
                &mut output,
            );
            match redact(&input, &findings, &formatter) {
                Ok(expected) => {
                    assert!(into.is_ok(), "case {case}");
                    assert_eq!(output, format!("{prefix}{expected}"), "case {case}");
                }
                Err(error) => {
                    assert_eq!(into.unwrap_err().code(), error.code(), "case {case}");
                    assert_eq!(output, prefix, "case {case}");
                }
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
            let new = ForbiddenMatchedText::build(&input, spans(&refs));
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
        assert!(!ForbiddenMatchedText::build("", spans(&refs)).contains("anything"));
        // A value of continuation-looking bytes never matches mid-character.
        let input = "é";
        let findings = [finding("finding-1", 0, 2, Action::Redact)];
        let refs: Vec<&Finding> = findings.iter().collect();
        let index = ForbiddenMatchedText::build(input, spans(&refs));
        assert!(index.contains("<é>"));
        assert!(!index.contains("<e\u{301}>"));
        assert!(!index.contains(""));
        // Overlong values are not indexed; value equal to the maximum is.
        let long = "a".repeat(MAX_PLACEHOLDER_LENGTH + 1);
        let findings = [finding("finding-1", 0, long.len(), Action::Redact)];
        let refs: Vec<&Finding> = findings.iter().collect();
        assert!(!ForbiddenMatchedText::build(&long, spans(&refs)).contains(&"a".repeat(256)));
        let max = "a".repeat(MAX_PLACEHOLDER_LENGTH);
        let findings = [finding("finding-1", 0, max.len(), Action::Redact)];
        let refs: Vec<&Finding> = findings.iter().collect();
        assert!(ForbiddenMatchedText::build(&max, spans(&refs)).contains(&max));
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
