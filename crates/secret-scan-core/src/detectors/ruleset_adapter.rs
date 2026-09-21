//! The `Detector` adapter for a parsed declarative ruleset (issue #495,
//! `decision-define-declarative-detector-ruleset-contract`).
//!
//! [`crate::ruleset::parse_ruleset`] turns caller-supplied bytes into
//! [`RulesetDetectorSpec`]s; this module turns each spec into a
//! [`RulesetDetector`], feeding the unmodified [`super::pattern::scan_prefixed_shapes`]
//! — the same left-to-right, longest-prefix-wins, linear-time engine every
//! built-in prefixed detector already runs through. Nothing here changes
//! `pattern.rs`'s matching logic, alphabets, `RunLength` shape, or boundary
//! check.
//!
//! Two properties this adapter fixes, both already documented as settled on
//! `crate::ruleset`'s module docs and issue #495's "Decisions this issue
//! settles":
//!
//! - **Confidence is always [`Confidence::Medium`]**, regardless of the
//!   ruleset's own content. There is no way to lower or raise it — revision
//!   1's grammar has no `confidence` field.
//! - **The `trailing-lower-hex` validator cannot be expressed as a
//!   [`PostCheck`]**, because `PostCheck` is a bare function pointer
//!   (`fn(&[u8], usize, usize) -> bool`) with no captured environment, and a
//!   ruleset's checksum tail length is a per-ruleset, runtime value. This
//!   adapter instead applies the check itself, after
//!   `scan_prefixed_shapes` returns — still the identical boundary- and
//!   run-length-filtered match, just with one extra fixed-shape filter on
//!   top, the same position a `PostCheck` would have run it in.

use crate::error::DetectorFailure;
use crate::ruleset::{AlphabetName, RulesetDetectorSpec, RunSpec, ValidatorName};
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext};

use super::pattern::{
    self, Alphabet, PrefixShape, RunLength, is_alnum, is_alnum_dash, is_alnum_dash_dot,
    is_base64_body, is_digit, is_lower_hex, is_upper_alnum,
};

/// Maps a ruleset's named alphabet to the matching byte-class predicate —
/// the same seven functions [`super::pattern`] already defines for every
/// built-in shape. A ruleset cannot name an eighth
/// (`crate::ruleset::AlphabetName::from_wire`).
const fn alphabet_fn(name: AlphabetName) -> Alphabet {
    match name {
        AlphabetName::Alnum => is_alnum,
        AlphabetName::AlnumDash => is_alnum_dash,
        AlphabetName::AlnumDashDot => is_alnum_dash_dot,
        AlphabetName::UpperAlnum => is_upper_alnum,
        AlphabetName::Digit => is_digit,
        AlphabetName::LowerHex => is_lower_hex,
        AlphabetName::Base64Body => is_base64_body,
    }
}

/// The declared `run` count, whichever form it took. This is the only
/// length available to the `trailing-lower-hex` validator — revision 1's
/// grammar has no second, caller-supplied checksum-length field
/// (`decision-define-declarative-detector-ruleset-contract`, "Closed
/// validator enum": "`n` comes from the ruleset detector's own run-length
/// field, not a second caller-supplied parameter").
const fn declared_run_count(run: RunSpec) -> usize {
    match run {
        RunSpec::Exact(count) | RunSpec::AtLeast(count) => count,
    }
}

/// `true` when the matched run's final `tail_len` bytes are lowercase hex —
/// generalizing the Cloudflare detector's already-shipped
/// `checksum_tail_is_lower_hex` shape
/// (`crate::detectors::cloudflare`) to a caller-declared tail length. For
/// `run: exact <n>`, `tail_len` equals the whole matched run, so the check
/// covers it entirely; for `run: at-least <n>`, it covers only the final
/// `n` bytes of however much longer the matched run turned out to be, the
/// same "body of unspecified length, fixed-length checksum tail" shape
/// Cloudflare's own detector uses.
fn trailing_lower_hex_ok(bytes: &[u8], start: usize, end: usize, tail_len: usize) -> bool {
    let matched_len = end - start;
    if tail_len > matched_len {
        return false;
    }
    let tail_start = end - tail_len;
    bytes[tail_start..end].iter().copied().all(is_lower_hex)
}

/// A registrable [`Detector`] for one parsed ruleset detector block.
///
/// Wraps the spec's prefix, alphabet, run, and validator into exactly the
/// [`PrefixShape`] grammar the ADR fixes, and always emits
/// [`Confidence::Medium`] at the spec's own claimed
/// [`Specificity`](crate::Specificity) — never [`Specificity::Structural`],
/// [`Specificity::Provider`], or [`Specificity::PrivateKey`], which
/// [`crate::ruleset::parse_ruleset`] already refuses to parse.
pub(crate) struct RulesetDetector {
    spec: RulesetDetectorSpec,
}

impl RulesetDetector {
    /// Wraps an already-validated spec. Construction cannot fail: every
    /// rejection happened during parsing.
    #[must_use]
    pub(crate) const fn new(spec: RulesetDetectorSpec) -> Self {
        Self { spec }
    }
}

impl Detector for RulesetDetector {
    fn id(&self) -> &str {
        self.spec.id()
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let alphabet = alphabet_fn(self.spec.alphabet());
        let run = match self.spec.run() {
            RunSpec::Exact(count) => RunLength::Exact(count),
            RunSpec::AtLeast(count) => RunLength::AtLeast(count),
        };
        // Revision 1's grammar carries no separate boundary alphabet, so
        // the matched alphabet doubles as its own boundary: a candidate is
        // rejected when it is a truncated slice of a longer run of the same
        // alphabet, the fixed behavior `crate::ruleset`'s module docs
        // promise ("Boundary behavior is fixed and not caller-configurable").
        let shape = PrefixShape {
            prefix: self.spec.prefix(),
            run,
            alphabet,
            signals: &[],
            post_check: None,
        };

        let mut candidates = Vec::with_capacity(1);
        for (start, end, _signals) in pattern::scan_prefixed_shapes(input, &[shape], alphabet) {
            if self.spec.validator() == ValidatorName::TrailingLowerHex {
                let tail_len = declared_run_count(self.spec.run());
                if !trailing_lower_hex_ok(input.as_bytes(), start, end, tail_len) {
                    continue;
                }
            }
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new(self.spec.id(), Confidence::Medium, range)
                    .with_specificity(self.spec.specificity()),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::parse_ruleset;
    use crate::types::Specificity;

    fn ruleset(body: &str) -> String {
        format!("ruleset-revision: 1\n{body}")
    }

    fn detect_with(ruleset_text: &str, input: &str) -> Vec<Candidate> {
        let mut parsed = parse_ruleset(ruleset_text.as_bytes()).unwrap();
        let detector = RulesetDetector::new(parsed.detectors.remove(0));
        detector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn id_is_the_declared_detector_id() {
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: at-least 20\n\
             validator: none\n",
        );
        let mut parsed = parse_ruleset(text.as_bytes()).unwrap();
        let detector = RulesetDetector::new(parsed.detectors.remove(0));
        assert_eq!(detector.id(), "acme-internal-token");
    }

    #[test]
    fn matches_an_exact_run_and_always_claims_medium_confidence() {
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: exact 20\n\
             validator: none\n",
        );
        let value = "a".repeat(20);
        let input = format!("ACME_{value}");
        let candidates = detect_with(&text, &input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "acme-internal-token");
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(
            candidates[0].effective_specificity(),
            Specificity::Contextual
        );
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, input.len()).unwrap()
        );
    }

    #[test]
    fn an_entropy_specificity_claim_round_trips() {
        let text = ruleset(
            "detector: acme-heuristic-token\n\
             specificity: entropy\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum\n\
             run: at-least 10\n\
             validator: none\n",
        );
        let candidates = detect_with(&text, "ACME_abcdefghij");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Entropy);
    }

    #[test]
    fn rejects_a_run_shorter_than_the_declared_minimum() {
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: at-least 20\n\
             validator: none\n",
        );
        assert!(detect_with(&text, "ACME_shorttoken").is_empty());
    }

    #[test]
    fn takes_the_maximal_run_for_at_least() {
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: at-least 10\n\
             validator: none\n",
        );
        let value = "a".repeat(40);
        let input = format!("ACME_{value}");
        let candidates = detect_with(&text, &input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].range().len(), input.len());
    }

    #[test]
    fn rejects_a_candidate_truncated_by_the_self_boundary() {
        // The matched alphabet is also the boundary: a wider identical-alphabet
        // run right after the declared count must reject, not truncate.
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: exact 20\n\
             validator: none\n",
        );
        let input = format!("ACME_{}extra", "a".repeat(20));
        assert!(detect_with(&text, &input).is_empty());
    }

    #[test]
    fn rejects_the_prefix_embedded_in_a_wider_identifier() {
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: at-least 20\n\
             validator: none\n",
        );
        let value = "a".repeat(20);
        assert_eq!(detect_with(&text, &format!("ACME_{value}")).len(), 1);
        assert!(detect_with(&text, &format!("xACME_{value}")).is_empty());
    }

    #[test]
    fn trailing_lower_hex_validator_requires_the_final_declared_count_of_bytes_to_be_hex() {
        let text = ruleset(
            "detector: acme-checksum-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum\n\
             run: at-least 8\n\
             validator: trailing-lower-hex\n",
        );
        // A run whose final 8 bytes are lowercase hex passes.
        let good = "SYNTHETICdeadbeef";
        let input = format!("ACME_{good}");
        let candidates = detect_with(&text, &input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].range().len(), input.len());

        // A run whose final 8 bytes are not all lowercase hex is rejected
        // outright — the ruleset grammar has no fallback truncation.
        let bad = "SYNTHETICnothexZZ";
        assert!(detect_with(&text, &format!("ACME_{bad}")).is_empty());
    }

    #[test]
    fn trailing_lower_hex_validator_on_an_exact_run_requires_the_whole_run_to_be_hex() {
        let text = ruleset(
            "detector: acme-checksum-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum\n\
             run: exact 8\n\
             validator: trailing-lower-hex\n",
        );
        assert_eq!(detect_with(&text, "ACME_deadbeef").len(), 1);
        assert!(detect_with(&text, "ACME_deadbeeZ").is_empty());
    }

    #[test]
    fn finds_deterministic_findings_across_repeated_calls() {
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: at-least 20\n\
             validator: none\n",
        );
        let input = format!("ACME_{}", "a".repeat(20));
        assert_eq!(detect_with(&text, &input), detect_with(&text, &input));
    }

    #[test]
    fn reports_every_occurrence_in_the_input() {
        let text = ruleset(
            "detector: acme-internal-token\n\
             specificity: contextual\n\
             prefix: \"ACME_\"\n\
             alphabet: alnum-dash\n\
             run: at-least 20\n\
             validator: none\n",
        );
        let value = "a".repeat(20);
        let input = format!("ACME_{value} ACME_{value}");
        assert_eq!(detect_with(&text, &input).len(), 2);
    }
}
