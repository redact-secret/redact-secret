//! THROWAWAY MEASUREMENT SCAFFOLD for issue #441 — not shipped code.
//!
//! Exists only so `scripts/measure-detector-cost.mjs`'s build/measure
//! helpers can be pointed at a real, representative "core parses the
//! declarative ruleset format itself" implementation and report a real
//! compiled WebAssembly size delta, instead of an estimate. It is added,
//! measured, and reverted with `git checkout --` in the same working
//! session that produced `docs/audits/evidence/441/README.md`; it must never
//! land on `main`.
//!
//! Deliberately representative of the shape issue #441 settles, and nothing
//! more: a hand-written line-oriented tokenizer (no external crate — the
//! core's `allowed-dependencies` stays `[]`), fixed closed enums for the
//! alphabet and validator names (mirroring [`super::detectors::pattern`]'s
//! existing `Alphabet` set and a placeholder single-member validator enum),
//! and fail-closed, input-free rejection of an unknown revision, field,
//! construct, or validator name. It does not implement the cost bounds,
//! ordering cap, or fixed-error-catalog that the real ADR-fixed design
//! requires — those are follow-up-issue work — so the measured number is a
//! representative floor, not a final one.

/// The one supported `ruleset-revision` value. Any other value is rejected
/// before any detector line is read.
const SUPPORTED_REVISION: &str = "1";

/// Closed alphabet-name vocabulary, mirroring
/// [`super::detectors::pattern::Alphabet`]'s existing byte-class set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlphabetName {
    Alnum,
    AlnumDash,
    AlnumDashDot,
    UpperAlnum,
    Digit,
    LowerHex,
    Base64Body,
}

impl AlphabetName {
    fn from_wire(name: &str) -> Option<Self> {
        match name {
            "alnum" => Some(Self::Alnum),
            "alnum-dash" => Some(Self::AlnumDash),
            "alnum-dash-dot" => Some(Self::AlnumDashDot),
            "upper-alnum" => Some(Self::UpperAlnum),
            "digit" => Some(Self::Digit),
            "lower-hex" => Some(Self::LowerHex),
            "base64-body" => Some(Self::Base64Body),
            _ => None,
        }
    }
}

/// Closed, single-placeholder validator vocabulary. The real ADR fixes the
/// full closed enum; this prototype carries exactly one member so the
/// "unknown validator name is rejected" path has real code behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValidatorName {
    None,
}

impl ValidatorName {
    fn from_wire(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Whether a matched run is `{n}` or `{n,}`, parsed from the wire form
/// `exact <n>` / `at-least <n>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunSpec {
    Exact(usize),
    AtLeast(usize),
}

/// A closed specificity a ruleset detector may claim. Deliberately excludes
/// `Provider` and `PrivateKey`: a ruleset detector must not be able to
/// outrank a built-in candidate (the open ordering question issue #441
/// leaves for the ADR to cap precisely; this prototype enforces the
/// conservative bound so the reject path has real code behind it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimableSpecificity {
    Entropy,
    Contextual,
    Structural,
}

impl ClaimableSpecificity {
    fn from_wire(name: &str) -> Option<Self> {
        match name {
            "entropy" => Some(Self::Entropy),
            "contextual" => Some(Self::Contextual),
            "structural" => Some(Self::Structural),
            _ => None,
        }
    }
}

/// One fully parsed and validated `detector:` block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RulesetDetectorSpec {
    id: String,
    specificity: ClaimableSpecificity,
    prefix: String,
    alphabet: AlphabetName,
    run: RunSpec,
    validator: ValidatorName,
}

/// Every rejection is fixed and input-free: no variant carries any byte
/// derived from the rejected content, only which fixed class it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RulesetLoadError {
    UnknownRevision,
    UnknownField,
    UnsupportedConstruct,
    UnknownAlphabet,
    UnknownValidator,
    UnknownSpecificity,
    MissingField,
    DuplicateId,
    InvalidRunLength,
    RunLengthOutOfBounds,
    PrefixTooShort,
    TooManyDetectors,
    EmptyRuleset,
}

/// Per-ruleset bound: a zero-length prefix would make every byte a start
/// position, so the minimum is 1; the maximum keeps one caller-supplied
/// ruleset from declaring pathologically many detectors. Real bounds are an
/// open ADR question (`#441`); these are representative placeholders only.
const MIN_PREFIX_LEN: usize = 1;
const MAX_RUN_LENGTH: usize = 4_096;
const MAX_DETECTORS_PER_RULESET: usize = 64;

struct LineScanner<'a> {
    lines: std::str::Lines<'a>,
}

impl<'a> LineScanner<'a> {
    fn new(text: &'a str) -> Self {
        Self { lines: text.lines() }
    }
}

impl<'a> Iterator for LineScanner<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        for line in self.lines.by_ref() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
        None
    }
}

/// Splits one `key: value` line, or `None` when the line has no `:`.
fn split_field(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    Some((key.trim(), value.trim()))
}

fn parse_run(value: &str) -> Result<RunSpec, RulesetLoadError> {
    let (kind, count) = value.split_once(' ').ok_or(RulesetLoadError::InvalidRunLength)?;
    let count: usize = count
        .trim()
        .parse()
        .map_err(|_| RulesetLoadError::InvalidRunLength)?;
    if count == 0 || count > MAX_RUN_LENGTH {
        return Err(RulesetLoadError::RunLengthOutOfBounds);
    }
    match kind {
        "exact" => Ok(RunSpec::Exact(count)),
        "at-least" => Ok(RunSpec::AtLeast(count)),
        _ => Err(RulesetLoadError::InvalidRunLength),
    }
}

fn parse_detector_block(header_value: &str, fields: &[(&str, &str)]) -> Result<RulesetDetectorSpec, RulesetLoadError> {
    let id = header_value.trim();
    if id.is_empty() {
        return Err(RulesetLoadError::MissingField);
    }

    let mut specificity = None;
    let mut prefix = None;
    let mut alphabet = None;
    let mut run = None;
    let mut validator = None;

    for (key, value) in fields {
        match *key {
            "specificity" => {
                specificity = Some(
                    ClaimableSpecificity::from_wire(value)
                        .ok_or(RulesetLoadError::UnknownSpecificity)?,
                );
            }
            "prefix" => {
                let unquoted = value.trim_matches('"');
                if unquoted.len() < MIN_PREFIX_LEN {
                    return Err(RulesetLoadError::PrefixTooShort);
                }
                prefix = Some(unquoted.to_string());
            }
            "alphabet" => {
                alphabet = Some(AlphabetName::from_wire(value).ok_or(RulesetLoadError::UnknownAlphabet)?);
            }
            "run" => {
                run = Some(parse_run(value)?);
            }
            "validator" => {
                validator = Some(ValidatorName::from_wire(value).ok_or(RulesetLoadError::UnknownValidator)?);
            }
            _ => return Err(RulesetLoadError::UnknownField),
        }
    }

    Ok(RulesetDetectorSpec {
        id: id.to_string(),
        specificity: specificity.ok_or(RulesetLoadError::MissingField)?,
        prefix: prefix.ok_or(RulesetLoadError::MissingField)?,
        alphabet: alphabet.ok_or(RulesetLoadError::MissingField)?,
        run: run.ok_or(RulesetLoadError::MissingField)?,
        validator: validator.ok_or(RulesetLoadError::MissingField)?,
    })
}

/// Parses a caller-supplied declarative ruleset. Never partially loads: the
/// whole input is validated before any [`RulesetDetectorSpec`] is returned,
/// and the first rejection wins.
///
/// THROWAWAY MEASUREMENT SCAFFOLD — see module docs. Not the shipped parser.
pub(crate) fn parse_ruleset_prototype(bytes: &[u8]) -> Result<Vec<RulesetDetectorSpec>, RulesetLoadError> {
    let text = std::str::from_utf8(bytes).map_err(|_| RulesetLoadError::UnsupportedConstruct)?;
    let mut scanner = LineScanner::new(text);

    let revision_line = scanner.next().ok_or(RulesetLoadError::EmptyRuleset)?;
    let (key, value) = split_field(revision_line).ok_or(RulesetLoadError::UnsupportedConstruct)?;
    if key != "ruleset-revision" {
        return Err(RulesetLoadError::UnsupportedConstruct);
    }
    if value != SUPPORTED_REVISION {
        return Err(RulesetLoadError::UnknownRevision);
    }

    let mut specs = Vec::new();
    let mut current_header: Option<&str> = None;
    let mut current_fields: Vec<(&str, &str)> = Vec::new();

    let flush = |header: Option<&str>, fields: &mut Vec<(&str, &str)>, specs: &mut Vec<RulesetDetectorSpec>| -> Result<(), RulesetLoadError> {
        if let Some(header_value) = header {
            let spec = parse_detector_block(header_value, fields)?;
            if specs.iter().any(|existing: &RulesetDetectorSpec| existing.id == spec.id) {
                return Err(RulesetLoadError::DuplicateId);
            }
            specs.push(spec);
        }
        fields.clear();
        Ok(())
    };

    for line in scanner {
        let Some((key, value)) = split_field(line) else {
            return Err(RulesetLoadError::UnsupportedConstruct);
        };
        if key == "detector" {
            flush(current_header.take(), &mut current_fields, &mut specs)?;
            if specs.len() >= MAX_DETECTORS_PER_RULESET {
                return Err(RulesetLoadError::TooManyDetectors);
            }
            current_header = Some(value);
        } else {
            if current_header.is_none() {
                return Err(RulesetLoadError::UnsupportedConstruct);
            }
            current_fields.push((key, value));
        }
    }
    flush(current_header.take(), &mut current_fields, &mut specs)?;

    if specs.is_empty() {
        return Err(RulesetLoadError::EmptyRuleset);
    }
    if specs.len() > MAX_DETECTORS_PER_RULESET {
        return Err(RulesetLoadError::TooManyDetectors);
    }

    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "ruleset-revision: 1\n\
detector: acme-internal-token\n\
specificity: contextual\n\
prefix: \"ACME_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";

    #[test]
    fn parses_a_valid_minimal_ruleset() {
        let specs = parse_ruleset_prototype(VALID.as_bytes()).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].id, "acme-internal-token");
    }

    #[test]
    fn rejects_unknown_revision() {
        let text = VALID.replacen("ruleset-revision: 1", "ruleset-revision: 2", 1);
        assert_eq!(
            parse_ruleset_prototype(text.as_bytes()),
            Err(RulesetLoadError::UnknownRevision)
        );
    }

    #[test]
    fn rejects_unknown_field() {
        let text = VALID.replacen("validator: none", "validator: none\nbogus: x", 1);
        assert_eq!(
            parse_ruleset_prototype(text.as_bytes()),
            Err(RulesetLoadError::UnknownField)
        );
    }

    #[test]
    fn rejects_unknown_validator_and_does_not_partially_load() {
        let text = VALID.replacen("validator: none", "validator: bogus-checksum", 1);
        assert_eq!(
            parse_ruleset_prototype(text.as_bytes()),
            Err(RulesetLoadError::UnknownValidator)
        );
    }

    #[test]
    fn rejects_a_specificity_it_may_not_claim() {
        let text = VALID.replacen("specificity: contextual", "specificity: provider", 1);
        assert_eq!(
            parse_ruleset_prototype(text.as_bytes()),
            Err(RulesetLoadError::UnknownSpecificity)
        );
    }

    #[test]
    fn rejects_an_over_bound_run_length() {
        let text = VALID.replacen("run: at-least 20", "run: at-least 999999", 1);
        assert_eq!(
            parse_ruleset_prototype(text.as_bytes()),
            Err(RulesetLoadError::RunLengthOutOfBounds)
        );
    }

    #[test]
    fn rejects_a_duplicate_detector_id() {
        let text = format!("{VALID}detector: acme-internal-token\nspecificity: contextual\nprefix: \"X\"\nalphabet: digit\nrun: exact 4\nvalidator: none\n");
        assert_eq!(
            parse_ruleset_prototype(text.as_bytes()),
            Err(RulesetLoadError::DuplicateId)
        );
    }
}
