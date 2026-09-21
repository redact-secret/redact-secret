//! The declarative ruleset parser and its normalized intermediate
//! representation (`decision-define-declarative-detector-ruleset-contract`).
//!
//! This is slice 1 of that decision's implementation, entirely
//! crate-internal: it parses and validates caller-supplied ruleset bytes
//! into an owned [`RulesetDetectorSpec`] per `detector:` block, fail-closed,
//! with the decision's cost bounds and rejection catalog. It never partially
//! loads a ruleset — every validated detector or one fixed, content-free
//! [`RulesetLoadError`], never a partial result — and it performs no
//! matching itself: nothing in this crate consumes a [`RulesetDetectorSpec`]
//! yet, the same way the decision separates "parse bytes into an IR" from
//! "borrow `PrefixShape`s from the IR and scan with them" as two different
//! pieces of follow-up work.
//!
//! # Matching semantics this slice fixes but does not implement
//!
//! A future scan built from a [`RulesetDetectorSpec`] inherits three
//! properties already true of every built-in prefixed detector, stated here
//! because the follow-up work's user-facing grammar documentation is
//! derived from them:
//!
//! - **Prefix matching is byte-exact and case-sensitive.** The scan copy a
//!   detector matches against has invisible and format code points removed
//!   and nothing else changed — no case folding, no NFKC, no decoding, no
//!   unescaping (`crate::normalize`) — and a ruleset-declared `prefix`
//!   inherits that: it is compared byte for byte, in the case the ruleset
//!   author wrote it.
//! - **Matching runs on the normalized scan copy; reported ranges are in
//!   original-input coordinates.** Every detector matches against the
//!   invisible-character-stripped copy, and every candidate range it
//!   returns is translated back before it becomes a public result
//!   (`decision-normalize-invisible-characters-before-detection`,
//!   `crate::pipeline`). A ruleset detector is not a special case.
//! - **Boundary behavior is fixed and not caller-configurable.** Whether a
//!   matched run is a truncated slice of a longer run of the same or a
//!   wider alphabet is decided by the existing adjacency check
//!   (`crate::detectors::pattern`'s `boundary_ok`), unchanged; a ruleset
//!   cannot loosen or tighten it.
//!
//! # Wire grammar
//!
//! A ruleset is UTF-8 text, at most [`MAX_RULESET_BYTES`] long. Blank lines
//! (after trimming) are ignored anywhere. Every other line is `key: value`;
//! any line without a `:` is rejected as [`RulesetLoadError::UnsupportedConstruct`].
//!
//! The first non-blank line must be `ruleset-revision: 1` — any other value
//! is [`RulesetLoadError::UnknownRevision`], any other key in that position
//! is [`RulesetLoadError::UnsupportedConstruct`]. Every following line
//! either starts a new detector block (`detector: <id>`) or supplies one of
//! that block's fields; a field line before the first `detector:` line is
//! [`RulesetLoadError::UnsupportedConstruct`]. A block's five fields —
//! `specificity`, `prefix`, `alphabet`, `run`, `validator` — are each
//! required exactly once; a sixth, unrecognized field name (`confidence`,
//! for example: revision 1 has none) is
//! [`RulesetLoadError::UnknownField`], and one omitted is
//! [`RulesetLoadError::MissingField`].
//!
//! `prefix` is a double-quoted literal with no escape sequences recognized
//! inside the quotes. `alphabet` and `validator` are each one name from a
//! closed, seven- and two-member vocabulary
//! ([`AlphabetName`], [`ValidatorName`]). `run` is `exact <n>` or `at-least
//! <n>`. `specificity` is `entropy` or `contextual`; every other name —
//! including the three reserved to built-ins and any name the pipeline's
//! specificity enum does not define at all — is the single fixed
//! [`RulesetLoadError::SpecificityNotClaimable`].

use crate::detectors::{RulesetDetector, built_in_ids};
use crate::error::SecretScanErrorCode;
use crate::types::{Detector, Specificity, is_identifier};

/// The one supported `ruleset-revision` value. Any other value is rejected
/// with [`RulesetLoadError::UnknownRevision`] before any detector block is
/// read.
const RULESET_REVISION: &str = "1";

/// Minimum `prefix` length in bytes. A zero- or one-byte prefix makes most
/// or all byte positions a candidate start, degrading toward the unbounded
/// case the linear scan exists to avoid; 3 bytes matches the shortest real
/// built-in prefixes (`hf_`, `sk-`).
const MIN_RULESET_PREFIX_BYTES: usize = 3;

/// Maximum `prefix` length in bytes. Over 4x the longest real built-in
/// prefix (`sk-ant-api03-`, `github_pat_`); declared separately from
/// [`crate::types::MAX_IDENTIFIER_LENGTH`] because a prefix is not an
/// identifier and the two bounds must be free to move apart.
pub(crate) const MAX_RULESET_PREFIX_BYTES: usize = 64;

/// Maximum `run` count, for both `exact` and `at-least`. Matches
/// `generic_token`'s existing bound on a single detected value's length —
/// the established precedent for "how long a single credential value is
/// allowed to be" in this codebase.
const MAX_RULESET_RUN_LENGTH: usize = 4_096;

/// Maximum number of `detector:` blocks in one ruleset. About 1.5x the
/// current built-in count: generous for a real internal-format inventory,
/// small enough that a scan's added per-input work stays the same order of
/// magnitude as the existing built-in set.
const MAX_RULESET_DETECTORS: usize = 64;

/// Minimum number of `detector:` blocks in one ruleset. An empty ruleset is
/// rejected ([`RulesetLoadError::EmptyRuleset`]), not silently accepted as a
/// no-op.
const MIN_RULESET_DETECTORS: usize = 1;

/// Maximum ruleset document size in bytes. Bounds the parser's own work
/// before any per-detector bound applies, the same role
/// [`crate::DEFAULT_MAX_INPUT_BYTES`] plays for scan input; a legitimate
/// ruleset (64 detectors x id + prefix + field names) is a few KB.
pub(crate) const MAX_RULESET_BYTES: usize = 64 * 1024;

/// The closed, seven-member alphabet-name vocabulary
/// (`decision-define-declarative-detector-ruleset-contract`, "Matching
/// vocabulary"). Mirrors the seven byte-class predicates
/// `crate::detectors::pattern` already defines; a ruleset cannot name an
/// eighth. The follow-up implementation maps each variant to the matching
/// predicate when it builds a scan shape from a [`RulesetDetectorSpec`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AlphabetName {
    /// `[A-Za-z0-9]`.
    Alnum,
    /// `[A-Za-z0-9_-]`.
    AlnumDash,
    /// `[A-Za-z0-9_.-]`.
    AlnumDashDot,
    /// `[A-Z0-9]`.
    UpperAlnum,
    /// `[0-9]`.
    Digit,
    /// `[0-9a-f]`.
    LowerHex,
    /// `[A-Za-z0-9+/]`.
    Base64Body,
}

impl AlphabetName {
    /// Parses a wire name, or `None` outside the seven-member vocabulary.
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

/// The closed, two-member validator (`PostCheck`) vocabulary
/// (`decision-define-declarative-detector-ruleset-contract`, "Closed
/// validator enum"). A ruleset selects a validator by name; it never
/// defines one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValidatorName {
    /// No post-check.
    None,
    /// The matched run's final `n` alphabet bytes must be lowercase hex,
    /// generalizing the Cloudflare detector's existing checksum-tail check.
    TrailingLowerHex,
}

impl ValidatorName {
    /// Parses a wire name, or `None` outside the closed enum.
    fn from_wire(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            "trailing-lower-hex" => Some(Self::TrailingLowerHex),
            _ => None,
        }
    }
}

/// Whether a `run` field is `exact <n>` or `at-least <n>`, mirroring the
/// pattern-matching engine's own quantifier shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunSpec {
    /// `exact <n>`.
    Exact(usize),
    /// `at-least <n>`.
    AtLeast(usize),
}

/// One fully parsed and validated `detector:` block: an owned, normalized
/// specification the follow-up implementation borrows from to build a
/// per-scan matching shape without copying the prefix bytes a second time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RulesetDetectorSpec {
    id: String,
    specificity: Specificity,
    prefix: String,
    alphabet: AlphabetName,
    run: RunSpec,
    validator: ValidatorName,
}

impl RulesetDetectorSpec {
    /// The caller-supplied detector id. Already validated against
    /// [`is_identifier`] and checked for collision with every `full`
    /// built-in id and every other detector id in the same ruleset.
    #[must_use]
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The claimed specificity: always [`Specificity::Entropy`] or
    /// [`Specificity::Contextual`], never one of the three reserved to
    /// built-ins.
    #[must_use]
    pub(crate) const fn specificity(&self) -> Specificity {
        self.specificity
    }

    /// The literal prefix, matched byte-exact and case-sensitive.
    #[must_use]
    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The named alphabet the run after [`Self::prefix`] must belong to.
    #[must_use]
    pub(crate) const fn alphabet(&self) -> AlphabetName {
        self.alphabet
    }

    /// The run-length quantifier.
    #[must_use]
    pub(crate) const fn run(&self) -> RunSpec {
        self.run
    }

    /// The selected post-check validator.
    #[must_use]
    pub(crate) const fn validator(&self) -> ValidatorName {
        self.validator
    }
}

/// Every way loading a ruleset can fail. Fixed and input-free by
/// construction: every variant is a unit variant, so no byte derived from
/// the rejected ruleset can ever be carried by one, satisfying the
/// fail-closed contract's "no byte derived from the rejected content is
/// ever carried"
/// (`decision-define-declarative-detector-ruleset-contract`).
///
/// Loading either returns every validated [`RulesetDetectorSpec`] or
/// rejects with one of these — never a partial result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RulesetLoadError {
    /// The whole ruleset document exceeds [`MAX_RULESET_BYTES`]. Checked
    /// before anything else is parsed.
    RulesetTooLarge,
    /// The `ruleset-revision` value is not [`RULESET_REVISION`].
    UnknownRevision,
    /// A field name a detector block's grammar does not define
    /// (`confidence`, for example).
    UnknownField,
    /// A line, block header, or field value shape the grammar does not
    /// define: no `:` on a line, a field before the first `detector:`
    /// line, non-UTF-8 bytes, a detector id failing [`is_identifier`], a
    /// `prefix` that is not a matched double-quoted literal, or a `run`
    /// value that is not `exact <n>` / `at-least <n>` with a valid `<n>`.
    UnsupportedConstruct,
    /// An `alphabet` name outside the seven-member vocabulary.
    UnknownAlphabet,
    /// A `validator` name outside the closed enum.
    UnknownValidator,
    /// A `specificity` name that either does not exist or is reserved to
    /// built-ins (`structural`, `provider`, `private-key`).
    SpecificityNotClaimable,
    /// A required field is absent from a detector block.
    MissingField,
    /// A `prefix` shorter than [`MIN_RULESET_PREFIX_BYTES`].
    PrefixTooShort,
    /// A `prefix` longer than [`MAX_RULESET_PREFIX_BYTES`].
    PrefixTooLong,
    /// A `run` count of zero or greater than [`MAX_RULESET_RUN_LENGTH`].
    RunLengthOutOfBounds,
    /// More than [`MAX_RULESET_DETECTORS`] detector blocks.
    TooManyDetectors,
    /// Two detector blocks declare the same id.
    DuplicateDetectorId,
    /// A detector id collides with a `full` built-in id.
    ReservedDetectorId,
    /// No detector blocks at all.
    EmptyRuleset,
}

/// The public, fixed rejection class of a rejected ruleset (issue #495,
/// `decision-define-declarative-detector-ruleset-contract`'s "Closed
/// validator enum" and "Fail-closed loading rule" sections).
///
/// This is [`RulesetLoadError`] translated one variant to one variant for
/// bindings that need the class as data rather than as a private Rust enum.
/// Like [`RulesetLoadError`], every variant is a content-free unit variant:
/// no byte from the rejected ruleset is ever carried by one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RulesetErrorClass {
    /// See [`RulesetLoadError::RulesetTooLarge`].
    RulesetTooLarge,
    /// See [`RulesetLoadError::UnknownRevision`].
    UnknownRevision,
    /// See [`RulesetLoadError::UnknownField`].
    UnknownField,
    /// See [`RulesetLoadError::UnsupportedConstruct`].
    UnsupportedConstruct,
    /// See [`RulesetLoadError::UnknownAlphabet`].
    UnknownAlphabet,
    /// See [`RulesetLoadError::UnknownValidator`].
    UnknownValidator,
    /// See [`RulesetLoadError::SpecificityNotClaimable`].
    SpecificityNotClaimable,
    /// See [`RulesetLoadError::MissingField`].
    MissingField,
    /// See [`RulesetLoadError::PrefixTooShort`].
    PrefixTooShort,
    /// See [`RulesetLoadError::PrefixTooLong`].
    PrefixTooLong,
    /// See [`RulesetLoadError::RunLengthOutOfBounds`].
    RunLengthOutOfBounds,
    /// See [`RulesetLoadError::TooManyDetectors`].
    TooManyDetectors,
    /// See [`RulesetLoadError::DuplicateDetectorId`].
    DuplicateDetectorId,
    /// See [`RulesetLoadError::ReservedDetectorId`].
    ReservedDetectorId,
    /// See [`RulesetLoadError::EmptyRuleset`].
    EmptyRuleset,
}

impl RulesetErrorClass {
    /// The stable `SCREAMING_SNAKE_CASE` class string, the same casing
    /// convention [`SecretScanErrorCode::as_str`] uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RulesetTooLarge => "RULESET_TOO_LARGE",
            Self::UnknownRevision => "UNKNOWN_REVISION",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::UnsupportedConstruct => "UNSUPPORTED_CONSTRUCT",
            Self::UnknownAlphabet => "UNKNOWN_ALPHABET",
            Self::UnknownValidator => "UNKNOWN_VALIDATOR",
            Self::SpecificityNotClaimable => "SPECIFICITY_NOT_CLAIMABLE",
            Self::MissingField => "MISSING_FIELD",
            Self::PrefixTooShort => "PREFIX_TOO_SHORT",
            Self::PrefixTooLong => "PREFIX_TOO_LONG",
            Self::RunLengthOutOfBounds => "RUN_LENGTH_OUT_OF_BOUNDS",
            Self::TooManyDetectors => "TOO_MANY_DETECTORS",
            Self::DuplicateDetectorId => "DUPLICATE_DETECTOR_ID",
            Self::ReservedDetectorId => "RESERVED_DETECTOR_ID",
            Self::EmptyRuleset => "EMPTY_RULESET",
        }
    }
}

impl std::fmt::Display for RulesetErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<RulesetLoadError> for RulesetErrorClass {
    fn from(error: RulesetLoadError) -> Self {
        match error {
            RulesetLoadError::RulesetTooLarge => Self::RulesetTooLarge,
            RulesetLoadError::UnknownRevision => Self::UnknownRevision,
            RulesetLoadError::UnknownField => Self::UnknownField,
            RulesetLoadError::UnsupportedConstruct => Self::UnsupportedConstruct,
            RulesetLoadError::UnknownAlphabet => Self::UnknownAlphabet,
            RulesetLoadError::UnknownValidator => Self::UnknownValidator,
            RulesetLoadError::SpecificityNotClaimable => Self::SpecificityNotClaimable,
            RulesetLoadError::MissingField => Self::MissingField,
            RulesetLoadError::PrefixTooShort => Self::PrefixTooShort,
            RulesetLoadError::PrefixTooLong => Self::PrefixTooLong,
            RulesetLoadError::RunLengthOutOfBounds => Self::RunLengthOutOfBounds,
            RulesetLoadError::TooManyDetectors => Self::TooManyDetectors,
            RulesetLoadError::DuplicateDetectorId => Self::DuplicateDetectorId,
            RulesetLoadError::ReservedDetectorId => Self::ReservedDetectorId,
            RulesetLoadError::EmptyRuleset => Self::EmptyRuleset,
        }
    }
}

/// A rejected ruleset, returned by [`load_ruleset`].
///
/// Carries exactly two fixed, content-free facts — never a byte derived
/// from the rejected ruleset (issue #495's "Bindings surface
/// `INVALID_RULESET` plus the fixed class name, and no caller-supplied or
/// input-derived byte appears in either"):
///
/// - [`Self::code`] is always [`SecretScanErrorCode::InvalidRuleset`], the
///   one public error code every binding maps to its own exception type.
/// - [`Self::class`] is the specific, fixed [`RulesetErrorClass`], so a
///   ruleset author (or the CLI printing a diagnostic) can tell a
///   `PrefixTooShort` rejection from an `UnknownAlphabet` one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RulesetError {
    class: RulesetErrorClass,
}

impl RulesetError {
    /// The one public error code every rejected ruleset carries.
    #[must_use]
    pub const fn code(self) -> SecretScanErrorCode {
        SecretScanErrorCode::InvalidRuleset
    }

    /// The fixed rejection class.
    #[must_use]
    pub const fn class(self) -> RulesetErrorClass {
        self.class
    }

    /// The fixed, input-free message for [`Self::code`]; identical to the
    /// `Display` output.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.code().message()
    }
}

impl From<RulesetLoadError> for RulesetError {
    fn from(error: RulesetLoadError) -> Self {
        Self {
            class: RulesetErrorClass::from(error),
        }
    }
}

impl std::fmt::Display for RulesetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for RulesetError {}

/// Parses `bytes` as a declarative ruleset and returns one registrable
/// [`Detector`] per validated `detector:` block, in the ruleset's own
/// declaration order (`decision-define-declarative-detector-ruleset-contract`).
///
/// This is the Rust core's whole ruleset surface: register the result the
/// same way a native custom detector is registered —
/// [`DetectorRegistry::with_built_in`](crate::DetectorRegistry::with_built_in),
/// [`DetectorRegistry::with_common_built_in`](crate::DetectorRegistry::with_common_built_in),
/// or [`DetectorRegistry::register`](crate::DetectorRegistry::register).
/// Passing the result to `with_built_in`/`with_common_built_in` keeps the
/// registry's [`Profile`](crate::Profile) identity, since a ruleset sits
/// outside profile identity (the ADR's "Profile interaction"); `register`
/// clears it, exactly as it does for any other custom detector.
///
/// Every returned detector claims [`Confidence::Medium`](crate::Confidence::Medium)
/// and either [`Specificity::Entropy`] or [`Specificity::Contextual`] —
/// never [`Specificity::Structural`], [`Specificity::Provider`], or
/// [`Specificity::PrivateKey`], which [`parse_ruleset`] already refuses to
/// parse. Combined with every custom detector registering after every
/// built-in (`decision-define-detector-profile-and-pack-contract`), a
/// ruleset detector can add detections but can never overturn a built-in's
/// resolved finding through the specificity or registration-order tie-break
/// keys (`crate::pipeline`'s `RankedCandidate::priority`).
///
/// # Errors
///
/// Returns a [`RulesetError`] describing the fixed rejection class; see
/// [`RulesetLoadError`] for the full catalog. Loading never partially
/// succeeds: either every detector block is returned or the whole ruleset
/// is rejected.
///
/// # Examples
///
/// ```
/// use redact_secret::{DetectorRegistry, load_ruleset};
///
/// let ruleset = b"ruleset-revision: 1\n\
/// detector: acme-internal-token\n\
/// specificity: contextual\n\
/// prefix: \"ACME_\"\n\
/// alphabet: alnum-dash\n\
/// run: at-least 20\n\
/// validator: none\n";
///
/// let detectors = load_ruleset(ruleset)?;
/// assert_eq!(detectors.len(), 1);
///
/// let registry = DetectorRegistry::with_built_in(detectors)?;
/// assert!(registry.contains("acme-internal-token"));
/// assert_eq!(registry.profile(), Some(redact_secret::Profile::Full));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn load_ruleset(bytes: &[u8]) -> Result<Vec<Box<dyn Detector>>, RulesetError> {
    let specs = parse_ruleset(bytes)?;
    Ok(specs
        .into_iter()
        .map(|spec| Box::new(RulesetDetector::new(spec)) as Box<dyn Detector>)
        .collect())
}

/// Trimmed, non-blank lines of `text`, in order.
fn non_blank_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|line| !line.is_empty())
}

/// Splits one `key: value` line. `None` when the line has no `:`.
fn split_field(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    Some((key.trim(), value.trim()))
}

/// Parses a `specificity` field value. Only [`Specificity::Entropy`] and
/// [`Specificity::Contextual`] are claimable; every other name — including
/// one the closed enum does not define at all — maps to the same fixed
/// [`RulesetLoadError::SpecificityNotClaimable`], per the decision's "a
/// specificity name that either does not exist or is reserved to
/// built-ins".
fn parse_specificity(value: &str) -> Result<Specificity, RulesetLoadError> {
    match Specificity::from_name(value) {
        Some(specificity @ (Specificity::Entropy | Specificity::Contextual)) => Ok(specificity),
        _ => Err(RulesetLoadError::SpecificityNotClaimable),
    }
}

/// Parses a `prefix` field value: a double-quoted literal with no escape
/// sequences recognized inside the quotes, bounded by
/// [`MIN_RULESET_PREFIX_BYTES`] and [`MAX_RULESET_PREFIX_BYTES`].
fn parse_prefix(value: &str) -> Result<String, RulesetLoadError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or(RulesetLoadError::UnsupportedConstruct)?;
    if inner.len() < MIN_RULESET_PREFIX_BYTES {
        return Err(RulesetLoadError::PrefixTooShort);
    }
    if inner.len() > MAX_RULESET_PREFIX_BYTES {
        return Err(RulesetLoadError::PrefixTooLong);
    }
    Ok(inner.to_owned())
}

/// Parses a `run` field value: `exact <n>` or `at-least <n>`, `<n>` bounded
/// by [`MAX_RULESET_RUN_LENGTH`] and required to be at least 1.
fn parse_run(value: &str) -> Result<RunSpec, RulesetLoadError> {
    let (kind, count) = value
        .split_once(' ')
        .ok_or(RulesetLoadError::UnsupportedConstruct)?;
    let count: usize = count
        .trim()
        .parse()
        .map_err(|_| RulesetLoadError::UnsupportedConstruct)?;
    if count == 0 || count > MAX_RULESET_RUN_LENGTH {
        return Err(RulesetLoadError::RunLengthOutOfBounds);
    }
    match kind {
        "exact" => Ok(RunSpec::Exact(count)),
        "at-least" => Ok(RunSpec::AtLeast(count)),
        _ => Err(RulesetLoadError::UnsupportedConstruct),
    }
}

/// Validates a completed detector block's id and fields, and appends the
/// resulting [`RulesetDetectorSpec`] to `specs`.
fn flush_block(
    id: &str,
    fields: &[(&str, &str)],
    specs: &mut Vec<RulesetDetectorSpec>,
) -> Result<(), RulesetLoadError> {
    if !is_identifier(id) {
        return Err(RulesetLoadError::UnsupportedConstruct);
    }
    if built_in_ids().any(|reserved| reserved == id) {
        return Err(RulesetLoadError::ReservedDetectorId);
    }
    if specs.iter().any(|existing| existing.id == id) {
        return Err(RulesetLoadError::DuplicateDetectorId);
    }
    if specs.len() >= MAX_RULESET_DETECTORS {
        return Err(RulesetLoadError::TooManyDetectors);
    }

    let mut specificity = None;
    let mut prefix = None;
    let mut alphabet = None;
    let mut run = None;
    let mut validator = None;

    for &(key, value) in fields {
        match key {
            "specificity" => specificity = Some(parse_specificity(value)?),
            "prefix" => prefix = Some(parse_prefix(value)?),
            "alphabet" => {
                alphabet =
                    Some(AlphabetName::from_wire(value).ok_or(RulesetLoadError::UnknownAlphabet)?);
            }
            "run" => run = Some(parse_run(value)?),
            "validator" => {
                validator = Some(
                    ValidatorName::from_wire(value).ok_or(RulesetLoadError::UnknownValidator)?,
                );
            }
            _ => return Err(RulesetLoadError::UnknownField),
        }
    }

    specs.push(RulesetDetectorSpec {
        id: id.to_owned(),
        specificity: specificity.ok_or(RulesetLoadError::MissingField)?,
        prefix: prefix.ok_or(RulesetLoadError::MissingField)?,
        alphabet: alphabet.ok_or(RulesetLoadError::MissingField)?,
        run: run.ok_or(RulesetLoadError::MissingField)?,
        validator: validator.ok_or(RulesetLoadError::MissingField)?,
    });
    Ok(())
}

/// Parses and validates a caller-supplied declarative ruleset.
///
/// Never partially loads: the whole document is validated before any
/// [`RulesetDetectorSpec`] is returned, and the first rejection wins. See
/// the module documentation for the wire grammar.
///
/// # Errors
///
/// Returns the first applicable [`RulesetLoadError`]; see its variants for
/// the full rejection catalog.
pub(crate) fn parse_ruleset(bytes: &[u8]) -> Result<Vec<RulesetDetectorSpec>, RulesetLoadError> {
    if bytes.len() > MAX_RULESET_BYTES {
        return Err(RulesetLoadError::RulesetTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RulesetLoadError::UnsupportedConstruct)?;
    let mut lines = non_blank_lines(text);

    let revision_line = lines.next().ok_or(RulesetLoadError::EmptyRuleset)?;
    let (key, value) = split_field(revision_line).ok_or(RulesetLoadError::UnsupportedConstruct)?;
    if key != "ruleset-revision" {
        return Err(RulesetLoadError::UnsupportedConstruct);
    }
    if value != RULESET_REVISION {
        return Err(RulesetLoadError::UnknownRevision);
    }

    let mut specs: Vec<RulesetDetectorSpec> = Vec::new();
    let mut current_id: Option<&str> = None;
    let mut current_fields: Vec<(&str, &str)> = Vec::new();

    for line in lines {
        let (key, value) = split_field(line).ok_or(RulesetLoadError::UnsupportedConstruct)?;
        if key == "detector" {
            if let Some(previous_id) = current_id.replace(value) {
                flush_block(previous_id, &current_fields, &mut specs)?;
                current_fields.clear();
            }
        } else {
            if current_id.is_none() {
                return Err(RulesetLoadError::UnsupportedConstruct);
            }
            current_fields.push((key, value));
        }
    }
    if let Some(id) = current_id {
        flush_block(id, &current_fields, &mut specs)?;
    }

    if specs.len() < MIN_RULESET_DETECTORS {
        return Err(RulesetLoadError::EmptyRuleset);
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

    fn replace_once(text: &str, from: &str, to: &str) -> String {
        assert!(text.contains(from), "fixture must contain {from:?}");
        text.replacen(from, to, 1)
    }

    #[test]
    fn parses_a_valid_minimal_ruleset() {
        let specs = parse_ruleset(VALID.as_bytes()).unwrap();
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];
        assert_eq!(spec.id(), "acme-internal-token");
        assert_eq!(spec.specificity(), Specificity::Contextual);
        assert_eq!(spec.prefix(), "ACME_");
        assert_eq!(spec.alphabet(), AlphabetName::AlnumDash);
        assert_eq!(spec.run(), RunSpec::AtLeast(20));
        assert_eq!(spec.validator(), ValidatorName::None);
    }

    #[test]
    fn parses_every_alphabet_and_validator_name() {
        for (name, expected) in [
            ("alnum", AlphabetName::Alnum),
            ("alnum-dash", AlphabetName::AlnumDash),
            ("alnum-dash-dot", AlphabetName::AlnumDashDot),
            ("upper-alnum", AlphabetName::UpperAlnum),
            ("digit", AlphabetName::Digit),
            ("lower-hex", AlphabetName::LowerHex),
            ("base64-body", AlphabetName::Base64Body),
        ] {
            let text = replace_once(VALID, "alnum-dash", name);
            let specs = parse_ruleset(text.as_bytes()).unwrap();
            assert_eq!(specs[0].alphabet(), expected, "{name}");
        }
        for (name, expected) in [
            ("none", ValidatorName::None),
            ("trailing-lower-hex", ValidatorName::TrailingLowerHex),
        ] {
            let text = replace_once(VALID, "validator: none", &format!("validator: {name}"));
            let specs = parse_ruleset(text.as_bytes()).unwrap();
            assert_eq!(specs[0].validator(), expected, "{name}");
        }
    }

    #[test]
    fn parses_exact_and_at_least_run_forms() {
        let text = replace_once(VALID, "run: at-least 20", "run: exact 12");
        let specs = parse_ruleset(text.as_bytes()).unwrap();
        assert_eq!(specs[0].run(), RunSpec::Exact(12));
    }

    #[test]
    fn owns_its_storage_independent_of_the_input_buffer() {
        let spec = {
            let bytes = VALID.as_bytes().to_vec();
            let mut specs = parse_ruleset(&bytes).unwrap();
            drop(bytes);
            specs.remove(0)
        };
        assert_eq!(spec.id(), "acme-internal-token");
        assert_eq!(spec.prefix(), "ACME_");
    }

    #[test]
    fn rejects_ruleset_bytes_over_the_size_bound() {
        let oversized = "x".repeat(MAX_RULESET_BYTES + 1);
        assert_eq!(
            parse_ruleset(oversized.as_bytes()),
            Err(RulesetLoadError::RulesetTooLarge)
        );
    }

    #[test]
    fn rejects_non_utf8_bytes() {
        assert_eq!(
            parse_ruleset(&[0x66, 0x6f, 0xff, 0x6f]),
            Err(RulesetLoadError::UnsupportedConstruct)
        );
    }

    #[test]
    fn rejects_unknown_revision() {
        let text = replace_once(VALID, "ruleset-revision: 1", "ruleset-revision: 2");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnknownRevision)
        );
    }

    #[test]
    fn rejects_a_first_line_that_is_not_the_revision_field() {
        let text = replace_once(VALID, "ruleset-revision: 1", "revision: 1");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnsupportedConstruct)
        );
    }

    #[test]
    fn rejects_a_line_with_no_colon() {
        let text = replace_once(VALID, "validator: none", "validator: none\nbogus line");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnsupportedConstruct)
        );
    }

    #[test]
    fn rejects_a_field_line_before_any_detector_header() {
        let text = "ruleset-revision: 1\nprefix: \"ACME_\"\n";
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnsupportedConstruct)
        );
    }

    #[test]
    fn rejects_unknown_field_including_confidence() {
        for extra in ["confidence: high", "bogus: x"] {
            let text = replace_once(
                VALID,
                "validator: none",
                &format!("validator: none\n{extra}"),
            );
            assert_eq!(
                parse_ruleset(text.as_bytes()),
                Err(RulesetLoadError::UnknownField),
                "{extra}"
            );
        }
    }

    #[test]
    fn rejects_unknown_alphabet() {
        let text = replace_once(VALID, "alnum-dash", "mixed-case");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnknownAlphabet)
        );
    }

    #[test]
    fn rejects_unknown_validator() {
        let text = replace_once(VALID, "validator: none", "validator: bogus-checksum");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnknownValidator)
        );
    }

    #[test]
    fn rejects_a_specificity_reserved_to_built_ins() {
        for reserved in ["structural", "provider", "private-key"] {
            let text = replace_once(
                VALID,
                "specificity: contextual",
                &format!("specificity: {reserved}"),
            );
            assert_eq!(
                parse_ruleset(text.as_bytes()),
                Err(RulesetLoadError::SpecificityNotClaimable),
                "{reserved}"
            );
        }
    }

    #[test]
    fn rejects_a_specificity_name_that_does_not_exist() {
        let text = replace_once(VALID, "specificity: contextual", "specificity: bogus");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::SpecificityNotClaimable)
        );
    }

    #[test]
    fn rejects_a_detector_block_missing_each_required_field() {
        for field_line in [
            "specificity: contextual",
            "prefix: \"ACME_\"",
            "alphabet: alnum-dash",
            "run: at-least 20",
            "validator: none",
        ] {
            let text = VALID.replacen(&format!("{field_line}\n"), "", 1);
            assert_eq!(
                parse_ruleset(text.as_bytes()),
                Err(RulesetLoadError::MissingField),
                "{field_line}"
            );
        }
    }

    #[test]
    fn rejects_a_prefix_shorter_than_the_minimum() {
        let text = replace_once(VALID, "prefix: \"ACME_\"", "prefix: \"AC\"");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::PrefixTooShort)
        );
    }

    #[test]
    fn rejects_an_unquoted_prefix() {
        let text = replace_once(VALID, "prefix: \"ACME_\"", "prefix: ACME_");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnsupportedConstruct)
        );
    }

    #[test]
    fn rejects_a_prefix_longer_than_the_maximum() {
        let long = "a".repeat(MAX_RULESET_PREFIX_BYTES + 1);
        let text = replace_once(VALID, "prefix: \"ACME_\"", &format!("prefix: \"{long}\""));
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::PrefixTooLong)
        );
    }

    #[test]
    fn rejects_a_zero_run_length() {
        let text = replace_once(VALID, "run: at-least 20", "run: at-least 0");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::RunLengthOutOfBounds)
        );
    }

    #[test]
    fn rejects_an_over_bound_run_length() {
        let text = replace_once(VALID, "run: at-least 20", "run: at-least 999999");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::RunLengthOutOfBounds)
        );
    }

    #[test]
    fn rejects_a_malformed_run_shape() {
        let text = replace_once(VALID, "run: at-least 20", "run: sometimes 20");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::UnsupportedConstruct)
        );
    }

    fn detector_block(id: &str) -> String {
        format!(
            "detector: {id}\nspecificity: contextual\nprefix: \"ACME_\"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n"
        )
    }

    #[test]
    fn rejects_too_many_detectors() {
        let mut text = String::from("ruleset-revision: 1\n");
        for index in 0..65 {
            text.push_str(&detector_block(&format!("acme-token-{index}")));
        }
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::TooManyDetectors)
        );
    }

    #[test]
    fn accepts_exactly_the_maximum_detector_count() {
        let mut text = String::from("ruleset-revision: 1\n");
        for index in 0..64 {
            text.push_str(&detector_block(&format!("acme-token-{index}")));
        }
        let specs = parse_ruleset(text.as_bytes()).unwrap();
        assert_eq!(specs.len(), 64);
    }

    #[test]
    fn rejects_a_duplicate_detector_id() {
        let text = format!("{VALID}{}", detector_block("acme-internal-token"));
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::DuplicateDetectorId)
        );
    }

    #[test]
    fn rejects_a_detector_id_that_collides_with_a_built_in() {
        let text = replace_once(VALID, "acme-internal-token", "github-token");
        assert_eq!(
            parse_ruleset(text.as_bytes()),
            Err(RulesetLoadError::ReservedDetectorId)
        );
    }

    #[test]
    fn rejects_a_detector_id_failing_is_identifier() {
        for malformed in ["Acme-Token", "1acme", "acme_", "", "acme token"] {
            let text = replace_once(VALID, "acme-internal-token", malformed);
            assert_eq!(
                parse_ruleset(text.as_bytes()),
                Err(RulesetLoadError::UnsupportedConstruct),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_ruleset() {
        assert_eq!(parse_ruleset(b""), Err(RulesetLoadError::EmptyRuleset));
        assert_eq!(
            parse_ruleset(b"ruleset-revision: 1\n"),
            Err(RulesetLoadError::EmptyRuleset)
        );
    }

    /// Demonstrates, not merely asserts by type, that a rejection carries no
    /// byte from the rejected ruleset: an adversarial marker placed in a
    /// field that trips several different rejection classes never survives
    /// into the error's own `Debug` rendering.
    #[test]
    fn rejections_never_carry_the_rejected_content() {
        let canary = "S3CR3T_CANARY_MARKER";
        let cases = [
            replace_once(VALID, "alnum-dash", canary),
            replace_once(VALID, "validator: none", &format!("validator: {canary}")),
            replace_once(VALID, "acme-internal-token", canary),
            format!("ruleset-revision: {canary}\n"),
        ];
        for text in cases {
            let error = parse_ruleset(text.as_bytes()).unwrap_err();
            assert!(!format!("{error:?}").contains(canary), "{text}");
        }
    }
}
