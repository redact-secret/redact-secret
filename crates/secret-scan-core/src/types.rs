//! Pipeline contract types shared by every detector, policy, and formatter.
//!
//! All values here are immutable once constructed: fields are private and
//! exposed through accessors, so a detector, policy, or host cannot mutate a
//! candidate or finding after it has been validated. Ranges are UTF-8 byte
//! offsets into the scanned input ([`crate::RANGE_UNIT`]).

use std::borrow::Cow;
use std::sync::OnceLock;

use crate::error::{
    DetectorFailure, FormatterFailure, PolicyFailure, SecretScanError, SecretScanErrorCode,
};

/// Maximum length in bytes of a public identifier (`type`, detector id,
/// finding id).
pub const MAX_IDENTIFIER_LENGTH: usize = 64;

/// Returns `true` when `value` matches `^[a-z][a-z0-9]*([._-][a-z0-9]+)*$`
/// and is at most [`MAX_IDENTIFIER_LENGTH`] bytes.
///
/// Identifiers are the only detector-controlled strings that reach public
/// results; the grammar keeps them free of anything that could carry a
/// matched value.
#[must_use]
pub fn is_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut previous_was_separator = false;
    for &byte in &bytes[1..] {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_was_separator = false,
            b'.' | b'_' | b'-' if !previous_was_separator => previous_was_separator = true,
            _ => return false,
        }
    }
    !previous_was_separator
}

/// How strongly a detector believes a candidate is a credential.
///
/// Ordering is `Low < Medium < High`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Confidence {
    /// Weak evidence, usually heuristic.
    Low,
    /// Moderate evidence.
    Medium,
    /// Strong structural or provider-format evidence.
    High,
}

impl Confidence {
    /// The wire name (`"high"`, `"medium"`, `"low"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Parses a wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

/// The evidence class a detector claims for a candidate. This is the first
/// key of overlap resolution.
///
/// Ordering is the documented precedence, lowest first:
/// `Entropy < Contextual < Structural < Provider < PrivateKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Specificity {
    /// Entropy-only heuristic. Also the default for candidates that omit a
    /// specificity, so an unclassified detector cannot displace a classified
    /// one.
    Entropy,
    /// Contextual assignment (`API_KEY=...`).
    Contextual,
    /// Structural syntax (`Authorization: Bearer ...`, connection URLs).
    Structural,
    /// Provider-specific token format.
    Provider,
    /// Private key or comparably specific credential.
    PrivateKey,
}

impl Specificity {
    /// The wire name (`"private-key"`, `"provider"`, `"structural"`,
    /// `"contextual"`, `"entropy"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKey => "private-key",
            Self::Provider => "provider",
            Self::Structural => "structural",
            Self::Contextual => "contextual",
            Self::Entropy => "entropy",
        }
    }

    /// Parses a wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "private-key" => Some(Self::PrivateKey),
            "provider" => Some(Self::Provider),
            "structural" => Some(Self::Structural),
            "contextual" => Some(Self::Contextual),
            "entropy" => Some(Self::Entropy),
            _ => None,
        }
    }
}

/// The enforcement decision a policy attaches to a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Replace the range with a placeholder.
    Redact,
    /// Replace the range with a placeholder and signal that the input must
    /// not proceed.
    Block,
    /// Keep the text and report the finding.
    Warn,
    /// Keep the text; the finding is informational.
    Allow,
}

impl Action {
    /// The wire name (`"redact"`, `"block"`, `"warn"`, `"allow"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Redact => "redact",
            Self::Block => "block",
            Self::Warn => "warn",
            Self::Allow => "allow",
        }
    }

    /// Parses a wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "redact" => Some(Self::Redact),
            "block" => Some(Self::Block),
            "warn" => Some(Self::Warn),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }

    /// `true` for `Redact` and `Block`: the range is replaced in output.
    #[must_use]
    pub const fn replaces_text(self) -> bool {
        matches!(self, Self::Redact | Self::Block)
    }

    /// Enforcement strength used only to keep overlap resolution
    /// (`crate::pipeline::RankedCandidate::priority`) from letting a
    /// candidate that would resolve to a weaker action displace one that
    /// would resolve to a stricter action. Not exposed publicly: `Action`
    /// has no general total order, and this fixed `Block > Redact > Warn >
    /// Allow` ranking is specific to that one use
    /// (`decision-resolve-overlap-precedence-by-resolved-action-severity`).
    #[must_use]
    pub(crate) const fn overlap_resolution_severity(self) -> u8 {
        match self {
            Self::Block => 3,
            Self::Redact => 2,
            Self::Warn => 1,
            Self::Allow => 0,
        }
    }
}

/// Whether a finding's reported range shows evidence of
/// invisible-character obfuscation.
///
/// Carries no value, no offset into the secret, and no plaintext —
/// consistent with the rule that neither [`Candidate`] nor [`Finding`] ever
/// carries matched text
/// (`decision-normalize-invisible-characters-before-detection`).
/// [`DefaultPolicy`](crate::DefaultPolicy) does not change behavior based on
/// this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Obfuscation {
    /// No removed code point lies inside the reported range.
    None,
    /// At least one invisible/format code point was removed from inside the
    /// candidate.
    InvisibleCharacters,
}

impl Obfuscation {
    /// The wire name (`"none"`, `"invisible-characters"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InvisibleCharacters => "invisible-characters",
        }
    }

    /// Parses a wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            "invisible-characters" => Some(Self::InvisibleCharacters),
            _ => None,
        }
    }
}

/// A non-empty half-open range `[start, end)` of UTF-8 byte offsets.
///
/// Construction only guarantees `start < end`; whether the range fits the
/// input and lies on character boundaries is checked by the pipeline against
/// the actual input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteRange {
    start: usize,
    end: usize,
}

// A `ByteRange` is never empty by construction, so `is_empty` would be a
// constant `false`.
#[allow(clippy::len_without_is_empty)]
impl ByteRange {
    /// Creates a range, or `None` when `start >= end`.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Option<Self> {
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Inclusive start offset.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive end offset.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Length in bytes; always positive.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    /// `true` when the two ranges share at least one byte.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// `true` when the range lies inside `input` and both offsets are on
    /// character boundaries.
    #[must_use]
    pub fn is_char_aligned_in(self, input: &str) -> bool {
        self.end <= input.len()
            && input.is_char_boundary(self.start)
            && input.is_char_boundary(self.end)
    }
}

/// Read-only information a detector receives alongside the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DetectorContext {
    input_len: usize,
}

impl DetectorContext {
    /// Creates a context for an input of `input_len` bytes.
    #[must_use]
    pub const fn new(input_len: usize) -> Self {
        Self { input_len }
    }

    /// Length of the scanned input in UTF-8 bytes.
    #[must_use]
    pub const fn input_len(self) -> usize {
        self.input_len
    }
}

/// A finite pack of compile-time diagnostic signal labels, materialized once
/// as `String`s so [`Candidate::signals`] can keep returning `&[String]`.
///
/// A pack only ever holds the fixed literals written at its definition site:
/// never source input, never a runtime-derived name, and there is no registry,
/// so the retained memory is bounded by the number of definition sites.
/// Define one through [`signal_pack!`].
pub(crate) struct SignalPack {
    names: &'static [&'static str],
    strings: OnceLock<Box<[String]>>,
}

impl SignalPack {
    pub(crate) const fn new(names: &'static [&'static str]) -> Self {
        Self {
            names,
            strings: OnceLock::new(),
        }
    }

    fn strings(&'static self) -> &'static [String] {
        self.strings
            .get_or_init(|| self.names.iter().map(|name| (*name).to_owned()).collect())
    }
}

/// Expands to a `&'static SignalPack` for the given string literals, one
/// `static` per expansion site.
macro_rules! signal_pack {
    ($($name:literal),+ $(,)?) => {{
        static PACK: $crate::types::SignalPack = $crate::types::SignalPack::new(&[$($name),+]);
        &PACK
    }};
}
pub(crate) use signal_pack;

/// A detector's private proposal: classification and range only.
///
/// A candidate never carries the matched text. It is validated by the
/// pipeline before it can influence any public result.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Candidate {
    type_name: Cow<'static, str>,
    confidence: Confidence,
    specificity: Option<Specificity>,
    range: ByteRange,
    signals: Cow<'static, [String]>,
    obfuscation: Obfuscation,
    reject_invisible_normalization: bool,
}

impl Candidate {
    /// Creates a candidate with no explicit specificity, no signals, and no
    /// claimed obfuscation.
    #[must_use]
    pub fn new(type_name: impl Into<String>, confidence: Confidence, range: ByteRange) -> Self {
        Self {
            type_name: Cow::Owned(type_name.into()),
            confidence,
            specificity: None,
            range,
            signals: Cow::Borrowed(&[]),
            obfuscation: Obfuscation::None,
            reject_invisible_normalization: false,
        }
    }

    /// [`new`](Self::new) for a `'static` type name: the name is borrowed, so
    /// constructing the candidate does not allocate it. Built-in detectors
    /// use this; the public constructor keeps owning its argument.
    #[must_use]
    pub(crate) const fn built_in(
        type_name: &'static str,
        confidence: Confidence,
        range: ByteRange,
    ) -> Self {
        Self {
            type_name: Cow::Borrowed(type_name),
            confidence,
            specificity: None,
            range,
            signals: Cow::Borrowed(&[]),
            obfuscation: Obfuscation::None,
            reject_invisible_normalization: false,
        }
    }

    /// Sets the claimed specificity.
    #[must_use]
    pub const fn with_specificity(mut self, specificity: Specificity) -> Self {
        self.specificity = Some(specificity);
        self
    }

    /// Sets the claimed invisible-character-obfuscation signal. The
    /// pipeline also derives this independently from the translated range;
    /// either source setting [`Obfuscation::InvisibleCharacters`] is enough.
    #[must_use]
    pub const fn with_obfuscation(mut self, obfuscation: Obfuscation) -> Self {
        self.obfuscation = obfuscation;
        self
    }

    /// Rejects this candidate when a governed invisible run lies inside or
    /// directly touches its range in the detector's normalized scan view.
    #[must_use]
    pub(crate) const fn reject_invisible_normalization(mut self) -> Self {
        self.reject_invisible_normalization = true;
        self
    }

    /// Replaces the diagnostic signal list. Signals are detector-internal
    /// evidence labels; they never reach public results.
    #[must_use]
    pub fn with_signals<I, S>(mut self, signals: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.signals = Cow::Owned(signals.into_iter().map(Into::into).collect());
        self
    }

    /// [`with_signals`](Self::with_signals) for a finite, compile-time set of
    /// diagnostic labels: the candidate borrows the pack's one shared slice,
    /// so constructing or cloning it allocates no signal strings. Built-in
    /// detectors use this; the observable values and their order are exactly
    /// those `with_signals` would produce from the same labels.
    #[must_use]
    pub(crate) fn with_signal_pack(mut self, pack: &'static SignalPack) -> Self {
        self.signals = Cow::Borrowed(pack.strings());
        self
    }

    /// The finding type this candidate claims.
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// The claimed type as stored: borrowed for a built-in detector's
    /// static name, so a finding built from it allocates nothing.
    pub(crate) const fn type_name_cow(&self) -> &Cow<'static, str> {
        &self.type_name
    }

    /// Confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Explicit specificity, if the detector set one.
    #[must_use]
    pub const fn specificity(&self) -> Option<Specificity> {
        self.specificity
    }

    /// Specificity used for overlap resolution: the explicit value or
    /// [`Specificity::Entropy`].
    #[must_use]
    pub fn effective_specificity(&self) -> Specificity {
        self.specificity.unwrap_or(Specificity::Entropy)
    }

    /// The claimed byte range.
    #[must_use]
    pub const fn range(&self) -> ByteRange {
        self.range
    }

    /// Detector-internal signal labels.
    #[must_use]
    pub fn signals(&self) -> &[String] {
        &self.signals
    }

    /// The claimed invisible-character-obfuscation signal.
    #[must_use]
    pub const fn obfuscation(&self) -> Obfuscation {
        self.obfuscation
    }

    pub(crate) const fn rejects_invisible_normalization(&self) -> bool {
        self.reject_invisible_normalization
    }

    /// This candidate with its range moved `by` bytes later, or `None` if
    /// that overflows.
    pub(crate) fn shifted(mut self, by: usize) -> Option<Self> {
        self.range = ByteRange::new(
            self.range.start().checked_add(by)?,
            self.range.end().checked_add(by)?,
        )?;
        Some(self)
    }
}

/// An independent detection unit.
///
/// A detector may inspect substrings of `input` while running, but must
/// only return classification and range metadata. It reports failure through
/// the payload-free [`DetectorFailure`].
pub trait Detector {
    /// Stable identifier; must satisfy [`is_identifier`] and be unique
    /// within a registry.
    fn id(&self) -> &str;

    /// Scans `input` and returns candidates in emission order.
    ///
    /// Inside the pipeline, `input` is the scan copy: the caller's text with
    /// invisible code points removed. Candidate ranges index that copy, and
    /// the pipeline translates them back to the caller's text.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorFailure`] on any internal failure. The pipeline
    /// reports it as [`SecretScanErrorCode::DetectorFailure`].
    fn detect(
        &self,
        input: &str,
        context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure>;
}

/// A finding after overlap resolution and before policy evaluation.
///
/// This is the immutable metadata a [`Policy`] receives. It contains no
/// matched value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DetectedFinding {
    id: String,
    type_name: Cow<'static, str>,
    detector: Cow<'static, str>,
    confidence: Confidence,
    range: ByteRange,
    obfuscation: Obfuscation,
}

impl DetectedFinding {
    /// Creates a finding from already-validated identifiers, with no
    /// obfuscation signal. Use [`with_obfuscation`](Self::with_obfuscation)
    /// to attach one.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidCandidate`] when `id`,
    /// `type_name`, or `detector` is not an [identifier](is_identifier).
    pub fn new(
        id: impl Into<String>,
        type_name: impl Into<String>,
        detector: impl Into<String>,
        confidence: Confidence,
        range: ByteRange,
    ) -> Result<Self, SecretScanError> {
        let id = id.into();
        let type_name = type_name.into();
        let detector = detector.into();
        if !is_identifier(&id) || !is_identifier(&type_name) || !is_identifier(&detector) {
            return Err(SecretScanErrorCode::InvalidCandidate.into());
        }
        Ok(Self {
            id,
            type_name: Cow::Owned(type_name),
            detector: Cow::Owned(detector),
            confidence,
            range,
            obfuscation: Obfuscation::None,
        })
    }

    /// The pipeline's constructor: `type_name` was validated as a candidate
    /// type, `detector` at registration, and `id` is `finding-<n>`, so no
    /// identifier is re-checked here. Built-in names arrive borrowed and
    /// allocate nothing.
    pub(crate) fn from_validated(
        id: String,
        type_name: Cow<'static, str>,
        detector: Cow<'static, str>,
        confidence: Confidence,
        range: ByteRange,
        obfuscation: Obfuscation,
    ) -> Self {
        debug_assert!(is_identifier(&id) && is_identifier(&type_name) && is_identifier(&detector));
        Self {
            id,
            type_name,
            detector,
            confidence,
            range,
            obfuscation,
        }
    }

    /// Attaches the invisible-character-obfuscation signal.
    #[must_use]
    pub const fn with_obfuscation(mut self, obfuscation: Obfuscation) -> Self {
        self.obfuscation = obfuscation;
        self
    }

    /// This finding with its range replaced. Every other field is moved, not
    /// revalidated: they were validated when this finding was built (issue
    /// #1060).
    #[must_use]
    pub(crate) const fn with_range(mut self, range: ByteRange) -> Self {
        self.range = range;
        self
    }

    /// This finding with its id replaced by `id`, which must be an
    /// [identifier](is_identifier); the incremental session passes only
    /// `finding-<n>` (issue #1060).
    #[must_use]
    pub(crate) fn with_id(mut self, id: String) -> Self {
        debug_assert!(is_identifier(&id));
        self.id = id;
        self
    }

    /// Deterministic finding id (`finding-1`, `finding-2`, ...).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Finding type.
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Id of the detector that produced the winning candidate.
    #[must_use]
    pub fn detector(&self) -> &str {
        &self.detector
    }

    /// Confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Byte range in the original input.
    #[must_use]
    pub const fn range(&self) -> ByteRange {
        self.range
    }

    /// Invisible-character-obfuscation signal for this finding's range.
    #[must_use]
    pub const fn obfuscation(&self) -> Obfuscation {
        self.obfuscation
    }

    /// Attaches a policy action, producing the public [`Finding`].
    #[must_use]
    pub fn with_action(self, action: Action) -> Finding {
        Finding {
            detected: self,
            action,
        }
    }
}

/// The public, immutable result of scanning: safe metadata plus the action.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finding {
    detected: DetectedFinding,
    action: Action,
}

impl Finding {
    /// Creates a finding from its parts.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidCandidate`] when an identifier
    /// is malformed; see [`DetectedFinding::new`].
    pub fn new(
        id: impl Into<String>,
        type_name: impl Into<String>,
        detector: impl Into<String>,
        confidence: Confidence,
        action: Action,
        range: ByteRange,
    ) -> Result<Self, SecretScanError> {
        Ok(DetectedFinding::new(id, type_name, detector, confidence, range)?.with_action(action))
    }

    /// Deterministic finding id.
    #[must_use]
    pub fn id(&self) -> &str {
        self.detected.id()
    }

    /// Finding type.
    #[must_use]
    pub fn type_name(&self) -> &str {
        self.detected.type_name()
    }

    /// Detector id.
    #[must_use]
    pub fn detector(&self) -> &str {
        self.detected.detector()
    }

    /// Confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.detected.confidence()
    }

    /// Policy action.
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// Byte range in the original input.
    #[must_use]
    pub const fn range(&self) -> ByteRange {
        self.detected.range()
    }

    /// Invisible-character-obfuscation signal for this finding's range.
    #[must_use]
    pub const fn obfuscation(&self) -> Obfuscation {
        self.detected.obfuscation()
    }

    /// The pre-policy metadata.
    #[must_use]
    pub const fn detected(&self) -> &DetectedFinding {
        &self.detected
    }
}

/// Sanitized text paired with the findings that produced it.
///
/// This is the result type of every API that redacts and reports in one
/// call: [`scan_and_redact`](crate::scan_and_redact) for a whole input, and
/// [`IncrementalSanitizer`](crate::IncrementalSanitizer) for a chunked
/// session (where it is named [`IncrementalResult`](crate::IncrementalResult)).
///
/// [`findings`](Self::findings) keep the UTF-8 byte offsets of the
/// **original** input ([`crate::RANGE_UNIT`]), not offsets into
/// [`text`](Self::text): redaction changes lengths, so a range read against
/// the sanitized text would select the wrong span. A caller that needs both
/// must keep the original input alongside the result.
///
/// # Examples
///
/// ```
/// use redact_secret::{DefaultPolicy, DetectorRegistry, default_placeholder_formatter, scan_and_redact};
///
/// let registry = DetectorRegistry::with_built_in([])?;
/// let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
/// let result = scan_and_redact(input, &registry, &DefaultPolicy, &default_placeholder_formatter)?;
///
/// let finding = &result.findings()[0];
/// // The range indexes the original input, never `result.text()`.
/// assert_eq!(&input[finding.range().start()..finding.range().end()], "ghp_SYNTHETICREVOKED00000000000000000000");
/// assert_eq!(result.text(), "API_KEY=<SECRET_1>");
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanResult {
    text: String,
    findings: Vec<Finding>,
}

impl ScanResult {
    /// Creates a result from its parts.
    #[must_use]
    pub(crate) const fn new(text: String, findings: Vec<Finding>) -> Self {
        Self { text, findings }
    }

    /// The sanitized text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The findings, ordered by their offset in the original input.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Consumes the result, returning its parts.
    #[must_use]
    pub fn into_parts(self) -> (String, Vec<Finding>) {
        (self.text, self.findings)
    }
}

/// Position information a whole-input policy receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyContext {
    finding_index: usize,
    finding_count: usize,
}

impl PolicyContext {
    /// Creates a context.
    #[must_use]
    pub const fn new(finding_index: usize, finding_count: usize) -> Self {
        Self {
            finding_index,
            finding_count,
        }
    }

    /// Zero-based position in the finalized detection list.
    #[must_use]
    pub const fn finding_index(self) -> usize {
        self.finding_index
    }

    /// Total number of finalized findings for the input.
    #[must_use]
    pub const fn finding_count(self) -> usize {
        self.finding_count
    }
}

/// Maps finalized safe metadata to an [`Action`].
///
/// A policy never sees the input or a matched value.
pub trait Policy {
    /// Chooses the action for `finding`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyFailure`] on any internal failure. The pipeline
    /// reports it as [`SecretScanErrorCode::PolicyFailure`].
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure>;
}

impl<F> Policy for F
where
    F: Fn(&DetectedFinding, &PolicyContext) -> Result<Action, PolicyFailure>,
{
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        self(finding, context)
    }
}

/// Position information a placeholder formatter receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlaceholderContext {
    placeholder_index: usize,
}

impl PlaceholderContext {
    /// Creates a context.
    #[must_use]
    pub const fn new(placeholder_index: usize) -> Self {
        Self { placeholder_index }
    }

    /// One-based position among findings that are actually replaced.
    #[must_use]
    pub const fn placeholder_index(self) -> usize {
        self.placeholder_index
    }
}

/// Produces the replacement text for a replaced finding.
///
/// Output constraints (non-empty, bounded, never reproducing a replaced
/// range) are enforced by redaction, not by the formatter.
pub trait PlaceholderFormatter {
    /// Formats the placeholder for `finding`.
    ///
    /// # Errors
    ///
    /// Returns [`FormatterFailure`] on any internal failure.
    fn format(
        &self,
        finding: &Finding,
        context: &PlaceholderContext,
    ) -> Result<String, FormatterFailure>;
}

impl<F> PlaceholderFormatter for F
where
    F: Fn(&Finding, &PlaceholderContext) -> Result<String, FormatterFailure>,
{
    fn format(
        &self,
        finding: &Finding,
        context: &PlaceholderContext,
    ) -> Result<String, FormatterFailure> {
        self(finding, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_grammar() {
        for valid in [
            "a",
            "a1",
            "aws.access-key_id",
            "x-y",
            "github_token",
            "a.b.c",
        ] {
            assert!(is_identifier(valid), "{valid}");
        }
        for invalid in [
            "", "A", "1a", "a-", "-a", "a--b", "a.-b", "a b", "a_", "a/b", "ä", "a\n",
        ] {
            assert!(!is_identifier(invalid), "{invalid:?}");
        }
        let longest = "a".repeat(MAX_IDENTIFIER_LENGTH);
        assert!(is_identifier(&longest));
        assert!(!is_identifier(&format!("{longest}a")));
    }

    #[test]
    fn enum_names_round_trip() {
        for confidence in [Confidence::High, Confidence::Medium, Confidence::Low] {
            assert_eq!(Confidence::from_name(confidence.as_str()), Some(confidence));
        }
        for specificity in [
            Specificity::PrivateKey,
            Specificity::Provider,
            Specificity::Structural,
            Specificity::Contextual,
            Specificity::Entropy,
        ] {
            assert_eq!(
                Specificity::from_name(specificity.as_str()),
                Some(specificity)
            );
        }
        for action in [Action::Redact, Action::Block, Action::Warn, Action::Allow] {
            assert_eq!(Action::from_name(action.as_str()), Some(action));
        }
        for obfuscation in [Obfuscation::None, Obfuscation::InvisibleCharacters] {
            assert_eq!(
                Obfuscation::from_name(obfuscation.as_str()),
                Some(obfuscation)
            );
        }
        assert_eq!(Confidence::from_name("HIGH"), None);
        assert_eq!(Specificity::from_name("private_key"), None);
        assert_eq!(Action::from_name(""), None);
        assert_eq!(Obfuscation::from_name("None"), None);
    }

    #[test]
    fn precedence_orderings() {
        assert!(Confidence::High > Confidence::Medium && Confidence::Medium > Confidence::Low);
        assert!(Specificity::PrivateKey > Specificity::Provider);
        assert!(Specificity::Provider > Specificity::Structural);
        assert!(Specificity::Structural > Specificity::Contextual);
        assert!(Specificity::Contextual > Specificity::Entropy);
        assert!(Action::Redact.replaces_text() && Action::Block.replaces_text());
        assert!(!Action::Warn.replaces_text() && !Action::Allow.replaces_text());
    }

    #[test]
    fn byte_range_rejects_empty_and_reversed() {
        assert_eq!(ByteRange::new(3, 3), None);
        assert_eq!(ByteRange::new(4, 3), None);
        let range = ByteRange::new(2, 5).unwrap();
        assert_eq!((range.start(), range.end(), range.len()), (2, 5, 3));
        assert!(range.overlaps(ByteRange::new(4, 9).unwrap()));
        assert!(range.overlaps(ByteRange::new(0, 3).unwrap()));
        assert!(!range.overlaps(ByteRange::new(5, 6).unwrap()));
        assert!(!range.overlaps(ByteRange::new(0, 2).unwrap()));
    }

    /// Mirrors `conformance/fixtures/unicode-conversion-corpus.json`
    /// (`decision-govern-cross-language-conformance`): an astral
    /// (supplementary-plane) character positioned before, within, and after
    /// a finding's UTF-8 byte span. Rust's native range unit is already
    /// UTF-8 bytes (`crate::RANGE_UNIT`), so there is no conversion step to
    /// assert here — the byte offsets in the canonical corpus are the exact
    /// literal `start`/`end` values every language must agree on. This
    /// proves those offsets land on Rust's own char boundaries and select
    /// the same substring the JavaScript and Python oracles select, without
    /// splitting the astral character's 4-byte encoding.
    #[test]
    fn unicode_conversion_corpus_byte_offsets_are_char_aligned() {
        let cases = [
            (
                "🔑 TOKEN_SYNTHETIC_REVOKED_VALUE",
                5,
                34,
                "TOKEN_SYNTHETIC_REVOKED_VALUE",
            ),
            (
                "TOKEN_🔑_SYNTHETIC_REVOKED",
                0,
                28,
                "TOKEN_🔑_SYNTHETIC_REVOKED",
            ),
            (
                "TOKEN_SYNTHETIC_REVOKED_VALUE 🔑",
                0,
                29,
                "TOKEN_SYNTHETIC_REVOKED_VALUE",
            ),
            (
                "e\u{0301} TOKEN_SYNTHETIC_REVOKED_VALUE",
                4,
                33,
                "TOKEN_SYNTHETIC_REVOKED_VALUE",
            ),
            (
                "键 TOKEN_SYNTHETIC_REVOKED_VALUE",
                4,
                33,
                "TOKEN_SYNTHETIC_REVOKED_VALUE",
            ),
            (
                "\u{201c}TOKEN_SYNTHETIC_REVOKED_VALUE\u{201d}",
                3,
                32,
                "TOKEN_SYNTHETIC_REVOKED_VALUE",
            ),
            // issue #446: `unicode-conversion-invisible-within-bmp` -- a
            // code point normalization removes before detection, inside
            // rather than adjacent to the span.
            (
                "TOKEN_\u{200B}_SYNTHETIC_REVOKED_VALUE",
                0,
                33,
                "TOKEN_\u{200B}_SYNTHETIC_REVOKED_VALUE",
            ),
            // `unicode-conversion-invisible-within-removed-run` -- a
            // three-code-point removed run (one maximal seam) inside the
            // span.
            (
                "TOKEN_\u{00AD}\u{00AD}\u{2060}_SYNTHETIC_REVOKED_VALUE",
                0,
                37,
                "TOKEN_\u{00AD}\u{00AD}\u{2060}_SYNTHETIC_REVOKED_VALUE",
            ),
            // `unicode-conversion-invisible-astral-within` -- U+E0041, both
            // removed by normalization and astral (a surrogate pair in
            // UTF-16), inside the span.
            (
                "TOKEN_\u{E0041}_SYNTHETIC_REVOKED",
                0,
                28,
                "TOKEN_\u{E0041}_SYNTHETIC_REVOKED",
            ),
        ];
        for (input, start, end, expected_slice) in cases {
            let range = ByteRange::new(start, end).unwrap();
            assert!(range.is_char_aligned_in(input), "{input:?}");
            assert_eq!(&input[start..end], expected_slice, "{input:?}");
        }
    }

    #[test]
    fn byte_range_char_alignment() {
        let input = "a😀b";
        assert!(ByteRange::new(1, 5).unwrap().is_char_aligned_in(input));
        assert!(!ByteRange::new(2, 5).unwrap().is_char_aligned_in(input));
        assert!(!ByteRange::new(1, 3).unwrap().is_char_aligned_in(input));
        assert!(!ByteRange::new(5, 7).unwrap().is_char_aligned_in(input));
        assert!(ByteRange::new(5, 6).unwrap().is_char_aligned_in(input));
    }

    #[test]
    fn candidate_defaults_to_entropy_specificity() {
        let range = ByteRange::new(0, 4).unwrap();
        let candidate = Candidate::new("token", Confidence::Low, range);
        assert_eq!(candidate.specificity(), None);
        assert_eq!(candidate.effective_specificity(), Specificity::Entropy);
        assert!(candidate.signals().is_empty());
        assert_eq!(candidate.obfuscation(), Obfuscation::None);
        let candidate = candidate
            .with_specificity(Specificity::Provider)
            .with_signals(["prefix"])
            .with_obfuscation(Obfuscation::InvisibleCharacters);
        assert_eq!(candidate.effective_specificity(), Specificity::Provider);
        assert_eq!(candidate.signals(), ["prefix"]);
        assert_eq!(candidate.type_name(), "token");
        assert_eq!(candidate.range(), range);
        assert_eq!(candidate.obfuscation(), Obfuscation::InvisibleCharacters);
    }

    fn signal_candidate() -> Candidate {
        Candidate::new("token", Confidence::Low, ByteRange::new(0, 4).unwrap())
    }

    #[test]
    fn a_signal_pack_equals_with_signals_for_the_same_labels() {
        use std::hash::{BuildHasher, BuildHasherDefault, DefaultHasher};

        let packed = signal_candidate().with_signal_pack(signal_pack!("alpha-label", "beta-label"));
        let owned = signal_candidate().with_signals(["alpha-label", "beta-label"]);
        assert_eq!(packed.signals(), ["alpha-label", "beta-label"]);
        assert_eq!(packed.signals(), owned.signals());
        assert_eq!(packed, owned);
        let hasher = BuildHasherDefault::<DefaultHasher>::default();
        assert_eq!(hasher.hash_one(&packed), hasher.hash_one(&owned));
        assert_eq!(format!("{packed:?}"), format!("{owned:?}"));
        // The public slice type is unchanged.
        let _: &[String] = packed.signals();
    }

    #[test]
    fn candidates_from_one_pack_share_a_single_slice_and_clone_keeps_it() {
        fn built() -> Candidate {
            signal_candidate().with_signal_pack(signal_pack!("shared-one", "shared-two"))
        }
        // Two separate constructions through the same expansion site return
        // the very same static slice: no per-candidate signal strings.
        let first = built();
        let second = built();
        assert!(std::ptr::eq(first.signals(), second.signals()));
        assert!(std::ptr::eq(first.signals(), first.clone().signals()));
        // A different pack is a different slice; custom signals stay owned.
        let other = signal_candidate().with_signal_pack(signal_pack!("shared-one", "shared-two"));
        assert!(!std::ptr::eq(first.signals(), other.signals()));
        let owned = signal_candidate().with_signals(["shared-one", "shared-two"]);
        assert!(!std::ptr::eq(first.signals(), owned.signals()));
        assert!(!std::ptr::eq(owned.signals(), owned.clone().signals()));
        assert_eq!(owned.clone().signals(), first.signals());
    }

    #[test]
    fn with_signals_and_with_signal_pack_each_replace_the_previous_list() {
        let packed_then_owned = signal_candidate()
            .with_signal_pack(signal_pack!("first-pack"))
            .with_signals(["custom"]);
        assert_eq!(packed_then_owned.signals(), ["custom"]);
        let owned_then_packed = signal_candidate()
            .with_signals(["custom"])
            .with_signal_pack(signal_pack!("second-pack"));
        assert_eq!(owned_then_packed.signals(), ["second-pack"]);
        let dynamic = signal_candidate().with_signals([format!("dyn-{}", 7)]);
        assert_eq!(dynamic.signals(), ["dyn-7"]);
    }

    #[test]
    fn finding_constructors_validate_identifiers() {
        let range = ByteRange::new(0, 1).unwrap();
        let finding = Finding::new(
            "finding-1",
            "jwt",
            "jwt",
            Confidence::High,
            Action::Redact,
            range,
        )
        .unwrap();
        assert_eq!(finding.id(), "finding-1");
        assert_eq!(finding.detected().detector(), "jwt");
        assert_eq!(finding.action(), Action::Redact);
        assert_eq!(finding.obfuscation(), Obfuscation::None);
        assert_eq!(finding.detected().obfuscation(), Obfuscation::None);

        let obfuscated = DetectedFinding::new("finding-2", "jwt", "jwt", Confidence::High, range)
            .unwrap()
            .with_obfuscation(Obfuscation::InvisibleCharacters)
            .with_action(Action::Redact);
        assert_eq!(obfuscated.obfuscation(), Obfuscation::InvisibleCharacters);
        for (id, type_name, detector) in [
            ("Finding-1", "jwt", "jwt"),
            ("finding-1", "JWT", "jwt"),
            ("finding-1", "jwt", "jwt "),
        ] {
            let error = Finding::new(
                id,
                type_name,
                detector,
                Confidence::High,
                Action::Redact,
                range,
            )
            .unwrap_err();
            assert_eq!(error.code(), SecretScanErrorCode::InvalidCandidate);
        }
    }

    #[test]
    fn closures_implement_policy_and_formatter() {
        let policy = |_: &DetectedFinding, context: &PolicyContext| {
            if context.finding_index() < context.finding_count() {
                Ok(Action::Warn)
            } else {
                Err(PolicyFailure)
            }
        };
        let finding = DetectedFinding::new(
            "finding-1",
            "t",
            "d",
            Confidence::Low,
            ByteRange::new(0, 1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            policy.evaluate(&finding, &PolicyContext::new(0, 1)),
            Ok(Action::Warn)
        );
        assert_eq!(
            policy.evaluate(&finding, &PolicyContext::new(1, 1)),
            Err(PolicyFailure)
        );

        let formatter = |_: &Finding, context: &PlaceholderContext| {
            Ok(format!("<SECRET_{}>", context.placeholder_index()))
        };
        let finding = finding.with_action(Action::Redact);
        assert_eq!(
            formatter
                .format(&finding, &PlaceholderContext::new(3))
                .as_deref(),
            Ok("<SECRET_3>")
        );
    }
}
