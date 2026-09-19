//! `CPython` binding for the `redact-secret` core built with `PyO3` and maturin
//! (`decision-define-runtime-bindings`).
//!
//! Exposes an idiomatic synchronous `redact_secret` module: immutable finding
//! and result types, sanitized exceptions, `scan`, `redact`,
//! `scan_and_redact`, the default policy and formatter helpers, and the
//! bounded incremental session in the private `incremental` module. Every
//! built-in detector
//! runs; there is no custom detector callback surface
//! (`decision-define-runtime-bindings`). A Python `policy` or `formatter`
//! callback only ever receives safe metadata objects defined in this crate,
//! never the input or a matched value, and any callback failure (an
//! exception or an invalid return value) becomes one of the fixed exceptions
//! below rather than propagating the callback's own error.
//!
//! Ranges exposed here use Unicode code points; conversion from the core's
//! UTF-8 byte offsets happens in this crate without changing the selected
//! span (`decision-govern-cross-language-conformance`).

mod incremental;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyString;
use pyo3::{create_exception, wrap_pyfunction};

use redact_secret::{
    Action, ByteRange, Confidence, DefaultPolicy, DetectedFinding, DetectorRegistry,
    Finding as CoreFinding, PlaceholderContext, PlaceholderFormatter, Policy, PolicyContext,
    SecretScanError as CoreError, SecretScanErrorCode, WholeInputLimits,
    default_placeholder_formatter as core_default_formatter, redact_with_limits as core_redact,
    run_detector_pipeline, typed_placeholder_formatter as core_typed_formatter,
};

/// The Unicode string-index unit every range this module reports uses.
const RANGE_UNIT: &str = "unicode-code-points";

// ---------------------------------------------------------------------
// Sanitized exceptions
//
// One exception per `SecretScanErrorCode` (`decision-govern-cross-language-
// conformance`), each carrying a fixed, input-free message and a `code`
// class attribute equal to the core's wire code string. No exception raised
// by this module ever carries the scanned input or a matched value.
// ---------------------------------------------------------------------

create_exception!(
    redact_secret._native,
    SecretScanError,
    pyo3::exceptions::PyException,
    "Base class for every sanitized redact-secret error.\n\nEach subclass carries a fixed, input-free `code` class attribute matching\nthe core's `SecretScanErrorCode` wire name."
);
create_exception!(
    redact_secret._native,
    InvalidInputError,
    SecretScanError,
    "`text` was not a Python string."
);
create_exception!(
    redact_secret._native,
    InvalidOptionsError,
    SecretScanError,
    "Scan options could not be interpreted."
);
create_exception!(
    redact_secret._native,
    InvalidDetectorError,
    SecretScanError,
    "A detector registration was rejected."
);
create_exception!(
    redact_secret._native,
    DetectorFailureError,
    SecretScanError,
    "A built-in detector failed while scanning."
);
create_exception!(
    redact_secret._native,
    InvalidCandidateError,
    SecretScanError,
    "A detector returned a candidate that violates the candidate contract."
);
create_exception!(
    redact_secret._native,
    PolicyFailureError,
    SecretScanError,
    "The policy callback raised an exception."
);
create_exception!(
    redact_secret._native,
    InvalidPolicyActionError,
    SecretScanError,
    "The policy callback returned something other than \"redact\", \"block\", \"warn\", or \"allow\"."
);
create_exception!(
    redact_secret._native,
    InvalidFindingsError,
    SecretScanError,
    "The findings passed to `redact` are out of range, misordered, or overlap."
);
create_exception!(
    redact_secret._native,
    PlaceholderFailureError,
    SecretScanError,
    "The placeholder formatter callback raised an exception or returned a non-string value."
);
create_exception!(
    redact_secret._native,
    InvalidPlaceholderError,
    SecretScanError,
    "The placeholder formatter returned an empty, oversized, or matched-value-reproducing placeholder."
);
// `InvalidLimitsError`, `InputLimitExceededError`, and
// `FindingLimitExceededError` are shared between an incremental session's
// `IncrementalLimits` and this module's synchronous `scan`/`redact`/
// `scan_and_redact` `WholeInputLimits`
// (`decision-bound-whole-input-operations-by-default`).
// `BufferLimitExceededError`, `TokenLimitExceededError`,
// `MultilineLimitExceededError`, and `InvalidStateError` remain
// incremental-only: only a session created by
// `incremental::PyIncrementalSanitizer` can trigger them
// (`decision-define-runtime-bindings`).
create_exception!(
    redact_secret._native,
    InvalidLimitsError,
    SecretScanError,
    "An incremental session's or whole-input operation's limits were missing, non-positive, or did not satisfy the documented relationship between them."
);
create_exception!(
    redact_secret._native,
    InputLimitExceededError,
    SecretScanError,
    "An incremental session's total accepted input, or a whole-input scan/redact/scan_and_redact call's input, would exceed its input limit."
);
create_exception!(
    redact_secret._native,
    BufferLimitExceededError,
    SecretScanError,
    "An incremental session's retained, unresolved plaintext would exceed its buffer limit."
);
create_exception!(
    redact_secret._native,
    TokenLimitExceededError,
    SecretScanError,
    "An incremental session's open single-line construct would exceed its token limit without closing."
);
create_exception!(
    redact_secret._native,
    MultilineLimitExceededError,
    SecretScanError,
    "An incremental session's open PEM-style private-key block would exceed its multiline limit without closing."
);
create_exception!(
    redact_secret._native,
    FindingLimitExceededError,
    SecretScanError,
    "A whole-input scan's accepted finding count would exceed its finding-count limit."
);
create_exception!(
    redact_secret._native,
    InvalidStateError,
    SecretScanError,
    "An incremental session received an operation after it left the accepting state."
);

/// Maps a fixed core error code to its exception type and fixed message.
pub(crate) fn map_error_code(code: SecretScanErrorCode) -> PyErr {
    let message = code.message();
    match code {
        SecretScanErrorCode::InvalidInput => PyErr::new::<InvalidInputError, _>(message),
        SecretScanErrorCode::InvalidOptions => PyErr::new::<InvalidOptionsError, _>(message),
        SecretScanErrorCode::InvalidDetector => PyErr::new::<InvalidDetectorError, _>(message),
        SecretScanErrorCode::DetectorFailure => PyErr::new::<DetectorFailureError, _>(message),
        SecretScanErrorCode::InvalidCandidate => PyErr::new::<InvalidCandidateError, _>(message),
        SecretScanErrorCode::PolicyFailure => PyErr::new::<PolicyFailureError, _>(message),
        SecretScanErrorCode::InvalidPolicyAction => {
            PyErr::new::<InvalidPolicyActionError, _>(message)
        }
        SecretScanErrorCode::InvalidFindings => PyErr::new::<InvalidFindingsError, _>(message),
        SecretScanErrorCode::PlaceholderFailure => {
            PyErr::new::<PlaceholderFailureError, _>(message)
        }
        SecretScanErrorCode::InvalidPlaceholder => {
            PyErr::new::<InvalidPlaceholderError, _>(message)
        }
        SecretScanErrorCode::InvalidLimits => PyErr::new::<InvalidLimitsError, _>(message),
        SecretScanErrorCode::InputLimitExceeded => {
            PyErr::new::<InputLimitExceededError, _>(message)
        }
        SecretScanErrorCode::BufferLimitExceeded => {
            PyErr::new::<BufferLimitExceededError, _>(message)
        }
        SecretScanErrorCode::TokenLimitExceeded => {
            PyErr::new::<TokenLimitExceededError, _>(message)
        }
        SecretScanErrorCode::MultilineLimitExceeded => {
            PyErr::new::<MultilineLimitExceededError, _>(message)
        }
        SecretScanErrorCode::FindingLimitExceeded => {
            PyErr::new::<FindingLimitExceededError, _>(message)
        }
        SecretScanErrorCode::InvalidState => PyErr::new::<InvalidStateError, _>(message),
    }
}

/// Maps a core error to its sanitized Python exception.
pub(crate) fn map_core_error(error: CoreError) -> PyErr {
    map_error_code(error.code())
}

/// Registers every exception type and sets its fixed `code` class attribute.
fn register_exceptions(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();

    macro_rules! register {
        ($name:literal, $ty:ty, $code:expr) => {
            module.add($name, py.get_type::<$ty>())?;
            py.get_type::<$ty>().setattr("code", $code.as_str())?;
        };
    }

    module.add("SecretScanError", py.get_type::<SecretScanError>())?;
    register!(
        "InvalidInputError",
        InvalidInputError,
        SecretScanErrorCode::InvalidInput
    );
    register!(
        "InvalidOptionsError",
        InvalidOptionsError,
        SecretScanErrorCode::InvalidOptions
    );
    register!(
        "InvalidDetectorError",
        InvalidDetectorError,
        SecretScanErrorCode::InvalidDetector
    );
    register!(
        "DetectorFailureError",
        DetectorFailureError,
        SecretScanErrorCode::DetectorFailure
    );
    register!(
        "InvalidCandidateError",
        InvalidCandidateError,
        SecretScanErrorCode::InvalidCandidate
    );
    register!(
        "PolicyFailureError",
        PolicyFailureError,
        SecretScanErrorCode::PolicyFailure
    );
    register!(
        "InvalidPolicyActionError",
        InvalidPolicyActionError,
        SecretScanErrorCode::InvalidPolicyAction
    );
    register!(
        "InvalidFindingsError",
        InvalidFindingsError,
        SecretScanErrorCode::InvalidFindings
    );
    register!(
        "PlaceholderFailureError",
        PlaceholderFailureError,
        SecretScanErrorCode::PlaceholderFailure
    );
    register!(
        "InvalidPlaceholderError",
        InvalidPlaceholderError,
        SecretScanErrorCode::InvalidPlaceholder
    );
    register!(
        "InvalidLimitsError",
        InvalidLimitsError,
        SecretScanErrorCode::InvalidLimits
    );
    register!(
        "InputLimitExceededError",
        InputLimitExceededError,
        SecretScanErrorCode::InputLimitExceeded
    );
    register!(
        "BufferLimitExceededError",
        BufferLimitExceededError,
        SecretScanErrorCode::BufferLimitExceeded
    );
    register!(
        "TokenLimitExceededError",
        TokenLimitExceededError,
        SecretScanErrorCode::TokenLimitExceeded
    );
    register!(
        "MultilineLimitExceededError",
        MultilineLimitExceededError,
        SecretScanErrorCode::MultilineLimitExceeded
    );
    register!(
        "FindingLimitExceededError",
        FindingLimitExceededError,
        SecretScanErrorCode::FindingLimitExceeded
    );
    register!(
        "InvalidStateError",
        InvalidStateError,
        SecretScanErrorCode::InvalidState
    );

    Ok(())
}

// ---------------------------------------------------------------------
// Range conversion
// ---------------------------------------------------------------------

/// Converts a UTF-8 byte offset into `text` to a Unicode code point offset,
/// or `None` when it is out of bounds or splits a character.
fn char_offset(text: &str, byte_offset: usize) -> Option<usize> {
    if byte_offset > text.len() || !text.is_char_boundary(byte_offset) {
        return None;
    }
    Some(text[..byte_offset].chars().count())
}

/// Converts a validated finding range to code point `(start, end)`.
///
/// The pipeline only ever produces char-aligned, in-bounds ranges, so
/// failure here would indicate an internal inconsistency; it is still
/// reported as a sanitized error rather than panicking.
fn char_range(text: &str, range: ByteRange) -> PyResult<(usize, usize)> {
    let start = char_offset(text, range.start())
        .ok_or_else(|| map_error_code(SecretScanErrorCode::InvalidCandidate))?;
    let end = char_offset(text, range.end())
        .ok_or_else(|| map_error_code(SecretScanErrorCode::InvalidCandidate))?;
    Ok((start, end))
}

/// Converts a UTF-8 byte offset into `text` (the core's native range unit,
/// [`redact_secret::RANGE_UNIT`]) to the Unicode code point offset Python's
/// `str` indexing sees at the same logical position
/// (`decision-govern-cross-language-conformance`). Every code point counts
/// as one unit regardless of plane, so an astral (supplementary-plane)
/// character advances this offset by exactly 1, unlike JavaScript's UTF-16
/// code units (2 for the same character) or the core's own UTF-8 bytes (4).
///
/// # Errors
///
/// Returns a `ValueError` when `byte_offset` is out of bounds or falls
/// inside a multi-byte character's encoding rather than on its boundary.
#[pyfunction]
fn byte_offset_to_char_offset(text: &str, byte_offset: usize) -> PyResult<usize> {
    char_offset(text, byte_offset)
        .ok_or_else(|| PyValueError::new_err("byte_offset is out of bounds or splits a character."))
}

/// Extracts owned `text` from an argument that must be a Python string.
///
/// Rejects a non-string argument with the sanitized `InvalidInputError`
/// instead of a generic `TypeError`, matching the cross-language contract:
/// `SecretScanErrorCode::InvalidInput` is "produced by bindings" for this
/// exact case.
pub(crate) fn extract_text(value: &Bound<'_, PyAny>) -> PyResult<String> {
    let text = value
        .cast::<PyString>()
        .map_err(|_| map_error_code(SecretScanErrorCode::InvalidInput))?;
    text.to_str()
        .map(str::to_owned)
        .map_err(|_| map_error_code(SecretScanErrorCode::InvalidInput))
}

// ---------------------------------------------------------------------
// Safe metadata types
// ---------------------------------------------------------------------

/// Pre-policy, immutable finding metadata: safe to pass to a policy
/// callback. Carries no matched value, only the finding's identifier, type,
/// detector, confidence, and Unicode code point span (`RANGE_UNIT`).
///
/// Never constructed from Python; only produced by `scan` and
/// `scan_and_redact` for their policy callback.
#[pyclass(module = "redact_secret._native", name = "DetectedFinding")]
pub(crate) struct PyDetectedFinding {
    /// Deterministic finding id (`finding-1`, `finding-2`, ...).
    #[pyo3(get)]
    id: String,
    /// Finding type.
    #[pyo3(get, name = "type")]
    type_name: String,
    /// Id of the detector that produced the finding.
    #[pyo3(get)]
    detector: String,
    /// `"high"`, `"medium"`, or `"low"`.
    #[pyo3(get)]
    confidence: String,
    /// Inclusive start offset, in Unicode code points.
    #[pyo3(get)]
    start: usize,
    /// Exclusive end offset, in Unicode code points.
    #[pyo3(get)]
    end: usize,
    confidence_value: Confidence,
    byte_range: ByteRange,
}

impl PyDetectedFinding {
    pub(crate) fn from_core(finding: &DetectedFinding, start: usize, end: usize) -> Self {
        Self {
            id: finding.id().to_owned(),
            type_name: finding.type_name().to_owned(),
            detector: finding.detector().to_owned(),
            confidence: finding.confidence().as_str().to_owned(),
            start,
            end,
            confidence_value: finding.confidence(),
            byte_range: finding.range(),
        }
    }

    /// Reconstructs the core finding this metadata was derived from.
    pub(crate) fn to_core(&self) -> PyResult<DetectedFinding> {
        DetectedFinding::new(
            self.id.clone(),
            self.type_name.clone(),
            self.detector.clone(),
            self.confidence_value,
            self.byte_range,
        )
        .map_err(map_core_error)
    }
}

#[pymethods]
impl PyDetectedFinding {
    fn __repr__(&self) -> String {
        format!(
            "DetectedFinding(id={:?}, type={:?}, detector={:?}, confidence={:?}, start={}, end={})",
            self.id, self.type_name, self.detector, self.confidence, self.start, self.end
        )
    }
}

/// Position of a finding within the finalized detection list, given to a
/// policy callback alongside a [`PyDetectedFinding`].
///
/// Never constructed from Python; only produced by `scan` and
/// `scan_and_redact` for their policy callback.
#[pyclass(module = "redact_secret._native", name = "PolicyContext")]
struct PyPolicyContext {
    /// Zero-based position in the finalized detection list.
    #[pyo3(get)]
    finding_index: usize,
    /// Total number of finalized findings for the input.
    #[pyo3(get)]
    finding_count: usize,
}

#[pymethods]
impl PyPolicyContext {
    fn __repr__(&self) -> String {
        format!(
            "PolicyContext(finding_index={}, finding_count={})",
            self.finding_index, self.finding_count
        )
    }
}

/// Immutable, policy-evaluated finding: safe metadata plus the assigned
/// action. Returned by `scan` and `scan_and_redact`, and passed to a
/// formatter callback.
///
/// Never constructed from Python; only produced by `scan` and
/// `scan_and_redact`.
#[pyclass(
    module = "redact_secret._native",
    name = "Finding",
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyFinding {
    /// Deterministic finding id (`finding-1`, `finding-2`, ...).
    #[pyo3(get)]
    id: String,
    /// Finding type.
    #[pyo3(get, name = "type")]
    type_name: String,
    /// Id of the detector that produced the finding.
    #[pyo3(get)]
    detector: String,
    /// `"high"`, `"medium"`, or `"low"`.
    #[pyo3(get)]
    confidence: String,
    /// `"redact"`, `"block"`, `"warn"`, or `"allow"`.
    #[pyo3(get)]
    action: String,
    /// Inclusive start offset, in Unicode code points.
    #[pyo3(get)]
    start: usize,
    /// Exclusive end offset, in Unicode code points.
    #[pyo3(get)]
    end: usize,
    inner: CoreFinding,
}

impl PyFinding {
    pub(crate) fn from_core(finding: CoreFinding, start: usize, end: usize) -> Self {
        Self {
            id: finding.id().to_owned(),
            type_name: finding.type_name().to_owned(),
            detector: finding.detector().to_owned(),
            confidence: finding.confidence().as_str().to_owned(),
            action: finding.action().as_str().to_owned(),
            start,
            end,
            inner: finding,
        }
    }
}

#[pymethods]
impl PyFinding {
    fn __repr__(&self) -> String {
        format!(
            "Finding(id={:?}, type={:?}, detector={:?}, confidence={:?}, action={:?}, start={}, end={})",
            self.id,
            self.type_name,
            self.detector,
            self.confidence,
            self.action,
            self.start,
            self.end
        )
    }
}

/// Position of a replaced finding among findings a formatter actually
/// replaces, given to a formatter callback alongside a [`PyFinding`].
///
/// Never constructed from Python; only produced by `redact` and
/// `scan_and_redact` for their formatter callback.
#[pyclass(module = "redact_secret._native", name = "PlaceholderContext")]
pub(crate) struct PyPlaceholderContext {
    /// One-based position among findings that are actually replaced.
    #[pyo3(get)]
    pub(crate) placeholder_index: usize,
}

#[pymethods]
impl PyPlaceholderContext {
    fn __repr__(&self) -> String {
        format!(
            "PlaceholderContext(placeholder_index={})",
            self.placeholder_index
        )
    }
}

/// The result of `scan_and_redact`: the redacted text and the findings used
/// to produce it, in one immutable object.
///
/// Never constructed from Python; only produced by `scan_and_redact`.
#[pyclass(module = "redact_secret._native", name = "ScanResult")]
struct PyScanResult {
    /// `text` with every `redact`/`block` finding replaced by a placeholder.
    #[pyo3(get)]
    text: String,
    /// The findings `text` was scanned into, in input order.
    #[pyo3(get)]
    findings: Vec<PyFinding>,
}

#[pymethods]
impl PyScanResult {
    fn __repr__(&self) -> String {
        format!(
            "ScanResult(text={:?}, findings=<{} finding(s)>)",
            self.text,
            self.findings.len()
        )
    }
}

/// Explicit byte and finding-count bounds for `scan`, `redact`, and
/// `scan_and_redact`. Omit (pass `None`, the default) to use the core's
/// default whole-input bound
/// (`decision-bound-whole-input-operations-by-default`).
#[pyclass(
    module = "redact_secret._native",
    name = "WholeInputLimits",
    frozen,
    skip_from_py_object
)]
#[derive(Clone, Copy)]
pub(crate) struct PyWholeInputLimits {
    inner: WholeInputLimits,
}

#[pymethods]
impl PyWholeInputLimits {
    /// Validates and creates a limit set.
    ///
    /// # Errors
    ///
    /// Raises `InvalidLimitsError` when either bound is zero.
    #[new]
    #[pyo3(signature = (*, max_input_bytes, max_findings))]
    fn new(max_input_bytes: usize, max_findings: usize) -> PyResult<Self> {
        let inner = WholeInputLimits::new(max_input_bytes, max_findings).map_err(map_core_error)?;
        Ok(Self { inner })
    }

    /// The largest whole-input byte length accepted.
    #[getter]
    const fn max_input_bytes(&self) -> usize {
        self.inner.max_input_bytes()
    }

    /// The largest accepted finding count.
    #[getter]
    const fn max_findings(&self) -> usize {
        self.inner.max_findings()
    }

    fn __repr__(&self) -> String {
        format!(
            "WholeInputLimits(max_input_bytes={}, max_findings={})",
            self.inner.max_input_bytes(),
            self.inner.max_findings(),
        )
    }
}

impl PyWholeInputLimits {
    /// Resolves an optional `PyWholeInputLimits` to a core
    /// [`WholeInputLimits`], using the core's default when `limits` is
    /// `None`.
    fn resolve(limits: Option<&Self>) -> WholeInputLimits {
        limits.map_or_else(WholeInputLimits::default, |limits| limits.inner)
    }
}

// ---------------------------------------------------------------------
// Detection and policy
// ---------------------------------------------------------------------

/// Builds a registry of every built-in detector. There is no custom
/// detector callback surface (`decision-define-runtime-bindings`).
fn registry() -> PyResult<DetectorRegistry> {
    DetectorRegistry::with_built_in([]).map_err(map_core_error)
}

/// Runs every built-in detector over `text` and resolves overlaps.
///
/// Checks `limits` explicitly: this function calls `run_detector_pipeline`
/// directly rather than a core function that already applies a limit set, so
/// it does not inherit the default whole-input bound for free
/// (`decision-bound-whole-input-operations-by-default`).
fn detect(text: &str, limits: &WholeInputLimits) -> PyResult<Vec<DetectedFinding>> {
    limits.check_input(text).map_err(map_core_error)?;
    let registry = registry()?;
    let detected = run_detector_pipeline(text, &registry).map_err(map_core_error)?;
    limits
        .check_findings(detected.len())
        .map_err(map_core_error)?;
    Ok(detected)
}

/// Evaluates the default policy for one finding. Infallible in practice;
/// any failure is still reported as `PolicyFailureError` rather than
/// panicking.
fn default_action(finding: &DetectedFinding, index: usize, count: usize) -> PyResult<Action> {
    let context = PolicyContext::new(index, count);
    DefaultPolicy
        .evaluate(finding, &context)
        .map_err(|_| map_error_code(SecretScanErrorCode::PolicyFailure))
}

/// Calls a Python policy callback for one finding.
///
/// An exception raised by `callable` becomes `PolicyFailureError`; a
/// non-string return value or one that is not `"redact"`, `"block"`,
/// `"warn"`, or `"allow"` becomes `InvalidPolicyActionError`. Either way the
/// callback's own exception or return value is discarded rather than
/// propagated, so a callback cannot leak arbitrary content through its
/// failure.
fn call_python_policy(
    callable: &Bound<'_, PyAny>,
    text: &str,
    finding: &DetectedFinding,
    index: usize,
    count: usize,
) -> PyResult<Action> {
    let py = callable.py();
    let (start, end) = char_range(text, finding.range())?;
    let py_finding = Bound::new(py, PyDetectedFinding::from_core(finding, start, end))?;
    let py_context = Bound::new(
        py,
        PyPolicyContext {
            finding_index: index,
            finding_count: count,
        },
    )?;

    let value = callable
        .call1((py_finding, py_context))
        .map_err(|_| map_error_code(SecretScanErrorCode::PolicyFailure))?;

    let action_name = value
        .extract::<String>()
        .map_err(|_| map_error_code(SecretScanErrorCode::InvalidPolicyAction))?;
    Action::from_name(&action_name)
        .ok_or_else(|| map_error_code(SecretScanErrorCode::InvalidPolicyAction))
}

/// Evaluates `policy` (or the default policy when `None`) once per finding.
fn apply_policy(
    text: &str,
    detected: Vec<DetectedFinding>,
    policy: Option<&Bound<'_, PyAny>>,
) -> PyResult<Vec<CoreFinding>> {
    let count = detected.len();
    let mut findings = Vec::with_capacity(count);
    for (index, finding) in detected.into_iter().enumerate() {
        let action = match policy {
            None => default_action(&finding, index, count)?,
            Some(callable) => call_python_policy(callable, text, &finding, index, count)?,
        };
        findings.push(finding.with_action(action));
    }
    Ok(findings)
}

/// Converts core findings to their Python-visible, code point-ranged form.
fn findings_to_py(text: &str, findings: Vec<CoreFinding>) -> PyResult<Vec<PyFinding>> {
    findings
        .into_iter()
        .map(|finding| {
            let (start, end) = char_range(text, finding.range())?;
            Ok(PyFinding::from_core(finding, start, end))
        })
        .collect()
}

// ---------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------

/// Adapts a Python formatter callback to [`PlaceholderFormatter`].
///
/// A raised exception or a non-string return value becomes an opaque
/// `FormatterFailure`, which `redact_secret::redact` reports as
/// `PlaceholderFailureError`; the callback's own error is discarded.
struct PyFormatterAdapter<'py, 'a> {
    callable: &'a Bound<'py, PyAny>,
    text: &'a str,
}

impl PlaceholderFormatter for PyFormatterAdapter<'_, '_> {
    fn format(
        &self,
        finding: &CoreFinding,
        context: &PlaceholderContext,
    ) -> Result<String, redact_secret::FormatterFailure> {
        let (start, end) =
            char_range(self.text, finding.range()).map_err(|_| redact_secret::FormatterFailure)?;
        let py_finding = Bound::new(
            self.callable.py(),
            PyFinding::from_core(finding.clone(), start, end),
        )
        .map_err(|_| redact_secret::FormatterFailure)?;
        let py_context = Bound::new(
            self.callable.py(),
            PyPlaceholderContext {
                placeholder_index: context.placeholder_index(),
            },
        )
        .map_err(|_| redact_secret::FormatterFailure)?;

        let value = self
            .callable
            .call1((py_finding, py_context))
            .map_err(|_| redact_secret::FormatterFailure)?;
        value
            .extract::<String>()
            .map_err(|_| redact_secret::FormatterFailure)
    }
}

/// Runs `redact_secret::redact_with_limits` with `formatter` (or the default
/// formatter when `None`) against `limits`.
fn redact_core(
    text: &str,
    findings: &[CoreFinding],
    formatter: Option<&Bound<'_, PyAny>>,
    limits: &WholeInputLimits,
) -> PyResult<String> {
    match formatter {
        None => {
            core_redact(text, findings, &core_default_formatter, limits).map_err(map_core_error)
        }
        Some(callable) => {
            let adapter = PyFormatterAdapter { callable, text };
            core_redact(text, findings, &adapter, limits).map_err(map_core_error)
        }
    }
}

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

/// Scans `text` for secrets and evaluates a policy once per finding.
///
/// Runs every built-in detector; there is no custom detector callback
/// surface. Identical `text` always produces identical findings.
///
/// `policy`, when given, is called once per finding as
/// `policy(finding: DetectedFinding, context: PolicyContext) -> str`,
/// returning one of `"redact"`, `"block"`, `"warn"`, or `"allow"`. It never
/// receives the input or a matched value. When omitted, the built-in
/// default policy runs (see `default_policy`).
///
/// # Errors
///
/// `limits`, when given, overrides the core's default whole-input bound
/// (`decision-bound-whole-input-operations-by-default`).
///
/// # Errors
///
/// Raises a `SecretScanError` subclass: `InvalidInputError` when `text` is
/// not a string, `InputLimitExceededError` when `text` exceeds
/// `limits.max_input_bytes` (or the default), `FindingLimitExceededError`
/// when the accepted finding count exceeds `limits.max_findings` (or the
/// default), `DetectorFailureError` or `InvalidCandidateError` for an
/// internal detector fault, or `PolicyFailureError` /
/// `InvalidPolicyActionError` for a failing or malformed `policy` callback.
#[pyfunction]
#[pyo3(signature = (text, policy=None, limits=None))]
// pyo3 argument extraction produces owned `Bound`/`Option<Bound>` values;
// there is no borrowed form to take instead.
#[allow(clippy::needless_pass_by_value)]
fn scan<'py>(
    text: Bound<'py, PyAny>,
    policy: Option<Bound<'py, PyAny>>,
    limits: Option<PyRef<'py, PyWholeInputLimits>>,
) -> PyResult<Vec<PyFinding>> {
    let text_owned = extract_text(&text)?;
    let limits = PyWholeInputLimits::resolve(limits.as_deref());
    let detected = detect(&text_owned, &limits)?;
    let findings = apply_policy(&text_owned, detected, policy.as_ref())?;
    findings_to_py(&text_owned, findings)
}

/// Replaces every `redact`/`block` finding's span in `text` with a
/// placeholder, leaving `warn`/`allow` findings unchanged.
///
/// `findings` is normally the list `scan` returned for this exact `text`.
/// `formatter`, when given, is called once per replaced finding as
/// `formatter(finding: Finding, context: PlaceholderContext) -> str`. It
/// never receives the input or a matched value. When omitted, the built-in
/// default formatter runs (see `default_placeholder_formatter`).
///
/// # Errors
///
/// `limits`, when given, overrides the core's default whole-input bound
/// (`decision-bound-whole-input-operations-by-default`).
///
/// # Errors
///
/// Raises a `SecretScanError` subclass: `InvalidInputError` when `text` is
/// not a string, `InputLimitExceededError` when `text` exceeds
/// `limits.max_input_bytes` (or the default), `FindingLimitExceededError`
/// when `len(findings)` exceeds `limits.max_findings` (or the default),
/// `InvalidFindingsError` when a finding's range falls outside `text`, is
/// misaligned, or overlaps another finding, `PlaceholderFailureError` for a
/// failing or non-string `formatter` callback, or `InvalidPlaceholderError`
/// when its return value is empty, oversized, or reproduces a matched value.
#[pyfunction]
#[pyo3(signature = (text, findings, formatter=None, limits=None))]
#[allow(clippy::needless_pass_by_value)]
fn redact<'py>(
    text: Bound<'py, PyAny>,
    findings: Vec<PyRef<'py, PyFinding>>,
    formatter: Option<Bound<'py, PyAny>>,
    limits: Option<PyRef<'py, PyWholeInputLimits>>,
) -> PyResult<String> {
    let text_owned = extract_text(&text)?;
    let limits = PyWholeInputLimits::resolve(limits.as_deref());
    let core_findings: Vec<CoreFinding> = findings
        .iter()
        .map(|finding| finding.inner.clone())
        .collect();
    redact_core(&text_owned, &core_findings, formatter.as_ref(), &limits)
}

/// Scans `text` and redacts it in one call, guaranteeing the returned
/// `ScanResult.findings` are exactly the findings used to produce
/// `ScanResult.text`.
///
/// See `scan` and `redact` for the `policy`, `formatter`, and `limits`
/// contracts and error conditions.
#[pyfunction]
#[pyo3(signature = (text, policy=None, formatter=None, limits=None))]
#[allow(clippy::needless_pass_by_value)]
fn scan_and_redact<'py>(
    text: Bound<'py, PyAny>,
    policy: Option<Bound<'py, PyAny>>,
    formatter: Option<Bound<'py, PyAny>>,
    limits: Option<PyRef<'py, PyWholeInputLimits>>,
) -> PyResult<PyScanResult> {
    let text_owned = extract_text(&text)?;
    let limits = PyWholeInputLimits::resolve(limits.as_deref());
    let detected = detect(&text_owned, &limits)?;
    let findings = apply_policy(&text_owned, detected, policy.as_ref())?;
    let redacted_text = redact_core(&text_owned, &findings, formatter.as_ref(), &limits)?;
    let py_findings = findings_to_py(&text_owned, findings)?;
    Ok(PyScanResult {
        text: redacted_text,
        findings: py_findings,
    })
}

/// The built-in default policy (`decision-define-runtime-bindings`):
/// blocks `private_key`; always redacts a fixed set of high-signal types
/// regardless of confidence; and otherwise redacts at high confidence and
/// warns otherwise. Ignores `context`.
///
/// Matches the `policy` callback protocol (`finding`, `context`) -> `str`,
/// so a custom policy can call this to fall back to default behavior for
/// findings it does not want to override.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
fn default_policy(
    finding: PyRef<'_, PyDetectedFinding>,
    context: PyRef<'_, PyPolicyContext>,
) -> PyResult<String> {
    let core_finding = finding.to_core()?;
    let core_context = PolicyContext::new(context.finding_index, context.finding_count);
    DefaultPolicy
        .evaluate(&core_finding, &core_context)
        .map(|action| action.as_str().to_owned())
        .map_err(|_| map_error_code(SecretScanErrorCode::PolicyFailure))
}

/// The built-in default placeholder formatter: `<SECRET_N>`, `N` one-based
/// among findings actually replaced. Ignores `finding`.
///
/// Matches the `formatter` callback protocol (`finding`, `context`) ->
/// `str`, so a custom formatter can call this as a fallback.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
fn default_placeholder_formatter(
    finding: PyRef<'_, PyFinding>,
    context: PyRef<'_, PyPlaceholderContext>,
) -> PyResult<String> {
    let core_context = PlaceholderContext::new(context.placeholder_index);
    core_default_formatter(&finding.inner, &core_context)
        .map_err(|_| map_error_code(SecretScanErrorCode::PlaceholderFailure))
}

/// A placeholder formatter that names the finding type: `<TYPE_NAME_N>`,
/// upper-cased with `.` and `-` mapped to `_`.
///
/// Matches the `formatter` callback protocol (`finding`, `context`) ->
/// `str`, so a custom formatter can call this as a fallback.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
fn typed_placeholder_formatter(
    finding: PyRef<'_, PyFinding>,
    context: PyRef<'_, PyPlaceholderContext>,
) -> PyResult<String> {
    let core_context = PlaceholderContext::new(context.placeholder_index);
    core_typed_formatter(&finding.inner, &core_context)
        .map_err(|_| map_error_code(SecretScanErrorCode::PlaceholderFailure))
}

/// Returns the shared product version.
#[pyfunction]
fn version() -> &'static str {
    redact_secret::VERSION
}

/// The native extension module.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("VERSION", redact_secret::VERSION)?;
    module.add("RANGE_UNIT", RANGE_UNIT)?;

    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(byte_offset_to_char_offset, module)?)?;
    module.add_function(wrap_pyfunction!(scan, module)?)?;
    module.add_function(wrap_pyfunction!(redact, module)?)?;
    module.add_function(wrap_pyfunction!(scan_and_redact, module)?)?;
    module.add_function(wrap_pyfunction!(default_policy, module)?)?;
    module.add_function(wrap_pyfunction!(default_placeholder_formatter, module)?)?;
    module.add_function(wrap_pyfunction!(typed_placeholder_formatter, module)?)?;

    module.add_class::<PyDetectedFinding>()?;
    module.add_class::<PyFinding>()?;
    module.add_class::<PyPolicyContext>()?;
    module.add_class::<PyPlaceholderContext>()?;
    module.add_class::<PyScanResult>()?;
    module.add_class::<PyWholeInputLimits>()?;

    incremental::register(module)?;
    register_exceptions(module)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::byte_offset_to_char_offset;

    /// Mirrors `conformance/fixtures/unicode-conversion-corpus.json`
    /// (`decision-govern-cross-language-conformance`): an astral
    /// (supplementary-plane) character positioned before, within, and after
    /// a finding's UTF-8 byte span, asserting the same canonical `start`/
    /// `end` byte offsets convert to the Python-native code point offsets
    /// every Python consumer of this binding actually sees.
    #[test]
    fn unicode_conversion_corpus_converts_to_code_point_offsets() {
        let cases = [
            // (input, canonical UTF-8 byte start/end, expected code point start/end)
            ("\u{1F511} TOKEN_SYNTHETIC_REVOKED_VALUE", 5, 34, 2, 31),
            ("TOKEN_\u{1F511}_SYNTHETIC_REVOKED", 0, 28, 0, 25),
            ("TOKEN_SYNTHETIC_REVOKED_VALUE \u{1F511}", 0, 29, 0, 29),
            ("e\u{0301} TOKEN_SYNTHETIC_REVOKED_VALUE", 4, 33, 3, 32),
            ("键 TOKEN_SYNTHETIC_REVOKED_VALUE", 4, 33, 2, 31),
            (
                "\u{201c}TOKEN_SYNTHETIC_REVOKED_VALUE\u{201d}",
                3,
                32,
                1,
                30,
            ),
        ];
        for (input, byte_start, byte_end, char_start, char_end) in cases {
            assert_eq!(
                byte_offset_to_char_offset(input, byte_start).unwrap(),
                char_start,
                "{input:?}"
            );
            assert_eq!(
                byte_offset_to_char_offset(input, byte_end).unwrap(),
                char_end,
                "{input:?}"
            );
        }
    }

    #[test]
    fn rejects_offsets_that_split_the_astral_characters_four_byte_encoding() {
        let input = "\u{1F511}key";
        for byte_offset in [1, 2, 3] {
            assert!(byte_offset_to_char_offset(input, byte_offset).is_err());
        }
        assert_eq!(byte_offset_to_char_offset(input, 4).unwrap(), 1);
    }

    #[test]
    fn rejects_an_out_of_bounds_offset() {
        assert!(byte_offset_to_char_offset("abc", 4).is_err());
    }
}
