//! Explain and compare action policies over one detection pass (issue #1220,
//! `decision-explain-and-compare-action-policies-over-one-detection-pass`).
//!
//! The whole-input primitive only: [`compare_action_policies`] detects once
//! and evaluates 1 to 4 policies on the same finalized findings through the
//! core's `compare_action_policies_with_limits`; this module reimplements no
//! evaluation. There is no incremental, session or stream comparison, and no
//! name here could be mistaken for one.
//!
//! The result is an observation: it carries no input byte, matched value,
//! snippet, hash of either, or score, and its `mode` is always `"preview"`
//! and its `enforced` always `False`. A policy document's SHA-256 is the only
//! digest it holds.

use std::cell::RefCell;

use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};
use pyo3::wrap_pyfunction;

use redact_secret::{
    ActionComparison, ActionDecision, ActionPolicy, ComparedPolicy as CorePolicy, DetectedFinding,
    MAX_COMPARED_POLICIES, Policy, PolicyContext, PolicyFailure, SecretScanErrorCode,
    compare_action_policies_with_limits,
};

use super::{
    CharOffsets, PyWholeInputLimits, RegistryError, call_python_policy, extract_ruleset_bytes,
    extract_text, load_action_policy_argument, map_core_error, map_error_code, with_registry,
    with_registry_released,
};

// ---------------------------------------------------------------------
// The policy a side compares
// ---------------------------------------------------------------------

/// What one side of a comparison evaluates.
enum Side {
    /// The running artifact's default evaluation.
    Default,
    /// A document, loaded and validated when the side was built.
    ActionPolicy(ActionPolicy),
    /// A legacy `policy` callback.
    Callback(Py<PyAny>),
}

/// One policy taking part in a comparison: the default policy, a declarative
/// action policy, or a legacy `policy` callback.
///
/// Built only with `ComparedPolicy.default()`, `ComparedPolicy.action_policy(document)`
/// and `ComparedPolicy.callback(policy)`; there is no public constructor. An
/// action policy is loaded and validated when its side is built, so a rejected
/// document raises `InvalidActionPolicyError` before any comparison runs.
#[pyclass(
    module = "redact_secret._native",
    name = "ComparedPolicy",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyComparedPolicy {
    side: Side,
}

#[pymethods]
impl PyComparedPolicy {
    /// The default policy: the running artifact's default evaluation.
    #[staticmethod]
    const fn default() -> Self {
        Self {
            side: Side::Default,
        }
    }

    /// A declarative action policy, in the input forms `action_policy=`
    /// accepts: a `dict`, or its document as `bytes`, `bytearray` or `str`.
    ///
    /// # Errors
    ///
    /// Raises `InvalidActionPolicyError` for a rejected document and
    /// `InvalidOptionsError` for a value of any other type.
    #[staticmethod]
    fn action_policy(document: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            side: Side::ActionPolicy(load_action_policy_argument(document)?),
        })
    }

    /// A legacy `policy` callback, called once per finalized finding in
    /// finding order, exactly as `scan(policy=...)` calls it.
    ///
    /// # Errors
    ///
    /// Raises `InvalidOptionsError` when `policy` is not callable.
    #[staticmethod]
    fn callback(policy: &Bound<'_, PyAny>) -> PyResult<Self> {
        if !policy.is_callable() {
            return Err(map_error_code(SecretScanErrorCode::InvalidOptions));
        }
        Ok(Self {
            side: Side::Callback(policy.clone().unbind()),
        })
    }

    /// `"default"`, `"action-policy"` or `"callback"`.
    #[getter]
    const fn kind(&self) -> &'static str {
        match self.side {
            Side::Default => "default",
            Side::ActionPolicy(_) => "action-policy",
            Side::Callback(_) => "callback",
        }
    }

    /// The lowercase SHA-256 of the exact document bytes, for an action
    /// policy; `None` for the default policy and for a callback.
    #[getter]
    fn document_sha256(&self) -> Option<String> {
        match &self.side {
            Side::ActionPolicy(policy) => Some(policy.document_sha256_hex()),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!("ComparedPolicy(kind={:?})", self.kind())
    }
}

// ---------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------

/// A Python literal for an optional, already-rendered value.
fn py_optional(value: Option<String>) -> String {
    value.unwrap_or_else(|| "None".to_owned())
}

/// The decision one policy reached for one finding, and why.
///
/// Never constructed from Python; only produced by `compare_action_policies`.
#[pyclass(
    module = "redact_secret._native",
    name = "ActionDecision",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyActionDecision {
    /// `"redact"`, `"block"`, `"warn"` or `"allow"`.
    #[pyo3(get)]
    action: &'static str,
    /// `"rule"`, `"rule-default"`, `"no-rule-matched"`, `"default-policy"` or
    /// `"callback"`.
    #[pyo3(get)]
    basis: &'static str,
    /// The matched rule's id for `"rule"` and `"rule-default"`, else `None`.
    #[pyo3(get)]
    rule_id: Option<String>,
    /// The matched rule's zero-based index for `"rule"` and `"rule-default"`,
    /// else `None`.
    #[pyo3(get)]
    rule_index: Option<usize>,
}

#[pymethods]
impl PyActionDecision {
    fn __repr__(&self) -> String {
        format!(
            "ActionDecision(action={:?}, basis={:?}, rule_id={}, rule_index={})",
            self.action,
            self.basis,
            py_optional(self.rule_id.as_deref().map(|id| format!("{id:?}"))),
            py_optional(self.rule_index.map(|index| index.to_string())),
        )
    }
}

impl PyActionDecision {
    fn from_core(decision: &ActionDecision) -> Self {
        Self {
            action: decision.action().as_str(),
            basis: decision.basis().as_str(),
            rule_id: decision.basis().rule_id().map(str::to_owned),
            rule_index: decision.basis().rule_index(),
        }
    }
}

/// One finalized finding and the decision every compared policy reached for it.
///
/// The finding fields are the safe metadata a `DetectedFinding` carries (no
/// matched value); ranges are Unicode code points. `decisions` holds one
/// `ActionDecision` per compared policy, in the order the policies were given.
///
/// Never constructed from Python; only produced by `compare_action_policies`.
#[pyclass(
    module = "redact_secret._native",
    name = "ComparedFinding",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyComparedFinding {
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
    confidence: &'static str,
    /// `"none"` or `"invisible-characters"`.
    #[pyo3(get)]
    obfuscation: &'static str,
    /// Inclusive start offset, in Unicode code points.
    #[pyo3(get)]
    start: usize,
    /// Exclusive end offset, in Unicode code points.
    #[pyo3(get)]
    end: usize,
    /// Whether the compared policies do not all choose the same action. The
    /// action only: a changed reason with the same action does not differ.
    #[pyo3(get)]
    differs: bool,
    decisions: Py<PyTuple>,
}

#[pymethods]
impl PyComparedFinding {
    /// One `ActionDecision` per compared policy, in the order given.
    #[getter]
    fn decisions(&self, py: Python<'_>) -> Py<PyTuple> {
        self.decisions.clone_ref(py)
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        format!(
            "ComparedFinding(id={:?}, type={:?}, detector={:?}, confidence={:?}, obfuscation={:?}, start={}, end={}, differs={}, decisions=<{} decision(s)>)",
            self.id,
            self.type_name,
            self.detector,
            self.confidence,
            self.obfuscation,
            self.start,
            self.end,
            if self.differs { "True" } else { "False" },
            self.decisions.bind(py).len(),
        )
    }
}

/// How many findings a policy chose each action for.
///
/// Never constructed from Python; only produced by `compare_action_policies`.
#[pyclass(
    module = "redact_secret._native",
    name = "ActionCounts",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyActionCounts {
    /// Findings the policy chose `"redact"` for.
    #[pyo3(get)]
    redact: usize,
    /// Findings the policy chose `"block"` for.
    #[pyo3(get)]
    block: usize,
    /// Findings the policy chose `"warn"` for.
    #[pyo3(get)]
    warn: usize,
    /// Findings the policy chose `"allow"` for.
    #[pyo3(get)]
    allow: usize,
}

#[pymethods]
impl PyActionCounts {
    fn __repr__(&self) -> String {
        format!(
            "ActionCounts(redact={}, block={}, warn={}, allow={})",
            self.redact, self.block, self.warn, self.allow,
        )
    }
}

/// One compared policy: its kind, its document digest if it has one, and its
/// per-action counts.
///
/// Never constructed from Python; only produced by `compare_action_policies`.
#[pyclass(
    module = "redact_secret._native",
    name = "ComparedSide",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyComparedSide {
    /// `"default"`, `"action-policy"` or `"callback"`.
    #[pyo3(get)]
    kind: &'static str,
    /// The lowercase SHA-256 of the exact document bytes for an action
    /// policy; `None` for the default policy and for a callback, which have
    /// no document identity.
    #[pyo3(get)]
    document_sha256: Option<String>,
    counts: Py<PyActionCounts>,
}

#[pymethods]
impl PyComparedSide {
    /// How many findings this policy chose each action for.
    #[getter]
    fn counts(&self, py: Python<'_>) -> Py<PyActionCounts> {
        self.counts.clone_ref(py)
    }

    fn __repr__(&self) -> String {
        format!(
            "ComparedSide(kind={:?}, document_sha256={})",
            self.kind,
            py_optional(
                self.document_sha256
                    .as_deref()
                    .map(|hex| format!("{hex:?}"))
            ),
        )
    }
}

/// The detection configuration the findings were produced under, apart from
/// every policy. It does not cover a custom detector set: a caller who passed
/// a `ruleset` keys that to its own identity next to the comparison.
///
/// Never constructed from Python; only produced by `compare_action_policies`.
#[pyclass(
    module = "redact_secret._native",
    name = "DetectionIdentity",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyDetectionIdentity {
    /// The registry's canonical activation identity.
    #[pyo3(get)]
    activation_identity: String,
    /// The detector profile, or `None` when the registry has none.
    #[pyo3(get)]
    profile: Option<&'static str>,
    /// The number of detectors that ran.
    #[pyo3(get)]
    detector_count: usize,
}

#[pymethods]
impl PyDetectionIdentity {
    fn __repr__(&self) -> String {
        format!(
            "DetectionIdentity(activation_identity={:?}, profile={}, detector_count={})",
            self.activation_identity,
            py_optional(self.profile.map(|profile| format!("{profile:?}"))),
            self.detector_count,
        )
    }
}

/// The result of `compare_action_policies`: what each compared policy would
/// choose for the findings one detection pass produced.
///
/// This is an observation, never enforcement: `mode` is `"preview"` and
/// `enforced` is `False`. It states what each policy does with what was found,
/// never that nothing else exists: it says nothing about overlap losers,
/// candidates that never survived, or PII alternatives the resolver
/// suppressed.
///
/// Never constructed from Python; only produced by `compare_action_policies`.
#[pyclass(
    module = "redact_secret._native",
    name = "ActionComparison",
    frozen,
    skip_from_py_object
)]
pub(crate) struct PyActionComparison {
    detection: Py<PyDetectionIdentity>,
    sides: Py<PyTuple>,
    findings: Py<PyTuple>,
    /// How many findings have a `differs` of `True`.
    #[pyo3(get)]
    changed_count: usize,
}

#[pymethods]
impl PyActionComparison {
    /// Always `"preview"`.
    #[getter]
    #[allow(clippy::unused_self)]
    const fn mode(&self) -> &'static str {
        "preview"
    }

    /// Always `False`: a comparison enforces nothing.
    #[getter]
    #[allow(clippy::unused_self)]
    const fn enforced(&self) -> bool {
        false
    }

    /// The detection configuration, identified apart from every policy.
    #[getter]
    fn detection(&self, py: Python<'_>) -> Py<PyDetectionIdentity> {
        self.detection.clone_ref(py)
    }

    /// One `ComparedSide` per compared policy, in the order given.
    #[getter]
    fn sides(&self, py: Python<'_>) -> Py<PyTuple> {
        self.sides.clone_ref(py)
    }

    /// The finalized findings, in the order `scan` returns them.
    #[getter]
    fn findings(&self, py: Python<'_>) -> Py<PyTuple> {
        self.findings.clone_ref(py)
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        format!(
            "ActionComparison(mode=\"preview\", enforced=False, sides=<{} side(s)>, findings=<{} finding(s)>, changed_count={})",
            self.sides.bind(py).len(),
            self.findings.bind(py).len(),
            self.changed_count,
        )
    }
}

// ---------------------------------------------------------------------
// Callback sides
// ---------------------------------------------------------------------

/// Adapts a Python `policy` callback to the core's [`Policy`] for one side.
///
/// The core's [`PolicyFailure`] carries no detail, so the sanitized Python
/// error [`call_python_policy`] produced is parked in `failure` for the
/// caller to raise in place of the core's generic `PolicyFailureError`: a bad
/// return value stays `InvalidPolicyActionError`, exactly as in `scan`.
struct CallbackAdapter<'a, 'py, 'text> {
    callable: Bound<'py, PyAny>,
    offsets: &'a RefCell<CharOffsets<'text>>,
    failure: &'a RefCell<Option<PyErr>>,
}

impl Policy for CallbackAdapter<'_, '_, '_> {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<redact_secret::Action, PolicyFailure> {
        call_python_policy(
            &self.callable,
            self.offsets,
            finding,
            context.finding_index(),
            context.finding_count(),
        )
        .map_err(|error| {
            *self.failure.borrow_mut() = Some(error);
            PolicyFailure
        })
    }
}

// ---------------------------------------------------------------------
// The primitive
// ---------------------------------------------------------------------

/// Converts the core's comparison into immutable Python objects, with every
/// range in code points.
fn comparison_to_py(
    py: Python<'_>,
    offsets: &RefCell<CharOffsets<'_>>,
    comparison: &ActionComparison,
) -> PyResult<PyActionComparison> {
    let detection = Bound::new(
        py,
        PyDetectionIdentity {
            activation_identity: comparison.detection().activation_identity().to_owned(),
            profile: comparison
                .detection()
                .profile()
                .map(redact_secret::Profile::as_str),
            detector_count: comparison.detection().detector_count(),
        },
    )?;

    let mut sides = Vec::with_capacity(comparison.sides().len());
    for side in comparison.sides() {
        let counts = side.counts();
        let counts = Bound::new(
            py,
            PyActionCounts {
                redact: counts.redact(),
                block: counts.block(),
                warn: counts.warn(),
                allow: counts.allow(),
            },
        )?;
        sides.push(Bound::new(
            py,
            PyComparedSide {
                kind: side.binding().kind(),
                document_sha256: side.binding().document_sha256_hex(),
                counts: counts.unbind(),
            },
        )?);
    }

    let mut findings = Vec::with_capacity(comparison.findings().len());
    for compared in comparison.findings() {
        let finding = compared.finding();
        let (start, end) = offsets.borrow_mut().range(finding.range())?;
        let decisions = compared
            .decisions()
            .iter()
            .map(|decision| Bound::new(py, PyActionDecision::from_core(decision)))
            .collect::<PyResult<Vec<_>>>()?;
        findings.push(Bound::new(
            py,
            PyComparedFinding {
                id: finding.id().to_owned(),
                type_name: finding.type_name().to_owned(),
                detector: finding.detector().to_owned(),
                confidence: finding.confidence().as_str(),
                obfuscation: finding.obfuscation().as_str(),
                start,
                end,
                differs: compared.differs(),
                decisions: PyTuple::new(py, decisions)?.unbind(),
            },
        )?);
    }

    Ok(PyActionComparison {
        detection: detection.unbind(),
        sides: PyTuple::new(py, sides)?.unbind(),
        findings: PyTuple::new(py, findings)?.unbind(),
        changed_count: comparison.changed_count(),
    })
}

/// Reads the `policies` argument: a `list` or `tuple` of 1 to
/// `MAX_COMPARED_POLICIES` [`PyComparedPolicy`] values. Anything else is the
/// existing `INVALID_OPTIONS`, decided from the length before any element is
/// touched and before any detection or callback.
fn extract_sides<'py>(policies: &Bound<'py, PyAny>) -> PyResult<Vec<Bound<'py, PyComparedPolicy>>> {
    let invalid = || map_error_code(SecretScanErrorCode::InvalidOptions);
    let items: Vec<Bound<'py, PyAny>> = if let Ok(list) = policies.cast::<PyList>() {
        list.iter().collect()
    } else if let Ok(tuple) = policies.cast::<PyTuple>() {
        tuple.iter().collect()
    } else {
        return Err(invalid());
    };
    if items.is_empty() || items.len() > MAX_COMPARED_POLICIES {
        return Err(invalid());
    }
    items
        .into_iter()
        .map(|item| item.cast_into::<PyComparedPolicy>().map_err(|_| invalid()))
        .collect()
}

/// Compares what 1 to 4 policies choose for the findings of one detection
/// pass, without enforcing any of them.
///
/// Detection runs once over `text` (every built-in detector, plus `ruleset`'s
/// when given, under the active PII selection); each of `policies` is then
/// evaluated on the same finalized findings, so a policy cannot add, remove or
/// reorder a finding. The result lists exactly the findings `scan(text, ...)`
/// returns, in the same order with the same ids, ranges and metadata, and
/// carries no input byte, matched value, snippet or score. It is a whole-input
/// primitive: there is no incremental, session or stream comparison.
///
/// `policies` is a `list` or `tuple` of `ComparedPolicy` values, in the order
/// the result reports them. A callback side is called once per finalized
/// finding in finding order, with the same `PolicyContext` `scan` gives it;
/// sides are evaluated one at a time in the order given, so two callbacks run
/// `A0 A1 A2 B0 B1 B2`. A callback that raises fails the whole comparison with
/// `PolicyFailureError`, with no partial result and no later call; one that
/// returns an invalid action raises `InvalidPolicyActionError`. A callback
/// with state or side effects advances them during a comparison like any
/// other call.
///
/// # Errors
///
/// Raises a `SecretScanError` subclass: `InvalidInputError` when `text` is
/// not a string, `InvalidOptionsError` when `policies` is not a `list` or
/// `tuple` of 1 to 4 `ComparedPolicy` values (before any detection or
/// callback) or `ruleset` has the wrong type, `InputLimitExceededError` and
/// `FindingLimitExceededError` against `limits` (or the default) as `scan`
/// applies them (the finding bound fails the call before any policy runs),
/// `InvalidRulesetError` for a rejected `ruleset`, `PolicyFailureError` /
/// `InvalidPolicyActionError` for a failing or malformed callback, and
/// `DetectorFailureError` or `InvalidCandidateError` for an internal detector
/// fault.
#[pyfunction]
#[pyo3(signature = (text, policies, limits=None, ruleset=None))]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn compare_action_policies<'py>(
    text: Bound<'py, PyAny>,
    policies: Bound<'py, PyAny>,
    limits: Option<PyRef<'py, PyWholeInputLimits>>,
    ruleset: Option<Bound<'py, PyAny>>,
) -> PyResult<PyActionComparison> {
    let py = text.py();
    let text_owned = extract_text(&text)?;
    let sides = extract_sides(&policies)?;
    let limits = PyWholeInputLimits::resolve(limits.as_deref());
    // The same order the core checks: the side count, then the byte bound,
    // both before a ruleset is parsed or anything is detected.
    limits.check_input(text_owned).map_err(map_core_error)?;
    let ruleset_bytes = ruleset.as_ref().map(extract_ruleset_bytes).transpose()?;

    let offsets = RefCell::new(CharOffsets::new(text_owned));
    let has_callback = sides
        .iter()
        .any(|side| matches!(side.get().side, Side::Callback(_)));

    let comparison = if has_callback {
        // A callback runs Python, so the GIL stays held, and the thread's
        // registry is moved out of its cache for the call: a callback that
        // itself scans or compares must not find the cache borrowed.
        let failure = RefCell::new(None);
        let adapters: Vec<CallbackAdapter<'_, '_, '_>> = sides
            .iter()
            .filter_map(|side| match &side.get().side {
                Side::Callback(callable) => Some(CallbackAdapter {
                    callable: callable.bind(py).clone(),
                    offsets: &offsets,
                    failure: &failure,
                }),
                _ => None,
            })
            .collect();
        let outcome = with_registry_released(ruleset_bytes.as_deref(), |registry| {
            let mut next_adapter = adapters.iter();
            let compared: Vec<CorePolicy<'_>> = sides
                .iter()
                .map(|side| match &side.get().side {
                    Side::Default => CorePolicy::Default,
                    Side::ActionPolicy(policy) => CorePolicy::ActionPolicy(policy),
                    Side::Callback(_) => next_adapter
                        .next()
                        .map_or(CorePolicy::Default, |adapter| CorePolicy::Callback(adapter)),
                })
                .collect();
            compare_action_policies_with_limits(text_owned, registry, &compared, &limits)
        })
        .map_err(RegistryError::into_py)?;
        outcome.map_err(|error| {
            // The callback's own sanitized error, when it left one, replaces
            // the core's detail-free `POLICY_FAILURE`.
            failure
                .borrow_mut()
                .take()
                .unwrap_or_else(|| map_core_error(error))
        })?
    } else {
        let documents: Vec<Option<&ActionPolicy>> = sides
            .iter()
            .map(|side| match &side.get().side {
                Side::ActionPolicy(policy) => Some(policy),
                _ => None,
            })
            .collect();
        // No Python object is touched while detecting, so other Python
        // threads run meanwhile, as in `scan`.
        py.detach(|| {
            with_registry(ruleset_bytes.as_deref(), |registry| {
                let compared: Vec<CorePolicy<'_>> = documents
                    .iter()
                    .map(|document| document.map_or(CorePolicy::Default, CorePolicy::ActionPolicy))
                    .collect();
                compare_action_policies_with_limits(text_owned, registry, &compared, &limits)
            })
        })
        .map_err(RegistryError::into_py)?
        .map_err(map_core_error)?
    };

    comparison_to_py(py, &offsets, &comparison)
}

/// Registers the comparison classes and function on the native module.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(compare_action_policies, module)?)?;
    module.add_class::<PyComparedPolicy>()?;
    module.add_class::<PyActionComparison>()?;
    module.add_class::<PyComparedFinding>()?;
    module.add_class::<PyActionDecision>()?;
    module.add_class::<PyComparedSide>()?;
    module.add_class::<PyActionCounts>()?;
    module.add_class::<PyDetectionIdentity>()?;
    Ok(())
}
