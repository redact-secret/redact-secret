//! Bounded incremental sanitization for `CPython`
//! (`decision-define-runtime-bindings`).
//!
//! Exposes [`redact_secret::IncrementalSanitizer`] as a synchronous Python
//! session with mandatory limits, an explicit `accepting` /
//! `finalized` / `aborted` / `failed` lifecycle, and immutable per-call
//! results. A session never hands retained plaintext back to Python: it
//! returns only sanitized text and safe finding metadata, and `abort` or
//! any failure discards what the core still held.
//!
//! Every range a session reports is an **absolute Unicode code point**
//! offset into the logical whole-session input, so
//! `"".join(chunks)[finding.start:finding.end]` selects the same span the
//! synchronous API would report for the joined input
//! (`decision-govern-cross-language-conformance`). The core reports
//! absolute UTF-8 byte offsets; [`CodePointIndex`] converts them without
//! retaining any of the input's characters.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use pyo3::prelude::*;

use redact_secret::{
    Action, ByteRange, DefaultPolicy, DetectedFinding, Finding as CoreFinding, FormatterFailure,
    IncrementalLimits, IncrementalPolicy, IncrementalPolicyContext, IncrementalResult,
    IncrementalSanitizer, PlaceholderContext, PlaceholderFormatter, PolicyFailure,
    SecretScanError as CoreError, SecretScanErrorCode, SessionState,
    default_placeholder_formatter as core_default_formatter,
};

use crate::{
    PyDetectedFinding, PyFinding, PyPlaceholderContext, extract_text, map_core_error,
    map_error_code, resolve_action_policy,
};

// ---------------------------------------------------------------------
// Absolute byte offset -> absolute code point offset
// ---------------------------------------------------------------------

/// Converts an absolute UTF-8 byte offset into the logical whole-session
/// input to the absolute Unicode code point offset Python's `str` indexing
/// sees at the same position, without retaining the input.
///
/// A code point offset is the byte offset minus the number of UTF-8
/// continuation bytes (`0b10xx_xxxx`) before it, so the only state this
/// needs is *where* the continuation bytes are — never which characters
/// they encode. Pure ASCII input, which every credential format this
/// project detects is made of, records nothing at all.
///
/// The recorded offsets are pruned to the window a future call can still
/// ask about. The core never retains more than `max_buffered_bytes` of
/// unresolved input, so once a call returns, no later finding can start
/// before `total_bytes - max_buffered_bytes`; everything below that is
/// collapsed into a running count. During `observe`, the index also includes
/// the entire incoming chunk until result conversion completes. Adjacent
/// same-width characters are recorded as one run, and `prune` releases
/// capacity a large chunk left behind, but the buffer limit alone is still
/// not a bound on index memory during one very large append.
pub(crate) struct CodePointIndex {
    /// Ascending byte offsets of isolated or short non-ASCII characters, one
    /// entry per continuation byte, at or above `floor`.
    discounts: VecDeque<usize>,
    /// Ascending runs of adjacent same-width non-ASCII characters (CJK
    /// text, emoji strings), one record per run instead of one entry per
    /// continuation byte.
    runs: VecDeque<Run>,
    /// Shortfall units popped from `discounts` (below `floor`).
    discounts_below_floor: usize,
    /// Shortfall units popped from `runs`, whole or in part (below `floor`).
    runs_below_floor: usize,
    /// Lowest byte offset this index can still convert.
    floor: usize,
    /// Total input bytes observed so far.
    total_bytes: usize,
    /// The session's declared buffer limit, which bounds how far back a
    /// future finding can begin.
    max_buffered_bytes: usize,
}

/// `count` adjacent non-ASCII characters of `width` UTF-8 bytes each, the
/// first starting at byte `start`.
struct Run {
    start: usize,
    /// Cumulative continuation bytes of every run up to and including this one,
    /// counted from the start of the session (never reduced by pruning).
    cumulative_shortfall: usize,
    count: u32,
    width: u8,
}

impl Run {
    /// Continuation bytes of one character of this run.
    fn shortfall(&self) -> usize {
        shortfall_of_width(self.width)
    }

    /// Byte offset of the first character after this run.
    fn end(&self) -> usize {
        self.start + self.count as usize * usize::from(self.width)
    }
}

/// UTF-8 continuation bytes of a character of `width` bytes: the amount a
/// code point offset falls short of the byte offset after it.
fn shortfall_of_width(width: u8) -> usize {
    usize::from(width) - 1
}

/// A run is recorded only when it replaces at least this many per-unit
/// entries, so the worst case (isolated characters) costs no more than it
/// did before runs existed.
const MIN_RUN_SHORTFALL: usize = 4;

impl CodePointIndex {
    /// Creates an index for a session with the given buffer limit.
    fn new(max_buffered_bytes: usize) -> Self {
        Self {
            discounts: VecDeque::new(),
            runs: VecDeque::new(),
            discounts_below_floor: 0,
            runs_below_floor: 0,
            floor: 0,
            total_bytes: 0,
            max_buffered_bytes,
        }
    }

    /// Records `chunk`'s UTF-8 shape as the next piece of logical input.
    fn observe(&mut self, chunk: &str) {
        // The run being extended: (start, width, count).
        let mut pending: Option<(usize, u8, u32)> = None;
        for (index, ch) in chunk.char_indices() {
            let width = ch.len_utf8();
            if width == 1 {
                continue;
            }
            let start = self.total_bytes + index;
            let width = u8::try_from(width).unwrap_or(4);
            match &mut pending {
                Some((run_start, run_width, count))
                    if *run_width == width
                        && *count < u32::MAX
                        && *run_start + *count as usize * usize::from(width) == start =>
                {
                    *count += 1;
                }
                _ => {
                    if let Some((run_start, run_width, count)) = pending.take() {
                        self.record(run_start, run_width, count);
                    }
                    pending = Some((start, width, 1));
                }
            }
        }
        if let Some((run_start, run_width, count)) = pending {
            self.record(run_start, run_width, count);
        }
        self.total_bytes += chunk.len();
    }

    /// Records `count` adjacent `width`-byte characters from `start`: onto
    /// the last run when it ends exactly there, as a new run when long
    /// enough to beat per-byte entries, and as per-byte entries otherwise.
    fn record(&mut self, start: usize, width: u8, count: u32) {
        let shortfall = shortfall_of_width(width);
        let added = count as usize * shortfall;
        if let Some(last) = self.runs.back_mut()
            && last.width == width
            && last.end() == start
            && last.count.checked_add(count).is_some()
        {
            last.count += count;
            last.cumulative_shortfall += added;
            return;
        }
        if added >= MIN_RUN_SHORTFALL {
            let previous = self
                .runs
                .back()
                .map_or(self.runs_below_floor, |last| last.cumulative_shortfall);
            self.runs.push_back(Run {
                start,
                cumulative_shortfall: previous + added,
                count,
                width,
            });
        } else {
            for index in 0..count as usize {
                for _ in 0..shortfall {
                    self.discounts.push_back(start + index * usize::from(width));
                }
            }
        }
    }

    /// Drops the offsets no later call can ask about, after a call has
    /// returned and the core's retained window has settled, and returns the
    /// capacity a large earlier chunk left behind.
    fn prune(&mut self) {
        let floor = self.total_bytes.saturating_sub(self.max_buffered_bytes);
        while self.discounts.front().is_some_and(|&at| at < floor) {
            self.discounts.pop_front();
            self.discounts_below_floor += 1;
        }
        while let Some(front) = self.runs.front_mut() {
            if front.start >= floor {
                break;
            }
            let width = usize::from(front.width);
            // Characters of the run that start below `floor`.
            let below = (floor - front.start).div_ceil(width);
            if below >= front.count as usize {
                self.runs_below_floor = front.cumulative_shortfall;
                self.runs.pop_front();
            } else {
                self.runs_below_floor += below * front.shortfall();
                front.start += below * width;
                front.count -= u32::try_from(below).unwrap_or(u32::MAX);
                break;
            }
        }
        self.floor = floor;
        shrink_if_sparse(&mut self.discounts);
        shrink_if_sparse(&mut self.runs);
    }

    /// Forgets everything: used when a session ends and no further offset
    /// can be reported.
    fn clear(&mut self) {
        self.discounts = VecDeque::new();
        self.runs = VecDeque::new();
        self.discounts_below_floor = 0;
        self.runs_below_floor = 0;
        self.floor = self.total_bytes;
    }

    /// Shortfall units of every character starting below `byte_offset`.
    fn shortfall_before(&self, byte_offset: usize) -> usize {
        let discounts =
            self.discounts_below_floor + self.discounts.partition_point(|&at| at < byte_offset);
        let started = self.runs.partition_point(|run| run.start < byte_offset);
        let runs = match started.checked_sub(1) {
            None => self.runs_below_floor,
            Some(last) => {
                let run = &self.runs[last];
                let before = match last.checked_sub(1) {
                    None => self.runs_below_floor,
                    Some(previous) => self.runs[previous].cumulative_shortfall,
                };
                let characters = (byte_offset - run.start)
                    .div_ceil(usize::from(run.width))
                    .min(run.count as usize);
                before + characters * run.shortfall()
            }
        };
        discounts + runs
    }

    /// Converts one absolute byte offset, or `None` when it falls below the
    /// pruning floor (which the core's own bounds make unreachable).
    fn char_offset(&self, byte_offset: usize) -> Option<usize> {
        if byte_offset < self.floor {
            return None;
        }
        byte_offset.checked_sub(self.shortfall_before(byte_offset))
    }

    /// Converts a finding's absolute byte range to `(start, end)` code
    /// point offsets.
    fn char_range(&self, range: ByteRange) -> Option<(usize, usize)> {
        Some((
            self.char_offset(range.start())?,
            self.char_offset(range.end())?,
        ))
    }
}

/// Releases the capacity a peak (one very large chunk) left behind once the
/// live entries are far fewer than the allocation.
fn shrink_if_sparse<T>(entries: &mut VecDeque<T>) {
    if entries.capacity() > 64 && entries.capacity() / 4 > entries.len() {
        entries.shrink_to(entries.len() * 2);
    }
}

/// The pre-#1096 index: one entry per continuation byte, never compacted. Kept
/// as the test oracle for [`CodePointIndex`].
#[cfg(test)]
struct OracleIndex {
    discounts: VecDeque<usize>,
    below_floor: usize,
    floor: usize,
    total_bytes: usize,
    max_buffered_bytes: usize,
}

#[cfg(test)]
impl OracleIndex {
    fn new(max_buffered_bytes: usize) -> Self {
        Self {
            discounts: VecDeque::new(),
            below_floor: 0,
            floor: 0,
            total_bytes: 0,
            max_buffered_bytes,
        }
    }

    fn observe(&mut self, chunk: &str) {
        for (index, byte) in chunk.as_bytes().iter().enumerate() {
            if byte & 0b1100_0000 == 0b1000_0000 {
                self.discounts.push_back(self.total_bytes + index);
            }
        }
        self.total_bytes += chunk.len();
    }

    fn prune(&mut self) {
        let floor = self.total_bytes.saturating_sub(self.max_buffered_bytes);
        while self.discounts.front().is_some_and(|&at| at < floor) {
            self.discounts.pop_front();
            self.below_floor += 1;
        }
        self.floor = floor;
    }

    fn char_offset(&self, byte_offset: usize) -> Option<usize> {
        if byte_offset < self.floor {
            return None;
        }
        let before = self.below_floor + self.discounts.partition_point(|&at| at < byte_offset);
        byte_offset.checked_sub(before)
    }
}

// ---------------------------------------------------------------------
// Callback adapters
// ---------------------------------------------------------------------

/// Adapts a Python policy callback to [`IncrementalPolicy`].
///
/// The callback receives only safe metadata — a [`PyDetectedFinding`] with
/// absolute code point offsets and a [`PyIncrementalPolicyContext`] — never
/// the input or a matched value. A raised exception or an unusable return
/// value is discarded and reported as a fixed error code: the core's
/// [`PolicyFailure`] carries no detail, so the precise code is recorded in
/// `policy_failure` for the session to read back.
struct PyIncrementalPolicyAdapter {
    callable: Py<PyAny>,
    index: Rc<RefCell<CodePointIndex>>,
    policy_failure: Rc<Cell<Option<SecretScanErrorCode>>>,
}

impl PyIncrementalPolicyAdapter {
    /// Records `code` as the reason this session is about to fail and
    /// returns the core's detail-free failure.
    fn fail(&self, code: SecretScanErrorCode) -> PolicyFailure {
        self.policy_failure.set(Some(code));
        PolicyFailure
    }
}

impl IncrementalPolicy for PyIncrementalPolicyAdapter {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &IncrementalPolicyContext,
    ) -> Result<Action, PolicyFailure> {
        let (start, end) = self
            .index
            .borrow()
            .char_range(finding.range())
            .ok_or_else(|| self.fail(SecretScanErrorCode::InvalidCandidate))?;

        Python::attach(|py| {
            let py_finding = Bound::new(py, PyDetectedFinding::from_core(finding, start, end))
                .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;
            let py_context = Bound::new(
                py,
                PyIncrementalPolicyContext {
                    finding_index: context.finding_index(),
                },
            )
            .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;

            let value = self
                .callable
                .bind(py)
                .call1((py_finding, py_context))
                .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;
            let name = value
                .extract::<String>()
                .map_err(|_| self.fail(SecretScanErrorCode::InvalidPolicyAction))?;
            Action::from_name(&name)
                .ok_or_else(|| self.fail(SecretScanErrorCode::InvalidPolicyAction))
        })
    }
}

/// Adapts a Python placeholder formatter callback to
/// [`PlaceholderFormatter`] for one session.
///
/// The callback receives the same safe metadata pair the synchronous
/// `redact` formatter does — a [`PyFinding`] with absolute code point
/// offsets and a session-wide [`PyPlaceholderContext`] — and its failure is
/// reduced to the core's detail-free [`FormatterFailure`], which surfaces
/// as `PlaceholderFailureError`.
struct PyIncrementalFormatterAdapter {
    callable: Py<PyAny>,
    index: Rc<RefCell<CodePointIndex>>,
}

impl PlaceholderFormatter for PyIncrementalFormatterAdapter {
    fn format(
        &self,
        finding: &CoreFinding,
        context: &PlaceholderContext,
    ) -> Result<String, FormatterFailure> {
        let (start, end) = self
            .index
            .borrow()
            .char_range(finding.range())
            .ok_or(FormatterFailure)?;

        Python::attach(|py| {
            let py_finding = Bound::new(py, PyFinding::from_core(finding.clone(), start, end))
                .map_err(|_| FormatterFailure)?;
            let py_context = Bound::new(
                py,
                PyPlaceholderContext {
                    placeholder_index: context.placeholder_index(),
                },
            )
            .map_err(|_| FormatterFailure)?;

            self.callable
                .bind(py)
                .call1((py_finding, py_context))
                .map_err(|_| FormatterFailure)?
                .extract::<String>()
                .map_err(|_| FormatterFailure)
        })
    }
}

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// The explicit, positive UTF-8 byte limits every incremental session
/// requires. There are no defaults: a session that does not declare its
/// bounds is not created.
///
/// `max_buffered_bytes` must be at least
/// `IncrementalLimits.minimum_buffered_bytes()` for the construct limits it
/// accompanies, and neither construct limit may exceed
/// `max_input_bytes`. Limits are byte
/// counts, not code point counts, because they bound memory rather than
/// index into a string; `len(chunk.encode("utf-8"))` is what they measure.
#[pyclass(
    module = "redact_secret._native",
    name = "IncrementalLimits",
    frozen,
    skip_from_py_object
)]
#[derive(Clone, Copy)]
pub(crate) struct PyIncrementalLimits {
    inner: IncrementalLimits,
}

#[pymethods]
impl PyIncrementalLimits {
    /// Validates and creates a limit set.
    ///
    /// # Errors
    ///
    /// Raises `InvalidLimitsError` when any limit is zero, when a construct
    /// limit exceeds `max_input_bytes`, or when `max_buffered_bytes` cannot
    /// accommodate the larger construct limit plus the lookaround window.
    #[new]
    #[pyo3(signature = (*, max_input_bytes, max_buffered_bytes, max_token_bytes, max_multiline_bytes))]
    fn new(
        max_input_bytes: usize,
        max_buffered_bytes: usize,
        max_token_bytes: usize,
        max_multiline_bytes: usize,
    ) -> PyResult<Self> {
        let inner = IncrementalLimits::new(
            max_input_bytes,
            max_buffered_bytes,
            max_token_bytes,
            max_multiline_bytes,
        )
        .map_err(map_core_error)?;
        Ok(Self { inner })
    }

    /// The smallest `max_buffered_bytes` this constructor accepts alongside
    /// these construct limits: the larger of the two plus the boundary
    /// lookaround the built-in detectors need to decide whether a construct
    /// is still open.
    ///
    /// The lookaround reserve itself is an implementation detail of the core
    /// that tracks the built-in detector set. Deriving the limit through
    /// this method keeps a caller correct when that reserve changes.
    #[staticmethod]
    #[pyo3(signature = (max_token_bytes, max_multiline_bytes))]
    const fn minimum_buffered_bytes(max_token_bytes: usize, max_multiline_bytes: usize) -> usize {
        IncrementalLimits::minimum_buffered_bytes(max_token_bytes, max_multiline_bytes)
    }

    /// Total logical input the session accepts across every `append` call.
    #[getter]
    const fn max_input_bytes(&self) -> usize {
        self.inner.max_input_bytes()
    }

    /// Unresolved plaintext the session may retain but not yet have
    /// emitted.
    #[getter]
    const fn max_buffered_bytes(&self) -> usize {
        self.inner.max_buffered_bytes()
    }

    /// Bound for an open logical line, single-line credential, or other
    /// delimiter-terminated token.
    #[getter]
    const fn max_token_bytes(&self) -> usize {
        self.inner.max_token_bytes()
    }

    /// Bound for an open PEM-style private-key block.
    #[getter]
    const fn max_multiline_bytes(&self) -> usize {
        self.inner.max_multiline_bytes()
    }

    fn __repr__(&self) -> String {
        format!(
            "IncrementalLimits(max_input_bytes={}, max_buffered_bytes={}, max_token_bytes={}, max_multiline_bytes={})",
            self.inner.max_input_bytes(),
            self.inner.max_buffered_bytes(),
            self.inner.max_token_bytes(),
            self.inner.max_multiline_bytes(),
        )
    }
}

/// Position of a finding among the findings a session has finalized so
/// far, given to an incremental policy callback alongside a
/// `DetectedFinding`.
///
/// Unlike the synchronous `PolicyContext` there is no total count:
/// progressive evaluation cannot know how many findings the whole session
/// will eventually produce.
///
/// Never constructed from Python; only produced for a policy callback.
#[pyclass(module = "redact_secret._native", name = "IncrementalPolicyContext")]
pub(crate) struct PyIncrementalPolicyContext {
    /// Zero-based position among findings finalized so far in this session.
    #[pyo3(get)]
    finding_index: usize,
}

#[pymethods]
impl PyIncrementalPolicyContext {
    fn __repr__(&self) -> String {
        format!(
            "IncrementalPolicyContext(finding_index={})",
            self.finding_index
        )
    }
}

/// The immutable result of one `append` or `finalize` call: the sanitized
/// text that call resolved, and the findings it finalized.
///
/// Concatenating every result's `text`, in call order, reconstructs the
/// whole sanitized output. `findings` carry absolute code point offsets
/// into the logical whole-session input.
///
/// Never constructed from Python; only produced by a session.
#[pyclass(module = "redact_secret._native", name = "IncrementalResult", frozen)]
pub(crate) struct PyIncrementalResult {
    /// The sanitized text this call resolved. May be empty when the call
    /// only extended the retained, still-unresolved window.
    #[pyo3(get)]
    text: String,
    /// The findings this call finalized, in input order.
    #[pyo3(get)]
    findings: Vec<PyFinding>,
}

#[pymethods]
impl PyIncrementalResult {
    fn __repr__(&self) -> String {
        format!(
            "IncrementalResult(text={:?}, findings=<{} finding(s)>)",
            self.text,
            self.findings.len()
        )
    }
}

/// A bounded incremental sanitization session over the built-in detectors.
///
/// Lifecycle: a session starts `accepting` and accepts `append`,
/// `finalize`, and `abort`. Exactly one successful `finalize` moves it to
/// `finalized`; `abort` moves it to `aborted`; any limit, detector, policy,
/// or placeholder failure moves it to `failed`. Host input rejection also
/// moves it to `failed`. All three are terminal:
/// every later operation raises `InvalidStateError`, and every terminal
/// transition discards the plaintext the core still retained.
///
/// A session holds a Python callback and Rust state that is not shared
/// between threads: use it from the thread that created it.
#[pyclass(
    module = "redact_secret._native",
    name = "IncrementalSanitizer",
    unsendable
)]
pub(crate) struct PyIncrementalSanitizer {
    session: IncrementalSanitizer,
    input_failed: bool,
    limits: PyIncrementalLimits,
    index: Rc<RefCell<CodePointIndex>>,
    policy_failure: Rc<Cell<Option<SecretScanErrorCode>>>,
}

impl PyIncrementalSanitizer {
    /// Ends the session's offset bookkeeping and maps a core failure to its
    /// sanitized exception, preferring the precise code a failing policy
    /// callback recorded over the core's generic `PolicyFailure`.
    fn fail(&mut self, error: CoreError) -> PyErr {
        self.index.borrow_mut().clear();
        match (error.code(), self.policy_failure.take()) {
            (SecretScanErrorCode::PolicyFailure, Some(recorded)) => map_error_code(recorded),
            (code, _) => map_error_code(code),
        }
    }

    /// Converts one call's result to its Python form and settles the offset
    /// index for the next call.
    fn finish(&mut self, result: IncrementalResult, ended: bool) -> PyResult<PyIncrementalResult> {
        self.policy_failure.set(None);
        let (text, findings) = result.into_parts();

        let converted = {
            let index = self.index.borrow();
            findings
                .into_iter()
                .map(|finding| {
                    let (start, end) = index
                        .char_range(finding.range())
                        .ok_or_else(|| map_error_code(SecretScanErrorCode::InvalidCandidate))?;
                    Ok(PyFinding::from_core(finding, start, end))
                })
                .collect::<PyResult<Vec<_>>>()
        };

        match converted {
            Ok(findings) => {
                let mut index = self.index.borrow_mut();
                if ended {
                    index.clear();
                } else {
                    index.prune();
                }
                Ok(PyIncrementalResult { text, findings })
            }
            // Unreachable while the core keeps its ranges char-aligned and
            // in bounds; an internal inconsistency still ends the session
            // rather than leaving it accepting with no way to convert.
            Err(error) => {
                let _ = self.session.abort();
                self.index.borrow_mut().clear();
                Err(error)
            }
        }
    }

    /// Rejects an operation on a session that has left `accepting`, before
    /// it observes anything.
    fn require_accepting(&self) -> PyResult<()> {
        if matches!(self.session.state(), SessionState::Accepting) {
            Ok(())
        } else {
            Err(map_error_code(SecretScanErrorCode::InvalidState))
        }
    }
}

#[pymethods]
impl PyIncrementalSanitizer {
    /// Creates a session with mandatory `limits`.
    ///
    /// `policy`, when given, is called once per finalized finding as
    /// `policy(finding: DetectedFinding, context: IncrementalPolicyContext)
    /// -> str`, returning `"redact"`, `"block"`, `"warn"`, or `"allow"`.
    /// `formatter`, when given, is called once per replaced finding as
    /// `formatter(finding: Finding, context: PlaceholderContext) -> str`.
    /// Both receive only safe metadata carrying absolute code point
    /// offsets, never the input or a matched value, and both are numbered
    /// across the whole session rather than per call.
    ///
    /// `action_policy`, keyword-only, is a declarative action policy as a
    /// `dict`, or its document as `bytes`, `bytearray`, or `str`. It is
    /// validated here, once, and the session keeps that compiled policy for
    /// its whole life. Supplying both `policy` and `action_policy` raises
    /// `InvalidOptionsError`; a rejected document raises
    /// `InvalidActionPolicyError`.
    ///
    /// # Errors
    ///
    /// Raises `InvalidDetectorError` only if the built-in detector registry
    /// itself is malformed, which cannot happen for the detectors this
    /// package ships.
    #[new]
    #[pyo3(signature = (limits, policy=None, formatter=None, *, action_policy=None))]
    #[allow(clippy::needless_pass_by_value)]
    fn new(
        limits: PyRef<'_, PyIncrementalLimits>,
        policy: Option<Bound<'_, PyAny>>,
        formatter: Option<Bound<'_, PyAny>>,
        action_policy: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        // Validated once, here, before any input: the session owns the
        // compiled policy for its whole life, and a later change to a native
        // object passed in changes nothing.
        let declared = resolve_action_policy(policy.as_ref(), action_policy.as_ref())?;
        let index = Rc::new(RefCell::new(CodePointIndex::new(
            limits.inner.max_buffered_bytes(),
        )));
        let policy_failure = Rc::new(Cell::new(None));

        let core_policy: Box<dyn IncrementalPolicy> = match (policy, declared) {
            (Some(callable), _) => Box::new(PyIncrementalPolicyAdapter {
                callable: callable.unbind(),
                index: Rc::clone(&index),
                policy_failure: Rc::clone(&policy_failure),
            }),
            (None, Some(declared)) => Box::new(declared),
            (None, None) => Box::new(DefaultPolicy),
        };
        let core_formatter: Box<dyn PlaceholderFormatter> = match formatter {
            None => Box::new(core_default_formatter),
            Some(callable) => Box::new(PyIncrementalFormatterAdapter {
                callable: callable.unbind(),
                index: Rc::clone(&index),
            }),
        };

        let selection = crate::active_pii_selection();
        let session = IncrementalSanitizer::with_built_in_and_pii_policy_and_formatter(
            limits.inner,
            &selection,
            core_policy,
            core_formatter,
        )
        .map_err(map_core_error)?;
        Ok(Self {
            session,
            input_failed: false,
            limits: *limits,
            index,
            policy_failure,
        })
    }

    /// The session's lifecycle state: `"accepting"`, `"finalized"`,
    /// `"aborted"`, or `"failed"`.
    #[getter]
    const fn state(&self) -> &'static str {
        if self.input_failed {
            return "failed";
        }
        match self.session.state() {
            SessionState::Accepting => "accepting",
            SessionState::Finalized => "finalized",
            SessionState::Aborted => "aborted",
            SessionState::Failed => "failed",
        }
    }

    /// The limits this session was created with.
    #[getter]
    const fn limits(&self) -> PyIncrementalLimits {
        self.limits
    }

    /// Appends `chunk` to the logical input and returns whatever became
    /// resolvable.
    ///
    /// Text and findings are emitted only once their detection window is
    /// closed, so a call that only extends an open construct returns an
    /// empty `text` and no findings. Nothing is lost: a later `append` or
    /// `finalize` emits it.
    ///
    /// # Errors
    ///
    /// Raises `InvalidInputError` when `chunk` is not a string or contains
    /// an unpaired surrogate,
    /// `InvalidStateError` outside the `accepting` state,
    /// `InputLimitExceededError`, `BufferLimitExceededError`,
    /// `TokenLimitExceededError`, or `MultilineLimitExceededError` when a
    /// declared limit is reached, and `DetectorFailureError`,
    /// `InvalidCandidateError`, `PolicyFailureError`,
    /// `InvalidPolicyActionError`, `PlaceholderFailureError`, or
    /// `InvalidPlaceholderError` when resolving a closed unit fails. Every
    /// one of them is terminal and discards retained plaintext.
    #[allow(clippy::needless_pass_by_value)]
    fn append(&mut self, chunk: Bound<'_, PyAny>) -> PyResult<PyIncrementalResult> {
        self.require_accepting()?;
        let text = match extract_text(&chunk) {
            Ok(text) => text,
            Err(error) => {
                // Host rejection never reaches append in the core. Abort drops
                // retained plaintext; expose this host failure as `failed`.
                self.input_failed = true;
                let _ = self.session.abort();
                self.index.borrow_mut().clear();
                self.policy_failure.set(None);
                return Err(error);
            }
        };
        self.index.borrow_mut().observe(text);
        match self.session.append(text) {
            Ok(result) => self.finish(result, false),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Supplies the end-of-input boundary, resolving whatever the session
    /// still retained, and moves it to `finalized`.
    ///
    /// # Errors
    ///
    /// The same codes as `append`, minus the input-type and input-limit
    /// failures, plus `InvalidStateError` outside the `accepting` state —
    /// including a second `finalize`, which never re-emits the first one's
    /// result.
    fn finalize(&mut self) -> PyResult<PyIncrementalResult> {
        self.require_accepting()?;
        match self.session.finalize() {
            Ok(result) => self.finish(result, true),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Discards every byte the session still retained and moves it to
    /// `aborted`, emitting no further text or findings.
    ///
    /// # Errors
    ///
    /// Raises `InvalidStateError` outside the `accepting` state, so a
    /// second `abort`, or an `abort` after `finalize`, is rejected rather
    /// than silently accepted.
    fn abort(&mut self) -> PyResult<()> {
        self.session.abort().map_err(map_core_error)?;
        self.index.borrow_mut().clear();
        self.policy_failure.set(None);
        Ok(())
    }

    /// Enters a `with` block, so a session that is not finalized on the way
    /// out is guaranteed to discard what it retained.
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Leaves a `with` block: aborts a still-`accepting` session and lets
    /// any in-flight exception propagate.
    #[allow(clippy::needless_pass_by_value)]
    fn __exit__(
        &mut self,
        _exc_type: Bound<'_, PyAny>,
        _exc_value: Bound<'_, PyAny>,
        _traceback: Bound<'_, PyAny>,
    ) -> bool {
        if matches!(self.session.state(), SessionState::Accepting) {
            let _ = self.session.abort();
            self.index.borrow_mut().clear();
            self.policy_failure.set(None);
        }
        false
    }

    /// A representation that carries the lifecycle state only: retained
    /// plaintext never reaches it.
    fn __repr__(&self) -> String {
        format!("IncrementalSanitizer(state={:?})", self.state())
    }
}

/// The built-in default policy, in the incremental callback's shape:
/// `(finding: DetectedFinding, context: IncrementalPolicyContext) -> str`.
///
/// The default action mapping does not depend on a total finding count, so
/// this returns exactly what `default_policy` returns for the same finding.
/// A custom incremental policy can call it to fall back for findings it
/// does not want to override.
///
/// # Errors
///
/// Raises `PolicyFailureError` on an internal failure, which the built-in
/// mapping does not produce.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn default_incremental_policy(
    finding: PyRef<'_, PyDetectedFinding>,
    context: PyRef<'_, PyIncrementalPolicyContext>,
) -> PyResult<String> {
    let core_finding = finding.to_core()?;
    let core_context = IncrementalPolicyContext::new(context.finding_index);
    IncrementalPolicy::evaluate(&DefaultPolicy, &core_finding, &core_context)
        .map(|action| action.as_str().to_owned())
        .map_err(|_| map_error_code(SecretScanErrorCode::PolicyFailure))
}

/// Registers the incremental surface on the extension module.
///
/// # Errors
///
/// Propagates any `CPython` failure while adding a name to the module.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(default_incremental_policy, module)?)?;
    module.add_class::<PyIncrementalLimits>()?;
    module.add_class::<PyIncrementalPolicyContext>()?;
    module.add_class::<PyIncrementalResult>()?;
    module.add_class::<PyIncrementalSanitizer>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CodePointIndex, OracleIndex};

    /// The independent reference the binding must agree with: the number of
    /// code points in the UTF-8 prefix ending at `byte_offset`.
    fn reference(text: &str, byte_offset: usize) -> usize {
        text[..byte_offset].chars().count()
    }

    #[test]
    fn converts_absolute_offsets_across_chunk_boundaries() {
        // An astral character before, within, and after the ASCII run, split
        // into chunks so no single chunk holds the whole input.
        let chunks = [
            "\u{1F511}api",
            "_key=SYN\u{1F511}THETIC",
            "_REVOKED\u{1F511}",
        ];
        let joined = chunks.concat();

        let mut index = CodePointIndex::new(1024);
        for chunk in chunks {
            index.observe(chunk);
        }

        for byte_offset in 0..=joined.len() {
            if !joined.is_char_boundary(byte_offset) {
                continue;
            }
            assert_eq!(
                index.char_offset(byte_offset),
                Some(reference(&joined, byte_offset)),
                "byte offset {byte_offset}",
            );
        }
    }

    #[test]
    fn pruning_keeps_every_offset_a_later_call_can_still_ask_about() {
        let chunk = "\u{1F511}ab\u{00E9}cd\n";
        let mut index = CodePointIndex::new(chunk.len());
        let mut joined = String::new();

        // Ten chunks with a four-byte and a two-byte character each, pruned
        // after every call exactly as a session does.
        for _ in 0..10 {
            index.observe(chunk);
            joined.push_str(chunk);
            index.prune();

            // Everything the core could still retain converts exactly.
            let floor = joined.len() - chunk.len();
            for byte_offset in floor..=joined.len() {
                if !joined.is_char_boundary(byte_offset) {
                    continue;
                }
                assert_eq!(
                    index.char_offset(byte_offset),
                    Some(reference(&joined, byte_offset)),
                    "byte offset {byte_offset}",
                );
            }
        }
    }

    #[test]
    fn ascii_input_records_nothing_and_converts_identically() {
        let mut index = CodePointIndex::new(64);
        index.observe("api_key=SYNTHETIC_REVOKED\n");
        assert!(index.discounts.is_empty());
        assert_eq!(index.char_offset(0), Some(0));
        assert_eq!(index.char_offset(25), Some(25));
    }

    #[test]
    fn clearing_forgets_every_offset() {
        let mut index = CodePointIndex::new(64);
        index.observe("\u{1F511}abc");
        index.clear();
        assert!(index.discounts.is_empty());
        assert_eq!(index.discounts_below_floor, 0);
        assert_eq!(index.runs_below_floor, 0);
        assert!(index.runs.is_empty());
        assert_eq!(index.char_offset(0), None);
    }

    /// A fixed-seed 32-bit generator: usize-safe on wasm32.
    fn next(state: &mut u32) -> u32 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        *state
    }

    /// Random text made of ASCII islands and runs of 2-, 3- and 4-byte
    /// characters, including combining marks and invisible code points.
    fn random_text(state: &mut u32, chars: usize) -> String {
        const POOL: [&[char]; 5] = [
            &['a', 'b', ' ', '\n', '='],
            &['\u{00E9}', '\u{0416}', '\u{00FC}'],
            &['\u{4E2D}', '\u{6587}', '\u{0301}', '\u{200B}', '\u{FEFF}'],
            &['\u{1F511}', '\u{1F512}', '\u{10400}'],
            &['\u{07FF}', '\u{0800}', '\u{FFFD}'],
        ];
        let mut out = String::new();
        while out.chars().count() < chars {
            let pool = POOL[(next(state) % 5) as usize];
            let run = 1 + next(state) % 9;
            for _ in 0..run {
                out.push(pool[(next(state) as usize) % pool.len()]);
            }
        }
        out
    }

    #[test]
    fn compacted_index_matches_the_per_unit_oracle_on_random_streams() {
        for seed in 1..=40u32 {
            let mut state = seed.wrapping_mul(2_654_435_761) | 1;
            let window = 1 + (next(&mut state) % 300) as usize;
            let mut index = CodePointIndex::new(window);
            let mut oracle = OracleIndex::new(window);
            let mut joined = String::new();
            for _ in 0..12 {
                let chars = (next(&mut state) % 200) as usize;
                let chunk = random_text(&mut state, chars);
                index.observe(&chunk);
                oracle.observe(&chunk);
                joined.push_str(&chunk);
                // Queries before pruning span the whole retained input.
                for byte_offset in 0..=joined.len() {
                    if joined.is_char_boundary(byte_offset) {
                        assert_eq!(
                            index.char_offset(byte_offset),
                            oracle.char_offset(byte_offset),
                            "seed {seed} offset {byte_offset} before prune",
                        );
                    }
                }
                if !next(&mut state).is_multiple_of(4) {
                    index.prune();
                    oracle.prune();
                }
                for byte_offset in 0..=joined.len() {
                    if joined.is_char_boundary(byte_offset) {
                        assert_eq!(
                            index.char_offset(byte_offset),
                            oracle.char_offset(byte_offset),
                            "seed {seed} offset {byte_offset} after prune",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dense_runs_are_recorded_compactly_and_prune_inside_a_run() {
        let cjk = "\u{4E2D}".repeat(1000);
        let emoji = "\u{1F511}".repeat(1000);
        let mut index = CodePointIndex::new(300);
        let mut oracle = OracleIndex::new(300);
        let mut joined = String::new();
        for chunk in [cjk.as_str(), "ab", emoji.as_str(), cjk.as_str()] {
            index.observe(chunk);
            oracle.observe(chunk);
            joined.push_str(chunk);
            index.prune();
            oracle.prune();
        }
        // Three dense runs, no per-unit entries.
        assert!(index.discounts.len() <= 2, "{}", index.discounts.len());
        assert!(index.runs.len() <= 3, "{}", index.runs.len());
        let floor = joined.len() - 300;
        for byte_offset in floor - 7..=joined.len() {
            if joined.is_char_boundary(byte_offset) {
                assert_eq!(
                    index.char_offset(byte_offset),
                    oracle.char_offset(byte_offset),
                    "offset {byte_offset}",
                );
            }
        }
    }

    #[test]
    fn a_run_continues_across_a_chunk_boundary_and_capacity_is_released() {
        let mut index = CodePointIndex::new(64);
        let big = "\u{1F511}".repeat(50_000);
        index.observe(&big);
        index.observe(&big);
        assert_eq!(index.runs.len(), 1);
        index.prune();
        for chunk in ["tail\u{1F511}\n"; 3] {
            index.observe(chunk);
            index.prune();
        }
        assert!(index.discounts.capacity() <= 256);
        assert!(index.runs.capacity() <= 256);
    }
}
