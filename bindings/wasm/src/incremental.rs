//! Bounded incremental sanitization for the browser
//! (`decision-define-runtime-bindings`).
//!
//! Exposes [`redact_secret::IncrementalSanitizer`] as a `wasm-bindgen` class
//! with mandatory limits, an explicit `accepting`/`finalized`/`aborted`/
//! `failed` lifecycle, and immutable per-call results — the same contract
//! `bindings/node/src/incremental.rs` exposes over N-API
//! (`decision-govern-cross-language-conformance`). A session never hands
//! retained plaintext back to JavaScript: it returns only sanitized text and
//! safe finding metadata, and `abort` or any failure discards what the core
//! still held.
//!
//! Every range this reports is an absolute **UTF-16 code-unit** offset into
//! the logical whole-session input, so `input.slice(finding.start,
//! finding.end)` selects the same span the synchronous API reports for the
//! joined input. The core reports absolute UTF-8 byte offsets; [`Utf16Index`]
//! converts them without retaining any of the input's characters — the same
//! algorithm `bindings/node/src/incremental.rs`'s own `Utf16Index`
//! implements, duplicated here rather than shared because a
//! `wasm32-unknown-unknown` build cannot depend on the N-API crate.
//!
//! The four limits are UTF-8 **byte** ceilings, passed to the core unchanged.
//! Their parameter names say `CodeUnits` for compatibility; the public
//! JavaScript wrapper also accepts `max*Bytes` aliases and resolves them to
//! these four positional values before this binding is called. A code unit
//! and a byte coincide for ASCII, which every credential format this project
//! detects is (`decision-govern-cross-language-conformance`).

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use js_sys::Function;
use redact_secret::{
    Action, ByteRange, DefaultPolicy, DetectedFinding, Finding, FormatterFailure,
    IncrementalLimits, IncrementalPolicy, IncrementalPolicyContext, IncrementalResult,
    IncrementalSanitizer as CoreIncrementalSanitizer, PlaceholderContext, PlaceholderFormatter,
    PolicyFailure, SecretScanError as CoreError, SecretScanErrorCode, SessionState,
    default_placeholder_formatter as core_default_formatter,
};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::{WasmErrorCode, to_js_error};
use crate::finding::FindingJs;
use crate::metadata;

// ---------------------------------------------------------------------
// Absolute byte offset -> absolute UTF-16 code-unit offset
// ---------------------------------------------------------------------

/// Converts an absolute UTF-8 byte offset into the logical whole-session
/// input to the absolute UTF-16 code-unit offset JavaScript string indexing
/// sees at the same position, without retaining the input.
///
/// Mirrors `bindings/node/src/incremental.rs`'s own `Utf16Index`: weighted by
/// each character's UTF-16 shortfall (`ch.len_utf8() - ch.len_utf16()`: 0 for
/// ASCII, 1 for a two- or three-byte character, 2 for a four-byte /
/// surrogate-pair character) instead of counting UTF-8 continuation bytes,
/// since UTF-16 and Unicode code point counting diverge on astral
/// characters.
///
/// The recorded offsets are pruned to the window a future call can still ask
/// about: the core never retains more than `max_buffered_bytes` of
/// unresolved input, so once a call returns, no later finding can start
/// before `total_bytes - max_buffered_bytes`.
struct Utf16Index {
    /// Ascending byte offsets of isolated or short non-ASCII characters, one
    /// entry per code unit of UTF-16 shortfall, at or above `floor`.
    discounts: VecDeque<usize>,
    /// Ascending runs of adjacent same-width non-ASCII characters (CJK
    /// text, emoji strings), one record per run instead of one entry per
    /// shortfall unit.
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
    /// Cumulative shortfall units of every run up to and including this one,
    /// counted from the start of the session (never reduced by pruning).
    cumulative_shortfall: usize,
    count: u32,
    width: u8,
}

impl Run {
    /// UTF-16 shortfall of one character of this run.
    fn shortfall(&self) -> usize {
        shortfall_of_width(self.width)
    }

    /// Byte offset of the first character after this run.
    fn end(&self) -> usize {
        self.start + self.count as usize * usize::from(self.width)
    }
}

/// `len_utf8 - len_utf16` for a character of `width` UTF-8 bytes: a
/// four-byte character is one surrogate pair, every other non-ASCII width
/// is one code unit.
fn shortfall_of_width(width: u8) -> usize {
    usize::from(width) - if width == 4 { 2 } else { 1 }
}

/// A run is recorded only when it replaces at least this many per-unit
/// entries, so the worst case (isolated characters) costs no more than it
/// did before runs existed.
const MIN_RUN_SHORTFALL: usize = 4;

impl Utf16Index {
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

    /// Records `chunk`'s UTF-16 shape as the next piece of logical input.
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
    /// enough to beat per-unit entries, and as per-unit entries otherwise.
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
    fn code_unit_offset(&self, byte_offset: usize) -> Option<u32> {
        if byte_offset < self.floor {
            return None;
        }
        let units = byte_offset.checked_sub(self.shortfall_before(byte_offset))?;
        u32::try_from(units).ok()
    }

    /// Converts a finding's absolute byte range to `(start, end)` UTF-16
    /// code-unit offsets.
    fn code_unit_range(&self, range: ByteRange) -> Option<(u32, u32)> {
        Some((
            self.code_unit_offset(range.start())?,
            self.code_unit_offset(range.end())?,
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

/// The pre-#1096 index: one entry per shortfall unit, never compacted. Kept
/// as the test oracle for [`Utf16Index`].
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
        for (index, ch) in chunk.char_indices() {
            let shortfall = ch.len_utf8() - ch.len_utf16();
            for _ in 0..shortfall {
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

    fn code_unit_offset(&self, byte_offset: usize) -> Option<u32> {
        if byte_offset < self.floor {
            return None;
        }
        let before = self.below_floor + self.discounts.partition_point(|&at| at < byte_offset);
        u32::try_from(byte_offset.checked_sub(before)?).ok()
    }
}

// ---------------------------------------------------------------------
// Callback adapters
// ---------------------------------------------------------------------

/// Adapts a JavaScript incremental policy callback (`(finding, context) =>
/// action`) to [`IncrementalPolicy`].
///
/// The callback receives only safe metadata — never the input or a matched
/// value. A thrown exception or an unusable return value is discarded and
/// reported as a fixed error code: the core's [`PolicyFailure`] carries no
/// detail, so the precise code is recorded in `policy_failure` for the
/// session to read back, exactly as `bindings/node`'s own adapter does.
struct JsIncrementalPolicyAdapter {
    callback: Function,
    index: Rc<RefCell<Utf16Index>>,
    policy_failure: Rc<Cell<Option<SecretScanErrorCode>>>,
}

impl JsIncrementalPolicyAdapter {
    /// Records `code` as the reason this session is about to fail and
    /// returns the core's detail-free failure.
    fn fail(&self, code: SecretScanErrorCode) -> PolicyFailure {
        self.policy_failure.set(Some(code));
        PolicyFailure
    }
}

impl IncrementalPolicy for JsIncrementalPolicyAdapter {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &IncrementalPolicyContext,
    ) -> Result<Action, PolicyFailure> {
        let (start, end) = self
            .index
            .borrow()
            .code_unit_range(finding.range())
            .ok_or_else(|| self.fail(SecretScanErrorCode::InvalidCandidate))?;
        let finding_metadata = metadata::policy_finding_with_range(finding, start, end)
            .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;
        let context_metadata = metadata::incremental_policy_context(*context)
            .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;
        let result = self
            .callback
            .call2(&JsValue::UNDEFINED, &finding_metadata, &context_metadata)
            .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;
        let action_name = result
            .as_string()
            .ok_or_else(|| self.fail(SecretScanErrorCode::PolicyFailure))?;
        Action::from_name(&action_name)
            .ok_or_else(|| self.fail(SecretScanErrorCode::InvalidPolicyAction))
    }
}

/// Adapts a JavaScript placeholder formatter callback to
/// [`PlaceholderFormatter`] for one session, the same safe metadata pair the
/// synchronous `redact` formatter receives.
struct JsIncrementalFormatterAdapter {
    callback: Function,
    index: Rc<RefCell<Utf16Index>>,
}

impl PlaceholderFormatter for JsIncrementalFormatterAdapter {
    fn format(
        &self,
        finding: &Finding,
        context: &PlaceholderContext,
    ) -> Result<String, FormatterFailure> {
        let (start, end) = self
            .index
            .borrow()
            .code_unit_range(finding.range())
            .ok_or(FormatterFailure)?;
        let finding_metadata = metadata::formatter_finding_with_range(finding, start, end)
            .map_err(|_| FormatterFailure)?;
        let context_metadata =
            metadata::placeholder_context(*context).map_err(|_| FormatterFailure)?;
        let result = self
            .callback
            .call2(&JsValue::UNDEFINED, &finding_metadata, &context_metadata)
            .map_err(|_| FormatterFailure)?;
        result.as_string().ok_or(FormatterFailure)
    }
}

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// The immutable result of one `append` or `finalize` call: the sanitized
/// text that call resolved, and the findings it finalized.
#[wasm_bindgen(js_name = "IncrementalResult")]
#[derive(Clone, Debug)]
pub struct IncrementalResultJs {
    text: String,
    findings: Vec<FindingJs>,
}

#[wasm_bindgen(js_class = "IncrementalResult")]
impl IncrementalResultJs {
    /// The sanitized text this call resolved. May be empty when the call
    /// only extended the retained, still-unresolved window.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// The findings this call finalized, in input order.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn findings(&self) -> Vec<FindingJs> {
        self.findings.clone()
    }

    /// Moves the sanitized text out of the result, leaving it empty. Unlike
    /// [`text`](Self::text) this keeps no second copy in linear memory; the
    /// JavaScript wrapper reads it once and then frees the result handle.
    #[wasm_bindgen(js_name = "takeText")]
    #[must_use]
    pub fn take_text(&mut self) -> String {
        std::mem::take(&mut self.text)
    }

    /// Moves the findings out of the result, leaving it with none. Unlike
    /// [`findings`](Self::findings) this clones no [`FindingJs`].
    #[wasm_bindgen(js_name = "takeFindings")]
    #[must_use]
    pub fn take_findings(&mut self) -> Vec<FindingJs> {
        std::mem::take(&mut self.findings)
    }
}

/// A bounded incremental sanitization session over the built-in detectors.
///
/// Lifecycle: a session starts `accepting` and accepts `append`, `finalize`,
/// and `abort`. Exactly one successful `finalize` moves it to `finalized`;
/// `abort` moves it to `aborted`; any limit, detector, policy, or
/// placeholder failure moves it to `failed`. All three are terminal: every
/// later operation raises `INVALID_STATE`, and every terminal transition
/// discards the plaintext the core still retained.
#[wasm_bindgen(js_name = "IncrementalSanitizer")]
pub struct IncrementalSanitizerJs {
    session: CoreIncrementalSanitizer,
    index: Rc<RefCell<Utf16Index>>,
    policy_failure: Rc<Cell<Option<SecretScanErrorCode>>>,
}

impl IncrementalSanitizerJs {
    /// Ends the session's offset bookkeeping and maps a core failure to its
    /// sanitized error, preferring the precise code a failing policy
    /// callback recorded over the core's generic `PolicyFailure`.
    fn fail(&mut self, error: CoreError) -> JsValue {
        self.index.borrow_mut().clear();
        let code = match (error.code(), self.policy_failure.take()) {
            (SecretScanErrorCode::PolicyFailure, Some(recorded)) => recorded,
            (code, _) => code,
        };
        to_js_error(WasmErrorCode::Core(code))
    }

    /// Converts one call's result to its JavaScript form and settles the
    /// offset index for the next call.
    fn finish(
        &mut self,
        result: IncrementalResult,
        ended: bool,
    ) -> Result<IncrementalResultJs, JsValue> {
        self.policy_failure.set(None);
        let (text, findings) = result.into_parts();

        let converted: Result<Vec<FindingJs>, CoreError> = {
            let index = self.index.borrow();
            findings
                .into_iter()
                .map(|finding| {
                    let (start, end) = index
                        .code_unit_range(finding.range())
                        .ok_or(SecretScanErrorCode::InvalidCandidate)?;
                    Ok(FindingJs::from_range(finding, start, end))
                })
                .collect()
        };

        match converted {
            Ok(findings) => {
                let mut index = self.index.borrow_mut();
                if ended {
                    index.clear();
                } else {
                    index.prune();
                }
                Ok(IncrementalResultJs { text, findings })
            }
            // Unreachable while the core keeps its ranges char-aligned and
            // in bounds; an internal inconsistency still ends the session
            // rather than leaving it accepting with no way to convert.
            Err(error) => {
                let _ = self.session.abort();
                self.index.borrow_mut().clear();
                Err(to_js_error(error.into()))
            }
        }
    }

    /// Rejects an operation on a session that has left `accepting`, before
    /// it observes anything.
    fn require_accepting(&self) -> Result<(), JsValue> {
        if matches!(self.session.state(), SessionState::Accepting) {
            Ok(())
        } else {
            Err(to_js_error(SecretScanErrorCode::InvalidState.into()))
        }
    }
}

#[wasm_bindgen(js_class = "IncrementalSanitizer")]
impl IncrementalSanitizerJs {
    /// The session's lifecycle state: `"accepting"`, `"finalized"`,
    /// `"aborted"`, or `"failed"`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn state(&self) -> String {
        match self.session.state() {
            SessionState::Accepting => "accepting",
            SessionState::Finalized => "finalized",
            SessionState::Aborted => "aborted",
            SessionState::Failed => "failed",
        }
        .to_owned()
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
    /// `INVALID_STATE` outside the `accepting` state,
    /// `INPUT_LIMIT_EXCEEDED`, `BUFFER_LIMIT_EXCEEDED`,
    /// `TOKEN_LIMIT_EXCEEDED`, or `MULTILINE_LIMIT_EXCEEDED` when a declared
    /// limit is reached, and `DETECTOR_FAILURE`, `INVALID_CANDIDATE`,
    /// `POLICY_FAILURE`, `INVALID_POLICY_ACTION`, `PLACEHOLDER_FAILURE`, or
    /// `INVALID_PLACEHOLDER` when resolving a closed unit fails. Every one
    /// of them is terminal and discards retained plaintext.
    #[wasm_bindgen]
    pub fn append(&mut self, chunk: &str) -> Result<IncrementalResultJs, JsValue> {
        self.require_accepting()?;
        self.index.borrow_mut().observe(chunk);
        match self.session.append(chunk) {
            Ok(result) => self.finish(result, false),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Supplies the end-of-input boundary, resolving whatever the session
    /// still retained, and moves it to `finalized`.
    ///
    /// # Errors
    ///
    /// The same codes as `append`, minus the input-limit failure, plus
    /// `INVALID_STATE` outside the `accepting` state — including a second
    /// `finalize`, which never re-emits the first one's result.
    #[wasm_bindgen]
    pub fn finalize(&mut self) -> Result<IncrementalResultJs, JsValue> {
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
    /// `INVALID_STATE` outside the `accepting` state, so a second `abort`,
    /// or an `abort` after `finalize`, is rejected rather than silently
    /// accepted.
    #[wasm_bindgen]
    pub fn abort(&mut self) -> Result<(), JsValue> {
        self.session
            .abort()
            .map_err(|error| to_js_error(error.into()))?;
        self.index.borrow_mut().clear();
        self.policy_failure.set(None);
        Ok(())
    }
}

fn to_core_limits(
    max_input_code_units: u32,
    max_buffered_code_units: u32,
    max_token_code_units: u32,
    max_multiline_code_units: u32,
) -> Result<IncrementalLimits, CoreError> {
    IncrementalLimits::new(
        max_input_code_units as usize,
        max_buffered_code_units as usize,
        max_token_code_units as usize,
        max_multiline_code_units as usize,
    )
}

/// Creates a bounded incremental sanitization session over the built-in
/// detectors (`decision-define-runtime-bindings`).
///
/// `policy`, when given, is called once per finalized finding as
/// `(findingMetadata, context) => string`, returning `"redact"`, `"block"`,
/// `"warn"`, or `"allow"`. `formatter`, when given, is called once per
/// replaced finding as `(findingMetadata, context) => string`. Both receive
/// only safe metadata, never the input or a matched value, and both are
/// numbered across the whole session rather than per call.
///
/// # Errors
///
/// Returns `INVALID_LIMITS` when the four limits are non-positive or do not
/// satisfy the documented relationship between them.
// `policy`/`formatter` cannot be `Option<&Function>` (see `lib.rs`'s `scan`);
// this crate takes ownership at every such boundary and borrows internally.
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen(js_name = "createIncrementalSanitizer")]
pub fn create_incremental_sanitizer(
    max_input_code_units: u32,
    max_buffered_code_units: u32,
    max_token_code_units: u32,
    max_multiline_code_units: u32,
    policy: Option<Function>,
    formatter: Option<Function>,
) -> Result<IncrementalSanitizerJs, JsValue> {
    let limits = to_core_limits(
        max_input_code_units,
        max_buffered_code_units,
        max_token_code_units,
        max_multiline_code_units,
    )
    .map_err(|error| to_js_error(error.into()))?;
    let index = Rc::new(RefCell::new(Utf16Index::new(limits.max_buffered_bytes())));
    let policy_failure = Rc::new(Cell::new(None));

    let policy: Box<dyn IncrementalPolicy> = match policy {
        None => Box::new(DefaultPolicy),
        Some(callback) => Box::new(JsIncrementalPolicyAdapter {
            callback,
            index: Rc::clone(&index),
            policy_failure: Rc::clone(&policy_failure),
        }),
    };
    let formatter: Box<dyn PlaceholderFormatter> = match formatter {
        None => Box::new(core_default_formatter),
        Some(callback) => Box::new(JsIncrementalFormatterAdapter {
            callback,
            index: Rc::clone(&index),
        }),
    };

    let session = crate::lifecycle::new_incremental_session(limits, policy, formatter)
        .map_err(|error| to_js_error(error.into()))?;

    Ok(IncrementalSanitizerJs {
        session,
        index,
        policy_failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "SYNTHETIC_REVOKED_RETENTION_MARKER";

    fn generous_limits() -> IncrementalLimits {
        let (token, multiline) = (8_192, 16_384);
        IncrementalLimits::new(
            1 << 20,
            IncrementalLimits::minimum_buffered_bytes(token, multiline),
            token,
            multiline,
        )
        .unwrap()
    }

    fn default_session() -> CoreIncrementalSanitizer {
        CoreIncrementalSanitizer::new(generous_limits()).unwrap()
    }

    #[test]
    fn incremental_result_take_accessors_move_what_the_getters_clone() {
        let core_finding = redact_secret::Finding::new(
            "finding-1",
            "jwt",
            "jwt",
            redact_secret::Confidence::High,
            redact_secret::Action::Redact,
            redact_secret::ByteRange::new(0, 3).unwrap(),
        )
        .unwrap();
        let mut result = IncrementalResultJs {
            text: "<REDACTED>".to_owned(),
            findings: vec![FindingJs::from_range(core_finding, 0, 3)],
        };
        let text = result.text();
        let findings = result.findings();

        assert_eq!(result.take_text(), text);
        let taken = result.take_findings();
        assert_eq!(taken.len(), findings.len());
        assert_eq!(taken[0].id(), findings[0].id());
        assert_eq!(
            (taken[0].start(), taken[0].end()),
            (findings[0].range().start(), findings[0].range().end())
        );
        assert_eq!(result.text(), "");
        assert!(result.findings().is_empty());
    }

    // ---------------------------------------------------------------
    // Utf16Index
    // ---------------------------------------------------------------

    /// The independent reference the index must agree with: the number of
    /// UTF-16 code units encoding the UTF-8 prefix ending at `byte_offset`.
    fn reference(text: &str, byte_offset: usize) -> u32 {
        u32::try_from(text[..byte_offset].encode_utf16().count()).unwrap()
    }

    #[test]
    fn converts_absolute_offsets_across_chunk_boundaries() {
        // An astral character before, within, and after an ASCII run, split
        // into chunks so no single chunk holds the whole input.
        let chunks = [
            "\u{1F511}api",
            "_key=SYN\u{1F511}THETIC",
            "_REVOKED\u{1F511}",
        ];
        let joined = chunks.concat();

        let mut index = Utf16Index::new(1024);
        for chunk in chunks {
            index.observe(chunk);
        }

        for byte_offset in 0..=joined.len() {
            if !joined.is_char_boundary(byte_offset) {
                continue;
            }
            assert_eq!(
                index.code_unit_offset(byte_offset),
                Some(reference(&joined, byte_offset)),
                "byte offset {byte_offset}",
            );
        }
    }

    #[test]
    fn pruning_keeps_every_offset_a_later_call_can_still_ask_about() {
        let chunk = "\u{1F511}ab\u{00E9}cd\n";
        let mut index = Utf16Index::new(chunk.len());
        let mut joined = String::new();

        for _ in 0..10 {
            index.observe(chunk);
            joined.push_str(chunk);
            index.prune();

            let floor = joined.len() - chunk.len();
            for byte_offset in floor..=joined.len() {
                if !joined.is_char_boundary(byte_offset) {
                    continue;
                }
                assert_eq!(
                    index.code_unit_offset(byte_offset),
                    Some(reference(&joined, byte_offset)),
                    "byte offset {byte_offset}",
                );
            }
        }
    }

    #[test]
    fn ascii_input_records_nothing_and_converts_identically() {
        let mut index = Utf16Index::new(64);
        index.observe("api_key=SYNTHETIC_REVOKED\n");
        assert!(index.discounts.is_empty());
        assert_eq!(index.code_unit_offset(0), Some(0));
        assert_eq!(index.code_unit_offset(25), Some(25));
    }

    #[test]
    fn clearing_forgets_every_offset() {
        let mut index = Utf16Index::new(64);
        index.observe("\u{1F511}abc");
        index.clear();
        assert!(index.discounts.is_empty());
        assert_eq!(index.discounts_below_floor, 0);
        assert_eq!(index.runs_below_floor, 0);
        assert!(index.runs.is_empty());
        assert_eq!(index.code_unit_offset(0), None);
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
            let mut index = Utf16Index::new(window);
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
                            index.code_unit_offset(byte_offset),
                            oracle.code_unit_offset(byte_offset),
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
                            index.code_unit_offset(byte_offset),
                            oracle.code_unit_offset(byte_offset),
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
        let mut index = Utf16Index::new(300);
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
                    index.code_unit_offset(byte_offset),
                    oracle.code_unit_offset(byte_offset),
                    "offset {byte_offset}",
                );
            }
        }
    }

    #[test]
    fn a_run_continues_across_a_chunk_boundary_and_capacity_is_released() {
        let mut index = Utf16Index::new(64);
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

    // ---------------------------------------------------------------
    // Limits
    // ---------------------------------------------------------------

    #[test]
    fn limits_pass_through_as_byte_counts() {
        let core = to_core_limits(1_048_576, 16_512, 8_192, 16_384).unwrap();
        assert_eq!(core.max_input_bytes(), 1_048_576);
        assert_eq!(core.max_buffered_bytes(), 16_512);
        assert_eq!(core.max_token_bytes(), 8_192);
        assert_eq!(core.max_multiline_bytes(), 16_384);
    }

    #[test]
    fn invalid_limits_are_rejected() {
        assert_eq!(
            to_core_limits(0, 16_512, 8_192, 16_384).unwrap_err().code(),
            SecretScanErrorCode::InvalidLimits
        );
    }

    // ---------------------------------------------------------------
    // Session lifecycle against the core directly (no JavaScript function
    // involved, so these run on every target, not just `wasm32`); the
    // `wasm-bindgen` surface itself — including custom policy/formatter
    // callbacks and the JavaScript error shape — is exercised by the
    // `#[wasm_bindgen_test]` functions below, which only run under
    // `wasm32` (see the crate-level note in `lib.rs`).
    // ---------------------------------------------------------------

    #[test]
    fn abort_discards_an_open_construct() {
        let mut sanitizer = default_session();
        sanitizer.append(&format!("api_key={MARKER}")).unwrap();
        sanitizer.abort().unwrap();
        assert_eq!(sanitizer.state(), SessionState::Aborted);
    }

    #[test]
    fn a_session_split_across_chunks_matches_the_whole_input_result() {
        let mut session = default_session();
        let mut output = String::new();
        for chunk in ["api_key=SYNTHETIC_", "REVOKED_PARTITION_MARKER\n", "tail"] {
            output.push_str(session.append(chunk).unwrap().text());
        }
        output.push_str(session.finalize().unwrap().text());
        assert_eq!(output, "api_key=<SECRET_1>\ntail");
        assert!(!output.contains(MARKER));
    }

    // ---------------------------------------------------------------
    // wasm-bindgen surface: real JavaScript functions and errors, so these
    // only run under `wasm32` via `wasm-bindgen-test-runner`.
    // ---------------------------------------------------------------

    fn js_error_code(error: &JsValue) -> String {
        let error: js_sys::Error = error.clone().into();
        js_sys::Reflect::get(&error, &JsValue::from_str("code"))
            .unwrap()
            .as_string()
            .unwrap()
    }

    fn wasm_session(
        policy: Option<Function>,
        formatter: Option<Function>,
    ) -> IncrementalSanitizerJs {
        crate::initialize(Vec::new()).unwrap();
        create_incremental_sanitizer(1 << 20, 16_512, 8_192, 16_384, policy, formatter).unwrap()
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_session_split_across_chunks_matches_the_whole_input_result_through_wasm_bindgen() {
        let mut session = wasm_session(None, None);
        assert_eq!(session.state(), "accepting");

        let mut output = String::new();
        for chunk in ["api_key=SYNTHETIC_", "REVOKED_PARTITION_MARKER\n", "tail"] {
            output.push_str(&session.append(chunk).unwrap().text());
        }
        output.push_str(&session.finalize().unwrap().text());

        assert_eq!(session.state(), "finalized");
        assert_eq!(output, "api_key=<SECRET_1>\ntail");
        assert!(!output.contains(MARKER));
    }

    /// The same synthetic value, split at every byte boundary rather than one
    /// fixed partition, must always reconstruct to the same sanitized output
    /// as scanning it whole — the partition-invariance guarantee
    /// `crates/secret-scan-core/src/incremental.rs` documents, exercised here
    /// through the actual `wasm-bindgen` surface.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn every_chunk_partition_matches_the_whole_input_result() {
        let input = format!("api_key={MARKER}\ntail");

        for split in 0..=input.len() {
            if !input.is_char_boundary(split) {
                continue;
            }
            let mut session = wasm_session(None, None);
            let mut output = String::new();
            output.push_str(&session.append(&input[..split]).unwrap().text());
            output.push_str(&session.append(&input[split..]).unwrap().text());
            output.push_str(&session.finalize().unwrap().text());
            assert_eq!(output, "api_key=<SECRET_1>\ntail", "split at byte {split}");
        }
    }

    /// An astral character positioned before, within, and after a finding
    /// that itself spans a chunk boundary: the reported range must select
    /// exactly the same UTF-16 code units the whole-input `scan`/`redact`
    /// surface would (`bindings/wasm/src/range.rs`'s own coverage), even
    /// though this session never held the whole input at once.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn finding_ranges_use_utf16_offsets_across_a_chunk_boundary() {
        let prefix = "\u{1F511} ";
        let secret = crate::synthetic::secret();
        let whole = format!("{prefix}{} suffix", secret.text);
        // Four bytes into the finding itself, so it spans the boundary.
        let finding_start = prefix.len() + secret.text.find(&secret.matched).unwrap();
        let value = secret.matched;
        let (chunk_a, chunk_b) = whole.split_at(finding_start + 4);

        let mut session = wasm_session(None, None);
        session.append(chunk_a).unwrap();
        let result = session.append(chunk_b).unwrap();
        let finalized = session.finalize().unwrap();

        let findings: Vec<FindingJs> = result
            .findings()
            .into_iter()
            .chain(finalized.findings())
            .collect();
        assert_eq!(findings.len(), 1);
        let range = findings[0].range();

        let utf16: Vec<u16> = whole.encode_utf16().collect();
        let matched =
            String::from_utf16(&utf16[range.start() as usize..range.end() as usize]).unwrap();
        assert_eq!(matched, value);
    }

    /// A custom policy callback sees only safe metadata (never the input,
    /// which this session never even holds as one string) and can redirect
    /// the action away from the default.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_custom_policy_callback_sees_only_safe_metadata() {
        let policy = Function::new_with_args(
            "finding, context",
            "if (Object.prototype.hasOwnProperty.call(finding, 'input')) { throw new Error('leak'); }
             if (typeof finding.range.start !== 'number' || typeof finding.range.end !== 'number') { throw new Error('bad range'); }
             if (context.findingIndex !== 0) { throw new Error('bad index'); }
             return 'block';",
        );
        let mut session = wasm_session(Some(policy), None);
        let mut findings = Vec::new();
        findings.extend(
            session
                .append(&format!("api_key={MARKER}\n"))
                .unwrap()
                .findings(),
        );
        findings.extend(session.finalize().unwrap().findings());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].action(), "block");
    }

    /// A throwing policy callback fails the session deterministically,
    /// discarding retained plaintext and rejecting every further call.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_throwing_policy_callback_fails_the_session_and_discards_retained_plaintext() {
        let policy = Function::new_no_args("throw new Error('boom');");
        let mut session = wasm_session(Some(policy), None);

        let error = session.append(&format!("api_key={MARKER}\n")).unwrap_err();
        assert_eq!(js_error_code(&error), "POLICY_FAILURE");
        assert_eq!(session.state(), "failed");

        let after = session.append("ignored").unwrap_err();
        assert_eq!(js_error_code(&after), "INVALID_STATE");
    }

    /// A custom formatter callback sees the action alongside safe metadata.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_custom_formatter_callback_sees_the_action() {
        let formatter = Function::new_with_args(
            "finding, context",
            "if (Object.prototype.hasOwnProperty.call(finding, 'input')) { throw new Error('leak'); }
             return '[' + finding.action + ':' + context.placeholderIndex + ']';",
        );
        let mut session = wasm_session(None, Some(formatter));
        let mut output = String::new();
        output.push_str(
            &session
                .append(&format!("api_key={MARKER}\n"))
                .unwrap()
                .text(),
        );
        output.push_str(&session.finalize().unwrap().text());
        assert_eq!(output, "api_key=[redact:1]\n");
    }

    /// A lifecycle misuse (appending after `finalize`) is rejected with a
    /// fixed code rather than silently accepted or panicking.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn append_after_finalize_is_rejected() {
        let mut session = wasm_session(None, None);
        session.finalize().unwrap();
        let error = session.append("ignored").unwrap_err();
        assert_eq!(js_error_code(&error), "INVALID_STATE");
    }

    /// `abort` releases retained plaintext and moves to a terminal state
    /// that rejects every further operation.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn abort_releases_retained_plaintext_and_rejects_further_calls() {
        let mut session = wasm_session(None, None);
        session.append(&format!("api_key={MARKER}")).unwrap();
        session.abort().unwrap();
        assert_eq!(session.state(), "aborted");

        let error = session.append("ignored").unwrap_err();
        assert_eq!(js_error_code(&error), "INVALID_STATE");
        let error = session.abort().unwrap_err();
        assert_eq!(js_error_code(&error), "INVALID_STATE");
    }

    /// An open construct that never closes within `max_token_code_units`
    /// fails the session with the declared limit code and discards the
    /// plaintext it was still holding.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_token_limit_failure_discards_retained_plaintext() {
        crate::initialize(Vec::new()).unwrap();
        let (token, multiline): (usize, usize) = (32, 64);
        let buffered = IncrementalLimits::minimum_buffered_bytes(token, multiline);
        let mut session = create_incremental_sanitizer(
            1 << 20,
            u32::try_from(buffered).unwrap(),
            u32::try_from(token).unwrap(),
            u32::try_from(multiline).unwrap(),
            None,
            None,
        )
        .unwrap();
        let error = session
            .append("api_key=SYNTHETIC_REVOKED_VALUE_LONGER_THAN_THE_TOKEN_LIMIT_ABCDEFGH")
            .unwrap_err();
        assert_eq!(js_error_code(&error), "TOKEN_LIMIT_EXCEEDED");
        assert_eq!(session.state(), "failed");

        let after = session.append("ignored").unwrap_err();
        assert_eq!(js_error_code(&after), "INVALID_STATE");
    }
}
