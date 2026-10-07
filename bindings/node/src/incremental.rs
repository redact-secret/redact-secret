//! Bounded incremental sanitization for Node.js
//! (`decision-define-runtime-bindings`).
//!
//! Exposes [`redact_secret::IncrementalSanitizer`] as a synchronous N-API
//! class with mandatory limits, an explicit `accepting` / `finalized` /
//! `aborted` / `failed` lifecycle, and immutable per-call results. A session
//! never hands retained plaintext back to JavaScript: it returns only
//! sanitized text and safe finding metadata, and `abort` or any failure
//! discards what the core still held.
//!
//! Every range a session reports is an absolute **UTF-16 code-unit** offset
//! into the logical whole-session input, so `input.slice(finding.start,
//! finding.end)` selects the same span the synchronous API reports for the
//! joined input (`decision-govern-cross-language-conformance`). The core
//! reports absolute UTF-8 byte offsets; [`Utf16Index`] converts them without
//! retaining any of the input's characters.
//!
//! The four `limits` fields are UTF-8 **byte** ceilings, passed to the core
//! unchanged. Their names say `CodeUnits` for compatibility; the public
//! JavaScript wrapper also accepts `max*Bytes` aliases and resolves them to
//! these four fields before this binding is called, so this binding sees only
//! the legacy spelling. A code unit and a byte coincide for ASCII, which every
//! credential format this project detects is, and the canonical
//! `conformance/fixtures/incremental-lifecycle-corpus.json` fixtures assert
//! exact ASCII boundaries with no conversion factor
//! (`decision-govern-cross-language-conformance`).

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use napi::bindgen_prelude::{Buffer, Env, FnArgs, Function, FunctionRef};
use napi_derive::napi;
use redact_secret::{
    Action, ByteRange, DefaultPolicy, DetectedFinding, Finding, FormatterFailure,
    IncrementalLimits, IncrementalPolicy, IncrementalPolicyContext, IncrementalResult,
    IncrementalSanitizer, PlaceholderContext, PlaceholderFormatter, PolicyFailure, Profile,
    SecretScanError as CoreError, SecretScanErrorCode, SessionState,
    default_placeholder_formatter as core_default_formatter, load_action_policy,
};

use crate::error::{to_js_action_policy_error, to_js_error};
use crate::{FormatterCallback, JsDetectedFinding, JsFinding, JsPlaceholderContext};

// ---------------------------------------------------------------------
// Absolute byte offset -> absolute UTF-16 code-unit offset
// ---------------------------------------------------------------------

/// Converts an absolute UTF-8 byte offset into the logical whole-session
/// input to the absolute UTF-16 code-unit offset JavaScript string indexing
/// sees at the same position, without retaining the input.
///
/// Mirrors `bindings/python`'s `CodePointIndex`, but weighted by each
/// character's UTF-16 shortfall (`ch.len_utf8() - ch.len_utf16()`: 0 for
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

type IncrementalPolicyArgs = FnArgs<(JsDetectedFinding, JsIncrementalPolicyContext)>;

/// A JavaScript incremental policy callback: `(finding, context) => action`.
type IncrementalPolicyCallback<'env> = Function<'env, IncrementalPolicyArgs, String>;

type FormatterArgs = FnArgs<(JsFinding, JsPlaceholderContext)>;

/// Adapts a JavaScript policy callback to [`IncrementalPolicy`].
///
/// The callback receives only safe metadata — a [`JsDetectedFinding`] with
/// absolute UTF-16 offsets and a [`JsIncrementalPolicyContext`] — never the
/// input or a matched value. A thrown exception or an unusable return value
/// is discarded and reported as a fixed error code: the core's
/// [`PolicyFailure`] carries no detail, so the precise code is recorded in
/// `policy_failure` for the session to read back.
///
/// `current_env` is set by the session immediately before it calls into the
/// core for one `append`/`finalize`, and cleared immediately after: a
/// `FunctionRef` outlives any single call, but the `Env` needed to invoke it
/// only exists for the duration of the JavaScript call that supplied it.
struct JsIncrementalPolicyAdapter {
    callback: FunctionRef<IncrementalPolicyArgs, String>,
    index: Rc<RefCell<Utf16Index>>,
    current_env: Rc<Cell<Option<Env>>>,
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
        let js_finding = JsDetectedFinding {
            id: finding.id().to_owned(),
            r#type: finding.type_name().to_owned(),
            detector: finding.detector().to_owned(),
            confidence: finding.confidence().as_str().to_owned(),
            obfuscation: finding.obfuscation().as_str().to_owned(),
            start,
            end,
        };
        let js_context = JsIncrementalPolicyContext {
            finding_index: u32::try_from(context.finding_index()).unwrap_or(u32::MAX),
        };
        let env = self
            .current_env
            .get()
            .ok_or_else(|| self.fail(SecretScanErrorCode::PolicyFailure))?;
        let function = self
            .callback
            .borrow_back(&env)
            .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;
        let action_name: String = function
            .call(FnArgs::from((js_finding, js_context)))
            .map_err(|_| self.fail(SecretScanErrorCode::PolicyFailure))?;
        Action::from_name(&action_name)
            .ok_or_else(|| self.fail(SecretScanErrorCode::InvalidPolicyAction))
    }
}

/// Adapts a JavaScript placeholder formatter callback to
/// [`PlaceholderFormatter`] for one session.
///
/// The callback receives the same safe metadata pair the synchronous
/// `redact` formatter does — a [`JsFinding`] with absolute UTF-16 offsets
/// and a session-wide [`JsPlaceholderContext`] — and its failure is reduced
/// to the core's detail-free [`FormatterFailure`].
struct JsIncrementalFormatterAdapter {
    callback: FunctionRef<FormatterArgs, String>,
    index: Rc<RefCell<Utf16Index>>,
    current_env: Rc<Cell<Option<Env>>>,
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
        let js_finding = JsFinding {
            id: finding.id().to_owned(),
            r#type: finding.type_name().to_owned(),
            detector: finding.detector().to_owned(),
            confidence: finding.confidence().as_str().to_owned(),
            action: finding.action().as_str().to_owned(),
            obfuscation: finding.obfuscation().as_str().to_owned(),
            start,
            end,
        };
        let js_context = JsPlaceholderContext {
            placeholder_index: u32::try_from(context.placeholder_index()).unwrap_or(u32::MAX),
        };
        let env = self.current_env.get().ok_or(FormatterFailure)?;
        let function = self
            .callback
            .borrow_back(&env)
            .map_err(|_| FormatterFailure)?;
        function
            .call(FnArgs::from((js_finding, js_context)))
            .map_err(|_| FormatterFailure)
    }
}

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// Explicit, positive limits every incremental session requires. There are
/// no defaults: a session that does not declare its bounds is not created.
///
/// All four are UTF-8 byte ceilings, passed to the core unchanged. The
/// `CodeUnits` names are legacy spellings; the public wrapper resolves its
/// `max*Bytes` aliases to these fields (see the module documentation).
#[napi(object)]
#[allow(clippy::struct_field_names)]
pub struct JsIncrementalLimits {
    /// Total logical input the session accepts across every `append` call.
    pub max_input_code_units: u32,
    /// Unresolved plaintext the session may retain but not yet have
    /// emitted.
    pub max_buffered_code_units: u32,
    /// Bound for an open logical line, single-line credential, or other
    /// delimiter-terminated token.
    pub max_token_code_units: u32,
    /// Bound for an open PEM-style private-key block.
    pub max_multiline_code_units: u32,
}

/// Position information passed alongside a [`JsDetectedFinding`] to an
/// incremental policy callback.
#[napi(object)]
pub struct JsIncrementalPolicyContext {
    /// Zero-based position among findings finalized so far in this session.
    pub finding_index: u32,
}

/// The immutable result of one `append` or `finalize` call: the sanitized
/// text that call resolved, and the findings it finalized.
#[napi(object)]
pub struct JsIncrementalResult {
    /// The sanitized text this call resolved. May be empty when the call
    /// only extended the retained, still-unresolved window.
    pub text: String,
    /// The findings this call finalized, in input order.
    pub findings: Vec<JsFinding>,
}

/// Options accepted by [`create_incremental_sanitizer`].
#[napi(object)]
pub struct JsIncrementalOptions<'env> {
    /// Mandatory bounds for the session.
    pub limits: JsIncrementalLimits,
    /// Called once per finalized finding. Omit to use the core's default
    /// policy.
    #[napi(
        ts_type = "(finding: JsDetectedFinding, context: JsIncrementalPolicyContext) => string"
    )]
    pub policy: Option<IncrementalPolicyCallback<'env>>,
    /// Called once per replaced finding. Omit to use the core's default
    /// `<SECRET_N>` formatter.
    #[napi(ts_type = "(finding: JsFinding, context: JsPlaceholderContext) => string")]
    pub formatter: Option<FormatterCallback<'env>>,
    /// The bytes of a revision 1 declarative action policy document
    /// (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`,
    /// issue #1219). Parsed once here, at construction; the compiled policy
    /// is owned by the session. Giving it together with `policy` is
    /// `INVALID_OPTIONS`; a rejected document is `INVALID_ACTION_POLICY`.
    pub action_policy: Option<Buffer>,
}

fn to_core_limits(limits: &JsIncrementalLimits) -> Result<IncrementalLimits, CoreError> {
    IncrementalLimits::new(
        limits.max_input_code_units as usize,
        limits.max_buffered_code_units as usize,
        limits.max_token_code_units as usize,
        limits.max_multiline_code_units as usize,
    )
}

/// A bounded incremental sanitization session over the built-in detectors.
///
/// Lifecycle: a session starts `accepting` and accepts `append`,
/// `finalize`, and `abort`. Exactly one successful `finalize` moves it to
/// `finalized`; `abort` moves it to `aborted`; any limit, detector, policy,
/// or placeholder failure moves it to `failed`. All three are terminal:
/// every later operation raises `INVALID_STATE`, and every terminal
/// transition discards the plaintext the core still retained.
///
/// A session holds a JavaScript callback reference and Rust state that is
/// not shared between threads: use it from the thread that created it.
#[napi]
pub struct JsIncrementalSanitizer {
    session: IncrementalSanitizer,
    index: Rc<RefCell<Utf16Index>>,
    policy_failure: Rc<Cell<Option<SecretScanErrorCode>>>,
    current_env: Rc<Cell<Option<Env>>>,
}

impl JsIncrementalSanitizer {
    /// Ends the session's offset bookkeeping and maps a core failure to its
    /// sanitized error, preferring the precise code a failing policy
    /// callback recorded over the core's generic `PolicyFailure`.
    fn fail(&mut self, error: CoreError) -> napi::Error<String> {
        self.index.borrow_mut().clear();
        let code = match (error.code(), self.policy_failure.take()) {
            (SecretScanErrorCode::PolicyFailure, Some(recorded)) => recorded,
            (code, _) => code,
        };
        to_js_error(code.into())
    }

    /// Converts one call's result to its JavaScript form and settles the
    /// offset index for the next call.
    fn finish(
        &mut self,
        result: IncrementalResult,
        ended: bool,
    ) -> napi::Result<JsIncrementalResult, String> {
        self.policy_failure.set(None);
        let (text, findings) = result.into_parts();

        let converted: Result<Vec<JsFinding>, CoreError> = {
            let index = self.index.borrow();
            findings
                .iter()
                .map(|finding| {
                    let (start, end) = index
                        .code_unit_range(finding.range())
                        .ok_or(SecretScanErrorCode::InvalidCandidate)?;
                    Ok(JsFinding {
                        id: finding.id().to_owned(),
                        r#type: finding.type_name().to_owned(),
                        detector: finding.detector().to_owned(),
                        confidence: finding.confidence().as_str().to_owned(),
                        action: finding.action().as_str().to_owned(),
                        obfuscation: finding.obfuscation().as_str().to_owned(),
                        start,
                        end,
                    })
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
                Ok(JsIncrementalResult { text, findings })
            }
            // Unreachable while the core keeps its ranges char-aligned and
            // in bounds; an internal inconsistency still ends the session
            // rather than leaving it accepting with no way to convert.
            Err(error) => {
                let _ = self.session.abort();
                self.index.borrow_mut().clear();
                Err(to_js_error(error))
            }
        }
    }

    /// Rejects an operation on a session that has left `accepting`, before
    /// it observes anything.
    fn require_accepting(&self) -> napi::Result<(), String> {
        if matches!(self.session.state(), SessionState::Accepting) {
            Ok(())
        } else {
            Err(to_js_error(SecretScanErrorCode::InvalidState.into()))
        }
    }
}

#[napi]
impl JsIncrementalSanitizer {
    /// The session's lifecycle state: `"accepting"`, `"finalized"`,
    /// `"aborted"`, or `"failed"`.
    #[must_use]
    #[napi(getter)]
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
    // N-API's generated argument conversion produces an owned `String`;
    // there is no borrowed form to take instead (see `lib.rs`'s `scan`).
    #[allow(clippy::needless_pass_by_value)]
    #[napi]
    pub fn append(&mut self, env: Env, chunk: String) -> napi::Result<JsIncrementalResult, String> {
        self.require_accepting()?;
        self.index.borrow_mut().observe(&chunk);
        self.current_env.set(Some(env));
        let outcome = self.session.append(&chunk);
        self.current_env.set(None);
        match outcome {
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
    #[napi]
    pub fn finalize(&mut self, env: Env) -> napi::Result<JsIncrementalResult, String> {
        self.require_accepting()?;
        self.current_env.set(Some(env));
        let outcome = self.session.finalize();
        self.current_env.set(None);
        match outcome {
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
    #[napi]
    pub fn abort(&mut self) -> napi::Result<(), String> {
        self.session.abort().map_err(to_js_error)?;
        self.index.borrow_mut().clear();
        self.policy_failure.set(None);
        Ok(())
    }
}

/// Shared setup for [`create_incremental_sanitizer`] and
/// [`create_incremental_sanitizer_common`]: validates `options.limits`,
/// builds the UTF-16 offset index and callback adapters, then hands the
/// resulting `(limits, policy, formatter)` triple to `constructor` — the only
/// part that differs between the two profiles
/// (`decision-define-detector-profile-and-pack-contract`).
///
/// # Errors
///
/// Returns `INVALID_LIMITS` when `options.limits` is missing, non-positive,
/// or does not satisfy the documented relationship between the four bounds.
/// Otherwise returns whatever `constructor` itself returns, mapped to its
/// sanitized JavaScript error.
fn build(
    options: JsIncrementalOptions<'_>,
    constructor: impl FnOnce(
        IncrementalLimits,
        Box<dyn IncrementalPolicy>,
        Box<dyn PlaceholderFormatter>,
    ) -> Result<IncrementalSanitizer, CoreError>,
) -> napi::Result<JsIncrementalSanitizer, String> {
    let limits = to_core_limits(&options.limits).map_err(to_js_error)?;
    let index = Rc::new(RefCell::new(Utf16Index::new(limits.max_buffered_bytes())));
    let policy_failure = Rc::new(Cell::new(None));
    let current_env: Rc<Cell<Option<Env>>> = Rc::new(Cell::new(None));

    // A callback and an action policy together are host misuse, rejected
    // before the document is read. The document is then loaded once, here:
    // the session owns the compiled policy for its whole life, so no other
    // session or call can change what it evaluates.
    if options.policy.is_some() && options.action_policy.is_some() {
        return Err(to_js_error(SecretScanErrorCode::InvalidOptions.into()));
    }
    let action_policy = match options.action_policy.as_deref() {
        None => None,
        Some(bytes) => Some(load_action_policy(bytes).map_err(to_js_action_policy_error)?),
    };

    let policy: Box<dyn IncrementalPolicy> = match (options.policy, action_policy) {
        (None, Some(overlay)) => Box::new(overlay),
        (None, None) => Box::new(DefaultPolicy),
        (Some(callback), _) => {
            // Unreachable in practice: `callback` is already a validated JS
            // function value by the time N-API decoded `options`, so only an
            // internal engine failure could prevent taking a reference to
            // it.
            let callback_ref = callback
                .create_ref()
                .map_err(|_| to_js_error(SecretScanErrorCode::InvalidOptions.into()))?;
            Box::new(JsIncrementalPolicyAdapter {
                callback: callback_ref,
                index: Rc::clone(&index),
                current_env: Rc::clone(&current_env),
                policy_failure: Rc::clone(&policy_failure),
            })
        }
    };
    let formatter: Box<dyn PlaceholderFormatter> = match options.formatter {
        None => Box::new(core_default_formatter),
        Some(callback) => {
            let callback_ref = callback
                .create_ref()
                .map_err(|_| to_js_error(SecretScanErrorCode::InvalidOptions.into()))?;
            Box::new(JsIncrementalFormatterAdapter {
                callback: callback_ref,
                index: Rc::clone(&index),
                current_env: Rc::clone(&current_env),
            })
        }
    };

    let session = constructor(limits, policy, formatter).map_err(to_js_error)?;

    Ok(JsIncrementalSanitizer {
        session,
        index,
        policy_failure,
        current_env,
    })
}

/// Creates a bounded incremental sanitization session over the `full`
/// built-in detectors (`decision-define-runtime-bindings`).
///
/// `options.policy`, when given, is called once per finalized finding as
/// `(finding: JsDetectedFinding, context: JsIncrementalPolicyContext) =>
/// string`, returning `"redact"`, `"block"`, `"warn"`, or `"allow"`.
/// `options.formatter`, when given, is called once per replaced finding as
/// `(finding: JsFinding, context: JsPlaceholderContext) => string`. Both
/// receive only safe metadata carrying absolute UTF-16 offsets, never the
/// input or a matched value, and both are numbered across the whole session
/// rather than per call.
///
/// # Errors
///
/// Returns `INVALID_LIMITS` when `options.limits` is missing, non-positive,
/// or does not satisfy the documented relationship between the four bounds.
#[napi]
pub fn create_incremental_sanitizer(
    options: JsIncrementalOptions<'_>,
) -> napi::Result<JsIncrementalSanitizer, String> {
    let selection = crate::pii_selection(Profile::Full);
    let detection = crate::detection_selection(Profile::Full);
    build(options, move |limits, policy, formatter| {
        // The session captures the owner's configuration here, once. With no
        // detector selection this is the legacy constructor's registry,
        // byte for byte.
        IncrementalSanitizer::with_built_in_and_pii_detection_policy_and_formatter(
            limits, &selection, &detection, policy, formatter,
        )
    })
}

/// The `common`-profile analogue of [`create_incremental_sanitizer`]
/// (`decision-define-detector-profile-and-pack-contract`): identical except
/// the session is built over the `common` built-in detectors
/// (`IncrementalSanitizer::with_common_built_in_policy_and_formatter`,
/// `crates/secret-scan-core/src/incremental.rs`), whose smaller detector set
/// never emits a provider-only finding.
///
/// # Errors
///
/// The same as [`create_incremental_sanitizer`].
#[napi]
pub fn create_incremental_sanitizer_common(
    options: JsIncrementalOptions<'_>,
) -> napi::Result<JsIncrementalSanitizer, String> {
    let selection = crate::pii_selection(Profile::Common);
    let detection = crate::detection_selection(Profile::Common);
    build(options, move |limits, policy, formatter| {
        IncrementalSanitizer::with_common_built_in_and_pii_detection_policy_and_formatter(
            limits, &selection, &detection, policy, formatter,
        )
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

    fn default_session() -> IncrementalSanitizer {
        IncrementalSanitizer::new(generous_limits()).unwrap()
    }

    /// [`generous_limits`], in the wire shape [`create_incremental_sanitizer_common`]
    /// (and [`create_incremental_sanitizer`]) accept.
    // `generous_limits`'s values are small fixed test constants, always in
    // range; the fallible-looking cast is the wire shape's own `u32`, not a
    // real truncation risk.
    #[allow(clippy::cast_possible_truncation)]
    fn generous_js_limits() -> JsIncrementalLimits {
        let limits = generous_limits();
        JsIncrementalLimits {
            max_input_code_units: limits.max_input_bytes() as u32,
            max_buffered_code_units: limits.max_buffered_bytes() as u32,
            max_token_code_units: limits.max_token_bytes() as u32,
            max_multiline_code_units: limits.max_multiline_bytes() as u32,
        }
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
        let limits = JsIncrementalLimits {
            max_input_code_units: 1_048_576,
            max_buffered_code_units: 16_512,
            max_token_code_units: 8_192,
            max_multiline_code_units: 16_384,
        };
        let core = to_core_limits(&limits).unwrap();
        assert_eq!(core.max_input_bytes(), 1_048_576);
        assert_eq!(core.max_buffered_bytes(), 16_512);
        assert_eq!(core.max_token_bytes(), 8_192);
        assert_eq!(core.max_multiline_bytes(), 16_384);
    }

    #[test]
    fn invalid_limits_are_rejected() {
        let limits = JsIncrementalLimits {
            max_input_code_units: 0,
            max_buffered_code_units: 16_512,
            max_token_code_units: 8_192,
            max_multiline_code_units: 16_384,
        };
        assert_eq!(
            to_core_limits(&limits).unwrap_err().code(),
            SecretScanErrorCode::InvalidLimits
        );
    }

    // ---------------------------------------------------------------
    // Session lifecycle (against the core directly; the N-API surface
    // itself is exercised through `packages/javascript`'s own contract
    // tests, which cannot load the compiled addon from a source checkout).
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

    /// A `common`-profile incremental session, built through
    /// [`create_incremental_sanitizer_common`] itself rather than the core's
    /// `IncrementalSanitizer::with_common_built_in` directly, so this proves
    /// the binding's constructor — not just the core — wires the `common`
    /// profile through. `common` links no `provider` detector, so a bare
    /// provider-shaped token with no credential-bearing context is never
    /// emitted as a finding — the same false-negative cost `lib.rs`'s
    /// `a_bare_provider_token_is_detected_only_by_the_full_profile`
    /// documents for the synchronous path. Mirrors
    /// `crates/secret-scan-core/src/incremental.rs::full_and_common_sessions_report_the_profile_they_were_built_from`
    /// in spirit.
    ///
    /// `append`/`finalize` normally take an `Env`, which only exists inside
    /// a real N-API call; with no JS policy or formatter callback supplied,
    /// the session never needs it, so this drives its underlying
    /// `IncrementalSanitizer` — the one the binding itself built — directly.
    #[test]
    fn a_common_incremental_session_never_emits_a_provider_only_finding() {
        let options = JsIncrementalOptions {
            limits: generous_js_limits(),
            policy: None,
            formatter: None,
            action_policy: None,
        };
        let mut sanitizer = create_incremental_sanitizer_common(options).unwrap();
        let input = format!("prefix \u{1F511} AKIA{} suffix", "SYNTHETICEXAMPLE");
        let mut findings = Vec::new();
        let (_, released) = sanitizer.session.append(&input).unwrap().into_parts();
        findings.extend(released);
        let (_, released) = sanitizer.session.finalize().unwrap().into_parts();
        findings.extend(released);
        assert!(findings.is_empty());
    }

    fn action_policy_options(document: &[u8]) -> JsIncrementalOptions<'static> {
        JsIncrementalOptions {
            limits: generous_js_limits(),
            policy: None,
            formatter: None,
            action_policy: Some(Buffer::from(document)),
        }
    }

    /// Every action the session assigns across `chunks`, in order.
    fn session_actions(sanitizer: &mut JsIncrementalSanitizer, chunks: &[&str]) -> Vec<Action> {
        let mut actions = Vec::new();
        for chunk in chunks {
            let (_, released) = sanitizer.session.append(chunk).unwrap().into_parts();
            actions.extend(released.iter().map(Finding::action));
        }
        let (_, released) = sanitizer.session.finalize().unwrap().into_parts();
        actions.extend(released.iter().map(Finding::action));
        actions
    }

    /// An incremental session evaluates the action policy it was built with,
    /// at every partition of the input, and two live sessions of different
    /// policies do not affect each other, in either construction order
    /// (issue #1219: no process-global policy slot).
    #[test]
    fn a_session_binds_the_action_policy_it_was_constructed_with() {
        const WARN: &[u8] = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"warn-github","match":{"type":["github_token"]},"action":"warn"}]}"#;
        const ALLOW: &[u8] = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"allow-github","match":{"type":["github_token"]},"action":"allow"}]}"#;
        let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
        for split in 1..input.len() {
            let (head, tail) = input.split_at(split);
            let mut warn = create_incremental_sanitizer(action_policy_options(WARN)).unwrap();
            let mut allow = create_incremental_sanitizer(action_policy_options(ALLOW)).unwrap();
            let mut default = create_incremental_sanitizer(JsIncrementalOptions {
                limits: generous_js_limits(),
                policy: None,
                formatter: None,
                action_policy: None,
            })
            .unwrap();
            assert_eq!(session_actions(&mut warn, &[head, tail]), [Action::Warn]);
            assert_eq!(session_actions(&mut allow, &[head, tail]), [Action::Allow]);
            assert_eq!(
                session_actions(&mut default, &[head, tail]),
                [Action::Redact]
            );
        }
    }

    #[test]
    fn a_rejected_action_policy_fails_session_construction() {
        let error = create_incremental_sanitizer(action_policy_options(b"{}"))
            .err()
            .expect("expected an error");
        assert_eq!(error.status, "INVALID_ACTION_POLICY");
        assert_eq!(
            error.reason,
            "The supplied action policy is invalid. (MISSING_FIELD)"
        );
    }
}
