//! Bounded incremental sanitizer session.
//!
//! A session consumes text in chunks and returns, from each [`append`] and
//! from [`finalize`], only the sanitized text and findings whose detection
//! window is closed: a chunk boundary, a minimum token length, or a
//! provisional match is never a closing boundary by itself. An open logical
//! line, structural authorization header, contextual assignment, PEM-style
//! private-key block, or Heroku `.netrc` entry or `heroku auth:token`
//! command awaiting its token line is retained until it closes or a
//! configured limit fails. Because retained plaintext is scanned fresh only once per
//! closed unit and never rescanned once finalized, whole-input acceptance
//! does not depend on how the caller partitions it into chunks.
//!
//! The state machine has four terminally distinct states: `accepting` may
//! receive [`append`], `finalize` (exactly once), or [`abort`]; `finalized`,
//! `aborted`, and `failed` are terminal and reject every further call. A
//! limit, detector, policy, or placeholder failure discards retained
//! plaintext and enters `failed`.
//!
//! # Partition invariance
//!
//! For every input this API accepts, the concatenated text, the findings and
//! their actions, their order, IDs and absolute UTF-8 byte ranges, and
//! placeholder numbering are identical to the whole-input reference
//! ([`scan`](crate::scan) then [`redact`](crate::redact)) at every partition
//! of that input — at every UTF-8 byte boundary and at every host-native
//! `&str` boundary. Only the distribution of safe output across [`append`]
//! and [`finalize`] results varies; what those results concatenate to does
//! not. `tests/incremental_partitions.rs` enumerates both boundary kinds
//! over the canonical corpus in `conformance/fixtures/incremental-corpus.json`,
//! and `tests/adversarial_bounds.rs` holds the adversarial tier of
//! `conformance/fixtures/synchronous-corpus.json` to its declared input,
//! finding-count, and runtime caps.
//!
//! # Unsupported extensions
//!
//! Two whole-input capabilities are deliberately outside this API, because
//! neither can be evaluated before the end of the input is known:
//!
//! - **Custom synchronous detectors.** No constructor accepts a
//!   [`DetectorRegistry`]; a session always runs one profile's built-in
//!   detectors only — [`IncrementalSanitizer::new`] and
//!   [`IncrementalSanitizer::with_policy_and_formatter`] select `full`,
//!   [`IncrementalSanitizer::with_common_built_in`] and
//!   [`IncrementalSanitizer::with_common_built_in_policy_and_formatter`]
//!   select `common`
//!   (`decision-define-detector-profile-and-pack-contract`). A custom
//!   [`Detector`](crate::Detector) carries no retention declaration, so a
//!   session could not bound how long it must hold an open construct for
//!   it. Register custom detectors on the whole-input [`scan`](crate::scan)
//!   path instead.
//! - **Whole-input count-dependent policies.** [`PolicyContext`] carries the
//!   total finalized finding count; [`IncrementalPolicyContext`]
//!   deliberately does not, because a progressive evaluation cannot know how
//!   many findings the whole session will produce. A [`Policy`] whose action
//!   depends on [`PolicyContext::finding_count`] therefore has no
//!   incremental equivalent: adapting it to [`IncrementalPolicy`] must
//!   substitute the running index, which yields a different result. Policies
//!   used incrementally must be count-independent, as [`DefaultPolicy`] is.
//!
//! [`append`]: IncrementalSanitizer::append
//! [`finalize`]: IncrementalSanitizer::finalize
//! [`abort`]: IncrementalSanitizer::abort

use std::collections::HashMap;

use crate::detectors::{
    PrivateKeyRetentionTracker, has_open_bearer_authorization, has_open_contextual_assignment,
    has_open_heroku_legacy_context,
};
use crate::error::{FormatterFailure, PolicyFailure, SecretScanError, SecretScanErrorCode};
use crate::normalize::NormalizedInput;
use crate::pipeline::run_detector_pipeline;
use crate::policy::DefaultPolicy;
use crate::redact::{default_placeholder_formatter, redact};
use crate::registry::{DetectorRegistry, Profile};
use crate::types::{
    Action, ByteRange, DetectedFinding, Finding, PlaceholderContext, PlaceholderFormatter, Policy,
    PolicyContext, ScanResult,
};

/// Reserve in bytes for the longest built-in fixed match and its boundary
/// lookaround, that `max_buffered_bytes` must accommodate on top of the
/// larger of `max_token_bytes` and `max_multiline_bytes`.
///
/// This is retention tuning, not a public contract: it tracks the built-in
/// detector set and changes with it. Callers ask
/// [`IncrementalLimits::minimum_buffered_bytes`] for the derived requirement
/// instead of reproducing this arithmetic.
const LOOKAROUND_BYTES: usize = 128;

/// The built-in detector whose multi-line `.netrc` and `heroku auth:token`
/// layouts need a retention hint; a session whose profile omits it (the
/// `common` profile) never holds a unit open for them.
const HEROKU_LEGACY_DETECTOR_ID: &str = "heroku-api-key-legacy";

/// Explicit, positive byte limits every incremental session requires. There
/// are no environment-derived or silent defaults.
///
/// `max_buffered_bytes` must be at least
/// [`minimum_buffered_bytes`](Self::minimum_buffered_bytes) for the construct
/// limits it accompanies. A construct that reaches its limit without a
/// closing boundary is not reclassified as ordinary text: the session fails
/// before any of its bytes are emitted.
///
/// # Examples
///
/// ```
/// use redact_secret::IncrementalLimits;
///
/// let (token, multiline) = (4_096, 16_384);
/// let limits = IncrementalLimits::new(
///     1 << 20,
///     IncrementalLimits::minimum_buffered_bytes(token, multiline),
///     token,
///     multiline,
/// )?;
/// assert_eq!(limits.max_token_bytes(), token);
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::struct_field_names)]
pub struct IncrementalLimits {
    max_input_bytes: usize,
    max_buffered_bytes: usize,
    max_token_bytes: usize,
    max_multiline_bytes: usize,
}

impl IncrementalLimits {
    /// The smallest `max_buffered_bytes` [`new`](Self::new) accepts
    /// alongside these construct limits: the larger of the two plus the
    /// boundary lookaround the built-in detectors need to decide whether a
    /// construct is still open.
    ///
    /// The lookaround reserve itself is an implementation detail that tracks
    /// the built-in detector set. Deriving the limit through this function
    /// keeps a caller correct when that reserve changes.
    #[must_use]
    pub const fn minimum_buffered_bytes(
        max_token_bytes: usize,
        max_multiline_bytes: usize,
    ) -> usize {
        let construct_max = if max_token_bytes > max_multiline_bytes {
            max_token_bytes
        } else {
            max_multiline_bytes
        };
        construct_max.saturating_add(LOOKAROUND_BYTES)
    }

    /// Validates and creates a limit set.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidLimits`] when any limit is
    /// zero, when `max_token_bytes` or `max_multiline_bytes` exceeds
    /// `max_input_bytes`, or when `max_buffered_bytes` is below
    /// [`minimum_buffered_bytes`](Self::minimum_buffered_bytes).
    pub fn new(
        max_input_bytes: usize,
        max_buffered_bytes: usize,
        max_token_bytes: usize,
        max_multiline_bytes: usize,
    ) -> Result<Self, SecretScanError> {
        let construct_max = max_token_bytes.max(max_multiline_bytes);
        let invalid = max_input_bytes == 0
            || max_buffered_bytes == 0
            || max_token_bytes == 0
            || max_multiline_bytes == 0
            || max_token_bytes > max_input_bytes
            || max_multiline_bytes > max_input_bytes
            || construct_max > usize::MAX - LOOKAROUND_BYTES
            || max_buffered_bytes
                < Self::minimum_buffered_bytes(max_token_bytes, max_multiline_bytes);
        if invalid {
            return Err(SecretScanErrorCode::InvalidLimits.into());
        }
        Ok(Self {
            max_input_bytes,
            max_buffered_bytes,
            max_token_bytes,
            max_multiline_bytes,
        })
    }

    /// Total logical input this session accepts across every `append` call.
    #[must_use]
    pub const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }

    /// Unresolved plaintext this session may retain but not yet have
    /// emitted.
    #[must_use]
    pub const fn max_buffered_bytes(self) -> usize {
        self.max_buffered_bytes
    }

    /// Bound for an open logical line, single-line credential, or other
    /// delimiter-terminated token.
    #[must_use]
    pub const fn max_token_bytes(self) -> usize {
        self.max_token_bytes
    }

    /// Bound for an open PEM-style private-key block.
    #[must_use]
    pub const fn max_multiline_bytes(self) -> usize {
        self.max_multiline_bytes
    }
}

/// Position information an incremental policy receives.
///
/// Unlike [`PolicyContext`], there is no total finding count: progressive
/// evaluation cannot know how many findings the whole session will
/// eventually produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IncrementalPolicyContext {
    finding_index: usize,
}

impl IncrementalPolicyContext {
    /// Creates a context for the given zero-based finalized finding index.
    #[must_use]
    pub const fn new(finding_index: usize) -> Self {
        Self { finding_index }
    }

    /// Zero-based position among findings finalized so far in this session.
    #[must_use]
    pub const fn finding_index(self) -> usize {
        self.finding_index
    }
}

/// Maps a finalized finding to an [`Action`] within an incremental session.
///
/// A policy never sees the input, a matched value, or a total finding
/// count.
pub trait IncrementalPolicy {
    /// Chooses the action for `finding`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyFailure`] on any internal failure. The session
    /// reports it as [`SecretScanErrorCode::PolicyFailure`] and fails.
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &IncrementalPolicyContext,
    ) -> Result<Action, PolicyFailure>;
}

impl<F> IncrementalPolicy for F
where
    F: Fn(&DetectedFinding, &IncrementalPolicyContext) -> Result<Action, PolicyFailure>,
{
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &IncrementalPolicyContext,
    ) -> Result<Action, PolicyFailure> {
        self(finding, context)
    }
}

/// The default incremental policy has the same action mapping as
/// [`DefaultPolicy`]'s whole-input evaluation: it does not depend on
/// [`PolicyContext`], so adapting it to [`IncrementalPolicyContext`] changes
/// nothing observable.
impl IncrementalPolicy for DefaultPolicy {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        _context: &IncrementalPolicyContext,
    ) -> Result<Action, PolicyFailure> {
        Policy::evaluate(self, finding, &PolicyContext::new(0, 0))
    }
}

/// The terminally distinct lifecycle states of an [`IncrementalSanitizer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// May receive `append`, `finalize`, or `abort`.
    Accepting,
    /// Reached by exactly one successful `finalize`. Terminal.
    Finalized,
    /// Reached by `abort`. Terminal.
    Aborted,
    /// Reached by a limit, detector, policy, or placeholder failure.
    /// Terminal.
    Failed,
}

/// The sanitized text and final findings produced by one `append` or
/// `finalize` call.
///
/// This is [`ScanResult`] under the name the incremental API reports it by:
/// the whole-input and chunked paths return the same shape, so a host can
/// carry one result type. [`text`](ScanResult::text) is the safe output this
/// call releases — concatenating every `append`/`finalize` result's text, in
/// call order, reconstructs the whole sanitized output — and
/// [`findings`](ScanResult::findings) are the findings this call finalized,
/// with absolute UTF-8 byte offsets into the logical whole-session input.
pub type IncrementalResult = ScanResult;

/// Finds the byte offset of the next `\n` or `\r` at or after `from`, or
/// `None` when `chunk` has no more line terminators.
fn find_next_newline(chunk: &str, from: usize) -> Option<usize> {
    chunk.as_bytes()[from..]
        .iter()
        .position(|&byte| byte == b'\n' || byte == b'\r')
        .map(|index| index + from)
}

/// A bounded, side-effect-free incremental sanitizer session over built-in
/// detectors. Custom detectors are not accepted: each has no retention
/// declaration, so the session cannot bound what it must hold open.
///
/// # Examples
///
/// ```
/// use redact_secret::{IncrementalLimits, IncrementalSanitizer, SessionState};
///
/// let (token, multiline) = (8_192, 16_384);
/// let limits = IncrementalLimits::new(
///     1 << 20,
///     IncrementalLimits::minimum_buffered_bytes(token, multiline),
///     token,
///     multiline,
/// )?;
/// let mut session = IncrementalSanitizer::new(limits)?;
///
/// let mut output = String::new();
/// // A value split across chunks is held until its detection window closes.
/// for chunk in ["API_KEY=ghp_SYNTHETIC", "REVOKED00000000000000000000\ntail"] {
///     output.push_str(session.append(chunk)?.text());
/// }
/// output.push_str(session.finalize()?.text());
///
/// assert_eq!(output, "API_KEY=<SECRET_1>\ntail");
/// assert_eq!(session.state(), SessionState::Finalized);
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
pub struct IncrementalSanitizer {
    registry: DetectorRegistry,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
    limits: IncrementalLimits,
    state: SessionState,
    retained: String,
    finalized_bytes: usize,
    total_input_bytes: usize,
    finding_count: usize,
    placeholder_count: usize,
    private_key: PrivateKeyRetentionTracker,
    multiline_open: bool,
    multiline_detected: bool,
}

impl std::fmt::Debug for IncrementalSanitizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncrementalSanitizer")
            .field("state", &self.state)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl IncrementalSanitizer {
    /// Creates a session using [`DefaultPolicy`] and
    /// [`default_placeholder_formatter`].
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] only if the
    /// built-in detector registry itself is malformed, which cannot happen
    /// for the detectors this crate ships.
    pub fn new(limits: IncrementalLimits) -> Result<Self, SecretScanError> {
        Self::with_policy_and_formatter(
            limits,
            Box::new(DefaultPolicy),
            Box::new(default_placeholder_formatter),
        )
    }

    /// Creates a session with an explicit policy and placeholder formatter.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] only if the
    /// built-in detector registry itself is malformed, which cannot happen
    /// for the detectors this crate ships.
    pub fn with_policy_and_formatter(
        limits: IncrementalLimits,
        policy: Box<dyn IncrementalPolicy>,
        formatter: Box<dyn PlaceholderFormatter>,
    ) -> Result<Self, SecretScanError> {
        let registry = DetectorRegistry::with_built_in([])?;
        Ok(Self::from_registry(registry, limits, policy, formatter))
    }

    /// Creates a session over the `common` profile's built-in detectors
    /// (`decision-define-detector-profile-and-pack-contract`), using
    /// [`DefaultPolicy`] and [`default_placeholder_formatter`].
    ///
    /// The whole-input and incremental paths select their built-in
    /// detectors the same way: this constructor pairs with
    /// [`DetectorRegistry::with_common_built_in`] exactly as [`Self::new`]
    /// pairs with [`DetectorRegistry::with_built_in`].
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] only if the
    /// built-in detector registry itself is malformed, which cannot happen
    /// for the detectors this crate ships.
    pub fn with_common_built_in(limits: IncrementalLimits) -> Result<Self, SecretScanError> {
        Self::with_common_built_in_policy_and_formatter(
            limits,
            Box::new(DefaultPolicy),
            Box::new(default_placeholder_formatter),
        )
    }

    /// Creates a session over the `common` profile's built-in detectors,
    /// with an explicit policy and placeholder formatter.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] only if the
    /// built-in detector registry itself is malformed, which cannot happen
    /// for the detectors this crate ships.
    pub fn with_common_built_in_policy_and_formatter(
        limits: IncrementalLimits,
        policy: Box<dyn IncrementalPolicy>,
        formatter: Box<dyn PlaceholderFormatter>,
    ) -> Result<Self, SecretScanError> {
        let registry = DetectorRegistry::with_common_built_in([])?;
        Ok(Self::from_registry(registry, limits, policy, formatter))
    }

    fn from_registry(
        registry: DetectorRegistry,
        limits: IncrementalLimits,
        policy: Box<dyn IncrementalPolicy>,
        formatter: Box<dyn PlaceholderFormatter>,
    ) -> Self {
        Self {
            registry,
            policy,
            formatter,
            limits,
            state: SessionState::Accepting,
            retained: String::new(),
            finalized_bytes: 0,
            total_input_bytes: 0,
            finding_count: 0,
            placeholder_count: 0,
            private_key: PrivateKeyRetentionTracker::new(),
            multiline_open: false,
            multiline_detected: false,
        }
    }

    /// The session's current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Which profile this session's built-in detectors were selected from.
    #[must_use]
    pub const fn profile(&self) -> Option<Profile> {
        self.registry.profile()
    }

    fn require_accepting(&self) -> Result<(), SecretScanError> {
        if matches!(self.state, SessionState::Accepting) {
            Ok(())
        } else {
            Err(SecretScanErrorCode::InvalidState.into())
        }
    }

    /// Discards retained plaintext and every parser state derived from it.
    ///
    /// The buffer is released rather than truncated: `clear` would leave the
    /// discarded bytes alive in a reusable allocation, and the retention
    /// contract is to drop them.
    fn discard_retained(&mut self) {
        self.retained = String::new();
        self.private_key.reset();
        self.multiline_open = false;
        self.multiline_detected = false;
    }

    /// Finishes a unit whose text and findings have been produced: its bytes
    /// become finalized input that advances absolute offsets, and the
    /// plaintext behind them is discarded.
    fn finish_unit(&mut self) {
        self.finalized_bytes += self.retained.len();
        self.discard_retained();
    }

    /// Discards retained plaintext and parser state and transitions to
    /// `failed`, returning `error` unchanged so callers can propagate it
    /// with `return Err(self.fail_with(error))`.
    fn fail_with(&mut self, error: SecretScanError) -> SecretScanError {
        self.discard_retained();
        self.state = SessionState::Failed;
        error
    }

    /// Judges the retained text the way [`process_unit`](Self::process_unit)
    /// will scan it: on the scan copy. Judged on the raw buffer, a keyword
    /// split by an invisible code point at a line end would not read as an
    /// open construct, the unit would close early, and the same input would
    /// yield different findings under a different partition.
    fn has_open_single_line_construct(&self) -> bool {
        let scanned = NormalizedInput::new(&self.retained).into_text();
        has_open_contextual_assignment(&scanned)
            || has_open_bearer_authorization(&scanned)
            || (self.registry.contains(HEROKU_LEGACY_DETECTOR_ID)
                && has_open_heroku_legacy_context(&scanned))
    }

    fn append_retained(&mut self, piece: &str, closes_line: bool) -> Result<(), SecretScanError> {
        self.retained.push_str(piece);
        // The tracker reads delimiters from the scan copy, as the detector
        // will. A piece is whole code points, so normalizing piece by piece
        // equals normalizing the unit. Only the tracker sees the copy: every
        // limit below is a memory bound and stays measured in original bytes.
        let (has_begin, has_open) = self
            .private_key
            .append(&NormalizedInput::new(piece).into_text());
        self.multiline_detected |= has_begin;
        self.multiline_open = has_open;

        let construct_limit = if self.multiline_detected {
            self.limits.max_multiline_bytes()
        } else {
            self.limits.max_token_bytes()
        };
        let open_length = if closes_line {
            self.retained.len() - 1
        } else {
            self.retained.len()
        };
        if open_length > construct_limit {
            let code = if self.multiline_detected {
                SecretScanErrorCode::MultilineLimitExceeded
            } else {
                SecretScanErrorCode::TokenLimitExceeded
            };
            return Err(self.fail_with(code.into()));
        }
        if self.retained.len() > self.limits.max_buffered_bytes() {
            return Err(self.fail_with(SecretScanErrorCode::BufferLimitExceeded.into()));
        }
        Ok(())
    }

    /// Runs detection, policy, and redaction over `self.retained` as one
    /// closed unit, without mutating any lifecycle or retention state.
    /// Callers finish the unit (advance `finalized_bytes`, clear retained
    /// state) on success, or call [`fail_with`](Self::fail_with) on error.
    fn process_unit(&mut self) -> Result<IncrementalResult, SecretScanError> {
        let input_offset = self.finalized_bytes;
        let detected = run_detector_pipeline(&self.retained, &self.registry)?;

        let mut findings: Vec<Finding> = Vec::with_capacity(detected.len());
        for local in &detected {
            let range = local.range();
            let global_range =
                ByteRange::new(range.start() + input_offset, range.end() + input_offset)
                    .ok_or_else(|| SecretScanError::from(SecretScanErrorCode::InvalidCandidate))?;
            let global_id = format!("finding-{}", self.finding_count + 1);
            let global_detected = DetectedFinding::new(
                global_id,
                local.type_name(),
                local.detector(),
                local.confidence(),
                global_range,
            )?
            .with_obfuscation(local.obfuscation());
            let context = IncrementalPolicyContext::new(self.finding_count);
            let action = self
                .policy
                .evaluate(&global_detected, &context)
                .map_err(|_| SecretScanError::from(SecretScanErrorCode::PolicyFailure))?;
            findings.push(global_detected.with_action(action));
            self.finding_count += 1;
        }

        let local_findings: Vec<Finding> = findings
            .iter()
            .map(|finding| {
                let range = finding.range();
                let local_range =
                    ByteRange::new(range.start() - input_offset, range.end() - input_offset)
                        .ok_or_else(|| {
                            SecretScanError::from(SecretScanErrorCode::InvalidCandidate)
                        })?;
                Ok(DetectedFinding::new(
                    finding.id(),
                    finding.type_name(),
                    finding.detector(),
                    finding.confidence(),
                    local_range,
                )?
                .with_obfuscation(finding.obfuscation())
                .with_action(finding.action()))
            })
            .collect::<Result<Vec<_>, SecretScanError>>()?;

        let by_id: HashMap<&str, &Finding> = findings
            .iter()
            .map(|finding| (finding.id(), finding))
            .collect();
        let placeholder_offset = self.placeholder_count;
        let formatter = self.formatter.as_ref();
        let wrapped = |local_finding: &Finding, local_context: &PlaceholderContext| {
            let Some(global_finding) = by_id.get(local_finding.id()) else {
                return Err(FormatterFailure);
            };
            let global_context =
                PlaceholderContext::new(placeholder_offset + local_context.placeholder_index());
            formatter.format(global_finding, &global_context)
        };

        let text = redact(&self.retained, &local_findings, &wrapped)?;

        self.placeholder_count += findings
            .iter()
            .filter(|finding| finding.action().replaces_text())
            .count();

        Ok(IncrementalResult::new(text, findings))
    }

    /// Appends `chunk` to the logical input.
    ///
    /// Returns only text and findings whose detection window is closed: a
    /// complete logical line with no open single-line construct or private
    /// key block. Remaining retained plaintext is held until a later
    /// `append` closes it or `finalize` supplies the end-of-input boundary.
    ///
    /// # Errors
    ///
    /// - [`SecretScanErrorCode::InvalidState`] outside the `accepting`
    ///   state.
    /// - [`SecretScanErrorCode::InputLimitExceeded`] when accepting `chunk`
    ///   would exceed `max_input_bytes`.
    /// - [`SecretScanErrorCode::BufferLimitExceeded`],
    ///   [`SecretScanErrorCode::TokenLimitExceeded`], or
    ///   [`SecretScanErrorCode::MultilineLimitExceeded`] when retained
    ///   plaintext exceeds the applicable limit.
    /// - [`SecretScanErrorCode::DetectorFailure`],
    ///   [`SecretScanErrorCode::InvalidCandidate`],
    ///   [`SecretScanErrorCode::PolicyFailure`],
    ///   [`SecretScanErrorCode::PlaceholderFailure`], or
    ///   [`SecretScanErrorCode::InvalidPlaceholder`] when finalizing a
    ///   closed unit fails.
    ///
    /// Every error discards retained plaintext and enters `failed`; no
    /// error carries input or a matched value.
    pub fn append(&mut self, chunk: &str) -> Result<IncrementalResult, SecretScanError> {
        self.require_accepting()?;

        let remaining = self
            .limits
            .max_input_bytes()
            .saturating_sub(self.total_input_bytes);
        if chunk.len() > remaining {
            return Err(self.fail_with(SecretScanErrorCode::InputLimitExceeded.into()));
        }
        self.total_input_bytes += chunk.len();

        let mut emitted = String::new();
        let mut findings = Vec::new();
        let mut cursor = 0usize;
        while cursor < chunk.len() {
            let Some(newline) = find_next_newline(chunk, cursor) else {
                self.append_retained(&chunk[cursor..], false)?;
                break;
            };
            self.append_retained(&chunk[cursor..=newline], true)?;

            if !self.multiline_open && !self.has_open_single_line_construct() {
                match self.process_unit() {
                    Ok(result) => {
                        self.finish_unit();
                        let (text, unit_findings) = result.into_parts();
                        emitted.push_str(&text);
                        findings.extend(unit_findings);
                    }
                    Err(error) => return Err(self.fail_with(error)),
                }
            }
            cursor = newline + 1;
        }
        Ok(IncrementalResult::new(emitted, findings))
    }

    /// Supplies the end-of-input boundary, finalizing any remaining
    /// retained plaintext. May be called exactly once, from the `accepting`
    /// state.
    ///
    /// # Errors
    ///
    /// The same codes as [`append`](Self::append), for finalizing the last
    /// retained unit, plus [`SecretScanErrorCode::InvalidState`] outside
    /// the `accepting` state (including a second `finalize`).
    pub fn finalize(&mut self) -> Result<IncrementalResult, SecretScanError> {
        self.require_accepting()?;
        match self.process_unit() {
            Ok(result) => {
                self.finish_unit();
                self.state = SessionState::Finalized;
                Ok(result)
            }
            Err(error) => Err(self.fail_with(error)),
        }
    }

    /// Discards retained plaintext and emits no further text or findings.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidState`] outside the
    /// `accepting` state.
    pub fn abort(&mut self) -> Result<(), SecretScanError> {
        self.require_accepting()?;
        self.discard_retained();
        self.state = SessionState::Aborted;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Marker for a retained, unresolved value. It is not credential-shaped
    /// on its own; the surrounding assignment is what a detector matches.
    const MARKER: &str = "SYNTHETIC_REVOKED_RETENTION_MARKER";

    fn generous_limits() -> IncrementalLimits {
        IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap()
    }

    fn session_with(
        policy: Box<dyn IncrementalPolicy>,
        formatter: Box<dyn PlaceholderFormatter>,
    ) -> IncrementalSanitizer {
        IncrementalSanitizer::with_policy_and_formatter(generous_limits(), policy, formatter)
            .unwrap()
    }

    fn default_session() -> IncrementalSanitizer {
        session_with(
            Box::new(DefaultPolicy),
            Box::new(default_placeholder_formatter),
        )
    }

    /// Every discarding transition must leave the session holding no
    /// plaintext and no parser state derived from it.
    fn assert_nothing_retained(sanitizer: &IncrementalSanitizer) {
        assert_eq!(sanitizer.retained, "");
        assert_eq!(sanitizer.retained.capacity(), 0);
        assert!(!sanitizer.multiline_open);
        assert!(!sanitizer.multiline_detected);
    }

    #[test]
    fn abort_discards_an_open_construct() {
        let mut sanitizer = default_session();
        sanitizer.append(&format!("api_key={MARKER}")).unwrap();
        assert!(sanitizer.retained.contains(MARKER));

        sanitizer.abort().unwrap();

        assert_eq!(sanitizer.state, SessionState::Aborted);
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn abort_discards_an_open_private_key_block() {
        let mut sanitizer = default_session();
        sanitizer
            .append(&format!("-----BEGIN PRIVATE KEY-----\n{MARKER}\n"))
            .unwrap();
        assert!(sanitizer.multiline_open);

        sanitizer.abort().unwrap();

        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn a_limit_failure_discards_the_construct_that_reached_it() {
        let limits = IncrementalLimits::new(1_000_000, 160, 32, 32).unwrap();
        let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();

        let error = sanitizer.append(&format!("api_key={MARKER}")).unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::TokenLimitExceeded);
        assert_eq!(sanitizer.state, SessionState::Failed);
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn an_input_limit_failure_discards_everything_retained_so_far() {
        let limits = IncrementalLimits::new(64, 200, 32, 32).unwrap();
        let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
        sanitizer.append("api_key").unwrap();
        assert_eq!(sanitizer.retained, "api_key");

        let error = sanitizer.append(&"x".repeat(64)).unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::InputLimitExceeded);
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn a_policy_failure_discards_the_unit_it_was_evaluating() {
        let failing = |_: &DetectedFinding, _: &IncrementalPolicyContext| Err(PolicyFailure);
        let mut sanitizer =
            session_with(Box::new(failing), Box::new(default_placeholder_formatter));

        let error = sanitizer
            .append(&format!("api_key={MARKER}\n"))
            .unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::PolicyFailure);
        assert_eq!(sanitizer.state, SessionState::Failed);
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn a_formatter_failure_discards_the_unit_it_was_redacting() {
        let failing = |_: &Finding, _: &PlaceholderContext| Err(FormatterFailure);
        let mut sanitizer = session_with(Box::new(DefaultPolicy), Box::new(failing));

        let error = sanitizer
            .append(&format!("api_key={MARKER}\n"))
            .unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::PlaceholderFailure);
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn an_invalid_placeholder_discards_the_unit_it_was_redacting() {
        let reproducing = |_: &Finding, _: &PlaceholderContext| Ok(MARKER.to_string());
        let mut sanitizer = session_with(Box::new(DefaultPolicy), Box::new(reproducing));

        let error = sanitizer
            .append(&format!("api_key={MARKER}\n"))
            .unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::InvalidPlaceholder);
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn a_state_failure_leaves_nothing_retained_to_discard() {
        let mut sanitizer = default_session();
        sanitizer.append(&format!("api_key={MARKER}")).unwrap();
        sanitizer.abort().unwrap();

        let error = sanitizer.append("ignored").unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
        assert_eq!(sanitizer.state, SessionState::Aborted);
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn a_finalized_unit_is_discarded_once_its_offsets_are_recorded() {
        let mut sanitizer = default_session();
        let unit = format!("api_key={MARKER}\n");

        sanitizer.append(&unit).unwrap();

        assert_eq!(sanitizer.finalized_bytes, unit.len());
        assert_nothing_retained(&sanitizer);
    }

    #[test]
    fn the_debug_representation_never_carries_retained_plaintext() {
        let mut sanitizer = default_session();
        sanitizer.append(&format!("api_key={MARKER}")).unwrap();

        let rendered = format!("{sanitizer:?}");

        assert!(!rendered.contains(MARKER));
        assert!(rendered.starts_with("IncrementalSanitizer {"));
    }

    #[test]
    fn full_and_common_sessions_report_the_profile_they_were_built_from() {
        assert_eq!(default_session().profile(), Some(Profile::Full));
        let common = IncrementalSanitizer::with_common_built_in(generous_limits()).unwrap();
        assert_eq!(common.profile(), Some(Profile::Common));
    }

    // Whether a `common` incremental session's cumulative output matches
    // the whole-input path ([`crate::scan_and_redact`] over a `common`
    // registry) is a public-API-level contract
    // (`decision-define-detector-profile-and-pack-contract`), covered by
    // `tests/public_api.rs`'s
    // `common_profile_incremental_session_selects_the_same_built_ins_as_the_whole_input_path`,
    // not repeated here.
}
