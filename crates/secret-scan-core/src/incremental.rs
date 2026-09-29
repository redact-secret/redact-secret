//! Bounded incremental sanitizer session.
//!
//! A session consumes text in chunks and returns, from each [`append`] and
//! from [`finalize`], only the sanitized text and findings whose detection
//! window is closed: a chunk boundary, a minimum token length, or a
//! provisional match is never a closing boundary by itself. An open logical
//! line, structural authorization header, contextual assignment, PEM-style
//! private-key block, or bounded provider layout awaiting its token line (a
//! Heroku `.netrc` entry, `heroku auth:token` command or `heroku
//! authorizations` table, a `twilio` CLI table with an `Auth Token` column,
//! or a Confluent properties block) is retained until it closes or a
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

use std::borrow::Cow;

use crate::detectors::{
    PrivateKeyRetentionTracker, continues_previous_line, has_open_aws_access_key_id_line,
    has_open_bearer_authorization, has_open_confluent_properties, has_open_contextual_assignment,
    has_open_heroku_legacy_context, has_open_twilio_cli_table, is_open_tail_neutral,
};
use crate::error::{FormatterFailure, PolicyFailure, SecretScanError, SecretScanErrorCode};
#[cfg(test)]
use crate::evidence::shadow::ShadowComparison;
use crate::normalize::NormalizedInput;
use crate::pii::PiiSelection;
#[cfg(test)]
use crate::pipeline::detect;
use crate::pipeline::detect_units;
#[cfg(not(test))]
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

/// The built-in detectors whose previous-line layouts (issue #933) need a
/// retention hint: a `twilio` CLI table's Auth Token column, and a Confluent
/// Schema Registry properties block. A session without the detector never
/// holds a unit open for its layout.
const TWILIO_AUTH_TOKEN_DETECTOR_ID: &str = "twilio-auth-token";
const CONFLUENT_LEGACY_DETECTOR_ID: &str = "confluent-cloud-api-secret-legacy";

/// The built-in detector that reads an AWS access key ID on the line above a
/// secret access key (issue #1028): a session holds a line carrying an ID
/// open for exactly one more line.
const AWS_SECRET_ACCESS_KEY_DETECTOR_ID: &str = "aws-secret-access-key";

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

/// Text and findings released by one `append` or `finalize` call so far.
#[derive(Default)]
struct Released {
    text: String,
    findings: Vec<Finding>,
}

/// `found` with its range moved `by` bytes later.
fn offset_by(found: &DetectedFinding, by: usize) -> Result<DetectedFinding, SecretScanError> {
    let range = found.range();
    let range = ByteRange::new(range.start() + by, range.end() + by)
        .ok_or(SecretScanErrorCode::InvalidCandidate)?;
    Ok(DetectedFinding::new(
        found.id(),
        found.type_name(),
        found.detector(),
        found.confidence(),
        range,
    )?
    .with_obfuscation(found.obfuscation()))
}

/// Finds the byte offset of the next `\n` or `\r` at or after `from`, or
/// `None` when `chunk` has no more line terminators.
fn find_next_newline(chunk: &str, from: usize) -> Option<usize> {
    chunk.as_bytes()[from..]
        .iter()
        .position(|&byte| byte == b'\n' || byte == b'\r')
        .map(|index| index + from)
}

/// The last result of the two open-construct checks whose backward scan is
/// unbounded, [`has_open_contextual_assignment`] and
/// [`has_open_bearer_authorization`]: whether either reports an open construct
/// over the first `checked_len` bytes of the unit's scan copy. Both are
/// unchanged by appended whitespace ([`is_open_tail_neutral`]), so the result
/// is recomputed only when a closed line brings other content, and every gap
/// of blank lines is crossed once instead of once per line (issue #986).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OpenTailCache {
    checked_len: usize,
    open: bool,
}

/// Which lookback retention hints apply: whether the registry holds the
/// detector each one serves. The registry never changes after construction,
/// so this is decided once instead of on every closed line.
#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct LookbackHints {
    heroku_legacy: bool,
    twilio_auth_token: bool,
    confluent_legacy: bool,
    aws_secret_access_key: bool,
}

impl LookbackHints {
    fn of(registry: &DetectorRegistry) -> Self {
        Self {
            heroku_legacy: registry.contains(HEROKU_LEGACY_DETECTOR_ID),
            twilio_auth_token: registry.contains(TWILIO_AUTH_TOKEN_DETECTOR_ID),
            confluent_legacy: registry.contains(CONFLUENT_LEGACY_DETECTOR_ID),
            aws_secret_access_key: registry.contains(AWS_SECRET_ACCESS_KEY_DETECTOR_ID),
        }
    }
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
    /// Closed units waiting in the current batch, then the current unit.
    retained: String,
    /// Where the current unit starts in `retained`.
    unit_start: usize,
    /// Where each closed unit in the batch ends in `retained`, ascending;
    /// the last one is `unit_start`.
    unit_ends: Vec<usize>,
    /// The scan copy of the current unit, normalized piece by piece as it is
    /// appended. Held only once a piece of this unit actually lost an
    /// invisible code point; until then the scan copy is the unit itself, so
    /// an ordinary unit is never copied (issue #986).
    scanned: Option<String>,
    open_tail: OpenTailCache,
    lookbacks: LookbackHints,
    finalized_bytes: usize,
    total_input_bytes: usize,
    finding_count: usize,
    placeholder_count: usize,
    private_key: PrivateKeyRetentionTracker,
    multiline_open: bool,
    multiline_detected: bool,
    /// Shadow comparisons of every finalized unit's findings, in session
    /// coordinates, when a maintainer-local caller asked for them (#771).
    /// Always `None` for a session built through the public API, so the
    /// scorer never runs on the public incremental path.
    #[cfg(test)]
    shadow: Option<Vec<ShadowComparison>>,
    /// Processes every unit as soon as it closes, as before batching: the
    /// reference the batched path is compared with (issue #985).
    #[cfg(test)]
    unbatched: bool,
    /// Units detected together in one pipeline call so far.
    #[cfg(test)]
    batched_units: usize,
    /// The most bytes `retained` has held.
    #[cfg(test)]
    peak_retained: usize,
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

    /// Creates a `full` session that captures `selection` at construction.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] if registration fails.
    pub fn with_built_in_and_pii(
        limits: IncrementalLimits,
        selection: &PiiSelection,
    ) -> Result<Self, SecretScanError> {
        Self::with_built_in_and_pii_policy_and_formatter(
            limits,
            selection,
            Box::new(DefaultPolicy),
            Box::new(default_placeholder_formatter),
        )
    }

    /// Creates a `full` PII-aware session with explicit callbacks.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] if registration fails.
    pub fn with_built_in_and_pii_policy_and_formatter(
        limits: IncrementalLimits,
        selection: &PiiSelection,
        policy: Box<dyn IncrementalPolicy>,
        formatter: Box<dyn PlaceholderFormatter>,
    ) -> Result<Self, SecretScanError> {
        let registry = DetectorRegistry::with_built_in_and_pii(selection)?;
        Ok(Self::from_registry(registry, limits, policy, formatter))
    }

    /// Creates a `common` session that captures `selection` at construction.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] if registration fails.
    pub fn with_common_built_in_and_pii_policy_and_formatter(
        limits: IncrementalLimits,
        selection: &PiiSelection,
        policy: Box<dyn IncrementalPolicy>,
        formatter: Box<dyn PlaceholderFormatter>,
    ) -> Result<Self, SecretScanError> {
        let registry = DetectorRegistry::with_common_built_in_and_pii(selection)?;
        Ok(Self::from_registry(registry, limits, policy, formatter))
    }

    pub(crate) fn from_registry(
        registry: DetectorRegistry,
        limits: IncrementalLimits,
        policy: Box<dyn IncrementalPolicy>,
        formatter: Box<dyn PlaceholderFormatter>,
    ) -> Self {
        let lookbacks = LookbackHints::of(&registry);
        Self {
            registry,
            policy,
            formatter,
            limits,
            state: SessionState::Accepting,
            retained: String::new(),
            unit_start: 0,
            unit_ends: Vec::new(),
            scanned: None,
            open_tail: OpenTailCache::default(),
            lookbacks,
            finalized_bytes: 0,
            total_input_bytes: 0,
            finding_count: 0,
            placeholder_count: 0,
            private_key: PrivateKeyRetentionTracker::new(),
            multiline_open: false,
            multiline_detected: false,
            #[cfg(test)]
            shadow: None,
            #[cfg(test)]
            unbatched: false,
            #[cfg(test)]
            batched_units: 0,
            #[cfg(test)]
            peak_retained: 0,
        }
    }

    /// Starts recording the shadow comparison of every finding this session
    /// finalizes from now on.
    #[cfg(test)]
    pub(crate) fn record_shadow(&mut self) {
        self.shadow = Some(Vec::new());
    }

    /// The shadow comparisons recorded so far, in session coordinates.
    #[cfg(test)]
    pub(crate) fn take_shadow(&mut self) -> Vec<ShadowComparison> {
        self.shadow.take().unwrap_or_default()
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

    /// Canonical activation captured when this session was constructed.
    #[must_use]
    pub fn activation_identity(&self) -> &str {
        self.registry.activation_identity()
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
        self.unit_start = 0;
        self.unit_ends = Vec::new();
        self.reset_unit_state();
    }

    /// Clears the parser state derived from the current unit: at a unit
    /// boundary, and with the plaintext it was derived from.
    fn reset_unit_state(&mut self) {
        self.scanned = None;
        self.open_tail = OpenTailCache::default();
        self.private_key.reset();
        self.multiline_open = false;
        self.multiline_detected = false;
    }

    /// Discards retained plaintext and parser state and transitions to
    /// `failed`, returning `error` unchanged so callers can propagate it
    /// with `return Err(self.fail_with(error))`.
    fn fail_with(&mut self, error: SecretScanError) -> SecretScanError {
        self.discard_retained();
        self.state = SessionState::Failed;
        error
    }

    /// Judges the current unit the way the pipeline will scan it: on the
    /// scan copy. Judged on the raw buffer, a keyword split by an invisible
    /// code point at a line end would not read as an open construct, the
    /// unit would close early, and the same input would yield different
    /// findings under a different partition.
    ///
    /// The scan copy is maintained as pieces arrive rather than rebuilt here,
    /// and the two tail checks, whose backward scan crosses any run of blank
    /// lines, reuse their last result when only whitespace has arrived since
    /// (issue #986). The four lookback checks read a bounded number of lines
    /// and run as before. Only the current unit is judged: closed units
    /// waiting in the batch are never part of it (issue #985).
    fn has_open_single_line_construct(&mut self) -> bool {
        let scanned = self
            .scanned
            .as_deref()
            .unwrap_or(&self.retained[self.unit_start..]);
        if !is_open_tail_neutral(&scanned[self.open_tail.checked_len..]) {
            self.open_tail.open =
                has_open_contextual_assignment(scanned) || has_open_bearer_authorization(scanned);
        }
        self.open_tail.checked_len = scanned.len();

        let lookbacks = self.lookbacks;
        let open = self.open_tail.open
            || (lookbacks.heroku_legacy && has_open_heroku_legacy_context(scanned))
            || (lookbacks.twilio_auth_token && has_open_twilio_cli_table(scanned))
            || (lookbacks.confluent_legacy && has_open_confluent_properties(scanned))
            || (lookbacks.aws_secret_access_key && has_open_aws_access_key_id_line(scanned));
        #[cfg(test)]
        self.assert_open_construct_matches_the_rescan(open);
        open
    }

    /// Differential check (issue #986): the maintained scan copy and the
    /// cached tail result equal what a fresh normalization and rescan of the
    /// whole current unit report, after every closed line of every test that
    /// drives a session.
    #[cfg(test)]
    fn assert_open_construct_matches_the_rescan(&self, open: bool) {
        let unit = &self.retained[self.unit_start..];
        let rescanned = NormalizedInput::new(unit).into_text();
        assert_eq!(
            self.scanned.as_deref().unwrap_or(unit),
            rescanned,
            "maintained scan copy"
        );
        let tail_open =
            has_open_contextual_assignment(&rescanned) || has_open_bearer_authorization(&rescanned);
        assert_eq!(self.open_tail.open, tail_open, "cached tail checks");
        let reference = tail_open
            || (self.registry.contains(HEROKU_LEGACY_DETECTOR_ID)
                && has_open_heroku_legacy_context(&rescanned))
            || (self.registry.contains(TWILIO_AUTH_TOKEN_DETECTOR_ID)
                && has_open_twilio_cli_table(&rescanned))
            || (self.registry.contains(CONFLUENT_LEGACY_DETECTOR_ID)
                && has_open_confluent_properties(&rescanned))
            || (self.registry.contains(AWS_SECRET_ACCESS_KEY_DETECTOR_ID)
                && has_open_aws_access_key_id_line(&rescanned));
        assert_eq!(open, reference, "open single-line construct");
    }

    /// Adds `piece` to the current unit and enforces the limits on it.
    ///
    /// Every limit is measured on the current unit alone, exactly as when
    /// each unit was processed as soon as it closed: closed units waiting in
    /// the batch are not retained constructs. They are processed first
    /// whenever the buffer would otherwise outgrow `max_buffered_bytes`, and
    /// before any limit failure, so a failure in an earlier unit is still
    /// the one reported (issue #985).
    fn append_retained(
        &mut self,
        piece: &str,
        closes_line: bool,
        released: &mut Released,
    ) -> Result<(), SecretScanError> {
        if !self.unit_ends.is_empty()
            && self.retained.len() + piece.len() > self.limits.max_buffered_bytes()
        {
            self.flush_batch(released)
                .map_err(|error| self.fail_with(error))?;
        }

        // The tracker and the open-construct checks read the scan copy, as
        // the detectors will. A piece is whole code points, so normalizing
        // piece by piece equals normalizing the unit. Every limit below is a
        // memory bound and stays measured in original bytes.
        let normalized = NormalizedInput::new(piece).into_text();
        match (&mut self.scanned, &normalized) {
            (Some(scanned), _) => scanned.push_str(&normalized),
            (None, Cow::Owned(normalized)) => {
                let unit = &self.retained[self.unit_start..];
                let mut scanned = String::with_capacity(unit.len() + normalized.len());
                scanned.push_str(unit);
                scanned.push_str(normalized);
                self.scanned = Some(scanned);
            }
            (None, Cow::Borrowed(_)) => {}
        }
        self.retained.push_str(piece);
        #[cfg(test)]
        {
            self.peak_retained = self.peak_retained.max(self.retained.len());
        }
        let (has_begin, has_open) = self.private_key.append(&normalized);
        self.multiline_detected |= has_begin;
        self.multiline_open = has_open;

        let construct_limit = if self.multiline_detected {
            self.limits.max_multiline_bytes()
        } else {
            self.limits.max_token_bytes()
        };
        let unit_length = self.retained.len() - self.unit_start;
        let open_length = if closes_line {
            unit_length - 1
        } else {
            unit_length
        };
        let exceeded = if open_length > construct_limit {
            Some(if self.multiline_detected {
                SecretScanErrorCode::MultilineLimitExceeded
            } else {
                SecretScanErrorCode::TokenLimitExceeded
            })
        } else if unit_length > self.limits.max_buffered_bytes() {
            Some(SecretScanErrorCode::BufferLimitExceeded)
        } else {
            None
        };
        if let Some(code) = exceeded {
            let error = self.flush_batch(released).err().unwrap_or(code.into());
            return Err(self.fail_with(error));
        }
        Ok(())
    }

    /// Ends the current unit at the end of the buffer and adds it to the
    /// batch of closed units (issue #985).
    ///
    /// A unit that a detector could bind to the text before it starts a new
    /// batch instead ([`starts_new_batch`](Self::starts_new_batch)), so every
    /// batch scans each of its units exactly as that unit alone would scan.
    fn close_unit(&mut self, released: &mut Released) -> Result<(), SecretScanError> {
        if !self.unit_ends.is_empty() && self.starts_new_batch() {
            self.flush_batch(released)?;
        }
        self.unit_ends.push(self.retained.len());
        self.unit_start = self.retained.len();
        self.reset_unit_state();
        #[cfg(test)]
        if self.unbatched {
            self.flush_batch(released)?;
        }
        Ok(())
    }

    /// Whether the current unit, about to close behind at least one closed
    /// unit, must not share a batch with the units before it. See the audit
    /// in `docs/audits/evidence/985/README.md`.
    ///
    /// That is a unit whose text starts with a construct a detector continues
    /// from the text before it ([`continues_previous_line`]).
    ///
    /// A unit after a lone `\r` used to start a new batch too, because
    /// several detectors split lines at `\n` only and read two
    /// `\r`-separated units as one line. Every detector now ends a line at a
    /// lone `\r` as well, as the session ends a unit there (issue #990), so
    /// such units batch like any others.
    fn starts_new_batch(&self) -> bool {
        let unit = &self.retained[self.unit_start..];
        continues_previous_line(self.scanned.as_deref().unwrap_or(unit))
    }

    /// Detects, applies policy to and redacts every closed unit in the batch,
    /// then drops their plaintext.
    ///
    /// Detection runs once over the whole batch when its units are
    /// separable ([`detect_units`]); otherwise, or when that call fails, each
    /// unit is scanned alone, which reproduces the failure in the order
    /// unit-by-unit processing would meet it. Policy and redaction always run
    /// unit by unit, so every callback sees the same calls in the same order
    /// and every per-unit bound (`redact`'s input, finding and placeholder
    /// checks) applies to the same text as before.
    fn flush_batch(&mut self, released: &mut Released) -> Result<(), SecretScanError> {
        if self.unit_ends.is_empty() {
            return Ok(());
        }
        let batch_length = self.unit_start;
        #[cfg(test)]
        let (finding_offset, mut batch_shadow) =
            (self.finding_count, self.shadow.as_ref().map(|_| Vec::new()));

        let batched = if self.unit_ends.len() > 1 {
            let batch = &self.retained[..batch_length];
            #[cfg(test)]
            let detected = detect_units(
                batch,
                &self.registry,
                &self.unit_ends,
                batch_shadow.as_mut(),
            );
            #[cfg(not(test))]
            let detected = detect_units(batch, &self.registry, &self.unit_ends, None);
            detected.ok().flatten()
        } else {
            None
        };

        let unit_ends = std::mem::take(&mut self.unit_ends);
        let mut unit_begin = 0;
        match batched {
            Some(detected) => {
                #[cfg(test)]
                {
                    self.batched_units += unit_ends.len();
                }
                let mut detected = detected.into_iter().peekable();
                for &unit_end in &unit_ends {
                    let mut unit_findings = Vec::new();
                    while let Some(found) =
                        detected.next_if(|found| found.range().start() < unit_end)
                    {
                        unit_findings.push(found);
                    }
                    self.finalize_unit(unit_begin, unit_end, &unit_findings, released)?;
                    unit_begin = unit_end;
                }
                #[cfg(test)]
                self.record_unit_shadow(batch_shadow, finding_offset, self.finalized_bytes)?;
            }
            None => {
                for &unit_end in &unit_ends {
                    let unit = &self.retained[unit_begin..unit_end];
                    #[cfg(test)]
                    let (finding_offset, mut unit_shadow) =
                        (self.finding_count, self.shadow.as_ref().map(|_| Vec::new()));
                    #[cfg(test)]
                    let detected = detect(unit, &self.registry, unit_shadow.as_mut())?;
                    #[cfg(not(test))]
                    let detected = run_detector_pipeline(unit, &self.registry)?;
                    let detected = detected
                        .iter()
                        .map(|found| offset_by(found, unit_begin))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.finalize_unit(unit_begin, unit_end, &detected, released)?;
                    #[cfg(test)]
                    self.record_unit_shadow(
                        unit_shadow,
                        finding_offset,
                        self.finalized_bytes + unit_begin,
                    )?;
                    unit_begin = unit_end;
                }
            }
        }

        self.finalized_bytes += batch_length;
        self.retained = if batch_length == self.retained.len() {
            String::new()
        } else {
            self.retained[batch_length..].to_owned()
        };
        self.unit_start = 0;
        self.unit_ends = unit_ends;
        self.unit_ends.clear();
        Ok(())
    }

    /// Applies policy to and redacts the closed unit `retained[begin..end]`,
    /// given its findings with ranges in `retained` coordinates, and appends
    /// the result to `released`.
    ///
    /// Global and unit-local findings are built together in one pass; the
    /// placeholder formatter reaches a finding's global form by its position,
    /// since both lists are ordered by start.
    fn finalize_unit(
        &mut self,
        begin: usize,
        end: usize,
        detected: &[DetectedFinding],
        released: &mut Released,
    ) -> Result<(), SecretScanError> {
        let input_offset = self.finalized_bytes;
        let mut global_findings: Vec<Finding> = Vec::with_capacity(detected.len());
        let mut local_findings: Vec<Finding> = Vec::with_capacity(detected.len());
        for found in detected {
            let range = found.range();
            let global_range =
                ByteRange::new(range.start() + input_offset, range.end() + input_offset)
                    .ok_or(SecretScanErrorCode::InvalidCandidate)?;
            let id = format!("finding-{}", self.finding_count + 1);
            let global_detected = DetectedFinding::new(
                id.as_str(),
                found.type_name(),
                found.detector(),
                found.confidence(),
                global_range,
            )?
            .with_obfuscation(found.obfuscation());
            let context = IncrementalPolicyContext::new(self.finding_count);
            let action = self
                .policy
                .evaluate(&global_detected, &context)
                .map_err(|_| SecretScanError::from(SecretScanErrorCode::PolicyFailure))?;
            let local_range = ByteRange::new(range.start() - begin, range.end() - begin)
                .ok_or(SecretScanErrorCode::InvalidCandidate)?;
            let local_detected = DetectedFinding::new(
                id,
                found.type_name(),
                found.detector(),
                found.confidence(),
                local_range,
            )?
            .with_obfuscation(found.obfuscation());
            local_findings.push(local_detected.with_action(action));
            global_findings.push(global_detected.with_action(action));
            self.finding_count += 1;
        }

        let placeholder_offset = self.placeholder_count;
        let formatter = self.formatter.as_ref();
        let wrapped = |local_finding: &Finding, local_context: &PlaceholderContext| {
            let Ok(index) = local_findings
                .binary_search_by_key(&local_finding.range().start(), |finding| {
                    finding.range().start()
                })
            else {
                return Err(FormatterFailure);
            };
            let global_context =
                PlaceholderContext::new(placeholder_offset + local_context.placeholder_index());
            formatter.format(&global_findings[index], &global_context)
        };
        let text = redact(&self.retained[begin..end], &local_findings, &wrapped)?;

        self.placeholder_count += global_findings
            .iter()
            .filter(|finding| finding.action().replaces_text())
            .count();
        released.text.push_str(&text);
        released.findings.extend(global_findings);
        Ok(())
    }

    /// Appends the shadow comparisons of findings finalized from
    /// `finding_offset`, found in text starting at `input_offset`.
    #[cfg(test)]
    fn record_unit_shadow(
        &mut self,
        unit_shadow: Option<Vec<ShadowComparison>>,
        finding_offset: usize,
        input_offset: usize,
    ) -> Result<(), SecretScanError> {
        if let (Some(recorded), Some(unit_shadow)) = (self.shadow.as_mut(), unit_shadow) {
            for comparison in unit_shadow {
                recorded.push(
                    comparison
                        .shifted(finding_offset, input_offset)
                        .ok_or(SecretScanErrorCode::InvalidCandidate)?,
                );
            }
        }
        Ok(())
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

        // Lines that close in this call are collected into one batch and
        // processed together at the end of the call (issue #985).
        let mut released = Released::default();
        let mut cursor = 0usize;
        while cursor < chunk.len() {
            let Some(newline) = find_next_newline(chunk, cursor) else {
                self.append_retained(&chunk[cursor..], false, &mut released)?;
                break;
            };
            self.append_retained(&chunk[cursor..=newline], true, &mut released)?;

            if !self.multiline_open && !self.has_open_single_line_construct() {
                self.close_unit(&mut released)
                    .map_err(|error| self.fail_with(error))?;
            }
            cursor = newline + 1;
        }
        self.flush_batch(&mut released)
            .map_err(|error| self.fail_with(error))?;
        Ok(IncrementalResult::new(released.text, released.findings))
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
        // Every `append` leaves the batch empty, so the last unit is
        // processed alone.
        let mut released = Released::default();
        self.unit_ends.push(self.retained.len());
        self.unit_start = self.retained.len();
        self.flush_batch(&mut released)
            .map_err(|error| self.fail_with(error))?;
        self.discard_retained();
        self.state = SessionState::Finalized;
        Ok(IncrementalResult::new(released.text, released.findings))
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
#[path = "incremental/batch_tests.rs"]
mod batch_tests;

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
        assert!(sanitizer.scanned.is_none());
        assert_eq!(sanitizer.open_tail, OpenTailCache::default());
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

    /// Runs `input` split at every char boundary into two chunks, and once
    /// a char at a time, through a `full` and a PII-aware session. Every
    /// closed line runs [`IncrementalSanitizer::assert_open_construct_matches_the_rescan`],
    /// and every partition must reproduce the one-chunk output.
    fn assert_every_partition_matches_the_rescan(input: &str) {
        fn run(sanitizer: &mut IncrementalSanitizer, chunks: &[&str]) -> (String, Vec<Finding>) {
            let mut text = String::new();
            let mut findings = Vec::new();
            for chunk in chunks {
                let result = sanitizer.append(chunk).unwrap();
                text.push_str(result.text());
                findings.extend_from_slice(result.findings());
            }
            let result = sanitizer.finalize().unwrap();
            text.push_str(result.text());
            findings.extend_from_slice(result.findings());
            (text, findings)
        }
        let selection = PiiSelection::parse(&["pii:global"]).unwrap();
        let sessions: [fn(&PiiSelection) -> IncrementalSanitizer; 2] = [
            |_| default_session(),
            |selection| {
                IncrementalSanitizer::with_built_in_and_pii(generous_limits(), selection).unwrap()
            },
        ];
        for session in sessions {
            let reference = run(&mut session(&selection), &[input]);
            let mut boundaries: Vec<usize> = (1..input.len())
                .filter(|&at| input.is_char_boundary(at))
                .collect();
            if input.len() > 512 {
                boundaries.retain(|at| at % 61 == 0 || input.as_bytes()[at - 1] == b'\n');
            }
            for at in boundaries {
                let chunks = [&input[..at], &input[at..]];
                assert_eq!(run(&mut session(&selection), &chunks), reference, "{at}");
            }
            let mut chars = Vec::new();
            let mut rest = input;
            while let Some(ch) = rest.chars().next() {
                chars.push(&rest[..ch.len_utf8()]);
                rest = &rest[ch.len_utf8()..];
            }
            assert_eq!(run(&mut session(&selection), &chars), reference);
        }
    }

    #[test]
    fn the_maintained_open_construct_state_matches_a_rescan_over_generated_inputs() {
        // Deterministic pseudo-random sequences of the pieces the five checks
        // react to: names, operators, quotes, header words, layout lines,
        // every kind of whitespace they skip, and invisible code points. Each
        // runs whole, one char per chunk, and at a few split points, under
        // `full` and `pii:global`; every closed line asserts the rescan.
        const PIECES: &[&str] = &[
            "api_key",
            "API_KEY",
            "password",
            "\"token\"",
            "`secret`",
            "k",
            "\"kty\":\"oct\",",
            "Authorization",
            "x-authorization",
            "Proxy-Authorization",
            "bearer",
            "Bearer",
            "=",
            ":",
            "=\n",
            ":\n",
            "api_key:\n",
            "Authorization:\n",
            "\n  ",
            ":=",
            "\\\"",
            "'",
            "{",
            "(",
            ",",
            ";",
            "#",
            "&",
            "?",
            "value",
            MARKER,
            " ",
            "  ",
            "\t",
            "\n",
            "\n",
            "\r",
            "\r\n",
            "\u{2028}",
            "\u{FEFF}",
            "\u{00A0}",
            "\u{200B}",
            "\u{00AD}",
            "machine api.heroku.com",
            "login user@example.invalid",
            "$ twilio api:core:accounts:list",
            "SID  Auth Token",
            "heroku auth:token",
            "schema.registry.url=https://psrc.example.invalid",
            "basic.auth.user.info=KEY:",
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "\u{e9}",
            "\u{65e5}",
        ];
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = |bound: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap() % bound
        };
        for _ in 0..300 {
            let length = 1 + next(14);
            let input: String = (0..length).map(|_| PIECES[next(PIECES.len())]).collect();
            assert_every_partition_matches_the_rescan(&input);
        }
    }

    #[test]
    fn the_maintained_open_construct_state_matches_a_rescan_across_whitespace_gaps() {
        // Whitespace-only lines keep the cached tail result; the line that
        // brings content re-evaluates it. The gaps mix every whitespace kind
        // the tail checks skip, and an invisible code point makes the scan
        // copy diverge mid-unit.
        let gaps = [
            "\n\n\n",
            "        \n        \n",
            "\r\n \t\r\n",
            "\u{2028}\n\u{FEFF}\u{00A0}\n",
            "\u{200B}\n \u{200B} \n",
        ];
        for gap in gaps {
            for input in [
                format!("API_KEY={gap}{MARKER}\nnext\n"),
                format!("API_KEY{gap}={gap}{MARKER}\n"),
                format!("API_\u{200B}KEY={gap}{MARKER}\n"),
                format!("config \"token\":{gap}{MARKER}\n"),
                format!("Authorization:{gap}Bearer {MARKER}\n"),
                format!("x-authorization{gap}Bearer {MARKER}\n"),
                format!("plain words{gap}api_key={gap}={gap}{MARKER}\n"),
                format!(
                    "machine api.heroku.com{gap}login user@example.invalid{gap}password {MARKER}\n"
                ),
                format!(
                    "$ twilio api:core:accounts:list{gap}SID  Auth Token{gap}AC{MARKER}  {MARKER}\n"
                ),
                format!(
                    "schema.registry.url=https://psrc.example.invalid{gap}basic.auth.user.info=KEY:{MARKER}\n"
                ),
                format!(
                    "-----BEGIN PRIVATE KEY-----{gap}{MARKER}{gap}-----END PRIVATE KEY-----{gap}api_key={gap}{MARKER}\n"
                ),
            ] {
                assert_every_partition_matches_the_rescan(&input);
            }
        }
    }

    // Whether a `common` incremental session's cumulative output matches
    // the whole-input path ([`crate::scan_and_redact`] over a `common`
    // registry) is a public-API-level contract
    // (`decision-define-detector-profile-and-pack-contract`), covered by
    // `tests/public_api.rs`'s
    // `common_profile_incremental_session_selects_the_same_built_ins_as_the_whole_input_path`,
    // not repeated here.
}
