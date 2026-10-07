//! Node.js N-API binding for the `redact-secret` core
//! (`decision-define-runtime-bindings`).
//!
//! Ranges exposed here use UTF-16 code units; conversion from the core's
//! UTF-8 byte offsets happens in this crate without changing the selected
//! span (`decision-govern-cross-language-conformance`). This is the first
//! stable extension surface: it accepts policy and placeholder formatter
//! callbacks, but not custom detector callbacks — every built-in detector
//! runs in Rust.

mod error;
mod incremental;
mod offsets;

use std::cell::{Cell, OnceCell, RefCell};
use std::rc::Rc;

use napi::bindgen_prelude::{Buffer, FnArgs, Function};
use napi_derive::napi;
use redact_secret::{
    Action, ActionComparison, ActionPolicy, ArtifactKind, ArtifactManifest, ByteRange,
    ComparedPolicy, Confidence, DefaultPolicy, DetectedFinding, DetectorRegistry, Finding,
    FormatterFailure, MAX_COMPARED_POLICIES, Obfuscation, PiiSelection, PlaceholderContext,
    PlaceholderFormatter, Policy, PolicyContext, PolicyFailure, Profile, SecretScanError,
    SecretScanErrorCode, WholeInputLimits, compare_action_policies_with_limits,
    default_placeholder_formatter, load_action_policy, load_ruleset,
    redact_with_limits as core_redact_with_limits, run_detector_pipeline,
};

use crate::error::{
    to_js_action_policy_error, to_js_error, to_js_manifest_error, to_js_ruleset_error,
};
use crate::offsets::{Utf16Offsets, utf16_offsets_to_bytes};
// Re-exported so the incremental N-API surface (a public export like `scan`
// or `redact`, just organized in its own module) is part of this crate's
// effective public API rather than dead code the compiler cannot prove any
// external caller reaches — the same reasoning `secret-scan-core`'s own
// `lib.rs` applies to its private `incremental` module.
pub use crate::incremental::{
    JsIncrementalLimits, JsIncrementalOptions, JsIncrementalPolicyContext, JsIncrementalResult,
    JsIncrementalSanitizer, create_incremental_sanitizer, create_incremental_sanitizer_common,
};

/// Returns the shared product version.
#[napi]
#[must_use]
pub fn version() -> String {
    redact_secret::VERSION.to_owned()
}

/// A finding before policy evaluation, passed to a policy callback.
/// Ranges are UTF-16 code-unit offsets.
#[napi(object)]
pub struct JsDetectedFinding {
    /// Deterministic finding id (`finding-1`, `finding-2`, ...).
    pub id: String,
    /// Finding type.
    pub r#type: String,
    /// Id of the detector that produced this finding.
    pub detector: String,
    /// `"high"`, `"medium"`, or `"low"`.
    pub confidence: String,
    /// `"none"` or `"invisible-characters"`.
    pub obfuscation: String,
    /// Start offset in UTF-16 code units.
    pub start: u32,
    /// End offset in UTF-16 code units (exclusive).
    pub end: u32,
}

/// Position information passed alongside a [`JsDetectedFinding`] to a policy
/// callback.
#[napi(object)]
pub struct JsPolicyContext {
    /// Zero-based position in the finalized detection list.
    pub finding_index: u32,
    /// Total number of finalized findings for the input.
    pub finding_count: u32,
}

/// A finding after policy evaluation: the shape [`scan`] returns. Ranges are
/// UTF-16 code-unit offsets.
#[napi(object)]
pub struct JsFinding {
    /// Deterministic finding id (`finding-1`, `finding-2`, ...).
    pub id: String,
    /// Finding type.
    pub r#type: String,
    /// Id of the detector that produced this finding.
    pub detector: String,
    /// `"high"`, `"medium"`, or `"low"`.
    pub confidence: String,
    /// `"redact"`, `"block"`, `"warn"`, or `"allow"`.
    pub action: String,
    /// `"none"` or `"invisible-characters"`.
    pub obfuscation: String,
    /// Start offset in UTF-16 code units.
    pub start: u32,
    /// End offset in UTF-16 code units (exclusive).
    pub end: u32,
}

/// Position information passed to a placeholder formatter callback.
#[napi(object)]
pub struct JsPlaceholderContext {
    /// One-based position among findings that are actually replaced.
    pub placeholder_index: u32,
}

/// The combined result of [`scan_and_redact`].
#[napi(object)]
pub struct JsScanAndRedactResult {
    /// Every finding, in the same shape [`scan`] returns.
    pub findings: Vec<JsFinding>,
    /// `input` with `redact`/`block` findings replaced by placeholders.
    pub redacted: String,
}

/// Explicit byte and finding-count bounds for [`scan`], [`redact`], and
/// [`scan_and_redact`] (and their `common`-profile counterparts). Omit to use
/// the core's default (`decision-bound-whole-input-operations-by-default`).
#[napi(object)]
#[allow(clippy::struct_field_names)]
pub struct JsWholeInputLimits {
    /// The largest whole-input byte length accepted.
    pub max_input_bytes: u32,
    /// The largest accepted finding count.
    pub max_findings: u32,
}

/// Resolves an optional [`JsWholeInputLimits`] to a core [`WholeInputLimits`],
/// using the core's default when `limits` is omitted.
fn resolve_whole_input_limits(
    limits: Option<&JsWholeInputLimits>,
) -> Result<WholeInputLimits, SecretScanError> {
    match limits {
        Some(limits) => WholeInputLimits::new(
            limits.max_input_bytes as usize,
            limits.max_findings as usize,
        ),
        None => Ok(WholeInputLimits::default()),
    }
}

/// A JavaScript policy callback: `(finding, context) => action`.
type PolicyCallback<'env> = Function<'env, FnArgs<(JsDetectedFinding, JsPolicyContext)>, String>;

/// A JavaScript placeholder formatter callback: `(finding, context) => text`.
///
/// `pub(crate)` so `incremental.rs` can accept the same callback shape for
/// an incremental session's formatter option.
pub(crate) type FormatterCallback<'env> =
    Function<'env, FnArgs<(JsFinding, JsPlaceholderContext)>, String>;

thread_local! {
    /// The built-in `full` detector registry, built at most once per thread
    /// (`decision-define-runtime-bindings`: initialization is idempotent).
    /// `DetectorRegistry` holds `Box<dyn Detector>` trait objects that are
    /// not required to be `Sync`, so the cache is thread-local rather than a
    /// single process-wide `static`; every export here runs synchronously on
    /// whichever JS thread calls it.
    static REGISTRY: OnceCell<Result<DetectorRegistry, SecretScanError>> = const { OnceCell::new() };
    /// The built-in `common` detector registry
    /// (`decision-define-detector-profile-and-pack-contract`), cached the
    /// same way as `REGISTRY` and independently of it: a process that only
    /// ever calls the `common` exports never builds the `full` registry, and
    /// vice versa.
    static REGISTRY_COMMON: OnceCell<Result<DetectorRegistry, SecretScanError>> = const { OnceCell::new() };
    static PII_SELECTION: OnceCell<PiiSelection> = const { OnceCell::new() };
    static PII_SELECTION_COMMON: OnceCell<PiiSelection> = const { OnceCell::new() };
}

fn selection_cell<T>(profile: Profile, f: impl FnOnce(&OnceCell<PiiSelection>) -> T) -> T {
    match profile {
        Profile::Common => PII_SELECTION_COMMON.with(f),
        // `Profile` is `#[non_exhaustive]`: a profile this addon does not
        // link yet falls back to the full set, the superset.
        _ => PII_SELECTION.with(f),
    }
}

pub(crate) fn pii_selection(profile: Profile) -> PiiSelection {
    selection_cell(profile, |cell| cell.get().cloned().unwrap_or_default())
}

/// Runs `f` against the shared built-in registry for `profile`, building it
/// on first use and caching it independently per profile
/// (`decision-define-detector-profile-and-pack-contract`): a process that
/// only ever asks for `Profile::Common` never builds the `Profile::Full`
/// registry, and vice versa.
fn with_profile_registry<T>(
    profile: Profile,
    f: impl FnOnce(&DetectorRegistry) -> Result<T, SecretScanError>,
) -> Result<T, SecretScanError> {
    match profile {
        Profile::Common => REGISTRY_COMMON.with(|cell| {
            match cell.get_or_init(|| DetectorRegistry::with_common_built_in(std::iter::empty())) {
                Ok(registry) => f(registry),
                Err(error) => Err(*error),
            }
        }),
        _ => REGISTRY.with(|cell| {
            match cell.get_or_init(|| DetectorRegistry::with_built_in(std::iter::empty())) {
                Ok(registry) => f(registry),
                Err(error) => Err(*error),
            }
        }),
    }
}

/// Returns the detector profile the default exports ([`scan`], [`redact`],
/// [`scan_and_redact`], [`initialize`]) operate on. Mirrors `bindings/wasm`'s
/// compile-time `profile()`, but Node links both profiles into one addon and
/// exposes each through its own function rather than a Cargo feature, so
/// this is a constant, not a build-time switch.
#[napi]
#[must_use]
pub fn profile() -> String {
    Profile::Full.as_str().to_owned()
}

/// Returns the detector profile the `*Common` exports ([`scan_common`],
/// [`scan_and_redact_common`], [`initialize_common`]) operate on.
#[napi]
#[must_use]
pub fn profile_common() -> String {
    Profile::Common.as_str().to_owned()
}

/// The 40-hex source commit this addon was built from, when the build
/// supplied one at compile time; `None` otherwise. The core reads no
/// environment; this is a value fixed in the binary by the build.
const SOURCE_REVISION: Option<&str> = option_env!("REDACT_SECRET_SOURCE_REVISION");

/// The `artifact-manifest/v1` document of the `full` profile of this addon,
/// as JSON text (issue #1250). Generated from the registration rows the
/// addon links; builds no registry and reads no PII selection, so it is
/// safe before and without [`initialize`] and cannot lock the thread's PII
/// activation.
///
/// # Errors
///
/// Returns the fixed `ARTIFACT_MANIFEST_INVALID_SOURCE_REVISION` class when
/// the compile-time source revision is malformed.
#[napi(js_name = "artifactManifest")]
pub fn artifact_manifest() -> napi::Result<String, String> {
    ArtifactManifest::full(ArtifactKind::NodeAddon, true, SOURCE_REVISION)
        .map(|manifest| manifest.as_json().to_owned())
        .map_err(to_js_manifest_error)
}

/// The `artifact-manifest/v1` document of the `common` profile of this
/// addon. Same guarantees as [`artifact_manifest`]; the `provider`
/// detectors are listed as `notIncluded` ids only.
///
/// # Errors
///
/// As [`artifact_manifest`].
#[napi(js_name = "artifactManifestCommon")]
pub fn artifact_manifest_common() -> napi::Result<String, String> {
    ArtifactManifest::common(ArtifactKind::NodeAddon, true, SOURCE_REVISION)
        .map(|manifest| manifest.as_json().to_owned())
        .map_err(to_js_manifest_error)
}

/// Idempotent initialization hook required by the cross-runtime contract:
/// every host, including Node, supports `await initialize()` before
/// scanning, even though Node's own loading has nothing to await. Calling it
/// any number of times, from any number of call sites, has the same effect
/// as calling it once.
///
/// # Errors
///
/// Returns `INVALID_DETECTOR` only if the built-in detector registry itself
/// is malformed, which the core's own test suite already proves cannot
/// happen.
#[napi]
pub fn initialize() -> napi::Result<(), String> {
    initialize_profile(Profile::Full, &[])
}

/// The `common`-profile analogue of [`initialize`]
/// (`decision-define-detector-profile-and-pack-contract`): idempotently
/// builds and caches the `common` registry, independently of `initialize`'s
/// `full` registry.
///
/// # Errors
///
/// Returns `INVALID_DETECTOR` only if the built-in `common` detector
/// registry itself is malformed, which the core's own test suite already
/// proves cannot happen.
#[napi]
pub fn initialize_common() -> napi::Result<(), String> {
    initialize_profile(Profile::Common, &[])
}

fn initialize_profile(profile: Profile, pii: &[String]) -> napi::Result<(), String> {
    let borrowed: Vec<&str> = pii.iter().map(String::as_str).collect();
    let selection = PiiSelection::parse(&borrowed).map_err(to_js_error)?;
    let identity = selection.activation_identity(profile);
    let existing = with_profile_registry(profile, |registry| {
        Ok(registry.activation_identity().to_owned())
    })
    .map_err(to_js_error)?;
    if existing != identity {
        return Err(to_js_error(
            SecretScanErrorCode::PiiActivationConflict.into(),
        ));
    }
    selection_cell(profile, |cell| {
        if let Some(active) = cell.get() {
            if active != &selection {
                return Err(to_js_error(
                    SecretScanErrorCode::PiiActivationConflict.into(),
                ));
            }
        } else {
            let _ = cell.set(selection);
        }
        Ok(())
    })
}

/// Initializes the full profile with a PII selector list.
///
/// # Errors
///
/// Returns a fixed selector, activation-conflict, or registry error.
#[napi(js_name = "initializePii")]
#[allow(clippy::needless_pass_by_value, reason = "N-API owns vector arguments")]
pub fn initialize_pii(pii: Vec<String>) -> napi::Result<(), String> {
    // A non-off selection must construct the selected registry before the
    // lazy legacy registry can lock the profile to `off`.
    initialize_profile_with_selection(Profile::Full, &pii)
}

/// Initializes the common profile with a PII selector list.
///
/// # Errors
///
/// Returns a fixed selector, activation-conflict, or registry error.
#[napi(js_name = "initializeCommonPii")]
#[allow(clippy::needless_pass_by_value, reason = "N-API owns vector arguments")]
pub fn initialize_common_pii(pii: Vec<String>) -> napi::Result<(), String> {
    initialize_profile_with_selection(Profile::Common, &pii)
}

fn initialize_profile_with_selection(profile: Profile, pii: &[String]) -> napi::Result<(), String> {
    let borrowed: Vec<&str> = pii.iter().map(String::as_str).collect();
    let selection = PiiSelection::parse(&borrowed).map_err(to_js_error)?;
    let identity = selection.activation_identity(profile);
    let result = match profile {
        Profile::Common => REGISTRY_COMMON
            .with(|cell| initialize_registry_cell(cell, profile, &selection, &identity)),
        _ => REGISTRY.with(|cell| initialize_registry_cell(cell, profile, &selection, &identity)),
    };
    result.map_err(to_js_error)?;
    selection_cell(profile, |cell| {
        if let Some(active) = cell.get() {
            if active != &selection {
                return Err(to_js_error(
                    SecretScanErrorCode::PiiActivationConflict.into(),
                ));
            }
        } else {
            let _ = cell.set(selection);
        }
        Ok(())
    })
}

fn initialize_registry_cell(
    cell: &OnceCell<Result<DetectorRegistry, SecretScanError>>,
    profile: Profile,
    selection: &PiiSelection,
    identity: &str,
) -> Result<(), SecretScanError> {
    if let Some(existing) = cell.get() {
        return match existing {
            Ok(registry) if registry.activation_identity() == identity => Ok(()),
            Ok(_) => Err(SecretScanErrorCode::PiiActivationConflict.into()),
            Err(error) => Err(*error),
        };
    }
    let registry = match profile {
        Profile::Common => DetectorRegistry::with_common_built_in_and_pii(selection),
        _ => DetectorRegistry::with_built_in_and_pii(selection),
    };
    let outcome = registry.as_ref().map(|_| ()).map_err(|error| *error);
    let _ = cell.set(registry);
    outcome
}

/// Canonical full-profile PII activation identity.
///
/// # Errors
///
/// Returns the cached fixed registry error if initialization failed.
#[napi]
pub fn pii_activation() -> napi::Result<String, String> {
    with_profile_registry(Profile::Full, |registry| {
        Ok(registry.activation_identity().to_owned())
    })
    .map_err(to_js_error)
}

/// Canonical common-profile PII activation identity.
///
/// # Errors
///
/// Returns the cached fixed registry error if initialization failed.
#[napi]
pub fn pii_activation_common() -> napi::Result<String, String> {
    with_profile_registry(Profile::Common, |registry| {
        Ok(registry.activation_identity().to_owned())
    })
    .map_err(to_js_error)
}

/// Converts `finding` to its N-API shape, its range through `offsets` (the
/// one converter every conversion over this call's input shares).
fn to_js_detected_finding(
    offsets: &mut Utf16Offsets<'_>,
    finding: &DetectedFinding,
) -> JsDetectedFinding {
    JsDetectedFinding {
        id: finding.id().to_owned(),
        r#type: finding.type_name().to_owned(),
        detector: finding.detector().to_owned(),
        confidence: finding.confidence().as_str().to_owned(),
        obfuscation: finding.obfuscation().as_str().to_owned(),
        start: offsets.utf16_at(finding.range().start()),
        end: offsets.utf16_at(finding.range().end()),
    }
}

/// As [`to_js_detected_finding`], for a finding with its chosen action.
fn to_js_finding(offsets: &mut Utf16Offsets<'_>, finding: &Finding) -> JsFinding {
    JsFinding {
        id: finding.id().to_owned(),
        r#type: finding.type_name().to_owned(),
        detector: finding.detector().to_owned(),
        confidence: finding.confidence().as_str().to_owned(),
        action: finding.action().as_str().to_owned(),
        obfuscation: finding.obfuscation().as_str().to_owned(),
        start: offsets.utf16_at(finding.range().start()),
        end: offsets.utf16_at(finding.range().end()),
    }
}

/// Converts every finding of one call to its N-API shape in one pass over
/// `offsets`' input.
fn to_js_findings(offsets: &mut Utf16Offsets<'_>, findings: &[Finding]) -> Vec<JsFinding> {
    findings
        .iter()
        .map(|finding| to_js_finding(offsets, finding))
        .collect()
}

/// Reconstructs native [`Finding`]s from JavaScript-supplied [`JsFinding`]s,
/// converting every UTF-16 range back to UTF-8 bytes in one walk over
/// `input` ([`utf16_offsets_to_bytes`]).
///
/// # Errors
///
/// The first error, in `findings` order, that [`from_js_finding`] reports.
fn from_js_findings(input: &str, findings: &[JsFinding]) -> Result<Vec<Finding>, SecretScanError> {
    let requested: Vec<usize> = findings
        .iter()
        .flat_map(|finding| [finding.start as usize, finding.end as usize])
        .collect();
    let resolved = utf16_offsets_to_bytes(input, &requested);
    findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            from_js_finding(finding, resolved[2 * index], resolved[2 * index + 1])
        })
        .collect()
}

/// Evaluates the core's [`DefaultPolicy`] for one finding's safe metadata and
/// returns its action name, so a JavaScript policy that wants "mine, else the
/// default" never copies the default table
/// (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`,
/// issue #1219). Only `type` and `confidence` decide the result; the range
/// is validated and otherwise ignored.
///
/// # Errors
///
/// `INVALID_FINDINGS` when `finding` is not a well-formed finding: a
/// non-identifier `id`, `type` or `detector`, an unknown `confidence` or
/// `obfuscation`, or an empty or reversed range.
#[napi(js_name = "defaultPolicy")]
#[allow(clippy::needless_pass_by_value, reason = "N-API owns object arguments")]
pub fn default_policy(finding: JsDetectedFinding) -> napi::Result<String, String> {
    let core_finding = from_js_detected_finding(&finding)
        .map_err(|_| to_js_error(SecretScanErrorCode::InvalidFindings.into()))?;
    DefaultPolicy
        .evaluate(&core_finding, &PolicyContext::new(0, 1))
        .map(|action| action.as_str().to_owned())
        .map_err(|_| to_js_error(SecretScanErrorCode::PolicyFailure.into()))
}

/// Reconstructs a native [`DetectedFinding`] from its JavaScript metadata,
/// using the UTF-16 offsets as the range: the default policy never reads it.
fn from_js_detected_finding(
    finding: &JsDetectedFinding,
) -> Result<DetectedFinding, SecretScanError> {
    let range = ByteRange::new(finding.start as usize, finding.end as usize)
        .ok_or(SecretScanErrorCode::InvalidFindings)?;
    let confidence =
        Confidence::from_name(&finding.confidence).ok_or(SecretScanErrorCode::InvalidFindings)?;
    let obfuscation =
        Obfuscation::from_name(&finding.obfuscation).ok_or(SecretScanErrorCode::InvalidFindings)?;
    Ok(DetectedFinding::new(
        &finding.id,
        &finding.r#type,
        &finding.detector,
        confidence,
        range,
    )?
    .with_obfuscation(obfuscation))
}

/// Reconstructs a native [`Finding`] from a JavaScript-supplied [`JsFinding`]
/// whose UTF-16 range bounds were already resolved to UTF-8 bytes.
///
/// # Errors
///
/// Returns [`SecretScanErrorCode::InvalidFindings`] when a range offset is
/// out of bounds or splits a surrogate pair (`start`/`end` carry that
/// resolution error, start first), `start >= end`, or `confidence` /
/// `action` is not one of the fixed wire names.
fn from_js_finding(
    finding: &JsFinding,
    start: Result<usize, SecretScanError>,
    end: Result<usize, SecretScanError>,
) -> Result<Finding, SecretScanError> {
    let start = start?;
    let end = end?;
    let range = ByteRange::new(start, end).ok_or(SecretScanErrorCode::InvalidFindings)?;
    let confidence =
        Confidence::from_name(&finding.confidence).ok_or(SecretScanErrorCode::InvalidFindings)?;
    let action = Action::from_name(&finding.action).ok_or(SecretScanErrorCode::InvalidFindings)?;
    let obfuscation =
        Obfuscation::from_name(&finding.obfuscation).ok_or(SecretScanErrorCode::InvalidFindings)?;
    Ok(DetectedFinding::new(
        &finding.id,
        &finding.r#type,
        &finding.detector,
        confidence,
        range,
    )?
    .with_obfuscation(obfuscation)
    .with_action(action))
}

/// Loads the optional declarative action policy a whole-input call carries
/// (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`,
/// issue #1219). The compiled [`ActionPolicy`] is owned by the one call that
/// loaded it: no thread-local, process-global or one-slot cache holds it, so
/// another call can neither evict nor overwrite it.
///
/// A callback `policy` and an action policy together are rejected with
/// `INVALID_OPTIONS` before the document is read; a rejected document is
/// `INVALID_ACTION_POLICY` with its fixed class and rule index in the
/// message. The core, not this function, performs every check of the
/// document.
fn load_call_action_policy(
    has_callback: bool,
    document: Option<&[u8]>,
) -> napi::Result<Option<ActionPolicy>, String> {
    let Some(bytes) = document else {
        return Ok(None);
    };
    if has_callback {
        return Err(to_js_error(SecretScanErrorCode::InvalidOptions.into()));
    }
    load_action_policy(bytes)
        .map(Some)
        .map_err(to_js_action_policy_error)
}

/// Runs the detector pipeline over `input` and evaluates `policy` (a
/// JavaScript callback), `action_policy` (a declarative overlay) or, when
/// both are absent, the core's [`DefaultPolicy`] once per finding. The caller
/// guarantees at most one of `policy` and `action_policy` is present
/// ([`load_call_action_policy`]).
///
/// Checks `limits` explicitly: unlike [`run_redact`], this function calls
/// `run_detector_pipeline` directly rather than a core function that already
/// applies a limit set, so it does not inherit the default bound for free.
///
/// `offsets` converts each finding's range for `policy`; it must be over
/// `input`.
fn run_scan(
    input: &str,
    registry: &DetectorRegistry,
    policy: Option<&PolicyCallback<'_>>,
    action_policy: Option<&ActionPolicy>,
    limits: &WholeInputLimits,
    offsets: &RefCell<Utf16Offsets<'_>>,
) -> Result<Vec<Finding>, SecretScanError> {
    limits.check_input(input)?;
    let detected = run_detector_pipeline(input, registry)?;
    limits.check_findings(detected.len())?;
    let finding_count = detected.len();
    detected
        .into_iter()
        .enumerate()
        .map(
            |(finding_index, finding)| -> Result<Finding, SecretScanError> {
                let context = PolicyContext::new(finding_index, finding_count);
                let action = if let Some(callback) = policy {
                    let js_finding = to_js_detected_finding(&mut offsets.borrow_mut(), &finding);
                    let js_context = JsPolicyContext {
                        finding_index: u32::try_from(finding_index).unwrap_or(u32::MAX),
                        finding_count: u32::try_from(finding_count).unwrap_or(u32::MAX),
                    };
                    let action_name: String = callback
                        .call(FnArgs::from((js_finding, js_context)))
                        .map_err(|_| SecretScanErrorCode::PolicyFailure)?;
                    Action::from_name(&action_name)
                        .ok_or(SecretScanErrorCode::InvalidPolicyAction)?
                } else if let Some(overlay) = action_policy {
                    Policy::evaluate(overlay, &finding, &context)
                        .map_err(|_| SecretScanErrorCode::PolicyFailure)?
                } else {
                    DefaultPolicy
                        .evaluate(&finding, &context)
                        .map_err(|_| SecretScanErrorCode::PolicyFailure)?
                };
                Ok(finding.with_action(action))
            },
        )
        .collect()
}

/// Adapts a JavaScript placeholder formatter callback to
/// [`PlaceholderFormatter`].
struct JsFormatterAdapter<'a, 'input, 'env> {
    callback: &'a FormatterCallback<'env>,
    offsets: &'a RefCell<Utf16Offsets<'input>>,
}

impl PlaceholderFormatter for JsFormatterAdapter<'_, '_, '_> {
    fn format(
        &self,
        finding: &Finding,
        context: &PlaceholderContext,
    ) -> Result<String, FormatterFailure> {
        // The borrow ends with this statement, before the callback runs.
        let js_finding = to_js_finding(&mut self.offsets.borrow_mut(), finding);
        let js_context = JsPlaceholderContext {
            placeholder_index: u32::try_from(context.placeholder_index()).unwrap_or(u32::MAX),
        };
        self.callback
            .call(FnArgs::from((js_finding, js_context)))
            .map_err(|_| FormatterFailure)
    }
}

/// Redacts `input`; `offsets` (over `input`) converts each range `formatter`
/// sees.
fn run_redact(
    input: &str,
    findings: &[Finding],
    formatter: Option<&FormatterCallback<'_>>,
    limits: &WholeInputLimits,
    offsets: &RefCell<Utf16Offsets<'_>>,
) -> Result<String, SecretScanError> {
    match formatter {
        Some(callback) => {
            let adapter = JsFormatterAdapter { callback, offsets };
            core_redact_with_limits(input, findings, &adapter, limits)
        }
        None => core_redact_with_limits(input, findings, &default_placeholder_formatter, limits),
    }
}

/// One ruleset registry and what it was built from (issue #1059).
struct RulesetEntry {
    profile: Profile,
    selection: PiiSelection,
    ruleset: Vec<u8>,
    registry: DetectorRegistry,
}

thread_local! {
    /// The registry for the last `(profile, PII selection, ruleset bytes)`
    /// seen, so a caller repeating one ruleset parses it and builds the
    /// registry once rather than per call. One entry, thread-local for the
    /// same `!Sync` reason as [`REGISTRY`]; a changed ruleset replaces it, and
    /// a rejected ruleset is never stored.
    static RULESET_REGISTRY: RefCell<Option<Rc<RulesetEntry>>> = const { RefCell::new(None) };
    /// Ruleset registries built on this thread, for the cache-reuse test.
    #[cfg(test)]
    static RULESET_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Runs `f` against the registry over `ruleset`'s declared detectors, on top
/// of `profile`'s built-in set, building it only when it is not the one this
/// thread last built (see [`RULESET_REGISTRY`]).
fn with_ruleset_registry<T>(
    profile: Profile,
    ruleset: &[u8],
    f: impl FnOnce(&DetectorRegistry) -> Result<T, SecretScanError>,
) -> napi::Result<T, String> {
    let selection = pii_selection(profile);
    // The entry is cloned out so the cache is not borrowed while `f` runs: a
    // JavaScript policy or formatter callback inside `f` may itself call back
    // into a ruleset export on this thread.
    let entry = RULESET_REGISTRY.with(|cache| -> napi::Result<Rc<RulesetEntry>, String> {
        let mut cache = cache.borrow_mut();
        if let Some(entry) = cache.as_ref().filter(|entry| {
            entry.profile == profile && entry.selection == selection && entry.ruleset == ruleset
        }) {
            return Ok(Rc::clone(entry));
        }
        let detectors = load_ruleset(ruleset).map_err(to_js_ruleset_error)?;
        let registry = match profile {
            Profile::Common => {
                DetectorRegistry::with_common_built_in_and_pii_custom(&selection, detectors)
            }
            _ => DetectorRegistry::with_built_in_and_pii_custom(&selection, detectors),
        }
        .map_err(to_js_error)?;
        #[cfg(test)]
        RULESET_BUILDS.with(|builds| builds.set(builds.get() + 1));
        let entry = Rc::new(RulesetEntry {
            profile,
            selection,
            ruleset: ruleset.to_vec(),
            registry,
        });
        *cache = Some(Rc::clone(&entry));
        Ok(entry)
    })?;
    f(&entry.registry).map_err(to_js_error)
}

/// Runs [`run_scan`] against `profile`'s registry: the shared cached
/// built-in-only registry when `ruleset` is omitted, or the registry
/// over `ruleset`'s declared detectors otherwise (cached for repeats)
/// (`decision-define-declarative-detector-ruleset-contract`'s "Surface
/// exposure": "a `Uint8Array`/`string` ruleset argument alongside the
/// existing registry construction path"). A registry built either way still
/// registers `profile`'s built-ins first, so a ruleset detector can add
/// detections but never outrank a built-in's resolved finding.
fn run_scan_for_profile(
    profile: Profile,
    input: &str,
    policy: Option<&PolicyCallback<'_>>,
    action_policy: Option<&ActionPolicy>,
    limits: &WholeInputLimits,
    ruleset: Option<&[u8]>,
    offsets: &RefCell<Utf16Offsets<'_>>,
) -> napi::Result<Vec<Finding>, String> {
    match ruleset {
        None => with_profile_registry(profile, |registry| {
            run_scan(input, registry, policy, action_policy, limits, offsets)
        })
        .map_err(to_js_error),
        Some(bytes) => with_ruleset_registry(profile, bytes, |registry| {
            run_scan(input, registry, policy, action_policy, limits, offsets)
        }),
    }
}

/// [`run_scan_for_profile`] plus the conversion of its findings to their
/// N-API shape, all through one [`Utf16Offsets`] over `input`.
fn scan_for_profile(
    profile: Profile,
    input: &str,
    policy: Option<&PolicyCallback<'_>>,
    limits: Option<&JsWholeInputLimits>,
    ruleset: Option<&[u8]>,
    action_policy: Option<&[u8]>,
) -> napi::Result<Vec<JsFinding>, String> {
    let limits = resolve_whole_input_limits(limits).map_err(to_js_error)?;
    let action_policy = load_call_action_policy(policy.is_some(), action_policy)?;
    let offsets = RefCell::new(Utf16Offsets::new(input));
    let findings = run_scan_for_profile(
        profile,
        input,
        policy,
        action_policy.as_ref(),
        &limits,
        ruleset,
        &offsets,
    )?;
    Ok(to_js_findings(&mut offsets.borrow_mut(), &findings))
}

/// Scans `input` and returns every finding, in input order, with UTF-16
/// ranges. When `policy` is omitted, the core's default policy chooses each
/// finding's action. When `limits` is omitted, the core's default whole-input
/// bound applies (`decision-bound-whole-input-operations-by-default`).
///
/// # Errors
///
/// - `INPUT_LIMIT_EXCEEDED` when `input` exceeds `limits.maxInputBytes` (or
///   the default).
/// - `FINDING_LIMIT_EXCEEDED` when the accepted finding count exceeds
///   `limits.maxFindings` (or the default).
/// - `INVALID_LIMITS` when `limits` is given and either field is zero.
/// - `DETECTOR_FAILURE` / `INVALID_CANDIDATE` from the detector pipeline.
/// - `POLICY_FAILURE` when `policy` throws.
/// - `INVALID_POLICY_ACTION` when `policy` returns something other than
///   `"redact"`, `"block"`, `"warn"`, or `"allow"`.
/// - `INVALID_RULESET` when `ruleset` is given and does not parse; the fixed
///   rejection class is appended to the thrown error's message.
/// - `INVALID_ACTION_POLICY` when `action_policy` is given and does not
///   parse; the fixed rejection class and, inside a rule, its zero-based
///   index are appended to the thrown error's message.
/// - `INVALID_OPTIONS` when both `policy` and `action_policy` are given.
///
/// No error carries `input`, `ruleset`'s or `action_policy`'s bytes, or a
/// matched value.
///
/// When `ruleset` is given, its declared detectors register after every
/// built-in, exactly as a native custom detector would
/// (`decision-define-declarative-detector-ruleset-contract`).
///
/// When `action_policy` is given (the bytes of a revision 1 declarative
/// action policy document), it replaces the default per-finding evaluation:
/// the first matching rule's action, or the default action when none
/// matches (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`).
/// The compiled policy lives only for this call.
// N-API's generated argument conversion produces owned `String`/`Function`
// values; there is no borrowed form to take instead.
#[allow(clippy::needless_pass_by_value)]
#[napi]
pub fn scan(
    input: String,
    #[napi(ts_arg_type = "(finding: JsDetectedFinding, context: JsPolicyContext) => string")]
    policy: Option<PolicyCallback<'_>>,
    limits: Option<JsWholeInputLimits>,
    ruleset: Option<Buffer>,
    action_policy: Option<Buffer>,
) -> napi::Result<Vec<JsFinding>, String> {
    scan_for_profile(
        Profile::Full,
        &input,
        policy.as_ref(),
        limits.as_ref(),
        ruleset.as_deref(),
        action_policy.as_deref(),
    )
}

/// The `common`-profile analogue of [`scan`]
/// (`decision-define-detector-profile-and-pack-contract`): same behavior,
/// against the `common` registry's smaller detector set. A bare
/// provider-shaped token with no credential-bearing context, which the
/// `full` profile's `provider` detectors catch, is not detected at all —
/// the documented false-negative cost of `common`.
///
/// # Errors
///
/// The same as [`scan`].
// See `scan`'s attribute: owned params are what N-API hands back.
#[allow(clippy::needless_pass_by_value)]
#[napi]
pub fn scan_common(
    input: String,
    #[napi(ts_arg_type = "(finding: JsDetectedFinding, context: JsPolicyContext) => string")]
    policy: Option<PolicyCallback<'_>>,
    limits: Option<JsWholeInputLimits>,
    ruleset: Option<Buffer>,
    action_policy: Option<Buffer>,
) -> napi::Result<Vec<JsFinding>, String> {
    scan_for_profile(
        Profile::Common,
        &input,
        policy.as_ref(),
        limits.as_ref(),
        ruleset.as_deref(),
        action_policy.as_deref(),
    )
}

/// Replaces `redact`/`block` findings in `input` with placeholder text,
/// leaving `warn`/`allow` findings untouched. `findings` is normally the
/// output of [`scan`] and need not be pre-sorted. When `formatter` is
/// omitted, the core's default `<SECRET_N>` formatter is used. When `limits`
/// is omitted, the core's default whole-input bound applies
/// (`decision-bound-whole-input-operations-by-default`).
///
/// # Errors
///
/// - `INPUT_LIMIT_EXCEEDED` when `input` exceeds `limits.maxInputBytes` (or
///   the default).
/// - `FINDING_LIMIT_EXCEEDED` when `findings.length` exceeds
///   `limits.maxFindings` (or the default).
/// - `INVALID_LIMITS` when `limits` is given and either field is zero.
/// - `INVALID_FINDINGS` when a finding's range is out of bounds, splits a
///   UTF-16 surrogate pair, or overlaps another finding, or its `confidence`
///   / `action` is not a fixed wire name.
/// - `PLACEHOLDER_FAILURE` when `formatter` throws.
/// - `INVALID_PLACEHOLDER` when `formatter` returns an empty, oversized, or
///   matched-value-reproducing placeholder.
///
/// No error carries `input`, a matched value, or a placeholder.
// See `scan`'s attribute: owned params are what N-API hands back.
#[allow(clippy::needless_pass_by_value)]
#[napi]
pub fn redact(
    input: String,
    findings: Vec<JsFinding>,
    #[napi(ts_arg_type = "(finding: JsFinding, context: JsPlaceholderContext) => string")]
    formatter: Option<FormatterCallback<'_>>,
    limits: Option<JsWholeInputLimits>,
) -> napi::Result<String, String> {
    let limits = resolve_whole_input_limits(limits.as_ref()).map_err(to_js_error)?;
    let native_findings = from_js_findings(&input, &findings).map_err(to_js_error)?;
    let offsets = RefCell::new(Utf16Offsets::new(&input));
    run_redact(
        &input,
        &native_findings,
        formatter.as_ref(),
        &limits,
        &offsets,
    )
    .map_err(to_js_error)
}

/// Runs [`run_scan_for_profile`] then [`run_redact`] against `profile`,
/// converting the result to its N-API shape.
fn run_scan_and_redact_for_profile(
    profile: Profile,
    input: &str,
    policy: Option<&PolicyCallback<'_>>,
    formatter: Option<&FormatterCallback<'_>>,
    limits: &WholeInputLimits,
    ruleset: Option<&[u8]>,
    action_policy: Option<&[u8]>,
) -> napi::Result<JsScanAndRedactResult, String> {
    let action_policy = load_call_action_policy(policy.is_some(), action_policy)?;
    // One converter for the whole call: the policy callback, the formatter
    // callback, and the returned findings all convert through it.
    let offsets = RefCell::new(Utf16Offsets::new(input));
    let findings = run_scan_for_profile(
        profile,
        input,
        policy,
        action_policy.as_ref(),
        limits,
        ruleset,
        &offsets,
    )?;
    let redacted =
        run_redact(input, &findings, formatter, limits, &offsets).map_err(to_js_error)?;
    let js_findings = to_js_findings(&mut offsets.borrow_mut(), &findings);
    Ok(JsScanAndRedactResult {
        findings: js_findings,
        redacted,
    })
}

/// Scans `input` and redacts it in one call, returning both the findings and
/// the redacted text. Equivalent to calling [`scan`] then [`redact`], but
/// avoids reconverting findings through their public UTF-16 shape.
///
/// # Errors
///
/// Every error [`scan`] and [`redact`] can return.
// See `scan`'s attribute: owned params are what N-API hands back.
#[allow(clippy::needless_pass_by_value)]
#[napi]
pub fn scan_and_redact(
    input: String,
    #[napi(ts_arg_type = "(finding: JsDetectedFinding, context: JsPolicyContext) => string")]
    policy: Option<PolicyCallback<'_>>,
    #[napi(ts_arg_type = "(finding: JsFinding, context: JsPlaceholderContext) => string")]
    formatter: Option<FormatterCallback<'_>>,
    limits: Option<JsWholeInputLimits>,
    ruleset: Option<Buffer>,
    action_policy: Option<Buffer>,
) -> napi::Result<JsScanAndRedactResult, String> {
    let limits = resolve_whole_input_limits(limits.as_ref()).map_err(to_js_error)?;
    run_scan_and_redact_for_profile(
        Profile::Full,
        &input,
        policy.as_ref(),
        formatter.as_ref(),
        &limits,
        ruleset.as_deref(),
        action_policy.as_deref(),
    )
}

/// The `common`-profile analogue of [`scan_and_redact`]
/// (`decision-define-detector-profile-and-pack-contract`): equivalent to
/// calling [`scan_common`] then [`redact`] with its result.
///
/// # Errors
///
/// Every error [`scan_common`] and [`redact`] can return.
// See `scan`'s attribute: owned params are what N-API hands back.
#[allow(clippy::needless_pass_by_value)]
#[napi]
pub fn scan_and_redact_common(
    input: String,
    #[napi(ts_arg_type = "(finding: JsDetectedFinding, context: JsPolicyContext) => string")]
    policy: Option<PolicyCallback<'_>>,
    #[napi(ts_arg_type = "(finding: JsFinding, context: JsPlaceholderContext) => string")]
    formatter: Option<FormatterCallback<'_>>,
    limits: Option<JsWholeInputLimits>,
    ruleset: Option<Buffer>,
    action_policy: Option<Buffer>,
) -> napi::Result<JsScanAndRedactResult, String> {
    let limits = resolve_whole_input_limits(limits.as_ref()).map_err(to_js_error)?;
    run_scan_and_redact_for_profile(
        Profile::Common,
        &input,
        policy.as_ref(),
        formatter.as_ref(),
        &limits,
        ruleset.as_deref(),
        action_policy.as_deref(),
    )
}

// ---------------------------------------------------------------------
// Explain and compare action policies (issue #1220)
// ---------------------------------------------------------------------

/// What detection saw, apart from every policy: the registry's activation
/// identity, its profile when it has one, and its detector count
/// (`decision-explain-and-compare-action-policies-over-one-detection-pass`).
#[napi(object)]
pub struct JsComparisonDetection {
    /// The canonical credentials/PII activation identity.
    pub activation_identity: String,
    /// `"full"` or `"common"`, or absent for a registry with no profile.
    pub profile: Option<String>,
    /// How many detectors the registry holds.
    pub detector_count: u32,
}

/// One compared policy's binding and per-action counts.
#[napi(object)]
pub struct JsComparedSide {
    /// `"default"`, `"action-policy"` or `"callback"`.
    pub kind: String,
    /// Lowercase SHA-256 of an action policy document's exact bytes; absent
    /// for the default and for a callback.
    pub document_sha256: Option<String>,
    /// Findings this side redacts.
    pub redact: u32,
    /// Findings this side blocks.
    pub block: u32,
    /// Findings this side warns on.
    pub warn: u32,
    /// Findings this side allows.
    pub allow: u32,
}

/// One side's action for one finding and the reason for it.
#[napi(object)]
pub struct JsActionDecision {
    /// `"redact"`, `"block"`, `"warn"` or `"allow"`.
    pub action: String,
    /// `"rule"`, `"rule-default"`, `"no-rule-matched"`, `"default-policy"` or
    /// `"callback"`.
    pub basis: String,
    /// The deciding rule's id, for `rule` and `rule-default`.
    pub rule_id: Option<String>,
    /// The deciding rule's zero-based index, for `rule` and `rule-default`.
    pub rule_index: Option<u32>,
}

/// One finalized finding and every side's decision for it. Ranges are UTF-16
/// code-unit offsets.
#[napi(object)]
pub struct JsComparedFinding {
    /// Deterministic finding id (`finding-1`, `finding-2`, ...).
    pub id: String,
    /// Finding type.
    pub r#type: String,
    /// Id of the detector that produced this finding.
    pub detector: String,
    /// `"high"`, `"medium"`, or `"low"`.
    pub confidence: String,
    /// `"none"` or `"invisible-characters"`.
    pub obfuscation: String,
    /// Start offset in UTF-16 code units.
    pub start: u32,
    /// End offset in UTF-16 code units (exclusive).
    pub end: u32,
    /// Whether the sides do not all choose the same action.
    pub differs: bool,
    /// One decision per side, in the order the sides were supplied.
    pub decisions: Vec<JsActionDecision>,
}

/// The result of [`compare_action_policies`]: a preview, never enforcement.
#[napi(object)]
pub struct JsActionComparison {
    /// The detection configuration, apart from every policy.
    pub detection: JsComparisonDetection,
    /// One entry per side, in the order supplied.
    pub sides: Vec<JsComparedSide>,
    /// How many findings differ between the sides.
    pub changed_count: u32,
    /// Every finalized finding, in `scan`'s order.
    pub findings: Vec<JsComparedFinding>,
}

/// How one comparison side is evaluated, once every document is loaded.
enum ComparedSidePlan {
    Default,
    ActionPolicy(ActionPolicy),
    /// The position among the call's callbacks.
    Callback(usize),
}

/// Resolves the parallel `kinds`/`documents`/`callbacks` arguments to one plan
/// per side. The count check comes first, so a call with no or too many sides
/// loads no document and runs no callback; a rejected document is
/// `INVALID_ACTION_POLICY` before detection starts. The parallel arrays are
/// built by this package's own wrapper, so a mismatch here is a malformed
/// call and `INVALID_OPTIONS`.
fn plan_compared_sides(
    kinds: &[String],
    documents: &[Buffer],
    callback_count: usize,
) -> napi::Result<Vec<ComparedSidePlan>, String> {
    let invalid = || to_js_error(SecretScanErrorCode::InvalidOptions.into());
    if kinds.is_empty() || kinds.len() > MAX_COMPARED_POLICIES {
        return Err(invalid());
    }
    let mut documents = documents.iter();
    let mut next_callback = 0;
    let mut plans = Vec::with_capacity(kinds.len());
    for kind in kinds {
        plans.push(match kind.as_str() {
            "default" => ComparedSidePlan::Default,
            "action-policy" => {
                let bytes = documents.next().ok_or_else(invalid)?;
                ComparedSidePlan::ActionPolicy(
                    load_action_policy(bytes).map_err(to_js_action_policy_error)?,
                )
            }
            "callback" => {
                if next_callback >= callback_count {
                    return Err(invalid());
                }
                next_callback += 1;
                ComparedSidePlan::Callback(next_callback - 1)
            }
            _ => return Err(invalid()),
        });
    }
    if documents.next().is_some() || next_callback != callback_count {
        return Err(invalid());
    }
    Ok(plans)
}

/// Adapts a JavaScript policy callback to [`Policy`] for one comparison side,
/// with the same callback arguments, UTF-16 conversion and failure codes as
/// [`run_scan`]: a throw is `POLICY_FAILURE` and a return outside the four
/// action names is `INVALID_POLICY_ACTION`. The core's [`PolicyFailure`]
/// carries no detail, so the precise code is recorded here for
/// [`Self::refine`].
struct JsCompareCallback<'a, 'input, 'env> {
    callback: &'a PolicyCallback<'env>,
    offsets: &'a RefCell<Utf16Offsets<'input>>,
    failure: Cell<Option<SecretScanErrorCode>>,
}

impl JsCompareCallback<'_, '_, '_> {
    /// The more precise code of the failure the core reported, if this
    /// callback recorded one.
    fn refine(&self, error: SecretScanError) -> SecretScanError {
        match (error.code(), self.failure.take()) {
            (SecretScanErrorCode::PolicyFailure, Some(code)) => code.into(),
            _ => error,
        }
    }
}

impl Policy for JsCompareCallback<'_, '_, '_> {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        let js_finding = to_js_detected_finding(&mut self.offsets.borrow_mut(), finding);
        let js_context = JsPolicyContext {
            finding_index: u32::try_from(context.finding_index()).unwrap_or(u32::MAX),
            finding_count: u32::try_from(context.finding_count()).unwrap_or(u32::MAX),
        };
        let action_name: String = self
            .callback
            .call(FnArgs::from((js_finding, js_context)))
            .map_err(|_| PolicyFailure)?;
        Action::from_name(&action_name).ok_or_else(|| {
            self.failure
                .set(Some(SecretScanErrorCode::InvalidPolicyAction));
            PolicyFailure
        })
    }
}

/// Converts the core comparison to its N-API shape, every range through
/// `offsets`.
fn to_js_comparison(
    offsets: &mut Utf16Offsets<'_>,
    comparison: &ActionComparison,
) -> JsActionComparison {
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    let detection = comparison.detection();
    JsActionComparison {
        detection: JsComparisonDetection {
            activation_identity: detection.activation_identity().to_owned(),
            profile: detection
                .profile()
                .map(|profile| profile.as_str().to_owned()),
            detector_count: count(detection.detector_count()),
        },
        sides: comparison
            .sides()
            .iter()
            .map(|side| {
                let counts = side.counts();
                JsComparedSide {
                    kind: side.binding().kind().to_owned(),
                    document_sha256: side.binding().document_sha256_hex(),
                    redact: count(counts.redact()),
                    block: count(counts.block()),
                    warn: count(counts.warn()),
                    allow: count(counts.allow()),
                }
            })
            .collect(),
        changed_count: count(comparison.changed_count()),
        findings: comparison
            .findings()
            .iter()
            .map(|compared| {
                let finding = compared.finding();
                JsComparedFinding {
                    id: finding.id().to_owned(),
                    r#type: finding.type_name().to_owned(),
                    detector: finding.detector().to_owned(),
                    confidence: finding.confidence().as_str().to_owned(),
                    obfuscation: finding.obfuscation().as_str().to_owned(),
                    start: offsets.utf16_at(finding.range().start()),
                    end: offsets.utf16_at(finding.range().end()),
                    differs: compared.differs(),
                    decisions: compared
                        .decisions()
                        .iter()
                        .map(|decision| JsActionDecision {
                            action: decision.action().as_str().to_owned(),
                            basis: decision.basis().as_str().to_owned(),
                            rule_id: decision.basis().rule_id().map(str::to_owned),
                            rule_index: decision.basis().rule_index().map(count),
                        })
                        .collect(),
                }
            })
            .collect(),
    }
}

/// Runs one comparison over `registry`: the whole-input primitive, with the
/// callback sides adapted and the failure of one refined to its precise code.
fn run_compare(
    input: &str,
    registry: &DetectorRegistry,
    plans: &[ComparedSidePlan],
    callbacks: &[PolicyCallback<'_>],
    limits: &WholeInputLimits,
) -> Result<JsActionComparison, SecretScanError> {
    // One converter for the whole call, so every callback and the result
    // convert through the same walk over `input`.
    let offsets = RefCell::new(Utf16Offsets::new(input));
    let adapters: Vec<JsCompareCallback<'_, '_, '_>> = callbacks
        .iter()
        .map(|callback| JsCompareCallback {
            callback,
            offsets: &offsets,
            failure: Cell::new(None),
        })
        .collect();
    let policies: Vec<ComparedPolicy<'_>> = plans
        .iter()
        .map(|plan| match plan {
            ComparedSidePlan::Default => ComparedPolicy::Default,
            ComparedSidePlan::ActionPolicy(document) => ComparedPolicy::ActionPolicy(document),
            ComparedSidePlan::Callback(index) => ComparedPolicy::Callback(&adapters[*index]),
        })
        .collect();
    let comparison = compare_action_policies_with_limits(input, registry, &policies, limits)
        .map_err(|error| {
            // At most one callback failed: the comparison stops at the first.
            adapters
                .iter()
                .fold(error, |error, adapter| adapter.refine(error))
        })?;
    Ok(to_js_comparison(&mut offsets.borrow_mut(), &comparison))
}

/// [`run_compare`] against `profile`'s shared registry, or the registry over
/// `ruleset` when one is given (cached for repeats, as for [`scan`]).
fn compare_for_profile(
    profile: Profile,
    input: &str,
    kinds: &[String],
    documents: &[Buffer],
    callbacks: &[PolicyCallback<'_>],
    limits: Option<&JsWholeInputLimits>,
    ruleset: Option<&[u8]>,
) -> napi::Result<JsActionComparison, String> {
    let plans = plan_compared_sides(kinds, documents, callbacks.len())?;
    let limits = resolve_whole_input_limits(limits).map_err(to_js_error)?;
    match ruleset {
        None => with_profile_registry(profile, |registry| {
            run_compare(input, registry, &plans, callbacks, &limits)
        })
        .map_err(to_js_error),
        Some(bytes) => with_ruleset_registry(profile, bytes, |registry| {
            run_compare(input, registry, &plans, callbacks, &limits)
        }),
    }
}

/// Compares what `kinds.len()` policies choose for the findings `input`
/// yields, over one detection pass and without enforcing any of them
/// (`decision-explain-and-compare-action-policies-over-one-detection-pass`,
/// issue #1220). The whole-input primitive only: there is no session or
/// stream variant.
///
/// The sides arrive as parallel arguments: `kinds` names each side in order
/// (`"default"`, `"action-policy"`, `"callback"`), `documents` holds the
/// action policy documents in the order their sides appear, and `callbacks`
/// the callbacks in the order theirs do. Callback sides run one at a time, in
/// the order given, each once per finding in finding order.
///
/// # Errors
///
/// - `INVALID_OPTIONS` when there are zero or more than four sides, or the
///   arguments do not describe the same sides.
/// - `INVALID_LIMITS`, `INPUT_LIMIT_EXCEEDED` and `FINDING_LIMIT_EXCEEDED`
///   exactly as [`scan`]; the finding bound fails before any callback runs.
/// - `INVALID_ACTION_POLICY` when a document does not parse, and
///   `INVALID_RULESET` when `ruleset` does not parse, before any callback.
/// - `POLICY_FAILURE` when a callback throws, and `INVALID_POLICY_ACTION` when
///   one returns something other than the four action names. Either fails
///   the whole comparison, with no partial result.
/// - `DETECTOR_FAILURE` / `INVALID_CANDIDATE` from the detector pipeline.
///
/// No error carries `input`, a document, or a matched value.
// See `scan`'s attribute: owned params are what N-API hands back.
#[allow(clippy::needless_pass_by_value)]
#[napi(js_name = "compareActionPolicies")]
pub fn compare_action_policies(
    input: String,
    kinds: Vec<String>,
    #[napi(ts_arg_type = "Uint8Array[]")] documents: Vec<Buffer>,
    #[napi(ts_arg_type = "((finding: JsDetectedFinding, context: JsPolicyContext) => string)[]")]
    callbacks: Vec<PolicyCallback<'_>>,
    limits: Option<JsWholeInputLimits>,
    ruleset: Option<Buffer>,
) -> napi::Result<JsActionComparison, String> {
    compare_for_profile(
        Profile::Full,
        &input,
        &kinds,
        &documents,
        &callbacks,
        limits.as_ref(),
        ruleset.as_deref(),
    )
}

/// The `common`-profile analogue of [`compare_action_policies`]: the same
/// behavior against the `common` registry.
///
/// # Errors
///
/// The same as [`compare_action_policies`].
// See `scan`'s attribute: owned params are what N-API hands back.
#[allow(clippy::needless_pass_by_value)]
#[napi(js_name = "compareActionPoliciesCommon")]
pub fn compare_action_policies_common(
    input: String,
    kinds: Vec<String>,
    #[napi(ts_arg_type = "Uint8Array[]")] documents: Vec<Buffer>,
    #[napi(ts_arg_type = "((finding: JsDetectedFinding, context: JsPolicyContext) => string)[]")]
    callbacks: Vec<PolicyCallback<'_>>,
    limits: Option<JsWholeInputLimits>,
    ruleset: Option<Buffer>,
) -> napi::Result<JsActionComparison, String> {
    compare_for_profile(
        Profile::Common,
        &input,
        &kinds,
        &documents,
        &callbacks,
        limits.as_ref(),
        ruleset.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offsets_for(input: &str) -> RefCell<Utf16Offsets<'_>> {
        RefCell::new(Utf16Offsets::new(input))
    }

    #[test]
    fn artifact_manifests_name_each_profile_and_touch_no_activation() {
        // Generation builds no registry: the thread's profile cells stay
        // empty, so a later initialization with a PII selection still works.
        let full = artifact_manifest().unwrap();
        let common = artifact_manifest_common().unwrap();
        assert!(full.starts_with("{\"schema\":\"artifact-manifest/v1\","));
        assert!(full.contains("\"kind\":\"node-addon\""));
        assert!(full.contains("\"variant\":\"full\""));
        assert!(common.contains("\"variant\":\"common\""));
        assert!(common.contains("\"notIncluded\":[\"aws-access-key\""));
        assert_ne!(full, common);
        assert_eq!(full, artifact_manifest().unwrap());
        assert!(pii_selection(Profile::Full).is_off());
        assert!(pii_selection(Profile::Common).is_off());
        REGISTRY.with(|cell| assert!(cell.get().is_none()));
        REGISTRY_COMMON.with(|cell| assert!(cell.get().is_none()));
    }

    fn from_one_js_finding(input: &str, finding: &JsFinding) -> Result<Finding, SecretScanError> {
        from_js_findings(input, std::slice::from_ref(finding)).map(|mut all| all.remove(0))
    }

    /// Comparable field tuple for a [`JsFinding`], which has no [`PartialEq`]
    /// of its own.
    fn finding_key(finding: &JsFinding) -> (&str, &str, &str, &str, &str, &str, u32, u32) {
        (
            &finding.id,
            &finding.r#type,
            &finding.detector,
            &finding.confidence,
            &finding.action,
            &finding.obfuscation,
            finding.start,
            finding.end,
        )
    }

    fn scan_default(input: &str) -> Vec<Finding> {
        with_profile_registry(Profile::Full, |registry| {
            run_scan(
                input,
                registry,
                None,
                None,
                &WholeInputLimits::default(),
                &offsets_for(input),
            )
        })
        .unwrap()
    }

    const COMPARE_INPUT: &str = "\u{1F511} API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";

    fn compare_document(action: &str) -> Buffer {
        Buffer::from(
            format!(
                r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"rule-a","match":{{"type":["github_token"]}},"action":"{action}"}}]}}"#
            )
            .into_bytes(),
        )
    }

    fn side_kinds(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn compare_default_and_documents(
        kind_names: &[&str],
        documents: &[Buffer],
        limits: &WholeInputLimits,
    ) -> Result<JsActionComparison, SecretScanError> {
        let plans = plan_compared_sides(&side_kinds(kind_names), documents, 0).unwrap();
        with_profile_registry(Profile::Full, |registry| {
            run_compare(COMPARE_INPUT, registry, &plans, &[], limits)
        })
    }

    #[test]
    fn plan_compared_sides_bounds_the_side_count_before_loading_anything() {
        // A document that would be rejected is never read: the count fails first.
        let broken: Vec<Buffer> = (0..5).map(|_| Buffer::from(b"{}".to_vec())).collect();

        for (names, documents) in [
            (side_kinds(&[]), vec![]),
            (side_kinds(&["action-policy"; 5]), broken),
        ] {
            let error = plan_compared_sides(&names, &documents, 0).err().unwrap();
            assert_eq!(error.status, "INVALID_OPTIONS");
        }
        assert_eq!(
            plan_compared_sides(&side_kinds(&["default"; 4]), &[], 0)
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn plan_compared_sides_refuses_arguments_that_do_not_describe_the_same_sides() {
        for (names, documents, callbacks) in [
            (side_kinds(&["session"]), vec![], 0),
            (side_kinds(&["default"]), vec![compare_document("warn")], 0),
            (side_kinds(&["action-policy"]), vec![], 0),
            (side_kinds(&["default"]), vec![], 1),
            (side_kinds(&["callback"]), vec![], 0),
        ] {
            let error = plan_compared_sides(&names, &documents, callbacks)
                .err()
                .unwrap();
            assert_eq!(error.status, "INVALID_OPTIONS", "{names:?}");
        }
    }

    #[test]
    fn plan_compared_sides_reports_a_rejected_document_with_its_class() {
        let error = plan_compared_sides(
            &side_kinds(&["default", "action-policy"]),
            &[Buffer::from(b"{}".to_vec())],
            0,
        )
        .err()
        .unwrap();

        assert_eq!(error.status, "INVALID_ACTION_POLICY");
        assert_eq!(
            error.reason,
            "The supplied action policy is invalid. (MISSING_FIELD)"
        );
    }

    #[test]
    fn a_comparison_explains_each_side_and_matches_scan_in_utf16() {
        let result = compare_default_and_documents(
            &["default", "action-policy", "action-policy"],
            &[compare_document("allow"), compare_document("default")],
            &WholeInputLimits::default(),
        )
        .unwrap();
        let scanned = scan_default(COMPARE_INPUT);
        let js_scanned = to_js_finding(&mut Utf16Offsets::new(COMPARE_INPUT), &scanned[0]);

        assert_eq!(result.findings.len(), scanned.len());
        let compared = &result.findings[0];
        assert_eq!(compared.id, scanned[0].id());
        // The key emoji is two UTF-16 code units but four UTF-8 bytes.
        assert_eq!(
            (compared.start, compared.end),
            (js_scanned.start, js_scanned.end)
        );
        assert_ne!(compared.start as usize, scanned[0].range().start());
        assert_eq!(compared.decisions.len(), 3);
        assert_eq!(compared.decisions[0].action, js_scanned.action);
        assert_eq!(compared.decisions[0].basis, "default-policy");
        assert_eq!(compared.decisions[1].action, "allow");
        assert_eq!(compared.decisions[1].basis, "rule");
        assert_eq!(compared.decisions[1].rule_id.as_deref(), Some("rule-a"));
        assert_eq!(compared.decisions[1].rule_index, Some(0));
        assert_eq!(compared.decisions[2].basis, "rule-default");
        assert_eq!(compared.decisions[2].action, js_scanned.action);
        assert!(compared.differs);
        assert_eq!(result.changed_count, 1);
        let registry_len =
            with_profile_registry(Profile::Full, |registry| Ok(registry.len())).unwrap();
        assert_eq!(result.detection.detector_count as usize, registry_len);
        assert_eq!(result.detection.profile.as_deref(), Some("full"));
        assert_eq!(result.sides[0].kind, "default");
        assert_eq!(result.sides[0].document_sha256, None);
        assert_eq!(result.sides[1].kind, "action-policy");
        assert_eq!(
            result.sides[1].document_sha256.as_ref().map(String::len),
            Some(64)
        );
        assert_eq!((result.sides[1].allow, result.sides[1].redact), (1, 0));
    }

    #[test]
    fn a_comparison_applies_the_whole_input_limits_as_scan_does() {
        let bytes = WholeInputLimits::new(5, 50).unwrap();
        let findings = WholeInputLimits::new(1_000, 1).unwrap();
        let two = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000\nTOKEN=ghp_SYNTHETICREVOKED00000000000000000001";

        let error = compare_default_and_documents(&["default"], &[], &bytes)
            .err()
            .unwrap();
        assert_eq!(error.code(), SecretScanErrorCode::InputLimitExceeded);

        let plans = plan_compared_sides(&side_kinds(&["default"]), &[], 0).unwrap();
        let error = with_profile_registry(Profile::Full, |registry| {
            run_compare(two, registry, &plans, &[], &findings)
        })
        .err()
        .unwrap();
        assert_eq!(error.code(), SecretScanErrorCode::FindingLimitExceeded);
    }

    #[test]
    fn initialize_is_idempotent() {
        assert!(initialize().is_ok());
        assert!(initialize().is_ok());
        assert!(initialize().is_ok());
        // The registry built on the first call is reused, not rebuilt.
        assert!(with_profile_registry(Profile::Full, |registry| Ok(!registry.is_empty())).unwrap());
    }

    /// A synthetic, revoked-looking synchronous conformance smoke case:
    /// exercises the real built-in detector pipeline, the default policy,
    /// and redaction end to end through this binding's own `run_scan`/
    /// `run_redact`, with UTF-16 offsets reported at an astral-adjacent
    /// boundary (mirrors `conformance/fixtures/synchronous-corpus.json` and
    /// `unicode-conversion-corpus.json` in spirit; this crate does not load
    /// the corpus itself — see `conformance/README.md`).
    #[test]
    fn canonical_synchronous_conformance_smoke_case() {
        let input =
            "\u{1F511} Authorization: Bearer sk-syntheticRevokedExampleToken00000000000000000000";
        let findings = scan_default(input);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.action(), Action::Redact);

        let js_finding = to_js_finding(&mut Utf16Offsets::new(input), finding);
        // The key emoji (one astral character, a UTF-16 surrogate pair) and
        // the following space sit entirely before the match.
        assert_eq!(
            js_finding.start,
            crate::offsets::byte_to_utf16(input, finding.range().start())
        );
        assert!(js_finding.start >= 3);

        let redacted = run_redact(
            input,
            &findings,
            None,
            &WholeInputLimits::default(),
            &offsets_for(input),
        )
        .unwrap();
        assert!(redacted.starts_with("\u{1F511} Authorization: Bearer <SECRET_1>"));
        assert!(!redacted.contains("sk-syntheticRevokedExampleToken"));
    }

    #[test]
    fn default_policy_warns_low_confidence_findings_without_replacing_text() {
        // A short, low-entropy contextual assignment: findable, but not
        // high-confidence enough for the default policy to redact.
        let input = "note=ok";
        let findings = scan_default(input);
        assert!(findings.iter().all(|f| f.action() != Action::Block));
    }

    #[test]
    fn redact_round_trips_scan_output_through_its_public_utf16_shape() {
        let input = "Authorization: Bearer sk-syntheticRevokedExampleToken00000000000000000000";
        let findings = scan_default(input);
        assert_eq!(findings.len(), 1);

        let js_findings: Vec<JsFinding> = findings
            .iter()
            .map(|f| to_js_finding(&mut Utf16Offsets::new(input), f))
            .collect();
        let native_again: Vec<Finding> = js_findings
            .iter()
            .map(|f| from_one_js_finding(input, f).unwrap())
            .collect();
        assert_eq!(native_again, findings);
    }

    #[test]
    fn redact_rejects_a_finding_whose_range_splits_a_surrogate_pair() {
        let input = "\u{1F511}key";
        let malformed = JsFinding {
            id: "finding-1".to_owned(),
            r#type: "synthetic".to_owned(),
            detector: "synthetic".to_owned(),
            confidence: "high".to_owned(),
            action: "redact".to_owned(),
            obfuscation: "none".to_owned(),
            start: 1,
            end: 2,
        };
        let error = from_one_js_finding(input, &malformed).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidFindings);
    }

    #[test]
    fn redact_rejects_an_unknown_action_name() {
        let input = "value";
        let malformed = JsFinding {
            id: "finding-1".to_owned(),
            r#type: "synthetic".to_owned(),
            detector: "synthetic".to_owned(),
            confidence: "high".to_owned(),
            action: "delete".to_owned(),
            obfuscation: "none".to_owned(),
            start: 0,
            end: 5,
        };
        let error = from_one_js_finding(input, &malformed).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidFindings);
    }

    #[test]
    fn scan_and_redact_matches_separate_scan_then_redact() {
        let input = "Authorization: Bearer sk-syntheticRevokedExampleToken00000000000000000000";
        let findings = scan_default(input);
        let redacted = run_redact(
            input,
            &findings,
            None,
            &WholeInputLimits::default(),
            &offsets_for(input),
        )
        .unwrap();
        let js_findings: Vec<JsFinding> = findings
            .iter()
            .map(|f| to_js_finding(&mut Utf16Offsets::new(input), f))
            .collect();
        assert_eq!(js_findings.len(), 1);

        let combined = scan_and_redact(input.to_owned(), None, None, None, None, None).unwrap();
        assert_eq!(
            combined
                .findings
                .iter()
                .map(finding_key)
                .collect::<Vec<_>>(),
            js_findings.iter().map(finding_key).collect::<Vec<_>>()
        );
        assert_eq!(combined.redacted, redacted);
    }

    fn scan_common_default(input: &str) -> Vec<Finding> {
        with_profile_registry(Profile::Common, |registry| {
            run_scan(
                input,
                registry,
                None,
                None,
                &WholeInputLimits::default(),
                &offsets_for(input),
            )
        })
        .unwrap()
    }

    #[test]
    fn profile_and_profile_common_report_their_fixed_names() {
        assert_eq!(profile(), "full");
        assert_eq!(profile_common(), "common");
    }

    #[test]
    fn initialize_common_is_idempotent() {
        assert!(initialize_common().is_ok());
        assert!(initialize_common().is_ok());
        assert!(initialize_common().is_ok());
        // The registry built on the first call is reused, not rebuilt.
        assert!(
            with_profile_registry(Profile::Common, |registry| Ok(!registry.is_empty())).unwrap()
        );
    }

    /// The `common` registry links no `provider` detector, so a bare
    /// provider-shaped token with no credential-bearing context is not
    /// detected at all — the documented false-negative cost of `common`
    /// (`decision-define-detector-profile-and-pack-contract`). The `full`
    /// registry detects the same input. Mirrors
    /// `bindings/wasm/src/lib.rs::a_bare_provider_token_is_detected_only_by_the_full_profile`.
    #[test]
    fn a_bare_provider_token_is_detected_only_by_the_full_profile() {
        let input = format!("prefix \u{1F511} AKIA{} suffix", "SYNTHETICEXAMPLE");

        let full_findings = scan_default(&input);
        assert_eq!(full_findings.len(), 1);
        assert_eq!(full_findings[0].detector(), "aws-access-key");

        let common_findings = scan_common_default(&input);
        assert!(common_findings.is_empty());
    }

    /// `scan_and_redact_common`'s body, exercised the same way
    /// `scan_and_redact_matches_separate_scan_then_redact` exercises the
    /// `full` path: equivalent to a separate `scan_common` then `redact`.
    #[test]
    fn scan_and_redact_common_matches_separate_scan_then_redact() {
        let input = "postgres://user:SYNTHETIC_REVOKED_PASSWORD@example.test:5432/db";
        let findings = scan_common_default(input);
        assert_eq!(findings.len(), 1);
        let redacted = run_redact(
            input,
            &findings,
            None,
            &WholeInputLimits::default(),
            &offsets_for(input),
        )
        .unwrap();
        assert!(!redacted.contains("SYNTHETIC_REVOKED_PASSWORD"));
        let js_findings: Vec<JsFinding> = findings
            .iter()
            .map(|f| to_js_finding(&mut Utf16Offsets::new(input), f))
            .collect();

        let combined =
            scan_and_redact_common(input.to_owned(), None, None, None, None, None).unwrap();
        assert_eq!(
            combined
                .findings
                .iter()
                .map(finding_key)
                .collect::<Vec<_>>(),
            js_findings.iter().map(finding_key).collect::<Vec<_>>()
        );
        assert_eq!(combined.redacted, redacted);
    }

    /// Asserts `result` is an `Err` whose `status` is `expected`, without
    /// requiring the `Ok` type to implement `Debug` (several of this
    /// module's `Ok` types deliberately do not, so plain `unwrap_err()`
    /// does not typecheck here).
    fn assert_err_status<T>(result: napi::Result<T, String>, expected: &str) {
        let error = result.err().expect("expected an error");
        assert_eq!(error.status, expected);
    }

    fn tight_limits() -> JsWholeInputLimits {
        JsWholeInputLimits {
            max_input_bytes: 5,
            max_findings: 50,
        }
    }

    #[test]
    fn scan_rejects_input_over_an_explicit_byte_limit() {
        let input = "abcdef".to_owned();
        let result = scan(input, None, Some(tight_limits()), None, None);
        assert_err_status(result, "INPUT_LIMIT_EXCEEDED");
    }

    #[test]
    fn scan_rejects_a_finding_count_over_an_explicit_bound() {
        let input = format!(
            "prefix \u{1F511} AKIA{} suffix ghp_SYNTHETICREVOKED00000000000000000000",
            "SYNTHETICEXAMPLE"
        );
        // Confirms the ordinary default finds more than one, so a limit of 1
        // is a genuine rejection, not a coincidence of the input.
        assert!(scan_default(&input).len() > 1);

        let result = scan(
            input,
            None,
            Some(JsWholeInputLimits {
                max_input_bytes: 1024,
                max_findings: 1,
            }),
            None,
            None,
        );
        assert_err_status(result, "FINDING_LIMIT_EXCEEDED");
    }

    #[test]
    fn scan_rejects_a_zero_valued_explicit_limit() {
        let result = scan(
            "input".to_owned(),
            None,
            Some(JsWholeInputLimits {
                max_input_bytes: 0,
                max_findings: 50,
            }),
            None,
            None,
        );
        assert_err_status(result, "INVALID_LIMITS");
    }

    /// A minimal, valid declarative ruleset (issue #495).
    const RULESET_FIXTURE: &[u8] = b"ruleset-revision: 1\n\
detector: acme-internal-token\n\
specificity: contextual\n\
prefix: \"ACME_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";

    fn ruleset_builds() -> usize {
        RULESET_BUILDS.with(std::cell::Cell::get)
    }

    fn ruleset_count(profile: Profile, ruleset: &[u8], input: &str) -> usize {
        with_ruleset_registry(profile, ruleset, |registry| {
            Ok(run_detector_pipeline(input, registry)?.len())
        })
        .unwrap()
    }

    /// Issue #1059: a repeated ruleset is parsed and built once per thread,
    /// a change of bytes or profile rebuilds, a rejected ruleset is not
    /// cached, and a callback re-entering a ruleset export while one is
    /// running does not hit a held borrow.
    #[test]
    fn a_repeated_ruleset_builds_its_registry_once() {
        std::thread::spawn(|| {
            let input = "x ACME_aaaaaaaaaaaaaaaaaaaaaaaa y";
            let start = ruleset_builds();
            for _ in 0..5 {
                assert_eq!(ruleset_count(Profile::Full, RULESET_FIXTURE, input), 1);
            }
            assert_eq!(ruleset_builds() - start, 1);

            assert_eq!(ruleset_count(Profile::Common, RULESET_FIXTURE, input), 1);
            assert_eq!(ruleset_builds() - start, 2);

            let other: Vec<u8> = RULESET_FIXTURE.iter().copied().chain(*b"\n").collect();
            assert_eq!(ruleset_count(Profile::Common, &other, input), 1);
            assert_eq!(ruleset_builds() - start, 3);

            assert!(with_ruleset_registry(Profile::Common, b"not a ruleset", |_| Ok(())).is_err());
            assert!(with_ruleset_registry(Profile::Common, b"not a ruleset", |_| Ok(())).is_err());
            assert_eq!(ruleset_builds() - start, 3);
            assert_eq!(ruleset_count(Profile::Common, &other, input), 1);
            assert_eq!(ruleset_builds() - start, 3);

            let nested = with_ruleset_registry(Profile::Common, &other, |_| {
                Ok(ruleset_count(Profile::Common, RULESET_FIXTURE, input))
            })
            .unwrap();
            assert_eq!(nested, 1);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn scan_accepts_a_ruleset_buffer_and_registers_it_after_the_built_ins() {
        let value = "a".repeat(20);
        let input = format!("ACME_{value}");
        let without_ruleset = scan(input.clone(), None, None, None, None).unwrap();
        assert!(
            without_ruleset.is_empty(),
            "no built-in detector claims ACME_"
        );

        let with_ruleset =
            scan(input, None, None, Some(Buffer::from(RULESET_FIXTURE)), None).unwrap();
        assert_eq!(with_ruleset.len(), 1);
        assert_eq!(with_ruleset[0].detector, "acme-internal-token");
        assert_eq!(with_ruleset[0].confidence, "medium");
    }

    #[test]
    fn scan_common_also_accepts_a_ruleset_and_keeps_its_own_built_in_set() {
        let value = "a".repeat(20);
        let input = format!("ACME_{value}");
        let findings =
            scan_common(input, None, None, Some(Buffer::from(RULESET_FIXTURE)), None).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "acme-internal-token");
    }

    #[test]
    fn scan_and_redact_thread_the_ruleset_through_to_the_scan_step() {
        let value = "a".repeat(20);
        let input = format!("ACME_{value}");
        let result = scan_and_redact(
            input,
            None,
            None,
            None,
            Some(Buffer::from(RULESET_FIXTURE)),
            None,
        )
        .unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].detector, "acme-internal-token");
        // `Confidence::Medium` warns rather than redacts under the default
        // policy, so the text passes through unchanged — the same behavior
        // an equal-confidence built-in already has.
        assert!(result.redacted.contains(&value));
    }

    #[test]
    fn scan_rejects_a_malformed_ruleset_with_the_fixed_code_and_class() {
        let malformed = std::str::from_utf8(RULESET_FIXTURE)
            .unwrap()
            .replace("ruleset-revision: 1", "ruleset-revision: 2");
        let result = scan(
            "irrelevant".to_owned(),
            None,
            None,
            Some(Buffer::from(malformed.into_bytes())),
            None,
        );
        let error = result.err().expect("expected an error");
        assert_eq!(error.status, "INVALID_RULESET");
        assert!(error.reason.contains("UNKNOWN_REVISION"));
    }

    /// A minimal, valid revision 1 action policy (issue #1219).
    const ACTION_POLICY_FIXTURE: &[u8] = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"warn-github","match":{"type":["github_token"]},"action":"warn"}]}"#;

    const ACTION_POLICY_INPUT: &str = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";

    #[test]
    fn scan_applies_an_action_policy_and_the_default_stays_the_base() {
        let default = scan(ACTION_POLICY_INPUT.to_owned(), None, None, None, None).unwrap();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].action, "redact");

        let overlaid = scan(
            ACTION_POLICY_INPUT.to_owned(),
            None,
            None,
            None,
            Some(Buffer::from(ACTION_POLICY_FIXTURE)),
        )
        .unwrap();
        assert_eq!(overlaid.len(), 1);
        assert_eq!(overlaid[0].action, "warn");
        assert_eq!(
            (overlaid[0].start, overlaid[0].end),
            (default[0].start, default[0].end)
        );

        let empty = br#"{"actionPolicyRevision":1,"base":"default","rules":[]}"#;
        let identity = scan(
            ACTION_POLICY_INPUT.to_owned(),
            None,
            None,
            None,
            Some(Buffer::from(&empty[..])),
        )
        .unwrap();
        assert_eq!(identity[0].action, default[0].action);
    }

    #[test]
    fn the_common_exports_and_scan_and_redact_apply_an_action_policy() {
        let common = scan_common(
            "postgres://user:SYNTHETIC_REVOKED_PASSWORD@example.test:5432/db".to_owned(),
            None,
            None,
            None,
            Some(Buffer::from(
                &br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"allow-all","match":{"confidence":["high","medium","low"]},"action":"allow"}]}"#[..],
            )),
        )
        .unwrap();
        assert!(common.iter().all(|finding| finding.action == "allow"));

        let combined = scan_and_redact(
            ACTION_POLICY_INPUT.to_owned(),
            None,
            None,
            None,
            None,
            Some(Buffer::from(ACTION_POLICY_FIXTURE)),
        )
        .unwrap();
        assert_eq!(combined.findings[0].action, "warn");
        // `warn` leaves the text unchanged.
        assert_eq!(combined.redacted, ACTION_POLICY_INPUT);
    }

    #[test]
    fn a_rejected_action_policy_carries_the_fixed_code_class_and_rule_index() {
        let rejected = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["jwt"]},"action":"mask"}]}"#;
        let error = scan(
            "irrelevant".to_owned(),
            None,
            None,
            None,
            Some(Buffer::from(&rejected[..])),
        )
        .err()
        .expect("expected an error");
        assert_eq!(error.status, "INVALID_ACTION_POLICY");
        assert_eq!(
            error.reason,
            "The supplied action policy is invalid. (INVALID_ACTION, rule 0)"
        );
    }

    #[test]
    fn a_callback_and_an_action_policy_together_are_invalid_options_before_parsing() {
        // `true` stands for a supplied callback; the document is never read,
        // so even a document that would be rejected reports the misuse code.
        let error =
            load_call_action_policy(true, Some(b"not json")).expect_err("expected an error");
        assert_eq!(error.status, "INVALID_OPTIONS");
        assert!(load_call_action_policy(true, None).unwrap().is_none());
        assert!(load_call_action_policy(false, None).unwrap().is_none());
    }

    /// Two live policies of different content evaluate independently, in
    /// either construction order: nothing is held between calls.
    #[test]
    fn no_process_global_action_policy_slot_exists() {
        let warn = ACTION_POLICY_FIXTURE;
        let allow = &br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"allow-github","match":{"type":["github_token"]},"action":"allow"}]}"#[..];
        let run = |document: &[u8]| {
            scan(
                ACTION_POLICY_INPUT.to_owned(),
                None,
                None,
                None,
                Some(Buffer::from(document)),
            )
            .unwrap()[0]
                .action
                .clone()
        };
        assert_eq!(run(warn), "warn");
        assert_eq!(run(allow), "allow");
        assert_eq!(run(warn), "warn");
        assert_eq!(run(allow), "allow");
    }

    #[test]
    fn default_policy_delegates_to_the_core_default_evaluation() {
        let finding = |type_name: &str, confidence: &str| JsDetectedFinding {
            id: "finding-1".to_owned(),
            r#type: type_name.to_owned(),
            detector: "synthetic-detector".to_owned(),
            confidence: confidence.to_owned(),
            obfuscation: "none".to_owned(),
            start: 0,
            end: 1,
        };
        assert_eq!(
            default_policy(finding("private_key", "low")).unwrap(),
            "block"
        );
        assert_eq!(
            default_policy(finding("github_token", "low")).unwrap(),
            "redact"
        );
        assert_eq!(
            default_policy(finding("acme-unknown-type", "high")).unwrap(),
            "redact"
        );
        assert_eq!(
            default_policy(finding("acme-unknown-type", "medium")).unwrap(),
            "warn"
        );
        for malformed in [
            finding("Not An Identifier", "high"),
            finding("jwt", "certain"),
        ] {
            assert_err_status(default_policy(malformed), "INVALID_FINDINGS");
        }
        let mut empty_range = finding("jwt", "high");
        empty_range.end = 0;
        assert_err_status(default_policy(empty_range), "INVALID_FINDINGS");
    }

    #[test]
    fn redact_and_scan_and_redact_also_honor_an_explicit_limit() {
        let input = "abcdef".to_owned();

        assert_err_status(
            redact(input.clone(), Vec::new(), None, Some(tight_limits())),
            "INPUT_LIMIT_EXCEEDED",
        );
        assert_err_status(
            scan_and_redact(input, None, None, Some(tight_limits()), None, None),
            "INPUT_LIMIT_EXCEEDED",
        );
    }

    #[test]
    fn pii_activation_is_canonical_idempotent_and_conflict_checked() {
        initialize_pii(vec!["pii".to_owned(), "pii:global".to_owned()]).unwrap();
        assert_eq!(
            pii_activation().unwrap(),
            "credentials=full;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2"
        );
        let findings = scan("🔒 client_ip=10.0.0.8".to_owned(), None, None, None, None).unwrap();
        let finding = findings
            .iter()
            .find(|finding| finding.r#type == "pii_global_network_address")
            .unwrap();
        assert_eq!((finding.start, finding.end), (13, 21));
        assert_eq!(finding.detector, "pii-domain");
        initialize_pii(vec!["pii:global".to_owned()]).unwrap();
        assert_err_status(initialize(), "PII_ACTIVATION_CONFLICT");
    }

    #[test]
    fn pii_family_fixtures_use_node_utf16_metadata() {
        for corpus in [
            include_str!("../../../conformance/fixtures/pii-email-v1.json"),
            include_str!("../../../conformance/fixtures/pii-iban-v1.json"),
            include_str!("../../../conformance/fixtures/pii-phone-v1.json"),
            include_str!("../../../conformance/fixtures/pii-us-ssn-v1.json"),
        ] {
            let document: serde_json::Value = serde_json::from_str(corpus).unwrap();
            let selector = document["selector"].as_str().unwrap();
            let selection = PiiSelection::parse(&[selector]).unwrap();
            let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
            for case in document["cases"].as_array().unwrap() {
                let input = case["input"].as_str().unwrap();
                let findings = run_scan(
                    input,
                    &registry,
                    None,
                    None,
                    &WholeInputLimits::default(),
                    &offsets_for(input),
                )
                .unwrap();
                let actual: Vec<serde_json::Value> = findings
                    .into_iter()
                    .map(|finding| to_js_finding(&mut Utf16Offsets::new(input), &finding))
                    .map(|finding| {
                        serde_json::json!({
                            "detector": finding.detector,
                            "type": finding.r#type,
                            "confidence": finding.confidence,
                            "action": finding.action,
                            "start": finding.start,
                            "end": finding.end,
                        })
                    })
                    .collect();
                let expected: Vec<serde_json::Value> = case["expected"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|finding| {
                        let byte_start =
                            usize::try_from(finding["start"].as_u64().unwrap()).unwrap();
                        let byte_end = usize::try_from(finding["end"].as_u64().unwrap()).unwrap();
                        let mut converted = finding.clone();
                        converted["start"] =
                            serde_json::json!(input[..byte_start].encode_utf16().count());
                        converted["end"] =
                            serde_json::json!(input[..byte_end].encode_utf16().count());
                        converted
                    })
                    .collect();
                assert_eq!(actual, expected, "{}", case["id"].as_str().unwrap());
            }
        }
    }

    #[test]
    fn payment_card_family_fixture_uses_node_utf16_metadata() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/pii-payment-card-v1.json"
        ))
        .unwrap();
        let selector = document["selector"].as_str().unwrap();
        let selection = PiiSelection::parse(&[selector]).unwrap();
        let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
        for case in document["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let findings = run_scan(
                input,
                &registry,
                None,
                None,
                &WholeInputLimits::default(),
                &offsets_for(input),
            )
            .unwrap();
            let actual: Vec<serde_json::Value> = findings
                .into_iter()
                .map(|finding| to_js_finding(&mut Utf16Offsets::new(input), &finding))
                .map(|finding| {
                    serde_json::json!({
                        "detector": finding.detector,
                        "type": finding.r#type,
                        "confidence": finding.confidence,
                        "action": finding.action,
                        "start": finding.start,
                        "end": finding.end,
                    })
                })
                .collect();
            let expected: Vec<serde_json::Value> = case["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|finding| {
                    let byte_start = usize::try_from(finding["start"].as_u64().unwrap()).unwrap();
                    let byte_end = usize::try_from(finding["end"].as_u64().unwrap()).unwrap();
                    let mut converted = finding.clone();
                    converted["start"] =
                        serde_json::json!(input[..byte_start].encode_utf16().count());
                    converted["end"] = serde_json::json!(input[..byte_end].encode_utf16().count());
                    converted
                })
                .collect();
            assert_eq!(actual, expected, "{}", case["id"].as_str().unwrap());
        }
    }
}
