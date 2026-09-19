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

use std::cell::OnceCell;

use napi::bindgen_prelude::{FnArgs, Function};
use napi_derive::napi;
use redact_secret::{
    Action, ByteRange, Confidence, DefaultPolicy, DetectedFinding, DetectorRegistry, Finding,
    FormatterFailure, PlaceholderContext, PlaceholderFormatter, Policy, PolicyContext, Profile,
    SecretScanError, SecretScanErrorCode, default_placeholder_formatter, redact as core_redact,
    run_detector_pipeline,
};

use crate::error::to_js_error;
use crate::offsets::{byte_to_utf16, utf16_to_byte};
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
        Profile::Full => REGISTRY.with(|cell| {
            match cell.get_or_init(|| DetectorRegistry::with_built_in(std::iter::empty())) {
                Ok(registry) => f(registry),
                Err(error) => Err(*error),
            }
        }),
        Profile::Common => REGISTRY_COMMON.with(|cell| {
            match cell.get_or_init(|| DetectorRegistry::with_common_built_in(std::iter::empty())) {
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
    with_profile_registry(Profile::Full, |_| Ok(())).map_err(to_js_error)
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
    with_profile_registry(Profile::Common, |_| Ok(())).map_err(to_js_error)
}

fn to_js_detected_finding(input: &str, finding: &DetectedFinding) -> JsDetectedFinding {
    JsDetectedFinding {
        id: finding.id().to_owned(),
        r#type: finding.type_name().to_owned(),
        detector: finding.detector().to_owned(),
        confidence: finding.confidence().as_str().to_owned(),
        start: byte_to_utf16(input, finding.range().start()),
        end: byte_to_utf16(input, finding.range().end()),
    }
}

fn to_js_finding(input: &str, finding: &Finding) -> JsFinding {
    JsFinding {
        id: finding.id().to_owned(),
        r#type: finding.type_name().to_owned(),
        detector: finding.detector().to_owned(),
        confidence: finding.confidence().as_str().to_owned(),
        action: finding.action().as_str().to_owned(),
        start: byte_to_utf16(input, finding.range().start()),
        end: byte_to_utf16(input, finding.range().end()),
    }
}

/// Reconstructs a native [`Finding`] from a JavaScript-supplied [`JsFinding`],
/// converting its UTF-16 range back to UTF-8 bytes.
///
/// # Errors
///
/// Returns [`SecretScanErrorCode::InvalidFindings`] when a range offset is
/// out of bounds or splits a surrogate pair, `start >= end`, or `confidence`
/// / `action` is not one of the fixed wire names.
fn from_js_finding(input: &str, finding: &JsFinding) -> Result<Finding, SecretScanError> {
    let start = utf16_to_byte(input, finding.start as usize)?;
    let end = utf16_to_byte(input, finding.end as usize)?;
    let range = ByteRange::new(start, end).ok_or(SecretScanErrorCode::InvalidFindings)?;
    let confidence =
        Confidence::from_name(&finding.confidence).ok_or(SecretScanErrorCode::InvalidFindings)?;
    let action = Action::from_name(&finding.action).ok_or(SecretScanErrorCode::InvalidFindings)?;
    Finding::new(
        &finding.id,
        &finding.r#type,
        &finding.detector,
        confidence,
        action,
        range,
    )
}

/// Runs the detector pipeline over `input` and evaluates `policy` (or the
/// core's [`DefaultPolicy`] when absent) once per finding.
fn run_scan(
    input: &str,
    registry: &DetectorRegistry,
    policy: Option<&PolicyCallback<'_>>,
) -> Result<Vec<Finding>, SecretScanError> {
    let detected = run_detector_pipeline(input, registry)?;
    let finding_count = detected.len();
    detected
        .into_iter()
        .enumerate()
        .map(
            |(finding_index, finding)| -> Result<Finding, SecretScanError> {
                let context = PolicyContext::new(finding_index, finding_count);
                let action = if let Some(callback) = policy {
                    let js_finding = to_js_detected_finding(input, &finding);
                    let js_context = JsPolicyContext {
                        finding_index: u32::try_from(finding_index).unwrap_or(u32::MAX),
                        finding_count: u32::try_from(finding_count).unwrap_or(u32::MAX),
                    };
                    let action_name: String = callback
                        .call(FnArgs::from((js_finding, js_context)))
                        .map_err(|_| SecretScanErrorCode::PolicyFailure)?;
                    Action::from_name(&action_name)
                        .ok_or(SecretScanErrorCode::InvalidPolicyAction)?
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
struct JsFormatterAdapter<'a, 'env> {
    callback: &'a FormatterCallback<'env>,
    input: &'a str,
}

impl PlaceholderFormatter for JsFormatterAdapter<'_, '_> {
    fn format(
        &self,
        finding: &Finding,
        context: &PlaceholderContext,
    ) -> Result<String, FormatterFailure> {
        let js_finding = to_js_finding(self.input, finding);
        let js_context = JsPlaceholderContext {
            placeholder_index: u32::try_from(context.placeholder_index()).unwrap_or(u32::MAX),
        };
        self.callback
            .call(FnArgs::from((js_finding, js_context)))
            .map_err(|_| FormatterFailure)
    }
}

fn run_redact(
    input: &str,
    findings: &[Finding],
    formatter: Option<&FormatterCallback<'_>>,
) -> Result<String, SecretScanError> {
    match formatter {
        Some(callback) => {
            let adapter = JsFormatterAdapter { callback, input };
            core_redact(input, findings, &adapter)
        }
        None => core_redact(input, findings, &default_placeholder_formatter),
    }
}

/// Runs [`run_scan`] against `profile`'s cached registry.
fn run_scan_for_profile(
    profile: Profile,
    input: &str,
    policy: Option<&PolicyCallback<'_>>,
) -> Result<Vec<Finding>, SecretScanError> {
    with_profile_registry(profile, |registry| run_scan(input, registry, policy))
}

/// Scans `input` and returns every finding, in input order, with UTF-16
/// ranges. When `policy` is omitted, the core's default policy chooses each
/// finding's action.
///
/// # Errors
///
/// - `DETECTOR_FAILURE` / `INVALID_CANDIDATE` from the detector pipeline.
/// - `POLICY_FAILURE` when `policy` throws.
/// - `INVALID_POLICY_ACTION` when `policy` returns something other than
///   `"redact"`, `"block"`, `"warn"`, or `"allow"`.
///
/// No error carries `input` or a matched value.
// N-API's generated argument conversion produces owned `String`/`Function`
// values; there is no borrowed form to take instead.
#[allow(clippy::needless_pass_by_value)]
#[napi]
pub fn scan(
    input: String,
    #[napi(ts_arg_type = "(finding: JsDetectedFinding, context: JsPolicyContext) => string")]
    policy: Option<PolicyCallback<'_>>,
) -> napi::Result<Vec<JsFinding>, String> {
    let findings =
        run_scan_for_profile(Profile::Full, &input, policy.as_ref()).map_err(to_js_error)?;
    Ok(findings.iter().map(|f| to_js_finding(&input, f)).collect())
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
) -> napi::Result<Vec<JsFinding>, String> {
    let findings =
        run_scan_for_profile(Profile::Common, &input, policy.as_ref()).map_err(to_js_error)?;
    Ok(findings.iter().map(|f| to_js_finding(&input, f)).collect())
}

/// Replaces `redact`/`block` findings in `input` with placeholder text,
/// leaving `warn`/`allow` findings untouched. `findings` is normally the
/// output of [`scan`] and need not be pre-sorted. When `formatter` is
/// omitted, the core's default `<SECRET_N>` formatter is used.
///
/// # Errors
///
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
) -> napi::Result<String, String> {
    let native_findings: Vec<Finding> = findings
        .iter()
        .map(|finding| from_js_finding(&input, finding))
        .collect::<Result<_, _>>()
        .map_err(to_js_error)?;
    run_redact(&input, &native_findings, formatter.as_ref()).map_err(to_js_error)
}

/// Runs [`run_scan_for_profile`] then [`run_redact`] against `profile`,
/// converting the result to its N-API shape.
fn run_scan_and_redact_for_profile(
    profile: Profile,
    input: &str,
    policy: Option<&PolicyCallback<'_>>,
    formatter: Option<&FormatterCallback<'_>>,
) -> Result<JsScanAndRedactResult, SecretScanError> {
    let findings = run_scan_for_profile(profile, input, policy)?;
    let redacted = run_redact(input, &findings, formatter)?;
    let js_findings = findings.iter().map(|f| to_js_finding(input, f)).collect();
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
) -> napi::Result<JsScanAndRedactResult, String> {
    run_scan_and_redact_for_profile(Profile::Full, &input, policy.as_ref(), formatter.as_ref())
        .map_err(to_js_error)
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
) -> napi::Result<JsScanAndRedactResult, String> {
    run_scan_and_redact_for_profile(Profile::Common, &input, policy.as_ref(), formatter.as_ref())
        .map_err(to_js_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Comparable field tuple for a [`JsFinding`], which has no [`PartialEq`]
    /// of its own.
    fn finding_key(finding: &JsFinding) -> (&str, &str, &str, &str, &str, u32, u32) {
        (
            &finding.id,
            &finding.r#type,
            &finding.detector,
            &finding.confidence,
            &finding.action,
            finding.start,
            finding.end,
        )
    }

    fn scan_default(input: &str) -> Vec<Finding> {
        with_profile_registry(Profile::Full, |registry| run_scan(input, registry, None)).unwrap()
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

        let js_finding = to_js_finding(input, finding);
        // The key emoji (one astral character, a UTF-16 surrogate pair) and
        // the following space sit entirely before the match.
        assert_eq!(
            js_finding.start,
            byte_to_utf16(input, finding.range().start())
        );
        assert!(js_finding.start >= 3);

        let redacted = run_redact(input, &findings, None).unwrap();
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

        let js_findings: Vec<JsFinding> =
            findings.iter().map(|f| to_js_finding(input, f)).collect();
        let native_again: Vec<Finding> = js_findings
            .iter()
            .map(|f| from_js_finding(input, f).unwrap())
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
            start: 1,
            end: 2,
        };
        let error = from_js_finding(input, &malformed).unwrap_err();
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
            start: 0,
            end: 5,
        };
        let error = from_js_finding(input, &malformed).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidFindings);
    }

    #[test]
    fn scan_and_redact_matches_separate_scan_then_redact() {
        let input = "Authorization: Bearer sk-syntheticRevokedExampleToken00000000000000000000";
        let findings = scan_default(input);
        let redacted = run_redact(input, &findings, None).unwrap();
        let js_findings: Vec<JsFinding> =
            findings.iter().map(|f| to_js_finding(input, f)).collect();
        assert_eq!(js_findings.len(), 1);

        let combined = scan_and_redact(input.to_owned(), None, None).unwrap();
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
        with_profile_registry(Profile::Common, |registry| run_scan(input, registry, None)).unwrap()
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
        let redacted = run_redact(input, &findings, None).unwrap();
        assert!(!redacted.contains("SYNTHETIC_REVOKED_PASSWORD"));
        let js_findings: Vec<JsFinding> =
            findings.iter().map(|f| to_js_finding(input, f)).collect();

        let combined = scan_and_redact_common(input.to_owned(), None, None).unwrap();
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
}
