//! Browser WebAssembly binding for the `redact-secret` core, built with
//! `wasm-bindgen` (`decision-define-runtime-bindings`).
//!
//! - Every synchronous operation ([`scan`], [`redact`], [`scan_and_redact`])
//!   requires a prior successful [`initialize`] call. `initialize` is
//!   idempotent and reports a fixed, input-free error if it ever fails; a
//!   call made before it has succeeded fails the same way, before touching
//!   its input.
//! - Ranges exposed here (see [`RangeJs`]) use UTF-16 code units; conversion
//!   from the core's UTF-8 byte offsets happens in the private `range`
//!   module without
//!   changing the selected span
//!   (`decision-govern-cross-language-conformance`).
//! - A custom `policy` or `formatter` callback ([`scan`], [`redact`],
//!   [`scan_and_redact`]) receives only the safe metadata the private
//!   `metadata` module builds; it never sees the scanned input or a matched
//!   value, and any
//!   failure (a thrown exception or an unexpected return value) becomes a
//!   fixed, input-free error, never the exception's own message.
//! - [`create_incremental_sanitizer`] builds a real, bounded
//!   [`IncrementalSanitizer`](redact_secret::IncrementalSanitizer) session
//!   (the private `incremental` module), the same core session
//!   `bindings/node` and `bindings/python` wrap, with an explicit
//!   `accepting`/`finalized`/`aborted`/`failed` lifecycle and absolute
//!   UTF-16 ranges.
//! - One Cargo feature, default-on `full`, picks which built-in registry the
//!   artifact links (`decision-define-detector-profile-and-pack-contract`):
//!   the default build is the `full` artifact; `--no-default-features`
//!   builds the `common` artifact, whose linked code references only the
//!   `common` registry constructor. [`profile`] reports which one was built.
//! - This crate's dependency graph contains only `wasm-bindgen`, `js-sys`,
//!   and the core: nothing Node-only, so it builds and runs for
//!   `wasm32-unknown-unknown` in any browser.

mod callbacks;
mod compare;
mod error;
mod finding;
mod incremental;
mod lifecycle;
mod metadata;
mod range;
mod result;
mod util;

use js_sys::Function;
use redact_secret::{
    ActionPolicy, ByteRange, Confidence, DefaultPolicy, DetectedFinding, DetectorRegistry, Finding,
    Obfuscation, Policy, PolicyContext, SecretScanError, SecretScanErrorCode, WholeInputLimits,
    default_placeholder_formatter, load_action_policy,
};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

pub use finding::{FindingJs, RangeJs};
pub use incremental::{IncrementalResultJs, IncrementalSanitizerJs, create_incremental_sanitizer};
pub use result::ScanAndRedactResultJs;

use error::to_js_error;

/// Returns the shared product version.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    redact_secret::VERSION.to_owned()
}

/// Returns the detector profile this artifact was compiled for: `"full"`
/// (the default build) or `"common"` (`--no-default-features`)
/// (`decision-define-detector-profile-and-pack-contract`).
///
/// Fixed at compile time and readable before [`initialize`], so a loader can
/// reject an artifact of the wrong profile before using it.
#[wasm_bindgen]
#[must_use]
pub fn profile() -> String {
    lifecycle::PROFILE.as_str().to_owned()
}

/// Idempotently initializes the module: builds and caches the built-in
/// detector registry. Every later call, whether or not the first one
/// succeeded, returns the same cached result without rebuilding it.
///
/// # Errors
///
/// Returns a fixed, input-free `INITIALIZATION_FAILED` error when the
/// registry cannot be built.
#[wasm_bindgen]
#[allow(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen owns vector arguments"
)]
pub fn initialize(pii: Vec<String>) -> Result<(), JsValue> {
    lifecycle::initialize(&pii).map_err(to_js_error)
}

/// Returns the canonical credentials/PII activation identity.
#[wasm_bindgen(js_name = piiActivation)]
/// Returns the canonical PII activation identity.
///
/// # Errors
///
/// Returns a fixed initialization error before successful initialization.
pub fn pii_activation() -> Result<String, JsValue> {
    lifecycle::pii_activation().map_err(to_js_error)
}

/// Resolves the two optional whole-input bound arguments every exported
/// `scan`/`redact`/`scanAndRedact` accepts to a core [`WholeInputLimits`],
/// using the core's default when both are omitted
/// (`decision-bound-whole-input-operations-by-default`).
fn resolve_whole_input_limits(
    max_input_bytes: Option<u32>,
    max_findings: Option<u32>,
) -> Result<WholeInputLimits, SecretScanError> {
    match (max_input_bytes, max_findings) {
        (None, None) => Ok(WholeInputLimits::default()),
        (input, findings) => {
            let defaults = WholeInputLimits::default();
            WholeInputLimits::new(
                input.map_or(defaults.max_input_bytes(), |value| value as usize),
                findings.map_or(defaults.max_findings(), |value| value as usize),
            )
        }
    }
}

#[cfg(test)]
fn run_scan(
    input: &str,
    registry: &DetectorRegistry,
    policy: Option<&Function>,
    limits: &WholeInputLimits,
) -> Result<Vec<Finding>, SecretScanError> {
    run_scan_with(input, registry, policy, None, limits)
}

/// [`run_scan`] with an optional declarative [`ActionPolicy`]. The caller
/// guarantees at most one of `policy` and `action_policy` is present
/// ([`load_call_action_policy`]).
fn run_scan_with(
    input: &str,
    registry: &DetectorRegistry,
    policy: Option<&Function>,
    action_policy: Option<&ActionPolicy>,
    limits: &WholeInputLimits,
) -> Result<Vec<Finding>, SecretScanError> {
    match (policy, action_policy) {
        (Some(function), _) => {
            let policy = callbacks::JsPolicy::new(input, function);
            redact_secret::scan_with_limits(input, registry, &policy, limits)
                .map_err(|error| policy.refine(error))
        }
        (None, Some(overlay)) => redact_secret::scan_with_limits(input, registry, overlay, limits),
        (None, None) => redact_secret::scan_with_limits(input, registry, &DefaultPolicy, limits),
    }
}

/// Loads the optional declarative action policy a whole-input call carries
/// (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`,
/// issue #1219). The compiled [`ActionPolicy`] is owned by the one call that
/// loaded it: no thread-local, process-global or one-slot cache holds it (the
/// single ruleset slot in `lifecycle` is not a precedent), so another call can
/// neither evict nor overwrite it.
///
/// A callback `policy` and an action policy together are `INVALID_OPTIONS`,
/// reported before the document is read; a rejected document is
/// `INVALID_ACTION_POLICY` with its fixed class and rule index in the
/// message. The core, not this function, performs every check of the
/// document.
fn load_call_action_policy(
    has_callback: bool,
    document: Option<&[u8]>,
) -> Result<Option<ActionPolicy>, JsValue> {
    let Some(bytes) = document else {
        return Ok(None);
    };
    if has_callback {
        return Err(to_js_error(SecretScanErrorCode::InvalidOptions.into()));
    }
    load_action_policy(bytes)
        .map(Some)
        .map_err(|error| to_js_error(error.into()))
}

fn run_redact(
    input: &str,
    findings: &[Finding],
    formatter: Option<&Function>,
    limits: &WholeInputLimits,
) -> Result<String, SecretScanError> {
    match formatter {
        Some(function) => redact_secret::redact_with_limits(
            input,
            findings,
            &callbacks::JsPlaceholderFormatter::new(input, function),
            limits,
        ),
        None => redact_secret::redact_with_limits(
            input,
            findings,
            &default_placeholder_formatter,
            limits,
        ),
    }
}

/// [`lifecycle::with_registry`] plus [`run_scan`], flattened into the one
/// `JsValue` error every exported function reports.
///
/// When `ruleset` is given, this bypasses the built-in registry and uses
/// [`lifecycle::with_ruleset_registry`] instead: a one-entry cache keyed by
/// the ruleset bytes, so repeating one ruleset builds its registry once
/// while a changed ruleset replaces the entry (issue #1059). `initialize()` is still required
/// first either way, so every exported operation keeps the one documented
/// rule ("every synchronous operation requires a prior successful
/// `initialize()`") regardless of whether it carries a ruleset.
fn scan_after_initialize(
    input: &str,
    policy: Option<&Function>,
    limits: &WholeInputLimits,
    ruleset: Option<&[u8]>,
    action_policy: Option<&[u8]>,
) -> Result<Vec<Finding>, JsValue> {
    // The initialization gate comes first, so a call made before
    // `initialize()` reports `NOT_INITIALIZED` whatever else it carries.
    lifecycle::ensure_initialized().map_err(to_js_error)?;
    let action_policy = load_call_action_policy(policy.is_some(), action_policy)?;
    match ruleset {
        None => lifecycle::with_registry(|registry| {
            run_scan_with(input, registry, policy, action_policy.as_ref(), limits)
        })
        .map_err(to_js_error)?
        .map_err(|error| to_js_error(error.into())),
        Some(bytes) => lifecycle::with_ruleset_registry(bytes, |registry| {
            run_scan_with(input, registry, policy, action_policy.as_ref(), limits)
        })
        .map_err(to_js_error)?
        .map_err(|error| to_js_error(error.into())),
    }
}

/// Scans `input` for secrets, in registration order with the documented
/// overlap precedence, and evaluates `policy` (or the built-in default
/// policy when `policy` is omitted) once per finding.
///
/// `policy`, when given, is called as `policy(findingMetadata, context)` and
/// must return one of `"redact"`, `"block"`, `"warn"`, or `"allow"`.
/// `maxInputBytes`/`maxFindings`, when omitted, use the core's default whole-
/// input bound (`decision-bound-whole-input-operations-by-default`).
///
/// # Errors
///
/// Returns a fixed `NOT_INITIALIZED` error, without inspecting `input`, when
/// [`initialize`] has not yet succeeded. Otherwise returns the sanitized,
/// input-free error the core pipeline or a failing `policy` call produces,
/// including `INPUT_LIMIT_EXCEEDED`, `FINDING_LIMIT_EXCEEDED`, and
/// `INVALID_LIMITS`. Returns `INVALID_RULESET` when `ruleset` is given and
/// does not parse.
///
/// `ruleset`, when given, is a caller-supplied declarative ruleset
/// (`decision-define-declarative-detector-ruleset-contract`); its declared
/// detectors register after every built-in, so a ruleset detector can add
/// detections but never outrank a built-in's resolved finding.
///
/// `action_policy`, when given, is the bytes of a revision 1 declarative
/// action policy document
/// (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`):
/// it replaces the default per-finding evaluation with the first matching
/// rule's action, or the default action when none matches. The compiled
/// policy lives only for this call. A rejected document is
/// `INVALID_ACTION_POLICY` (the fixed class and rule index are appended to
/// the message); supplying both `policy` and `action_policy` is
/// `INVALID_OPTIONS`.
// `policy` cannot be `Option<&Function>`: wasm-bindgen only implements
// `FromWasmAbi` for owned imported types across an exported function
// boundary, so this crate takes ownership at every such boundary and
// borrows internally instead.
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn scan(
    input: &str,
    policy: Option<Function>,
    max_input_bytes: Option<u32>,
    max_findings: Option<u32>,
    ruleset: Option<Vec<u8>>,
    action_policy: Option<Vec<u8>>,
) -> Result<Vec<FindingJs>, JsValue> {
    let limits = resolve_whole_input_limits(max_input_bytes, max_findings)
        .map_err(|error| to_js_error(error.into()))?;
    let findings = scan_after_initialize(
        input,
        policy.as_ref(),
        &limits,
        ruleset.as_deref(),
        action_policy.as_deref(),
    )?;
    Ok(FindingJs::all(input, findings))
}

/// Compares what several policies choose for the findings `input` yields,
/// over one detection pass and without enforcing any of them
/// (`decision-explain-and-compare-action-policies-over-one-detection-pass`,
/// issue #1220). The whole-input primitive only: there is no session or
/// stream variant.
///
/// The sides arrive as parallel arguments: `kinds` names each side in order
/// (`"default"`, `"action-policy"`, `"callback"`), `documents` holds the
/// action policy documents in the order their sides appear, and `callbacks`
/// the callbacks in the order theirs do. Callback sides run one at a time, in
/// the order given, each once per finding in finding order. The result is a
/// plain object of safe metadata and decisions (see `compare`); absent values
/// are `null`.
///
/// # Errors
///
/// Returns a fixed `NOT_INITIALIZED` error before a successful
/// [`initialize`]. `INVALID_OPTIONS` when there are zero or more than four
/// sides or the arguments do not describe the same sides;
/// `INVALID_ACTION_POLICY` for a document that does not parse and
/// `INVALID_RULESET` for a ruleset that does not, both before any callback;
/// `INVALID_LIMITS`, `INPUT_LIMIT_EXCEEDED` and `FINDING_LIMIT_EXCEEDED`
/// exactly as [`scan`]; and `POLICY_FAILURE` or `INVALID_POLICY_ACTION` when a
/// callback fails, which fails the whole comparison with no partial result.
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen(js_name = "compareActionPolicies")]
pub fn compare_action_policies(
    input: &str,
    kinds: Vec<String>,
    documents: Vec<js_sys::Uint8Array>,
    callbacks: Vec<Function>,
    max_input_bytes: Option<u32>,
    max_findings: Option<u32>,
    ruleset: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    lifecycle::ensure_initialized().map_err(to_js_error)?;
    let documents: Vec<Vec<u8>> = documents.iter().map(js_sys::Uint8Array::to_vec).collect();
    let plans = compare::plan_sides(&kinds, &documents, callbacks.len()).map_err(to_js_error)?;
    let limits = resolve_whole_input_limits(max_input_bytes, max_findings)
        .map_err(|error| to_js_error(error.into()))?;
    let comparison = match ruleset.as_deref() {
        None => lifecycle::with_registry(|registry| {
            compare::run_compare(input, registry, &plans, &callbacks, &limits)
        })
        .map_err(to_js_error)?,
        Some(bytes) => lifecycle::with_ruleset_registry(bytes, |registry| {
            compare::run_compare(input, registry, &plans, &callbacks, &limits)
        })
        .map_err(to_js_error)?,
    }
    .map_err(|error| to_js_error(error.into()))?;
    Ok(compare::comparison_to_array(input, &comparison).into())
}

/// Evaluates the core's default policy for one finding's safe metadata and
/// returns its action name, so a JavaScript policy that wants "mine, else the
/// default" never copies the default table
/// (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`,
/// issue #1219). Only `type_name` and `confidence` decide the result; the
/// range is validated and otherwise ignored.
///
/// # Errors
///
/// Returns a fixed `NOT_INITIALIZED` error before a successful
/// [`initialize`], and `INVALID_FINDINGS` when the metadata is not a
/// well-formed finding: a non-identifier `id`, `type_name` or `detector`, an
/// unknown `confidence` or `obfuscation`, or an empty or reversed range.
#[wasm_bindgen(js_name = "defaultPolicy")]
pub fn default_policy(
    id: &str,
    type_name: &str,
    detector: &str,
    confidence: &str,
    obfuscation: &str,
    start: u32,
    end: u32,
) -> Result<String, JsValue> {
    lifecycle::ensure_initialized().map_err(to_js_error)?;
    let invalid = || to_js_error(SecretScanErrorCode::InvalidFindings.into());
    let range = ByteRange::new(start as usize, end as usize).ok_or_else(invalid)?;
    let confidence = Confidence::from_name(confidence).ok_or_else(invalid)?;
    let obfuscation = Obfuscation::from_name(obfuscation).ok_or_else(invalid)?;
    let finding = DetectedFinding::new(id, type_name, detector, confidence, range)
        .map_err(|_| invalid())?
        .with_obfuscation(obfuscation);
    DefaultPolicy
        .evaluate(&finding, &PolicyContext::new(0, 1))
        .map(|action| action.as_str().to_owned())
        .map_err(|_| to_js_error(SecretScanErrorCode::PolicyFailure.into()))
}

/// Redacts `input` using `findings` (as returned by [`scan`] for the same
/// `input`), replacing every `redact`/`block` finding's span with a
/// placeholder from `formatter` (or the built-in default formatter when
/// `formatter` is omitted).
///
/// `formatter`, when given, is called as `formatter(findingMetadata,
/// context)` and must return the placeholder string.
/// `maxInputBytes`/`maxFindings`, when omitted, use the core's default whole-
/// input bound (`decision-bound-whole-input-operations-by-default`).
///
/// # Errors
///
/// Returns a fixed `NOT_INITIALIZED` error, without inspecting `input`, when
/// [`initialize`] has not yet succeeded. Otherwise returns the sanitized,
/// input-free error the core redaction pass or a failing `formatter` call
/// produces, including `INPUT_LIMIT_EXCEEDED`, `FINDING_LIMIT_EXCEEDED`, and
/// `INVALID_LIMITS`.
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen]
pub fn redact(
    input: &str,
    findings: Vec<FindingJs>,
    formatter: Option<Function>,
    max_input_bytes: Option<u32>,
    max_findings: Option<u32>,
) -> Result<String, JsValue> {
    lifecycle::ensure_initialized().map_err(to_js_error)?;
    let limits = resolve_whole_input_limits(max_input_bytes, max_findings)
        .map_err(|error| to_js_error(error.into()))?;
    let findings: Vec<Finding> = findings.into_iter().map(FindingJs::into_inner).collect();
    run_redact(input, &findings, formatter.as_ref(), &limits)
        .map_err(|error| to_js_error(error.into()))
}

/// Scans `input`, then redacts it with the resulting findings, in one call.
/// Equivalent to calling [`scan`] followed by [`redact`] with its result, but
/// without a round trip through JavaScript for the intermediate findings.
///
/// # Errors
///
/// The same as [`scan`] and [`redact`].
#[allow(clippy::needless_pass_by_value)]
#[wasm_bindgen(js_name = "scanAndRedact")]
pub fn scan_and_redact(
    input: &str,
    policy: Option<Function>,
    formatter: Option<Function>,
    max_input_bytes: Option<u32>,
    max_findings: Option<u32>,
    ruleset: Option<Vec<u8>>,
    action_policy: Option<Vec<u8>>,
) -> Result<ScanAndRedactResultJs, JsValue> {
    let limits = resolve_whole_input_limits(max_input_bytes, max_findings)
        .map_err(|error| to_js_error(error.into()))?;
    let findings = scan_after_initialize(
        input,
        policy.as_ref(),
        &limits,
        ruleset.as_deref(),
        action_policy.as_deref(),
    )?;
    let text = run_redact(input, &findings, formatter.as_ref(), &limits)
        .map_err(|error| to_js_error(error.into()))?;
    Ok(ScanAndRedactResultJs::new(
        text,
        FindingJs::all(input, findings),
    ))
}

/// A synthetic, never-issued secret that the compiled profile detects, shared
/// by this crate's scan tests so they hold for both the `full` and the
/// `common` artifact.
#[cfg(test)]
pub(crate) mod synthetic {
    /// A secret-bearing text, the span its one finding selects, and that
    /// finding's type.
    pub(crate) struct Secret {
        pub(crate) text: String,
        pub(crate) matched: String,
        pub(crate) type_name: &'static str,
    }

    /// `full`: a bare AWS-shaped access key id, a `provider` detector.
    #[cfg(feature = "full")]
    pub(crate) fn secret() -> Secret {
        let key = format!("AKIA{}", "SYNTHETICEXAMPLE");
        Secret {
            text: key.clone(),
            matched: key,
            type_name: "aws_access_key_id",
        }
    }

    /// `common`: a connection-URI password, a `common` detector.
    #[cfg(not(feature = "full"))]
    pub(crate) fn secret() -> Secret {
        let password = format!("SYNTHETIC_REVOKED_{}", "PASSWORD");
        Secret {
            text: format!("postgres://user:{password}@example.test:5432/db"),
            matched: password,
            type_name: "connection_string_password",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic secret the compiled profile detects, after an astral
    /// (supplementary plane) character, exercising the same evidence
    /// `conformance/fixtures/unicode-conversion-corpus.json` documents
    /// (`decision-govern-cross-language-conformance`) through the full
    /// `scan`/`redact` surface rather than the isolated range conversion.
    fn synthetic_input() -> String {
        format!("prefix \u{1F511} {} suffix", synthetic::secret().text)
    }

    /// `synthetic_input` with its one finding replaced by `placeholder`.
    fn redacted_input(placeholder: &str) -> String {
        synthetic_input().replace(&synthetic::secret().matched, placeholder)
    }

    // The limit-resolution and `run_scan`/`run_redact` tests below exercise
    // plain `Result<_, SecretScanError>` values, so — unlike the exported
    // `#[wasm_bindgen]` functions, whose `JsValue` errors need a real
    // JavaScript engine — they run natively, not just under `wasm32`.

    #[test]
    fn resolve_whole_input_limits_defaults_when_both_are_omitted() {
        let limits = resolve_whole_input_limits(None, None).unwrap();
        assert_eq!(limits, WholeInputLimits::default());
    }

    #[test]
    fn resolve_whole_input_limits_uses_explicit_values() {
        let limits = resolve_whole_input_limits(Some(1024), Some(10)).unwrap();
        assert_eq!(limits.max_input_bytes(), 1024);
        assert_eq!(limits.max_findings(), 10);
    }

    #[test]
    fn resolve_whole_input_limits_rejects_a_zero_value() {
        let error = resolve_whole_input_limits(Some(0), Some(10)).unwrap_err();
        assert_eq!(
            error.code(),
            redact_secret::SecretScanErrorCode::InvalidLimits
        );
    }

    #[test]
    fn run_scan_rejects_input_over_an_explicit_byte_limit() {
        initialize(Vec::new()).unwrap();
        let limits = WholeInputLimits::new(5, 50).unwrap();
        let error =
            lifecycle::with_registry(|registry| run_scan("abcdef", registry, None, &limits))
                .unwrap()
                .unwrap_err();
        assert_eq!(
            error.code(),
            redact_secret::SecretScanErrorCode::InputLimitExceeded
        );
    }

    #[test]
    fn compiled_wasm_profile_runs_the_network_address_family() {
        let selection =
            redact_secret::PiiSelection::parse(&["pii:family:global:network-address"]).unwrap();
        let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
        let findings = run_scan(
            "🔒 client_ip=10.0.0.8",
            &registry,
            None,
            &WholeInputLimits::default(),
        )
        .unwrap();
        let finding = findings
            .iter()
            .find(|finding| finding.type_name() == "pii_global_network_address")
            .unwrap();
        assert_eq!((finding.range().start(), finding.range().end()), (15, 23));
    }

    /// Only meaningful for the `full` profile, which links the `provider`
    /// detector this input needs two disjoint findings from; `common` finds
    /// nothing here (the documented false-negative cost of `common`), so
    /// there is no finding count to bound.
    #[test]
    fn run_scan_rejects_a_finding_count_over_an_explicit_bound() {
        if !cfg!(feature = "full") {
            return;
        }
        initialize(Vec::new()).unwrap();
        let input = format!(
            "prefix AKIA{} middle AKIA{} suffix",
            "SYNTHETICEXAMPLE", "SYNTHETICEXAMPL2"
        );
        let at_bound = WholeInputLimits::new(1024, 2).unwrap();
        let found =
            lifecycle::with_registry(|registry| run_scan(&input, registry, None, &at_bound))
                .unwrap()
                .unwrap();
        assert_eq!(found.len(), 2);

        let one_under = WholeInputLimits::new(1024, 1).unwrap();
        let error =
            lifecycle::with_registry(|registry| run_scan(&input, registry, None, &one_under))
                .unwrap()
                .unwrap_err();
        assert_eq!(
            error.code(),
            redact_secret::SecretScanErrorCode::FindingLimitExceeded
        );
    }

    #[test]
    fn run_redact_rejects_input_over_an_explicit_byte_limit() {
        let limits = WholeInputLimits::new(5, 50).unwrap();
        let error = run_redact("abcdef", &[], None, &limits).unwrap_err();
        assert_eq!(
            error.code(),
            redact_secret::SecretScanErrorCode::InputLimitExceeded
        );
    }

    /// Canonical synchronous conformance, exercised through the exported
    /// `scan`/`redact`/`scanAndRedact` functions themselves (with no custom
    /// `policy`/`formatter`, so no JavaScript callback is invoked and this
    /// runs on a native host, not just `wasm32`): the profile's built-in
    /// detector fires, the default policy redacts its `Confidence::High`
    /// finding, and the default formatter replaces it with
    /// `<SECRET_1>` — deterministically, on every call, for the same input,
    /// whether `scan` and `redact` are called separately or as one
    /// `scanAndRedact` call.
    #[test]
    fn scan_and_redact_agree_on_a_canonical_synthetic_finding() {
        initialize(Vec::new()).unwrap();
        let input = synthetic_input();

        let findings = scan(&input, None, None, None, None, None).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name(), synthetic::secret().type_name);
        assert_eq!(findings[0].action(), "redact");

        let output = redact(&input, findings, None, None, None).unwrap();
        assert_eq!(output, redacted_input("<SECRET_1>"));

        let combined = scan_and_redact(&input, None, None, None, None, None, None).unwrap();
        assert_eq!(combined.text(), output);
        assert_eq!(combined.findings().len(), 1);
        assert_eq!(
            combined.findings()[0].type_name(),
            synthetic::secret().type_name
        );
    }

    /// The `common` artifact links no `provider` detector, so a bare
    /// provider-format token with no credential-bearing context is not
    /// detected at all: the documented false-negative cost of `common`
    /// (`decision-define-detector-profile-and-pack-contract`). The `full`
    /// artifact detects the same input.
    #[test]
    fn a_bare_provider_token_is_detected_only_by_the_full_profile() {
        initialize(Vec::new()).unwrap();
        let input = format!("prefix \u{1F511} AKIA{} suffix", "SYNTHETICEXAMPLE");
        let findings = scan(&input, None, None, None, None, None).unwrap();
        if cfg!(feature = "full") {
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].detector(), "aws-access-key");
        } else {
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn profile_reports_the_compiled_profile() {
        let expected = if cfg!(feature = "full") {
            "full"
        } else {
            "common"
        };
        assert_eq!(profile(), expected);
    }

    /// A minimal, valid declarative ruleset (issue #495).
    const RULESET_FIXTURE: &[u8] = b"ruleset-revision: 1\n\
detector: acme-internal-token\n\
specificity: contextual\n\
prefix: \"ACME_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";

    #[test]
    fn scan_accepts_a_ruleset_and_registers_it_after_the_compiled_profiles_built_ins() {
        initialize(Vec::new()).unwrap();
        let value = "a".repeat(20);
        let input = format!("ACME_{value}");

        let without_ruleset = scan(&input, None, None, None, None, None).unwrap();
        assert!(
            without_ruleset.is_empty(),
            "no built-in detector claims ACME_"
        );

        let with_ruleset = scan(
            &input,
            None,
            None,
            None,
            Some(RULESET_FIXTURE.to_vec()),
            None,
        )
        .unwrap();
        assert_eq!(with_ruleset.len(), 1);
        assert_eq!(with_ruleset[0].detector(), "acme-internal-token");
        assert_eq!(with_ruleset[0].confidence(), "medium");
    }

    #[test]
    fn scan_and_redact_thread_the_ruleset_through_to_the_scan_step() {
        initialize(Vec::new()).unwrap();
        let value = "a".repeat(20);
        let input = format!("ACME_{value}");

        let combined = scan_and_redact(
            &input,
            None,
            None,
            None,
            None,
            Some(RULESET_FIXTURE.to_vec()),
            None,
        )
        .unwrap();
        assert_eq!(combined.findings().len(), 1);
        assert_eq!(combined.findings()[0].detector(), "acme-internal-token");
        // `Confidence::Medium` warns rather than redacts under the default
        // policy, so the text passes through unchanged.
        assert!(combined.text().contains(&value));
    }

    /// A revision 1 action policy (issue #1219) with one rule that names the
    /// compiled profile's one synthetic finding type, so the tests below hold
    /// for `full` and `common`.
    fn policy_for_compiled_secret(action: &str) -> Vec<u8> {
        format!(
            r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"type":["{}"]}},"action":"{action}"}}]}}"#,
            synthetic::secret().type_name
        )
        .into_bytes()
    }

    #[test]
    fn scan_applies_an_action_policy_and_the_default_stays_the_base() {
        initialize(Vec::new()).unwrap();
        let input = synthetic_input();

        let default = scan(&input, None, None, None, None, None).unwrap();
        assert_eq!(default[0].action(), "redact");

        let warned = scan(
            &input,
            None,
            None,
            None,
            None,
            Some(policy_for_compiled_secret("warn")),
        )
        .unwrap();
        assert_eq!(warned.len(), 1);
        assert_eq!(warned[0].action(), "warn");

        let identity = scan(
            &input,
            None,
            None,
            None,
            None,
            Some(br#"{"actionPolicyRevision":1,"base":"default","rules":[]}"#.to_vec()),
        )
        .unwrap();
        assert_eq!(identity[0].action(), "redact");

        // A rule for a type the finding does not carry leaves the base.
        let unrelated = scan(
            &input,
            None,
            None,
            None,
            None,
            Some(br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["acme-not-emitted"]},"action":"allow"}]}"#.to_vec()),
        )
        .unwrap();
        assert_eq!(unrelated[0].action(), "redact");

        let combined = scan_and_redact(
            &input,
            None,
            None,
            None,
            None,
            None,
            Some(policy_for_compiled_secret("warn")),
        )
        .unwrap();
        assert_eq!(combined.findings()[0].action(), "warn");
        assert_eq!(combined.text(), input);
    }

    /// Two live policies of different content evaluate independently, in
    /// either construction order: nothing is held between calls.
    #[test]
    fn no_process_global_action_policy_slot_exists() {
        initialize(Vec::new()).unwrap();
        let input = synthetic_input();
        let run = |document: &[u8]| {
            scan(&input, None, None, None, None, Some(document.to_vec())).unwrap()[0].action()
        };
        let warn = policy_for_compiled_secret("warn");
        let allow = policy_for_compiled_secret("allow");
        assert_eq!(run(&warn), "warn");
        assert_eq!(run(&allow), "allow");
        assert_eq!(run(&warn), "warn");
        assert_eq!(run(&allow), "allow");
    }

    /// The `code` and `message` JavaScript sees on a failed call. These
    /// build real JavaScript errors, so they only run under `wasm32`.
    fn js_error_parts(error: JsValue) -> (String, String) {
        let error: js_sys::Error = error.into();
        let code = js_sys::Reflect::get(&error, &JsValue::from_str("code"))
            .unwrap()
            .as_string()
            .unwrap();
        (code, String::from(error.message()))
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_rejected_action_policy_reaches_javascript_with_its_code_class_and_rule_index() {
        initialize(Vec::new()).unwrap();
        let rejected = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["jwt"]},"action":"mask"}]}"#;
        let error = scan(
            "irrelevant",
            None,
            None,
            None,
            None,
            Some(rejected.to_vec()),
        )
        .unwrap_err();
        assert_eq!(
            js_error_parts(error),
            (
                "INVALID_ACTION_POLICY".to_owned(),
                "The supplied action policy is invalid. (INVALID_ACTION, rule 0)".to_owned()
            )
        );
        let error = scan("irrelevant", None, None, None, None, Some(b"{}".to_vec())).unwrap_err();
        assert_eq!(
            js_error_parts(error).1,
            "The supplied action policy is invalid. (MISSING_FIELD)"
        );
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_callback_and_an_action_policy_together_are_invalid_options_before_the_document_is_read() {
        initialize(Vec::new()).unwrap();
        let callback = Function::new_no_args("return 'redact';");
        // A document that would be rejected still reports the misuse code.
        let error = scan(
            "irrelevant",
            Some(callback),
            None,
            None,
            None,
            Some(b"not json".to_vec()),
        )
        .unwrap_err();
        assert_eq!(js_error_parts(error).0, "INVALID_OPTIONS");
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    fn a_callback_returning_an_unknown_action_name_is_invalid_policy_action() {
        initialize(Vec::new()).unwrap();
        let input = synthetic_input();
        let callback = Function::new_no_args("return 'mask';");
        let error = scan(&input, Some(callback), None, None, None, None).unwrap_err();
        assert_eq!(js_error_parts(error).0, "INVALID_POLICY_ACTION");
        // A thrown exception and a non-string return stay the generic failure.
        let throwing =
            Function::new_no_args("throw new Error('SYNTHETIC_REVOKED_CALLBACK_FAILURE');");
        let error = scan(&input, Some(throwing), None, None, None, None).unwrap_err();
        assert_eq!(js_error_parts(error).0, "POLICY_FAILURE");
        let non_string = Function::new_no_args("return 7;");
        let error = scan(&input, Some(non_string), None, None, None, None).unwrap_err();
        assert_eq!(js_error_parts(error).0, "POLICY_FAILURE");
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    fn default_policy_rejects_malformed_metadata_as_invalid_findings() {
        initialize(Vec::new()).unwrap();
        let error = default_policy("finding-1", "Not An Identifier", "d", "high", "none", 0, 1)
            .unwrap_err();
        assert_eq!(js_error_parts(error).0, "INVALID_FINDINGS");
        let error = default_policy("finding-1", "jwt", "d", "certain", "none", 0, 1).unwrap_err();
        assert_eq!(js_error_parts(error).0, "INVALID_FINDINGS");
        let error = default_policy("finding-1", "jwt", "d", "high", "none", 1, 1).unwrap_err();
        assert_eq!(js_error_parts(error).0, "INVALID_FINDINGS");
    }

    #[test]
    fn default_policy_delegates_to_the_core_default_evaluation() {
        initialize(Vec::new()).unwrap();
        let evaluate = |type_name: &str, confidence: &str| {
            default_policy(
                "finding-1",
                type_name,
                "synthetic-detector",
                confidence,
                "none",
                0,
                1,
            )
            .unwrap()
        };
        assert_eq!(evaluate("private_key", "low"), "block");
        assert_eq!(evaluate("github_token", "low"), "redact");
        assert_eq!(evaluate("acme-unknown-type", "high"), "redact");
        assert_eq!(evaluate("acme-unknown-type", "medium"), "warn");
    }

    /// [`lifecycle::registry_with_ruleset`] itself, exercised natively:
    /// [`scan`]'s own error path needs a real JavaScript engine (see this
    /// module's other tests' note), but the registry construction it
    /// delegates to does not.
    #[test]
    fn registry_with_ruleset_builds_a_registry_over_the_compiled_profile() {
        initialize(Vec::new()).unwrap();
        let registry = lifecycle::registry_with_ruleset(RULESET_FIXTURE).unwrap();
        assert!(registry.contains("acme-internal-token"));
        assert_eq!(registry.profile(), Some(lifecycle::PROFILE));
    }

    #[test]
    fn registry_with_ruleset_rejects_a_malformed_ruleset_with_the_fixed_code_and_class() {
        let error = lifecycle::registry_with_ruleset(b"ruleset-revision: 2\n").unwrap_err();
        assert_eq!(
            error,
            error::WasmErrorCode::Ruleset(redact_secret::RulesetErrorClass::UnknownRevision)
        );
    }

    /// The finding's range converts to UTF-16 code units without changing
    /// the selected span, even with the astral character positioned before
    /// the match.
    #[test]
    fn finding_range_uses_utf16_offsets_end_to_end() {
        initialize(Vec::new()).unwrap();
        let input = synthetic_input();
        let findings = scan(&input, None, None, None, None, None).unwrap();
        let range = findings[0].range();

        let utf16: Vec<u16> = input.encode_utf16().collect();
        let matched =
            String::from_utf16(&utf16[range.start() as usize..range.end() as usize]).unwrap();
        assert_eq!(matched, synthetic::secret().matched);
    }

    #[test]
    fn pii_family_fixtures_use_wasm_utf16_metadata() {
        for corpus in [
            include_str!("../../../conformance/fixtures/pii-email-v1.json"),
            include_str!("../../../conformance/fixtures/pii-iban-v1.json"),
            include_str!("../../../conformance/fixtures/pii-phone-v1.json"),
            include_str!("../../../conformance/fixtures/pii-us-ssn-v1.json"),
        ] {
            let document: serde_json::Value = serde_json::from_str(corpus).unwrap();
            let selector = document["selector"].as_str().unwrap();
            let selection = redact_secret::PiiSelection::parse(&[selector]).unwrap();
            let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
            for case in document["cases"].as_array().unwrap() {
                let input = case["input"].as_str().unwrap();
                let findings =
                    run_scan(input, &registry, None, &WholeInputLimits::default()).unwrap();
                let actual: Vec<serde_json::Value> = findings
                    .into_iter()
                    .map(|finding| FindingJs::new(input, finding))
                    .map(|finding| {
                        let range = finding.range();
                        serde_json::json!({
                            "detector": finding.detector(),
                            "type": finding.type_name(),
                            "confidence": finding.confidence(),
                            "action": finding.action(),
                            "start": range.start(),
                            "end": range.end(),
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
    fn payment_card_family_fixture_uses_wasm_utf16_metadata() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/fixtures/pii-payment-card-v1.json"
        ))
        .unwrap();
        let selector = document["selector"].as_str().unwrap();
        let selection = redact_secret::PiiSelection::parse(&[selector]).unwrap();
        let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
        for case in document["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let findings = run_scan(input, &registry, None, &WholeInputLimits::default()).unwrap();
            let actual: Vec<serde_json::Value> = findings
                .into_iter()
                .map(|finding| FindingJs::new(input, finding))
                .map(|finding| {
                    let range = finding.range();
                    serde_json::json!({
                        "detector": finding.detector(),
                        "type": finding.type_name(),
                        "confidence": finding.confidence(),
                        "action": finding.action(),
                        "start": range.start(),
                        "end": range.end(),
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

    /// A call made before `initialize()` succeeds fails deterministically,
    /// through `lifecycle::ensure_initialized`/`with_registry`, before ever
    /// reaching the detector pipeline or touching `input`
    /// (`decision-define-runtime-bindings`). This is asserted directly on
    /// `lifecycle`, which never calls into JavaScript, rather than on `scan`/
    /// `redact` themselves: their own `NOT_INITIALIZED` error path builds a
    /// JavaScript `Error` object, which — like every other JavaScript call
    /// this crate makes — only runs under `wasm32`, not a native `cargo
    /// test`. `error::tests::js_error_carries_the_fixed_code_and_message_and_nothing_else`
    /// (a `wasm_bindgen_test`, run under `wasm32`) covers that JavaScript
    /// error shape directly.
    #[test]
    fn calls_before_initialize_fail_without_touching_input_or_the_registry() {
        assert_eq!(
            lifecycle::ensure_initialized().unwrap_err(),
            error::WasmErrorCode::NotInitialized
        );
    }

    /// A custom `policy`/`formatter` pair through the exported `scan` and
    /// `redact` functions themselves, not just the internal `JsPolicy`/
    /// `JsPlaceholderFormatter` wrappers (`callbacks::tests` exercises those
    /// directly). Only runs under `wasm32`: `js_sys::Function::new_with_args`
    /// builds a real JavaScript function.
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn scan_and_redact_accept_custom_policy_and_formatter_callbacks() {
        initialize(Vec::new()).unwrap();
        let input = synthetic_input();

        let policy = Function::new_with_args("finding, context", "return 'block';");
        let findings = scan(&input, Some(policy), None, None, None, None).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].action(), "block");

        let formatter = Function::new_with_args(
            "finding, context",
            "return '[REDACTED:' + finding.type + ']';",
        );
        let output = redact(&input, findings, Some(formatter), None, None).unwrap();
        assert_eq!(
            output,
            redacted_input(&format!("[REDACTED:{}]", synthetic::secret().type_name))
        );
    }
}
