//! Explicit, idempotent module initialization
//! (`decision-define-runtime-bindings`).
//!
//! [`initialize`] builds and caches the built-in detector registry of the
//! profile this artifact was compiled for ([`PROFILE`]) exactly once. Every synchronous operation this crate exports reads that
//! cache through [`with_registry`] or [`ensure_initialized`] instead of
//! rebuilding it, and fails deterministically, before touching its input,
//! when [`initialize`] has not yet succeeded.
//!
//! The cache is a thread-local, not a plain `static`: [`Detector`] carries no
//! `Send`/`Sync` bound (there is exactly one thread in a WebAssembly module
//! without the threads proposal, so the core never requires one), and a
//! `static` requires `Sync`.
//!
//! [`Detector`]: redact_secret::Detector

use std::cell::OnceCell;

use redact_secret::{
    DetectorRegistry, IncrementalLimits, IncrementalPolicy, IncrementalSanitizer, PiiSelection,
    PlaceholderFormatter, Profile, SecretScanError, SecretScanErrorCode,
};

use crate::error::WasmErrorCode;

/// The detector profile this artifact was compiled for
/// (`decision-define-detector-profile-and-pack-contract`): `full` under the
/// default-on `full` Cargo feature, `common` without it.
#[cfg(feature = "full")]
pub(crate) const PROFILE: Profile = Profile::Full;
/// See the `full` variant above.
#[cfg(not(feature = "full"))]
pub(crate) const PROFILE: Profile = Profile::Common;

/// Whether this artifact links the PII domain runtime (issue #937): `true`
/// under the off-by-default `pii` Cargo feature. Without it, [`initialize`]
/// rejects every non-empty PII selection with `PII_SELECTOR_UNAVAILABLE`,
/// and no constructor that references the `pii-domain` adapter is linked.
pub(crate) const PII_RUNTIME: bool = cfg!(feature = "pii");

/// Builds this artifact's profile registry with no custom detectors.
///
/// Exactly one registry constructor is referenced per build, selected at
/// compile time rather than by a runtime `match` on [`PROFILE`]: the
/// reachability rule that keeps every `provider` detector out of the
/// `common` artifact's linked code, with no reliance on constant
/// propagation. The same rule keeps the PII domain runtime out of an
/// artifact built without the `pii` feature (issue #937): the PII-off
/// constructors never name the `pii-domain` adapter, where the `*_and_pii`
/// ones name it even for an off selection.
///
/// This has no input and no side effect beyond the returned value, so its
/// failure (today, never observed: the built-in detectors always register
/// cleanly) is fixed and input-free by construction.
#[cfg(all(feature = "full", feature = "pii"))]
fn build_registry(selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_built_in_and_pii(selection).map_err(WasmErrorCode::from)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), feature = "pii"))]
fn build_registry(selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_common_built_in_and_pii(selection).map_err(WasmErrorCode::from)
}

/// See the `full` + `pii` variant above. [`initialize`] admits only the off
/// selection here, so the registry is the PII-off profile registry.
#[cfg(all(feature = "full", not(feature = "pii")))]
fn build_registry(_selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_built_in([]).map_err(WasmErrorCode::from)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), not(feature = "pii")))]
fn build_registry(_selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_common_built_in([]).map_err(WasmErrorCode::from)
}

/// Builds a registry over this artifact's compiled profile's built-ins,
/// plus every detector `ruleset` declares (issue #495,
/// `decision-define-declarative-detector-ruleset-contract`). Unlike
/// [`build_registry`]'s cached result, this is built fresh per call:
/// `ruleset`'s content can differ on every call, where the built-in-only
/// registry is the same value every time. The compile-time profile
/// selection is the same reachability rule [`build_registry`] documents, so
/// a ruleset scanned by the `common` artifact still links no `provider`
/// detector, and one scanned by a PII-off artifact links no PII runtime.
///
/// The PII-off constructors validate custom detectors exactly as the
/// `*_and_pii_custom` ones do for an off selection: a malformed, duplicate,
/// built-in (including a `provider` id in `common`), or reserved PII id is
/// rejected either way.
///
/// # Errors
///
/// A [`WasmErrorCode::Ruleset`] when `ruleset` does not parse, or
/// [`WasmErrorCode::InitializationFailed`] on the same never-observed
/// built-in registration failure [`build_registry`] documents.
#[cfg(all(feature = "full", feature = "pii"))]
pub(crate) fn registry_with_ruleset(ruleset: &[u8]) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    let selection = active_selection()?;
    Ok(DetectorRegistry::with_built_in_and_pii_custom(
        &selection, detectors,
    )?)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), feature = "pii"))]
pub(crate) fn registry_with_ruleset(ruleset: &[u8]) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    let selection = active_selection()?;
    Ok(DetectorRegistry::with_common_built_in_and_pii_custom(
        &selection, detectors,
    )?)
}

/// See the `full` + `pii` variant above.
#[cfg(all(feature = "full", not(feature = "pii")))]
pub(crate) fn registry_with_ruleset(ruleset: &[u8]) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    active_selection()?;
    Ok(DetectorRegistry::with_built_in(detectors)?)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), not(feature = "pii")))]
pub(crate) fn registry_with_ruleset(ruleset: &[u8]) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    active_selection()?;
    Ok(DetectorRegistry::with_common_built_in(detectors)?)
}

/// The selection captured by the last successful [`initialize`], as the
/// core error an incremental constructor reports.
fn active_selection_for_session() -> Result<PiiSelection, SecretScanError> {
    active_selection().map_err(|code| match code {
        WasmErrorCode::Core(core) => SecretScanError::from(core),
        _ => SecretScanErrorCode::InvalidState.into(),
    })
}

/// Creates an incremental session over this artifact's profile's built-in
/// detectors: the incremental counterpart of [`build_registry`], selected
/// the same compile-time way so the `common` artifact's streaming path
/// neither behaves as `full` nor links a `provider` detector, and a PII-off
/// artifact's links no PII runtime.
///
/// # Errors
///
/// Returns the core's error when the built-in registry cannot be built,
/// which cannot happen for the detectors the core ships.
#[cfg(all(feature = "full", feature = "pii"))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    let selection = active_selection_for_session()?;
    IncrementalSanitizer::with_built_in_and_pii_policy_and_formatter(
        limits, &selection, policy, formatter,
    )
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), feature = "pii"))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    let selection = active_selection_for_session()?;
    IncrementalSanitizer::with_common_built_in_and_pii_policy_and_formatter(
        limits, &selection, policy, formatter,
    )
}

/// See the `full` + `pii` variant above.
#[cfg(all(feature = "full", not(feature = "pii")))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    active_selection_for_session()?;
    IncrementalSanitizer::with_policy_and_formatter(limits, policy, formatter)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), not(feature = "pii")))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    active_selection_for_session()?;
    IncrementalSanitizer::with_common_built_in_policy_and_formatter(limits, policy, formatter)
}

thread_local! {
    static REGISTRY: OnceCell<Result<DetectorRegistry, WasmErrorCode>> = const { OnceCell::new() };
    static SELECTION: OnceCell<PiiSelection> = const { OnceCell::new() };
}

/// Idempotently initializes the module: the first call builds and caches the
/// registry; every later call returns the cached result without rebuilding
/// it.
///
/// # Errors
///
/// Returns [`WasmErrorCode::InitializationFailed`] when the registry cannot
/// be built. The failure is fixed and does not depend on any input, and it is
/// reported identically on every subsequent call.
///
/// Selector errors come first, then activation conflicts, in every build.
/// An artifact without the PII runtime ([`PII_RUNTIME`] `false`) then
/// rejects a valid non-empty selection with `PII_SELECTOR_UNAVAILABLE`,
/// without caching it, so a later PII-off call can still succeed; once it
/// has been initialized PII-off, a different selection is the same
/// `PII_ACTIVATION_CONFLICT` a PII-capable artifact reports.
pub(crate) fn initialize(selectors: &[String]) -> Result<(), WasmErrorCode> {
    let borrowed: Vec<&str> = selectors.iter().map(String::as_str).collect();
    let selection = PiiSelection::parse(&borrowed)?;
    let identity = selection.activation_identity(PROFILE);
    REGISTRY.with(|cell| {
        if let Some(existing) = cell.get() {
            return match existing {
                Ok(registry) if registry.activation_identity() == identity => Ok(()),
                Ok(_) => Err(SecretScanErrorCode::PiiActivationConflict.into()),
                Err(code) => Err(*code),
            };
        }
        if !PII_RUNTIME && !selection.is_off() {
            return Err(SecretScanErrorCode::PiiSelectorUnavailable.into());
        }
        let registry = build_registry(&selection);
        let outcome = registry.as_ref().map(|_| ()).map_err(|code| *code);
        let _ = cell.set(registry);
        if outcome.is_ok() {
            SELECTION.with(|slot| {
                let _ = slot.set(selection);
            });
        }
        outcome
    })
}

fn active_selection() -> Result<PiiSelection, WasmErrorCode> {
    SELECTION.with(|cell| cell.get().cloned().ok_or(WasmErrorCode::NotInitialized))
}

pub(crate) fn pii_activation() -> Result<String, WasmErrorCode> {
    with_registry(|registry| registry.activation_identity().to_owned())
}

/// Fails with [`WasmErrorCode::NotInitialized`] when [`initialize`] has not
/// yet succeeded; otherwise does nothing. Every exported operation that does
/// not itself need the registry (`redact`, and `scan`/`scanAndRedact` before
/// they call [`with_registry`]) still calls this first, so a call made
/// before initialization succeeds fails the same deterministic way regardless
/// of which operation it was.
///
/// # Errors
///
/// See above.
pub(crate) fn ensure_initialized() -> Result<(), WasmErrorCode> {
    with_registry(|_| ())
}

/// Calls `f` with the cached registry.
///
/// # Errors
///
/// Returns [`WasmErrorCode::NotInitialized`] when [`initialize`] has not yet
/// been called, or the cached initialization failure when it was called and
/// failed, without calling `f`. Both are fixed, input-free codes.
pub(crate) fn with_registry<T>(f: impl FnOnce(&DetectorRegistry) -> T) -> Result<T, WasmErrorCode> {
    REGISTRY.with(|cell| match cell.get() {
        None => Err(WasmErrorCode::NotInitialized),
        Some(Ok(registry)) => Ok(f(registry)),
        Some(Err(code)) => Err(*code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rust's test harness runs every `#[test]` function on its own freshly
    // spawned thread, so each test below sees its own unshared `REGISTRY`
    // thread-local and cannot race another test's initialization.

    #[test]
    fn calls_before_initialize_fail_deterministically_without_calling_f() {
        assert_eq!(
            ensure_initialized().unwrap_err(),
            WasmErrorCode::NotInitialized
        );
        let called = std::cell::Cell::new(false);
        let result = with_registry(|_| called.set(true));
        assert_eq!(result.unwrap_err(), WasmErrorCode::NotInitialized);
        assert!(!called.get());
    }

    #[test]
    fn initialize_is_idempotent_and_gates_registry_access() {
        assert_eq!(initialize(&[]), Ok(()));
        let first = with_registry(DetectorRegistry::len).unwrap();
        assert_eq!(initialize(&[]), Ok(()));
        let second = with_registry(DetectorRegistry::len).unwrap();
        assert_eq!(first, second);
        assert!(first > 0);
        assert_eq!(ensure_initialized(), Ok(()));
    }

    #[cfg(feature = "pii")]
    #[test]
    fn pii_activation_is_canonical_and_conflict_checked() {
        assert_eq!(
            initialize(&["pii".to_owned(), "pii:global".to_owned()]),
            Ok(())
        );
        assert_eq!(
            pii_activation().unwrap(),
            format!(
                "credentials={};selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v1",
                PROFILE.as_str()
            )
        );
        assert_eq!(
            initialize(&[]).unwrap_err(),
            WasmErrorCode::Core(redact_secret::SecretScanErrorCode::PiiActivationConflict)
        );
    }

    #[test]
    fn the_cached_registry_is_the_compiled_profile() {
        assert_eq!(initialize(&[]), Ok(()));
        assert_eq!(
            with_registry(DetectorRegistry::profile).unwrap(),
            Some(PROFILE)
        );
        let expected = if cfg!(feature = "full") {
            Profile::Full
        } else {
            Profile::Common
        };
        assert_eq!(PROFILE, expected);
    }

    /// Issue #937: an artifact built without the `pii` feature parses a
    /// selector exactly as a PII-capable one does, rejects a valid PII
    /// selection as unavailable without caching the failure, and after a
    /// PII-off initialization reports a different selection as the same
    /// activation conflict.
    #[cfg(not(feature = "pii"))]
    #[test]
    fn a_pii_off_artifact_rejects_pii_selection_as_unavailable() {
        assert_eq!(
            initialize(&["pii:global".to_owned()]).unwrap_err(),
            WasmErrorCode::Core(SecretScanErrorCode::PiiSelectorUnavailable)
        );
        assert_eq!(
            initialize(&["not a selector".to_owned()]).unwrap_err(),
            WasmErrorCode::Core(SecretScanErrorCode::PiiSelectorInvalid)
        );
        assert_eq!(
            ensure_initialized().unwrap_err(),
            WasmErrorCode::NotInitialized
        );
        assert_eq!(initialize(&[]), Ok(()));
        assert_eq!(
            pii_activation().unwrap(),
            format!(
                "credentials={};selectors=off;families=;vocabulary=pii-context/v1",
                PROFILE.as_str()
            )
        );
        assert_eq!(
            initialize(&["pii".to_owned()]).unwrap_err(),
            WasmErrorCode::Core(SecretScanErrorCode::PiiActivationConflict)
        );
        assert!(!with_registry(|registry| registry.contains("pii-domain")).unwrap());
    }
}
