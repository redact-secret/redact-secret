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
    DetectorRegistry, IncrementalLimits, IncrementalPolicy, IncrementalSanitizer,
    PlaceholderFormatter, Profile, SecretScanError,
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

/// Builds this artifact's profile registry with no custom detectors.
///
/// Exactly one registry constructor is referenced per build, selected at
/// compile time rather than by a runtime `match` on [`PROFILE`]: the
/// reachability rule that keeps every `provider` detector out of the
/// `common` artifact's linked code, with no reliance on constant
/// propagation.
///
/// This has no input and no side effect beyond the returned value, so its
/// failure (today, never observed: the built-in detectors always register
/// cleanly) is fixed and input-free by construction.
#[cfg(feature = "full")]
fn build_registry() -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_built_in([]).map_err(|_| WasmErrorCode::InitializationFailed)
}

/// See the `full` variant above.
#[cfg(not(feature = "full"))]
fn build_registry() -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_common_built_in([]).map_err(|_| WasmErrorCode::InitializationFailed)
}

/// Creates an incremental session over this artifact's profile's built-in
/// detectors: the incremental counterpart of [`build_registry`], selected
/// the same compile-time way so the `common` artifact's streaming path
/// neither behaves as `full` nor links a `provider` detector.
///
/// # Errors
///
/// Returns the core's error when the built-in registry cannot be built,
/// which cannot happen for the detectors the core ships.
#[cfg(feature = "full")]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    IncrementalSanitizer::with_policy_and_formatter(limits, policy, formatter)
}

/// See the `full` variant above.
#[cfg(not(feature = "full"))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    IncrementalSanitizer::with_common_built_in_policy_and_formatter(limits, policy, formatter)
}

thread_local! {
    static REGISTRY: OnceCell<Result<DetectorRegistry, WasmErrorCode>> = const { OnceCell::new() };
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
pub(crate) fn initialize() -> Result<(), WasmErrorCode> {
    REGISTRY.with(|cell| match cell.get_or_init(build_registry) {
        Ok(_) => Ok(()),
        Err(code) => Err(*code),
    })
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
        assert_eq!(initialize(), Ok(()));
        let first = with_registry(DetectorRegistry::len).unwrap();
        assert_eq!(initialize(), Ok(()));
        let second = with_registry(DetectorRegistry::len).unwrap();
        assert_eq!(first, second);
        assert!(first > 0);
        assert_eq!(ensure_initialized(), Ok(()));
    }

    #[test]
    fn the_cached_registry_is_the_compiled_profile() {
        assert_eq!(initialize(), Ok(()));
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
}
