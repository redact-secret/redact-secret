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

use std::cell::{OnceCell, RefCell};
use std::rc::Rc;

use redact_secret::{
    ArtifactKind, ArtifactManifest, ConfigRequest, DetectionSelection, DetectorRegistry,
    IncrementalLimits, IncrementalPolicy, IncrementalSanitizer, PiiSelection, PlaceholderFormatter,
    Profile, SecretScanError, SecretScanErrorCode, WholeInputLimits,
};

use crate::error::WasmErrorCode;

/// The detector profile this artifact was compiled for
/// (`decision-define-detector-profile-and-pack-contract`): `full` under the
/// default-on `full` Cargo feature, `common` without it.
#[cfg(all(feature = "full", not(feature = "custom")))]
pub(crate) const PROFILE: Profile = Profile::Full;
/// See the `full` variant above.
#[cfg(not(any(feature = "full", feature = "custom")))]
pub(crate) const PROFILE: Profile = Profile::Common;
/// A static custom composition (issue #1253, the `custom` Cargo feature): the
/// artifact links only the detectors its generated leaf crate selected.
#[cfg(feature = "custom")]
pub(crate) const PROFILE: Profile = Profile::Custom;

/// Whether this artifact links the PII domain runtime (issue #937): `true`
/// under the off-by-default `pii` Cargo feature. Without it, [`initialize`]
/// rejects every non-empty PII selection with `PII_SELECTOR_UNAVAILABLE`,
/// and no constructor that references the `pii-domain` adapter is linked.
pub(crate) const PII_RUNTIME: bool = cfg!(feature = "pii");

/// The 40-hex source commit this artifact was built from, when the build
/// supplied one at compile time; `None` otherwise. Fixed in the binary by the
/// build: the core reads no environment.
const SOURCE_REVISION: Option<&str> = option_env!("REDACT_SECRET_SOURCE_REVISION");

/// The `artifact-manifest/v1` document of this artifact (issue #1250), as
/// JSON text. Exactly one manifest constructor is referenced per build,
/// selected at compile time like the registry constructors below, so a
/// `common` artifact links no `provider` detector for it. It builds no
/// registry and reads no PII selection, so it is safe before and without
/// [`initialize`].
pub(crate) fn artifact_manifest() -> Result<String, WasmErrorCode> {
    manifest().map(|manifest| manifest.as_json().to_owned())
}

/// The compile-time source revision of this artifact, when the build gave one.
#[cfg(all(test, feature = "custom"))]
pub(crate) const fn source_revision() -> Option<&'static str> {
    SOURCE_REVISION
}

/// This artifact's manifest value, selected at compile time like
/// [`artifact_manifest`] (one constructor per build).
#[cfg(all(feature = "full", not(feature = "custom")))]
fn manifest() -> Result<ArtifactManifest, WasmErrorCode> {
    ArtifactManifest::full(ArtifactKind::Wasm, PII_RUNTIME, SOURCE_REVISION)
        .map_err(WasmErrorCode::from)
}

/// See the `full` variant above.
#[cfg(not(any(feature = "full", feature = "custom")))]
fn manifest() -> Result<ArtifactManifest, WasmErrorCode> {
    ArtifactManifest::common(ArtifactKind::Wasm, PII_RUNTIME, SOURCE_REVISION)
        .map_err(WasmErrorCode::from)
}

/// See the `full` variant above. The manifest names the composition's own
/// selected detectors and no others.
#[cfg(feature = "custom")]
fn manifest() -> Result<ArtifactManifest, WasmErrorCode> {
    let composition = crate::custom::composition()?;
    ArtifactManifest::custom(ArtifactKind::Wasm, &composition, SOURCE_REVISION)
        .map_err(WasmErrorCode::from)
}

/// Resolves explicit runtime input over this artifact's build defaults into
/// the `config-resolution/v1` document (issue #1251), as JSON text. Pure: it
/// builds no registry, reads no owner state and initializes nothing, so it is
/// safe before and without [`initialize`]. Invalid input is data in the
/// document, never an error.
///
/// # Errors
///
/// The fixed `ARTIFACT_MANIFEST_INVALID_SOURCE_REVISION` class when the
/// compile-time source revision is malformed.
pub(crate) fn resolve_config(
    config: Option<&str>,
    ruleset: Option<&[u8]>,
    action_policy: Option<&[u8]>,
    callback: bool,
    disclose: bool,
) -> Result<String, WasmErrorCode> {
    let manifest = manifest()?;
    let mut request = ConfigRequest::new();
    if let Some(config) = config {
        request = request.runtime_config(config);
    }
    if let Some(bytes) = ruleset {
        request = request.ruleset(bytes);
    }
    if let Some(bytes) = action_policy {
        request = request.action_policy(bytes);
    }
    if callback {
        request = request.callback_policy();
    }
    if disclose {
        request = request.disclose_ruleset_identity();
    }
    Ok(redact_secret::resolve_config(&manifest, &request)
        .as_json()
        .to_owned())
}

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
#[cfg(all(feature = "full", feature = "pii", not(feature = "custom")))]
fn build_registry(selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_built_in_and_pii(selection).map_err(WasmErrorCode::from)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), feature = "pii", not(feature = "custom")))]
fn build_registry(selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_common_built_in_and_pii(selection).map_err(WasmErrorCode::from)
}

/// See the `full` + `pii` variant above. [`initialize`] admits only the off
/// selection here, so the registry is the PII-off profile registry.
#[cfg(all(feature = "full", not(feature = "pii"), not(feature = "custom")))]
fn build_registry(_selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_built_in([]).map_err(WasmErrorCode::from)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), not(feature = "pii"), not(feature = "custom")))]
fn build_registry(_selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    DetectorRegistry::with_common_built_in([]).map_err(WasmErrorCode::from)
}

/// [`registry_with_ruleset_unselected`] with the owner's detector selection
/// applied to the built-ins (issue #1251). The ruleset's detectors stay, so
/// the registry is never inert here. Applied after construction, so the
/// compile-time constructor choice below is untouched and a `common` artifact
/// still links no `provider` detector.
///
/// # Errors
///
/// The errors of [`registry_with_ruleset_unselected`], or the selection's own
/// rejection, which a validated owner never produces.
pub(crate) fn registry_with_ruleset(ruleset: &[u8]) -> Result<DetectorRegistry, WasmErrorCode> {
    let registry = registry_with_ruleset_unselected(ruleset, active_selection())?;
    let detection = active_detection()?;
    Ok(registry.with_detection(&detection)?)
}

/// Builds one configuration's **temporary** registry from explicit input
/// (issue #1254): the configuration is resolved over this artifact's
/// defaults, then composed with the same constructors the owner uses. It
/// reads no owner state, so it needs no [`initialize`], caches nothing and
/// changes nothing. Returns the registry and the whole-input limits the
/// configuration resolved. The caller has already read `resolveConfig`'s
/// diagnostics, so a configuration that does not resolve is only
/// `INVALID_OPTIONS` here.
///
/// # Errors
///
/// `INVALID_OPTIONS` for input that does not resolve, `EMPTY_DETECTION_SET`
/// for a configuration that enables nothing, or the composition's own code.
pub(crate) fn build_temporary_registry(
    config: Option<&str>,
    ruleset: Option<&[u8]>,
) -> Result<(DetectorRegistry, WholeInputLimits), WasmErrorCode> {
    let mut request = ConfigRequest::new();
    if let Some(config) = config {
        request = request.runtime_config(config);
    }
    if let Some(bytes) = ruleset {
        request = request.ruleset(bytes);
    }
    let resolution = redact_secret::resolve_config(&manifest()?, &request);
    let Some(snapshot) = resolution.snapshot() else {
        return Err(SecretScanErrorCode::InvalidOptions.into());
    };
    if snapshot.is_inert() {
        return Err(SecretScanErrorCode::EmptyDetectionSet.into());
    }
    let pii = snapshot.pii_selection();
    let registry = match ruleset {
        Some(bytes) => registry_with_ruleset_unselected(bytes, Ok(pii.clone()))?,
        None => build_registry(pii)?,
    };
    Ok((
        registry.with_detection(snapshot.detection_selection())?,
        snapshot.whole_input_limits(),
    ))
}

/// Builds a registry over this artifact's compiled profile's built-ins,
/// plus every detector `ruleset` declares (issue #495,
/// `decision-define-declarative-detector-ruleset-contract`). Unlike
/// [`build_registry`]'s cached result, this is built per ruleset (see
/// [`with_ruleset_registry`] for the one-entry cache over it):
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
#[cfg(all(feature = "full", feature = "pii", not(feature = "custom")))]
fn registry_with_ruleset_unselected(
    ruleset: &[u8],
    selection: Result<PiiSelection, WasmErrorCode>,
) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    let selection = selection?;
    Ok(DetectorRegistry::with_built_in_and_pii_custom(
        &selection, detectors,
    )?)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), feature = "pii", not(feature = "custom")))]
fn registry_with_ruleset_unselected(
    ruleset: &[u8],
    selection: Result<PiiSelection, WasmErrorCode>,
) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    let selection = selection?;
    Ok(DetectorRegistry::with_common_built_in_and_pii_custom(
        &selection, detectors,
    )?)
}

/// See the `full` + `pii` variant above.
#[cfg(all(feature = "full", not(feature = "pii"), not(feature = "custom")))]
fn registry_with_ruleset_unselected(
    ruleset: &[u8],
    selection: Result<PiiSelection, WasmErrorCode>,
) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    selection?;
    Ok(DetectorRegistry::with_built_in(detectors)?)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), not(feature = "pii"), not(feature = "custom")))]
fn registry_with_ruleset_unselected(
    ruleset: &[u8],
    selection: Result<PiiSelection, WasmErrorCode>,
) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    selection?;
    Ok(DetectorRegistry::with_common_built_in(detectors)?)
}

/// The registry for the ruleset this thread last built, so a caller that
/// repeats one ruleset parses it and builds the registry once rather than
/// per call (issue #1059). One entry: a changed ruleset replaces it, and a
/// rejected ruleset is never stored. The PII selection and compiled profile
/// cannot change after a successful [`initialize`], so the ruleset bytes are
/// the whole key. Thread-local for the same `!Sync` reason as [`REGISTRY`].
struct RulesetEntry {
    ruleset: Vec<u8>,
    registry: DetectorRegistry,
}

thread_local! {
    static RULESET_REGISTRY: RefCell<Option<Rc<RulesetEntry>>> = const { RefCell::new(None) };
    /// Ruleset registries built on this thread, for the cache-reuse test.
    #[cfg(test)]
    static RULESET_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Calls `f` with the registry over `ruleset`'s detectors, building it only
/// when it is not the one this thread last built.
///
/// The entry is cloned out of the cache before `f` runs, so a JavaScript
/// policy callback inside `f` that scans again with another ruleset cannot
/// hit a held borrow.
///
/// # Errors
///
/// The errors of [`registry_with_ruleset`]; nothing is cached on failure.
pub(crate) fn with_ruleset_registry<T>(
    ruleset: &[u8],
    f: impl FnOnce(&DetectorRegistry) -> T,
) -> Result<T, WasmErrorCode> {
    let entry = RULESET_REGISTRY.with(|cache| -> Result<Rc<RulesetEntry>, WasmErrorCode> {
        let mut cache = cache.borrow_mut();
        if let Some(entry) = cache.as_ref().filter(|entry| entry.ruleset == ruleset) {
            return Ok(Rc::clone(entry));
        }
        let registry = registry_with_ruleset(ruleset)?;
        #[cfg(test)]
        RULESET_BUILDS.with(|builds| builds.set(builds.get() + 1));
        let entry = Rc::new(RulesetEntry {
            ruleset: ruleset.to_vec(),
            registry,
        });
        *cache = Some(Rc::clone(&entry));
        Ok(entry)
    })?;
    Ok(f(&entry.registry))
}

/// The selection captured by the last successful [`initialize`], as the
/// core error an incremental constructor reports.
fn active_selection_for_session() -> Result<PiiSelection, SecretScanError> {
    active_selection().map_err(|code| match code {
        WasmErrorCode::Core(core) => SecretScanError::from(core),
        _ => SecretScanErrorCode::InvalidState.into(),
    })
}

/// The detector selection the owner is fixed to, as the core error an
/// incremental constructor reports.
fn active_detection_for_session() -> Result<DetectionSelection, SecretScanError> {
    active_detection().map_err(|code| match code {
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
#[cfg(all(feature = "full", feature = "pii", not(feature = "custom")))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    let selection = active_selection_for_session()?;
    let detection = active_detection_for_session()?;
    IncrementalSanitizer::with_built_in_and_pii_detection_policy_and_formatter(
        limits, &selection, &detection, policy, formatter,
    )
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), feature = "pii", not(feature = "custom")))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    let selection = active_selection_for_session()?;
    let detection = active_detection_for_session()?;
    IncrementalSanitizer::with_common_built_in_and_pii_detection_policy_and_formatter(
        limits, &selection, &detection, policy, formatter,
    )
}

/// See the `full` + `pii` variant above.
#[cfg(all(feature = "full", not(feature = "pii"), not(feature = "custom")))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    active_selection_for_session()?;
    let detection = active_detection_for_session()?;
    IncrementalSanitizer::with_detection_policy_and_formatter(limits, &detection, policy, formatter)
}

/// See the `full` + `pii` variant above.
#[cfg(all(not(feature = "full"), not(feature = "pii"), not(feature = "custom")))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    active_selection_for_session()?;
    let detection = active_detection_for_session()?;
    IncrementalSanitizer::with_common_built_in_detection_policy_and_formatter(
        limits, &detection, policy, formatter,
    )
}

/// The custom-composition constructors (issue #1253, the `custom` Cargo
/// feature). Each names `redact_secret::composition` only, through the
/// composition the generated leaf crate provides, so none of them makes a
/// built-in detector outside the composition reachable.
#[cfg(all(feature = "custom", feature = "pii"))]
fn build_registry(selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    let composition = crate::custom::composition()?;
    DetectorRegistry::with_composition_and_pii(&composition, selection, [])
        .map_err(WasmErrorCode::from)
}

/// See the `custom` + `pii` variant above.
#[cfg(all(feature = "custom", not(feature = "pii")))]
fn build_registry(_selection: &PiiSelection) -> Result<DetectorRegistry, WasmErrorCode> {
    let composition = crate::custom::composition()?;
    DetectorRegistry::with_composition(&composition, []).map_err(WasmErrorCode::from)
}

/// See the `custom` + `pii` variant above.
#[cfg(all(feature = "custom", feature = "pii"))]
fn registry_with_ruleset_unselected(
    ruleset: &[u8],
    selection: Result<PiiSelection, WasmErrorCode>,
) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    let selection = selection?;
    let composition = crate::custom::composition()?;
    Ok(DetectorRegistry::with_composition_and_pii(
        &composition,
        &selection,
        detectors,
    )?)
}

/// See the `custom` + `pii` variant above.
#[cfg(all(feature = "custom", not(feature = "pii")))]
fn registry_with_ruleset_unselected(
    ruleset: &[u8],
    selection: Result<PiiSelection, WasmErrorCode>,
) -> Result<DetectorRegistry, WasmErrorCode> {
    let detectors = redact_secret::load_ruleset(ruleset)?;
    selection?;
    let composition = crate::custom::composition()?;
    Ok(DetectorRegistry::with_composition(&composition, detectors)?)
}

/// See the `custom` + `pii` variant above.
#[cfg(all(feature = "custom", feature = "pii"))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    let selection = active_selection_for_session()?;
    let detection = active_detection_for_session()?;
    let composition = crate::custom::composition()
        .map_err(|_| SecretScanError::from(SecretScanErrorCode::InvalidState))?;
    IncrementalSanitizer::with_composition_and_pii_detection_policy_and_formatter(
        limits,
        &composition,
        &selection,
        &detection,
        policy,
        formatter,
    )
}

/// See the `custom` + `pii` variant above.
#[cfg(all(feature = "custom", not(feature = "pii")))]
pub(crate) fn new_incremental_session(
    limits: IncrementalLimits,
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> Result<IncrementalSanitizer, SecretScanError> {
    active_selection_for_session()?;
    let detection = active_detection_for_session()?;
    let composition = crate::custom::composition()
        .map_err(|_| SecretScanError::from(SecretScanErrorCode::InvalidState))?;
    IncrementalSanitizer::with_composition_detection_policy_and_formatter(
        limits,
        &composition,
        &detection,
        policy,
        formatter,
    )
}

thread_local! {
    static REGISTRY: OnceCell<Result<DetectorRegistry, WasmErrorCode>> = const { OnceCell::new() };
    static SELECTION: OnceCell<PiiSelection> = const { OnceCell::new() };
    /// The detector selection the owner is fixed to (issue #1251), set by the
    /// first successful initialization and never changed afterwards.
    static DETECTION: OnceCell<DetectionSelection> = const { OnceCell::new() };
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
#[cfg(test)]
pub(crate) fn initialize(selectors: &[String]) -> Result<(), WasmErrorCode> {
    initialize_with(selectors, &DetectionSelection::all())
}

/// [`initialize`] with a detector-id selection (issue #1251).
///
/// An equivalent resolved selection is idempotent (the same enabled detectors
/// in the same order), a differing one, including the legacy call that names
/// none, is `DETECTION_CONFIG_CONFLICT`, and a rejected or conflicting
/// request changes nothing: it is validated before anything is cached, so a
/// later valid initialization still succeeds. An unknown, not-included or
/// repeated id is `INVALID_DETECTION_CONFIG`; a configuration that enables
/// nothing is `EMPTY_DETECTION_SET`. No other artifact is ever loaded to
/// satisfy a request.
///
/// # Errors
///
/// As [`initialize`], plus the selection errors above.
pub(crate) fn initialize_with(
    selectors: &[String],
    detection: &DetectionSelection,
) -> Result<(), WasmErrorCode> {
    // A custom artifact compares the manifest it ships with the one it
    // generates before anything is cached (issue #1253).
    #[cfg(feature = "custom")]
    crate::custom::verify_packaged(&manifest()?)?;
    let borrowed: Vec<&str> = selectors.iter().map(String::as_str).collect();
    let selection = PiiSelection::parse(&borrowed)?;
    let identity = selection.activation_identity(PROFILE);
    REGISTRY.with(|cell| {
        if let Some(existing) = cell.get() {
            return match existing {
                Ok(registry) if registry.activation_identity() == identity => {
                    let candidate = build_registry(&selection)?.with_detection(detection)?;
                    if registry.ids().eq(candidate.ids()) {
                        Ok(())
                    } else {
                        Err(SecretScanErrorCode::DetectionConfigConflict.into())
                    }
                }
                Ok(_) => Err(SecretScanErrorCode::PiiActivationConflict.into()),
                Err(code) => Err(*code),
            };
        }
        if !PII_RUNTIME && !selection.is_off() {
            return Err(SecretScanErrorCode::PiiSelectorUnavailable.into());
        }
        // Validate before caching: a rejected selection leaves the owner as
        // it was.
        let registry = build_registry(&selection).and_then(|registry| {
            registry
                .with_detection(detection)
                .map_err(WasmErrorCode::from)
        });
        if let Err(code) = &registry
            && matches!(code, WasmErrorCode::Detection(_))
        {
            return Err(*code);
        }
        let outcome = registry.as_ref().map(|_| ()).map_err(|code| *code);
        let _ = cell.set(registry);
        if outcome.is_ok() {
            SELECTION.with(|slot| {
                let _ = slot.set(selection);
            });
            DETECTION.with(|slot| {
                let _ = slot.set(detection.clone());
            });
        }
        outcome
    })
}

/// The detector selection the owner is fixed to.
///
/// # Errors
///
/// [`WasmErrorCode::NotInitialized`] before a successful [`initialize`].
fn active_detection() -> Result<DetectionSelection, WasmErrorCode> {
    DETECTION.with(|cell| cell.get().cloned().ok_or(WasmErrorCode::NotInitialized))
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
                "credentials={};selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2",
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
        let expected = if cfg!(feature = "custom") {
            Profile::Custom
        } else if cfg!(feature = "full") {
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
                "credentials={};selectors=off;families=;vocabulary=pii-context/v2",
                PROFILE.as_str()
            )
        );
        assert_eq!(
            initialize(&["pii".to_owned()]).unwrap_err(),
            WasmErrorCode::Core(SecretScanErrorCode::PiiActivationConflict)
        );
        assert!(!with_registry(|registry| registry.contains("pii-domain")).unwrap());
    }

    const RULESET_A: &[u8] = b"ruleset-revision: 1\n\
detector: acme-internal-token\n\
specificity: contextual\n\
prefix: \"ACME_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";
    const RULESET_B: &[u8] = b"ruleset-revision: 1\n\
detector: other-internal-token\n\
specificity: contextual\n\
prefix: \"OTHER_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";

    fn builds() -> usize {
        RULESET_BUILDS.with(std::cell::Cell::get)
    }

    #[test]
    fn a_ruleset_registry_is_built_once_per_ruleset_and_matches_a_fresh_one() {
        assert_eq!(
            with_ruleset_registry(RULESET_A, |_| ()).unwrap_err(),
            WasmErrorCode::NotInitialized
        );
        assert_eq!(builds(), 0);
        initialize(&[]).unwrap();
        let input = format!("ACME_{} OTHER_{}", "a".repeat(20), "b".repeat(20));
        let scan = |registry: &DetectorRegistry| {
            redact_secret::scan(&input, registry, &redact_secret::DefaultPolicy).unwrap()
        };
        let fresh = scan(&registry_with_ruleset(RULESET_A).unwrap());
        assert_eq!(fresh.len(), 1);
        for _ in 0..3 {
            assert_eq!(with_ruleset_registry(RULESET_A, scan).unwrap(), fresh);
        }
        assert_eq!(builds(), 1);
        // A changed ruleset replaces the entry and never sees the old one's
        // detector.
        let other = with_ruleset_registry(RULESET_B, scan).unwrap();
        assert_eq!(other.len(), 1);
        assert_ne!(other, fresh);
        assert_eq!(builds(), 2);
        assert_eq!(with_ruleset_registry(RULESET_A, scan).unwrap(), fresh);
        assert_eq!(builds(), 3);
    }

    #[test]
    fn a_rejected_ruleset_is_not_cached_and_keeps_the_previous_entry() {
        initialize(&[]).unwrap();
        with_ruleset_registry(RULESET_A, |_| ()).unwrap();
        for _ in 0..2 {
            assert!(with_ruleset_registry(b"ruleset-revision: 2\n", |_| ()).is_err());
        }
        assert_eq!(builds(), 1);
        with_ruleset_registry(RULESET_A, |_| ()).unwrap();
        assert_eq!(builds(), 1);
    }

    #[test]
    fn a_ruleset_scan_may_reenter_with_another_ruleset() {
        initialize(&[]).unwrap();
        let inner = with_ruleset_registry(RULESET_A, |_| {
            with_ruleset_registry(RULESET_B, |registry| {
                registry.contains("other-internal-token")
            })
        })
        .unwrap()
        .unwrap();
        assert!(inner);
    }

    // -- Detector selection (issue #1251). Each test runs on its own thread
    // and so sees its own owner state.

    fn include(ids: &[&str]) -> DetectionSelection {
        DetectionSelection::include(ids.iter().copied())
    }

    #[test]
    fn a_selection_narrows_every_registry_the_owner_builds() {
        let selection = DetectionSelection::exclude(["github-token"]);
        if !cfg!(all(feature = "full", not(feature = "custom"))) {
            // `common` has no `github-token`: the request is rejected, never
            // satisfied by loading `full`.
            let error = initialize_with(&[], &selection).unwrap_err();
            assert!(matches!(error, WasmErrorCode::Detection(_)));
            return;
        }
        initialize_with(&[], &selection).unwrap();
        assert!(!with_registry(|registry| registry.contains("github-token")).unwrap());
        assert!(
            !registry_with_ruleset(RULESET_A)
                .unwrap()
                .contains("github-token")
        );
        assert!(
            registry_with_ruleset(RULESET_A)
                .unwrap()
                .contains("acme-internal-token")
        );
        assert_eq!(active_detection().unwrap(), selection);
    }

    #[test]
    fn equivalent_selections_are_idempotent_and_differing_ones_conflict_without_change() {
        initialize_with(&[], &include(&["jwt", "private-key"])).unwrap();
        initialize_with(&[], &include(&["private-key", "jwt"])).unwrap();
        let before =
            with_registry(|registry| registry.ids().map(str::to_owned).collect::<Vec<_>>())
                .unwrap();
        for different in [
            include(&["jwt"]),
            DetectionSelection::exclude(["jwt"]),
            DetectionSelection::all(),
        ] {
            assert_eq!(
                initialize_with(&[], &different).unwrap_err(),
                WasmErrorCode::Core(SecretScanErrorCode::DetectionConfigConflict)
            );
        }
        assert_eq!(
            initialize(&[]).unwrap_err(),
            WasmErrorCode::Core(SecretScanErrorCode::DetectionConfigConflict)
        );
        let after = with_registry(|registry| registry.ids().map(str::to_owned).collect::<Vec<_>>())
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn a_rejected_selection_caches_nothing_and_a_later_valid_one_succeeds() {
        for rejected in [
            include(&["jwt", "no-such-detector"]),
            include(&["jwt", "jwt"]),
            include(&[]),
        ] {
            assert!(matches!(
                initialize_with(&[], &rejected).unwrap_err(),
                WasmErrorCode::Detection(_)
            ));
            assert_eq!(
                ensure_initialized().unwrap_err(),
                WasmErrorCode::NotInitialized
            );
        }
        initialize_with(&[], &include(&["jwt"])).unwrap();
        assert_eq!(with_registry(DetectorRegistry::len).unwrap(), 1);
    }

    #[test]
    fn a_session_captures_the_owner_selection_at_creation() {
        initialize_with(&[], &include(&["jwt"])).unwrap();
        let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
        let mut session = new_incremental_session(
            limits,
            Box::new(redact_secret::DefaultPolicy),
            Box::new(redact_secret::default_placeholder_formatter),
        )
        .unwrap();
        let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
        let mut text = session.append(input).unwrap().text().to_owned();
        text.push_str(session.finalize().unwrap().text());
        assert_eq!(text, input, "no enabled detector claims the span");
    }

    #[test]
    fn resolve_config_is_pure_before_initialize() {
        let document = resolve_config(
            Some(r#"{"detection":{"exclude":["jwt"]}}"#),
            None,
            None,
            false,
            false,
        )
        .unwrap();
        assert!(document.starts_with("{\"schema\":\"config-resolution/v1\","));
        assert!(document.contains("\"ok\":true"));
        assert_eq!(
            ensure_initialized().unwrap_err(),
            WasmErrorCode::NotInitialized
        );
        REGISTRY.with(|cell| assert!(cell.get().is_none()));
        // The artifact manifest says selection is supported on WebAssembly.
        assert!(manifest().unwrap().detector_selection());
    }

    /// Issue #1254: a comparison side builds its own registry from explicit
    /// input, before and without an owner, and leaves the owner alone.
    #[test]
    fn a_temporary_registry_is_independent_of_the_owner() {
        let (all, limits) = build_temporary_registry(None, None).unwrap();
        let (narrow, narrow_limits) = build_temporary_registry(
            Some(r#"{"detection":{"include":["jwt"]},"limits":{"maxFindings":7}}"#),
            None,
        )
        .unwrap();
        assert_eq!(limits, WholeInputLimits::default());
        assert_eq!(narrow_limits.max_findings(), 7);
        assert_eq!(narrow.ids().collect::<Vec<_>>(), ["jwt"]);
        assert!(all.len() > narrow.len());
        // No owner was created or consulted.
        REGISTRY.with(|cell| assert!(cell.get().is_none()));
        assert_eq!(
            ensure_initialized().unwrap_err(),
            WasmErrorCode::NotInitialized
        );
    }

    #[test]
    fn a_temporary_registry_refuses_what_it_cannot_build() {
        let inert = build_temporary_registry(Some(r#"{"detection":{"include":[]}}"#), None);
        assert_eq!(
            inert.unwrap_err(),
            WasmErrorCode::Core(SecretScanErrorCode::EmptyDetectionSet)
        );
        let unknown =
            build_temporary_registry(Some(r#"{"detection":{"include":["no-such-id"]}}"#), None);
        assert_eq!(
            unknown.unwrap_err(),
            WasmErrorCode::Core(SecretScanErrorCode::InvalidOptions)
        );
        let pii = build_temporary_registry(Some(r#"{"pii":["pii:global"]}"#), None);
        assert_eq!(
            pii.is_ok(),
            PII_RUNTIME,
            "PII is built only where the PII runtime is linked"
        );
    }
}
