//! The seam between a generated custom-composition leaf crate and this
//! binding (issue #1253,
//! `decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`).
//!
//! Built with the `custom` Cargo feature, this crate references no built-in
//! detector constructor at all: not the `full` one, not the `common` one. The
//! leaf crate that `scripts/build-custom-artifact.mjs` generates in an isolated
//! build workspace owns the one thing that differs between custom artifacts, a
//! function that calls exactly the selected per-detector constructors of
//! `redact_secret::composition` and passes them to
//! [`Composition::new`](redact_secret::composition::Composition::new). It hands
//! that function to this crate, together with the exact bytes of the packaged
//! `artifact-manifest.custom.json`, through [`install`] from a
//! `#[wasm_bindgen(start)]` function, which runs when the module is
//! instantiated and before any export is callable. Link-time reachability
//! then keeps only the detectors that function names.
//!
//! This crate stays one crate with the `full`, `common` and `custom` builds
//! sharing every export: the generated wrapper has the function set of
//! `./common` because it re-exports this crate's.

use std::cell::OnceCell;
use std::rc::Rc;

use redact_secret::composition::Composition;
use redact_secret::{ArtifactManifest, ArtifactManifestError, SecretScanError};

use crate::error::WasmErrorCode;

/// What a generated leaf crate provides for one custom artifact.
pub struct Provider {
    /// Builds the composition from the selected constructors only.
    pub composition: fn() -> Result<Composition, SecretScanError>,
    /// The exact bytes of the packaged `artifact-manifest.custom.json` the
    /// build ships beside the artifact, compared with the manifest this
    /// artifact generates at initialization. `None` when the build packaged
    /// none, which initialization reports as `ARTIFACT_MANIFEST_MISSING`.
    pub packaged_manifest: Option<&'static str>,
}

thread_local! {
    static PROVIDER: OnceCell<&'static Provider> = const { OnceCell::new() };
    static COMPOSITION: OnceCell<Result<Rc<Composition>, WasmErrorCode>> = const { OnceCell::new() };
    static VERIFIED: OnceCell<Result<(), WasmErrorCode>> = const { OnceCell::new() };
}

/// Installs the leaf crate's provider. Called once, from the leaf crate's
/// `#[wasm_bindgen(start)]` function; a later call changes nothing.
pub fn install(provider: &'static Provider) {
    PROVIDER.with(|cell| {
        let _ = cell.set(provider);
    });
}

#[cfg(not(test))]
fn provider() -> Result<&'static Provider, WasmErrorCode> {
    PROVIDER
        .with(|cell| cell.get().copied())
        .ok_or(WasmErrorCode::InitializationFailed)
}

/// Under test no leaf crate installs one: see [`test_provider`].
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
fn provider() -> Result<&'static Provider, WasmErrorCode> {
    Ok(PROVIDER.with(|cell| *cell.get_or_init(test_provider)))
}

/// The composition of this artifact, built once from the installed provider.
///
/// # Errors
///
/// `INITIALIZATION_FAILED` when no provider is installed or the provider's
/// composition is rejected; both are build defects, fixed and input-free.
pub(crate) fn composition() -> Result<Rc<Composition>, WasmErrorCode> {
    COMPOSITION.with(|cell| {
        cell.get_or_init(|| {
            let provider = provider()?;
            (provider.composition)()
                .map(Rc::new)
                .map_err(|_| WasmErrorCode::InitializationFailed)
        })
        .clone()
    })
}

/// Checks the packaged manifest against the manifest this artifact generates
/// from its own composition, once per module instance
/// ([`ArtifactManifest::verify_packaged`]).
///
/// # Errors
///
/// The fixed `ARTIFACT_MANIFEST_MISSING`, `ARTIFACT_MANIFEST_SCHEMA_MISMATCH`
/// or `ARTIFACT_MANIFEST_DIGEST_MISMATCH` class; nothing of either document
/// is echoed.
pub(crate) fn verify_packaged(manifest: &ArtifactManifest) -> Result<(), WasmErrorCode> {
    VERIFIED.with(|cell| {
        *cell.get_or_init(|| {
            let packaged = provider()?.packaged_manifest;
            manifest
                .verify_packaged(packaged)
                .map_err(|error: ArtifactManifestError| WasmErrorCode::from(error))
        })
    })
}

/// Under test no leaf crate exists: the composition is the six `common`
/// detectors, which is what every `not full` assertion in this crate's tests
/// expects, and the packaged manifest is the one it generates.
#[cfg(test)]
fn test_provider() -> &'static Provider {
    use redact_secret::composition::{
        bearer_token, connection_string, generic_token, jwt, otpauth_uri, private_key,
    };
    use redact_secret::{ArtifactKind, ArtifactManifest};

    fn composition() -> Result<Composition, SecretScanError> {
        Composition::new(
            "wasm-tests",
            cfg!(feature = "pii"),
            [
                private_key(),
                jwt(),
                bearer_token(),
                connection_string(),
                otpauth_uri(),
                generic_token(),
            ],
        )
    }
    let manifest = composition()
        .ok()
        .and_then(|composition| {
            ArtifactManifest::custom(
                ArtifactKind::Wasm,
                &composition,
                crate::lifecycle::source_revision(),
            )
            .ok()
        })
        .map(|manifest| manifest.as_json().to_owned());
    let packaged: Option<&'static str> = manifest.map(|text| &*Box::leak(text.into_boxed_str()));
    Box::leak(Box::new(Provider {
        composition,
        packaged_manifest: packaged,
    }))
}

#[cfg(test)]
mod tests;
