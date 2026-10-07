use super::*;
use crate::lifecycle;
use redact_secret::ArtifactManifestError;
use redact_secret::composition::{github_token, jwt};

fn selected() -> Result<Composition, SecretScanError> {
    Composition::new("edge", false, [github_token(), jwt()])
}

fn manifest_text() -> String {
    let composition = selected().expect("composition");
    ArtifactManifest::custom(redact_secret::ArtifactKind::Wasm, &composition, None)
        .expect("manifest")
        .as_json()
        .to_owned()
}

fn install_with(packaged: Option<&'static str>) {
    install(Box::leak(Box::new(Provider {
        composition: selected,
        packaged_manifest: packaged,
    })));
}

#[test]
fn a_matching_packaged_manifest_initializes_and_the_registry_is_the_composition() {
    install_with(Some(Box::leak(manifest_text().into_boxed_str())));
    assert_eq!(lifecycle::initialize(&[]), Ok(()));
    let ids =
        lifecycle::with_registry(|registry| registry.ids().map(str::to_owned).collect::<Vec<_>>())
            .unwrap();
    assert_eq!(ids, ["github-token", "jwt"]);
    assert_eq!(
        lifecycle::with_registry(redact_secret::DetectorRegistry::profile).unwrap(),
        Some(redact_secret::Profile::Custom)
    );
    assert_eq!(crate::profile(), "custom");
    let document = lifecycle::artifact_manifest().unwrap();
    assert!(document.contains("\"variant\":\"custom\""));
    assert!(document.contains("\"kind\":\"custom\""));
}

#[test]
fn a_missing_packaged_manifest_fails_initialization_with_a_fixed_class() {
    install_with(None);
    assert_eq!(
        lifecycle::initialize(&[]),
        Err(WasmErrorCode::Manifest(ArtifactManifestError::Missing))
    );
    // Nothing was cached: the registry is not available.
    assert_eq!(
        lifecycle::ensure_initialized(),
        Err(WasmErrorCode::NotInitialized)
    );
}

#[test]
fn a_foreign_packaged_manifest_fails_with_the_schema_class() {
    install_with(Some("{\"not\":\"a manifest\"}"));
    assert_eq!(
        lifecycle::initialize(&[]),
        Err(WasmErrorCode::Manifest(
            ArtifactManifestError::SchemaMismatch
        ))
    );
}

#[test]
fn another_compositions_manifest_is_a_digest_mismatch_that_echoes_nothing() {
    let other = Composition::new("other", false, [jwt()]).expect("composition");
    let text = ArtifactManifest::custom(redact_secret::ArtifactKind::Wasm, &other, None)
        .expect("manifest")
        .as_json()
        .to_owned();
    install_with(Some(Box::leak(text.into_boxed_str())));
    let error = lifecycle::initialize(&[]).unwrap_err();
    assert_eq!(
        error,
        WasmErrorCode::Manifest(ArtifactManifestError::DigestMismatch)
    );
    assert!(!format!("{error:?}").contains("other"));
}
