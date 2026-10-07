//! The artifact manifest and its detector catalog (issue #1250,
//! `decision-define-the-artifact-manifest-and-configuration-data-contracts`),
//! through the crate's public API only.
//!
//! These are the catalog drift tests: a detector id, its pack, the canonical
//! order or an emitted type cannot change in the registration rows, the
//! reviewed inventory or the manifest without one of them failing. There is
//! no second policy table in any binding to keep in step; the bindings only
//! forward this value.
//!
//! Every input is synthetic. No manifest holds an input or a ruleset.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use redact_secret::{
    ArtifactKind, ArtifactManifest, ArtifactManifestError, BuiltInRegistry, DetectorRegistry,
    PiiSelection, Profile, VERSION,
};
use serde_json::Value;

const INVENTORY: &str = include_str!("../../../docs/coverage/detector-inventory.json");
const CANONICAL_FIXTURE: &str =
    include_str!("../../../conformance/fixtures/artifact-manifest-v1.json");

fn full() -> ArtifactManifest {
    ArtifactManifest::full(ArtifactKind::RustRegistry, true, None).unwrap()
}

fn common() -> ArtifactManifest {
    ArtifactManifest::common(ArtifactKind::RustRegistry, true, None).unwrap()
}

fn document(manifest: &ArtifactManifest) -> Value {
    serde_json::from_str(manifest.as_json()).expect("the manifest is valid JSON")
}

fn detectors(manifest: &ArtifactManifest) -> Vec<Value> {
    document(manifest)["detectors"].as_array().unwrap().clone()
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect()
}

#[test]
fn full_and_common_ids_equal_the_registered_ids_in_canonical_order() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let built_in = BuiltInRegistry::with_built_in().unwrap();
    let registered: Vec<&str> = registry.ids().collect();
    assert_eq!(full().detector_ids().collect::<Vec<_>>(), registered);
    assert_eq!(built_in.ids().collect::<Vec<_>>(), registered);
    let listed: Vec<String> = detectors(&full())
        .iter()
        .map(|entry| entry["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(listed, registered);

    let common_registry = DetectorRegistry::with_common_built_in([]).unwrap();
    let common_registered: Vec<&str> = common_registry.ids().collect();
    assert_eq!(
        common().detector_ids().collect::<Vec<_>>(),
        common_registered
    );
    assert_eq!(common_registered.len(), 6);
}

#[test]
fn common_is_an_order_preserving_subset_and_every_other_id_is_not_included() {
    let full_manifest = full();
    let full_ids: Vec<&str> = full_manifest.detector_ids().collect();
    let common_manifest = common();
    let common_ids: Vec<&str> = common_manifest.detector_ids().collect();
    let positions: Vec<usize> = common_ids
        .iter()
        .map(|id| full_ids.iter().position(|full_id| full_id == id).unwrap())
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    let absent: Vec<&str> = full_ids
        .iter()
        .copied()
        .filter(|id| !common_ids.contains(id))
        .collect();
    assert_eq!(
        common_manifest.not_included_ids().collect::<Vec<_>>(),
        absent
    );
    assert_eq!(strings(&document(&common_manifest)["notIncluded"]), absent);
    assert!(strings(&document(&full())["notIncluded"]).is_empty());
}

#[test]
fn pack_membership_matches_the_profiles() {
    let common_manifest = common();
    let common_ids: BTreeSet<&str> = common_manifest.detector_ids().collect();
    for entry in detectors(&full()) {
        let id = entry["id"].as_str().unwrap();
        let pack = entry["pack"].as_str().unwrap();
        assert_eq!(
            pack == "common",
            common_ids.contains(id),
            "{id} has pack {pack}"
        );
        assert!(pack == "common" || pack == "provider");
    }
    for entry in detectors(&common()) {
        assert_eq!(entry["pack"], "common");
    }
}

#[test]
fn declared_types_equal_the_reviewed_inventory_in_both_directions() {
    let inventory: Value = serde_json::from_str(INVENTORY).unwrap();
    let mut reviewed: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for row in inventory["types"].as_array().unwrap() {
        reviewed
            .entry(row["detector"].as_str().unwrap())
            .or_default()
            .insert(row["type"].as_str().unwrap());
    }
    let manifest = full();
    let listed = detectors(&manifest);
    assert_eq!(listed.len(), reviewed.len());
    for entry in &listed {
        let id = entry["id"].as_str().unwrap();
        let types = strings(&entry["types"]);
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert_eq!(types, sorted, "{id}: types are sorted");
        let declared: BTreeSet<&str> = types.into_iter().collect();
        assert_eq!(
            Some(&declared),
            reviewed.get(id),
            "{id}: the manifest and docs/coverage/detector-inventory.json disagree"
        );
    }
}

#[test]
fn every_included_detector_entry_has_the_contracted_shape() {
    for manifest in [full(), common()] {
        for entry in detectors(&manifest) {
            let members: Vec<&str> = entry
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(members, ["aliases", "id", "pack", "types"]);
            assert!(entry["aliases"].as_array().unwrap().is_empty());
            assert!(!entry["types"].as_array().unwrap().is_empty());
        }
    }
}

#[test]
fn the_document_carries_the_contracted_identity_and_capabilities() {
    let manifest = ArtifactManifest::common(ArtifactKind::Wasm, false, None).unwrap();
    let value = document(&manifest);
    assert_eq!(value["schema"], ArtifactManifest::SCHEMA);
    assert_eq!(value["product"], "redact-secret");
    assert_eq!(value["version"], VERSION);
    assert_eq!(value["sourceRevision"], Value::Null);
    assert_eq!(value["artifact"]["kind"], "wasm");
    assert_eq!(value["artifact"]["variant"], "common");
    assert_eq!(value["artifact"]["pii"], false);
    assert_eq!(value["composition"]["kind"], "standard");
    assert_eq!(value["composition"]["profile"], "common");
    assert_eq!(value["composition"]["id"], Value::Null);
    assert_eq!(value["pii"]["available"], false);
    assert!(value["pii"]["families"].as_array().unwrap().is_empty());
    assert_eq!(value["capabilities"]["detectorSelection"], false);
    assert_eq!(value["capabilities"]["incremental"], true);
    assert_eq!(value["capabilities"]["ruleset"]["revisions"][0], 1);
    assert_eq!(value["capabilities"]["actionPolicy"]["revisions"][0], 1);
    assert_eq!(value["defaults"]["schema"], "build-defaults/v1");
    assert_eq!(value["defaults"]["detection"], "all-included");
    assert_eq!(
        value["defaults"]["pii"]["selectors"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(value["bounds"]["limits"]["maxFindings"], 50_000);
    assert_eq!(value["bounds"]["limits"]["maxInputBytes"], 64 * 1024 * 1024);
    assert_eq!(value["bounds"]["actionPolicyBytes"], 65_536);
    assert_eq!(value["bounds"]["detectorIdsMax"], 256);
    assert_eq!(value["bounds"]["diagnosticsMax"], 256);
    assert_eq!(manifest.profile(), Profile::Common);
    assert_eq!(manifest.kind(), ArtifactKind::Wasm);
}

#[test]
fn pii_families_are_the_linked_runtime_families_in_sorted_order() {
    let value = document(&full());
    assert_eq!(value["pii"]["available"], true);
    let families = strings(&value["pii"]["families"]);
    assert!(!families.is_empty());
    let mut sorted = families.clone();
    sorted.sort_unstable();
    assert_eq!(families, sorted);
    // Every listed family is accepted by the real selector grammar for this
    // artifact, so the list cannot name a family the runtime lacks.
    for family in families {
        let selector = format!("pii:family:{}", family.strip_prefix("pii:").unwrap());
        PiiSelection::parse(&[selector.as_str()]).unwrap();
    }
}

#[test]
fn type_vocabulary_is_not_claimed_to_be_closed() {
    let value = document(&full());
    assert_eq!(value["typeVocabulary"]["complete"], false);
    assert_eq!(value["typeVocabulary"]["builtInTypes"], "declared");
    assert_eq!(
        strings(&value["typeVocabulary"]["dynamicSources"]),
        ["custom-detector", "pii", "ruleset"]
    );
}

#[test]
fn a_manifest_carries_no_synthetic_trigger_literal_path_or_timestamp() {
    let inventory: Value = serde_json::from_str(INVENTORY).unwrap();
    let json = full().as_json().to_owned();
    for row in inventory["types"].as_array().unwrap() {
        let trigger = row["reconciliationTrigger"].as_str().unwrap();
        assert!(!json.contains(trigger));
    }
    assert!(json.is_ascii());
    for forbidden in ["\\\\", "://", "T00:", "localhost", "HOME"] {
        assert!(!json.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn canonical_fixture_cases_match_the_sorted_compact_form() {
    let fixture: Value = serde_json::from_str(CANONICAL_FIXTURE).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let rendered = serde_json::to_string(&case["input"]).unwrap();
        assert_eq!(
            rendered,
            case["canonical"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
    let members = strings(&fixture["manifest"]["members"]);
    let value = document(&full());
    let live: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(live, members);
    assert!(
        full()
            .as_json()
            .starts_with("{\"schema\":\"artifact-manifest/v1\",")
    );
}

#[test]
fn generation_is_deterministic_and_leaves_pii_selection_untouched() {
    let before = PiiSelection::default().activation_identity(Profile::Full);
    let first = full();
    let second = full();
    assert_eq!(first.as_json(), second.as_json());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(
        PiiSelection::default().activation_identity(Profile::Full),
        before
    );
}

#[test]
fn verification_diagnostics_are_fixed_and_carry_no_content() {
    let manifest = full();
    assert_eq!(manifest.verify_packaged(Some(manifest.as_json())), Ok(()));
    let missing = manifest.verify_packaged(None).unwrap_err();
    assert_eq!(missing, ArtifactManifestError::Missing);
    assert_eq!(missing.code(), "ARTIFACT_MANIFEST_MISSING");
    let marker = "SYNTHETIC-DOCUMENT-CONTENT";
    let wrong_schema = manifest.verify_packaged(Some(marker)).unwrap_err();
    assert_eq!(wrong_schema, ArtifactManifestError::SchemaMismatch);
    let other = common();
    let mismatch = manifest.verify_packaged(Some(other.as_json())).unwrap_err();
    assert_eq!(mismatch, ArtifactManifestError::DigestMismatch);
    for error in [missing, wrong_schema, mismatch] {
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
        assert!(error.message().len() <= 64);
    }
}

#[test]
fn source_revision_is_bound_into_the_digest() {
    let revision = "0123456789abcdef0123456789abcdef01234567";
    let pinned = ArtifactManifest::full(ArtifactKind::Cli, true, Some(revision)).unwrap();
    let unpinned = ArtifactManifest::full(ArtifactKind::Cli, true, None).unwrap();
    assert_ne!(pinned.digest(), unpinned.digest());
    assert_eq!(document(&pinned)["sourceRevision"], revision);
    assert_eq!(
        ArtifactManifest::full(ArtifactKind::Cli, true, Some("not-a-revision")),
        Err(ArtifactManifestError::InvalidSourceRevision)
    );
}
