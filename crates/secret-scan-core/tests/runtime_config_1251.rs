//! `resolve_config` and `describe_config` (issue #1251): the shared truth
//! table, snapshot identity, immutability and input-freedom.
//!
//! The table lives in `conformance/fixtures/runtime-config-v1.json` and is
//! run here against the Rust core and, separately, by every JavaScript
//! runtime that loads a binding. Every input is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    ArtifactKind, ArtifactManifest, ConfigDiagnostic, ConfigRequest, DetectionSelection,
    DetectorRegistry, PiiSelection, describe_config, resolve_config,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../conformance/fixtures/runtime-config-v1.json");

fn manifest(profile: &str) -> ArtifactManifest {
    match profile {
        "full" => ArtifactManifest::full(ArtifactKind::RustRegistry, true, None).unwrap(),
        "common" => ArtifactManifest::common(ArtifactKind::RustRegistry, true, None).unwrap(),
        other => panic!("unknown profile {other}"),
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn request_text(case: &Value) -> Option<String> {
    if let Some(text) = case.get("configText") {
        return Some(text.as_str().unwrap().to_owned());
    }
    case.get("config")
        .map(|config| serde_json::to_string(config).unwrap())
}

fn policy_text(case: &Value) -> Option<String> {
    case.get("actionPolicy").map(|policy| match policy {
        Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap(),
    })
}

#[test]
fn every_fixture_case_resolves_as_expected() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(fixture["schema"], "runtime-config-conformance/v1");
    let mut ran = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        for profile in strings(&case["profiles"]) {
            ran += 1;
            let manifest = manifest(&profile);
            let text = request_text(case);
            let policy = policy_text(case);
            let ruleset = case
                .get("ruleset")
                .map(|ruleset| ruleset.as_str().unwrap().to_owned());
            let mut request = ConfigRequest::new();
            if let Some(text) = text.as_deref() {
                request = request.runtime_config(text);
            }
            if let Some(policy) = policy.as_deref() {
                request = request.action_policy(policy.as_bytes());
            }
            if let Some(ruleset) = ruleset.as_deref() {
                request = request.ruleset(ruleset.as_bytes());
            }
            if case.get("callback") == Some(&Value::Bool(true)) {
                request = request.callback_policy();
            }
            if case.get("discloseRulesetIdentity") == Some(&Value::Bool(true)) {
                request = request.disclose_ruleset_identity();
            }
            let resolution = resolve_config(&manifest, &request);
            let envelope: Value = serde_json::from_str(resolution.as_json()).unwrap();
            check_case(
                name,
                &profile,
                &case["expect"],
                &manifest,
                &resolution,
                &envelope,
            );
        }
    }
    assert!(ran >= 40, "the fixture ran {ran} cases");
}

#[allow(
    clippy::too_many_lines,
    reason = "one flat list of the fixture's expectations"
)]
fn check_case(
    name: &str,
    profile: &str,
    expect: &Value,
    manifest: &ArtifactManifest,
    resolution: &redact_secret::ConfigResolution,
    envelope: &Value,
) {
    let at = format!("{name} [{profile}]");
    assert_eq!(envelope["schema"], "config-resolution/v1", "{at}");
    assert_eq!(envelope["ok"], expect["ok"], "{at}");
    assert_eq!(resolution.is_ok(), expect["ok"].as_bool().unwrap(), "{at}");
    let codes: Vec<&str> = resolution
        .diagnostics()
        .iter()
        .map(ConfigDiagnostic::code)
        .collect();
    assert_eq!(codes, strings(&expect["codes"]), "{at}");
    if let Some(paths) = expect.get("paths") {
        let actual: Vec<&str> = resolution
            .diagnostics()
            .iter()
            .map(ConfigDiagnostic::path)
            .collect();
        assert_eq!(actual, strings(paths), "{at}");
    }
    // Errors come first, then everything else, in a stable order.
    let severities: Vec<&str> = resolution
        .diagnostics()
        .iter()
        .map(|d| d.severity().as_str())
        .collect();
    let mut sorted = severities.clone();
    sorted.sort_by_key(|severity| match *severity {
        "error" => 0,
        "warning" => 1,
        _ => 2,
    });
    assert_eq!(severities, sorted, "{at}");
    assert_eq!(
        envelope["diagnostics"]["schema"], "config-diagnostics/v1",
        "{at}"
    );

    if !expect["ok"].as_bool().unwrap() {
        assert!(envelope["snapshot"].is_null(), "{at}");
        return;
    }
    let snapshot = &envelope["snapshot"];
    assert_eq!(snapshot["schema"], "config-snapshot/v1", "{at}");
    assert_eq!(
        snapshot["artifact"]["manifestDigest"],
        manifest.digest(),
        "{at}"
    );
    if let Some(mode) = expect.get("mode") {
        assert_eq!(&snapshot["detection"]["mode"], mode, "{at}");
    }
    let detection = &snapshot["detection"];
    if let Some(ids) = expect.get("enabledIds") {
        assert_eq!(strings(&detection["enabled"]), strings(ids), "{at}");
    }
    if let Some(count) = expect.get("enabledCount") {
        assert_eq!(&detection["enabledCount"], count, "{at}");
    }
    if let Some(count) = expect.get("disabledCount") {
        assert_eq!(
            detection["disabled"].as_array().unwrap().len(),
            usize::try_from(count.as_u64().unwrap()).unwrap(),
            "{at}"
        );
    }
    if let Some(ids) = expect.get("disabledIds") {
        assert_eq!(strings(&detection["disabled"]), strings(ids), "{at}");
    }
    // compiled = enabled + disabled; unavailable is the rest of `full`.
    let compiled = detection["compiledCount"].as_u64().unwrap();
    assert_eq!(
        compiled,
        detection["enabledCount"].as_u64().unwrap()
            + detection["disabled"].as_array().unwrap().len() as u64,
        "{at}"
    );
    assert_eq!(
        strings(&detection["unavailable"]),
        manifest
            .not_included_ids()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        "{at}"
    );
    if let Some(inert) = expect.get("inert") {
        assert_eq!(&snapshot["effects"]["inert"], inert, "{at}");
        assert_eq!(
            resolution.snapshot().unwrap().is_inert(),
            inert.as_bool().unwrap()
        );
    }
    if let Some(source) = expect.get("policySource") {
        assert_eq!(&snapshot["actionPolicy"]["source"], source, "{at}");
    }
    if let Some(digest) = expect.get("policyDigest") {
        assert_eq!(&snapshot["actionPolicy"]["digest"], digest, "{at}");
    }
    if let Some(count) = expect.get("policyRuleCount") {
        assert_eq!(&snapshot["actionPolicy"]["ruleCount"], count, "{at}");
    }
    if let Some(explainable) = expect.get("policyExplainable") {
        assert_eq!(
            &snapshot["actionPolicy"]["explainable"], explainable,
            "{at}"
        );
    }
    if let Some(limits) = expect.get("limits") {
        assert_eq!(&snapshot["limits"], limits, "{at}");
    }
    if let Some(origins) = expect.get("origins") {
        for (key, value) in origins.as_object().unwrap() {
            assert_eq!(&snapshot["origins"][key], value, "{at} origin {key}");
        }
    }
    if let Some(selectors) = expect.get("piiSelectors") {
        assert_eq!(&snapshot["pii"]["selectors"], selectors, "{at}");
    }
    let ruleset = &snapshot["ruleset"];
    if let Some(present) = expect.get("rulesetPresent") {
        assert_eq!(&ruleset["present"], present, "{at}");
    }
    if let Some(disclosed) = expect.get("rulesetDisclosed") {
        assert_eq!(&ruleset["disclosed"], disclosed, "{at}");
        if !disclosed.as_bool().unwrap() {
            assert!(ruleset["detectorIds"].is_null(), "{at}");
            assert!(ruleset["digest"].is_null(), "{at}");
        }
    }
    if let Some(count) = expect.get("rulesetDetectorCount") {
        assert_eq!(&ruleset["detectorCount"], count, "{at}");
    }
    if let Some(ids) = expect.get("rulesetDetectorIds") {
        assert_eq!(strings(&ruleset["detectorIds"]), strings(ids), "{at}");
    }
    if let Some(digest) = expect.get("rulesetDigest") {
        assert_eq!(&ruleset["digest"], digest, "{at}");
    }
}

#[test]
fn the_snapshot_document_and_digest_follow_the_manifest_convention() {
    let manifest = manifest("full");
    let resolution = resolve_config(&manifest, &ConfigRequest::new());
    let snapshot = resolution.snapshot().unwrap();
    let json = snapshot.as_json();
    assert!(json.starts_with("{\"schema\":\"config-snapshot/v1\","));
    assert!(json.is_ascii() && !json.contains(' '));

    // The digest is over the canonical form without `digest`: every member,
    // `schema` included, in bytewise order (serde_json keeps keys sorted).
    let mut value: Value = serde_json::from_str(json).unwrap();
    let digest = value.as_object_mut().unwrap().remove("digest").unwrap();
    assert_eq!(digest, snapshot.digest());
    let canonical = serde_json::to_string(&value).unwrap();
    assert!(canonical.starts_with("{\"actionPolicy\":"));
    // The independent re-derivation of the digest (SHA-256 over that text)
    // is a conformance check of every JavaScript runtime, where WebCrypto is
    // not the implementation under test.
    assert_eq!(snapshot.digest().len(), "sha256:".len() + 64);
    assert!(snapshot.digest().starts_with("sha256:"));

    // The envelope embeds exactly the snapshot's own document.
    assert!(resolution.as_json().contains(json));
    assert!(
        resolution
            .as_json()
            .starts_with("{\"schema\":\"config-resolution/v1\",")
    );
}

#[test]
fn the_same_effective_detection_has_the_same_digest_whatever_the_spelling() {
    let manifest = manifest("full");
    let digest = |config: &str| {
        resolve_config(&manifest, &ConfigRequest::new().runtime_config(config))
            .snapshot()
            .unwrap()
            .detection_digest()
            .to_owned()
    };
    let default = resolve_config(&manifest, &ConfigRequest::new())
        .snapshot()
        .unwrap()
        .detection_digest()
        .to_owned();
    // Absent, `{}` and `exclude: []` enable the same detectors.
    assert_eq!(digest("{}"), default);
    assert_eq!(digest(r#"{"detection":{"exclude":[]}}"#), default);
    // Request order and spelling of include never matter.
    assert_eq!(
        digest(r#"{"detection":{"include":["jwt","private-key"]}}"#),
        digest(r#"{ "detection" : { "include" : ["private-key", "jwt"] } }"#)
    );
    assert_ne!(digest(r#"{"detection":{"include":["jwt"]}}"#), default);
    // A different artifact never shares a detection digest.
    let common = self::manifest("common");
    let other = resolve_config(&common, &ConfigRequest::new());
    assert_ne!(other.snapshot().unwrap().detection_digest(), default);
}

#[test]
fn an_action_never_changes_detection_and_a_document_replaces_the_whole_policy() {
    let manifest = manifest("full");
    let allow = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"a","match":{"type":["github_token"]},"action":"allow"}]}"#;
    let with_policy = resolve_config(&manifest, &ConfigRequest::new().action_policy(allow));
    let plain = resolve_config(&manifest, &ConfigRequest::new());
    let (with_policy, plain) = (with_policy.snapshot().unwrap(), plain.snapshot().unwrap());
    assert_eq!(with_policy.detection_digest(), plain.detection_digest());
    assert_ne!(with_policy.digest(), plain.digest());
    assert!(with_policy.enabled_ids().eq(plain.enabled_ids()));

    // The same bytes always give the same policy identity; any byte differs.
    let spaced = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"a","match":{"type":["github_token"]},"action":"allow"} ]}"#;
    let again = resolve_config(&manifest, &ConfigRequest::new().action_policy(allow));
    let other = resolve_config(&manifest, &ConfigRequest::new().action_policy(spaced));
    assert_eq!(again.snapshot().unwrap().digest(), with_policy.digest());
    assert_ne!(other.snapshot().unwrap().digest(), with_policy.digest());
}

#[test]
fn rulesets_change_the_detection_digest_and_their_identity_stays_out_unless_asked() {
    let manifest = manifest("full");
    let ruleset = b"ruleset-revision: 1\ndetector: acme-internal-token\nspecificity: contextual\nprefix: \"ACME_\"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n";
    let with = resolve_config(&manifest, &ConfigRequest::new().ruleset(ruleset));
    let disclosed = resolve_config(
        &manifest,
        &ConfigRequest::new()
            .ruleset(ruleset)
            .disclose_ruleset_identity(),
    );
    let plain = resolve_config(&manifest, &ConfigRequest::new());
    assert_ne!(
        with.snapshot().unwrap().detection_digest(),
        plain.snapshot().unwrap().detection_digest()
    );
    // The detection identity does not depend on whether the identity is shown.
    assert_eq!(
        with.snapshot().unwrap().detection_digest(),
        disclosed.snapshot().unwrap().detection_digest()
    );
    assert!(!with.as_json().contains("acme-internal-token"));
    assert!(disclosed.as_json().contains("acme-internal-token"));
}

#[test]
fn a_rejected_request_never_echoes_the_text_it_was_given() {
    let manifest = manifest("full");
    let secretish = "SYNTHETICUNKNOWNDETECTORID000000";
    for config in [
        format!(r#"{{"detection":{{"include":["{secretish}"]}}}}"#),
        format!(r#"{{"{secretish}":1}}"#),
        format!(r#"{{"pii":["{secretish}"]}}"#),
        format!(r#"{{"schema":"{secretish}"}}"#),
        format!(r#"{{"limits":{{"{secretish}":1}}}}"#),
        format!(r#"{{"detection":{{"include":["a"]}}, {secretish}"#),
    ] {
        let resolution = resolve_config(&manifest, &ConfigRequest::new().runtime_config(&config));
        assert!(!resolution.is_ok(), "{config}");
        assert!(!resolution.as_json().contains(secretish), "{config}");
        assert!(
            !format!("{resolution:?}")
                .to_lowercase()
                .contains("synthetic"),
            "{config}"
        );
    }
}

#[test]
fn an_oversized_document_is_refused_before_parsing() {
    let manifest = manifest("full");
    let big = format!(
        "{{\"detection\":{{\"include\":[{}]}}}}",
        "\"jwt\",".repeat(60_000)
    );
    assert!(big.len() > 262_144);
    let resolution = resolve_config(&manifest, &ConfigRequest::new().runtime_config(&big));
    assert!(!resolution.is_ok());
    assert_eq!(resolution.diagnostics()[0].code(), "WRONG_TYPE");
}

#[test]
fn selection_on_an_artifact_without_the_capability_is_unsupported_not_ignored() {
    for kind in [ArtifactKind::PythonWheel, ArtifactKind::Cli] {
        let manifest = ArtifactManifest::full(kind, true, None).unwrap();
        assert!(!manifest.detector_selection());
        let resolution = resolve_config(
            &manifest,
            &ConfigRequest::new().runtime_config(r#"{"detection":{"include":["jwt"]}}"#),
        );
        let codes: Vec<&str> = resolution
            .diagnostics()
            .iter()
            .map(ConfigDiagnostic::code)
            .collect();
        assert_eq!(codes, ["DETECTION_SELECTION_UNSUPPORTED"]);
        assert!(!resolution.is_ok());
        // `{}` asks for nothing, so it still resolves.
        assert!(
            resolve_config(
                &manifest,
                &ConfigRequest::new().runtime_config(r#"{"detection":{}}"#)
            )
            .is_ok()
        );
    }
    for kind in [
        ArtifactKind::RustRegistry,
        ArtifactKind::NodeAddon,
        ArtifactKind::Wasm,
    ] {
        assert!(
            ArtifactManifest::full(kind, true, None)
                .unwrap()
                .detector_selection()
        );
    }
}

#[test]
fn pii_the_artifact_lacks_is_unavailable_not_silently_dropped() {
    let no_pii = ArtifactManifest::full(ArtifactKind::Wasm, false, None).unwrap();
    let resolution = resolve_config(
        &no_pii,
        &ConfigRequest::new().runtime_config(r#"{"pii":["pii:global"]}"#),
    );
    assert_eq!(
        resolution.diagnostics()[0].code(),
        "PII_SELECTOR_UNAVAILABLE"
    );
    assert!(!resolution.is_ok());
    // Off is always available.
    assert!(
        resolve_config(
            &no_pii,
            &ConfigRequest::new().runtime_config(r#"{"pii":[]}"#)
        )
        .is_ok()
    );
    let with_pii = manifest("full");
    let resolution = resolve_config(
        &with_pii,
        &ConfigRequest::new().runtime_config(r#"{"pii":["pii:global","pii"]}"#),
    );
    let snapshot: Value = serde_json::from_str(resolution.snapshot().unwrap().as_json()).unwrap();
    assert_eq!(
        snapshot["pii"]["selectors"],
        serde_json::json!(["pii:global"])
    );
    assert!(
        snapshot["pii"]["activation"]
            .as_str()
            .unwrap()
            .contains("selectors=pii:global")
    );
}

#[test]
fn describing_a_registry_reports_what_it_holds_and_changes_nothing() {
    let manifest = manifest("full");
    let registry = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::exclude(["github-token"]))
        .unwrap();
    let before: Vec<String> = registry.ids().map(str::to_owned).collect();
    let described = describe_config(&manifest, &registry);
    assert_eq!(
        registry.ids().map(str::to_owned).collect::<Vec<_>>(),
        before
    );
    assert!(!described.enabled_ids().any(|id| id == "github-token"));
    let json: Value = serde_json::from_str(described.as_json()).unwrap();
    assert_eq!(json["detection"]["mode"], "exclude");
    assert_eq!(
        json["detection"]["disabled"],
        serde_json::json!(["github-token"])
    );
    assert_eq!(json["owners"]["detection"], "registry");
    assert_eq!(json["effects"]["overlapOutcomesMayChange"], true);

    // It equals what resolving the same request says.
    let resolved = resolve_config(
        &manifest,
        &ConfigRequest::new().runtime_config(r#"{"detection":{"exclude":["github-token"]}}"#),
    );
    assert_eq!(
        resolved.snapshot().unwrap().detection_digest(),
        described.detection_digest()
    );

    let email = PiiSelection::parse(&["pii:family:global:email"]).unwrap();
    let with_pii = DetectorRegistry::with_built_in_and_pii(&email).unwrap();
    let json: Value =
        serde_json::from_str(describe_config(&manifest, &with_pii).as_json()).unwrap();
    assert_eq!(
        json["pii"]["selectors"],
        serde_json::json!(["pii:family:global:email"])
    );
}

#[test]
fn resolution_is_pure_the_same_request_gives_the_same_bytes() {
    let manifest = manifest("full");
    let request = ConfigRequest::new()
        .runtime_config(r#"{"detection":{"exclude":["jwt"]},"limits":{"maxFindings":5}}"#);
    assert_eq!(
        resolve_config(&manifest, &request).as_json(),
        resolve_config(&manifest, &request).as_json()
    );
}
