//! Effective configuration: the detector-id selection and the pure
//! `resolve_config` / `describe_config` that explain it (issue #1251,
//! `decision-define-detector-id-selection-and-configuration-replacement-precedence`
//! and `decision-define-the-artifact-manifest-and-configuration-data-contracts`).
//!
//! # Two things, kept apart
//!
//! - A [`DetectionSelection`] chooses which of an artifact's **included**
//!   built-in detectors are **enabled**. It acts when a registry is composed
//!   ([`DetectorRegistry::with_detection`](crate::DetectorRegistry::with_detection)),
//!   before the shared prefilter, candidate collection and overlap
//!   resolution, so a disabled detector is not constructed, not prefiltered,
//!   no overlap competitor and no retention input.
//! - [`resolve_config`] and [`describe_config`] are **data**: they read an
//!   [`ArtifactManifest`] and explicit input, scan nothing, build no
//!   registry, initialize nothing and hold nothing. A [`ConfigSnapshot`]
//!   cannot scan.
//!
//! # The truth table
//!
//! There are two layers and no third: the artifact's build defaults, then the
//! runtime input. This module is the one place the table is implemented; the
//! bindings forward to it and keep no copy.
//!
//! | Key | Absent | Explicit empty | Explicit value |
//! | --- | --- | --- | --- |
//! | `detection.include` | all included enabled | no built-in enabled | exactly the list |
//! | `detection.exclude` | none excluded | same as absent | every included detector but the list |
//! | `pii` | off | off | the canonical selector set |
//! | `ruleset` | none | not expressible | adds the ruleset's detectors |
//! | `actionPolicy` | the artifact's default evaluation | `rules: []` is the base | replaces the whole document |
//! | `limits.*` | artifact default | zero is rejected | replaces that field only |
//! | callback `policy` | none | n/a | replaces the default; with `actionPolicy` is `INVALID_OPTIONS` |
//!
//! Arrays replace and are never unioned or concatenated, a policy document
//! replaces the document and its rules are never merged, and an action
//! (including `allow`) never enables or disables a detector.

use crate::action_policy::load_action_policy;
use crate::detectors::built_in_ids;
use crate::error::SecretScanErrorCode;
use crate::json::{self, Value};
use crate::limits::{DEFAULT_MAX_FINDINGS, DEFAULT_MAX_INPUT_BYTES};
use crate::manifest::{ArtifactKind, ArtifactManifest};
use crate::pii::{PiiSelection, is_reserved_detector_id};
use crate::registry::DetectorRegistry;
use crate::ruleset::load_ruleset;
use crate::selection::{
    CLASS_UNKNOWN_FIELD, CLASS_UNSUPPORTED, CLASS_WRONG_TYPE, DetectionSelection, PII_ADAPTER_ID,
    selection_from_value,
};
use crate::sha256::{sha256, to_hex};
use crate::types::is_identifier;
use std::fmt::{self, Write as _};

/// The most diagnostics one resolution reports.
const DIAGNOSTICS_MAX: usize = 256;
/// The largest `runtime-config/v1` document, checked before parsing.
const RUNTIME_CONFIG_BYTES_MAX: usize = 262_144;
/// The largest limit value every binding can carry (`u32`).
const LIMIT_MAX: u64 = 0xffff_ffff;

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// How serious a [`ConfigDiagnostic`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigSeverity {
    /// The input cannot be resolved.
    Error,
    /// The input resolves, and something deserves attention.
    Warning,
    /// A consequence worth knowing.
    Info,
}

impl ConfigSeverity {
    /// `error`, `warning` or `info`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

/// One safe finding about a configuration input (`config-diagnostics/v1`).
///
/// `path` is a fixed-syntax pointer such as `detection.include[3]`; an
/// unknown member is addressed by its position (`detection.@1`), never its
/// name. `id` is only ever a canonical detector id from the catalog. No
/// input string is echoed: a user can paste a secret where an id belongs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigDiagnostic {
    code: &'static str,
    severity: ConfigSeverity,
    path: String,
    id: Option<&'static str>,
}

impl ConfigDiagnostic {
    /// The fixed code, for example `UNKNOWN_DETECTOR_ID`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The severity.
    #[must_use]
    pub const fn severity(&self) -> ConfigSeverity {
        self.severity
    }

    /// The pointer to the offending part of the input.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The canonical detector id this concerns, when it concerns one.
    #[must_use]
    pub const fn id(&self) -> Option<&'static str> {
        self.id
    }
}

#[derive(Default)]
struct Diagnostics {
    items: Vec<ConfigDiagnostic>,
}

impl Diagnostics {
    fn push(&mut self, severity: ConfigSeverity, code: &'static str, path: &str) {
        self.items.push(ConfigDiagnostic {
            code,
            severity,
            path: path.to_owned(),
            id: None,
        });
    }

    fn error(&mut self, code: &'static str, path: &str) {
        self.push(ConfigSeverity::Error, code, path);
    }

    fn has_error(&self) -> bool {
        self.items
            .iter()
            .any(|item| item.severity == ConfigSeverity::Error)
    }

    /// Errors first, then warnings, then notes, each in document order; at
    /// most [`DIAGNOSTICS_MAX`].
    fn finish(self) -> (Vec<ConfigDiagnostic>, bool) {
        let mut ordered = Vec::with_capacity(self.items.len().min(DIAGNOSTICS_MAX));
        let mut seen = 0;
        for severity in [
            ConfigSeverity::Error,
            ConfigSeverity::Warning,
            ConfigSeverity::Info,
        ] {
            for item in self.items.iter().filter(|item| item.severity == severity) {
                seen += 1;
                if ordered.len() < DIAGNOSTICS_MAX {
                    ordered.push(item.clone());
                }
            }
        }
        (ordered, seen > DIAGNOSTICS_MAX)
    }
}

// ---------------------------------------------------------------------------
// The request and the result
// ---------------------------------------------------------------------------

/// What to resolve: explicit runtime input over the artifact's defaults.
///
/// The input is `runtime-config/v1` text for the members that are data
/// (`schema`, `detection`, `pii`, `limits`) plus the exact bytes of the two
/// documents a binding already receives as bytes (`ruleset`, `actionPolicy`),
/// so the policy identity is the digest of the bytes a call would load. A
/// callback is not data: it is only recorded as present.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigRequest<'a> {
    runtime_config: Option<&'a str>,
    ruleset: Option<&'a [u8]>,
    action_policy: Option<&'a [u8]>,
    callback: bool,
    disclose_ruleset: bool,
}

impl<'a> ConfigRequest<'a> {
    /// An empty request: nothing given, so every key inherits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            runtime_config: None,
            ruleset: None,
            action_policy: None,
            callback: false,
            disclose_ruleset: false,
        }
    }

    /// The `runtime-config/v1` document: at most 262,144 bytes, with the
    /// members `schema`, `detection`, `pii` and `limits`.
    #[must_use]
    pub const fn runtime_config(mut self, json: &'a str) -> Self {
        self.runtime_config = Some(json);
        self
    }

    /// The exact bytes of a declarative ruleset.
    #[must_use]
    pub const fn ruleset(mut self, bytes: &'a [u8]) -> Self {
        self.ruleset = Some(bytes);
        self
    }

    /// The exact bytes of an action policy document.
    #[must_use]
    pub const fn action_policy(mut self, bytes: &'a [u8]) -> Self {
        self.action_policy = Some(bytes);
        self
    }

    /// A callback policy is in force. It is reported as a dynamic reference
    /// without content.
    #[must_use]
    pub const fn callback_policy(mut self) -> Self {
        self.callback = true;
        self
    }

    /// Includes the ruleset's detector ids and byte digest in the snapshot.
    /// Off by default: a ruleset's identity can be sensitive, and the
    /// snapshot's `detectionDigest` already says whether two detections are
    /// the same.
    #[must_use]
    pub const fn disclose_ruleset_identity(mut self) -> Self {
        self.disclose_ruleset = true;
        self
    }
}

/// The resolved, effective configuration (`config-snapshot/v1`): immutable
/// data. It is not a handle and cannot scan.
///
/// The snapshot holds ids, counts, digests and fixed words. It never holds an
/// input byte, a ruleset body or a rule's pattern, a matched value or a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigSnapshot {
    json: String,
    digest: String,
    detection_digest: String,
    enabled: Vec<String>,
    inert: bool,
}

impl ConfigSnapshot {
    /// The document: UTF-8 JSON with `schema` first, every other member at
    /// every depth in bytewise order, no whitespace.
    #[must_use]
    pub fn as_json(&self) -> &str {
        &self.json
    }

    /// `sha256:` over the canonical JSON of the snapshot without `digest`
    /// (all members, `schema` included, in bytewise order).
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// `sha256:` over the canonical `{ manifestDigest, enabled, ruleset digest,
    /// PII activation }`: equal digests mean the same detection.
    #[must_use]
    pub fn detection_digest(&self) -> &str {
        &self.detection_digest
    }

    /// The enabled built-in detector ids, in canonical order.
    pub fn enabled_ids(&self) -> impl Iterator<Item = &str> {
        self.enabled.iter().map(String::as_str)
    }

    /// Whether nothing at all is enabled (no built-in detector, no ruleset,
    /// PII off). Binding such a configuration to a scan owner fails with
    /// `EMPTY_DETECTION_SET`; describing it succeeds.
    #[must_use]
    pub const fn is_inert(&self) -> bool {
        self.inert
    }
}

/// The result of [`resolve_config`] (`config-resolution/v1`): the snapshot
/// when the input is valid, and every safe diagnostic either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigResolution {
    json: String,
    snapshot: Option<ConfigSnapshot>,
    diagnostics: Vec<ConfigDiagnostic>,
}

impl ConfigResolution {
    /// The envelope `{ schema, ok, snapshot, diagnostics }` as UTF-8 JSON,
    /// `schema` first. `snapshot` is `null` when `ok` is false.
    #[must_use]
    pub fn as_json(&self) -> &str {
        &self.json
    }

    /// Whether the input resolved without an error.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.snapshot.is_some()
    }

    /// The snapshot, `None` when the input was rejected.
    #[must_use]
    pub const fn snapshot(&self) -> Option<&ConfigSnapshot> {
        self.snapshot.as_ref()
    }

    /// Every diagnostic: errors first, then in document order, at most 256.
    #[must_use]
    pub fn diagnostics(&self) -> &[ConfigDiagnostic] {
        &self.diagnostics
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// The effective values the snapshot is built from.
struct Effective<'a> {
    detection_mode: &'static str,
    detection_origin: &'static str,
    enabled: Vec<&'a str>,
    custom_detectors: usize,
    pii: PiiSelection,
    pii_origin: &'static str,
    ruleset: Option<RulesetFacts>,
    policy: PolicyFacts,
    policy_origin: &'static str,
    max_input_bytes: usize,
    max_input_origin: &'static str,
    max_findings: usize,
    max_findings_origin: &'static str,
}

struct RulesetFacts {
    detector_ids: Vec<String>,
    digest: String,
}

enum PolicyFacts {
    Default,
    Document { digest: String, rule_count: usize },
    Callback,
}

/// Resolves explicit runtime input over `manifest`'s build defaults into an
/// immutable [`ConfigSnapshot`], with no hidden concatenation and no silent
/// fallback.
///
/// Invalid input is data, never a panic or an error value to unwrap: the
/// returned [`ConfigResolution`] says `ok = false`, holds no snapshot and lists
/// every problem, so a tool can show them all. It reads no file, network or
/// environment value, scans nothing, builds no registry and changes no
/// owner. Nothing in the request is hashed except the two policy documents'
/// own bytes, which are configuration and never a secret.
///
/// A request for something above the artifact's ceiling (a detector it does
/// not include, a PII family it lacks, detector selection on an artifact
/// without that capability) is rejected with a coded diagnostic, never
/// ignored and never satisfied by another artifact.
#[must_use]
pub fn resolve_config(
    manifest: &ArtifactManifest,
    request: &ConfigRequest<'_>,
) -> ConfigResolution {
    let mut diagnostics = Diagnostics::default();
    let document = read_document(request, &mut diagnostics);
    let member = |name: &str| document.as_ref().and_then(|value| value.member(name));

    // Sections are judged in a fixed order, so the diagnostics' order does not
    // depend on the order of the document's members.
    let (selection, detection_given, enabled) =
        resolve_detection(member("detection"), manifest, &mut diagnostics);
    let (pii, pii_given) = resolve_pii(manifest, member("pii"), &mut diagnostics);
    let (limit_input, limit_findings) = read_limits(member("limits"), &mut diagnostics);
    let ruleset = request
        .ruleset
        .and_then(|bytes| resolve_ruleset(bytes, &mut diagnostics));
    let (policy, policy_given) = resolve_policy(request, &mut diagnostics);

    if diagnostics.has_error() {
        let (items, truncated) = diagnostics.finish();
        return envelope(None, items, truncated);
    }

    let effective = Effective {
        detection_mode: selection.mode(),
        detection_origin: origin(detection_given),
        custom_detectors: 0,
        pii,
        pii_origin: origin(pii_given),
        ruleset,
        policy,
        policy_origin: origin(policy_given),
        max_input_bytes: limit_input.unwrap_or(DEFAULT_MAX_INPUT_BYTES),
        max_input_origin: origin(limit_input.is_some()),
        max_findings: limit_findings.unwrap_or(DEFAULT_MAX_FINDINGS),
        max_findings_origin: origin(limit_findings.is_some()),
        enabled,
    };

    let snapshot = build_snapshot(manifest, &effective, request.disclose_ruleset);
    advise(manifest, &effective, &mut diagnostics);
    let (items, truncated) = diagnostics.finish();
    envelope(Some(snapshot), items, truncated)
}

/// Parses the `runtime-config/v1` text and judges its top level: size, shape,
/// member names and `schema`. Returns the document when it is an object.
#[inline(never)]
fn read_document(request: &ConfigRequest<'_>, diagnostics: &mut Diagnostics) -> Option<Value> {
    let text = request.runtime_config?;
    if text.len() > RUNTIME_CONFIG_BYTES_MAX {
        diagnostics.error(CLASS_WRONG_TYPE, "$");
        return None;
    }
    let Some(document) = json::parse(text) else {
        diagnostics.error(CLASS_WRONG_TYPE, "$");
        return None;
    };
    let Value::Object(members) = &document else {
        diagnostics.error(CLASS_WRONG_TYPE, "$");
        return None;
    };
    for (position, (name, _)) in members.iter().enumerate() {
        if !matches!(name.as_str(), "schema" | "detection" | "pii" | "limits") {
            diagnostics.error(CLASS_UNKNOWN_FIELD, &format!("@{position}"));
        }
    }
    match document.member("schema") {
        None => {}
        Some(Value::Str(name)) if name == "runtime-config/v1" => {}
        Some(Value::Str(_)) => diagnostics.error("UNKNOWN_SCHEMA", "schema"),
        Some(_) => diagnostics.error(CLASS_WRONG_TYPE, "schema"),
    }
    Some(document)
}

/// The `detection` row of the truth table: absent inherits every included
/// detector; a value replaces. Returns the parsed selection, whether the
/// document gave one, and the enabled ids in canonical order.
#[inline(never)]
fn resolve_detection<'a>(
    value: Option<&Value>,
    manifest: &'a ArtifactManifest,
    diagnostics: &mut Diagnostics,
) -> (DetectionSelection, bool, Vec<&'a str>) {
    let included: Vec<&str> = manifest.detector_ids().collect();
    let Some(value) = value else {
        return (DetectionSelection::all(), false, included);
    };
    let selection = match selection_from_value(value) {
        Ok(selection) => selection,
        Err(fault) => {
            diagnostics.error(fault.class, &fault.path());
            return (DetectionSelection::all(), true, included);
        }
    };
    // Step 4: an artifact without the capability cannot take a selection.
    // `{}` asks for nothing.
    if !selection.is_all() && !manifest.detector_selection() {
        diagnostics.error(CLASS_UNSUPPORTED, "detection");
        return (DetectionSelection::all(), true, included);
    }
    match selection.enabled_of(&included) {
        Ok(enabled) => (selection, true, enabled),
        Err(fault) => {
            diagnostics.error(fault.class, &fault.path());
            (DetectionSelection::all(), true, included)
        }
    }
}

/// The `limits` row: each scalar inherits independently; zero, a fraction or
/// a value no binding can carry is rejected.
#[inline(never)]
fn read_limits(
    value: Option<&Value>,
    diagnostics: &mut Diagnostics,
) -> (Option<usize>, Option<usize>) {
    let mut input = None;
    let mut findings = None;
    let Some(value) = value else {
        return (input, findings);
    };
    let Value::Object(members) = value else {
        diagnostics.error(CLASS_WRONG_TYPE, "limits");
        return (input, findings);
    };
    for (position, (name, member)) in members.iter().enumerate() {
        let (slot, path) = match name.as_str() {
            "maxInputBytes" => (&mut input, "limits.maxInputBytes"),
            "maxFindings" => (&mut findings, "limits.maxFindings"),
            _ => {
                diagnostics.error(CLASS_UNKNOWN_FIELD, &format!("limits.@{position}"));
                continue;
            }
        };
        match member {
            Value::Int(number) if (1..=LIMIT_MAX).contains(number) => {
                *slot = usize::try_from(*number).ok();
            }
            Value::Int(_) | Value::Other => diagnostics.error("INVALID_LIMITS", path),
            _ => diagnostics.error(CLASS_WRONG_TYPE, path),
        }
    }
    (input, findings)
}

/// The `pii` row: absent and explicit empty are both off; a list replaces.
#[inline(never)]
fn resolve_pii(
    manifest: &ArtifactManifest,
    value: Option<&Value>,
    diagnostics: &mut Diagnostics,
) -> (PiiSelection, bool) {
    let Some(value) = value else {
        return (PiiSelection::default(), false);
    };
    let Value::Array(items) = value else {
        diagnostics.error(CLASS_WRONG_TYPE, "pii");
        return (PiiSelection::default(), true);
    };
    let mut selectors: Vec<&str> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Value::Str(selector) = item else {
            diagnostics.error(CLASS_WRONG_TYPE, &format!("pii[{index}]"));
            return (PiiSelection::default(), true);
        };
        selectors.push(selector);
    }
    match PiiSelection::parse(&selectors) {
        Ok(selection) => {
            if !selection.is_off() && !manifest.pii_linked() {
                diagnostics.error("PII_SELECTOR_UNAVAILABLE", "pii");
            }
            (selection, true)
        }
        Err(error) => {
            let code = match error.code() {
                SecretScanErrorCode::PiiSelectorInvalid => "PII_SELECTOR_INVALID",
                SecretScanErrorCode::PiiSelectorUnsupported => "PII_SELECTOR_UNSUPPORTED",
                _ => "PII_SELECTOR_UNAVAILABLE",
            };
            diagnostics.error(code, "pii");
            (PiiSelection::default(), true)
        }
    }
}

#[inline(never)]
fn resolve_ruleset(bytes: &[u8], diagnostics: &mut Diagnostics) -> Option<RulesetFacts> {
    let Ok(detectors) = load_ruleset(bytes) else {
        diagnostics.error("INVALID_RULESET", "ruleset");
        return None;
    };
    let ids: Vec<String> = detectors
        .iter()
        .map(|detector| detector.id().to_owned())
        .collect();
    // The ids a registry would refuse: a built-in or PII id, or a repeat.
    let refused = ids.iter().enumerate().any(|(index, id)| {
        !is_identifier(id)
            || is_reserved_detector_id(id)
            || built_in_ids().any(|known| known == id)
            || ids[..index].contains(id)
    });
    if refused {
        diagnostics.error("INVALID_RULESET", "ruleset");
        return None;
    }
    Some(RulesetFacts {
        detector_ids: ids,
        digest: format!("sha256:{}", to_hex(&sha256(bytes))),
    })
}

#[inline(never)]
fn resolve_policy(
    request: &ConfigRequest<'_>,
    diagnostics: &mut Diagnostics,
) -> (PolicyFacts, bool) {
    match (request.action_policy, request.callback) {
        (Some(_), true) => {
            diagnostics.error("INVALID_OPTIONS", "actionPolicy");
            (PolicyFacts::Default, true)
        }
        (Some(bytes), false) => match load_action_policy(bytes) {
            Ok(policy) => (
                PolicyFacts::Document {
                    digest: format!("sha256:{}", policy.document_sha256_hex()),
                    rule_count: policy.rule_count(),
                },
                true,
            ),
            Err(error) => {
                let path = error.rule_index().map_or_else(
                    || "actionPolicy".to_owned(),
                    |index| format!("actionPolicy.rules[{index}]"),
                );
                diagnostics.error("INVALID_ACTION_POLICY", &path);
                (PolicyFacts::Default, true)
            }
        },
        (None, true) => (PolicyFacts::Callback, true),
        (None, false) => (PolicyFacts::Default, false),
    }
}

/// The warnings and notes that need the resolved facts.
#[inline(never)]
fn advise(manifest: &ArtifactManifest, effective: &Effective<'_>, diagnostics: &mut Diagnostics) {
    if effective.enabled.is_empty() {
        diagnostics.push(
            ConfigSeverity::Warning,
            "NO_BUILT_IN_DETECTORS",
            "detection",
        );
    }
    if effective.enabled.len() < manifest.detector_ids().count() {
        diagnostics.push(
            ConfigSeverity::Info,
            "OVERLAP_OUTCOMES_MAY_CHANGE",
            "detection",
        );
    }
}

fn owner_word(manifest: &ArtifactManifest) -> &'static str {
    match manifest.kind() {
        ArtifactKind::RustRegistry => "registry",
        _ => "initialize",
    }
}

const fn origin(given: bool) -> &'static str {
    if given { "runtime" } else { "artifact-default" }
}

/// `sha256:` and the lowercase hex of the digest of `text`.
fn sha256_text(text: &str) -> String {
    format!("sha256:{}", to_hex(&sha256(text.as_bytes())))
}

// The documents below are rendered with `format!` rather than a JSON writer:
// every string they hold is a fixed word, a catalog id, a validated
// identifier, a selector or a digest, none of which needs escaping, and a
// format string is data, where a writer is code that ships in every
// WebAssembly artifact. Every object's members are written in bytewise order,
// which is the canonical form a digest is taken over.

/// A JSON array of strings.
struct Strs<'a>(&'a [&'a str]);

impl fmt::Display for Strs<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[")?;
        for (index, item) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "\"{item}\"")?;
        }
        formatter.write_str("]")
    }
}

/// A JSON string, or `null`.
struct OptStr<'a>(Option<&'a str>);

impl fmt::Display for OptStr<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(text) => write!(formatter, "\"{text}\""),
            None => formatter.write_str("null"),
        }
    }
}

/// A JSON integer, or `null`.
struct OptInt(Option<usize>);

impl fmt::Display for OptInt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(number) => write!(formatter, "{number}"),
            None => formatter.write_str("null"),
        }
    }
}

/// Everything a snapshot document states, borrowed, so the same facts render
/// twice: once as the canonical form a digest is taken over and once as the
/// emitted document.
struct SnapshotFacts<'a> {
    manifest: &'a ArtifactManifest,
    effective: &'a Effective<'a>,
    disclose_ruleset: bool,
    activation: &'a str,
    disabled: &'a [&'a str],
    detection_digest: &'a str,
    inert: bool,
}

impl SnapshotFacts<'_> {
    /// Renders the snapshot. The canonical form (`digest` absent, `schema` in
    /// its bytewise place) is what the digest is taken over; the emitted form
    /// (`schema_first`, with `digest` between `detectionDigest` and `effects`)
    /// is the document.
    #[allow(
        clippy::too_many_lines,
        reason = "one format string states the whole document in bytewise order; splitting it would scatter that order"
    )]
    fn render(&self, schema_first: bool, digest: Option<&str>) -> String {
        const SCHEMA: &str = "\"schema\":\"config-snapshot/v1\"";
        let manifest = self.manifest;
        let effective = self.effective;
        let head = if schema_first {
            format!("{SCHEMA},")
        } else {
            String::new()
        };
        let tail = if schema_first {
            String::new()
        } else {
            format!(",{SCHEMA}")
        };
        let digest_member =
            digest.map_or_else(String::new, |digest| format!("\"digest\":\"{digest}\","));

        let (policy_source, policy_digest, policy_rules) = match &effective.policy {
            PolicyFacts::Default => ("default", None, None),
            PolicyFacts::Document { digest, rule_count } => {
                ("document", Some(digest.as_str()), Some(*rule_count))
            }
            PolicyFacts::Callback => ("callback", None, None),
        };
        let policy_revision = policy_rules.map(|_| 1);
        let explainable = !matches!(effective.policy, PolicyFacts::Callback);

        let compiled = manifest.detector_ids().count();
        let unavailable: Vec<&str> = manifest.not_included_ids().collect();
        let families: Vec<&str> = effective
            .pii
            .families()
            .iter()
            .map(String::as_str)
            .collect();
        let selectors: Vec<&str> = effective
            .pii
            .selectors()
            .iter()
            .map(String::as_str)
            .collect();
        let owner = owner_word(manifest);

        let ruleset = effective.ruleset.as_ref();
        let rs_ids: Vec<&str> = ruleset
            .filter(|_| self.disclose_ruleset)
            .map(|facts| facts.detector_ids.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let rs_ids_json = if ruleset.is_some() && self.disclose_ruleset {
            Strs(&rs_ids).to_string()
        } else {
            "null".to_owned()
        };
        let rs_digest = ruleset
            .filter(|_| self.disclose_ruleset)
            .map(|facts| facts.digest.as_str());
        let rs_count = ruleset.map(|facts| facts.detector_ids.len());
        let rs_present = ruleset.is_some();
        let rs_disclosed = rs_present && self.disclose_ruleset;
        let rs_revision = rs_count.map(|_| 1);

        let enabled = Strs(&effective.enabled);
        let disabled = Strs(self.disabled);
        let unavailable = Strs(&unavailable);
        let families = Strs(&families);
        let selectors = Strs(&selectors);
        let policy_digest = OptStr(policy_digest);
        let policy_rules = OptInt(policy_rules);
        let policy_revision = OptInt(policy_revision);
        let rs_digest = OptStr(rs_digest);
        let rs_count = OptInt(rs_count);
        let rs_revision = OptInt(rs_revision);
        let kind = manifest.kind().as_str();
        let manifest_digest = manifest.digest();
        let profile = manifest.profile().as_str();
        let version = crate::VERSION;
        let custom = effective.custom_detectors;
        let enabled_count = effective.enabled.len();
        let mode = effective.detection_mode;
        let detection_digest = self.detection_digest;
        let inert = self.inert;
        let overlap = !self.disabled.is_empty();
        let max_findings = effective.max_findings;
        let max_input = effective.max_input_bytes;
        let origin_policy = effective.policy_origin;
        let origin_detection = effective.detection_origin;
        let origin_findings = effective.max_findings_origin;
        let origin_input = effective.max_input_origin;
        let origin_pii = effective.pii_origin;
        let origin_ruleset = origin(rs_present);
        let activation = self.activation;
        let pii_available = manifest.pii_linked();

        format!(
            "{{{head}\"actionPolicy\":{{\"digest\":{policy_digest},\"explainable\":{explainable},\
             \"revision\":{policy_revision},\"ruleCount\":{policy_rules},\"source\":\"{policy_source}\"}},\
             \"artifact\":{{\"compositionId\":null,\"kind\":\"{kind}\",\"manifestDigest\":\"{manifest_digest}\",\
             \"profile\":\"{profile}\",\"version\":\"{version}\"}},\
             \"detection\":{{\"compiledCount\":{compiled},\"customDetectors\":{custom},\"disabled\":{disabled},\
             \"enabled\":{enabled},\"enabledCount\":{enabled_count},\"mode\":\"{mode}\",\"unavailable\":{unavailable}}},\
             \"detectionDigest\":\"{detection_digest}\",{digest_member}\
             \"effects\":{{\"inert\":{inert},\"overlapOutcomesMayChange\":{overlap}}},\
             \"limits\":{{\"maxFindings\":{max_findings},\"maxInputBytes\":{max_input}}},\
             \"origins\":{{\"actionPolicy\":\"{origin_policy}\",\"detection\":\"{origin_detection}\",\
             \"maxFindings\":\"{origin_findings}\",\"maxInputBytes\":\"{origin_input}\",\"pii\":\"{origin_pii}\",\
             \"ruleset\":\"{origin_ruleset}\"}},\
             \"owners\":{{\"actionPolicy\":\"call\",\"detection\":\"{owner}\",\"incremental\":\"session\",\
             \"limits\":\"call\",\"pii\":\"{owner}\",\"ruleset\":\"call\"}},\
             \"pii\":{{\"activation\":\"{activation}\",\"available\":{pii_available},\"families\":{families},\
             \"selectors\":{selectors}}},\
             \"ruleset\":{{\"detectorCount\":{rs_count},\"detectorIds\":{rs_ids_json},\"digest\":{rs_digest},\
             \"disclosed\":{rs_disclosed},\"present\":{rs_present},\"revision\":{rs_revision}}}{tail}}}"
        )
    }
}

fn build_snapshot(
    manifest: &ArtifactManifest,
    effective: &Effective<'_>,
    disclose_ruleset: bool,
) -> ConfigSnapshot {
    let disabled: Vec<&str> = manifest
        .detector_ids()
        .filter(|id| !effective.enabled.contains(id))
        .collect();
    let activation = effective.pii.activation_identity(manifest.profile());
    let inert = effective.enabled.is_empty()
        && effective.ruleset.is_none()
        && effective.pii.is_off()
        && effective.custom_detectors == 0;

    // What makes two detections the same: the artifact, the enabled
    // detectors, the ruleset's bytes and the PII activation.
    let detection_digest = {
        let enabled = Strs(&effective.enabled);
        let manifest_digest = manifest.digest();
        let ruleset_digest = OptStr(
            effective
                .ruleset
                .as_ref()
                .map(|facts| facts.digest.as_str()),
        );
        sha256_text(&format!(
            "{{\"enabled\":{enabled},\"manifestDigest\":\"{manifest_digest}\",\
             \"piiActivation\":\"{activation}\",\"rulesetDigest\":{ruleset_digest}}}"
        ))
    };

    let facts = SnapshotFacts {
        manifest,
        effective,
        disclose_ruleset,
        activation: &activation,
        disabled: &disabled,
        detection_digest: &detection_digest,
        inert,
    };
    // The digest is over the canonical form without `digest`; the document
    // that is emitted carries it, with `schema` first.
    let digest = sha256_text(&facts.render(false, None));
    let json = facts.render(true, Some(&digest));
    ConfigSnapshot {
        json,
        digest,
        detection_digest,
        enabled: effective
            .enabled
            .iter()
            .map(|id| (*id).to_owned())
            .collect(),
        inert,
    }
}

fn envelope(
    snapshot: Option<ConfigSnapshot>,
    items: Vec<ConfigDiagnostic>,
    truncated: bool,
) -> ConfigResolution {
    let mut rendered = String::new();
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            rendered.push(',');
        }
        let (code, path, severity) = (item.code, &item.path, item.severity.as_str());
        let id = OptStr(item.id);
        // `path` is fixed syntax: letters, digits and `.@[]$` only.
        let _ = write!(
            rendered,
            "{{\"code\":\"{code}\",\"id\":{id},\"path\":\"{path}\",\"severity\":\"{severity}\"}}"
        );
    }
    let ok = snapshot.is_some();
    // The snapshot is spliced in as already-rendered JSON so its member order
    // and digest are exactly what its own accessors report.
    let snapshot_json = snapshot
        .as_ref()
        .map_or("null", |snapshot| snapshot.json.as_str());
    let json = format!(
        "{{\"schema\":\"config-resolution/v1\",\"diagnostics\":{{\"schema\":\"config-diagnostics/v1\",\
         \"items\":[{rendered}],\"truncated\":{truncated}}},\"ok\":{ok},\"snapshot\":{snapshot_json}}}"
    );
    ConfigResolution {
        json,
        snapshot,
        diagnostics: items,
    }
}

/// Describes the configuration a registry is fixed to: its enabled built-in
/// detectors, PII selection and the artifact's defaults for everything a call
/// supplies. Input-free: it reads no scan input, builds nothing and does not
/// change the registry.
///
/// Custom detectors the registry holds are code, not data; they are counted
/// in `detection.customDetectors` and are not described further.
///
/// A registry that is not a profile registry of `manifest`'s artifact (it has
/// no built-in the manifest lacks, and every id it holds is a manifest id or a
/// custom one) is described by what it holds; ids the manifest does not
/// include are never reported as enabled.
#[must_use]
pub fn describe_config(manifest: &ArtifactManifest, registry: &DetectorRegistry) -> ConfigSnapshot {
    let included: Vec<&str> = manifest.detector_ids().collect();
    let enabled: Vec<&str> = registry
        .built_in_ids()
        .filter(|id| included.contains(id))
        .collect();
    let custom = registry.len()
        - registry.built_in_ids().count()
        - usize::from(registry.contains(PII_ADAPTER_ID));
    let effective = Effective {
        detection_mode: registry.detection().mode(),
        detection_origin: origin(!registry.detection().is_all()),
        enabled,
        custom_detectors: custom,
        pii: registry.pii_selection().clone(),
        pii_origin: origin(!registry.pii_selection().is_off()),
        ruleset: None,
        policy: PolicyFacts::Default,
        policy_origin: origin(false),
        max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
        max_input_origin: origin(false),
        max_findings: DEFAULT_MAX_FINDINGS,
        max_findings_origin: origin(false),
    };
    build_snapshot(manifest, &effective, false)
}
