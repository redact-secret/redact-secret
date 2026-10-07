//! The artifact capability manifest, `artifact-manifest/v1` (issue #1250,
//! `decision-define-the-artifact-manifest-and-configuration-data-contracts`).
//!
//! An [`ArtifactManifest`] says what one artifact contains: its identity, the
//! built-in detectors it links in canonical order, the finding types each can
//! emit, whether the PII runtime is linked, and the capabilities, defaults and
//! bounds it supports. It is the **included** level of the capability ceiling
//! (`decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`),
//! before any runtime choice narrows it.
//!
//! # Generated, not declared
//!
//! The detector ids are read from the same registration rows a registry is
//! built from ([`DetectorRegistry::with_built_in`](crate::DetectorRegistry::with_built_in)
//! and [`DetectorRegistry::with_common_built_in`](crate::DetectorRegistry::with_common_built_in)),
//! so the manifest cannot list a detector the artifact does not register.
//! The pack and emitted types come from the pure-data catalog beside those
//! rows; tests pin every row to its catalog entry.
//!
//! # Side-effect free
//!
//! Generating a manifest builds no registry, constructs no detector, reads no
//! PII selection and initializes nothing, so it cannot activate or lock the
//! legacy PII configuration of a binding. It reads no file, network or
//! environment value; the one build-time value, the source revision, is passed
//! in by the host. The manifest holds no input, ruleset, literal, path, host
//! name or timestamp.
//!
//! # Reachability
//!
//! [`ArtifactManifest::full`] and [`ArtifactManifest::common`] are separate
//! functions so a `common` artifact that calls only the second links no
//! `provider` detector (the profile contract's reachability rule). The
//! excluded detectors appear in a `common` manifest as ids only; their
//! constructors stay unreachable.
//!
//! # Document and digest
//!
//! [`ArtifactManifest::as_json`] is UTF-8 JSON with `schema` as its first
//! member and every other member, at every depth, in bytewise order, with no
//! whitespace. [`ArtifactManifest::digest`] is `sha256:` over the **canonical
//! JSON** of the manifest without `digest`: the same object with all members,
//! `schema` included, in bytewise order. A consumer re-derives it from the
//! parsed document by sorting keys.
//!
//! # What the type lists do and do not say
//!
//! A detector's `types` is its reviewed declaration of the finding types it can
//! emit. It is not a closed vocabulary for the engine: a declarative ruleset, a
//! custom detector and the PII adapter emit types the list does not name, and
//! the document says so in `typeVocabulary`.

use std::fmt::{self, Write as _};

use crate::VERSION;
use crate::action_policy::MAX_ACTION_POLICY_BYTES;
use crate::composition::Composition;
use crate::detectors::{
    BUILT_IN_PACKS, Pack, built_in_detectors, common_built_in_detectors, declared_common_types,
    declared_types,
};
use crate::limits::{DEFAULT_MAX_FINDINGS, DEFAULT_MAX_INPUT_BYTES};
use crate::pii::available_families;
use crate::registry::Profile;
use crate::sha256::{sha256, to_hex};

/// The first member every manifest document starts with.
const SCHEMA_PREFIX: &str = "{\"schema\":\"artifact-manifest/v1\",";
/// The most detector ids one selection may name (`detection.include`/`exclude`).
const DETECTOR_IDS_MAX: usize = 256;
/// The most diagnostics one `config-diagnostics/v1` document holds.
const DIAGNOSTICS_MAX: usize = 256;

/// The kind of artifact a manifest describes: the build target class.
///
/// The value is fixed by the binding that generates the manifest, never read
/// from the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactKind {
    /// A WebAssembly build (`bindings/wasm`).
    Wasm,
    /// The Node.js N-API addon (`bindings/node`).
    NodeAddon,
    /// The Python wheel's native module (`bindings/python`).
    PythonWheel,
    /// The command-line binary.
    Cli,
    /// The Rust crate as a library dependency.
    RustRegistry,
}

impl ArtifactKind {
    /// Whether runtime detector-id selection is supported on this kind of
    /// artifact: Rust, the Node addon and WebAssembly. Python and the CLI are
    /// server and enforcement surfaces where a reduced detection set would
    /// only weaken them (`decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`).
    const fn supports_detector_selection(self) -> bool {
        matches!(self, Self::Wasm | Self::NodeAddon | Self::RustRegistry)
    }

    /// The wire name: `wasm`, `node-addon`, `python-wheel`, `cli` or
    /// `rust-registry`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::NodeAddon => "node-addon",
            Self::PythonWheel => "python-wheel",
            Self::Cli => "cli",
            Self::RustRegistry => "rust-registry",
        }
    }
}

/// Why a manifest could not be generated or did not match its artifact.
///
/// Every class has a fixed code and a fixed message. None carries the
/// offending text, so a malformed or substituted document is never echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactManifestError {
    /// No manifest was supplied where the artifact requires one.
    Missing,
    /// The supplied document is not an `artifact-manifest/v1` document.
    SchemaMismatch,
    /// The supplied document differs from the manifest the loaded artifact
    /// generates, so its digest does not match.
    DigestMismatch,
    /// The source revision given to the generator is not 40 lowercase
    /// hexadecimal characters.
    InvalidSourceRevision,
}

impl ArtifactManifestError {
    /// The fixed code: `ARTIFACT_MANIFEST_MISSING`,
    /// `ARTIFACT_MANIFEST_SCHEMA_MISMATCH`, `ARTIFACT_MANIFEST_DIGEST_MISMATCH`
    /// or `ARTIFACT_MANIFEST_INVALID_SOURCE_REVISION`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "ARTIFACT_MANIFEST_MISSING",
            Self::SchemaMismatch => "ARTIFACT_MANIFEST_SCHEMA_MISMATCH",
            Self::DigestMismatch => "ARTIFACT_MANIFEST_DIGEST_MISMATCH",
            Self::InvalidSourceRevision => "ARTIFACT_MANIFEST_INVALID_SOURCE_REVISION",
        }
    }

    /// The fixed message; identical to the `Display` output.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Missing => "The artifact manifest is missing.",
            Self::SchemaMismatch => "The artifact manifest schema is not supported.",
            Self::DigestMismatch => "The artifact manifest does not match this artifact.",
            Self::InvalidSourceRevision => "The artifact source revision is invalid.",
        }
    }
}

impl fmt::Display for ArtifactManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ArtifactManifestError {}

/// What one artifact contains and supports, generated from its real
/// composition (`artifact-manifest/v1`).
///
/// The detector ids come from the registration rows the artifact links, so
/// the manifest cannot list a detector the artifact does not register.
/// Generating it builds no registry, constructs no detector and reads no PII
/// selection, input, file, network or environment value, so it cannot
/// initialize anything or lock the legacy PII activation.
///
/// [`as_json`](Self::as_json) is UTF-8 JSON with `schema` as its first member
/// and every other member, at every depth, in bytewise order, with no
/// whitespace. [`digest`](Self::digest) is `sha256:` over the canonical JSON of
/// the manifest without `digest`: the same object with all members, `schema`
/// included, in bytewise order. Each detector's `types` is its reviewed
/// declaration, not a closed vocabulary: a ruleset, a custom detector and the
/// PII adapter emit others, which `typeVocabulary` states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactManifest {
    profile: Profile,
    kind: ArtifactKind,
    pii: bool,
    selection: bool,
    ids: Vec<&'static str>,
    declared: Vec<(&'static str, &'static [&'static str])>,
    not_included: Vec<&'static str>,
    composition_id: Option<String>,
    digest: String,
    json: String,
}

/// One included detector as the generator sees it.
struct Entry {
    id: &'static str,
    pack: &'static str,
    types: &'static [&'static str],
}

impl ArtifactManifest {
    /// The schema name every manifest carries.
    pub const SCHEMA: &'static str = "artifact-manifest/v1";

    /// The manifest of an artifact that links the `full` profile: every
    /// built-in detector.
    ///
    /// `pii` says whether the PII runtime is linked into the artifact.
    /// `source_revision` is the 40-hex source commit of the build, or `None`
    /// when the build has none.
    ///
    /// # Errors
    ///
    /// [`ArtifactManifestError::InvalidSourceRevision`] when `source_revision`
    /// is not 40 lowercase hexadecimal characters.
    pub fn full(
        kind: ArtifactKind,
        pii: bool,
        source_revision: Option<&str>,
    ) -> Result<Self, ArtifactManifestError> {
        let entries = built_in_detectors().iter().map(|row| Entry {
            id: row.id,
            pack: pack_name(row.id),
            types: declared_types(row.id).unwrap_or_default(),
        });
        Self::assemble(Profile::Full, kind, pii, source_revision, None, entries)
    }

    /// The manifest of an artifact that links only the `common` profile.
    ///
    /// Names no `provider` detector row and no provider type list, so calling
    /// it from a `common`-only artifact does not link a provider detector.
    /// The `full` built-in ids the artifact lacks are listed as ids only, in
    /// `notIncluded`.
    ///
    /// # Errors
    ///
    /// [`ArtifactManifestError::InvalidSourceRevision`] when `source_revision`
    /// is not 40 lowercase hexadecimal characters.
    pub fn common(
        kind: ArtifactKind,
        pii: bool,
        source_revision: Option<&str>,
    ) -> Result<Self, ArtifactManifestError> {
        let entries = common_built_in_detectors().iter().map(|row| Entry {
            id: row.id,
            pack: pack_name(row.id),
            types: declared_common_types(row.id).unwrap_or_default(),
        });
        Self::assemble(Profile::Common, kind, pii, source_revision, None, entries)
    }

    /// The manifest of an artifact built from a static custom composition
    /// (issue #1253): `artifact.variant` and `composition.profile` are
    /// `custom`, `composition.kind` is `custom` and `composition.id` is the
    /// composition identity. The PII flag is the composition's.
    ///
    /// Names only the selected detectors' rows and their own catalog types, so
    /// calling it from a composed artifact links no other detector. The other
    /// `full` built-in ids are listed as ids only, in `notIncluded`.
    ///
    /// # Errors
    ///
    /// [`ArtifactManifestError::InvalidSourceRevision`] when `source_revision`
    /// is not 40 lowercase hexadecimal characters.
    pub fn custom(
        kind: ArtifactKind,
        composition: &Composition,
        source_revision: Option<&str>,
    ) -> Result<Self, ArtifactManifestError> {
        let entries = composition.selected().iter().map(|selected| Entry {
            id: selected.id,
            pack: pack_name(selected.id),
            types: selected.types,
        });
        Self::assemble(
            Profile::Custom,
            kind,
            composition.pii(),
            source_revision,
            Some(composition.id()),
            entries,
        )
    }

    fn assemble(
        profile: Profile,
        kind: ArtifactKind,
        pii: bool,
        source_revision: Option<&str>,
        composition_id: Option<&str>,
        entries: impl Iterator<Item = Entry>,
    ) -> Result<Self, ArtifactManifestError> {
        if source_revision.is_some_and(|revision| !is_revision(revision)) {
            return Err(ArtifactManifestError::InvalidSourceRevision);
        }
        let entries: Vec<Entry> = entries.collect();
        let ids: Vec<&'static str> = entries.iter().map(|entry| entry.id).collect();
        let declared = entries
            .iter()
            .map(|entry| (entry.id, entry.types))
            .collect();
        let not_included: Vec<&'static str> = BUILT_IN_PACKS
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !ids.contains(id))
            .collect();

        let selection = kind.supports_detector_selection();
        let members = Members::new(
            profile,
            kind,
            pii,
            selection,
            source_revision,
            composition_id,
            &entries,
            &not_included,
        );
        let canonical = members.render(None);
        let digest = format!("sha256:{}", to_hex(&sha256(canonical.as_bytes())));
        let json = members.render(Some(&digest));

        Ok(Self {
            profile,
            kind,
            pii,
            selection,
            ids,
            declared,
            not_included,
            composition_id: composition_id.map(str::to_owned),
            digest,
            json,
        })
    }

    /// The profile of the detectors this artifact links.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// The composition identity of a custom artifact (`custom:` and 64
    /// lowercase hexadecimal characters); `None` for `full` and `common`.
    #[must_use]
    pub fn composition_id(&self) -> Option<&str> {
        self.composition_id.as_deref()
    }

    /// The kind of artifact the manifest describes.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Whether the PII runtime is linked into the artifact.
    #[must_use]
    pub const fn pii_linked(&self) -> bool {
        self.pii
    }

    /// Whether the artifact supports runtime detector-id selection
    /// (`capabilities.detectorSelection`): true for Rust, the Node addon and
    /// WebAssembly, false for Python and the CLI.
    #[must_use]
    pub const fn detector_selection(&self) -> bool {
        self.selection
    }

    /// The included built-in detector ids, in canonical registration order.
    pub fn detector_ids(&self) -> impl Iterator<Item = &str> {
        self.ids.iter().copied()
    }

    /// Each included detector with the finding types it declares, in
    /// canonical order (the manifest's `detectors[].types`; not a closed
    /// vocabulary).
    pub(crate) fn declared_types(
        &self,
    ) -> impl Iterator<Item = (&'static str, &'static [&'static str])> + '_ {
        self.declared.iter().copied()
    }

    /// The `full` built-in ids this artifact does not include, in canonical
    /// order. Empty for `full`. Ids only: no constructor is reachable through
    /// them.
    pub fn not_included_ids(&self) -> impl Iterator<Item = &str> {
        self.not_included.iter().copied()
    }

    /// The manifest digest, `sha256:` and 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The manifest document: UTF-8 JSON, `schema` first, every other member
    /// in bytewise order, no whitespace. The same value for the same build.
    #[must_use]
    pub fn as_json(&self) -> &str {
        &self.json
    }

    /// Checks a packaged manifest document against this manifest, which the
    /// loaded artifact generates from its own composition.
    ///
    /// Generation is deterministic, so a document that belongs to this
    /// artifact is byte-identical to [`as_json`](Self::as_json). Any other
    /// document is rejected with a fixed class and nothing of its content.
    ///
    /// # Errors
    ///
    /// [`ArtifactManifestError::Missing`] when `packaged` is `None`;
    /// [`ArtifactManifestError::SchemaMismatch`] when it does not start as an
    /// `artifact-manifest/v1` document; [`ArtifactManifestError::DigestMismatch`]
    /// when it is such a document but not this artifact's.
    pub fn verify_packaged(&self, packaged: Option<&str>) -> Result<(), ArtifactManifestError> {
        let Some(document) = packaged else {
            return Err(ArtifactManifestError::Missing);
        };
        if !document.starts_with(SCHEMA_PREFIX) {
            return Err(ArtifactManifestError::SchemaMismatch);
        }
        if document != self.json {
            return Err(ArtifactManifestError::DigestMismatch);
        }
        Ok(())
    }
}

/// Whether `value` is a 40-character lowercase hexadecimal commit id.
fn is_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The pre-rendered JSON value of every member of the document except
/// `digest`, held by name in the bytewise order the canonical form requires:
/// no sorting happens at run time.
struct Members {
    artifact: String,
    bounds: String,
    capabilities: String,
    composition: String,
    defaults: &'static str,
    detectors: String,
    not_included: String,
    pii: String,
    source_revision: String,
    type_vocabulary: &'static str,
    version: String,
}

impl Members {
    #[allow(clippy::too_many_arguments)] // one value per manifest member group
    fn new(
        profile: Profile,
        kind: ArtifactKind,
        pii: bool,
        selection: bool,
        source_revision: Option<&str>,
        composition_id: Option<&str>,
        entries: &[Entry],
        not_included: &[&'static str],
    ) -> Self {
        let profile_name = profile.as_str();
        let mut artifact = String::from("{\"kind\":");
        push_string(&mut artifact, kind.as_str());
        let _ = write!(artifact, ",\"pii\":{pii},\"variant\":");
        push_string(&mut artifact, profile_name);
        artifact.push('}');

        let mut composition = String::from("{\"id\":");
        match composition_id {
            Some(id) => push_string(&mut composition, id),
            None => composition.push_str("null"),
        }
        composition.push_str(",\"kind\":");
        push_string(
            &mut composition,
            if composition_id.is_some() {
                "custom"
            } else {
                "standard"
            },
        );
        composition.push_str(",\"profile\":");
        push_string(&mut composition, profile_name);
        composition.push('}');

        let mut pii_block = String::new();
        let _ = write!(pii_block, "{{\"available\":{pii},\"families\":");
        push_array(
            &mut pii_block,
            if pii {
                available_families().iter().copied()
            } else {
                [].iter().copied()
            },
        );
        pii_block.push('}');

        let mut source = String::new();
        match source_revision {
            Some(revision) => push_string(&mut source, revision),
            None => source.push_str("null"),
        }
        let mut version = String::new();
        push_string(&mut version, VERSION);
        let mut not_included_json = String::new();
        push_array(&mut not_included_json, not_included.iter().copied());

        let mut bounds = String::new();
        let _ = write!(
            bounds,
            "{{\"actionPolicyBytes\":{MAX_ACTION_POLICY_BYTES},\
             \"detectorIdsMax\":{DETECTOR_IDS_MAX},\
             \"diagnosticsMax\":{DIAGNOSTICS_MAX},\
             \"limits\":{{\"maxFindings\":{DEFAULT_MAX_FINDINGS},\
             \"maxInputBytes\":{DEFAULT_MAX_INPUT_BYTES}}}}}"
        );

        Self {
            artifact,
            bounds,
            capabilities: format!(
                "{{\"actionPolicy\":{{\"revisions\":[1]}},\"detectorSelection\":{selection},\
                 \"incremental\":true,\"ruleset\":{{\"revisions\":[1]}}}}"
            ),
            composition,
            defaults: "{\"actionPolicy\":\"artifact-default\",\"detection\":\"all-included\",\
                       \"limits\":\"artifact-default\",\"pii\":{\"selectors\":[]},\
                       \"schema\":\"build-defaults/v1\"}",
            detectors: detectors_json(entries),
            not_included: not_included_json,
            pii: pii_block,
            source_revision: source,
            type_vocabulary: "{\"builtInTypes\":\"declared\",\"complete\":false,\
                              \"dynamicSources\":[\"custom-detector\",\"pii\",\"ruleset\"]}",
            version,
        }
    }

    /// Renders the document. Without a digest it is the canonical JSON the
    /// digest is taken over: every member, `schema` included, in bytewise
    /// order. With one it is the emitted document: `schema` first, then every
    /// other member, `digest` included, in bytewise order.
    fn render(&self, digest: Option<&str>) -> String {
        let quoted_digest = digest.map(|value| ["\"", value, "\""].concat());
        let schema = "\"artifact-manifest/v1\"";
        let rows: [(&str, &str); 14] = [
            ("artifact", &self.artifact),
            ("bounds", &self.bounds),
            ("capabilities", &self.capabilities),
            ("composition", &self.composition),
            ("defaults", self.defaults),
            ("detectors", &self.detectors),
            ("digest", quoted_digest.as_deref().unwrap_or("")),
            ("notIncluded", &self.not_included),
            ("pii", &self.pii),
            ("product", "\"redact-secret\""),
            ("schema", schema),
            ("sourceRevision", &self.source_revision),
            ("typeVocabulary", self.type_vocabulary),
            ("version", &self.version),
        ];
        let mut out = String::from("{");
        let mut first = true;
        if digest.is_some() {
            out.push_str("\"schema\":");
            out.push_str(schema);
            first = false;
        }
        for (name, value) in rows {
            let skipped = value.is_empty() || (digest.is_some() && name == "schema");
            if skipped {
                continue;
            }
            if !first {
                out.push(',');
            }
            first = false;
            out.push('"');
            out.push_str(name);
            out.push_str("\":");
            out.push_str(value);
        }
        out.push('}');
        out
    }
}

/// The `detectors` array: one object per included built-in, members sorted.
fn detectors_json(entries: &[Entry]) -> String {
    let mut out = String::from("[");
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"aliases\":[],\"id\":");
        push_string(&mut out, entry.id);
        out.push_str(",\"pack\":");
        push_string(&mut out, entry.pack);
        out.push_str(",\"types\":");
        push_array(&mut out, entry.types.iter().copied());
        out.push('}');
    }
    out.push(']');
    out
}

/// `"common"` or `"provider"` for a built-in id. Pure data.
fn pack_name(id: &str) -> &'static str {
    match BUILT_IN_PACKS.iter().find(|(known, _)| *known == id) {
        Some((_, Pack::Common)) => "common",
        _ => "provider",
    }
}

/// Appends `value` as a JSON string. Every string this module writes is a
/// static ASCII identifier, the product version or a validated hex revision;
/// the escapes are defensive.
fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other if other.is_ascii() && !other.is_ascii_control() => out.push(other),
            _ => out.push('?'),
        }
    }
    out.push('"');
}

fn push_array<'a>(out: &mut String, items: impl Iterator<Item = &'a str>) {
    out.push('[');
    for (index, item) in items.enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_string(out, item);
    }
    out.push(']');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetectorRegistry;

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    fn full() -> ArtifactManifest {
        ArtifactManifest::full(ArtifactKind::RustRegistry, true, None).expect("manifest")
    }

    fn common() -> ArtifactManifest {
        ArtifactManifest::common(ArtifactKind::RustRegistry, true, None).expect("manifest")
    }

    fn custom() -> ArtifactManifest {
        let composition = Composition::new(
            "edge-checks",
            false,
            [
                crate::composition::github_token(),
                crate::composition::jwt(),
                crate::composition::generic_token(),
            ],
        )
        .expect("composition");
        ArtifactManifest::custom(ArtifactKind::Wasm, &composition, None).expect("manifest")
    }

    #[test]
    fn full_ids_are_the_registered_ids_in_order() {
        let registry = DetectorRegistry::with_built_in([]).expect("registry");
        let registered: Vec<&str> = registry.ids().collect();
        let manifest = full();
        let listed: Vec<&str> = manifest.detector_ids().collect();
        assert_eq!(listed, registered);
        assert_eq!(manifest.not_included_ids().count(), 0);
    }

    #[test]
    fn common_ids_are_the_registered_ids_and_the_rest_are_not_included() {
        let registry = DetectorRegistry::with_common_built_in([]).expect("registry");
        let registered: Vec<&str> = registry.ids().collect();
        let manifest = common();
        let listed: Vec<&str> = manifest.detector_ids().collect();
        assert_eq!(listed, registered);
        let full_manifest = full();
        let full_ids: Vec<&str> = full_manifest.detector_ids().collect();
        let mut partition: Vec<&str> = manifest
            .detector_ids()
            .chain(manifest.not_included_ids())
            .collect();
        partition.sort_unstable();
        let mut expected = full_ids;
        expected.sort_unstable();
        assert_eq!(partition, expected);
        assert!(manifest.not_included_ids().all(|id| !listed.contains(&id)));
    }

    #[test]
    fn generation_is_deterministic_and_profile_specific() {
        assert_eq!(full(), full());
        assert_eq!(common(), common());
        assert_ne!(full().digest(), common().digest());
        assert_ne!(
            full().digest(),
            ArtifactManifest::full(ArtifactKind::Wasm, true, None)
                .expect("manifest")
                .digest()
        );
        assert_ne!(
            full().digest(),
            ArtifactManifest::full(ArtifactKind::RustRegistry, false, None)
                .expect("manifest")
                .digest()
        );
    }

    #[test]
    fn document_starts_with_the_schema_and_ends_with_the_digest_member_in_order() {
        let manifest = full();
        let json = manifest.as_json();
        assert!(json.starts_with(SCHEMA_PREFIX));
        assert!(json.ends_with('}'));
        assert!(json.is_ascii());
        assert!(!json.contains(' '));
        assert!(json.contains(&format!("\"digest\":\"{}\"", manifest.digest())));
        assert_eq!(manifest.digest().len(), "sha256:".len() + 64);
        let mut last = 0;
        for name in [
            "\"artifact\":",
            "\"bounds\":",
            "\"capabilities\":",
            "\"composition\":",
            "\"defaults\":",
            "\"detectors\":",
            "\"digest\":",
            "\"notIncluded\":",
            "\"pii\":{\"available\"",
            "\"product\":",
            "\"sourceRevision\":",
            "\"typeVocabulary\":",
            "\"version\":",
        ] {
            let at = json.find(name).expect("member present");
            assert!(at > last, "{name} out of order");
            last = at;
        }
    }

    #[test]
    fn pii_families_are_listed_only_when_the_runtime_is_linked() {
        let on = full();
        assert!(
            on.as_json()
                .contains("\"pii\":{\"available\":true,\"families\":[\"pii:global:email\"")
        );
        let off = ArtifactManifest::full(ArtifactKind::Wasm, false, None).expect("manifest");
        assert!(
            off.as_json()
                .contains("\"pii\":{\"available\":false,\"families\":[]}")
        );
        assert!(!off.pii_linked());
    }

    #[test]
    fn source_revision_is_null_or_validated() {
        assert!(full().as_json().contains("\"sourceRevision\":null"));
        let pinned = ArtifactManifest::full(ArtifactKind::Cli, true, Some(REVISION)).expect("ok");
        assert!(
            pinned
                .as_json()
                .contains(&format!("\"sourceRevision\":\"{REVISION}\""))
        );
        for bad in ["", "abc", &REVISION.to_uppercase(), &format!("{REVISION}0")] {
            assert_eq!(
                ArtifactManifest::full(ArtifactKind::Cli, true, Some(bad)),
                Err(ArtifactManifestError::InvalidSourceRevision)
            );
        }
    }

    #[test]
    fn dynamic_types_are_not_presented_as_a_closed_vocabulary() {
        let json = full().as_json().to_owned();
        assert!(
            json.contains("\"typeVocabulary\":{\"builtInTypes\":\"declared\",\"complete\":false,")
        );
        assert!(json.contains("\"dynamicSources\":[\"custom-detector\",\"pii\",\"ruleset\"]"));
    }

    #[test]
    fn a_common_manifest_names_no_provider_type() {
        let json = common().as_json().to_owned();
        assert!(json.contains("\"id\":\"jwt\""));
        assert!(!json.contains("github_token"));
        assert!(json.contains("\"notIncluded\":[\"aws-access-key\""));
    }

    #[test]
    fn verification_has_fixed_bounded_diagnostics() {
        let manifest = full();
        assert_eq!(manifest.verify_packaged(Some(manifest.as_json())), Ok(()));
        assert_eq!(
            manifest.verify_packaged(None),
            Err(ArtifactManifestError::Missing)
        );
        assert_eq!(
            manifest.verify_packaged(Some("")),
            Err(ArtifactManifestError::SchemaMismatch)
        );
        assert_eq!(
            manifest.verify_packaged(Some("{\"schema\":\"artifact-manifest/v2\"}")),
            Err(ArtifactManifestError::SchemaMismatch)
        );
        assert_eq!(
            manifest.verify_packaged(Some(common().as_json())),
            Err(ArtifactManifestError::DigestMismatch)
        );
        let tampered =
            manifest
                .as_json()
                .replacen("\"incremental\":true", "\"incremental\":false", 1);
        assert_eq!(
            manifest.verify_packaged(Some(&tampered)),
            Err(ArtifactManifestError::DigestMismatch)
        );
        for error in [
            ArtifactManifestError::Missing,
            ArtifactManifestError::SchemaMismatch,
            ArtifactManifestError::DigestMismatch,
            ArtifactManifestError::InvalidSourceRevision,
        ] {
            assert_eq!(error.to_string(), error.message());
            assert!(error.code().starts_with("ARTIFACT_MANIFEST_"));
            assert!(error.message().len() < 64);
        }
    }

    /// The canonical JSON of `value`: members in bytewise order at every
    /// depth, no whitespace. `serde_json` keeps objects sorted (no
    /// `preserve_order`), so its compact form is the contract's form.
    fn canonical(value: &serde_json::Value) -> String {
        serde_json::to_string(value).expect("serializes")
    }

    #[test]
    fn digest_is_the_sha256_of_the_canonical_document_without_digest() {
        for manifest in [full(), common(), custom()] {
            let mut value: serde_json::Value =
                serde_json::from_str(manifest.as_json()).expect("valid JSON");
            let object = value.as_object_mut().expect("object");
            let digest = object.remove("digest").expect("digest member");
            assert_eq!(digest, manifest.digest());
            let expected = format!("sha256:{}", to_hex(&sha256(canonical(&value).as_bytes())));
            assert_eq!(manifest.digest(), expected);
            // The emitted text is the canonical text with `digest` added and
            // `schema` moved first.
            let mut with_digest = value.clone();
            with_digest["digest"] = serde_json::Value::String(expected);
            let rendered = canonical(&with_digest);
            let moved = rendered.replacen(
                "{\"artifact\":",
                &format!("{SCHEMA_PREFIX}\"artifact\":"),
                1,
            );
            let without_schema = moved.replacen(
                &format!(",\"schema\":\"{}\"", ArtifactManifest::SCHEMA),
                "",
                1,
            );
            assert_eq!(without_schema, manifest.as_json());
        }
    }

    #[test]
    fn a_custom_manifest_lists_the_composition_and_its_complement() {
        let manifest = custom();
        assert_eq!(manifest.profile(), Profile::Custom);
        let listed: Vec<&str> = manifest.detector_ids().collect();
        assert_eq!(listed, ["github-token", "jwt", "generic-token"]);
        assert_eq!(
            manifest.not_included_ids().count(),
            BUILT_IN_PACKS.len() - 3
        );
        let value: serde_json::Value = serde_json::from_str(manifest.as_json()).expect("JSON");
        assert_eq!(value["artifact"]["variant"], "custom");
        assert_eq!(value["composition"]["kind"], "custom");
        assert_eq!(value["composition"]["profile"], "custom");
        let id = manifest.composition_id().expect("custom id");
        assert_eq!(value["composition"]["id"], id);
        assert!(id.starts_with("custom:") && id.len() == "custom:".len() + 64);
        assert_eq!(full().composition_id(), None);
        assert_ne!(custom().digest(), full().digest());
        // The same selection under another name is another artifact.
        let renamed = Composition::new(
            "other-name",
            false,
            [
                crate::composition::github_token(),
                crate::composition::jwt(),
                crate::composition::generic_token(),
            ],
        )
        .expect("composition");
        assert_ne!(
            ArtifactManifest::custom(ArtifactKind::Wasm, &renamed, None)
                .expect("manifest")
                .digest(),
            custom().digest()
        );
    }

    #[test]
    fn artifact_kinds_have_their_wire_names() {
        for (kind, name) in [
            (ArtifactKind::Wasm, "wasm"),
            (ArtifactKind::NodeAddon, "node-addon"),
            (ArtifactKind::PythonWheel, "python-wheel"),
            (ArtifactKind::Cli, "cli"),
            (ArtifactKind::RustRegistry, "rust-registry"),
        ] {
            assert_eq!(kind.as_str(), name);
        }
    }
}
