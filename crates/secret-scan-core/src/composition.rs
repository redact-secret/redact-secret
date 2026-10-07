//! Static custom composition (issue #1253,
//! `decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`).
//!
//! A [`Composition`] is a chosen subset of the built-in detectors, in canonical
//! order, that a build links into one artifact. It is **not** a profile: the
//! profiles stay `full` and `common`, a composed registry reports
//! [`Profile::Custom`](crate::Profile::Custom), and the core stays
//! Cargo-feature-free.
//!
//! # The generation seam
//!
//! The official detector tables are crate-private, so a consumer cannot name
//! a detector's constructor, and the core does not offer a filter over the
//! full table (referencing the full table makes every detector reachable, and
//! a run-time filter cannot shrink a binary). This module is the reviewed seam
//! between the two: **one public constructor per built-in detector**, a
//! function named after the detector id with `-` written `_`
//! ([`github_token`], [`jwt`], [`generic_token`] and so on), each returning an
//! opaque [`SelectedDetector`]. A generated leaf crate calls exactly the
//! constructors its composition selects and passes them to [`Composition::new`].
//! Link-time reachability then removes every detector it never calls: its code,
//! grammar tables, finding-type names and prefilter literals. The constructors
//! are the entire accepted public naming; adding a built-in detector adds one
//! constructor, pinned by tests against the registration row, the catalog and
//! the prefilter declaration.
//!
//! The registry and manifest of a composition are built from the selected
//! constructors alone: [`DetectorRegistry::with_composition`](crate::DetectorRegistry::with_composition),
//! [`DetectorRegistry::with_composition_and_pii`](crate::DetectorRegistry::with_composition_and_pii),
//! [`IncrementalSanitizer::with_composition_detection_policy_and_formatter`](crate::IncrementalSanitizer::with_composition_detection_policy_and_formatter)
//! and [`ArtifactManifest::custom`](crate::ArtifactManifest::custom).
//!
//! What a composition removes is detector code and data. The engine floor stays:
//! the pipeline, overlap resolution, the redaction and policy code, the
//! incremental retention logic that every detector's hint is consulted by,
//! the declarative ruleset adapter and the shared text helpers. No size or speed
//! guarantee follows from selecting fewer detectors.

use std::sync::{Arc, OnceLock};

pub use crate::detectors::selected::*;

use crate::detectors::{BUILT_IN_PACKS, LiteralMatcher};
use crate::error::{SecretScanError, SecretScanErrorCode};
use crate::registry::compile_matcher;
use crate::sha256::{sha256, to_hex};
use crate::types::is_identifier;

/// A named, ordered, duplicate-free set of selected built-in detectors: the
/// build input of one custom artifact.
///
/// Created by [`Composition::new`], which fixes the canonical order rule and
/// derives the composition identity.
#[derive(Clone, Debug)]
pub struct Composition {
    name: String,
    pii: bool,
    selected: Vec<SelectedDetector>,
    id: String,
    prefilter: OnceLock<Option<Arc<LiteralMatcher>>>,
}

impl Composition {
    /// Creates the composition `name` over `selected`, in the given order.
    ///
    /// `pii` says whether the artifact links the PII runtime; the composition
    /// identity records it. The order must already be the canonical
    /// registration order of the built-ins: the fourth overlap tie breaker is
    /// registration order, so a composition never reorders what it is given.
    ///
    /// The identity is `custom:` followed by the SHA-256 (lowercase hex) of the
    /// canonical `composition/v1` document
    /// `{"include":[<ids>],"name":"<name>","pii":"all"|"none","schema":"composition/v1"}`:
    /// members in bytewise order, no whitespace.
    ///
    /// # Errors
    ///
    /// [`SecretScanErrorCode::InvalidDetector`] when `name` is not an
    /// [`is_identifier`], `selected` is empty, or an id repeats or is out of
    /// canonical order.
    pub fn new<I>(name: &str, pii: bool, selected: I) -> Result<Self, SecretScanError>
    where
        I: IntoIterator<Item = SelectedDetector>,
    {
        let selected: Vec<SelectedDetector> = selected.into_iter().collect();
        if !is_identifier(name) || selected.is_empty() {
            return Err(SecretScanErrorCode::InvalidDetector.into());
        }
        let mut previous: Option<usize> = None;
        for detector in &selected {
            let position = BUILT_IN_PACKS.iter().position(|(id, _)| *id == detector.id);
            match (previous, position) {
                (_, None) => return Err(SecretScanErrorCode::InvalidDetector.into()),
                (Some(before), Some(now)) if now <= before => {
                    return Err(SecretScanErrorCode::InvalidDetector.into());
                }
                _ => previous = position,
            }
        }
        let mut document = String::from("{\"include\":[");
        for (index, detector) in selected.iter().enumerate() {
            if index > 0 {
                document.push(',');
            }
            document.push('"');
            document.push_str(detector.id);
            document.push('"');
        }
        document.push_str("],\"name\":\"");
        document.push_str(name);
        document.push_str("\",\"pii\":\"");
        document.push_str(if pii { "all" } else { "none" });
        document.push_str("\",\"schema\":\"composition/v1\"}");
        let id = format!("custom:{}", to_hex(&sha256(document.as_bytes())));
        Ok(Self {
            name: name.to_owned(),
            pii,
            selected,
            id,
            prefilter: OnceLock::new(),
        })
    }

    /// The composition name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The composition identity, `custom:` and 64 lowercase hexadecimal
    /// characters, the `composition.id` of the artifact manifest.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the artifact this composition describes links the PII runtime.
    #[must_use]
    pub const fn pii(&self) -> bool {
        self.pii
    }

    /// The selected detector ids, in canonical order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.selected.iter().map(|detector| detector.id)
    }

    /// The number of selected detectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.selected.len()
    }

    /// Always `false`: a composition selects at least one detector.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }

    pub(crate) fn selected(&self) -> &[SelectedDetector] {
        &self.selected
    }

    /// The prefilter compiled over the selected detectors' declarations, once
    /// per composition and shared by every registry built from it.
    pub(crate) fn prefilter(&self) -> Option<Arc<LiteralMatcher>> {
        self.prefilter
            .get_or_init(|| {
                compile_matcher(
                    self.selected
                        .iter()
                        .map(|detector| detector.required.as_ref())
                        .collect(),
                )
                .map(Arc::new)
            })
            .clone()
    }
}
