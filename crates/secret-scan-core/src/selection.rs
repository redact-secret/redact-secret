//! Detector-id selection (issue #1251,
//! `decision-define-detector-id-selection-and-configuration-replacement-precedence`).
//!
//! A [`DetectionSelection`] chooses which of an artifact's **included**
//! built-in detectors are **enabled**. It acts when a registry is composed
//! ([`DetectorRegistry::with_detection`](crate::DetectorRegistry::with_detection)),
//! before the shared prefilter, candidate collection and overlap resolution,
//! so a disabled detector is not constructed, not prefiltered, no overlap
//! competitor and no retention input.
//!
//! This module is the selection grammar and its judgment only. It reads no
//! manifest and builds no registry, so the registry can depend on it without
//! the configuration resolver; the resolver (`crate::config`) judges the same
//! selection against an artifact manifest through the same functions.

use crate::detectors::built_in_ids;
use crate::error::SecretScanErrorCode;
use crate::json::{self, Value};
use crate::types::is_identifier;

/// The most ids one `include` or `exclude` array may hold.
const DETECTOR_IDS_MAX: usize = 256;
/// The built-in id of the PII adapter, which a selection cannot name.
pub(crate) const PII_ADAPTER_ID: &str = "pii-domain";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Mode {
    #[default]
    All,
    Include,
    Exclude,
}

/// Which of an artifact's included built-in detectors are enabled
/// (`detection` of `runtime-config/v1`).
///
/// - [`all`](Self::all): every included detector (the build default).
/// - [`include`](Self::include): exactly these, an allowlist. A detector
///   added in a later release is not enabled.
/// - [`exclude`](Self::exclude): every included detector except these, a
///   denylist. A detector added later is enabled.
///
/// Ids are `Finding.detector` values such as `github-token`, not types. They
/// are not case-folded or trimmed, and request order never matters: the
/// enabled set is the artifact's canonical order filtered to the enabled ids.
/// Nothing is validated until the selection is applied
/// ([`DetectorRegistry::with_detection`](crate::DetectorRegistry::with_detection))
/// or resolved ([`resolve_config`](crate::resolve_config)), when an unknown, not-included or repeated
/// id is rejected rather than ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DetectionSelection {
    pub(crate) mode: Mode,
    ids: Vec<String>,
}

impl DetectionSelection {
    /// Every included detector is enabled.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            mode: Mode::All,
            ids: Vec::new(),
        }
    }

    /// Exactly `ids` are enabled. An empty list enables no built-in detector.
    #[must_use]
    pub fn include<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            mode: Mode::Include,
            ids: ids.into_iter().map(Into::into).collect(),
        }
    }

    /// Every included detector except `ids` is enabled. An empty list is the
    /// same selection as [`all`](Self::all).
    #[must_use]
    pub fn exclude<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            mode: Mode::Exclude,
            ids: ids.into_iter().map(Into::into).collect(),
        }
    }

    /// Parses the `detection` object of `runtime-config/v1`: `{}`,
    /// `{"include":[ids]}` or `{"exclude":[ids]}`.
    ///
    /// Only the grammar is judged here (member names and types, at most 256
    /// ids, each an identifier); the ids are judged against an artifact when
    /// the selection is applied.
    ///
    /// # Errors
    ///
    /// A [`DetectionConfigError`] naming the first violation. It carries no
    /// input text.
    pub fn from_json(json: &str) -> Result<Self, DetectionConfigError> {
        let value = json::parse(json).ok_or(DetectionConfigError::class(CLASS_WRONG_TYPE, None))?;
        selection_from_value(&value).map_err(Fault::error)
    }

    /// Whether this enables every included detector: the build default, and
    /// also `exclude` with no ids, which is the same selection.
    #[must_use]
    pub fn is_all(&self) -> bool {
        self.mode == Mode::All || (self.mode == Mode::Exclude && self.ids.is_empty())
    }

    /// `all-included`, `include` or `exclude`.
    #[must_use]
    pub const fn mode(&self) -> &'static str {
        match self.mode {
            Mode::All => "all-included",
            Mode::Include => "include",
            Mode::Exclude => "exclude",
        }
    }

    /// The ids as given, in request order. Empty for [`all`](Self::all).
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.ids.iter().map(String::as_str)
    }
}

pub(crate) const CLASS_UNKNOWN_FIELD: &str = "UNKNOWN_FIELD";
pub(crate) const CLASS_WRONG_TYPE: &str = "WRONG_TYPE";
pub(crate) const CLASS_TOO_MANY: &str = "TOO_MANY_DETECTOR_IDS";
pub(crate) const CLASS_IDENTIFIER: &str = "INVALID_IDENTIFIER";
pub(crate) const CLASS_UNSUPPORTED: &str = "DETECTION_SELECTION_UNSUPPORTED";
pub(crate) const CLASS_DUPLICATE: &str = "DUPLICATE_DETECTOR_ID";
pub(crate) const CLASS_NOT_SELECTABLE: &str = "DETECTOR_NOT_SELECTABLE";
pub(crate) const CLASS_NOT_INCLUDED: &str = "DETECTOR_NOT_INCLUDED";
pub(crate) const CLASS_UNKNOWN_ID: &str = "UNKNOWN_DETECTOR_ID";
pub(crate) const CLASS_CONFLICT: &str = "DETECTION_SELECTOR_CONFLICT";
pub(crate) const CLASS_EMPTY: &str = "EMPTY_DETECTION_SET";

/// Why a detector selection was rejected: a fixed class and, for a problem in
/// one id, that id's zero-based position in its array.
///
/// The class is one of the `config-diagnostics/v1` error codes
/// (`UNKNOWN_FIELD`, `WRONG_TYPE`, `TOO_MANY_DETECTOR_IDS`,
/// `INVALID_IDENTIFIER`, `DUPLICATE_DETECTOR_ID`, `DETECTOR_NOT_SELECTABLE`,
/// `DETECTOR_NOT_INCLUDED`, `UNKNOWN_DETECTOR_ID`, `DETECTION_SELECTOR_CONFLICT`
/// or `EMPTY_DETECTION_SET`). Nothing of the rejected input is carried, so a
/// pasted secret in place of an id is never echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectionConfigError {
    code: SecretScanErrorCode,
    class: &'static str,
    index: Option<usize>,
}

impl DetectionConfigError {
    const fn class(class: &'static str, index: Option<usize>) -> Self {
        let code = if matches!(class.as_bytes(), b"EMPTY_DETECTION_SET") {
            SecretScanErrorCode::EmptyDetectionSet
        } else {
            SecretScanErrorCode::InvalidDetectionConfig
        };
        Self { code, class, index }
    }

    /// `INVALID_DETECTION_CONFIG`, or `EMPTY_DETECTION_SET` when the selection
    /// leaves nothing to detect.
    #[must_use]
    pub const fn code(self) -> SecretScanErrorCode {
        self.code
    }

    /// The fixed diagnostic class, for example `DETECTOR_NOT_INCLUDED`.
    #[must_use]
    pub const fn class_name(self) -> &'static str {
        self.class
    }

    /// The zero-based position of the offending id in its array, if one id is
    /// to blame.
    #[must_use]
    pub const fn index(self) -> Option<usize> {
        self.index
    }
}

impl std::fmt::Display for DetectionConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.message())
    }
}

impl std::error::Error for DetectionConfigError {}

impl From<DetectionConfigError> for crate::SecretScanError {
    fn from(error: DetectionConfigError) -> Self {
        error.code.into()
    }
}

/// A selection problem before it becomes a public error or a diagnostic: the
/// class plus the array it concerns and the position inside it.
#[derive(Clone, Copy)]
pub(crate) struct Fault {
    pub(crate) class: &'static str,
    array: Option<&'static str>,
    index: Option<usize>,
}

impl Fault {
    const fn new(class: &'static str) -> Self {
        Self {
            class,
            array: None,
            index: None,
        }
    }

    const fn at(class: &'static str, array: &'static str, index: usize) -> Self {
        Self {
            class,
            array: Some(array),
            index: Some(index),
        }
    }

    const fn error(self) -> DetectionConfigError {
        DetectionConfigError::class(self.class, self.index)
    }

    pub(crate) fn path(self) -> String {
        match (self.array, self.index) {
            // An unknown member is addressed by position, never by name.
            (None, Some(index)) if self.class == CLASS_UNKNOWN_FIELD => {
                format!("detection.@{index}")
            }
            (Some(array), Some(index)) => format!("detection.{array}[{index}]"),
            (Some(array), None) => format!("detection.{array}"),
            _ => "detection".to_owned(),
        }
    }
}

/// Parses a `detection` value: members, types, id count, identifier grammar,
/// in that order, first violation first.
pub(crate) fn selection_from_value(value: &Value) -> Result<DetectionSelection, Fault> {
    let Value::Object(members) = value else {
        return Err(Fault::new(CLASS_WRONG_TYPE));
    };
    let mut include: Option<&Value> = None;
    let mut exclude: Option<&Value> = None;
    for (position, (name, member)) in members.iter().enumerate() {
        match name.as_str() {
            "include" => include = Some(member),
            "exclude" => exclude = Some(member),
            _ => {
                return Err(Fault {
                    class: CLASS_UNKNOWN_FIELD,
                    array: None,
                    index: Some(position),
                });
            }
        }
    }
    let list = |member: &Value, array: &'static str| -> Result<Vec<String>, Fault> {
        let Value::Array(items) = member else {
            return Err(Fault {
                class: CLASS_WRONG_TYPE,
                array: Some(array),
                index: None,
            });
        };
        let mut ids = Vec::with_capacity(items.len().min(DETECTOR_IDS_MAX));
        for (index, item) in items.iter().enumerate() {
            let Value::Str(id) = item else {
                return Err(Fault::at(CLASS_WRONG_TYPE, array, index));
            };
            ids.push(id.clone());
        }
        if ids.len() > DETECTOR_IDS_MAX {
            return Err(Fault {
                class: CLASS_TOO_MANY,
                array: Some(array),
                index: None,
            });
        }
        if let Some(index) = ids.iter().position(|id| !is_identifier(id)) {
            return Err(Fault::at(CLASS_IDENTIFIER, array, index));
        }
        Ok(ids)
    };
    match (include, exclude) {
        (Some(_), Some(_)) => Err(Fault::new(CLASS_CONFLICT)),
        (Some(member), None) => Ok(DetectionSelection::include(list(member, "include")?)),
        (None, Some(member)) => Ok(DetectionSelection::exclude(list(member, "exclude")?)),
        (None, None) => Ok(DetectionSelection::all()),
    }
}

/// One entry of a registry as selection planning sees it.
pub(crate) struct PlanEntry<'a> {
    pub(crate) id: &'a str,
    /// A built-in detector, the only kind a selection can name or remove.
    pub(crate) built_in: bool,
}

/// Judges `selection` over `entries`, in registration order, and returns
/// which entries stay. Entries that are not built-in always stay.
///
/// `included` is what the selection can name: the registry's built-ins. An
/// id that is a `full` built-in absent from the registry is not included; an
/// id that names a registered custom or PII-adapter detector is not
/// selectable; anything else is unknown.
pub(crate) fn plan_selection(
    selection: &DetectionSelection,
    entries: &[PlanEntry<'_>],
) -> Result<Vec<bool>, DetectionConfigError> {
    let included: Vec<&str> = entries
        .iter()
        .filter(|entry| entry.built_in)
        .map(|entry| entry.id)
        .collect();
    let named = judge(selection, &included, |id| {
        id == PII_ADAPTER_ID
            || entries
                .iter()
                .any(|entry| !entry.built_in && entry.id == id)
    })
    .map_err(Fault::error)?;
    let keep: Vec<bool> = entries
        .iter()
        .map(|entry| {
            !entry.built_in
                || match selection.mode {
                    Mode::All => true,
                    Mode::Include => named.contains(&entry.id),
                    Mode::Exclude => !named.contains(&entry.id),
                }
        })
        .collect();
    if selection.mode != Mode::All && !keep.iter().any(|kept| *kept) {
        return Err(DetectionConfigError::class(CLASS_EMPTY, None));
    }
    Ok(keep)
}

/// Step 5 of the validation order: every named id, in array order, must be
/// included, and none may repeat. Returns the named ids.
pub(crate) fn judge<'a>(
    selection: &'a DetectionSelection,
    included: &[&str],
    not_selectable: impl Fn(&str) -> bool,
) -> Result<Vec<&'a str>, Fault> {
    let array = match selection.mode {
        Mode::Exclude => "exclude",
        _ => "include",
    };
    // At most 256 ids, so a linear scan is cheaper than a set in code size and
    // in time.
    let mut named: Vec<&str> = Vec::new();
    for (index, id) in selection.ids.iter().enumerate() {
        let id = id.as_str();
        let class = if named.contains(&id) {
            CLASS_DUPLICATE
        } else if included.contains(&id) {
            named.push(id);
            continue;
        } else if not_selectable(id) {
            CLASS_NOT_SELECTABLE
        } else if built_in_ids().any(|known| known == id) {
            CLASS_NOT_INCLUDED
        } else {
            CLASS_UNKNOWN_ID
        };
        return Err(Fault::at(class, array, index));
    }
    Ok(named)
}

impl DetectionSelection {
    /// The ids of `included` this selection enables, in the order of
    /// `included` (the artifact's canonical order), judged as the validation
    /// order requires: every named id must be included, and none may repeat.
    pub(crate) fn enabled_of<'a>(&self, included: &[&'a str]) -> Result<Vec<&'a str>, Fault> {
        let named = judge(self, included, |id| id == PII_ADAPTER_ID)?;
        Ok(included
            .iter()
            .copied()
            .filter(|id| match self.mode {
                Mode::All => true,
                Mode::Include => named.contains(id),
                Mode::Exclude => !named.contains(id),
            })
            .collect())
    }
}
