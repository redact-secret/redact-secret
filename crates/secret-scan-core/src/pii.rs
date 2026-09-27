//! Internal `pii-v1` activation, arbitration, and context substrate.
//!
//! Production PII families are registered here only after their family
//! contract has been reviewed. The adapter remains the single detector slot.

use std::collections::{BTreeMap, BTreeSet};

use unicode_normalization::UnicodeNormalization;

use crate::error::{DetectorFailure, SecretScanError, SecretScanErrorCode};
use crate::types::{
    ByteRange, Candidate, Confidence, Detector, DetectorContext, Obfuscation, Specificity,
    is_identifier,
};

const ADAPTER_ID: &str = "pii-domain";
const KNOWN_JURISDICTIONS: &[&str] = &["us"];
const AVAILABLE_FAMILIES: &[&str] = &["pii:global:email", "pii:global:network-address"];
const KNOWN_FAMILIES: &[&str] = &[
    "pii:global:ambiguous-national-id",
    "pii:global:email",
    "pii:global:iban",
    "pii:global:network-address",
    "pii:global:payment-card",
    "pii:global:phone",
    "pii:global:us-ssn",
    "pii:us:ssn",
];
#[path = "pii/pii_email.rs"]
mod pii_email;

/// A canonical, closed PII selector set for the loaded artifact.
///
/// Parsing validates the accepted selector grammar against the production PII
/// families compiled into this artifact and distinguishes invalid,
/// unsupported, and known-but-unavailable requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PiiSelection {
    selectors: Vec<String>,
    families: Vec<String>,
}

impl PiiSelection {
    /// Parses, canonicalizes, and closes PII selectors against this artifact.
    ///
    /// An absent or empty list is the one `off` representation.
    ///
    /// # Errors
    ///
    /// Returns one of the fixed `PII_SELECTOR_*` errors. No error contains a
    /// selector or any caller input.
    pub fn parse(selectors: &[&str]) -> Result<Self, SecretScanError> {
        Self::parse_with_catalog(selectors, KNOWN_FAMILIES, AVAILABLE_FAMILIES)
    }

    fn parse_with_catalog(
        selectors: &[&str],
        known_families: &[&str],
        available_families: &[&str],
    ) -> Result<Self, SecretScanError> {
        let mut canonical = BTreeSet::new();
        for selector in selectors {
            canonical.insert(canonicalize_selector(selector)?);
        }

        let known: BTreeSet<&str> = known_families.iter().copied().collect();
        let available: BTreeSet<&str> = available_families.iter().copied().collect();
        let mut closure = BTreeSet::new();
        for selector in &canonical {
            if selector == "pii:global" {
                closure.extend(
                    available
                        .iter()
                        .copied()
                        .filter(|family| family.starts_with("pii:global:"))
                        .map(str::to_owned),
                );
                continue;
            }
            if let Some(cc) = selector.strip_prefix("pii:")
                && !cc.contains(':')
            {
                if !KNOWN_JURISDICTIONS.contains(&cc) {
                    return Err(SecretScanErrorCode::PiiSelectorUnsupported.into());
                }
                let prefix = format!("pii:{cc}:");
                let jurisdiction_available = available.iter().any(|id| id.starts_with(&prefix));
                if !jurisdiction_available {
                    return Err(SecretScanErrorCode::PiiSelectorUnavailable.into());
                }
                closure.extend(
                    available
                        .iter()
                        .copied()
                        .filter(|family| {
                            family.starts_with("pii:global:") || family.starts_with(&prefix)
                        })
                        .map(str::to_owned),
                );
                continue;
            }
            let family =
                selector_to_family(selector).ok_or(SecretScanErrorCode::PiiSelectorInvalid)?;
            if !known.contains(family.as_str()) {
                return Err(SecretScanErrorCode::PiiSelectorUnsupported.into());
            }
            if !available.contains(family.as_str()) {
                return Err(SecretScanErrorCode::PiiSelectorUnavailable.into());
            }
            closure.insert(family);
        }

        Ok(Self {
            selectors: canonical.into_iter().collect(),
            families: closure.into_iter().collect(),
        })
    }

    /// Whether the selector list was absent or empty.
    #[must_use]
    pub fn is_off(&self) -> bool {
        self.selectors.is_empty()
    }

    /// Canonical activation identity for `profile`.
    #[must_use]
    pub fn activation_identity(&self, profile: crate::Profile) -> String {
        let selectors = if self.selectors.is_empty() {
            "off".to_owned()
        } else {
            self.selectors.join(",")
        };
        format!(
            "credentials={};selectors={selectors};families={};vocabulary={}",
            profile.as_str(),
            self.families.join(","),
            pii_context_table::CONTEXT_VERSION,
        )
    }
}

fn canonicalize_selector(selector: &str) -> Result<String, SecretScanError> {
    if selector == "pii" {
        return Ok("pii:global".to_owned());
    }
    if selector == "pii:global" {
        return Ok(selector.to_owned());
    }
    let parts: Vec<&str> = selector.split(':').collect();
    let valid = match parts.as_slice() {
        ["pii", cc] => valid_cc(cc),
        ["pii", "family", "global", slug] => valid_slug(slug),
        ["pii", "family", cc, slug] => valid_cc(cc) && valid_slug(slug),
        _ => false,
    };
    if !valid || !selector.is_ascii() || selector.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(SecretScanErrorCode::PiiSelectorInvalid.into());
    }
    Ok(selector.to_owned())
}

fn valid_cc(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_lowercase())
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn selector_to_family(selector: &str) -> Option<String> {
    let rest = selector.strip_prefix("pii:family:")?;
    Some(format!("pii:{rest}"))
}

pub(crate) fn is_reserved_detector_id(id: &str) -> bool {
    id == ADAPTER_ID || id.starts_with("pii:")
}

pub(crate) fn adapter(selection: &PiiSelection) -> Box<dyn Detector> {
    Box::new(PiiDomain::new(
        selection.clone(),
        vec![Box::new(pii_email::EmailFamily), network_address::family()],
    ))
}

#[path = "pii_network_address.rs"]
mod network_address;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum IdentityDomain {
    Email,
    PaymentCard,
    NetworkAddress,
    Iban,
    Phone,
    NationalId,
}

impl IdentityDomain {
    const ALL: &'static [Self] = &[
        Self::Email,
        Self::PaymentCard,
        Self::NetworkAddress,
        Self::Iban,
        Self::Phone,
        Self::NationalId,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::PaymentCard => "payment-card",
            Self::NetworkAddress => "network-address",
            Self::Iban => "iban",
            Self::Phone => "phone",
            Self::NationalId => "national-id",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityState {
    Unmatched,
    Established,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SensitivityState {
    NotEstablished,
    Sensitive,
    NonSensitive,
}

#[derive(Clone, Debug)]
struct Alternative {
    family_id: &'static str,
    domain: IdentityDomain,
    range: ByteRange,
    identity: IdentityState,
    identity_confidence: Confidence,
    identity_specificity: Specificity,
    sensitivity: SensitivityState,
    sensitivity_confidence: Confidence,
    sensitivity_specificity: Specificity,
    obfuscation: Obfuscation,
    reject_invisible_normalization: bool,
}

trait PiiFamily {
    fn id(&self) -> &'static str;
    fn context_requirement(&self) -> ContextRequirement;
    fn occurrence_exclusions(&self) -> &'static [&'static str];
    fn reinforced_sensitivity_confidence(&self) -> Option<Confidence> {
        None
    }
    fn reject_invisible_normalization(&self) -> bool {
        false
    }
    fn detect(&self, input: &str) -> Vec<Alternative>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContextRequirement {
    None,
    Reinforcing,
    RequiredForSensitiveClassification,
}

struct FamilyAlternative {
    alternative: Alternative,
    context_requirement: ContextRequirement,
    occurrence_exclusions: &'static [&'static str],
    reinforced_sensitivity_confidence: Option<Confidence>,
}

struct PiiDomain {
    _selection: PiiSelection,
    families: Vec<Box<dyn PiiFamily>>,
}

impl PiiDomain {
    fn new(selection: PiiSelection, mut families: Vec<Box<dyn PiiFamily>>) -> Self {
        families.retain(|family| selection.families.iter().any(|id| id == family.id()));
        families.sort_by_key(|family| family.id());
        Self {
            _selection: selection,
            families,
        }
    }
}

impl Detector for PiiDomain {
    fn id(&self) -> &str {
        ADAPTER_ID
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the arbitration stages stay visibly ordered"
    )]
    fn detect(&self, input: &str, _: &DetectorContext) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut grouped: BTreeMap<(usize, usize, IdentityDomain), Vec<Alternative>> =
            BTreeMap::new();
        let mut detected = Vec::new();
        for family in &self.families {
            for mut alternative in family.detect(input) {
                // The registry owns family identity. A family implementation
                // cannot impersonate another selected alternative.
                alternative.family_id = family.id();
                alternative.reject_invisible_normalization =
                    family.reject_invisible_normalization();
                detected.push(FamilyAlternative {
                    alternative,
                    context_requirement: family.context_requirement(),
                    occurrence_exclusions: family.occurrence_exclusions(),
                    reinforced_sensitivity_confidence: family.reinforced_sensitivity_confidence(),
                });
            }
        }
        let context_candidates: Vec<_> = detected
            .iter()
            .filter(|item| item.alternative.identity == IdentityState::Established)
            .map(|item| (item.alternative.range, item.alternative.domain))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let contexts = context_matches(input, &context_candidates);
        for mut item in detected {
            let alternative = &mut item.alternative;
            if alternative.identity == IdentityState::Established {
                let matches = context_candidates
                    .iter()
                    .position(|candidate| *candidate == (alternative.range, alternative.domain))
                    .map_or(&[][..], |index| contexts[index].as_slice());
                apply_context_contract(
                    alternative,
                    item.context_requirement,
                    matches,
                    item.occurrence_exclusions,
                    item.reinforced_sensitivity_confidence,
                );
                if alternative.identity == IdentityState::Established {
                    grouped
                        .entry((
                            alternative.range.start(),
                            alternative.range.end(),
                            alternative.domain,
                        ))
                        .or_default()
                        .push(item.alternative);
                }
            }
        }

        let mut output = Vec::new();
        for ((_start, _end, domain), mut alternatives) in grouped {
            alternatives.sort_by_key(|alternative| alternative.family_id);
            alternatives.dedup_by_key(|alternative| alternative.family_id);
            let sensitivity = if alternatives
                .iter()
                .any(|alt| alt.sensitivity == SensitivityState::Sensitive)
            {
                SensitivityState::Sensitive
            } else if alternatives
                .iter()
                .all(|alt| alt.sensitivity == SensitivityState::NonSensitive)
            {
                SensitivityState::NonSensitive
            } else {
                SensitivityState::NotEstablished
            };
            if sensitivity != SensitivityState::Sensitive {
                continue;
            }

            let type_name = if alternatives.len() == 1 {
                public_type(alternatives[0].family_id)
            } else {
                format!("pii_ambiguous_{}", domain.as_str().replace('-', "_"))
            };
            if type_name.len() > crate::MAX_IDENTIFIER_LENGTH || !is_identifier(&type_name) {
                return Err(DetectorFailure);
            }
            let identity_confidence = alternatives
                .iter()
                .map(|alt| alt.identity_confidence)
                .min()
                .ok_or(DetectorFailure)?;
            let sensitivity_confidence = alternatives
                .iter()
                .filter(|alt| alt.sensitivity == SensitivityState::Sensitive)
                .map(|alt| alt.sensitivity_confidence)
                .min()
                .ok_or(DetectorFailure)?;
            let confidence = identity_confidence.min(sensitivity_confidence);
            let identity_specificity = alternatives
                .iter()
                .map(|alt| alt.identity_specificity.min(Specificity::Structural))
                .min()
                .ok_or(DetectorFailure)?;
            let sensitivity_specificity = alternatives
                .iter()
                .filter(|alt| alt.sensitivity == SensitivityState::Sensitive)
                .map(|alt| alt.sensitivity_specificity.min(Specificity::Structural))
                .min()
                .ok_or(DetectorFailure)?;
            let specificity = identity_specificity.min(sensitivity_specificity);
            let range = alternatives[0].range;
            let governed_invisible_inside_range =
                input[range.start()..range.end()].chars().any(|character| {
                    let code_point = character as u32;
                    crate::invisible_table::INVISIBLE_RANGES
                        .iter()
                        .any(|(start, end)| (*start..=*end).contains(&code_point))
                });
            let obfuscation = if governed_invisible_inside_range
                || alternatives
                    .iter()
                    .any(|alt| alt.obfuscation == Obfuscation::InvisibleCharacters)
            {
                Obfuscation::InvisibleCharacters
            } else {
                Obfuscation::None
            };
            let mut candidate = Candidate::new(type_name, confidence, range)
                .with_specificity(specificity)
                .with_obfuscation(obfuscation);
            if alternatives
                .iter()
                .any(|alternative| alternative.reject_invisible_normalization)
            {
                candidate = candidate.reject_invisible_normalization();
            }
            output.push((domain, candidate));
        }
        output.sort_by(|(left_domain, left), (right_domain, right)| {
            (
                left.range().start(),
                left.range().end(),
                *left_domain,
                left.type_name(),
            )
                .cmp(&(
                    right.range().start(),
                    right.range().end(),
                    *right_domain,
                    right.type_name(),
                ))
        });
        Ok(output.into_iter().map(|(_, candidate)| candidate).collect())
    }
}

fn public_type(family_id: &str) -> String {
    let parts: Vec<&str> = family_id.split(':').collect();
    match parts.as_slice() {
        ["pii", "global", slug] => format!("pii_global_{}", slug.replace('-', "_")),
        ["pii", cc, slug] => format!("pii_jurisdiction_{cc}_{}", slug.replace('-', "_")),
        _ => String::new(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContextKind {
    FieldLabel,
    NaturalLanguageLabel,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContextLanguage {
    English,
    Korean,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ContextClass {
    Neutral,
    Positive,
    Negative,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ContextStrength {
    Ambiguous,
    HighSignal,
}

struct ContextEntry {
    id: &'static str,
    language: ContextLanguage,
    kind: ContextKind,
    class: ContextClass,
    strength: ContextStrength,
    domains: &'static [IdentityDomain],
    forms: &'static [&'static str],
}

impl ContextEntry {
    const fn new(
        id: &'static str,
        language: ContextLanguage,
        kind: ContextKind,
        class: ContextClass,
        strength: ContextStrength,
        domains: &'static [IdentityDomain],
        forms: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            language,
            kind,
            class,
            strength,
            domains,
            forms,
        }
    }
}

#[path = "pii_context_table.rs"]
mod pii_context_table;

fn normalize_context(value: &str, language: ContextLanguage) -> String {
    let visible = value.chars().filter(|character| {
        let code_point = *character as u32;
        !crate::invisible_table::INVISIBLE_RANGES
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&code_point))
    });
    let mut tokenized = String::new();
    let mut in_separator = false;
    for character in visible.nfc().map(|character| {
        if language == ContextLanguage::English && character.is_ascii_uppercase() {
            character.to_ascii_lowercase()
        } else {
            character
        }
    }) {
        let separator = character.is_whitespace() || matches!(character, '_' | '-' | ':' | '=');
        if separator {
            if !in_separator {
                tokenized.push(' ');
                in_separator = true;
            }
        } else {
            tokenized.push(character);
            in_separator = false;
        }
    }
    tokenized
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ContextMatch {
    entry_id: &'static str,
    class: ContextClass,
    strength: ContextStrength,
}

fn apply_context_contract(
    alternative: &mut Alternative,
    requirement: ContextRequirement,
    matches: &[ContextMatch],
    occurrence_exclusions: &[&str],
    reinforced_sensitivity_confidence: Option<Confidence>,
) {
    let has_authoritative_positive = matches.iter().any(|context| {
        context.class == ContextClass::Positive && context.strength == ContextStrength::HighSignal
    });
    if alternative.sensitivity != SensitivityState::NonSensitive {
        match requirement {
            ContextRequirement::RequiredForSensitiveClassification => {
                alternative.sensitivity = if has_authoritative_positive {
                    SensitivityState::Sensitive
                } else {
                    SensitivityState::NotEstablished
                };
                alternative.sensitivity_specificity = Specificity::Contextual;
            }
            ContextRequirement::Reinforcing if has_authoritative_positive => {
                if let Some(reinforced) = reinforced_sensitivity_confidence {
                    alternative.sensitivity_confidence =
                        alternative.sensitivity_confidence.max(reinforced);
                }
            }
            ContextRequirement::None | ContextRequirement::Reinforcing => {}
        }
    }
    alternative.sensitivity =
        apply_named_negative(alternative.sensitivity, matches, occurrence_exclusions);
}

fn apply_named_negative(
    positive_result: SensitivityState,
    matches: &[ContextMatch],
    occurrence_exclusions: &[&str],
) -> SensitivityState {
    if matches.iter().any(|context| {
        context.class == ContextClass::Negative
            && context.strength == ContextStrength::HighSignal
            && occurrence_exclusions.contains(&context.entry_id)
    }) {
        SensitivityState::NonSensitive
    } else {
        positive_result
    }
}

#[derive(Clone, Copy)]
struct ContextOccurrence<'a> {
    entry: &'a ContextEntry,
    side: usize,
    start: usize,
    end: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded association rules are one ordered contract"
)]
fn context_matches(
    input: &str,
    candidates: &[(ByteRange, IdentityDomain)],
) -> Vec<Vec<ContextMatch>> {
    let mut result = vec![Vec::new(); candidates.len()];
    for (candidate_index, (range, domain)) in candidates.iter().copied().enumerate() {
        let (line_start, line_end) = logical_line_bounds(input, range);
        let before_barrier = candidates
            .iter()
            .enumerate()
            .filter(|(index, (other, _))| {
                *index != candidate_index
                    && other.end() <= range.start()
                    && other.end() >= line_start
            })
            .map(|(_, (other, _))| other.end())
            .max()
            .unwrap_or(line_start);
        let after_barrier = candidates
            .iter()
            .enumerate()
            .filter(|(index, (other, _))| {
                *index != candidate_index
                    && other.start() >= range.end()
                    && other.start() <= line_end
            })
            .map(|(_, (other, _))| other.start())
            .min()
            .unwrap_or(line_end);
        let mut found = Vec::new();
        for entry in pii_context_table::CONTEXT_ENTRIES
            .iter()
            .filter(|entry| entry.domains.contains(&domain))
        {
            let before = normalize_context(&input[before_barrier..range.start()], entry.language);
            let after = normalize_context(&input[range.end()..after_barrier], entry.language);
            let before_offset =
                normalize_context(&input[line_start..before_barrier], entry.language)
                    .chars()
                    .count();
            let after_offset = normalize_context(&input[line_start..range.end()], entry.language)
                .chars()
                .count();
            for form in entry.forms {
                for (side, view) in [(0usize, before.as_str()), (1usize, after.as_str())] {
                    if entry.kind == ContextKind::FieldLabel && side == 1 {
                        continue;
                    }
                    let normalized_form = normalize_context(form, entry.language);
                    for (position, _) in view.match_indices(&normalized_form) {
                        let byte_end = position + normalized_form.len();
                        let boundary_ok = view[..position]
                            .chars()
                            .next_back()
                            .is_none_or(|character| is_context_boundary(entry.kind, character))
                            && view[byte_end..]
                                .chars()
                                .next()
                                .is_none_or(|character| is_context_boundary(entry.kind, character));
                        if !boundary_ok {
                            continue;
                        }
                        let distance = if side == 0 {
                            view[byte_end..].chars().count()
                        } else {
                            view[..position].chars().count()
                        };
                        let limit = if entry.kind == ContextKind::FieldLabel {
                            16
                        } else {
                            64
                        };
                        if distance > limit {
                            continue;
                        }
                        if entry.kind == ContextKind::FieldLabel
                            && !view[byte_end..].chars().all(is_field_gap)
                        {
                            continue;
                        }
                        let local_start = view[..position].chars().count();
                        let scalar_span = normalized_form.chars().count();
                        let occurrence_start = if side == 0 {
                            before_offset
                        } else {
                            after_offset
                        } + local_start;
                        let occurrence_end = occurrence_start + scalar_span;
                        if equidistant_from_candidates(
                            input,
                            entry.language,
                            line_start,
                            line_end,
                            occurrence_start,
                            occurrence_end,
                            candidates,
                        ) {
                            continue;
                        }
                        found.push(ContextOccurrence {
                            entry,
                            side,
                            start: occurrence_start,
                            end: occurrence_end,
                        });
                    }
                }
            }
        }
        found.sort_by(|a, b| {
            (b.end - b.start)
                .cmp(&(a.end - a.start))
                .then_with(|| b.entry.strength.cmp(&a.entry.strength))
                .then_with(|| b.entry.class.cmp(&a.entry.class))
                .then_with(|| a.entry.id.as_bytes().cmp(b.entry.id.as_bytes()))
                .then_with(|| a.start.cmp(&b.start))
        });
        let mut accepted_occurrences: Vec<ContextOccurrence<'_>> = Vec::new();
        let mut selected: Vec<ContextMatch> = Vec::new();
        for occurrence in found {
            if accepted_occurrences.iter().any(|accepted| {
                accepted.side == occurrence.side
                    && accepted.start < occurrence.end
                    && occurrence.start < accepted.end
            }) {
                continue;
            }
            accepted_occurrences.push(occurrence);
            if selected
                .iter()
                .all(|item| item.entry_id != occurrence.entry.id)
            {
                selected.push(ContextMatch {
                    entry_id: occurrence.entry.id,
                    class: occurrence.entry.class,
                    strength: occurrence.entry.strength,
                });
            }
        }
        result[candidate_index] = selected;
    }
    result
}

fn is_context_boundary(kind: ContextKind, character: char) -> bool {
    character.is_whitespace()
        || (kind == ContextKind::FieldLabel && matches!(character, '"' | '\''))
}
fn is_field_gap(character: char) -> bool {
    character.is_whitespace() || matches!(character, '"' | '\'')
}

fn is_logical_line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{001C}'
            | '\u{001D}'
            | '\u{001E}'
            | '\u{0085}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

fn logical_line_bounds(input: &str, range: ByteRange) -> (usize, usize) {
    let mut line_start = 0;
    for (index, character) in input[..range.start()].char_indices() {
        if is_logical_line_break(character) {
            line_start = index + character.len_utf8();
        }
    }
    let line_end = input[range.end()..]
        .char_indices()
        .find(|(_, character)| is_logical_line_break(*character))
        .map_or(input.len(), |(index, _)| range.end() + index);
    (line_start, line_end)
}

fn equidistant_from_candidates(
    input: &str,
    language: ContextLanguage,
    line_start: usize,
    line_end: usize,
    occurrence_start: usize,
    occurrence_end: usize,
    candidates: &[(ByteRange, IdentityDomain)],
) -> bool {
    let mut distances = Vec::new();
    for (range, _) in candidates {
        if range.start() < line_start || range.end() > line_end {
            continue;
        }
        let candidate_start = normalize_context(&input[line_start..range.start()], language)
            .chars()
            .count();
        let candidate_end = candidate_start
            + normalize_context(&input[range.start()..range.end()], language)
                .chars()
                .count();
        let distance = if candidate_end <= occurrence_start {
            occurrence_start - candidate_end
        } else {
            candidate_start.saturating_sub(occurrence_end)
        };
        distances.push(distance);
    }
    let Some(nearest) = distances.iter().min() else {
        return false;
    };
    distances
        .iter()
        .filter(|distance| *distance == nearest)
        .count()
        > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SyntheticFamily {
        id: &'static str,
        context_requirement: ContextRequirement,
        occurrence_exclusions: &'static [&'static str],
        alternatives: Vec<Alternative>,
    }
    impl PiiFamily for SyntheticFamily {
        fn id(&self) -> &'static str {
            self.id
        }
        fn context_requirement(&self) -> ContextRequirement {
            self.context_requirement
        }
        fn occurrence_exclusions(&self) -> &'static [&'static str] {
            self.occurrence_exclusions
        }
        fn detect(&self, _: &str) -> Vec<Alternative> {
            self.alternatives.clone()
        }
    }

    struct MarkerFamily;
    impl PiiFamily for MarkerFamily {
        fn id(&self) -> &'static str {
            "pii:global:email"
        }
        fn context_requirement(&self) -> ContextRequirement {
            ContextRequirement::RequiredForSensitiveClassification
        }
        fn occurrence_exclusions(&self) -> &'static [&'static str] {
            &["en-example-label"]
        }
        fn detect(&self, input: &str) -> Vec<Alternative> {
            input
                .match_indices("TEST")
                .map(|(start, _)| Alternative {
                    family_id: self.id(),
                    domain: IdentityDomain::Email,
                    range: ByteRange::new(start, start + 4).unwrap(),
                    identity: IdentityState::Established,
                    identity_confidence: Confidence::High,
                    identity_specificity: Specificity::Structural,
                    sensitivity: SensitivityState::NotEstablished,
                    sensitivity_confidence: Confidence::High,
                    sensitivity_specificity: Specificity::Structural,
                    obfuscation: Obfuscation::None,
                    reject_invisible_normalization: false,
                })
                .collect()
        }
    }

    fn family(
        id: &'static str,
        context_requirement: ContextRequirement,
        occurrence_exclusions: &'static [&'static str],
        alternatives: Vec<Alternative>,
    ) -> Box<dyn PiiFamily> {
        Box::new(SyntheticFamily {
            id,
            context_requirement,
            occurrence_exclusions,
            alternatives,
        })
    }

    fn selected(ids: &[&str]) -> PiiSelection {
        let selectors: Vec<String> = ids
            .iter()
            .map(|id| format!("pii:family:{}", id.strip_prefix("pii:").unwrap()))
            .collect();
        let selector_refs: Vec<&str> = selectors.iter().map(String::as_str).collect();
        PiiSelection::parse_with_catalog(&selector_refs, ids, ids).unwrap()
    }

    fn alt(
        id: &'static str,
        sensitivity: SensitivityState,
        identity: Confidence,
        sensitivity_confidence: Confidence,
    ) -> Alternative {
        Alternative {
            family_id: id,
            domain: IdentityDomain::NationalId,
            range: ByteRange::new(0, 4).unwrap(),
            identity: IdentityState::Established,
            identity_confidence: identity,
            identity_specificity: Specificity::Structural,
            sensitivity,
            sensitivity_confidence,
            sensitivity_specificity: Specificity::Contextual,
            obfuscation: Obfuscation::None,
            reject_invisible_normalization: false,
        }
    }

    #[test]
    fn selectors_canonicalize_close_and_distinguish_failures() {
        let selected = PiiSelection::parse_with_catalog(
            &["pii", "pii:global", "pii:family:us:ssn"],
            KNOWN_FAMILIES,
            &["pii:global:email", "pii:us:ssn"],
        )
        .unwrap();
        assert_eq!(selected.selectors, ["pii:family:us:ssn", "pii:global"]);
        assert_eq!(selected.families, ["pii:global:email", "pii:us:ssn"]);
        assert_eq!(
            PiiSelection::parse(&["PII"]).unwrap_err().code(),
            SecretScanErrorCode::PiiSelectorInvalid
        );
        assert_eq!(
            PiiSelection::parse(&["pii:kr"]).unwrap_err().code(),
            SecretScanErrorCode::PiiSelectorUnsupported
        );
        assert_eq!(
            PiiSelection::parse(&["pii:us"]).unwrap_err().code(),
            SecretScanErrorCode::PiiSelectorUnavailable
        );
    }

    #[test]
    fn activation_identity_is_canonical_and_off_is_distinct() {
        assert_eq!(
            PiiSelection::default().activation_identity(crate::Profile::Full),
            "credentials=full;selectors=off;families=;vocabulary=pii-context/v1"
        );
        let active = PiiSelection::parse(&["pii", "pii:global"]).unwrap();
        assert_eq!(
            active.activation_identity(crate::Profile::Common),
            "credentials=common;selectors=pii:global;families=pii:global:email,pii:global:network-address;vocabulary=pii-context/v1"
        );
    }

    #[test]
    fn arbitration_joins_identity_sensitivity_confidence_and_public_types() {
        let families: Vec<Box<dyn PiiFamily>> = vec![
            family(
                "pii:us:ssn",
                ContextRequirement::None,
                &[],
                vec![alt(
                    "pii:us:ssn",
                    SensitivityState::Sensitive,
                    Confidence::High,
                    Confidence::Medium,
                )],
            ),
            family(
                "pii:global:us-ssn",
                ContextRequirement::Reinforcing,
                &[],
                vec![alt(
                    "pii:global:us-ssn",
                    SensitivityState::NotEstablished,
                    Confidence::Medium,
                    Confidence::High,
                )],
            ),
        ];
        let candidates = PiiDomain::new(selected(&["pii:us:ssn", "pii:global:us-ssn"]), families)
            .detect("TEST", &DetectorContext::new(4))
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "pii_ambiguous_national_id");
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
        assert_eq!(public_type("pii:global:us-ssn"), "pii_global_us_ssn");
        assert_eq!(public_type("pii:us:ssn"), "pii_jurisdiction_us_ssn");
        assert_eq!(
            public_type("pii:global:ambiguous-national-id"),
            "pii_global_ambiguous_national_id"
        );
    }

    #[test]
    fn sensitivity_join_suppresses_non_sensitive_and_unestablished_groups() {
        for alternatives in [
            vec![alt(
                "pii:global:email",
                SensitivityState::NonSensitive,
                Confidence::High,
                Confidence::High,
            )],
            vec![alt(
                "pii:global:email",
                SensitivityState::NotEstablished,
                Confidence::High,
                Confidence::High,
            )],
        ] {
            let id = alternatives[0].family_id;
            let families: Vec<Box<dyn PiiFamily>> =
                vec![family(id, ContextRequirement::None, &[], alternatives)];
            assert!(
                PiiDomain::new(selected(&[id]), families)
                    .detect("TEST", &DetectorContext::new(4))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn selection_closure_controls_family_execution_and_off_is_absolute() {
        let make_families = || {
            vec![family(
                "pii:global:email",
                ContextRequirement::None,
                &[],
                vec![Alternative {
                    family_id: "pii:global:email",
                    domain: IdentityDomain::Email,
                    range: ByteRange::new(0, 4).unwrap(),
                    identity: IdentityState::Established,
                    identity_confidence: Confidence::High,
                    identity_specificity: Specificity::Structural,
                    sensitivity: SensitivityState::Sensitive,
                    sensitivity_confidence: Confidence::High,
                    sensitivity_specificity: Specificity::Structural,
                    obfuscation: Obfuscation::None,
                    reject_invisible_normalization: false,
                }],
            )]
        };
        assert!(
            PiiDomain::new(PiiSelection::default(), make_families())
                .detect("TEST", &DetectorContext::new(4))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            PiiDomain::new(selected(&["pii:global:email"]), make_families())
                .detect("TEST", &DetectorContext::new(4))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn adapter_enforces_required_context_and_declared_negative_exclusions() {
        let scan = |input: &str, exclusions: &'static [&'static str]| {
            let start = input.find("TEST").unwrap();
            let alternatives = vec![Alternative {
                family_id: "pii:global:email",
                domain: IdentityDomain::Email,
                range: ByteRange::new(start, start + 4).unwrap(),
                identity: IdentityState::Established,
                identity_confidence: Confidence::High,
                identity_specificity: Specificity::Structural,
                sensitivity: SensitivityState::NotEstablished,
                sensitivity_confidence: Confidence::High,
                sensitivity_specificity: Specificity::Structural,
                obfuscation: Obfuscation::None,
                reject_invisible_normalization: false,
            }];
            PiiDomain::new(
                selected(&["pii:global:email"]),
                vec![family(
                    "pii:global:email",
                    ContextRequirement::RequiredForSensitiveClassification,
                    exclusions,
                    alternatives,
                )],
            )
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
        };

        assert!(scan("TEST", &[]).is_empty());
        assert!(scan("contact TEST", &[]).is_empty());
        let positive = scan("email: TEST", &[]);
        assert_eq!(positive.len(), 1);
        assert_eq!(positive[0].specificity(), Some(Specificity::Contextual));
        assert!(scan("contact details documentation TEST", &["en-example-label"]).is_empty());
        assert_eq!(scan("contact details documentation TEST", &[]).len(), 1);

        let matches = vec![ContextMatch {
            entry_id: "en-email-field",
            class: ContextClass::Positive,
            strength: ContextStrength::HighSignal,
        }];
        let mut whole_candidate_negative = alt(
            "pii:global:email",
            SensitivityState::NonSensitive,
            Confidence::High,
            Confidence::High,
        );
        apply_context_contract(
            &mut whole_candidate_negative,
            ContextRequirement::RequiredForSensitiveClassification,
            &matches,
            &[],
            None,
        );
        assert_eq!(
            whole_candidate_negative.sensitivity,
            SensitivityState::NonSensitive
        );

        let mut reinforcing = alt(
            "pii:global:email",
            SensitivityState::Sensitive,
            Confidence::High,
            Confidence::Low,
        );
        apply_context_contract(
            &mut reinforcing,
            ContextRequirement::Reinforcing,
            &matches,
            &[],
            Some(Confidence::High),
        );
        assert_eq!(reinforcing.sensitivity_confidence, Confidence::High);
    }

    #[test]
    fn synthetic_registry_whole_input_and_every_chunk_partition_are_equal() {
        use crate::{
            DefaultPolicy, IncrementalLimits, IncrementalPolicy, IncrementalSanitizer,
            PlaceholderFormatter, default_placeholder_formatter, scan_and_redact,
        };

        let input = "email: TEST\n";
        let make_registry = || {
            crate::DetectorRegistry::with_internal_test_detector(Box::new(PiiDomain::new(
                selected(&["pii:global:email"]),
                vec![Box::new(MarkerFamily)],
            )))
        };
        let expected = scan_and_redact(
            input,
            &make_registry(),
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        assert_eq!(expected.findings().len(), 1);
        assert_eq!(expected.findings()[0].detector(), ADAPTER_ID);

        for split in input
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(input.len()))
        {
            let limits = IncrementalLimits::new(1_024, 512, 128, 256).unwrap();
            let policy: Box<dyn IncrementalPolicy> = Box::new(DefaultPolicy);
            let formatter: Box<dyn PlaceholderFormatter> = Box::new(default_placeholder_formatter);
            let mut session =
                IncrementalSanitizer::from_registry(make_registry(), limits, policy, formatter);
            let first = session.append(&input[..split]).unwrap();
            let second = session.append(&input[split..]).unwrap();
            let final_result = session.finalize().unwrap();
            let text = format!("{}{}{}", first.text(), second.text(), final_result.text());
            let findings: Vec<_> = first
                .findings()
                .iter()
                .chain(second.findings())
                .chain(final_result.findings())
                .collect();
            assert_eq!(text, expected.text(), "split {split}");
            assert_eq!(findings.len(), expected.findings().len(), "split {split}");
            for (actual, expected) in findings.into_iter().zip(expected.findings()) {
                assert_eq!(actual.id(), expected.id(), "split {split}");
                assert_eq!(actual.type_name(), expected.type_name(), "split {split}");
                assert_eq!(actual.detector(), expected.detector(), "split {split}");
                assert_eq!(actual.confidence(), expected.confidence(), "split {split}");
                assert_eq!(actual.action(), expected.action(), "split {split}");
                assert_eq!(actual.range(), expected.range(), "split {split}");
            }
        }
    }

    #[test]
    #[allow(
        clippy::unicode_not_nfc,
        reason = "the fixture deliberately contains Korean NFD text"
    )]
    fn context_matches_english_korean_normalization_barriers_and_substrings() {
        let cases = [
            ("\"EMAIL\" = TEST", IdentityDomain::Email, "en-email-field"),
            ("이메일: TEST", IdentityDomain::Email, "ko-email-field"),
            ("예시 TEST", IdentityDomain::NationalId, "ko-example-label"),
        ];
        for (input, domain, expected) in cases {
            let start = input.find("TEST").unwrap();
            let range = ByteRange::new(start, start + 4).unwrap();
            let matches = context_matches(input, &[(range, domain)]);
            assert!(matches[0].iter().any(|item| item.entry_id == expected));
        }
        let substring = context_matches(
            "myemailvalue TEST",
            &[(ByteRange::new(13, 17).unwrap(), IdentityDomain::Email)],
        );
        assert!(substring[0].is_empty());
        let barriers = context_matches(
            "contact AAAA BBBB",
            &[
                (ByteRange::new(8, 12).unwrap(), IdentityDomain::PaymentCard),
                (ByteRange::new(13, 17).unwrap(), IdentityDomain::Email),
            ],
        );
        assert!(barriers.iter().all(Vec::is_empty));
        assert_eq!(
            normalize_context("e\u{301}", ContextLanguage::English),
            normalize_context("é", ContextLanguage::English)
        );
        assert_eq!(normalize_context("ASCII", ContextLanguage::Korean), "ASCII");

        let quoted_natural = context_matches(
            "\"contact details\" TEST",
            &[(ByteRange::new(18, 22).unwrap(), IdentityDomain::Email)],
        );
        assert!(quoted_natural[0].is_empty());
        let separate_line = context_matches(
            "contact details\rTEST",
            &[(ByteRange::new(16, 20).unwrap(), IdentityDomain::Email)],
        );
        assert!(separate_line[0].is_empty());
    }

    #[test]
    fn named_negative_wins_after_positive_but_ambiguous_context_has_no_authority() {
        let input = "contact details documentation TEST";
        let start = input.find("TEST").unwrap();
        let matches = context_matches(
            input,
            &[(
                ByteRange::new(start, start + 4).unwrap(),
                IdentityDomain::Email,
            )],
        );
        assert!(
            matches[0]
                .iter()
                .any(|item| item.class == ContextClass::Positive)
        );
        assert!(
            matches[0]
                .iter()
                .any(|item| item.class == ContextClass::Negative
                    && item.strength == ContextStrength::HighSignal)
        );
        assert!(
            matches[0]
                .iter()
                .any(|item| item.entry_id == "en-contact-details-label")
        );
        assert!(
            matches[0]
                .iter()
                .all(|item| item.entry_id != "en-contact-label")
        );
        assert_eq!(
            apply_named_negative(
                SensitivityState::Sensitive,
                &matches[0],
                &["en-example-label"]
            ),
            SensitivityState::NonSensitive
        );
        assert_eq!(
            apply_named_negative(
                SensitivityState::Sensitive,
                &matches[0],
                &["ko-example-label"]
            ),
            SensitivityState::Sensitive
        );
        let ambiguous = context_matches(
            "contact TEST",
            &[(ByteRange::new(8, 12).unwrap(), IdentityDomain::Email)],
        );
        assert!(
            ambiguous[0]
                .iter()
                .all(|item| item.strength == ContextStrength::Ambiguous)
        );
        assert_eq!(
            apply_named_negative(
                SensitivityState::Sensitive,
                &ambiguous[0],
                &["en-contact-label"]
            ),
            SensitivityState::Sensitive
        );
    }

    #[test]
    fn equidistant_context_associates_with_neither_candidate() {
        // Candidate barriers prevent either side from reaching through the
        // other candidate; the central context is therefore unassociated.
        let matches = context_matches(
            "AAAA contact BBBB",
            &[
                (ByteRange::new(0, 4).unwrap(), IdentityDomain::Email),
                (ByteRange::new(13, 17).unwrap(), IdentityDomain::Email),
            ],
        );
        assert!(matches.iter().all(Vec::is_empty));
        let mixed_domains = context_matches(
            "AAAA contact BBBB",
            &[
                (ByteRange::new(0, 4).unwrap(), IdentityDomain::Email),
                (ByteRange::new(13, 17).unwrap(), IdentityDomain::PaymentCard),
            ],
        );
        assert!(mixed_domains.iter().all(Vec::is_empty));
    }

    #[test]
    fn unmatched_alternatives_are_discarded_and_invisible_points_are_reported() {
        let mut unmatched = alt(
            "pii:global:email",
            SensitivityState::Sensitive,
            Confidence::High,
            Confidence::High,
        );
        unmatched.identity = IdentityState::Unmatched;
        let families: Vec<Box<dyn PiiFamily>> = vec![family(
            unmatched.family_id,
            ContextRequirement::None,
            &[],
            vec![unmatched],
        )];
        assert!(
            PiiDomain::new(selected(&["pii:global:email"]), families)
                .detect("TEST", &DetectorContext::new(4))
                .unwrap()
                .is_empty()
        );

        let mut obfuscated = alt(
            "pii:global:email",
            SensitivityState::Sensitive,
            Confidence::High,
            Confidence::High,
        );
        obfuscated.range = ByteRange::new(0, "TE\u{200b}ST".len()).unwrap();
        let id = obfuscated.family_id;
        let families: Vec<Box<dyn PiiFamily>> =
            vec![family(id, ContextRequirement::None, &[], vec![obfuscated])];
        let candidates = PiiDomain::new(selected(&[id]), families)
            .detect("TE\u{200b}ST", &DetectorContext::new("TE\u{200b}ST".len()))
            .unwrap();
        assert_eq!(
            candidates[0].obfuscation(),
            Obfuscation::InvisibleCharacters
        );
    }
}
