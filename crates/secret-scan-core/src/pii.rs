//! Internal `pii-v1` activation, arbitration, and context substrate.
//!
//! Production PII families are registered here only after their family
//! contract has been reviewed. The adapter remains the single detector slot.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use unicode_normalization::UnicodeNormalization;

use crate::error::{DetectorFailure, SecretScanError, SecretScanErrorCode};
use crate::types::{
    ByteRange, Candidate, Confidence, Detector, DetectorContext, Obfuscation, Specificity,
    is_identifier,
};

const ADAPTER_ID: &str = "pii-domain";
const KNOWN_JURISDICTIONS: &[&str] = &["us"];
const AVAILABLE_FAMILIES: &[&str] = &[
    "pii:global:email",
    "pii:global:iban",
    "pii:global:network-address",
    "pii:global:payment-card",
    "pii:global:phone",
    "pii:us:ssn",
];
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
#[path = "pii/pii_iban.rs"]
mod pii_iban;
#[path = "pii/pii_payment_card.rs"]
mod pii_payment_card;
#[path = "pii/pii_phone.rs"]
mod pii_phone;
#[path = "pii/pii_us_ssn.rs"]
mod pii_us_ssn;

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
    Box::new(production_domain(selection.clone()))
}

/// The production families behind `selection`, the one arbitration the
/// public adapter and the maintainer-local [`IdentityEvaluator`] share.
fn production_domain(selection: PiiSelection) -> PiiDomain {
    PiiDomain::new(
        selection,
        vec![
            Box::new(pii_email::EmailFamily),
            Box::new(pii_iban::IbanFamily),
            network_address::family(),
            Box::new(pii_payment_card::PaymentCardFamily),
            Box::new(pii_phone::PhoneFamily),
            Box::new(pii_us_ssn::UsSsnFamily),
        ],
    )
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

    /// Every alternative the selected families report for `input`, in
    /// family then detection order, after the context contract has been
    /// applied to each established one. The context contract can still
    /// demote an alternative's identity, so a caller that joins alternatives
    /// reads `identity` afterwards.
    fn contextualized(&self, input: &str) -> Vec<Alternative> {
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
        let contexts = if context_candidates.is_empty() {
            Vec::new()
        } else {
            ContextVocabulary::shared().matches(input, &context_candidates)
        };
        let mut contextualized = Vec::with_capacity(detected.len());
        for mut item in detected {
            let alternative = &mut item.alternative;
            if alternative.identity == IdentityState::Established {
                // `context_candidates` is sorted and distinct.
                let matches = context_candidates
                    .binary_search(&(alternative.range, alternative.domain))
                    .map_or(&[][..], |index| contexts[index].as_slice());
                apply_context_contract(
                    alternative,
                    item.context_requirement,
                    matches,
                    item.occurrence_exclusions,
                    item.reinforced_sensitivity_confidence,
                );
            }
            contextualized.push(item.alternative);
        }
        contextualized
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
        for alternative in self.contextualized(input) {
            if alternative.identity == IdentityState::Established {
                grouped
                    .entry((
                        alternative.range.start(),
                        alternative.range.end(),
                        alternative.domain,
                    ))
                    .or_default()
                    .push(alternative);
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

/// Identity of the JSON Lines format `examples/pii_identity_evaluation.rs`
/// writes from [`IdentityEvaluator`]. A change to a field or its meaning is a
/// new identity.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "read only by examples/pii_identity_evaluation.rs, which compiles the core source as its own crate"
    )
)]
pub(crate) const IDENTITY_EVALUATION_FORMAT: &str = "redact-secret/pii-identity-evaluation/1";

/// The joined identity and sensitivity of one caller-authored candidate
/// range, as the closed wire words of `redact-secret/pii-identity-evaluation/1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IdentityOutcome {
    /// `established` or `unmatched`.
    pub(crate) identity: &'static str,
    /// `sensitive`, `non-sensitive` or `not-established`.
    pub(crate) sensitivity: &'static str,
}

/// Maintainer-local identity/sensitivity evaluation of one production PII
/// family (issue #910).
///
/// It runs the family's own detector, context vocabulary and join through
/// the same [`PiiDomain`] the public adapter uses, and reports, for one
/// caller-authored candidate range, the alternative the join keeps for
/// exactly that range: the first established alternative, in detection
/// order, whose range equals the candidate. That alternative's sensitivity
/// is the one the public adapter would act on, so `sensitive` here is the
/// adapter emitting a candidate for that range. The outcome carries only the
/// two closed words, never a confidence, specificity, obfuscation, other
/// range or any input byte.
///
/// No public item reaches this type. Its only non-test caller is
/// `examples/pii_identity_evaluation.rs`, which compiles this source as its
/// own crate, so the core library's own build sees no caller.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "called only by examples/pii_identity_evaluation.rs, which compiles the core source as its own crate"
    )
)]
pub(crate) struct IdentityEvaluator {
    family: &'static str,
    activation_identity: String,
    domain: PiiDomain,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "called only by examples/pii_identity_evaluation.rs, which compiles the core source as its own crate"
    )
)]
impl IdentityEvaluator {
    /// The evaluator for exactly `family`, one of the production families
    /// compiled into this artifact (`pii:global:email`, `pii:us:ssn`, …),
    /// under the `full` credential profile's activation identity. `None`
    /// for any other string.
    pub(crate) fn new(family: &str) -> Option<Self> {
        let family = AVAILABLE_FAMILIES
            .iter()
            .copied()
            .find(|id| *id == family)?;
        let selector = format!("pii:family:{}", family.strip_prefix("pii:")?);
        let selection = PiiSelection::parse(&[selector.as_str()]).ok()?;
        if selection.families != [family] {
            return None;
        }
        let activation_identity = selection.activation_identity(crate::Profile::Full);
        Some(Self {
            family,
            activation_identity,
            domain: production_domain(selection),
        })
    }

    /// The family id this evaluator runs.
    pub(crate) const fn family(&self) -> &'static str {
        self.family
    }

    /// The canonical activation identity of the equivalent public registry
    /// (`DetectorRegistry::with_built_in_and_pii` with this one family).
    pub(crate) fn activation_identity(&self) -> &str {
        &self.activation_identity
    }

    /// The context vocabulary version the family's join reads.
    pub(crate) const fn vocabulary() -> &'static str {
        pii_context_table::CONTEXT_VERSION
    }

    /// The outcome for `candidate`, a caller-authored UTF-8 byte range of
    /// `input`. `None`, a range no alternative has, or a range that is not
    /// even a valid slice of `input` reports `unmatched` / `not-established`.
    ///
    /// The family runs where the public pipeline runs it
    /// (`crate::pipeline::detect`): on the scan copy with governed invisible
    /// code points removed, its ranges translated back into `input`. An
    /// alternative the pipeline drops before overlap resolution (a family
    /// that rejects invisible normalization touching a removed run, or a
    /// known vendor placeholder literal) is no alternative here either.
    pub(crate) fn evaluate(
        &self,
        input: &str,
        candidate: Option<(usize, usize)>,
    ) -> IdentityOutcome {
        let unmatched = IdentityOutcome {
            identity: "unmatched",
            sensitivity: "not-established",
        };
        let Some((start, end)) = candidate else {
            return unmatched;
        };
        let normalized = crate::normalize::NormalizedInput::new(input);
        let scanned = normalized.text();
        self.domain
            .contextualized(scanned)
            .into_iter()
            .find(|alternative| {
                alternative.identity == IdentityState::Established
                    && normalized
                        .to_original(alternative.range)
                        .is_some_and(|range| range.start() == start && range.end() == end)
            })
            .filter(|alternative| {
                let range = alternative.range;
                let dropped_by_pipeline = (alternative.reject_invisible_normalization
                    && normalized.touches_removed_run(range))
                    || (range.is_char_aligned_in(scanned)
                        && crate::pipeline::is_known_vendor_placeholder_literal(
                            &scanned[range.start()..range.end()],
                        ));
                !dropped_by_pipeline
            })
            .map_or(unmatched, |alternative| IdentityOutcome {
                identity: "established",
                sensitivity: match alternative.sensitivity {
                    SensitivityState::Sensitive => "sensitive",
                    SensitivityState::NonSensitive => "non-sensitive",
                    SensitivityState::NotEstablished => "not-established",
                },
            })
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
    #[allow(
        dead_code,
        reason = "reviewed contract metadata; pii-context/v2 matching no longer depends on the language"
    )]
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

/// The context-only comparison view: governed invisible code points removed,
/// NFC, ASCII case folded, and every separator run collapsed to one space.
/// `pii-context/v2` folds ASCII case in every language, so the ASCII part of
/// a Korean form (`ip 주소`, `클라이언트 ip`) matches in any case (issue #927);
/// Hangul has no case and is unchanged.
fn normalize_context(value: &str) -> String {
    let mut tokenized = String::new();
    let mut in_separator = false;
    for character in visible_nfc(value).map(|character| character.to_ascii_lowercase()) {
        let separator = is_context_separator(character);
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

/// `value` with governed invisible code points removed, in NFC. The context
/// view and its running scalar count ([`ContextScalars`]) share this one
/// iterator type, so the normalization code is instantiated once.
fn visible_nfc(value: &str) -> impl Iterator<Item = char> + '_ {
    value.chars().filter(is_visible).nfc()
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "a named `Iterator::filter` predicate, so both callers share one iterator type"
)]
fn is_visible(character: &char) -> bool {
    !is_governed_invisible(*character)
}

fn is_governed_invisible(character: char) -> bool {
    let code_point = character as u32;
    crate::invisible_table::INVISIBLE_RANGES
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&code_point))
}

/// A separator of the context-only view, after ASCII case folding.
fn is_context_separator(character: char) -> bool {
    character.is_whitespace() || matches!(character, '_' | '-' | ':' | '=')
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

/// One vocabulary form in the context-only comparison view (issue #902).
struct NormalizedForm {
    text: String,
    scalars: usize,
}

/// The generated `pii-context/v2` vocabulary with every form already passed
/// through [`normalize_context`], in table then form order.
struct ContextVocabulary {
    entries: Vec<(&'static ContextEntry, Vec<NormalizedForm>)>,
}

/// The vocabulary every adapter in the process shares, normalized the first
/// time a candidate needs it rather than when a registry or session is built.
static VOCABULARY: OnceLock<ContextVocabulary> = OnceLock::new();

impl ContextVocabulary {
    fn new() -> Self {
        let entries = pii_context_table::CONTEXT_ENTRIES
            .iter()
            .map(|entry| {
                let forms = entry
                    .forms
                    .iter()
                    .map(|form| {
                        let text = normalize_context(form);
                        let scalars = text.chars().count();
                        NormalizedForm { text, scalars }
                    })
                    .collect();
                (entry, forms)
            })
            .collect();
        Self { entries }
    }

    fn shared() -> &'static Self {
        VOCABULARY.get_or_init(Self::new)
    }

    /// The context entries each candidate associates with, index for index.
    ///
    /// Positions are the scalar offsets of the context-only view of the
    /// candidate's logical line, exactly as `pii-context/v2` defines them.
    /// Candidates are grouped by logical line once, so the barriers, the
    /// line offsets and the equidistance rule cost O(log k) per candidate or
    /// context occurrence instead of a rescan of the input or of every
    /// candidate (issue #902).
    fn matches(
        &self,
        input: &str,
        candidates: &[(ByteRange, IdentityDomain)],
    ) -> Vec<Vec<ContextMatch>> {
        let mut result = vec![Vec::new(); candidates.len()];
        if candidates.is_empty() {
            return result;
        }
        let lines = LogicalLines::new(input);
        let mut by_start: Vec<(usize, usize)> = candidates
            .iter()
            .enumerate()
            .map(|(index, (range, _))| (range.start(), index))
            .collect();
        heap_sort(&mut by_start);
        let mut by_end: Vec<(usize, usize)> = candidates
            .iter()
            .enumerate()
            .map(|(index, (range, _))| (range.end(), index))
            .collect();
        heap_sort(&mut by_end);
        // Equidistance counts each distinct range once (issue #922).
        let mut ranges: Vec<ByteRange> = candidates.iter().map(|(range, _)| *range).collect();
        ranges.sort();
        ranges.dedup();

        // Every candidate keyed by its logical line, with its barriers:
        // `(candidate index, before barrier, after barrier)`.
        let mut members: Vec<((usize, usize), [usize; 3])> = candidates
            .iter()
            .enumerate()
            .map(|(candidate_index, (range, _))| {
                let (line_start, line_end) = lines.bounds(input.len(), *range);
                let before_barrier = by_end
                    [..by_end.partition_point(|(end, _)| *end <= range.start())]
                    .iter()
                    .rev()
                    .find(|(_, index)| *index != candidate_index)
                    .map(|(end, _)| *end)
                    .filter(|end| *end >= line_start)
                    .unwrap_or(line_start);
                let after_barrier = by_start
                    [by_start.partition_point(|(start, _)| *start < range.end())..]
                    .iter()
                    .find(|(_, index)| *index != candidate_index)
                    .map(|(start, _)| *start)
                    .filter(|start| *start <= line_end)
                    .unwrap_or(line_end);
                (
                    (line_start, line_end),
                    [candidate_index, before_barrier, after_barrier],
                )
            })
            .collect();
        heap_sort(&mut members);

        let mut group_start = 0;
        while group_start < members.len() {
            let (line_start, line_end) = members[group_start].0;
            let group_end = group_start
                + members[group_start..]
                    .iter()
                    .take_while(|(line, _)| *line == (line_start, line_end))
                    .count();
            let group = &members[group_start..group_end];
            group_start = group_end;

            let window: Vec<ByteRange> = ranges
                [ranges.partition_point(|range| range.start() < line_start)..]
                .iter()
                .take_while(|range| range.start() <= line_end)
                .filter(|range| range.end() <= line_end)
                .copied()
                .collect();
            let mut positions: Vec<usize> = window.iter().map(|range| range.start()).collect();
            for (_, [candidate_index, before_barrier, _]) in group {
                positions.push(*before_barrier);
                positions.push(candidates[*candidate_index].0.end());
            }
            heap_sort(&mut positions);
            positions.dedup();
            let offsets = LineOffsets::new(input, line_start, positions);
            let occurrences = LineOccurrences::new(input, &window, &offsets);
            for (_, [candidate_index, before_barrier, after_barrier]) in group {
                let (range, domain) = candidates[*candidate_index];
                result[*candidate_index] = self.associate(
                    input,
                    range,
                    domain,
                    [*before_barrier, *after_barrier],
                    &offsets,
                    &occurrences,
                );
            }
        }
        result
    }

    /// The context entries one candidate associates with, given its
    /// barriers and its line's offsets and occurrences. Kept out of line so
    /// the per-call driver above stays small: in the WebAssembly build each
    /// function is compiled and tiered up on its own, and a whole-input scan
    /// calls this once per candidate.
    #[inline(never)]
    #[allow(
        clippy::too_many_lines,
        reason = "the bounded association rules are one ordered contract"
    )]
    fn associate(
        &self,
        input: &str,
        range: ByteRange,
        domain: IdentityDomain,
        [before_barrier, after_barrier]: [usize; 2],
        offsets: &LineOffsets,
        occurrences: &LineOccurrences,
    ) -> Vec<ContextMatch> {
        let mut found = Vec::new();
        let before = normalize_context(&input[before_barrier..range.start()]);
        let after = normalize_context(&input[range.end()..after_barrier]);
        let before_offset = offsets.at(before_barrier);
        let after_offset = offsets.at(range.end());
        let views = [
            (0usize, before.as_str(), before.chars().count()),
            (1usize, after.as_str(), after.chars().count()),
        ];
        for (entry, forms) in self
            .entries
            .iter()
            .filter(|(entry, _)| entry.domains.contains(&domain))
        {
            for form in forms {
                for (side, view, view_scalars) in views {
                    if entry.kind == ContextKind::FieldLabel && side == 1 {
                        continue;
                    }
                    // Matches arrive in position order, so the scalar
                    // count before each one is carried forward rather
                    // than recounted from the start of the view.
                    let mut counted_bytes = 0;
                    let mut counted_scalars = 0;
                    for (position, _) in view.match_indices(form.text.as_str()) {
                        let byte_end = position + form.text.len();
                        let boundary_ok = view[..position]
                            .chars()
                            .next_back()
                            .is_none_or(|character| is_context_boundary(entry, character))
                            && view[byte_end..]
                                .chars()
                                .next()
                                .is_none_or(|character| is_context_boundary(entry, character));
                        if !boundary_ok {
                            continue;
                        }
                        counted_scalars += view[counted_bytes..position].chars().count();
                        counted_bytes = position;
                        let local_start = counted_scalars;
                        let distance = if side == 0 {
                            view_scalars - local_start - form.scalars
                        } else {
                            local_start
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
                            && !view[byte_end..]
                                .chars()
                                .all(|character| is_field_gap(entry, character))
                        {
                            continue;
                        }
                        let occurrence_start = if side == 0 {
                            before_offset
                        } else {
                            after_offset
                        } + local_start;
                        let occurrence_end = occurrence_start + form.scalars;
                        if occurrences.equidistant(entry.kind, occurrence_start, occurrence_end) {
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
        selected
    }
}

fn is_context_boundary(entry: &ContextEntry, character: char) -> bool {
    character.is_whitespace()
        || (entry.kind == ContextKind::FieldLabel && matches!(character, '"' | '\''))
        || is_positive_field_label_pipe(entry, character)
}
fn is_field_gap(entry: &ContextEntry, character: char) -> bool {
    character.is_whitespace()
        || matches!(character, '"' | '\'')
        || is_positive_field_label_pipe(entry, character)
}

/// A `|` field or cell delimiter bounds a positive field label and may sit
/// in its gap, as whitespace does, so `a|b|email=V`, `x|phone: V`, and the
/// `| ssn | V |` cells of a pipe table associate (`pii-context/v2`,
/// `association.fieldLabel.pipeDelimiter: positive-field-labels`, issue #940).
/// It is not a token separator, so two cells never join into one multi-word
/// form. A negative or neutral entry and a natural-language label keep the
/// whitespace-only boundary: a pipe adds association, never a suppression.
fn is_positive_field_label_pipe(entry: &ContextEntry, character: char) -> bool {
    character == '|'
        && entry.kind == ContextKind::FieldLabel
        && entry.class == ContextClass::Positive
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

/// Every candidate's context matches under the generated vocabulary, for
/// tests that exercise the association rules without a family.
#[cfg(test)]
fn context_matches(
    input: &str,
    candidates: &[(ByteRange, IdentityDomain)],
) -> Vec<Vec<ContextMatch>> {
    ContextVocabulary::new().matches(input, candidates)
}

/// Sorts `items` ascending in O(n log n) with no allocation. The association
/// sorts only small `Copy` keys; a heap sort keeps that to a few hundred
/// bytes of code per key type in the WebAssembly build, where each
/// `sort_unstable` instantiation costs several kilobytes (issue #902).
#[inline(never)]
fn heap_sort<T: Ord + Copy>(items: &mut [T]) {
    fn sift_down<T: Ord + Copy>(items: &mut [T], mut root: usize) {
        loop {
            let mut child = 2 * root + 1;
            if child >= items.len() {
                return;
            }
            if child + 1 < items.len() && items[child] < items[child + 1] {
                child += 1;
            }
            if items[root] >= items[child] {
                return;
            }
            items.swap(root, child);
            root = child;
        }
    }
    for root in (0..items.len() / 2).rev() {
        sift_down(items, root);
    }
    for end in (1..items.len()).rev() {
        items.swap(0, end);
        sift_down(&mut items[..end], 0);
    }
}

/// The byte index and length of every logical line break of an input, found
/// in one pass so a candidate's line is two binary searches away.
struct LogicalLines {
    breaks: Vec<(usize, usize)>,
}

impl LogicalLines {
    fn new(input: &str) -> Self {
        Self {
            breaks: input
                .char_indices()
                .filter(|(_, character)| is_logical_line_break(*character))
                .map(|(index, character)| (index, character.len_utf8()))
                .collect(),
        }
    }

    /// The logical line around `range`: from just after the last break that
    /// starts before the range to the first break at or after its end. A
    /// break inside the range does not split it.
    fn bounds(&self, input_len: usize, range: ByteRange) -> (usize, usize) {
        let before = self
            .breaks
            .partition_point(|(index, _)| *index < range.start());
        let line_start = before
            .checked_sub(1)
            .map_or(0, |last| self.breaks[last].0 + self.breaks[last].1);
        let after = self
            .breaks
            .partition_point(|(index, _)| *index < range.end());
        let line_end = self
            .breaks
            .get(after)
            .map_or(input_len, |(index, _)| *index);
        (line_start, line_end)
    }
}

/// Whether NFC never joins `character` with anything before it, so the
/// context-only view of a text splits there: an ASCII scalar or a
/// precomposed Hangul syllable is a starter that no canonical composition
/// takes as its second element, and canonical reordering never moves a mark
/// across a starter. Governed invisible code points are never ASCII or
/// Hangul syllables, so removing them first does not move such a split.
fn starts_normalization_segment(character: char) -> bool {
    character.is_ascii() || ('\u{AC00}'..='\u{D7A3}').contains(&character)
}

/// The scalar count of [`normalize_context`] kept as a running state, so the
/// count of a prefix grows by feeding text instead of renormalizing it.
#[derive(Clone, Copy, Default)]
struct ContextScalars {
    count: usize,
    in_separator: bool,
}

impl ContextScalars {
    fn push(&mut self, character: char) {
        if is_context_separator(character.to_ascii_lowercase()) {
            if !self.in_separator {
                self.count += 1;
                self.in_separator = true;
            }
        } else {
            self.count += 1;
            self.in_separator = false;
        }
    }

    /// Continues the count over `text`. The result equals the count of
    /// `normalize_context` over everything fed so far only when nothing was
    /// fed before or `text` is empty or starts a normalization segment
    /// ([`starts_normalization_segment`]).
    fn feed(&mut self, text: &str) {
        if text.is_ascii() {
            for byte in text.bytes() {
                self.push(char::from(byte));
            }
        } else {
            for character in visible_nfc(text) {
                self.push(character);
            }
        }
    }
}

/// `normalize_context(&input[line_start..position]).chars().count()` for a
/// sorted set of positions of one logical line, computed in one pass over
/// the line.
struct LineOffsets {
    positions: Vec<usize>,
    offsets: Vec<usize>,
}

impl LineOffsets {
    fn new(input: &str, line_start: usize, positions: Vec<usize>) -> Self {
        let mut committed = ContextScalars::default();
        let mut cursor = line_start;
        let offsets = positions
            .iter()
            .map(|&position| {
                let pending = &input[cursor..position];
                if let Some((split, _)) = pending
                    .char_indices()
                    .rev()
                    .find(|(_, character)| starts_normalization_segment(*character))
                {
                    committed.feed(&pending[..split]);
                    cursor += split;
                }
                let mut partial = committed;
                partial.feed(&input[cursor..position]);
                partial.count
            })
            .collect();
        Self { positions, offsets }
    }

    fn at(&self, position: usize) -> usize {
        self.positions
            .binary_search(&position)
            .map_or(0, |index| self.offsets[index])
    }
}

/// The distinct candidate ranges of one logical line in context-view scalar
/// coordinates, indexed for [`LineOccurrences::equidistant`].
struct LineOccurrences {
    /// `(end, start)` of every range, sorted.
    by_end: Vec<(usize, usize)>,
    /// The two smallest starts among `by_end[index..]`; `usize::MAX` when
    /// absent.
    smallest_starts_from: Vec<(usize, usize)>,
}

impl LineOccurrences {
    fn new(input: &str, window: &[ByteRange], offsets: &LineOffsets) -> Self {
        let mut by_end: Vec<(usize, usize)> = window
            .iter()
            .map(|range| {
                let start = offsets.at(range.start());
                let mut scalars = ContextScalars::default();
                scalars.feed(&input[range.start()..range.end()]);
                (start + scalars.count, start)
            })
            .collect();
        heap_sort(&mut by_end);
        let mut smallest_starts_from = vec![(usize::MAX, usize::MAX); by_end.len() + 1];
        for index in (0..by_end.len()).rev() {
            let (first, second) = smallest_starts_from[index + 1];
            let start = by_end[index].1;
            smallest_starts_from[index] = if start <= first {
                (start, first)
            } else {
                (first, second.min(start))
            };
        }
        Self {
            by_end,
            smallest_starts_from,
        }
    }

    /// Whether a context occurrence is equally near two candidate
    /// occurrences it could associate with. A field label only associates
    /// with a candidate after it, so a candidate that ends before the label
    /// never makes it equidistant (`pii-context/v2`, issue #924); a
    /// natural-language label may associate either way and keeps the
    /// two-sided rule. Only the two nearest candidates on each side can
    /// decide it, so it is two lookups rather than a pass over the line.
    fn equidistant(
        &self,
        kind: ContextKind,
        occurrence_start: usize,
        occurrence_end: usize,
    ) -> bool {
        let split = self
            .by_end
            .partition_point(|(end, _)| *end <= occurrence_start);
        let mut nearest = [usize::MAX; 4];
        let mut count = 0;
        if kind == ContextKind::NaturalLanguageLabel {
            for (end, _) in self.by_end[..split].iter().rev().take(2) {
                nearest[count] = occurrence_start - end;
                count += 1;
            }
        }
        let (first, second) = self.smallest_starts_from[split];
        for start in [first, second] {
            if start != usize::MAX {
                nearest[count] = start.saturating_sub(occurrence_end);
                count += 1;
            }
        }
        let nearest = &nearest[..count];
        nearest.iter().min().is_some_and(|minimum| {
            nearest
                .iter()
                .filter(|distance| *distance == minimum)
                .count()
                > 1
        })
    }
}

#[cfg(test)]
#[path = "pii/context_association_tests.rs"]
mod context_association_tests;

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
            PiiSelection::parse_with_catalog(&["pii:us"], KNOWN_FAMILIES, &["pii:global:email"],)
                .unwrap_err()
                .code(),
            SecretScanErrorCode::PiiSelectorUnavailable
        );
    }

    #[test]
    fn activation_identity_is_canonical_and_off_is_distinct() {
        assert_eq!(
            PiiSelection::default().activation_identity(crate::Profile::Full),
            "credentials=full;selectors=off;families=;vocabulary=pii-context/v2"
        );
        let active = PiiSelection::parse(&["pii", "pii:global"]).unwrap();
        assert_eq!(
            active.activation_identity(crate::Profile::Common),
            "credentials=common;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2"
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
        assert_eq!(normalize_context("e\u{301}"), normalize_context("é"));
        // pii-context/v2 folds ASCII case in every language (issue #927).
        assert_eq!(normalize_context("IP 주소"), "ip 주소");
        assert_eq!(normalize_context("클라이언트_IP"), "클라이언트 ip");

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
    fn positive_field_label_after_a_pipe_associates_like_after_whitespace() {
        // Issue #940: a `|` field or cell delimiter bounds a positive field
        // label and may sit in its gap.
        for (input, domain, expected) in [
            ("x|email: TEST", IdentityDomain::Email, "en-email-field"),
            ("a|b|email=TEST", IdentityDomain::Email, "en-email-field"),
            (
                "a|b|customer_email=TEST",
                IdentityDomain::Email,
                "en-email-field",
            ),
            ("x|phone=TEST", IdentityDomain::Phone, "en-phone-field"),
            (
                "| ssn | TEST |",
                IdentityDomain::NationalId,
                "en-us-ssn-field",
            ),
            (
                "|ip|TEST|",
                IdentityDomain::NetworkAddress,
                "en-network-address-field",
            ),
            (
                "| card number | TEST |",
                IdentityDomain::PaymentCard,
                "en-payment-card-field",
            ),
            ("x|iban: TEST", IdentityDomain::Iban, "en-iban-field"),
            ("x|이메일=TEST", IdentityDomain::Email, "ko-email-field"),
        ] {
            let start = input.find("TEST").unwrap();
            let matches = context_matches(
                input,
                &[(ByteRange::new(start, start + 4).unwrap(), domain)],
            );
            assert!(
                matches[0].iter().any(|item| item.entry_id == expected),
                "{input}"
            );
        }
        // Benign twins: not a whole label token, another cell in the gap, two
        // cells joined into one form, or the label on a header line.
        for (input, domain) in [
            ("user|emailx=TEST", IdentityDomain::Email),
            ("user|user.email=TEST", IdentityDomain::Email),
            ("| email | name | TEST |", IdentityDomain::Email),
            ("| card | number | TEST |", IdentityDomain::PaymentCard),
            (
                "| email | phone |\n| --- | --- |\n| TEST |",
                IdentityDomain::Email,
            ),
        ] {
            let start = input.find("TEST").unwrap();
            let matches = context_matches(
                input,
                &[(ByteRange::new(start, start + 4).unwrap(), domain)],
            );
            assert!(matches[0].is_empty(), "{input}");
        }
        // A pipe adds no suppression: a negative or natural-language entry
        // keeps the whitespace-only boundary.
        let input = "x|example email: TEST";
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
                .all(|item| item.class != ContextClass::Negative)
        );
        assert!(
            matches[0]
                .iter()
                .any(|item| item.entry_id == "en-email-field")
        );
        let input = "x|not_ssn=TEST";
        let start = input.find("TEST").unwrap();
        let matches = context_matches(
            input,
            &[(
                ByteRange::new(start, start + 4).unwrap(),
                IdentityDomain::NationalId,
            )],
        );
        assert!(
            matches[0]
                .iter()
                .all(|item| item.class != ContextClass::Negative)
        );
    }

    #[test]
    fn field_label_after_an_earlier_candidate_associates_forward() {
        // Issue #924: a field label only associates with the candidate after
        // it, so the candidate before it on the same line never makes it
        // equidistant.
        for (input, first, second, first_entry, second_entry) in [
            (
                "email: AAAA phone: BBBB",
                IdentityDomain::Email,
                IdentityDomain::Phone,
                "en-email-field",
                "en-phone-field",
            ),
            (
                "ip=AAAA card_number=BBBB",
                IdentityDomain::NetworkAddress,
                IdentityDomain::PaymentCard,
                "en-network-address-field",
                "en-payment-card-field",
            ),
            (
                "ip: AAAA ip: BBBB",
                IdentityDomain::NetworkAddress,
                IdentityDomain::NetworkAddress,
                "en-network-address-field",
                "en-network-address-field",
            ),
        ] {
            let a = input.find("AAAA").unwrap();
            let b = input.find("BBBB").unwrap();
            let matches = context_matches(
                input,
                &[
                    (ByteRange::new(a, a + 4).unwrap(), first),
                    (ByteRange::new(b, b + 4).unwrap(), second),
                ],
            );
            assert!(
                matches[0].iter().any(|item| item.entry_id == first_entry),
                "{input}"
            );
            assert!(
                matches[1].iter().any(|item| item.entry_id == second_entry),
                "{input}"
            );
        }
        // A label of another domain after the first value reaches nothing.
        let other_domain = context_matches(
            "ip: AAAA order_id=BBBB",
            &[
                (
                    ByteRange::new(4, 8).unwrap(),
                    IdentityDomain::NetworkAddress,
                ),
                (ByteRange::new(18, 22).unwrap(), IdentityDomain::PaymentCard),
            ],
        );
        assert!(!other_domain[0].is_empty());
        assert!(other_domain[1].is_empty());
    }

    #[test]
    fn same_range_alternative_of_another_domain_is_not_equidistant() {
        // Issue #922: one occurrence read as both a payment card and a phone
        // number is one candidate position, not two equidistant candidates.
        for (input, domain, entry) in [
            (
                "card_number=TEST",
                IdentityDomain::PaymentCard,
                "en-payment-card-field",
            ),
            ("phone: TEST", IdentityDomain::Phone, "en-phone-field"),
        ] {
            let start = input.find("TEST").unwrap();
            let range = ByteRange::new(start, start + 4).unwrap();
            let candidates = [
                (range, IdentityDomain::PaymentCard),
                (range, IdentityDomain::Phone),
            ];
            let matches = context_matches(input, &candidates);
            let index = candidates
                .iter()
                .position(|(_, candidate)| *candidate == domain)
                .unwrap();
            assert!(
                matches[index].iter().any(|item| item.entry_id == entry),
                "{input}"
            );
            assert!(matches[1 - index].is_empty(), "{input}");
        }
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

    /// Issue #910: one authored case of the maintainer-local identity
    /// evaluation, with the outcome the family contract fixes for it.
    struct IdentityCase {
        family: &'static str,
        input: &'static str,
        candidate: &'static str,
        identity: &'static str,
        sensitivity: &'static str,
    }

    const fn identity_case(
        family: &'static str,
        input: &'static str,
        candidate: &'static str,
        identity: &'static str,
        sensitivity: &'static str,
    ) -> IdentityCase {
        IdentityCase {
            family,
            input,
            candidate,
            identity,
            sensitivity,
        }
    }

    /// Per family: a synthetic sensitive positive, the authority-reserved
    /// benign control (or, for IBAN and US SSN, which reserve no
    /// non-sensitive value in `pii-v1`, a valid identity without context),
    /// and a one-property twin that is not a family identity. Synthetic and
    /// reserved values only; each `candidate` is the authored value itself.
    const IDENTITY_CASES: &[IdentityCase] = &[
        identity_case(
            "pii:global:payment-card",
            "card_number=4000008770000003",
            "4000008770000003",
            "established",
            "sensitive",
        ),
        identity_case(
            "pii:global:payment-card",
            "card_number=4111111111111111",
            "4111111111111111",
            "established",
            "non-sensitive",
        ),
        identity_case(
            "pii:global:payment-card",
            "card_number=4000008770000004",
            "4000008770000004",
            "unmatched",
            "not-established",
        ),
        identity_case(
            "pii:global:email",
            "email: fixture876-q7m9@x4z8v2n6.synthetic",
            "fixture876-q7m9@x4z8v2n6.synthetic",
            "established",
            "sensitive",
        ),
        identity_case(
            "pii:global:email",
            "email: identity@example.com",
            "identity@example.com",
            "established",
            "non-sensitive",
        ),
        identity_case(
            "pii:global:email",
            "email: user@domain",
            "user@domain",
            "unmatched",
            "not-established",
        ),
        identity_case(
            "pii:global:email",
            "email: postgres://user:pass@x4z8v2n6.synthetic/database",
            "pass@x4z8v2n6.synthetic",
            "unmatched",
            "not-established",
        ),
        identity_case(
            "pii:global:phone",
            "phone_number=212-555-2345",
            "212-555-2345",
            "established",
            "sensitive",
        ),
        identity_case(
            "pii:global:phone",
            "phone=212-555-0100",
            "212-555-0100",
            "established",
            "non-sensitive",
        ),
        identity_case(
            "pii:global:phone",
            "phone=211-555-2345",
            "211-555-2345",
            "unmatched",
            "not-established",
        ),
        identity_case(
            "pii:global:iban",
            "iban: GB18SYNX00000000000000",
            "GB18SYNX00000000000000",
            "established",
            "sensitive",
        ),
        identity_case(
            "pii:global:iban",
            "GB18SYNX00000000000000",
            "GB18SYNX00000000000000",
            "established",
            "not-established",
        ),
        identity_case(
            "pii:global:iban",
            "iban: GB00SYNX00000000000000",
            "GB00SYNX00000000000000",
            "unmatched",
            "not-established",
        ),
        identity_case(
            "pii:us:ssn",
            "ssn=890626879",
            "890626879",
            "established",
            "sensitive",
        ),
        identity_case(
            "pii:us:ssn",
            "890-62-6879",
            "890-62-6879",
            "established",
            "not-established",
        ),
        identity_case(
            "pii:us:ssn",
            "ssn=666-62-6879",
            "666-62-6879",
            "unmatched",
            "not-established",
        ),
        identity_case(
            "pii:global:network-address",
            "client_ip=10.0.0.8",
            "10.0.0.8",
            "established",
            "sensitive",
        ),
        identity_case(
            "pii:global:network-address",
            "client_ip=192.0.2.1",
            "192.0.2.1",
            "established",
            "non-sensitive",
        ),
        identity_case(
            "pii:global:network-address",
            "client_ip=010.0.0.8",
            "010.0.0.8",
            "unmatched",
            "not-established",
        ),
    ];

    fn candidate_range(case: &IdentityCase) -> (usize, usize) {
        let start = case.input.find(case.candidate).unwrap();
        (start, start + case.candidate.len())
    }

    /// Public findings of `family`'s own type at exactly `range`, through the
    /// public registry the evaluator's activation identity names.
    fn public_findings_at(family: &str, input: &str, range: (usize, usize)) -> usize {
        let selector = format!("pii:family:{}", family.strip_prefix("pii:").unwrap());
        let selection = PiiSelection::parse(&[selector.as_str()]).unwrap();
        let registry = crate::DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
        let findings = crate::scan(input, &registry, &crate::DefaultPolicy).unwrap();
        findings
            .iter()
            .filter(|finding| {
                finding.type_name() == public_type(family)
                    && (finding.range().start(), finding.range().end()) == range
            })
            .count()
    }

    #[test]
    fn identity_evaluation_reports_the_joined_state_of_the_authored_candidate() {
        for case in IDENTITY_CASES {
            let evaluator = IdentityEvaluator::new(case.family).unwrap();
            assert_eq!(evaluator.family(), case.family);
            let range = candidate_range(case);
            let outcome = evaluator.evaluate(case.input, Some(range));
            assert_eq!(
                (outcome.identity, outcome.sensitivity),
                (case.identity, case.sensitivity),
                "{} {:?}",
                case.family,
                case.candidate
            );
            // Source equivalence: `sensitive` iff the public surface reports
            // exactly one finding of this family at exactly this range.
            assert_eq!(
                outcome.sensitivity == "sensitive",
                public_findings_at(case.family, case.input, range) == 1,
                "{} {:?}",
                case.family,
                case.candidate
            );
            // The evaluation is a pure function of its inputs.
            assert_eq!(evaluator.evaluate(case.input, Some(range)), outcome);
        }
        // Every family is exercised with all three outcomes it can reach.
        for family in AVAILABLE_FAMILIES {
            let reached: BTreeSet<(&str, &str)> = IDENTITY_CASES
                .iter()
                .filter(|case| case.family == *family)
                .map(|case| (case.identity, case.sensitivity))
                .collect();
            assert!(reached.contains(&("established", "sensitive")), "{family}");
            assert!(
                reached.contains(&("unmatched", "not-established")),
                "{family}"
            );
            assert!(
                reached.contains(&("established", "non-sensitive"))
                    || reached.contains(&("established", "not-established")),
                "{family}"
            );
        }
    }

    #[test]
    fn identity_evaluation_never_establishes_credential_uri_userinfo_as_email() {
        let input = "email: postgres://user:pass@x4z8v2n6.synthetic/database";
        let evaluator = IdentityEvaluator::new("pii:global:email").unwrap();
        assert!(
            evaluator
                .domain
                .contextualized(input)
                .iter()
                .all(|alternative| alternative.identity != IdentityState::Established)
        );
        let unmatched = IdentityOutcome {
            identity: "unmatched",
            sensitivity: "not-established",
        };
        assert_eq!(evaluator.evaluate(input, None), unmatched);
        for start in 0..=input.len() {
            for end in start..=input.len() {
                assert_eq!(evaluator.evaluate(input, Some((start, end))), unmatched);
            }
        }
    }

    #[test]
    fn identity_evaluation_reports_unmatched_for_null_and_misaligned_candidates() {
        let unmatched = IdentityOutcome {
            identity: "unmatched",
            sensitivity: "not-established",
        };
        for case in IDENTITY_CASES {
            let evaluator = IdentityEvaluator::new(case.family).unwrap();
            let (start, end) = candidate_range(case);
            assert_eq!(evaluator.evaluate(case.input, None), unmatched);
            let widened_left = if start == 0 {
                (start, end + 1)
            } else {
                (start - 1, end)
            };
            for misaligned in [
                (start + 1, end),
                (start, end - 1),
                widened_left,
                (start, end + 1),
                (end, start),
                (start, start),
                (0, case.input.len() + 1),
                (usize::MAX, usize::MAX),
            ] {
                assert_eq!(
                    evaluator.evaluate(case.input, Some(misaligned)),
                    unmatched,
                    "{} {misaligned:?}",
                    case.family
                );
            }
        }
        // A range inside a multi-byte character is not a slice boundary;
        // the evaluation compares offsets and never slices with them.
        let evaluator = IdentityEvaluator::new("pii:global:email").unwrap();
        assert_eq!(
            evaluator.evaluate("email: 고객876@x4z8v2n6.synthetic", Some((8, 30))),
            unmatched
        );
    }

    #[test]
    fn identity_evaluation_uses_the_pipeline_scan_copy_and_its_rejections() {
        // A governed invisible code point inside an address: the pipeline
        // scans the copy without it and reports the translated original
        // range, so the evaluation does too.
        let input = "client_ip=192.168.1.\u{200b}7";
        let evaluator = IdentityEvaluator::new("pii:global:network-address").unwrap();
        let range = (10, input.len());
        assert_eq!(
            evaluator.evaluate(input, Some(range)),
            IdentityOutcome {
                identity: "established",
                sensitivity: "sensitive",
            }
        );
        assert_eq!(
            public_findings_at("pii:global:network-address", input, range),
            1
        );
        // Email rejects invisible normalization: the pipeline drops the
        // alternative before overlap resolution, and so does the evaluation.
        let input = "email: fixture876-q7m9@x4z8v2n6\u{200b}.synthetic";
        let evaluator = IdentityEvaluator::new("pii:global:email").unwrap();
        let range = (7, input.len());
        assert_eq!(
            evaluator.evaluate(input, Some(range)),
            IdentityOutcome {
                identity: "unmatched",
                sensitivity: "not-established",
            }
        );
        assert_eq!(public_findings_at("pii:global:email", input, range), 0);
    }

    #[test]
    fn identity_evaluator_accepts_exactly_one_production_family() {
        for family in AVAILABLE_FAMILIES {
            let evaluator = IdentityEvaluator::new(family).unwrap();
            assert_eq!(IdentityEvaluator::vocabulary(), "pii-context/v2");
            assert_eq!(
                IDENTITY_EVALUATION_FORMAT,
                "redact-secret/pii-identity-evaluation/1"
            );
            let selector = format!("pii:family:{}", family.strip_prefix("pii:").unwrap());
            let selection = PiiSelection::parse(&[selector.as_str()]).unwrap();
            assert_eq!(
                evaluator.activation_identity(),
                crate::DetectorRegistry::with_built_in_and_pii(&selection)
                    .unwrap()
                    .activation_identity()
            );
            assert_eq!(evaluator.domain.families.len(), 1);
            assert_eq!(evaluator.domain.families[0].id(), *family);
        }
        assert_eq!(
            IdentityEvaluator::new("pii:us:ssn")
                .unwrap()
                .activation_identity(),
            "credentials=full;selectors=pii:family:us:ssn;families=pii:us:ssn;vocabulary=pii-context/v2"
        );
        for other in [
            "",
            "pii",
            "pii:global",
            "pii:us",
            "pii:family:global:email",
            "pii:global:us-ssn",
            "pii:global:ambiguous-national-id",
            "PII:GLOBAL:EMAIL",
            "pii:global:email ",
        ] {
            assert!(IdentityEvaluator::new(other).is_none(), "{other:?}");
        }
    }
}
