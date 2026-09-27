//! Generated `pii-context/v1` vocabulary. Do not edit by hand.

use super::{
    ContextClass, ContextEntry, ContextKind, ContextLanguage, ContextStrength, IdentityDomain,
};

pub(super) const CONTEXT_VERSION: &str = "pii-context/v1";

#[rustfmt::skip]
pub(super) const CONTEXT_ENTRIES: &[ContextEntry] = &[
    ContextEntry::new("en-email-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Email], &["email", "e-mail"]),
    ContextEntry::new("en-network-address-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::NetworkAddress], &["ip", "ip address", "client ip", "source ip", "remote address"]),
    ContextEntry::new("en-iban-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Iban], &["iban", "international bank account number"]),
    ContextEntry::new("en-contact-label", ContextLanguage::English, ContextKind::NaturalLanguageLabel, ContextClass::Positive, ContextStrength::Ambiguous, &[IdentityDomain::Email, IdentityDomain::Phone], &["contact"]),
    ContextEntry::new("en-contact-details-label", ContextLanguage::English, ContextKind::NaturalLanguageLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Email, IdentityDomain::Phone], &["contact details"]),
    ContextEntry::new("en-example-label", ContextLanguage::English, ContextKind::NaturalLanguageLabel, ContextClass::Negative, ContextStrength::HighSignal, IdentityDomain::ALL, &["example", "documentation"]),
    ContextEntry::new("en-value-neutral", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Neutral, ContextStrength::Ambiguous, IdentityDomain::ALL, &["value"]),
    ContextEntry::new("ko-email-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Email], &["이메일", "고객 이메일"]),
    ContextEntry::new("ko-network-address-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::NetworkAddress], &["ip", "ip 주소", "클라이언트 ip", "원격 주소"]),
    ContextEntry::new("ko-iban-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Iban], &["iban", "국제 계좌번호"]),
    ContextEntry::new("ko-contact-label", ContextLanguage::Korean, ContextKind::NaturalLanguageLabel, ContextClass::Positive, ContextStrength::Ambiguous, &[IdentityDomain::Email, IdentityDomain::Phone], &["연락처"]),
    ContextEntry::new("ko-example-label", ContextLanguage::Korean, ContextKind::NaturalLanguageLabel, ContextClass::Negative, ContextStrength::HighSignal, IdentityDomain::ALL, &["예시"]),
    ContextEntry::new("ko-value-neutral", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Neutral, ContextStrength::Ambiguous, IdentityDomain::ALL, &["값"]),
];
