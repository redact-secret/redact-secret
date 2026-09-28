//! Generated `pii-context/v2` vocabulary. Do not edit by hand.

use super::{
    ContextClass, ContextEntry, ContextKind, ContextLanguage, ContextStrength, IdentityDomain,
};

pub(super) const CONTEXT_VERSION: &str = "pii-context/v2";

#[rustfmt::skip]
pub(super) const CONTEXT_ENTRIES: &[ContextEntry] = &[
    ContextEntry::new("en-email-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Email], &["email", "e-mail"]),
    ContextEntry::new("en-network-address-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::NetworkAddress], &["ip", "ip address", "client ip", "source ip", "remote address"]),
    ContextEntry::new("en-iban-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Iban], &["iban", "international bank account number"]),
    ContextEntry::new("en-payment-card-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::PaymentCard], &["payment card", "card number", "credit card number", "debit card number", "pan"]),
    ContextEntry::new("en-phone-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Phone], &["phone", "phone number", "telephone", "telephone number"]),
    ContextEntry::new("en-us-ssn-field", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::NationalId], &["ssn", "social security number"]),
    ContextEntry::new("en-us-ssn-negation", ContextLanguage::English, ContextKind::NaturalLanguageLabel, ContextClass::Negative, ContextStrength::HighSignal, &[IdentityDomain::NationalId], &["not ssn", "not social security number"]),
    ContextEntry::new("en-contact-label", ContextLanguage::English, ContextKind::NaturalLanguageLabel, ContextClass::Positive, ContextStrength::Ambiguous, &[IdentityDomain::Email, IdentityDomain::Phone], &["contact"]),
    ContextEntry::new("en-contact-details-label", ContextLanguage::English, ContextKind::NaturalLanguageLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Email, IdentityDomain::Phone], &["contact details"]),
    ContextEntry::new("en-example-label", ContextLanguage::English, ContextKind::NaturalLanguageLabel, ContextClass::Negative, ContextStrength::HighSignal, IdentityDomain::ALL, &["example", "documentation"]),
    ContextEntry::new("en-value-neutral", ContextLanguage::English, ContextKind::FieldLabel, ContextClass::Neutral, ContextStrength::Ambiguous, IdentityDomain::ALL, &["value"]),
    ContextEntry::new("ko-email-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Email], &["이메일", "고객 이메일"]),
    ContextEntry::new("ko-network-address-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::NetworkAddress], &["ip", "ip 주소", "클라이언트 ip", "원격 주소"]),
    ContextEntry::new("ko-iban-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Iban], &["iban", "국제 계좌번호"]),
    ContextEntry::new("ko-payment-card-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::PaymentCard], &["결제 카드", "카드 번호", "신용 카드 번호", "직불 카드 번호"]),
    ContextEntry::new("ko-phone-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::Phone], &["전화번호", "휴대전화번호"]),
    ContextEntry::new("ko-us-ssn-field", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Positive, ContextStrength::HighSignal, &[IdentityDomain::NationalId], &["사회보장번호", "사회 보장 번호", "미국 사회보장번호"]),
    ContextEntry::new("ko-us-ssn-negation", ContextLanguage::Korean, ContextKind::NaturalLanguageLabel, ContextClass::Negative, ContextStrength::HighSignal, &[IdentityDomain::NationalId], &["사회보장번호 아님", "사회 보장 번호 아님"]),
    ContextEntry::new("ko-contact-label", ContextLanguage::Korean, ContextKind::NaturalLanguageLabel, ContextClass::Positive, ContextStrength::Ambiguous, &[IdentityDomain::Email, IdentityDomain::Phone], &["연락처"]),
    ContextEntry::new("ko-example-label", ContextLanguage::Korean, ContextKind::NaturalLanguageLabel, ContextClass::Negative, ContextStrength::HighSignal, IdentityDomain::ALL, &["예시"]),
    ContextEntry::new("ko-value-neutral", ContextLanguage::Korean, ContextKind::FieldLabel, ContextClass::Neutral, ContextStrength::Ambiguous, IdentityDomain::ALL, &["값"]),
];
