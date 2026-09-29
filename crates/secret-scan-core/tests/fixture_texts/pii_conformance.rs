//! The PII conformance fixture files, as text, for the core's own unit tests.
//!
//! `src/pii/context_association_tests.rs` (issue #902) compares the context
//! association against its pre-#902 form over these fixtures' inputs. A file
//! under `src/` may not name `include_str!` (`scripts/check-rust-workspace.py`,
//! core source boundary), so the inclusion lives here, outside `src/` and
//! outside the published package, and is compiled only into the unit-test
//! build through a `#[cfg(test)]` module. It is not an integration-test
//! target: Cargo builds only `tests/*.rs` and `tests/*/main.rs` as those.

/// `(file name, file text)` of the seven PII conformance fixtures that carry
/// inputs (`pii-runtime-v1.json` carries only activation selectors).
pub(super) const PII_FIXTURES: &[(&str, &str)] = &[
    (
        "pii-cross-family-v1.json",
        include_str!("../../../../conformance/fixtures/pii-cross-family-v1.json"),
    ),
    (
        "pii-email-v1.json",
        include_str!("../../../../conformance/fixtures/pii-email-v1.json"),
    ),
    (
        "pii-iban-v1.json",
        include_str!("../../../../conformance/fixtures/pii-iban-v1.json"),
    ),
    (
        "pii-network-address-v1.json",
        include_str!("../../../../conformance/fixtures/pii-network-address-v1.json"),
    ),
    (
        "pii-payment-card-v1.json",
        include_str!("../../../../conformance/fixtures/pii-payment-card-v1.json"),
    ),
    (
        "pii-phone-v1.json",
        include_str!("../../../../conformance/fixtures/pii-phone-v1.json"),
    ),
    (
        "pii-us-ssn-v1.json",
        include_str!("../../../../conformance/fixtures/pii-us-ssn-v1.json"),
    ),
];
