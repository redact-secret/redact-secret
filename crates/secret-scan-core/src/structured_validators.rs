//! Bounded validators for structured PII type evidence.
//!
//! This registry is deliberately crate-private and fixed at compile time. A
//! detector submits one already-bounded candidate and a built-in validator
//! identity; callers cannot register code or widen declarative ruleset v1.
//! Successful validation proves only that the candidate has the requested
//! structure. It does not decide whether the occurrence is sensitive.

/// Stable identity recorded when validator evidence is exported for evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatorProvenance {
    /// Stable algorithm name. A semantic change requires a new version.
    pub(crate) identity: &'static str,
    /// Positive semantic version of this validator contract.
    pub(crate) version: u16,
}

/// Safe, input-free reasons that validation did not produce type evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidationFailure {
    /// The registry does not contain the requested built-in identity/version.
    UnknownValidator,
    /// The candidate exceeds the selected validator's byte bound.
    CandidateTooLong,
    /// The candidate does not satisfy the validator's lexical shape.
    Malformed,
    /// The shape is valid but its check value is not.
    ChecksumMismatch,
}

/// Type evidence returned only after a complete successful validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidationEvidence {
    /// Exact validator contract that produced this evidence.
    pub(crate) provenance: ValidatorProvenance,
}

#[derive(Clone, Copy)]
struct Registration {
    provenance: ValidatorProvenance,
    max_candidate_bytes: usize,
    validate: fn(&str) -> Result<(), ValidationFailure>,
}

const LUHN_V1: ValidatorProvenance = ValidatorProvenance {
    identity: "luhn",
    version: 1,
};
const IBAN_MOD97_V1: ValidatorProvenance = ValidatorProvenance {
    identity: "iban-mod97",
    version: 1,
};
const US_SSN_ALLOCATION_V1: ValidatorProvenance = ValidatorProvenance {
    identity: "us-ssn-allocation",
    version: 1,
};

const REGISTRATIONS: [Registration; 3] = [
    Registration {
        provenance: LUHN_V1,
        max_candidate_bytes: 19,
        validate: validate_luhn_v1,
    },
    Registration {
        provenance: IBAN_MOD97_V1,
        max_candidate_bytes: 34,
        validate: validate_iban_mod97_v1,
    },
    Registration {
        provenance: US_SSN_ALLOCATION_V1,
        max_candidate_bytes: 9,
        validate: validate_us_ssn_allocation_v1,
    },
];

/// Fixed built-in registry shared by all PII detectors in the Rust core.
pub(crate) struct StructuredValidatorRegistry;

impl StructuredValidatorRegistry {
    /// Validates one candidate under an exact validator identity and version.
    ///
    /// Lookup happens before candidate inspection. Oversized candidates fail
    /// before an algorithm runs, every algorithm makes one bounded pass, and
    /// failures contain neither the candidate nor a derived value.
    pub(crate) fn validate(
        identity: &str,
        version: u16,
        candidate: &str,
    ) -> Result<ValidationEvidence, ValidationFailure> {
        let Some(registration) = REGISTRATIONS.iter().find(|entry| {
            entry.provenance.identity == identity && entry.provenance.version == version
        }) else {
            return Err(ValidationFailure::UnknownValidator);
        };
        if candidate.len() > registration.max_candidate_bytes {
            return Err(ValidationFailure::CandidateTooLong);
        }
        (registration.validate)(candidate)?;
        Ok(ValidationEvidence {
            provenance: registration.provenance,
        })
    }
}

fn validate_luhn_v1(candidate: &str) -> Result<(), ValidationFailure> {
    if candidate.len() < 2 || !candidate.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ValidationFailure::Malformed);
    }

    let mut sum = 0_u16;
    let parity = candidate.len() % 2;
    for (index, byte) in candidate.bytes().enumerate() {
        let mut digit = u16::from(byte - b'0');
        if index % 2 == parity {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    if sum.is_multiple_of(10) {
        Ok(())
    } else {
        Err(ValidationFailure::ChecksumMismatch)
    }
}

fn validate_iban_mod97_v1(candidate: &str) -> Result<(), ValidationFailure> {
    let bytes = candidate.as_bytes();
    if !(15..=34).contains(&bytes.len())
        || !bytes[0..2].iter().all(u8::is_ascii_uppercase)
        || !bytes[2..4].iter().all(u8::is_ascii_digit)
        || !bytes[4..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(ValidationFailure::Malformed);
    }

    let mut remainder = 0_u16;
    for byte in bytes[4..].iter().chain(&bytes[..4]) {
        if byte.is_ascii_digit() {
            remainder = push_decimal_digit(remainder, byte - b'0');
        } else {
            let expanded = byte - b'A' + 10;
            remainder = push_decimal_digit(remainder, expanded / 10);
            remainder = push_decimal_digit(remainder, expanded % 10);
        }
    }
    if remainder == 1 {
        Ok(())
    } else {
        Err(ValidationFailure::ChecksumMismatch)
    }
}

fn validate_us_ssn_allocation_v1(candidate: &str) -> Result<(), ValidationFailure> {
    let bytes = candidate.as_bytes();
    if bytes.len() != 9 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ValidationFailure::Malformed);
    }

    let area = u16::from(bytes[0] - b'0') * 100
        + u16::from(bytes[1] - b'0') * 10
        + u16::from(bytes[2] - b'0');
    let group = u16::from(bytes[3] - b'0') * 10 + u16::from(bytes[4] - b'0');
    let serial = u16::from(bytes[5] - b'0') * 1_000
        + u16::from(bytes[6] - b'0') * 100
        + u16::from(bytes[7] - b'0') * 10
        + u16::from(bytes[8] - b'0');

    if area == 0 || area == 666 || area >= 900 || group == 0 || serial == 0 {
        Err(ValidationFailure::Malformed)
    } else {
        Ok(())
    }
}

const fn push_decimal_digit(remainder: u16, digit: u8) -> u16 {
    (remainder * 10 + digit as u16) % 97
}

#[cfg(test)]
mod tests {
    use super::{
        IBAN_MOD97_V1, LUHN_V1, StructuredValidatorRegistry, US_SSN_ALLOCATION_V1,
        ValidationFailure, ValidatorProvenance,
    };

    fn validate(
        provenance: ValidatorProvenance,
        candidate: &str,
    ) -> Result<ValidatorProvenance, ValidationFailure> {
        StructuredValidatorRegistry::validate(provenance.identity, provenance.version, candidate)
            .map(|evidence| evidence.provenance)
    }

    fn synthetic_us_ssn() -> String {
        let mut hash = 0x811c_9dc5_u32;
        for byte in b"redact-secret-us-ssn-v1-fixture-879" {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        let mut area = 1 + hash % 898;
        if area >= 666 {
            area += 1;
        }
        let group = 1 + (hash / 898) % 99;
        let serial = 1 + (hash / (898 * 99)) % 9_999;
        format!("{area:03}{group:02}{serial:04}")
    }

    #[test]
    fn luhn_and_non_luhn_validators_share_the_registry_contract() {
        // All-zero digits and the ZZ/SYNTHETIC IBAN body are algorithm-only,
        // unmistakably synthetic values rather than personal data.
        assert_eq!(validate(LUHN_V1, "0000000000000000"), Ok(LUHN_V1));
        assert_eq!(
            validate(IBAN_MOD97_V1, "ZZ50SYNTHETIC000000"),
            Ok(IBAN_MOD97_V1)
        );
        assert_eq!(
            validate(US_SSN_ALLOCATION_V1, &synthetic_us_ssn()),
            Ok(US_SSN_ALLOCATION_V1)
        );
    }

    #[test]
    fn us_ssn_v1_enforces_only_current_ssa_structural_exclusions() {
        assert_eq!(
            validate(US_SSN_ALLOCATION_V1, &synthetic_us_ssn()),
            Ok(US_SSN_ALLOCATION_V1)
        );
        for excluded in [
            "000010001",
            "666010001",
            "900010001",
            "999010001",
            "001000001",
            "001010000",
        ] {
            assert_eq!(
                validate(US_SSN_ALLOCATION_V1, excluded),
                Err(ValidationFailure::Malformed)
            );
        }
    }

    #[test]
    fn luhn_v1_pins_even_and_odd_length_doubling_parity() {
        // These deliberately short, nondegenerate algorithm vectors are not
        // plausible personal identifiers. For the even vector, indexes 0 and
        // 2 double; for the odd vector, indexes 1 and 3 double. Applying the
        // opposite parity makes both checksums fail.
        assert_eq!(validate(LUHN_V1, "1230"), Ok(LUHN_V1));
        assert_eq!(validate(LUHN_V1, "12344"), Ok(LUHN_V1));
        assert_eq!(
            validate(LUHN_V1, "1231"),
            Err(ValidationFailure::ChecksumMismatch)
        );
        assert_eq!(
            validate(LUHN_V1, "12345"),
            Err(ValidationFailure::ChecksumMismatch)
        );
    }

    #[test]
    fn malformed_candidates_fail_without_checksum_evidence() {
        for candidate in ["", "0", "0000-0000", "000000000000000x", "００００"] {
            assert_eq!(
                validate(LUHN_V1, candidate),
                Err(ValidationFailure::Malformed),
                "candidate length {}",
                candidate.len()
            );
        }
        for candidate in [
            "ZZ50SYNTHETIC",       // shorter than the IBAN lower bound
            "zz50SYNTHETIC000000", // lower-case country code
            "ZZ5XSYNTHETIC000000", // non-digit check field
            "ZZ50SYNTHETIC-00000", // punctuation
            "ZZ50SYNTHETIC０００", // non-ASCII digits
        ] {
            assert_eq!(
                validate(IBAN_MOD97_V1, candidate),
                Err(ValidationFailure::Malformed),
                "candidate length {}",
                candidate.len()
            );
        }
        for candidate in ["", "00000000", "00000000x"] {
            assert_eq!(
                validate(US_SSN_ALLOCATION_V1, candidate),
                Err(ValidationFailure::Malformed),
                "candidate length {}",
                candidate.len()
            );
        }
    }

    #[test]
    fn checksum_mismatches_are_distinct_from_malformed_input() {
        assert_eq!(
            validate(LUHN_V1, "0000000000000001"),
            Err(ValidationFailure::ChecksumMismatch)
        );
        assert_eq!(
            validate(IBAN_MOD97_V1, "ZZ51SYNTHETIC000000"),
            Err(ValidationFailure::ChecksumMismatch)
        );
    }

    #[test]
    fn exact_bounds_are_processed_and_oversized_inputs_fail_before_validation() {
        assert_eq!(validate(LUHN_V1, "0000000000000000000"), Ok(LUHN_V1));
        assert_eq!(
            validate(LUHN_V1, "0".repeat(20).as_str()),
            Err(ValidationFailure::CandidateTooLong)
        );

        let max_iban = format!("ZZ25SYNTHETIC{}", "0".repeat(21));
        assert_eq!(max_iban.len(), 34);
        assert_eq!(validate(IBAN_MOD97_V1, &max_iban), Ok(IBAN_MOD97_V1));
        assert_eq!(
            validate(IBAN_MOD97_V1, format!("{max_iban}0").as_str()),
            Err(ValidationFailure::CandidateTooLong)
        );
        assert_eq!(
            validate(US_SSN_ALLOCATION_V1, "0000000000"),
            Err(ValidationFailure::CandidateTooLong)
        );
        for display_or_unicode in ["000-00-0000", "０００００００００"] {
            assert_eq!(
                validate(US_SSN_ALLOCATION_V1, display_or_unicode),
                Err(ValidationFailure::CandidateTooLong)
            );
        }
    }

    #[test]
    fn adversarial_and_unknown_inputs_have_fixed_failures() {
        let adversarial = "9".repeat(1_000_000);
        assert_eq!(
            validate(LUHN_V1, &adversarial),
            Err(ValidationFailure::CandidateTooLong)
        );
        assert_eq!(
            StructuredValidatorRegistry::validate("user-code", 1, &adversarial),
            Err(ValidationFailure::UnknownValidator)
        );
        assert_eq!(
            StructuredValidatorRegistry::validate("luhn", 2, "0000000000000000"),
            Err(ValidationFailure::UnknownValidator)
        );
        assert_eq!(
            StructuredValidatorRegistry::validate("us-ssn-allocation", 2, &synthetic_us_ssn(),),
            Err(ValidationFailure::UnknownValidator)
        );
    }

    #[test]
    fn repeated_runs_are_byte_for_byte_deterministic() {
        let synthetic_ssn = synthetic_us_ssn();
        let cases = [
            (LUHN_V1, "0000000000000000"),
            (LUHN_V1, "0000000000000001"),
            (IBAN_MOD97_V1, "ZZ50SYNTHETIC000000"),
            (IBAN_MOD97_V1, "ZZ51SYNTHETIC000000"),
            (US_SSN_ALLOCATION_V1, synthetic_ssn.as_str()),
            (US_SSN_ALLOCATION_V1, "900626879"),
        ];
        for (provenance, candidate) in cases {
            let first = validate(provenance, candidate);
            for _ in 0..1_000 {
                assert_eq!(validate(provenance, candidate), first);
            }
        }
    }
}
