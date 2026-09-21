//! Sanitized public errors.
//!
//! Every failure that crosses the crate boundary is a [`SecretScanError`]
//! carrying only a fixed [`SecretScanErrorCode`]. The code selects a fixed
//! message; nothing about the input, a candidate, or a matched value is ever
//! attached. Bindings surface the code string and message verbatim so every
//! host reports identical, input-free diagnostics.

use std::fmt;

/// Fixed public error codes.
///
/// The string form ([`as_str`](Self::as_str)) and the message
/// ([`message`](Self::message)) are part of the cross-language contract and
/// must not change without a corpus review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecretScanErrorCode {
    /// The host passed something other than a text input. The core itself
    /// only accepts `&str`, so this code is produced by bindings.
    InvalidInput,
    /// Scan options could not be interpreted. Produced by bindings that accept
    /// dynamically typed option objects.
    InvalidOptions,
    /// A detector registration was rejected: malformed or duplicate id.
    InvalidDetector,
    /// A detector reported a failure while scanning.
    DetectorFailure,
    /// A detector returned a candidate that violates the candidate contract.
    InvalidCandidate,
    /// The policy reported a failure while evaluating a finding.
    PolicyFailure,
    /// A policy returned something that is not one of the four actions.
    /// The Rust [`Action`](crate::Action) enum cannot express this, so this
    /// code is produced by bindings that accept dynamically typed actions.
    InvalidPolicyAction,
    /// A redaction finding is out of range, misordered, or overlaps another
    /// finding.
    InvalidFindings,
    /// The placeholder formatter reported a failure while redacting.
    PlaceholderFailure,
    /// The placeholder formatter returned an empty, oversized, or
    /// matched-value-reproducing placeholder.
    InvalidPlaceholder,
    /// An incremental session's or whole-input operation's limits were
    /// missing, non-positive, or did not satisfy the documented relationship
    /// between them.
    InvalidLimits,
    /// An accepted input would exceed the configured input-byte limit: an
    /// incremental session's total accepted input across every append, or a
    /// whole-input `scan`/`redact`/`scan_and_redact` call's input.
    InputLimitExceeded,
    /// An incremental session's retained, unresolved plaintext would exceed
    /// `max_buffered_bytes`.
    BufferLimitExceeded,
    /// An incremental session's open single-line construct would exceed
    /// `max_token_bytes` without closing.
    TokenLimitExceeded,
    /// An incremental session's open PEM-style private-key block would
    /// exceed `max_multiline_bytes` without closing.
    MultilineLimitExceeded,
    /// The accepted finding count from a whole-input scan would exceed the
    /// configured finding-count limit. Only whole-input `scan` and
    /// `scan_and_redact` (and `redact` given an externally-constructed
    /// finding list) produce this code; there is no incremental equivalent.
    FindingLimitExceeded,
    /// An incremental session received `append`, `finalize`, or `abort`
    /// after it left the accepting state.
    InvalidState,
    /// A caller-supplied declarative ruleset was rejected while loading
    /// (`decision-define-declarative-detector-ruleset-contract`). The fixed
    /// rejection class is carried separately by
    /// [`RulesetError::class`](crate::RulesetError::class), never by this
    /// code alone.
    InvalidRuleset,
}

impl SecretScanErrorCode {
    /// Every code, in declaration order.
    pub const ALL: [Self; 18] = [
        Self::InvalidInput,
        Self::InvalidOptions,
        Self::InvalidDetector,
        Self::DetectorFailure,
        Self::InvalidCandidate,
        Self::PolicyFailure,
        Self::InvalidPolicyAction,
        Self::InvalidFindings,
        Self::PlaceholderFailure,
        Self::InvalidPlaceholder,
        Self::InvalidLimits,
        Self::InputLimitExceeded,
        Self::BufferLimitExceeded,
        Self::TokenLimitExceeded,
        Self::MultilineLimitExceeded,
        Self::FindingLimitExceeded,
        Self::InvalidState,
        Self::InvalidRuleset,
    ];

    /// The stable `SCREAMING_SNAKE_CASE` code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::InvalidOptions => "INVALID_OPTIONS",
            Self::InvalidDetector => "INVALID_DETECTOR",
            Self::DetectorFailure => "DETECTOR_FAILURE",
            Self::InvalidCandidate => "INVALID_CANDIDATE",
            Self::PolicyFailure => "POLICY_FAILURE",
            Self::InvalidPolicyAction => "INVALID_POLICY_ACTION",
            Self::InvalidFindings => "INVALID_FINDINGS",
            Self::PlaceholderFailure => "PLACEHOLDER_FAILURE",
            Self::InvalidPlaceholder => "INVALID_PLACEHOLDER",
            Self::InvalidLimits => "INVALID_LIMITS",
            Self::InputLimitExceeded => "INPUT_LIMIT_EXCEEDED",
            Self::BufferLimitExceeded => "BUFFER_LIMIT_EXCEEDED",
            Self::TokenLimitExceeded => "TOKEN_LIMIT_EXCEEDED",
            Self::MultilineLimitExceeded => "MULTILINE_LIMIT_EXCEEDED",
            Self::FindingLimitExceeded => "FINDING_LIMIT_EXCEEDED",
            Self::InvalidState => "INVALID_STATE",
            Self::InvalidRuleset => "INVALID_RULESET",
        }
    }

    /// The fixed, input-free message for this code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidInput => "Secret scan input must be a string.",
            Self::InvalidOptions => "Secret scan options are invalid.",
            Self::InvalidDetector => "Invalid detector registration.",
            Self::DetectorFailure => "A secret detector failed.",
            Self::InvalidCandidate => "A secret detector returned an invalid candidate.",
            Self::PolicyFailure => "The secret policy failed.",
            Self::InvalidPolicyAction => "The secret policy returned an invalid action.",
            Self::InvalidFindings => "Redaction findings are invalid.",
            Self::PlaceholderFailure => "The placeholder formatter failed.",
            Self::InvalidPlaceholder => "The placeholder formatter returned an invalid value.",
            Self::InvalidLimits => "Secret scan limits are invalid.",
            Self::InputLimitExceeded => "Secret scan input limit exceeded.",
            Self::BufferLimitExceeded => "Incremental sanitizer buffer limit exceeded.",
            Self::TokenLimitExceeded => "Incremental sanitizer token limit exceeded.",
            Self::MultilineLimitExceeded => "Incremental sanitizer multiline limit exceeded.",
            Self::FindingLimitExceeded => "Secret scan finding limit exceeded.",
            Self::InvalidState => "The incremental sanitizer is no longer accepting input.",
            Self::InvalidRuleset => "The supplied ruleset is invalid.",
        }
    }
}

impl fmt::Display for SecretScanErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A sanitized scan error. It holds nothing but its code.
///
/// Every failure this crate reports is one of these: a fixed
/// [`SecretScanErrorCode`] and its fixed message, with no payload. No error
/// carries the scanned input, a matched value, a candidate field, or a
/// placeholder, so an error can be logged or returned to a caller without
/// leaking what was being scanned.
///
/// # Examples
///
/// ```
/// use redact_secret::{DetectorRegistry, SecretScanErrorCode, redact, scan, DefaultPolicy};
///
/// let registry = DetectorRegistry::with_built_in([])?;
/// let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
/// let findings = scan(input, &registry, &DefaultPolicy)?;
///
/// // The same findings do not describe a shorter input.
/// let error = redact("short", &findings, &redact_secret::default_placeholder_formatter).unwrap_err();
/// assert_eq!(error.code(), SecretScanErrorCode::InvalidFindings);
/// assert_eq!(error.to_string(), "Redaction findings are invalid.");
/// assert!(!error.to_string().contains("ghp_"));
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SecretScanError {
    code: SecretScanErrorCode,
}

impl SecretScanError {
    /// Creates an error for `code`.
    #[must_use]
    pub const fn new(code: SecretScanErrorCode) -> Self {
        Self { code }
    }

    /// The error code.
    #[must_use]
    pub const fn code(self) -> SecretScanErrorCode {
        self.code
    }

    /// The fixed message; identical to the `Display` output.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.code.message()
    }
}

impl From<SecretScanErrorCode> for SecretScanError {
    fn from(code: SecretScanErrorCode) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for SecretScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SecretScanError {}

/// Opaque failure reported by a [`Detector`](crate::Detector).
///
/// It carries no payload by design: a detector that fails cannot leak the
/// substring it was inspecting. The pipeline maps it to
/// [`SecretScanErrorCode::DetectorFailure`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DetectorFailure;

/// Opaque failure reported by a [`Policy`](crate::Policy).
///
/// The pipeline maps it to [`SecretScanErrorCode::PolicyFailure`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PolicyFailure;

/// Opaque failure reported by a [`PlaceholderFormatter`](crate::PlaceholderFormatter).
///
/// Redaction maps it to its own fixed placeholder-failure code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FormatterFailure;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_messages_are_fixed() {
        let expected = [
            ("INVALID_INPUT", "Secret scan input must be a string."),
            ("INVALID_OPTIONS", "Secret scan options are invalid."),
            ("INVALID_DETECTOR", "Invalid detector registration."),
            ("DETECTOR_FAILURE", "A secret detector failed."),
            (
                "INVALID_CANDIDATE",
                "A secret detector returned an invalid candidate.",
            ),
            ("POLICY_FAILURE", "The secret policy failed."),
            (
                "INVALID_POLICY_ACTION",
                "The secret policy returned an invalid action.",
            ),
            ("INVALID_FINDINGS", "Redaction findings are invalid."),
            ("PLACEHOLDER_FAILURE", "The placeholder formatter failed."),
            (
                "INVALID_PLACEHOLDER",
                "The placeholder formatter returned an invalid value.",
            ),
            ("INVALID_LIMITS", "Secret scan limits are invalid."),
            ("INPUT_LIMIT_EXCEEDED", "Secret scan input limit exceeded."),
            (
                "BUFFER_LIMIT_EXCEEDED",
                "Incremental sanitizer buffer limit exceeded.",
            ),
            (
                "TOKEN_LIMIT_EXCEEDED",
                "Incremental sanitizer token limit exceeded.",
            ),
            (
                "MULTILINE_LIMIT_EXCEEDED",
                "Incremental sanitizer multiline limit exceeded.",
            ),
            (
                "FINDING_LIMIT_EXCEEDED",
                "Secret scan finding limit exceeded.",
            ),
            (
                "INVALID_STATE",
                "The incremental sanitizer is no longer accepting input.",
            ),
            ("INVALID_RULESET", "The supplied ruleset is invalid."),
        ];
        for (code, (name, message)) in SecretScanErrorCode::ALL.into_iter().zip(expected) {
            assert_eq!(code.as_str(), name);
            assert_eq!(code.message(), message);
            assert_eq!(code.to_string(), name);
            let error = SecretScanError::new(code);
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), message);
            assert_eq!(
                format!("{error:?}"),
                format!("SecretScanError {{ code: {code:?} }}")
            );
        }
    }

    #[test]
    fn opaque_failures_carry_nothing() {
        assert_eq!(std::mem::size_of::<DetectorFailure>(), 0);
        assert_eq!(std::mem::size_of::<PolicyFailure>(), 0);
        assert_eq!(std::mem::size_of::<FormatterFailure>(), 0);
        assert_eq!(std::mem::size_of::<SecretScanError>(), 1);
    }
}
