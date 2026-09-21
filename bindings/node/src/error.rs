//! Sanitized error mapping between [`redact_secret::SecretScanError`] and the
//! JavaScript error contract (`decision-define-runtime-bindings`).
//!
//! Every thrown error carries the core's fixed `SCREAMING_SNAKE_CASE` code as
//! its `code` property and the core's fixed message as `message`. No thrown
//! error carries input or a matched value.

use napi::Error as NapiError;
use redact_secret::{RulesetError, SecretScanError};

/// The JavaScript error type this crate throws: `status` (surfaced to
/// JavaScript as `code`) carries the fixed [`redact_secret::SecretScanErrorCode`]
/// string instead of a generic N-API status name.
pub type JsError = NapiError<String>;

/// Converts a sanitized core error into the JavaScript error contract.
#[must_use]
pub fn to_js_error(error: SecretScanError) -> JsError {
    NapiError::new(error.code().as_str().to_owned(), error.message().to_owned())
}

/// Converts a rejected `--ruleset`-equivalent load into the JavaScript error
/// contract (issue #495). `status` is always the one public
/// `INVALID_RULESET` code; the fixed rejection class is appended to the
/// message, in parentheses, since [`JsError`] carries no third field — never
/// a byte from the rejected ruleset, only the fixed class name
/// [`redact_secret::RulesetErrorClass::as_str`] already gives.
#[must_use]
pub fn to_js_ruleset_error(error: RulesetError) -> JsError {
    NapiError::new(
        error.code().as_str().to_owned(),
        format!("{} ({})", error.message(), error.class().as_str()),
    )
}

#[cfg(test)]
mod tests {
    use redact_secret::SecretScanErrorCode;

    use super::*;

    #[test]
    fn carries_the_fixed_code_and_message() {
        let error = to_js_error(SecretScanErrorCode::InvalidFindings.into());
        assert_eq!(error.status, "INVALID_FINDINGS");
        assert_eq!(error.reason, "Redaction findings are invalid.");
    }

    #[test]
    fn ruleset_errors_carry_the_fixed_code_and_class() {
        let text = b"ruleset-revision: 2\n";
        let rejection = redact_secret::load_ruleset(text)
            .err()
            .expect("expected the unsupported revision to be rejected");
        let error = to_js_ruleset_error(rejection);
        assert_eq!(error.status, "INVALID_RULESET");
        assert!(error.reason.contains("UNKNOWN_REVISION"));
        assert_eq!(
            error.reason,
            "The supplied ruleset is invalid. (UNKNOWN_REVISION)"
        );
    }
}
