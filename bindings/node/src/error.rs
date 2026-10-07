//! Sanitized error mapping between [`redact_secret::SecretScanError`] and the
//! JavaScript error contract (`decision-define-runtime-bindings`).
//!
//! Every thrown error carries the core's fixed `SCREAMING_SNAKE_CASE` code as
//! its `code` property and the core's fixed message as `message`. No thrown
//! error carries input or a matched value.

use napi::Error as NapiError;
use redact_secret::{ActionPolicyError, ArtifactManifestError, RulesetError, SecretScanError};

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

/// The message of a rejected action policy: the one fixed
/// `INVALID_ACTION_POLICY` message, then the fixed rejection class, then the
/// zero-based rule index when the violation is inside a rule. Only fixed
/// identifiers and an integer; never a byte of the rejected document.
#[must_use]
pub fn action_policy_message(error: ActionPolicyError) -> String {
    match error.rule_index() {
        Some(index) => format!(
            "{} ({}, rule {index})",
            error.message(),
            error.class().as_str()
        ),
        None => format!("{} ({})", error.message(), error.class().as_str()),
    }
}

/// Converts a rejected action policy load into the JavaScript error contract
/// (`decision-define-the-versioned-declarative-action-policy-and-default-overlay`,
/// issue #1219). `status` is always the one public `INVALID_ACTION_POLICY`
/// code. [`JsError`] carries no third field, so the fixed rejection class and
/// the rule index are appended to the message as [`action_policy_message`]
/// formats them (the class alone for a document-level violation), the same
/// way [`to_js_ruleset_error`] carries a ruleset's class.
#[must_use]
pub fn to_js_action_policy_error(error: ActionPolicyError) -> JsError {
    NapiError::new(
        error.code().as_str().to_owned(),
        action_policy_message(error),
    )
}

/// Converts a manifest failure into the JavaScript error contract (issue
/// #1250). `status` is the fixed `ARTIFACT_MANIFEST_*` class code and the
/// message is the fixed one; neither carries any document content.
#[must_use]
pub fn to_js_manifest_error(error: ArtifactManifestError) -> JsError {
    NapiError::new(error.code().to_owned(), error.message().to_owned())
}

#[cfg(test)]
mod tests {
    use redact_secret::SecretScanErrorCode;

    use super::*;

    #[test]
    fn manifest_errors_carry_the_fixed_class_code_and_message() {
        let error = to_js_manifest_error(ArtifactManifestError::DigestMismatch);
        assert_eq!(error.status, "ARTIFACT_MANIFEST_DIGEST_MISMATCH");
        assert_eq!(
            error.reason,
            "The artifact manifest does not match this artifact."
        );
    }

    #[test]
    fn carries_the_fixed_code_and_message() {
        let error = to_js_error(SecretScanErrorCode::InvalidFindings.into());
        assert_eq!(error.status, "INVALID_FINDINGS");
        assert_eq!(error.reason, "Redaction findings are invalid.");
    }

    #[test]
    fn action_policy_errors_carry_the_fixed_code_class_and_rule_index() {
        let document = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["jwt"]},"action":"mask"}]}"#;
        let rejection = redact_secret::load_action_policy(document)
            .expect_err("expected the unknown action to be rejected");
        let error = to_js_action_policy_error(rejection);
        assert_eq!(error.status, "INVALID_ACTION_POLICY");
        assert_eq!(
            error.reason,
            "The supplied action policy is invalid. (INVALID_ACTION, rule 0)"
        );

        let rejection = redact_secret::load_action_policy(b"")
            .expect_err("expected an empty document to be rejected");
        let error = to_js_action_policy_error(rejection);
        assert_eq!(error.status, "INVALID_ACTION_POLICY");
        assert_eq!(
            error.reason,
            "The supplied action policy is invalid. (MALFORMED_DOCUMENT)"
        );
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
