//! Sanitized, fixed public errors at the WebAssembly boundary
//! (`decision-define-runtime-bindings`).
//!
//! Every failure this crate reports to JavaScript carries only a fixed code
//! and message, mirroring [`redact_secret::SecretScanError`]'s input-free
//! contract. Two codes ([`WasmErrorCode::NotInitialized`] and
//! [`WasmErrorCode::InitializationFailed`]) are produced by this binding
//! rather than the core, the same way the core documents that
//! `INVALID_INPUT` and `INVALID_OPTIONS` are host-produced codes.

use redact_secret::{
    ActionPolicyError, ActionPolicyErrorClass, ArtifactManifestError, DetectionConfigError,
    RulesetError, RulesetErrorClass, SecretScanError, SecretScanErrorCode,
};
use wasm_bindgen::JsValue;

/// Every error code this binding can report to JavaScript: every
/// [`SecretScanErrorCode`] plus the binding-only lifecycle codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WasmErrorCode {
    /// A synchronous operation was called before `initialize()` succeeded.
    NotInitialized,
    /// `initialize()` itself failed.
    #[allow(
        dead_code,
        reason = "kept as the binding-level loader failure contract"
    )]
    InitializationFailed,
    /// A code produced by the core pipeline.
    Core(SecretScanErrorCode),
    /// A `ruleset` argument was rejected while loading (issue #495). The
    /// code is always the core's fixed `INVALID_RULESET`; the fixed class
    /// is folded into [`Self::message`].
    Ruleset(RulesetErrorClass),
    /// An `actionPolicy` argument was rejected while loading (issue #1219).
    /// The code is always the core's fixed `INVALID_ACTION_POLICY`; the fixed
    /// class and, inside a rule, its zero-based index are folded into
    /// [`Self::message`].
    ActionPolicy(ActionPolicyErrorClass, Option<usize>),
    /// The artifact manifest could not be generated (issue #1250). The code
    /// and message are the manifest class's fixed strings.
    Manifest(ArtifactManifestError),
    /// A detector selection was rejected (issue #1251). The code is the
    /// core's fixed `INVALID_DETECTION_CONFIG` (or `EMPTY_DETECTION_SET`); the
    /// fixed class and, for one id, its array position are folded into
    /// [`Self::message`], never the id itself.
    Detection(DetectionConfigError),
}

impl WasmErrorCode {
    /// The stable `SCREAMING_SNAKE_CASE` code string, matching the core's
    /// convention for the codes this binding shares with it.
    fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "NOT_INITIALIZED",
            Self::InitializationFailed => "INITIALIZATION_FAILED",
            Self::Core(code) => code.as_str(),
            Self::Ruleset(_) => SecretScanErrorCode::InvalidRuleset.as_str(),
            Self::ActionPolicy(..) => SecretScanErrorCode::InvalidActionPolicy.as_str(),
            Self::Manifest(error) => error.code(),
            Self::Detection(error) => error.code().as_str(),
        }
    }

    /// The fixed, input-free message for this code. A [`Self::Ruleset`]
    /// message appends the fixed class name in parentheses — never a byte
    /// from the rejected ruleset, only
    /// [`RulesetErrorClass::as_str`](redact_secret::RulesetErrorClass::as_str)'s
    /// fixed name.
    fn message(self) -> String {
        match self {
            Self::NotInitialized => {
                "redact-secret wasm module is not initialized; call initialize() first.".to_owned()
            }
            Self::InitializationFailed => {
                "redact-secret wasm module failed to initialize.".to_owned()
            }
            Self::Core(code) => code.message().to_owned(),
            Self::Ruleset(class) => format!(
                "{} ({})",
                SecretScanErrorCode::InvalidRuleset.message(),
                class.as_str()
            ),
            // The same text `bindings/node` builds, so one rejected document
            // reads identically on both runtimes: the fixed message, the
            // fixed class, and the rule index when the violation is inside a
            // rule. Never a byte of the rejected document.
            Self::ActionPolicy(class, Some(index)) => format!(
                "{} ({}, rule {index})",
                SecretScanErrorCode::InvalidActionPolicy.message(),
                class.as_str()
            ),
            Self::ActionPolicy(class, None) => format!(
                "{} ({})",
                SecretScanErrorCode::InvalidActionPolicy.message(),
                class.as_str()
            ),
            Self::Manifest(error) => error.message().to_owned(),
            // The same text `bindings/node` builds.
            Self::Detection(error) => match error.index() {
                Some(index) => format!(
                    "{} ({}, id {index})",
                    error.code().message(),
                    error.class_name()
                ),
                None => format!("{} ({})", error.code().message(), error.class_name()),
            },
        }
    }
}

impl From<SecretScanErrorCode> for WasmErrorCode {
    fn from(code: SecretScanErrorCode) -> Self {
        Self::Core(code)
    }
}

impl From<SecretScanError> for WasmErrorCode {
    fn from(error: SecretScanError) -> Self {
        Self::Core(error.code())
    }
}

impl From<RulesetError> for WasmErrorCode {
    fn from(error: RulesetError) -> Self {
        Self::Ruleset(error.class())
    }
}

impl From<ArtifactManifestError> for WasmErrorCode {
    fn from(error: ArtifactManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<DetectionConfigError> for WasmErrorCode {
    fn from(error: DetectionConfigError) -> Self {
        Self::Detection(error)
    }
}

impl From<ActionPolicyError> for WasmErrorCode {
    fn from(error: ActionPolicyError) -> Self {
        Self::ActionPolicy(error.class(), error.rule_index())
    }
}

/// Builds the `Error` JavaScript sees for `code`, with a `code` property
/// alongside the standard `message`. Never carries input, a matched value,
/// or anything beyond `code`'s fixed strings.
pub(crate) fn to_js_error(code: WasmErrorCode) -> JsValue {
    let error = js_sys::Error::new(&code.message());
    error.set_name("SecretScanError");
    let _ = js_sys::Reflect::set(
        &error,
        &JsValue::from_str("code"),
        &JsValue::from_str(code.as_str()),
    );
    error.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_only_codes_have_fixed_input_free_strings() {
        assert_eq!(WasmErrorCode::NotInitialized.as_str(), "NOT_INITIALIZED");
        assert!(!WasmErrorCode::NotInitialized.message().is_empty());
        assert_eq!(
            WasmErrorCode::InitializationFailed.as_str(),
            "INITIALIZATION_FAILED"
        );
        assert!(!WasmErrorCode::InitializationFailed.message().is_empty());
    }

    #[test]
    fn manifest_errors_carry_the_fixed_class_code_and_message() {
        let wrapped = WasmErrorCode::from(ArtifactManifestError::SchemaMismatch);
        assert_eq!(wrapped.as_str(), "ARTIFACT_MANIFEST_SCHEMA_MISMATCH");
        assert_eq!(
            wrapped.message(),
            "The artifact manifest schema is not supported."
        );
    }

    #[test]
    fn detection_errors_carry_the_fixed_code_class_and_position_only() {
        let rejection = redact_secret::DetectionSelection::from_json(
            r#"{"include":["jwt","Not-An-Identifier"]}"#,
        )
        .expect_err("expected the malformed id to be rejected");
        let wrapped = WasmErrorCode::from(rejection);
        assert_eq!(wrapped.as_str(), "INVALID_DETECTION_CONFIG");
        assert_eq!(
            wrapped.message(),
            "The detector selection is invalid. (INVALID_IDENTIFIER, id 1)"
        );
        assert!(!wrapped.message().contains("Not-An-Identifier"));
    }

    #[test]
    fn core_codes_pass_through_unchanged() {
        for code in SecretScanErrorCode::ALL {
            let wrapped = WasmErrorCode::from(code);
            assert_eq!(wrapped.as_str(), code.as_str());
            assert_eq!(wrapped.message(), code.message());
        }
        let error = SecretScanError::new(SecretScanErrorCode::PolicyFailure);
        assert_eq!(
            WasmErrorCode::from(error).as_str(),
            SecretScanErrorCode::PolicyFailure.as_str()
        );
    }

    #[test]
    fn action_policy_errors_carry_the_fixed_code_class_and_rule_index() {
        let document = br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["jwt"]},"action":"mask"}]}"#;
        let rejection = redact_secret::load_action_policy(document)
            .expect_err("expected the unknown action to be rejected");
        let wrapped = WasmErrorCode::from(rejection);
        assert_eq!(wrapped.as_str(), "INVALID_ACTION_POLICY");
        assert_eq!(
            wrapped.message(),
            "The supplied action policy is invalid. (INVALID_ACTION, rule 0)"
        );

        let rejection = redact_secret::load_action_policy(b"")
            .expect_err("expected an empty document to be rejected");
        let wrapped = WasmErrorCode::from(rejection);
        assert_eq!(wrapped.as_str(), "INVALID_ACTION_POLICY");
        assert_eq!(
            wrapped.message(),
            "The supplied action policy is invalid. (MALFORMED_DOCUMENT)"
        );
    }

    #[test]
    fn ruleset_errors_carry_the_fixed_code_and_append_the_class() {
        let rejection = redact_secret::load_ruleset(b"ruleset-revision: 2\n")
            .err()
            .expect("expected the unsupported revision to be rejected");
        let wrapped = WasmErrorCode::from(rejection);
        assert_eq!(wrapped.as_str(), "INVALID_RULESET");
        assert!(wrapped.message().contains("UNKNOWN_REVISION"));
    }

    // `to_js_error` builds a real JavaScript `Error`, so this only runs
    // under `wasm32` (see the crate-level note in `lib.rs`).
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn js_error_carries_the_fixed_code_and_message_and_nothing_else() {
        let js_error = to_js_error(WasmErrorCode::NotInitialized);
        let error: js_sys::Error = js_error.into();
        assert_eq!(error.name(), "SecretScanError");
        assert_eq!(error.message(), WasmErrorCode::NotInitialized.message());
        let code = js_sys::Reflect::get(&error, &JsValue::from_str("code")).unwrap();
        assert_eq!(code.as_string().as_deref(), Some("NOT_INITIALIZED"));
    }
}
