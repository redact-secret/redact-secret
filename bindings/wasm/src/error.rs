//! Sanitized, fixed public errors at the WebAssembly boundary
//! (`decision-define-runtime-bindings`).
//!
//! Every failure this crate reports to JavaScript carries only a fixed code
//! and message, mirroring [`redact_secret::SecretScanError`]'s input-free
//! contract. Two codes ([`WasmErrorCode::NotInitialized`] and
//! [`WasmErrorCode::InitializationFailed`]) are produced by this binding
//! rather than the core, the same way the core documents that
//! `INVALID_INPUT` and `INVALID_OPTIONS` are host-produced codes.

use redact_secret::{RulesetError, RulesetErrorClass, SecretScanError, SecretScanErrorCode};
use wasm_bindgen::JsValue;

/// Every error code this binding can report to JavaScript: every
/// [`SecretScanErrorCode`] plus the binding-only lifecycle codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WasmErrorCode {
    /// A synchronous operation was called before `initialize()` succeeded.
    NotInitialized,
    /// `initialize()` itself failed.
    InitializationFailed,
    /// A code produced by the core pipeline.
    Core(SecretScanErrorCode),
    /// A `ruleset` argument was rejected while loading (issue #495). The
    /// code is always the core's fixed `INVALID_RULESET`; the fixed class
    /// is folded into [`Self::message`].
    Ruleset(RulesetErrorClass),
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
