//! Adapts a JavaScript function into the core's [`Policy`] or
//! [`PlaceholderFormatter`] trait (`decision-define-runtime-bindings`).
//!
//! Every failure path here — the callback throwing, or returning something
//! that is not the expected shape — collapses to the opaque, payload-free
//! [`PolicyFailure`] or [`FormatterFailure`] the core already defines. The
//! pipeline turns that into a fixed [`SecretScanErrorCode::PolicyFailure`] or
//! `PlaceholderFailure`, so a callback can never leak a JavaScript exception's
//! message (which could echo the input) into the public error surface
//! (`decision-govern-cross-language-conformance`).

use js_sys::Function;
use redact_secret::{
    Action, DetectedFinding, Finding, FormatterFailure, PlaceholderContext, PlaceholderFormatter,
    Policy, PolicyContext, PolicyFailure,
};
use wasm_bindgen::JsValue;

use crate::metadata;

/// Wraps a JavaScript function as a [`Policy`]: called with
/// `(findingMetadata, context)`, it must return one of the four fixed action
/// names (`"redact"`, `"block"`, `"warn"`, `"allow"`).
pub(crate) struct JsPolicy<'a> {
    input: &'a str,
    function: &'a Function,
}

impl<'a> JsPolicy<'a> {
    pub(crate) const fn new(input: &'a str, function: &'a Function) -> Self {
        Self { input, function }
    }
}

impl Policy for JsPolicy<'_> {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        let finding_metadata =
            metadata::policy_finding(self.input, finding).map_err(|_| PolicyFailure)?;
        let context_metadata = metadata::policy_context(*context).map_err(|_| PolicyFailure)?;
        let result = self
            .function
            .call2(&JsValue::UNDEFINED, &finding_metadata, &context_metadata)
            .map_err(|_| PolicyFailure)?;
        let action_name = result.as_string().ok_or(PolicyFailure)?;
        Action::from_name(&action_name).ok_or(PolicyFailure)
    }
}

/// Wraps a JavaScript function as a [`PlaceholderFormatter`]: called with
/// `(findingMetadata, context)`, it must return a placeholder string. Any
/// further validation of that string (non-empty, bounded, not reproducing a
/// matched value) is the core's responsibility, not this wrapper's.
pub(crate) struct JsPlaceholderFormatter<'a> {
    input: &'a str,
    function: &'a Function,
}

impl<'a> JsPlaceholderFormatter<'a> {
    pub(crate) const fn new(input: &'a str, function: &'a Function) -> Self {
        Self { input, function }
    }
}

impl PlaceholderFormatter for JsPlaceholderFormatter<'_> {
    fn format(
        &self,
        finding: &Finding,
        context: &PlaceholderContext,
    ) -> Result<String, FormatterFailure> {
        let finding_metadata =
            metadata::formatter_finding(self.input, finding).map_err(|_| FormatterFailure)?;
        let context_metadata =
            metadata::placeholder_context(*context).map_err(|_| FormatterFailure)?;
        let result = self
            .function
            .call2(&JsValue::UNDEFINED, &finding_metadata, &context_metadata)
            .map_err(|_| FormatterFailure)?;
        result.as_string().ok_or(FormatterFailure)
    }
}

// These tests call real JavaScript functions through `js_sys::Function`, so
// they only run under `wasm32` (via `wasm-bindgen-test-runner`), not a native
// `cargo test`: `#[wasm_bindgen_test]` compiles to a no-op on every other
// target (see the crate-level note in `lib.rs`).
#[cfg(test)]
mod tests {
    use super::*;
    use redact_secret::{ByteRange, Confidence};
    use wasm_bindgen_test::wasm_bindgen_test;

    fn detected_finding() -> DetectedFinding {
        DetectedFinding::new(
            "finding-1",
            "aws_access_key_id",
            "aws-access-key",
            Confidence::High,
            ByteRange::new(0, 4).unwrap(),
        )
        .unwrap()
    }

    fn finding() -> Finding {
        detected_finding().with_action(Action::Redact)
    }

    #[wasm_bindgen_test]
    fn policy_callback_receives_only_safe_metadata_and_can_choose_an_action() {
        let function = Function::new_with_args(
            "finding, context",
            "if (Object.prototype.hasOwnProperty.call(finding, 'input')) { throw new Error('leak'); }
             const findingOk = finding.id === 'finding-1' && finding.type === 'aws_access_key_id'
               && finding.detector === 'aws-access-key' && finding.confidence === 'high'
               && finding.obfuscation === 'none'
               && finding.range.start === 0 && finding.range.end === 4
               && Object.keys(finding).sort().join(',') === 'confidence,detector,id,obfuscation,range,type';
             const contextOk = context.findingIndex === 0 && context.findingCount === 1;
             return (findingOk && contextOk) ? 'redact' : 'warn';",
        );
        let policy = JsPolicy::new("AKIA", &function);
        let action = policy
            .evaluate(&detected_finding(), &PolicyContext::new(0, 1))
            .unwrap();
        assert_eq!(action, Action::Redact);
    }

    #[wasm_bindgen_test]
    fn policy_callback_throwing_is_a_deterministic_policy_failure() {
        let function = Function::new_no_args("throw new Error('boom');");
        let policy = JsPolicy::new("AKIA", &function);
        assert_eq!(
            policy.evaluate(&detected_finding(), &PolicyContext::new(0, 1)),
            Err(PolicyFailure)
        );
    }

    #[wasm_bindgen_test]
    fn policy_callback_returning_an_unrecognized_action_is_a_policy_failure() {
        let function = Function::new_no_args("return 'not-a-real-action';");
        let policy = JsPolicy::new("AKIA", &function);
        assert_eq!(
            policy.evaluate(&detected_finding(), &PolicyContext::new(0, 1)),
            Err(PolicyFailure)
        );
    }

    #[wasm_bindgen_test]
    fn policy_callback_returning_a_non_string_is_a_policy_failure() {
        let function = Function::new_no_args("return 42;");
        let policy = JsPolicy::new("AKIA", &function);
        assert_eq!(
            policy.evaluate(&detected_finding(), &PolicyContext::new(0, 1)),
            Err(PolicyFailure)
        );
    }

    #[wasm_bindgen_test]
    fn formatter_callback_receives_the_action_alongside_safe_metadata() {
        let function = Function::new_with_args(
            "finding, context",
            "if (Object.prototype.hasOwnProperty.call(finding, 'input')) { throw new Error('leak'); }
             return finding.action + '-' + context.placeholderIndex;",
        );
        let formatter = JsPlaceholderFormatter::new("AKIA", &function);
        let placeholder = formatter
            .format(&finding(), &PlaceholderContext::new(1))
            .unwrap();
        assert_eq!(placeholder, "redact-1");
    }

    #[wasm_bindgen_test]
    fn formatter_callback_throwing_is_a_deterministic_formatter_failure() {
        let function = Function::new_no_args("throw new Error('boom');");
        let formatter = JsPlaceholderFormatter::new("AKIA", &function);
        assert_eq!(
            formatter.format(&finding(), &PlaceholderContext::new(1)),
            Err(FormatterFailure)
        );
    }

    #[wasm_bindgen_test]
    fn formatter_callback_returning_a_non_string_is_a_formatter_failure() {
        let function = Function::new_no_args("return null;");
        let formatter = JsPlaceholderFormatter::new("AKIA", &function);
        assert_eq!(
            formatter.format(&finding(), &PlaceholderContext::new(1)),
            Err(FormatterFailure)
        );
    }
}
