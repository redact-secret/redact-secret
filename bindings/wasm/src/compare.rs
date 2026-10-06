//! Explain and compare action policies over one detection pass
//! (`decision-explain-and-compare-action-policies-over-one-detection-pass`,
//! issue #1220).
//!
//! The whole-input primitive only: there is no session or stream variant. The
//! sides arrive as parallel arguments built by `@redact-secret/core`'s own
//! wrapper (`kinds`, the action policy `documents` in the order their sides
//! appear, and the `callbacks` in the order theirs do).
//!
//! The result is one flat JavaScript array of strings, numbers, booleans and
//! `null`, assembled from the core's [`ActionComparison`]: safe metadata and
//! the per-side decisions only, no input byte and no matched value. A flat
//! array keeps this artifact small (a nested object would spend a property
//! write and a key string on every field), and the wrapper
//! (`runtime/wasm-binding.ts`'s `decodeComparison`) rebuilds the nested shape
//! the Node addon returns, so the two runtimes meet in one public result.
//!
//! Layout, in order, with `S` sides and `N` findings:
//!
//! ```text
//! activationIdentity, profile|null, detectorCount,
//! S, S x (kind, documentSha256|null, redact, block, warn, allow),
//! changedCount,
//! N, N x (id, type, detector, confidence, obfuscation, start, end, differs,
//!         S x (action, basis, ruleId|null, ruleIndex|null))
//! ```

use js_sys::{Array, Function};
use redact_secret::{
    ActionComparison, ActionPolicy, ComparedPolicy, DetectorRegistry, MAX_COMPARED_POLICIES,
    SecretScanError, SecretScanErrorCode, WholeInputLimits, load_action_policy,
};
use wasm_bindgen::JsValue;

use crate::callbacks::JsPolicy;
use crate::error::WasmErrorCode;
use crate::range::Utf16Ranges;
use crate::util::saturating_u32;

/// How one comparison side is evaluated, once every document is loaded.
pub(crate) enum SidePlan {
    Default,
    ActionPolicy(ActionPolicy),
    /// The position among the call's callbacks.
    Callback(usize),
}

/// Resolves the parallel `kinds`/`documents`/`callbacks` arguments to one plan
/// per side. The count check comes first, so a call with no or too many sides
/// loads no document and runs no callback; a rejected document is
/// `INVALID_ACTION_POLICY` before detection starts. The arrays are built by
/// this package's own wrapper, so a mismatch is a malformed call and
/// `INVALID_OPTIONS`.
pub(crate) fn plan_sides(
    kinds: &[String],
    documents: &[Vec<u8>],
    callback_count: usize,
) -> Result<Vec<SidePlan>, WasmErrorCode> {
    let invalid = || WasmErrorCode::from(SecretScanErrorCode::InvalidOptions);
    if kinds.is_empty() || kinds.len() > MAX_COMPARED_POLICIES {
        return Err(invalid());
    }
    let mut documents = documents.iter();
    let mut next_callback = 0;
    let mut plans = Vec::with_capacity(kinds.len());
    for kind in kinds {
        plans.push(match kind.as_str() {
            "default" => SidePlan::Default,
            "action-policy" => {
                let bytes = documents.next().ok_or_else(invalid)?;
                SidePlan::ActionPolicy(load_action_policy(bytes)?)
            }
            "callback" => {
                if next_callback >= callback_count {
                    return Err(invalid());
                }
                next_callback += 1;
                SidePlan::Callback(next_callback - 1)
            }
            _ => return Err(invalid()),
        });
    }
    if documents.next().is_some() || next_callback != callback_count {
        return Err(invalid());
    }
    Ok(plans)
}

/// Runs one comparison over `registry`: the core primitive, with each callback
/// side adapted by the same [`JsPolicy`] `scan` uses (so a throw is
/// `POLICY_FAILURE` and a return outside the four action names is
/// `INVALID_POLICY_ACTION`, as in `scan`).
pub(crate) fn run_compare(
    input: &str,
    registry: &DetectorRegistry,
    plans: &[SidePlan],
    callbacks: &[Function],
    limits: &WholeInputLimits,
) -> Result<ActionComparison, SecretScanError> {
    let adapters: Vec<JsPolicy<'_>> = callbacks
        .iter()
        .map(|function| JsPolicy::new(input, function))
        .collect();
    let policies: Vec<ComparedPolicy<'_>> = plans
        .iter()
        .map(|plan| match plan {
            SidePlan::Default => ComparedPolicy::Default,
            SidePlan::ActionPolicy(document) => ComparedPolicy::ActionPolicy(document),
            SidePlan::Callback(index) => ComparedPolicy::Callback(&adapters[*index]),
        })
        .collect();
    redact_secret::compare_action_policies_with_limits(input, registry, &policies, limits).map_err(
        |error| {
            // At most one callback failed: the comparison stops at the first.
            adapters
                .iter()
                .fold(error, |error, adapter| adapter.refine(error))
        },
    )
}

fn text(out: &Array, value: &str) {
    out.push(&JsValue::from_str(value));
}

fn nullable_text(out: &Array, value: Option<&str>) {
    out.push(&value.map_or(JsValue::NULL, JsValue::from_str));
}

fn number(out: &Array, value: usize) {
    out.push(&JsValue::from_f64(f64::from(saturating_u32(value))));
}

/// Flattens `comparison` into the array described in the module
/// documentation, every range converted to UTF-16 code units over `input`.
pub(crate) fn comparison_to_array(input: &str, comparison: &ActionComparison) -> Array {
    let out = Array::new();

    let detection = comparison.detection();
    text(&out, detection.activation_identity());
    nullable_text(
        &out,
        detection.profile().map(redact_secret::Profile::as_str),
    );
    number(&out, detection.detector_count());

    number(&out, comparison.sides().len());
    for side in comparison.sides() {
        let counts = side.counts();
        text(&out, side.binding().kind());
        nullable_text(&out, side.binding().document_sha256_hex().as_deref());
        number(&out, counts.redact());
        number(&out, counts.block());
        number(&out, counts.warn());
        number(&out, counts.allow());
    }
    number(&out, comparison.changed_count());

    let mut ranges = Utf16Ranges::new(input);
    number(&out, comparison.findings().len());
    for compared in comparison.findings() {
        let finding = compared.finding();
        let (start, end) = ranges.convert(finding.range());
        text(&out, finding.id());
        text(&out, finding.type_name());
        text(&out, finding.detector());
        text(&out, finding.confidence().as_str());
        text(&out, finding.obfuscation().as_str());
        number(&out, start as usize);
        number(&out, end as usize);
        out.push(&JsValue::from_bool(compared.differs()));
        for decision in compared.decisions() {
            text(&out, decision.action().as_str());
            text(&out, decision.basis().as_str());
            nullable_text(&out, decision.basis().rule_id());
            match decision.basis().rule_index() {
                Some(index) => number(&out, index),
                None => {
                    out.push(&JsValue::NULL);
                }
            }
        }
    }
    out
}

// The callback and flat-array tests call real JavaScript, so they only run
// under `wasm32` (via `wasm-bindgen-test-runner`); the rest run natively.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lifecycle, synthetic};
    use redact_secret::{Action, DecisionBasis, PolicyBinding};
    use wasm_bindgen::JsCast;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// The synthetic input of the compiled profile, after an astral character
    /// so every converted range differs from its byte offset.
    fn input() -> String {
        format!("prefix \u{1F511} {} suffix", synthetic::secret().text)
    }

    fn document(action: &str) -> Vec<u8> {
        format!(
            r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"rule-a","match":{{"type":["{}"]}},"action":"{action}"}}]}}"#,
            synthetic::secret().type_name
        )
        .into_bytes()
    }

    fn kinds(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn compare_without_callbacks(
        kind_names: &[&str],
        documents: &[Vec<u8>],
        limits: &WholeInputLimits,
    ) -> Result<ActionComparison, SecretScanError> {
        lifecycle::initialize(&[]).unwrap();
        let plans = plan_sides(&kinds(kind_names), documents, 0).unwrap();
        lifecycle::with_registry(|registry| run_compare(&input(), registry, &plans, &[], limits))
            .unwrap()
    }

    #[test]
    fn plan_sides_bounds_the_side_count_before_loading_anything() {
        let invalid = WasmErrorCode::from(SecretScanErrorCode::InvalidOptions);
        // A document that would be rejected is never read: the count fails first.
        let broken = vec![b"{}".to_vec(); 5];

        assert!(matches!(plan_sides(&[], &[], 0), Err(code) if code == invalid));
        assert!(matches!(
            plan_sides(&kinds(&["action-policy"; 5]), &broken, 0),
            Err(code) if code == invalid
        ));
        assert_eq!(
            plan_sides(&kinds(&["default"; 4]), &[], 0).map(|plans| plans.len()),
            Ok(4)
        );
    }

    #[test]
    fn plan_sides_refuses_arguments_that_do_not_describe_the_same_sides() {
        let invalid = WasmErrorCode::from(SecretScanErrorCode::InvalidOptions);
        let one = document("warn");

        for (names, documents, callbacks) in [
            (kinds(&["session"]), vec![], 0),
            (kinds(&["default"]), vec![one.clone()], 0),
            (kinds(&["action-policy"]), vec![], 0),
            (kinds(&["default"]), vec![], 1),
            (kinds(&["callback"]), vec![], 0),
        ] {
            assert!(
                matches!(plan_sides(&names, &documents, callbacks), Err(code) if code == invalid),
                "{names:?}"
            );
        }
    }

    #[test]
    fn plan_sides_reports_a_rejected_document_as_invalid_action_policy() {
        let rejected = plan_sides(&kinds(&["default", "action-policy"]), &[b"{}".to_vec()], 0);

        assert!(matches!(rejected, Err(WasmErrorCode::ActionPolicy(..))));
    }

    #[test]
    fn a_comparison_explains_each_side_and_keeps_scans_findings() {
        let comparison = compare_without_callbacks(
            &["default", "action-policy", "action-policy"],
            &[document("allow"), document("default")],
            &WholeInputLimits::default(),
        )
        .unwrap();
        let findings = lifecycle::with_registry(|registry| {
            redact_secret::scan_with_limits(
                &input(),
                registry,
                &redact_secret::DefaultPolicy,
                &WholeInputLimits::default(),
            )
        })
        .unwrap()
        .unwrap();

        assert_eq!(comparison.findings().len(), findings.len());
        let compared = &comparison.findings()[0];
        assert_eq!(compared.finding().id(), findings[0].id());
        assert_eq!(compared.finding().range(), findings[0].range());
        assert_eq!(compared.decisions().len(), 3);
        let (default, allowed, carved) = (
            &compared.decisions()[0],
            &compared.decisions()[1],
            &compared.decisions()[2],
        );
        assert_eq!(default.action(), findings[0].action());
        assert_eq!(default.basis(), &DecisionBasis::DefaultPolicy);
        assert_eq!(allowed.action(), Action::Allow);
        assert_eq!(allowed.basis().rule_id(), Some("rule-a"));
        assert_eq!(carved.action(), findings[0].action());
        assert!(matches!(carved.basis(), DecisionBasis::RuleDefault { .. }));
        assert!(compared.differs());
        assert_eq!(comparison.changed_count(), 1);
        assert!(matches!(
            comparison.sides()[1].binding(),
            PolicyBinding::ActionPolicy { .. }
        ));
        assert_eq!(
            comparison.sides()[1]
                .binding()
                .document_sha256_hex()
                .map(|hex| hex.len()),
            Some(64)
        );
    }

    #[test]
    fn a_comparison_applies_the_whole_input_limits_as_scan_does() {
        let error =
            compare_without_callbacks(&["default"], &[], &WholeInputLimits::new(5, 50).unwrap())
                .unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::InputLimitExceeded);
    }

    fn global_log() -> Array {
        let global = js_sys::global();
        let key = JsValue::from_str("__compareLog");
        let existing = js_sys::Reflect::get(&global, &key).unwrap();
        if let Some(log) = existing.dyn_ref::<Array>() {
            return log.clone();
        }
        let log = Array::new();
        js_sys::Reflect::set(&global, &key, &log).unwrap();
        log
    }

    fn logging_callback(label: &str, body: &str) -> Function {
        Function::new_with_args(
            "finding, context",
            &format!("globalThis.__compareLog.push('{label}' + context.findingIndex); {body}"),
        )
    }

    fn drain_log() -> Vec<String> {
        let log = global_log();
        let calls = log.iter().filter_map(|entry| entry.as_string()).collect();
        log.set_length(0);
        calls
    }

    fn run_with_callbacks(callbacks: &[Function]) -> Result<ActionComparison, SecretScanError> {
        lifecycle::initialize(&[]).unwrap();
        drain_log();
        let names: Vec<&str> = callbacks.iter().map(|_| "callback").collect();
        let plans = plan_sides(&kinds(&names), &[], callbacks.len()).unwrap();
        lifecycle::with_registry(|registry| {
            run_compare(
                &input(),
                registry,
                &plans,
                callbacks,
                &WholeInputLimits::default(),
            )
        })
        .unwrap()
    }

    #[wasm_bindgen_test]
    fn callback_sides_run_one_at_a_time_once_per_finding() {
        let first = logging_callback("A", "return 'warn';");
        let second = logging_callback("B", "return 'allow';");

        let comparison = run_with_callbacks(&[first, second]).unwrap();

        let expected: Vec<String> = ["A", "B"]
            .iter()
            .flat_map(|label| {
                (0..comparison.findings().len()).map(move |index| format!("{label}{index}"))
            })
            .collect();
        assert_eq!(drain_log(), expected);
        let compared = &comparison.findings()[0];
        assert_eq!(compared.decisions()[0].action(), Action::Warn);
        assert_eq!(compared.decisions()[1].action(), Action::Allow);
        assert_eq!(compared.decisions()[0].basis(), &DecisionBasis::Callback);
    }

    #[wasm_bindgen_test]
    fn a_throwing_callback_fails_the_whole_comparison_and_stops_later_sides() {
        let failing = logging_callback("A", "throw new Error('boom');");
        let later = logging_callback("B", "return 'allow';");

        let error = run_with_callbacks(&[failing, later]).unwrap_err();

        assert_eq!(error.code(), SecretScanErrorCode::PolicyFailure);
        assert_eq!(drain_log(), vec!["A0".to_owned()]);
    }

    #[wasm_bindgen_test]
    fn an_unknown_action_is_invalid_policy_action_and_a_non_string_is_policy_failure() {
        let unknown = logging_callback("A", "return 'mask';");
        let error = run_with_callbacks(&[unknown]).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidPolicyAction);
        assert_eq!(drain_log(), vec!["A0".to_owned()]);

        let non_string = logging_callback("A", "return 7;");
        let error = run_with_callbacks(&[non_string]).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::PolicyFailure);
    }

    #[wasm_bindgen_test]
    fn the_flat_array_follows_the_documented_layout_with_utf16_ranges() {
        let comparison = compare_without_callbacks(
            &["default", "action-policy"],
            &[document("allow")],
            &WholeInputLimits::default(),
        )
        .unwrap();

        let flat = comparison_to_array(&input(), &comparison);

        // 3 detection values, a side count, 2 sides of 6, the changed count,
        // the finding count, then per finding 8 values and 4 per side.
        let findings = comparison.findings().len();
        assert_eq!(
            flat.length() as usize,
            3 + 1 + 2 * 6 + 1 + 1 + findings * (8 + 2 * 4)
        );
        assert_eq!(flat.get(3).as_f64(), Some(2.0));
        assert_eq!(flat.get(4).as_string().as_deref(), Some("default"));
        assert!(flat.get(5).is_null());
        let first_finding = 3 + 1 + 12 + 1 + 1;
        // The key emoji is two UTF-16 code units and four UTF-8 bytes.
        let byte_start = comparison.findings()[0].finding().range().start();
        assert_eq!(
            flat.get(first_finding + 5),
            JsValue::from_f64(f64::from(u32::try_from(byte_start - 2).unwrap()))
        );
        assert_eq!(flat.get(first_finding + 7).as_bool(), Some(true));
        assert_eq!(
            flat.get(first_finding + 9).as_string().as_deref(),
            Some("default-policy")
        );
    }
}
