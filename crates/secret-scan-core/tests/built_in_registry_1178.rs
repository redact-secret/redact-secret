//! `BuiltInRegistry`, the `Send + Sync` built-in-only registry (issue #1178).
//!
//! Pins that the handle returns exactly what a `DetectorRegistry` of the same
//! profile and PII selection returns, that one value is safe to share across
//! threads with identical results, and that the original registry's
//! thread-safety did not change. Every input is synthetic or taken from the
//! canonical synthetic corpus.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;
use std::thread;

use redact_secret::{
    BuiltInRegistry, DefaultPolicy, DetectorRegistry, PiiSelection, Profile, ScanResult,
    SecretScanError, SecretScanErrorCode, WholeInputLimits, default_placeholder_formatter,
    scan_and_redact, scan_and_redact_with_limits, scan_with_limits,
};

const FIXTURE: &str = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";

/// Compile-time: the handle is shareable. The same check is a `const` in
/// `src/registry.rs`; repeating it here pins it from a dependent crate's view.
const fn assert_send_sync<T: Send + Sync>() {}
const _: () = assert_send_sync::<BuiltInRegistry>();
const _: () = assert_send_sync::<Arc<BuiltInRegistry>>();

/// A corpus covering several detector kinds, PII and a clean line, kept small
/// enough to repeat per thread.
fn inputs() -> Vec<String> {
    let mut inputs: Vec<String> = support::synchronous_corpus()
        .into_iter()
        .filter(|fixture| fixture.support != "not-yet-evaluated" && fixture.resource.is_none())
        .map(|fixture| fixture.input)
        .collect();
    inputs.extend(
        [
            "",
            "nothing sensitive in this line",
            FIXTURE,
            "email: owner.synthetic@mail-synthetic.org and a note",
            "zero\u{200b}width ghp_SYNTHETICREVOKED00000000000000000000 inside",
        ]
        .map(str::to_owned),
    );
    inputs
}

fn pii() -> PiiSelection {
    PiiSelection::parse(&["pii:global"]).unwrap()
}

fn run_owned(registry: &DetectorRegistry, input: &str) -> Result<ScanResult, SecretScanError> {
    scan_and_redact(
        input,
        registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
}

fn run_shared(registry: &BuiltInRegistry, input: &str) -> Result<ScanResult, SecretScanError> {
    registry.scan_and_redact(input, &DefaultPolicy, &default_placeholder_formatter)
}

/// All four constructors paired with the `DetectorRegistry` they replace.
fn pairs() -> Vec<(&'static str, BuiltInRegistry, DetectorRegistry)> {
    let selection = pii();
    vec![
        (
            "full",
            BuiltInRegistry::with_built_in().unwrap(),
            DetectorRegistry::with_built_in([]).unwrap(),
        ),
        (
            "common",
            BuiltInRegistry::with_common_built_in().unwrap(),
            DetectorRegistry::with_common_built_in([]).unwrap(),
        ),
        (
            "full+pii",
            BuiltInRegistry::with_built_in_and_pii(&selection).unwrap(),
            DetectorRegistry::with_built_in_and_pii(&selection).unwrap(),
        ),
        (
            "common+pii",
            BuiltInRegistry::with_common_built_in_and_pii(&selection).unwrap(),
            DetectorRegistry::with_common_built_in_and_pii(&selection).unwrap(),
        ),
    ]
}

#[test]
fn metadata_matches_the_registry_it_replaces() {
    for (name, shared, owned) in pairs() {
        assert_eq!(Some(shared.profile()), owned.profile(), "{name}");
        assert_eq!(
            shared.activation_identity(),
            owned.activation_identity(),
            "{name}"
        );
        assert_eq!(shared.len(), owned.len(), "{name}");
        assert!(!shared.is_empty(), "{name}");
        assert_eq!(
            shared.ids().collect::<Vec<_>>(),
            owned.ids().collect::<Vec<_>>(),
            "{name}: ids and registration order"
        );
        assert_eq!(
            shared.contains("github-token"),
            owned.contains("github-token")
        );
    }
    let full = BuiltInRegistry::with_built_in().unwrap();
    let common = BuiltInRegistry::with_common_built_in().unwrap();
    assert_eq!(full.profile(), Profile::Full);
    assert_eq!(common.profile(), Profile::Common);
    assert!(full.contains("github-token"));
    assert!(!common.contains("github-token"));
    assert!(!full.contains("pii-domain"));
    assert!(
        BuiltInRegistry::with_built_in_and_pii(&pii())
            .unwrap()
            .contains("pii-domain")
    );
    assert!(format!("{full:?}").contains("BuiltInRegistry"));
}

#[test]
fn results_equal_the_owned_registry_for_every_profile_and_pii_selection() {
    let inputs = inputs();
    assert!(inputs.len() > 20, "the corpus must not be empty");
    for (name, shared, owned) in pairs() {
        for input in &inputs {
            assert_eq!(
                run_shared(&shared, input),
                run_owned(&owned, input),
                "{name}: scanAndRedact differs"
            );
            assert_eq!(
                shared.scan(input, &DefaultPolicy),
                scan_with_limits(input, &owned, &DefaultPolicy, &WholeInputLimits::default()),
                "{name}: scan differs"
            );
        }
    }
}

#[test]
fn pii_activation_changes_results_exactly_as_it_does_for_the_owned_registry() {
    let input = "email: owner.synthetic@mail-synthetic.org";
    let off = BuiltInRegistry::with_built_in().unwrap();
    let on = BuiltInRegistry::with_built_in_and_pii(&pii()).unwrap();
    let off_result = run_shared(&off, input).unwrap();
    let on_result = run_shared(&on, input).unwrap();
    assert!(off_result.findings().is_empty());
    assert!(!on_result.findings().is_empty());
    assert_eq!(
        on_result,
        run_owned(
            &DetectorRegistry::with_built_in_and_pii(&pii()).unwrap(),
            input
        )
        .unwrap()
    );
}

#[test]
fn limits_and_error_codes_match_the_owned_registry() {
    let shared = BuiltInRegistry::with_built_in().unwrap();
    let owned = DetectorRegistry::with_built_in([]).unwrap();
    let tiny_input = WholeInputLimits::new(8, 10).unwrap();
    let no_findings = WholeInputLimits::new(1024, 1).unwrap();
    let two = format!("{FIXTURE}\n{FIXTURE}");

    for (input, limits, code) in [
        (
            FIXTURE,
            &tiny_input,
            SecretScanErrorCode::InputLimitExceeded,
        ),
        (
            two.as_str(),
            &no_findings,
            SecretScanErrorCode::FindingLimitExceeded,
        ),
    ] {
        let from_shared = shared.scan_and_redact_with_limits(
            input,
            &DefaultPolicy,
            &default_placeholder_formatter,
            limits,
        );
        let from_owned = scan_and_redact_with_limits(
            input,
            &owned,
            &DefaultPolicy,
            &default_placeholder_formatter,
            limits,
        );
        assert_eq!(from_shared, from_owned);
        assert_eq!(from_shared.unwrap_err().code(), code);
        assert_eq!(
            shared
                .scan_with_limits(input, &DefaultPolicy, limits)
                .unwrap_err()
                .code(),
            code
        );
    }
}

#[test]
fn one_handle_shared_by_reference_and_by_arc_matches_a_registry_per_thread() {
    let inputs = Arc::new(inputs());
    let shared = Arc::new(BuiltInRegistry::with_built_in_and_pii(&pii()).unwrap());

    // The baseline: one registry per thread, built the way the gateway does
    // today, which is what the handle replaces.
    let expected: Vec<_> = inputs
        .iter()
        .map(|input| {
            run_owned(
                &DetectorRegistry::with_built_in_and_pii(&pii()).unwrap(),
                input,
            )
        })
        .collect();

    // Shared through an Arc.
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let shared = Arc::clone(&shared);
            let inputs = Arc::clone(&inputs);
            thread::spawn(move || {
                inputs
                    .iter()
                    .map(|input| run_shared(&shared, input))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    for worker in workers {
        assert_eq!(worker.join().unwrap(), expected);
    }

    // Shared by plain reference with scoped threads, and with each thread
    // building its own owned registry at the same time, so the shared
    // prefilter is read concurrently with its first compile elsewhere.
    thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let (shared, inputs) = (&*shared, &*inputs);
                scope.spawn(move || {
                    let own = DetectorRegistry::with_built_in_and_pii(&pii()).unwrap();
                    inputs
                        .iter()
                        .map(|input| {
                            let from_shared = run_shared(shared, input);
                            assert_eq!(from_shared, run_owned(&own, input), "thread {index}");
                            from_shared
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), expected);
        }
    });
}

#[test]
fn a_shared_handle_is_unchanged_by_scans() {
    let shared = BuiltInRegistry::with_built_in().unwrap();
    let (ids, identity, len) = (
        shared.ids().map(str::to_owned).collect::<Vec<_>>(),
        shared.activation_identity().to_owned(),
        shared.len(),
    );
    let first = run_shared(&shared, FIXTURE).unwrap();
    for _ in 0..3 {
        assert_eq!(run_shared(&shared, FIXTURE).unwrap(), first);
    }
    assert_eq!(shared.ids().collect::<Vec<_>>(), ids);
    assert_eq!(shared.activation_identity(), identity);
    assert_eq!(shared.len(), len);
}
