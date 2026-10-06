//! Same-process, per-instance PII isolation (issue #1221).
//!
//! Three configuration owners live in one process: A (PII off), B
//! (`pii:global`) and C (the network-address family only, a different family
//! from B's set). The core owns no process-wide configuration, so each
//! `BuiltInRegistry` and each `IncrementalSanitizer` carries its own PII
//! selection and nothing leaks between them. Pins:
//!
//! - results per owner for both profiles, whatever the construction order;
//! - concurrent use of the three handles from separate threads;
//! - interleaved incremental sessions, one per owner;
//! - the same selection per owner when a custom ruleset is added through
//!   `DetectorRegistry` (the one registry type that accepts rulesets);
//! - teardown: dropping one owner changes nothing for the others, and a
//!   re-created owner behaves like the first one.
//!
//! The binding-level legacy behavior (a process or thread that is initialized
//! once, idempotent for an equivalent selection and a conflict for a differing
//! one) is not the core's; it is untouched here. Every value is synthetic, and
//! the credential-shaped one is assembled at run time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::thread;

use redact_secret::{
    BuiltInRegistry, DefaultPolicy, DetectorRegistry, Finding, IncrementalLimits,
    IncrementalSanitizer, PiiSelection, load_ruleset,
};

const EMAIL: &str = "email: owner.synthetic@mail-synthetic.org";
const IP: &str = "client_ip = 192.168.1.7";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    A,
    B,
    C,
}

const OWNERS: [Owner; 3] = [Owner::A, Owner::B, Owner::C];

/// `(email findings, network-address findings)` each owner must produce.
const fn expected(owner: Owner) -> (usize, usize) {
    match owner {
        Owner::A => (0, 0),
        Owner::B => (1, 1),
        Owner::C => (0, 1),
    }
}

fn selection(owner: Owner) -> PiiSelection {
    match owner {
        Owner::A => PiiSelection::parse(&[]).unwrap(),
        Owner::B => PiiSelection::parse(&["pii:global"]).unwrap(),
        Owner::C => PiiSelection::parse(&["pii:family:global:network-address"]).unwrap(),
    }
}

fn token_line() -> String {
    format!(
        "API_KEY={}{}{}",
        "ghp", "_SYNTHETICREVOKED", "00000000000000000000"
    )
}

fn build(owner: Owner, common: bool) -> BuiltInRegistry {
    let selection = selection(owner);
    match (owner, common) {
        (Owner::A, false) => BuiltInRegistry::with_built_in(),
        (Owner::A, true) => BuiltInRegistry::with_common_built_in(),
        (_, false) => BuiltInRegistry::with_built_in_and_pii(&selection),
        (_, true) => BuiltInRegistry::with_common_built_in_and_pii(&selection),
    }
    .unwrap()
}

fn count(registry: &BuiltInRegistry, text: &str) -> usize {
    registry.scan(text, &DefaultPolicy).unwrap().len()
}

fn observed(registry: &BuiltInRegistry) -> (usize, usize) {
    (count(registry, EMAIL), count(registry, IP))
}

const PERMUTATIONS: [[Owner; 3]; 6] = [
    [Owner::A, Owner::B, Owner::C],
    [Owner::A, Owner::C, Owner::B],
    [Owner::B, Owner::A, Owner::C],
    [Owner::B, Owner::C, Owner::A],
    [Owner::C, Owner::A, Owner::B],
    [Owner::C, Owner::B, Owner::A],
];

#[test]
fn each_owner_keeps_its_own_selection_in_every_construction_order() {
    for common in [false, true] {
        for order in PERMUTATIONS {
            // All three exist at once; each is queried only after all are built.
            let built: Vec<(Owner, BuiltInRegistry)> = order
                .iter()
                .map(|owner| (*owner, build(*owner, common)))
                .collect();
            for (owner, registry) in &built {
                assert_eq!(
                    observed(registry),
                    expected(*owner),
                    "owner {owner:?} common={common} order={order:?}"
                );
            }
        }
    }
}

#[test]
fn activation_identity_reports_each_owners_own_selection() {
    for common in [false, true] {
        let identities: Vec<String> = OWNERS
            .iter()
            .map(|owner| build(*owner, common).activation_identity().to_owned())
            .collect();
        let profile = if common { "common" } else { "full" };
        assert!(identities[0].starts_with(&format!("credentials={profile};selectors=off;")));
        assert!(identities[1].contains("selectors=pii:global;"));
        assert!(identities[2].contains("selectors=pii:family:global:network-address;"));
        assert_ne!(identities[0], identities[1]);
        assert_ne!(identities[1], identities[2]);
        assert_ne!(identities[0], identities[2]);
    }
}

#[test]
fn credential_detection_does_not_depend_on_the_pii_selection() {
    let line = token_line();
    for common in [false, true] {
        let baseline = build(Owner::A, common).scan(&line, &DefaultPolicy).unwrap();
        assert!(!baseline.is_empty());
        for owner in OWNERS {
            let findings = build(owner, common).scan(&line, &DefaultPolicy).unwrap();
            assert_eq!(findings, baseline, "owner {owner:?} common={common}");
        }
    }
}

#[test]
fn three_handles_scanned_concurrently_stay_isolated() {
    let handles: Vec<(Owner, Arc<BuiltInRegistry>)> = OWNERS
        .iter()
        .map(|owner| (*owner, Arc::new(build(*owner, false))))
        .collect();
    thread::scope(|scope| {
        for round in 0..4 {
            for (owner, handle) in &handles {
                scope.spawn(move || {
                    for _ in 0..25 {
                        assert_eq!(
                            observed(handle),
                            expected(*owner),
                            "owner {owner:?} round {round}"
                        );
                    }
                });
            }
        }
    });
}

fn limits() -> IncrementalLimits {
    IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap()
}

fn session(owner: Owner) -> IncrementalSanitizer {
    match owner {
        Owner::A => IncrementalSanitizer::new(limits()),
        _ => IncrementalSanitizer::with_built_in_and_pii(limits(), &selection(owner)),
    }
    .unwrap()
}

fn type_names(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| finding.type_name().to_owned())
        .collect()
}

#[test]
fn interleaved_incremental_sessions_keep_their_own_selection() {
    let mut sessions: Vec<(Owner, IncrementalSanitizer)> = OWNERS
        .iter()
        .map(|owner| (*owner, session(*owner)))
        .collect();
    // The email is split across a chunk boundary after its `@`.
    let split = EMAIL.find('@').unwrap() + 3;
    let chunks = [&EMAIL[..split], &EMAIL[split..], "\n", IP, "\n"];
    let mut seen: Vec<(Owner, Vec<String>)> = OWNERS.iter().map(|o| (*o, Vec::new())).collect();
    for chunk in chunks {
        for ((_, sanitizer), (_, names)) in sessions.iter_mut().zip(seen.iter_mut()) {
            names.extend(type_names(sanitizer.append(chunk).unwrap().findings()));
        }
    }
    for ((_, sanitizer), (_, names)) in sessions.iter_mut().zip(seen.iter_mut()) {
        names.extend(type_names(sanitizer.finalize().unwrap().findings()));
    }
    let by_owner = |owner: Owner| &seen.iter().find(|(o, _)| *o == owner).unwrap().1;
    assert!(by_owner(Owner::A).is_empty());
    assert_eq!(
        *by_owner(Owner::B),
        vec!["pii_global_email", "pii_global_network_address"]
    );
    assert_eq!(*by_owner(Owner::C), vec!["pii_global_network_address"]);
}

const RULESET_ONE: &[u8] = b"ruleset-revision: 1\n\
detector: acme-one\n\
specificity: contextual\n\
prefix: \"ACMEONE_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";

const RULESET_TWO: &[u8] = b"ruleset-revision: 1\n\
detector: acme-two\n\
specificity: contextual\n\
prefix: \"ACMETWO_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";

fn ruleset_registry(owner: Owner, ruleset: &[u8]) -> DetectorRegistry {
    let detectors = load_ruleset(ruleset).unwrap();
    DetectorRegistry::with_built_in_and_pii_custom(&selection(owner), detectors).unwrap()
}

fn ruleset_count(registry: &DetectorRegistry, text: &str) -> usize {
    redact_secret::scan(text, registry, &DefaultPolicy)
        .unwrap()
        .len()
}

#[test]
fn custom_rulesets_and_pii_selections_combine_independently_per_registry() {
    let one = format!("v = ACMEONE_{}", "abcdefghij".repeat(3));
    let two = format!("v = ACMETWO_{}", "abcdefghij".repeat(3));
    // Every owner x ruleset pair coexists; each reacts only to its own ruleset
    // and keeps its own PII selection while the ruleset is registered.
    let mut registries = Vec::new();
    for owner in OWNERS {
        registries.push((owner, 1, ruleset_registry(owner, RULESET_ONE)));
        registries.push((owner, 2, ruleset_registry(owner, RULESET_TWO)));
    }
    for (owner, which, registry) in &registries {
        let (own, other) = if *which == 1 {
            (&one, &two)
        } else {
            (&two, &one)
        };
        assert_eq!(ruleset_count(registry, own), 1, "{owner:?} ruleset {which}");
        assert_eq!(
            ruleset_count(registry, other),
            0,
            "{owner:?} ruleset {which}"
        );
        let (email, ip) = expected(*owner);
        assert_eq!(
            ruleset_count(registry, EMAIL),
            email,
            "{owner:?} ruleset {which}"
        );
        assert_eq!(ruleset_count(registry, IP), ip, "{owner:?} ruleset {which}");
    }
}

#[test]
fn dropping_an_owner_leaves_the_others_and_a_rebuilt_owner_matches_the_first() {
    let a = build(Owner::A, false);
    let b = build(Owner::B, false);
    let c = build(Owner::C, false);
    let first_b = observed(&b);
    drop(b);
    assert_eq!(observed(&a), expected(Owner::A));
    assert_eq!(observed(&c), expected(Owner::C));
    // A rebuilt owner inherits nothing from the dropped one or from `c`.
    let rebuilt = build(Owner::B, false);
    assert_eq!(observed(&rebuilt), first_b);
    drop(a);
    drop(c);
    assert_eq!(observed(&rebuilt), expected(Owner::B));
    // With every other owner gone, a fresh A is still PII off.
    assert_eq!(observed(&build(Owner::A, false)), expected(Owner::A));
}
