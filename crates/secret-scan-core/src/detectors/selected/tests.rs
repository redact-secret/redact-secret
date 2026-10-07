//! Pins every per-detector constructor to its registration row, its catalog
//! entry and its prefilter declaration (issue #1253).

use super::super::{
    BUILT_IN_PACKS, built_in_detectors, built_in_required_literals, declared_types,
};
use super::*;

#[test]
fn one_constructor_per_registration_row_in_canonical_order() {
    let rows: Vec<&str> = built_in_detectors().iter().map(|row| row.id).collect();
    let constructors: Vec<&str> = ALL.iter().map(|(id, _)| *id).collect();
    assert_eq!(constructors, rows);
    let packs: Vec<&str> = BUILT_IN_PACKS.iter().map(|(id, _)| *id).collect();
    assert_eq!(constructors, packs);
}

#[test]
fn snake_case_names_are_unique_identifiers() {
    // The accepted public naming is the id with `-` written `_`; it must stay
    // a unique Rust identifier for every id.
    let mut snake: Vec<String> = ALL.iter().map(|(id, _)| id.replace('-', "_")).collect();
    assert!(snake.iter().all(|name| {
        name.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
    }));
    snake.sort();
    snake.dedup();
    assert_eq!(snake.len(), ALL.len());
}

#[test]
fn every_constructor_matches_its_row_its_catalog_entry_and_its_prefilter() {
    for (row, (id, constructor)) in built_in_detectors().iter().zip(ALL) {
        let selected = constructor();
        assert_eq!(selected.id(), *id);
        assert_eq!(selected.detector.id(), *id, "{id}: the detector's own id");
        assert_eq!(Some(selected.types), declared_types(id), "{id}: types");
        let expected = built_in_required_literals(id).map(RequiredLiterals::literals);
        let actual = selected.required.map(RequiredLiterals::literals);
        assert_eq!(actual, expected, "{id}: prefilter declaration");
        assert_eq!(row.id, *id);
    }
}

#[test]
fn a_constructor_yields_the_candidates_its_registration_row_yields() {
    // Both name the one `static`/`const` grammar, so equal candidates over
    // inputs that exercise several grammars are the observable identity.
    let input = [
        "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000",
        "AKIASYNTHETICEXAMPLE",
        "postgres://user:SYNTHETIC_REVOKED_PASSWORD@example.test:5432/db",
        "Authorization: Bearer SYNTHETICREVOKEDTOKEN0000000000",
    ]
    .join("\n");
    let context = crate::types::DetectorContext::new(input.len());
    for (row, (id, constructor)) in built_in_detectors().iter().zip(ALL) {
        let selected = constructor();
        let from_row = row
            .detect(&input, &context)
            .map(|found| format!("{found:?}"));
        let from_constructor = selected
            .detector
            .detect(&input, &context)
            .map(|found| format!("{found:?}"));
        assert_eq!(from_constructor.ok(), from_row.ok(), "{id}");
    }
}
