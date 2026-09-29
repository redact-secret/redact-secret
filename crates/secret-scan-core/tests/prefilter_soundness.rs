//! The shared literal prefilter (issue #983) never skips a detector that
//! would have proposed a candidate.
//!
//! Debug builds run every detector the prefilter skips and assert that it
//! returns nothing (`pipeline::collect_candidates`), so every scan in a
//! debug test checks each declaration against its input. This test feeds
//! that check a mutation corpus built from the canonical synchronous corpus:
//! each positive fixture, cut down to a window around its findings, with
//! one byte near a finding changed (case swap, neighbouring byte) or
//! deleted. A mutation that breaks a declared literal while the detector
//! still matches, through a second prefix, a case-insensitive match or an
//! emission path the declaration missed, makes the skipped detector propose
//! a candidate and fails the scan's assertion.
//!
//! Release builds compile the check out, so this test only runs in debug.
//! Every fixture value is synthetic.

#![cfg(debug_assertions)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{DefaultPolicy, DetectorRegistry, scan};
use support::CanonicalFixture;

/// How many tests the corpus is split across, so the harness runs them in
/// parallel.
const SHARDS: usize = 8;

/// Bytes kept on each side of a fixture's findings, so line and keyword
/// context a gated detector needs survives the cut.
const CONTEXT: usize = 96;

/// Bytes before a finding's start and after its end that are mutated: a
/// declared literal sits at or near a candidate's start (a prefix, a marker
/// after a fixed-width head, a scheme before a password) or at its end (a
/// datacenter suffix).
const MUTATED_LEAD: usize = 40;
const MUTATED_TAIL: usize = 12;

/// A different ASCII byte of the same kind, so the input stays valid UTF-8
/// and close to the grammar.
fn perturb(byte: u8) -> u8 {
    match byte {
        b'a'..=b'z' | b'A'..=b'Z' => byte ^ 0x20,
        b'0'..=b'8' => byte + 1,
        b'9' => b'0',
        b'_' => b'-',
        b'-' | b'.' => b'_',
        b':' => b';',
        b'=' => b':',
        b'/' => b'\\',
        b' ' => b'\t',
        _ => b'#',
    }
}

fn floor_char_boundary(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn ceil_char_boundary(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// Bytes around a finding's start where a deletion is also tried: a
/// deletion shifts every later byte, which matters most for a prefix.
const DELETED_AROUND_START: usize = 8;

/// Every mutation of `fixture`: the window around its findings with one
/// ASCII byte near a finding perturbed, or, near a finding's start,
/// deleted.
fn mutations(fixture: &CanonicalFixture) -> Vec<String> {
    let input = fixture.input.as_str();
    let expected = fixture.declared_expectations();
    let first = expected.iter().map(|found| found.start).min().unwrap();
    let last = expected.iter().map(|found| found.end).max().unwrap();
    let window_start = floor_char_boundary(input, first.saturating_sub(CONTEXT));
    let window_end = ceil_char_boundary(input, (last + CONTEXT).min(input.len()));
    let window = &input[window_start..window_end];
    let mut positions: Vec<usize> = expected
        .iter()
        .flat_map(|found| {
            let start = found.start - window_start;
            let end = found.end - window_start;
            (start.saturating_sub(MUTATED_LEAD)..(start + MUTATED_LEAD).min(end))
                .chain(end.saturating_sub(MUTATED_TAIL)..(end + MUTATED_TAIL).min(window.len()))
        })
        .collect();
    positions.sort_unstable();
    positions.dedup();
    let starts: Vec<usize> = expected
        .iter()
        .map(|found| found.start - window_start)
        .collect();
    let bytes = window.as_bytes();
    let mut variants = Vec::new();
    for at in positions {
        if !bytes[at].is_ascii() {
            continue;
        }
        let mut changed = bytes.to_vec();
        changed[at] = perturb(bytes[at]);
        variants.push(String::from_utf8(changed).unwrap());
        if starts
            .iter()
            .any(|&start| at.abs_diff(start) < DELETED_AROUND_START)
        {
            let mut deleted = bytes.to_vec();
            deleted.remove(at);
            variants.push(String::from_utf8(deleted).unwrap());
        }
    }
    variants
}

/// Scans every mutation of every positive fixture in `shard` with the
/// `full` registry; a wrong skip panics inside the scan. Returns how many
/// mutated inputs were scanned.
fn scan_shard(shard: usize) -> usize {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let mut scanned = 0;
    for fixture in support::synchronous_corpus()
        .iter()
        .filter(|fixture| fixture.tier != "adversarial" && fixture.expected.is_some())
        .filter(|fixture| !fixture.declared_expectations().is_empty())
        .skip(shard)
        .step_by(SHARDS)
    {
        for variant in mutations(fixture) {
            // Only the assertion inside the scan matters here; a mutated
            // input may legitimately find something else, or fail a limit.
            let _ = scan(&variant, &registry, &DefaultPolicy);
            scanned += 1;
        }
    }
    scanned
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_0() {
    assert!(scan_shard(0) > 1_000);
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_1() {
    assert!(scan_shard(1) > 1_000);
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_2() {
    assert!(scan_shard(2) > 1_000);
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_3() {
    assert!(scan_shard(3) > 1_000);
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_4() {
    assert!(scan_shard(4) > 1_000);
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_5() {
    assert!(scan_shard(5) > 1_000);
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_6() {
    assert!(scan_shard(6) > 1_000);
}

#[test]
fn skipped_detectors_propose_nothing_over_mutations_shard_7() {
    assert!(scan_shard(7) > 1_000);
}
