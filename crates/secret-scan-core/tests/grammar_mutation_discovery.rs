//! Deterministic, bounded grammar-mutation discovery (issue #115).
//!
//! A handful of built-in provider detectors reduce to one documented shape:
//! a literal prefix, then a fixed or minimum-length run of an alphabet, then
//! a boundary check (see `detectors::pattern::scan_prefixed_runs`). This
//! module reimplements that shape independently as [`predict`] — a small,
//! dependency-free model of the *documented* grammar — and differentially
//! tests it against the real, black-box pipeline (`support::whole_input`,
//! which runs the full built-in registry, `DefaultPolicy` overlap
//! resolution, and redaction together) across deterministically generated
//! mutations of each grammar's prefix, length, alphabet, delimiter,
//! surrounding host context, Unicode boundary, and chunk partition.
//!
//! Every generated input is built from a fixed, cycling synthetic body
//! (`SYNTHETIC_BODY_POOL`, below) — never a real-looking secret — so every
//! case is unmistakably synthetic. Generation is seeded by the fixed
//! [`SEED_ID`] and is fully deterministic: the same seed always produces the
//! same bounded case set, each case carrying its own
//! `(grammar, seedId, operation, ordinal)` provenance, the same shape
//! `CanonicalMutationProvenance` declares in `conformance/schema.ts` for a
//! fixture promoted into the corpus's `regression` tier.
//!
//! Each case is already the minimal input its mutation needs — there is
//! nothing further to shrink — so a disagreement between [`predict`] and the
//! real pipeline is reported already minimized, with a ready-to-paste
//! regression-fixture snippet. A disagreement is either:
//!
//! - a **confirmed failure**: not declared in
//!   `EXPECTED_EXPLORATORY_DIFFERENCES`, so the test fails with the
//!   minimized input and its provenance, ready to promote into
//!   `conformance/fixtures/synchronous-corpus.json` at `tier: "regression"`; or
//! - an **expected exploratory difference**: a documented, intentional
//!   detector policy the plain prefix/run/boundary model has no way to
//!   express, which `EXPECTED_EXPLORATORY_DIFFERENCES` names explicitly.
//!   The suite also asserts every declared entry actually fires, so a stale
//!   allowance (the exclusion changing or disappearing) is itself caught.
//!   The list is empty today: `openai-token` used to be the one entry (its
//!   `sk-ant-` exclusion), but since issue #368 that detector requires a
//!   literal `T3BlbkFJ` marker between two exact-length segments, a
//!   compound shape this model does not describe at all, so it is no longer
//!   a grammar here. Its boundary mutations live as explicit fixtures in
//!   `conformance/fixtures/synchronous-corpus.json` instead.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::HashSet;
use std::time::Instant;

use redact_secret::Finding;
use support::{as_chunks, generous_limits, run_session, whole_input};

// ---------------------------------------------------------------------------
// seed and resource bounds
// ---------------------------------------------------------------------------

/// Stable seed identity recorded in every case's provenance.
const SEED_ID: &str = "gmd-v1";

/// Upper bound on how many mutations one (grammar, operation) pair may
/// contribute. Each pool below may describe more candidates than this; a
/// deterministic, seeded selection keeps the executed set bounded.
const MAX_CASES_PER_OPERATION: usize = 5;

/// Upper bound on any one generated input, so a mutation can never grow
/// unboundedly (e.g. a large length delta).
const MAX_INPUT_BYTES: usize = 512;

/// The runtime budget the whole discovery suite is held to. Generous next to
/// its actual cost (each case scans well under 512 bytes), the way
/// `adversarial_bounds.rs`'s `DEBUG_RUNTIME_ALLOWANCE` is generous next to a
/// debug build's slower detectors.
const RUNTIME_BUDGET_MS: u128 = if cfg!(debug_assertions) { 5_000 } else { 1_000 };

/// A fixed, cycling pool of unmistakably synthetic characters used to build
/// every mutated body. Contains no real-looking secret shape.
const SYNTHETIC_BODY_POOL: &[u8] = b"SYNTHETIC0REVOKED1MUTATION2DISCOVERY3BOUNDARY4FIXTURE5";

/// A byte-membership predicate for a token alphabet, mirroring
/// `detectors::pattern::Alphabet`. Reimplemented here (rather than imported)
/// because `tests/` only sees the crate's public API, and because an
/// independent reimplementation is the point of a differential model.
type Alphabet = fn(u8) -> bool;

fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_upper_alnum(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

fn is_alnum_dash(byte: u8) -> bool {
    is_alnum(byte) || byte == b'_' || byte == b'-'
}

/// `len` synthetic bytes, cycled from [`SYNTHETIC_BODY_POOL`] and filtered to
/// `alphabet` (every pool byte already satisfies every alphabet used below;
/// the filter is defensive, not load-bearing).
fn synthetic_body(alphabet: Alphabet, len: usize) -> String {
    let mut out = Vec::with_capacity(len);
    let mut index = 0;
    while out.len() < len {
        let byte = SYNTHETIC_BODY_POOL[index % SYNTHETIC_BODY_POOL.len()];
        if alphabet(byte) {
            out.push(byte);
        }
        index += 1;
    }
    String::from_utf8(out).unwrap()
}

// ---------------------------------------------------------------------------
// deterministic PRNG (splitmix64) and bounded sampling
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % bound as u64).unwrap()
    }
}

/// A stable seed for one (seed id, grammar, operation) group, so every group
/// gets its own reproducible, independent sampling order.
fn group_seed(grammar_id: &str, operation: &str) -> u64 {
    // FNV-1a.
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in format!("{SEED_ID}/{grammar_id}/{operation}").bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

/// A deterministic Fisher-Yates selection of up to [`MAX_CASES_PER_OPERATION`]
/// indices into `0..len`, in the order they will be executed (that order is
/// each case's `ordinal`).
fn bounded_selection(grammar_id: &str, operation: &str, len: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..len).collect();
    let mut rng = Rng::new(group_seed(grammar_id, operation));
    for i in (1..indices.len()).rev() {
        let j = rng.below(i + 1);
        indices.swap(i, j);
    }
    indices.truncate(MAX_CASES_PER_OPERATION);
    indices
}

// ---------------------------------------------------------------------------
// grammar model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Run {
    Exact(usize),
    AtLeast(usize),
}

impl Run {
    const fn min_len(self) -> usize {
        match self {
            Run::Exact(len) | Run::AtLeast(len) => len,
        }
    }
}

/// The documented shape of one built-in provider detector: a literal prefix
/// set, then a run of `alphabet` bytes of the declared length, then a
/// `boundary` check. Values below are the same literals each detector's own
/// unit tests already assert (see `additional_providers.rs`, `aws.rs`,
/// `openai.rs`), redeclared here because `tests/` cannot import the
/// `pub(super)` detector internals.
struct Grammar {
    id: &'static str,
    type_name: &'static str,
    prefixes: &'static [&'static str],
    run: Run,
    alphabet: Alphabet,
    boundary: Alphabet,
}

const AWS_ACCESS_KEY: Grammar = Grammar {
    id: "aws-access-key",
    type_name: "aws_access_key_id",
    prefixes: &["AKIA", "ASIA"],
    run: Run::Exact(16),
    alphabet: is_upper_alnum,
    boundary: is_alnum,
};

const HUGGING_FACE: Grammar = Grammar {
    id: "huggingface-token",
    type_name: "huggingface_token",
    prefixes: &["hf_"],
    run: Run::AtLeast(20),
    alphabet: is_alnum_dash,
    boundary: is_alnum_dash,
};

const STRIPE: Grammar = Grammar {
    id: "stripe-token",
    type_name: "stripe_credential",
    prefixes: &[
        "sk_test_", "sk_live_", "rk_test_", "rk_live_", "sk_org_", "whsec_",
    ],
    run: Run::AtLeast(20),
    alphabet: is_alnum,
    boundary: is_alnum_dash,
};

const VERCEL: Grammar = Grammar {
    id: "vercel-token",
    type_name: "vercel_token",
    prefixes: &["vcp_", "vci_", "vca_", "vcr_", "vck_"],
    run: Run::AtLeast(20),
    alphabet: is_alnum_dash,
    boundary: is_alnum_dash,
};

/// `openai-token` is deliberately absent: see the module docs.
const GRAMMARS: &[Grammar] = &[AWS_ACCESS_KEY, HUGGING_FACE, STRIPE, VERCEL];

/// The independent, dependency-free reimplementation of
/// `scan_prefixed_runs`: the documented grammar's own prediction of the
/// first `(start, end)` match in `input`, with no per-detector exclusion
/// policy applied. Disagreement between this and the real pipeline is what
/// the rest of this module hunts for.
fn predict(input: &str, grammar: &Grammar) -> Option<(usize, usize)> {
    let bytes = input.as_bytes();
    let mut ends = vec![0usize; bytes.len() + 1];
    ends[bytes.len()] = bytes.len();
    for index in (0..bytes.len()).rev() {
        ends[index] = if (grammar.alphabet)(bytes[index]) {
            ends[index + 1]
        } else {
            index
        };
    }

    let mut start = 0;
    while start < bytes.len() {
        let Some(prefix) = grammar
            .prefixes
            .iter()
            .filter(|prefix| bytes[start..].starts_with(prefix.as_bytes()))
            .max_by_key(|prefix| prefix.len())
        else {
            start += 1;
            continue;
        };

        let suffix_start = start + prefix.len();
        let available = ends[suffix_start] - suffix_start;
        let matched_len = match grammar.run {
            Run::Exact(len) if available >= len => len,
            Run::AtLeast(len) if available >= len => available,
            _ => {
                start += 1;
                continue;
            }
        };

        let end = suffix_start + matched_len;
        let before_ok = start == 0 || !(grammar.boundary)(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !(grammar.boundary)(bytes[end]);
        if before_ok && after_ok {
            return Some((start, end));
        }
        start = end;
    }
    None
}

fn valid_literal(grammar: &Grammar) -> String {
    format!(
        "{}{}",
        grammar.prefixes[0],
        synthetic_body(grammar.alphabet, grammar.run.min_len())
    )
}

// ---------------------------------------------------------------------------
// mutation operations
// ---------------------------------------------------------------------------

const OPERATIONS: &[&str] = &[
    "prefix",
    "length",
    "alphabet",
    "delimiter",
    "context",
    "unicode-boundary",
    "chunk-partition",
];

fn flip_case(byte: u8) -> Option<u8> {
    if byte.is_ascii_uppercase() {
        Some(byte.to_ascii_lowercase())
    } else if byte.is_ascii_lowercase() {
        Some(byte.to_ascii_uppercase())
    } else {
        None
    }
}

/// Corruptions of the literal prefix: broken case, a truncated prefix, an
/// inserted stray byte, and a reversed prefix. Every recipe is skipped if it
/// would accidentally reconstruct a still-valid prefix.
fn prefix_pool(grammar: &Grammar) -> Vec<(String, String)> {
    let mut pool = Vec::new();
    for &prefix in grammar.prefixes {
        let body = synthetic_body(grammar.alphabet, grammar.run.min_len());

        if let Some(first_alpha) = prefix.bytes().position(|byte| flip_case(byte).is_some()) {
            let mut corrupted = prefix.as_bytes().to_vec();
            corrupted[first_alpha] = flip_case(corrupted[first_alpha]).unwrap();
            let corrupted = String::from_utf8(corrupted).unwrap();
            if !grammar.prefixes.contains(&corrupted.as_str()) {
                pool.push((format!("case-flip:{prefix}"), format!("{corrupted}{body}")));
            }
        }

        if prefix.len() > 1 {
            let truncated = &prefix[..prefix.len() - 1];
            if !grammar.prefixes.contains(&truncated) {
                pool.push((format!("truncate:{prefix}"), format!("{truncated}{body}")));
            }
        }

        let inserted = format!("{}X{}", &prefix[..1], &prefix[1..]);
        if !grammar.prefixes.contains(&inserted.as_str()) {
            pool.push((format!("insert:{prefix}"), format!("{inserted}{body}")));
        }

        let reversed: String = prefix.chars().rev().collect();
        if !grammar.prefixes.contains(&reversed.as_str()) {
            pool.push((format!("reverse:{prefix}"), format!("{reversed}{body}")));
        }
    }

    pool
}

/// Shrinking below, and growing past, the declared run length.
fn length_pool(grammar: &Grammar) -> Vec<(String, String)> {
    let prefix = grammar.prefixes[0];
    [-2i64, -1, 1, 2, 3]
        .into_iter()
        .filter_map(|delta| {
            let base = i64::try_from(grammar.run.min_len()).unwrap();
            let len = usize::try_from(base + delta).ok()?;
            Some((
                format!("delta:{delta}"),
                format!("{prefix}{}", synthetic_body(grammar.alphabet, len)),
            ))
        })
        .collect()
}

/// A single out-of-alphabet byte substituted at the start of the run, which
/// always collapses the available run to zero at that position.
fn alphabet_pool(grammar: &Grammar) -> Vec<(String, String)> {
    let prefix = grammar.prefixes[0];
    let body = synthetic_body(grammar.alphabet, grammar.run.min_len());
    b"!@#~ "
        .iter()
        .copied()
        .map(|breaker| {
            let mut mutated = body.clone().into_bytes();
            mutated[0] = breaker;
            (
                format!("breaker:{}", breaker as char),
                format!("{prefix}{}", String::from_utf8(mutated).unwrap()),
            )
        })
        .collect()
}

/// A stray delimiter byte inserted between the prefix and the run.
fn delimiter_pool(grammar: &Grammar) -> Vec<(String, String)> {
    let prefix = grammar.prefixes[0];
    let body = synthetic_body(grammar.alphabet, grammar.run.min_len());
    b":/\n\t|"
        .iter()
        .copied()
        .map(|delimiter| {
            (
                format!("delimiter:{}", delimiter.escape_ascii()),
                format!("{prefix}{}{body}", delimiter as char),
            )
        })
        .collect()
}

/// The valid literal embedded in surrounding host-context-shaped text that
/// never touches the match itself.
fn context_pool(grammar: &Grammar) -> Vec<(String, String)> {
    let literal = valid_literal(grammar);
    vec![
        ("dotenv".to_owned(), format!("TOKEN_VALUE={literal}\n")),
        ("json".to_owned(), format!("{{\"token\":\"{literal}\"}}")),
        ("shell".to_owned(), format!("export TOKEN={literal}")),
        ("markdown".to_owned(), format!("`{literal}`")),
        (
            "log".to_owned(),
            format!("2024-01-01T00:00:00Z INFO token={literal}"),
        ),
        (
            "http".to_owned(),
            format!("Authorization: Bearer {literal}"),
        ),
    ]
}

/// A Unicode marker (an astral emoji, a combining accent, an RTL mark, a
/// zero-width joiner) placed immediately before or after the match, which
/// must never affect a byte-boundary check that only inspects ASCII.
fn unicode_boundary_pool(grammar: &Grammar) -> Vec<(String, String)> {
    let literal = valid_literal(grammar);
    let markers = ["\u{1F511}", "\u{0301}", "\u{200F}", "\u{200D}"];
    let mut pool = Vec::new();
    for marker in markers {
        pool.push((format!("before:{marker:?}"), format!("{marker}{literal}")));
        pool.push((format!("after:{marker:?}"), format!("{literal}{marker}")));
    }
    pool
}

fn fixed_size_chunks(input: &str, chunk_bytes: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let mut end = (cursor + chunk_bytes).min(input.len());
        while !input.is_char_boundary(end) {
            end += 1;
        }
        chunks.push(input[cursor..end].to_owned());
        cursor = end;
    }
    chunks
}

/// The candidate chunk partitions for the `chunk-partition` operation: the
/// same (unmutated) valid literal, wrapped in a little surrounding context,
/// delivered to a bounded incremental session at different granularities.
fn chunk_partition_pool(grammar: &Grammar) -> Vec<(String, Vec<String>)> {
    let wrapped = format!("TOKEN_VALUE={}\n", valid_literal(grammar));
    vec![
        (
            "single-char".to_owned(),
            wrapped.chars().map(String::from).collect(),
        ),
        ("fixed-size-3".to_owned(), fixed_size_chunks(&wrapped, 3)),
        ("fixed-size-7".to_owned(), fixed_size_chunks(&wrapped, 7)),
    ]
}

// ---------------------------------------------------------------------------
// case assembly
// ---------------------------------------------------------------------------

enum CaseKind {
    /// Compare [`predict`] against the real pipeline's finding for
    /// `grammar.type_name`.
    Grammar,
    /// Compare a chunked incremental session against the whole-input
    /// reference for the same (unmutated) input.
    ChunkPartition { chunks: Vec<String> },
}

struct Case {
    grammar: &'static Grammar,
    operation: &'static str,
    ordinal: usize,
    note: String,
    input: String,
    kind: CaseKind,
}

impl Case {
    fn id(&self) -> String {
        format!(
            "{SEED_ID}:{}:{}#{} ({})",
            self.grammar.id, self.operation, self.ordinal, self.note
        )
    }
}

/// Every case this seed generates, in deterministic order. Bounded by
/// [`MAX_CASES_PER_OPERATION`] per (grammar, operation) pair and by
/// [`MAX_INPUT_BYTES`] per input.
fn discover_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for grammar in GRAMMARS {
        for &operation in OPERATIONS {
            if operation == "chunk-partition" {
                let pool = chunk_partition_pool(grammar);
                let selection = bounded_selection(grammar.id, operation, pool.len());
                for (ordinal, index) in selection.into_iter().enumerate() {
                    let (note, chunks) = pool[index].clone();
                    let joined = chunks.concat();
                    assert!(
                        joined.len() <= MAX_INPUT_BYTES,
                        "{}/{operation}: {} bytes exceeds the {MAX_INPUT_BYTES}-byte resource bound",
                        grammar.id,
                        joined.len(),
                    );
                    cases.push(Case {
                        grammar,
                        operation,
                        ordinal,
                        note,
                        input: joined,
                        kind: CaseKind::ChunkPartition { chunks },
                    });
                }
                continue;
            }

            let pool: Vec<(String, String)> = match operation {
                "prefix" => prefix_pool(grammar),
                "length" => length_pool(grammar),
                "alphabet" => alphabet_pool(grammar),
                "delimiter" => delimiter_pool(grammar),
                "context" => context_pool(grammar),
                "unicode-boundary" => unicode_boundary_pool(grammar),
                other => unreachable!("unhandled operation {other}"),
            };

            let selection = bounded_selection(grammar.id, operation, pool.len());
            for (ordinal, index) in selection.into_iter().enumerate() {
                let (note, input) = pool[index].clone();
                assert!(
                    input.len() <= MAX_INPUT_BYTES,
                    "{}/{operation}: {} bytes exceeds the {MAX_INPUT_BYTES}-byte resource bound",
                    grammar.id,
                    input.len(),
                );
                cases.push(Case {
                    grammar,
                    operation,
                    ordinal,
                    note,
                    input,
                    kind: CaseKind::Grammar,
                });
            }
        }
    }
    cases
}

// ---------------------------------------------------------------------------
// expected exploratory differences
// ---------------------------------------------------------------------------

/// Documented, intentional mismatches between [`predict`]'s plain grammar
/// model and the real pipeline: not defects, so not promoted to the
/// regression tier. Keyed by `(grammar id, operation, note)`. The suite
/// asserts every entry here actually fires, so a stale allowance cannot
/// silently mask a real regression once the underlying exclusion changes.
const EXPECTED_EXPLORATORY_DIFFERENCES: &[(&str, &str, &str)] = &[];

fn single_matching_range(
    findings: &[Finding],
    grammar: &Grammar,
    case: &Case,
) -> Option<(usize, usize)> {
    let matches: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.type_name() == grammar.type_name)
        .collect();
    match matches.as_slice() {
        [] => None,
        [only] => Some((only.range().start(), only.range().end())),
        multiple => panic!(
            "{}: expected at most one {} finding, got {}",
            case.id(),
            grammar.type_name,
            multiple.len(),
        ),
    }
}

/// A ready-to-paste `synchronous-corpus.json` regression-tier fixture stub
/// for a confirmed failure, carrying its mutation provenance and nothing
/// resembling a real secret.
fn promotion_snippet(case: &Case) -> String {
    format!(
        "{{\n  \"id\": \"gmd-{}-{}-{}\",\n  \"detector\": \"{}\",\n  \"kind\": \"boundary\",\n  \"support\": \"supported\",\n  \"tier\": \"regression\",\n  \"contexts\": [\"plain-text\"],\n  \"mutation\": {{ \"grammar\": \"{}\", \"seedId\": \"{SEED_ID}\", \"operation\": \"{}\", \"ordinal\": {} }},\n  \"input\": {:?},\n  \"note\": \"promoted from grammar-mutation discovery: {}\"\n}}",
        case.grammar.id,
        case.operation,
        case.ordinal,
        case.grammar.id,
        case.grammar.id,
        case.operation,
        case.ordinal,
        case.input,
        case.note,
    )
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[test]
fn discovery_generates_a_bounded_deterministic_case_set() {
    let cases = discover_cases();
    assert!(!cases.is_empty(), "the discovery suite generated no cases");
    assert!(
        cases.len() <= GRAMMARS.len() * OPERATIONS.len() * MAX_CASES_PER_OPERATION,
        "{} cases exceeds the declared per-group bound",
        cases.len(),
    );
    for case in &cases {
        assert!(
            case.input.len() <= MAX_INPUT_BYTES,
            "{}: input exceeds the {MAX_INPUT_BYTES}-byte resource bound",
            case.id(),
        );
    }

    let first_run: Vec<(String, String)> = cases
        .iter()
        .map(|case| (case.id(), case.input.clone()))
        .collect();
    let second_run: Vec<(String, String)> = discover_cases()
        .iter()
        .map(|case| (case.id(), case.input.clone()))
        .collect();
    assert_eq!(
        first_run, second_run,
        "generation must be deterministic for a fixed seed",
    );
}

#[test]
fn every_generated_mutation_matches_its_oracle_or_is_an_expected_exploratory_difference() {
    let started = Instant::now();
    let mut exploratory_seen: HashSet<(String, String, String)> = HashSet::new();

    for case in discover_cases() {
        match &case.kind {
            CaseKind::Grammar => {
                let (_, findings) = whole_input(&case.input);
                let actual = single_matching_range(&findings, case.grammar, &case);
                let predicted = predict(&case.input, case.grammar);
                if actual == predicted {
                    continue;
                }

                let is_expected = EXPECTED_EXPLORATORY_DIFFERENCES.iter().any(
                    |&(grammar_id, operation, note)| {
                        grammar_id == case.grammar.id
                            && operation == case.operation
                            && note == case.note
                    },
                );
                assert!(
                    is_expected,
                    "{}: confirmed grammar-mutation regression — predicted {predicted:?}, got {actual:?}.\n\
                     Promote as a canonical regression fixture:\n{}",
                    case.id(),
                    promotion_snippet(&case),
                );
                exploratory_seen.insert((
                    case.grammar.id.to_owned(),
                    case.operation.to_owned(),
                    case.note.clone(),
                ));
            }
            CaseKind::ChunkPartition { chunks } => {
                let (expected_text, expected_findings) = whole_input(&case.input);
                let session = run_session(&as_chunks(chunks), generous_limits());
                assert_eq!(session.text(), expected_text, "{}: text", case.id());
                assert_eq!(
                    session.findings(),
                    expected_findings,
                    "{}: findings",
                    case.id()
                );
            }
        }
    }

    assert_eq!(
        exploratory_seen.len(),
        EXPECTED_EXPLORATORY_DIFFERENCES.len(),
        "a declared expected exploratory difference did not fire — remove the stale entry \
         from EXPECTED_EXPLORATORY_DIFFERENCES or investigate why it stopped occurring",
    );

    let elapsed = started.elapsed().as_millis();
    assert!(
        elapsed <= RUNTIME_BUDGET_MS,
        "the discovery suite took {elapsed}ms, above the {RUNTIME_BUDGET_MS}ms budget",
    );
}
