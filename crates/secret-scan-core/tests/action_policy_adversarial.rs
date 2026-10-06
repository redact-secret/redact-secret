//! Property and adversarial tests for the action policy parser and evaluator
//! (issue #1219).
//!
//! Deterministic: a fixed-seed generator, no clock-dependent assertion on a
//! tight bound, no network, no real credential. The properties:
//!
//! - the parser never panics and is a pure function of the bytes, for random
//!   bytes, random mutations of valid documents, every strict prefix of a valid
//!   document, and every byte value in every string position;
//! - a rejection carries a fixed class and a rule index and never a document
//!   byte;
//! - work stays bounded for documents at the size limit that are deeply nested,
//!   duplicate-heavy or set-heavy, because the parser is one pass with no
//!   recursion and a value in the wrong slot is never read;
//! - the evaluator agrees with a naive reference evaluator on random valid
//!   documents, and insignificant whitespace never changes what loads or what a
//!   document decides.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use redact_secret::{
    Action, ActionPolicyErrorClass, ByteRange, Confidence, DefaultPolicy, DetectedFinding,
    MAX_ACTION_POLICY_BYTES, Obfuscation, Policy, PolicyContext, load_action_policy,
};

/// A fixed-seed xorshift64 stream: the same cases on every target.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const VALID: &str = r#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"redact-acme","match":{"type":["acme-alnum-token"]},"action":"redact"},{"id":"block-obfuscated","match":{"type":["github_token"],"obfuscation":["invisible-characters"],"confidence":["high","medium"],"detector":["github-token"]},"action":"block"},{"id":"keep","match":{"type":["jwt"]},"action":"default"}]}"#;

/// Generous enough that no loaded CI machine reaches it, tight enough that a
/// quadratic or exponential parser on these inputs would.
const WORK_CAP: Duration = Duration::from_secs(20);

fn class(bytes: &[u8]) -> Option<(ActionPolicyErrorClass, Option<usize>)> {
    load_action_policy(bytes)
        .err()
        .map(|error| (error.class(), error.rule_index()))
}

// ---------------------------------------------------------------------------
// the parser never panics and is a pure function of the bytes
// ---------------------------------------------------------------------------

#[test]
fn random_bytes_never_panic_and_are_deterministic() {
    let mut rng = Rng::new(0x1219_0001);
    for _ in 0..4_000 {
        let length = rng.below(160);
        let bytes: Vec<u8> = (0..length)
            .map(|_| u8::try_from(rng.below(256)).unwrap())
            .collect();
        assert_eq!(class(&bytes), class(&bytes));
    }
    // Biased toward the structural alphabet, where the parser branches most.
    let alphabet = br#"{}[]":,0123456789 truefalsn\ae"#;
    for _ in 0..4_000 {
        let length = rng.below(120);
        let bytes: Vec<u8> = (0..length).map(|_| *rng.pick(alphabet)).collect();
        assert_eq!(class(&bytes), class(&bytes));
    }
}

#[test]
fn every_strict_prefix_of_a_valid_document_is_rejected() {
    assert!(load_action_policy(VALID.as_bytes()).is_ok());
    for end in 0..VALID.len() {
        assert!(
            class(&VALID.as_bytes()[..end]).is_some(),
            "a strict prefix of {end} bytes was accepted"
        );
    }
}

#[test]
fn anything_after_the_document_other_than_whitespace_is_rejected() {
    for suffix in [
        &b"x"[..],
        b"{}",
        b",",
        b"\"",
        b"0",
        b"\xef\xbb\xbf",
        b"\0",
        b"\x0b",
    ] {
        let mut bytes = VALID.as_bytes().to_vec();
        bytes.extend_from_slice(suffix);
        assert_eq!(
            class(&bytes),
            Some((ActionPolicyErrorClass::MalformedDocument, None)),
            "{suffix:?}"
        );
    }
    let mut padded = VALID.as_bytes().to_vec();
    padded.extend_from_slice(b" \t\r\n \n");
    assert!(load_action_policy(&padded).is_ok());
}

#[test]
fn random_mutations_of_a_valid_document_never_panic() {
    let mut rng = Rng::new(0x1219_0002);
    for _ in 0..6_000 {
        let mut bytes = VALID.as_bytes().to_vec();
        for _ in 0..=rng.below(4) {
            let at = rng.below(bytes.len().max(1));
            match rng.below(5) {
                0 if !bytes.is_empty() => bytes[at] = u8::try_from(rng.below(256)).unwrap(),
                1 if !bytes.is_empty() => {
                    bytes.remove(at);
                }
                2 => bytes.insert(at.min(bytes.len()), u8::try_from(rng.below(256)).unwrap()),
                3 => bytes.truncate(at),
                _ => {
                    let slice = bytes[..at.min(bytes.len())].to_vec();
                    bytes.extend_from_slice(&slice[slice.len().saturating_sub(8)..]);
                }
            }
        }
        // Total and deterministic: an `Ok` or a fixed class, never a panic.
        assert_eq!(class(&bytes), class(&bytes));
    }
}

#[test]
fn every_byte_value_in_a_string_position_is_judged_by_the_string_rule() {
    for byte in 0..=u8::MAX {
        let mut document =
            br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["a"#
                .to_vec();
        document.push(byte);
        document.extend_from_slice(br#"c"]},"action":"warn"}]}"#);
        let printable = (0x20..=0x7e).contains(&byte) && byte != b'\\' && byte != b'"';
        match class(&document) {
            None => assert!(
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-'),
                "byte {byte:#04x} produced a valid document"
            ),
            Some((found, index)) if printable => {
                assert_eq!(
                    found,
                    ActionPolicyErrorClass::InvalidIdentifier,
                    "{byte:#04x}"
                );
                assert_eq!(index, Some(0));
            }
            Some((found, index)) => {
                // A control byte, a DEL, a backslash, a non-ASCII byte, or a
                // quote that ends the string early: all syntax errors, never
                // attributed to a rule.
                assert_eq!(
                    found,
                    ActionPolicyErrorClass::MalformedDocument,
                    "{byte:#04x}"
                );
                assert_eq!(index, None);
            }
        }
    }
}

#[test]
fn non_ascii_and_escapes_are_syntax_errors_in_every_string_position() {
    let positions = [
        r#"{"actionPolicyRevision":1,"base":"%","rules":[]}"#,
        r#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"%","match":{"type":["jwt"]},"action":"warn"}]}"#,
        r#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"%":["jwt"]},"action":"warn"}]}"#,
        r#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["%"]},"action":"warn"}]}"#,
        r#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"confidence":["%"]},"action":"warn"}]}"#,
        r#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"r","match":{"type":["jwt"]},"action":"%"}]}"#,
        r#"{"actionPolicyRevision":1,"%":1,"base":"default","rules":[]}"#,
    ];
    for template in positions {
        for hostile in [
            "\\u0041",
            "\\n",
            "\\\"",
            "\\\\",
            "\u{e9}",
            "\u{3b1}",
            "\u{1f600}",
            "\u{200b}",
            "\u{feff}",
            "\u{202e}",
            "\0",
            "\u{7f}",
            "\u{85}",
            "\u{2028}",
        ] {
            let document = template.replace('%', hostile);
            let (found, index) = class(document.as_bytes())
                .unwrap_or_else(|| panic!("{hostile:?} was accepted in {template}"));
            assert_eq!(
                found,
                ActionPolicyErrorClass::MalformedDocument,
                "{hostile:?} in {template}"
            );
            assert_eq!(index, None);
        }
    }
}

#[test]
fn a_rejection_never_carries_a_document_byte() {
    let marker = "SYNTHETICMARKERNOTAREALVALUE";
    let templates = [
        format!(r#"{{"actionPolicyRevision":1,"base":"{marker}","rules":[]}}"#),
        format!(
            r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"{marker}","match":{{"type":["jwt"]}},"action":"warn"}}]}}"#
        ),
        format!(
            r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"{marker}":["jwt"]}},"action":"warn"}}]}}"#
        ),
        format!(
            r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"type":["{marker}"]}},"action":"{marker}"}}]}}"#
        ),
        format!(
            r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"confidence":["{marker}"]}},"action":"warn"}}]}}"#
        ),
        format!(r#"{{"{marker}":1}}"#),
        format!(r#"{{"actionPolicyRevision":1,"{marker}":1}}"#),
        marker.to_string(),
    ];
    for document in templates {
        let error = load_action_policy(document.as_bytes()).unwrap_err();
        for rendered in [
            error.to_string(),
            format!("{error:?}"),
            error.message().to_owned(),
            error.class().to_string(),
        ] {
            assert!(!rendered.contains("SYNTHETIC"), "{rendered}");
            assert!(!rendered.contains("MARKER"), "{rendered}");
        }
    }
}

// ---------------------------------------------------------------------------
// bounded work
// ---------------------------------------------------------------------------

fn within_cap(label: &str, work: impl FnOnce()) {
    let started = Instant::now();
    work();
    let elapsed = started.elapsed();
    assert!(elapsed < WORK_CAP, "{label} took {elapsed:?}");
}

#[test]
fn documents_at_the_size_limit_are_bounded_work() {
    let limit = MAX_ACTION_POLICY_BYTES;
    let prefix = r#"{"actionPolicyRevision":1,"base":"default","rules":"#;
    let mut hostile: Vec<(&str, Vec<u8>, ActionPolicyErrorClass)> = Vec::new();

    // Deep nesting in a slot that wants a string, an array of rules, an object.
    for (label, open) in [("nested arrays", b'['), ("nested objects", b'{')] {
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.resize(limit, open);
        hostile.push((label, bytes, ActionPolicyErrorClass::WrongType));
    }
    // A single enormous string.
    let mut bytes = format!(r#"{prefix}[{{"id":""#).into_bytes();
    bytes.resize(limit, b'a');
    hostile.push((
        "unterminated string",
        bytes,
        ActionPolicyErrorClass::MalformedDocument,
    ));
    // Whitespace-padded and truncated.
    let mut bytes = prefix.as_bytes().to_vec();
    bytes.resize(limit, b' ');
    hostile.push(("padding", bytes, ActionPolicyErrorClass::MalformedDocument));
    // Duplicate-heavy: the same key again and again.
    let mut bytes = br#"{"actionPolicyRevision":1,"#.to_vec();
    while bytes.len() + 40 < limit {
        bytes.extend_from_slice(br#""base":"default","#);
    }
    bytes.extend_from_slice(br#""rules":[]}"#);
    hostile.push((
        "repeated key",
        bytes,
        ActionPolicyErrorClass::DuplicateField,
    ));
    // Rules after the 128th are never read.
    let mut bytes = format!("{prefix}[").into_bytes();
    let mut index = 0;
    while bytes.len() + 64 < limit {
        bytes.extend_from_slice(
            format!(r#"{{"id":"r{index}","match":{{"type":["jwt"]}},"action":"warn"}},"#)
                .as_bytes(),
        );
        index += 1;
    }
    hostile.push(("rule flood", bytes, ActionPolicyErrorClass::TooManyRules));

    for (label, bytes, expected) in hostile {
        assert!(bytes.len() <= limit, "{label}");
        within_cap(label, || {
            let (found, _) = class(&bytes).unwrap_or_else(|| panic!("{label} was accepted"));
            assert_eq!(found, expected, "{label}");
        });
    }
}

#[test]
fn the_worst_accepted_documents_load_and_evaluate_within_the_cap() {
    // As many 256-member sets as the byte bound allows, in rules with distinct
    // ids: the largest legitimate cost the parser and the evaluator see.
    let members: Vec<String> = (0..256)
        .map(|index| format!(r#""type-{index:03}""#))
        .collect();
    let set = members.join(",");
    let mut rules = Vec::new();
    let mut length = 80;
    while rules.len() < 128 {
        let rule = format!(
            r#"{{"id":"r{}","match":{{"type":[{set}],"detector":[{set}]}},"action":"warn"}}"#,
            rules.len()
        );
        if length + rule.len() + 1 > MAX_ACTION_POLICY_BYTES {
            break;
        }
        length += rule.len() + 1;
        rules.push(rule);
    }
    assert!(
        rules.len() >= 2,
        "the worst case must hold several full rules"
    );
    let document = format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
        rules.join(",")
    );
    assert!(document.len() <= MAX_ACTION_POLICY_BYTES);

    within_cap("worst accepted document", || {
        let policy = load_action_policy(document.as_bytes()).unwrap();
        let finding = DetectedFinding::new(
            "finding-1",
            "no-such-type",
            "no-such-detector",
            Confidence::Low,
            ByteRange::new(0, 1).unwrap(),
        )
        .unwrap();
        // No rule matches, so every member of every set is compared.
        for _ in 0..200 {
            let action = Policy::evaluate(&policy, &finding, &PolicyContext::new(0, 1)).unwrap();
            assert_eq!(action, Action::Warn);
        }
    });
}

#[test]
fn a_duplicate_heavy_set_is_rejected_in_bounded_time() {
    // 256 members that are all the same: the duplicate is found on the second.
    let repeated = vec![r#""jwt""#; 256].join(",");
    let document = format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"type":[{repeated}]}},"action":"warn"}}]}}"#
    );
    assert_eq!(
        class(document.as_bytes()),
        Some((ActionPolicyErrorClass::DuplicateSetMember, Some(0)))
    );
    // 256 distinct members and then one repeat of the first: the worst case of
    // the linear duplicate scan, still within the set bound.
    let mut members: Vec<String> = (0..256).map(|index| format!(r#""t{index}""#)).collect();
    members[255] = members[0].clone();
    let document = format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"type":[{}]}},"action":"warn"}}]}}"#,
        members.join(",")
    );
    within_cap("worst duplicate scan", || {
        assert_eq!(
            class(document.as_bytes()),
            Some((ActionPolicyErrorClass::DuplicateSetMember, Some(0)))
        );
    });
}

// ---------------------------------------------------------------------------
// the evaluator agrees with a naive reference
// ---------------------------------------------------------------------------

const TYPES: [&str; 5] = [
    "jwt",
    "github_token",
    "private_key",
    "contextual_secret",
    "acme-x",
];
const DETECTORS: [&str; 3] = ["jwt", "generic-token", "acme-detector"];
const CONFIDENCES: [Confidence; 3] = [Confidence::High, Confidence::Medium, Confidence::Low];
const OBFUSCATIONS: [Obfuscation; 2] = [Obfuscation::None, Obfuscation::InvisibleCharacters];
const ACTIONS: [&str; 5] = ["redact", "block", "warn", "allow", "default"];

struct GeneratedRule {
    types: Vec<&'static str>,
    detectors: Vec<&'static str>,
    confidences: Vec<Confidence>,
    obfuscations: Vec<Obfuscation>,
    action: &'static str,
}

fn subset<T: Copy>(rng: &mut Rng, pool: &[T]) -> Vec<T> {
    let mut chosen: Vec<T> = Vec::new();
    for _ in 0..=rng.below(pool.len()) {
        chosen.push(*rng.pick(pool));
    }
    chosen
}

fn dedup_by_name<T: Copy>(items: Vec<T>, name: impl Fn(T) -> String) -> Vec<T> {
    let mut seen = Vec::new();
    items
        .into_iter()
        .filter(|item| {
            let key = name(*item);
            let fresh = !seen.contains(&key);
            seen.push(key);
            fresh
        })
        .collect()
}

fn generate_rule(rng: &mut Rng) -> GeneratedRule {
    let mut rule = GeneratedRule {
        types: Vec::new(),
        detectors: Vec::new(),
        confidences: Vec::new(),
        obfuscations: Vec::new(),
        action: ACTIONS[rng.below(ACTIONS.len())],
    };
    // At least one key, so the rule is loadable.
    let keys = 1 + rng.below(15);
    if keys & 1 != 0 {
        rule.types = dedup_by_name(subset(rng, &TYPES), str::to_owned);
    }
    if keys & 2 != 0 {
        rule.detectors = dedup_by_name(subset(rng, &DETECTORS), str::to_owned);
    }
    if keys & 4 != 0 {
        rule.confidences = dedup_by_name(subset(rng, &CONFIDENCES), |c| c.as_str().to_owned());
    }
    if keys & 8 != 0 {
        rule.obfuscations = dedup_by_name(subset(rng, &OBFUSCATIONS), |o| o.as_str().to_owned());
    }
    rule
}

fn quote_all<T: Copy>(items: &[T], name: impl Fn(T) -> String) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|item| format!("\"{}\"", name(*item)))
        .collect();
    format!("[{}]", quoted.join(","))
}

fn render(rules: &[GeneratedRule]) -> String {
    let rendered: Vec<String> = rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let mut keys = Vec::new();
            if !rule.types.is_empty() {
                keys.push(format!(
                    r#""type":{}"#,
                    quote_all(&rule.types, str::to_owned)
                ));
            }
            if !rule.detectors.is_empty() {
                keys.push(format!(
                    r#""detector":{}"#,
                    quote_all(&rule.detectors, str::to_owned)
                ));
            }
            if !rule.confidences.is_empty() {
                keys.push(format!(
                    r#""confidence":{}"#,
                    quote_all(&rule.confidences, |c| c.as_str().to_owned())
                ));
            }
            if !rule.obfuscations.is_empty() {
                keys.push(format!(
                    r#""obfuscation":{}"#,
                    quote_all(&rule.obfuscations, |o| o.as_str().to_owned())
                ));
            }
            format!(
                r#"{{"id":"rule-{index}","match":{{{}}},"action":"{}"}}"#,
                keys.join(","),
                rule.action
            )
        })
        .collect();
    format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
        rendered.join(",")
    )
}

fn reference(rules: &[GeneratedRule], finding: &DetectedFinding) -> Action {
    let base = Policy::evaluate(&DefaultPolicy, finding, &PolicyContext::new(0, 1)).unwrap();
    for rule in rules {
        let holds = (rule.types.is_empty() || rule.types.iter().any(|t| *t == finding.type_name()))
            && (rule.detectors.is_empty()
                || rule.detectors.iter().any(|d| *d == finding.detector()))
            && (rule.confidences.is_empty() || rule.confidences.contains(&finding.confidence()))
            && (rule.obfuscations.is_empty() || rule.obfuscations.contains(&finding.obfuscation()));
        if holds {
            return Action::from_name(rule.action).unwrap_or(base);
        }
    }
    base
}

/// Inserts insignificant whitespace after every structural byte outside a
/// string.
fn spread(document: &str, rng: &mut Rng) -> String {
    let mut out = String::new();
    let mut in_string = false;
    for character in document.chars() {
        out.push(character);
        if character == '"' {
            in_string = !in_string;
        } else if !in_string && matches!(character, '{' | '}' | '[' | ']' | ',' | ':') {
            for _ in 0..rng.below(3) {
                out.push(*rng.pick(&[' ', '\t', '\n', '\r']));
            }
        }
    }
    out
}

#[test]
fn the_evaluator_agrees_with_a_naive_reference_on_random_documents() {
    let mut rng = Rng::new(0x1219_0003);
    for round in 0..400 {
        let rules: Vec<GeneratedRule> =
            (0..rng.below(6)).map(|_| generate_rule(&mut rng)).collect();
        let document = render(&rules);
        let policy = load_action_policy(document.as_bytes())
            .unwrap_or_else(|error| panic!("round {round}: {error:?}: {document}"));
        let spread_policy = load_action_policy(spread(&document, &mut rng).as_bytes())
            .unwrap_or_else(|error| {
                panic!("round {round}: whitespace changed validity: {error:?}")
            });

        for type_name in TYPES {
            for detector in DETECTORS {
                for confidence in CONFIDENCES {
                    for obfuscation in OBFUSCATIONS {
                        let finding = DetectedFinding::new(
                            "finding-1",
                            type_name,
                            detector,
                            confidence,
                            ByteRange::new(0, 1).unwrap(),
                        )
                        .unwrap()
                        .with_obfuscation(obfuscation);
                        let want = reference(&rules, &finding);
                        for loaded in [&policy, &spread_policy] {
                            let got = Policy::evaluate(loaded, &finding, &PolicyContext::new(0, 1))
                                .unwrap();
                            assert_eq!(got, want, "round {round}: {document}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn a_loaded_policy_does_not_depend_on_the_context() {
    let policy = load_action_policy(VALID.as_bytes()).unwrap();
    let finding = DetectedFinding::new(
        "finding-1",
        "acme-alnum-token",
        "acme-alnum-token",
        Confidence::Medium,
        ByteRange::new(0, 1).unwrap(),
    )
    .unwrap();
    for (index, count) in [(0, 0), (0, 1), (7, 9), (usize::MAX - 1, usize::MAX)] {
        assert_eq!(
            Policy::evaluate(&policy, &finding, &PolicyContext::new(index, count)).unwrap(),
            Action::Redact
        );
    }
}
