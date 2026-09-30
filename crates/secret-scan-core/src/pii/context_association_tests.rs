//! Differential tests for the indexed context association (issue #902).
//!
//! [`ContextVocabulary::matches`] replaced a per-candidate rescan of the
//! input and of every other candidate with one grouping by logical line. The
//! association it computes must not change, so the pre-#902 functions are
//! kept below, verbatim, as the oracle, and both run over the PII conformance
//! fixtures, the identity-evaluation path over those fixtures, and a
//! generated corpus of labels, candidate-like values, separators, line
//! breaks, invisible code points, combining marks and conjoining jamo.

use super::*;

#[path = "../../tests/fixture_texts/pii_conformance.rs"]
mod fixtures;

/// The association exactly as it was before issue #902 (`main` 8f97f14d,
/// `src/pii.rs`), copied verbatim and not to be edited: it is the oracle.
#[allow(
    clippy::all,
    clippy::pedantic,
    reason = "a verbatim copy of the pre-#902 source, kept unchanged as the oracle"
)]
mod oracle {
    use std::collections::BTreeSet;

    use unicode_normalization::UnicodeNormalization;

    use super::super::{
        ContextClass, ContextEntry, ContextKind, ContextMatch, IdentityDomain, pii_context_table,
    };
    use crate::types::ByteRange;

    pub(super) fn normalize_context(value: &str) -> String {
        let visible = value.chars().filter(|character| {
            let code_point = *character as u32;
            !crate::invisible_table::INVISIBLE_RANGES
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&code_point))
        });
        let mut tokenized = String::new();
        let mut in_separator = false;
        for character in visible
            .nfc()
            .map(|character| character.to_ascii_lowercase())
        {
            let separator = character.is_whitespace() || matches!(character, '_' | '-' | ':' | '=');
            if separator {
                if !in_separator {
                    tokenized.push(' ');
                    in_separator = true;
                }
            } else {
                tokenized.push(character);
                in_separator = false;
            }
        }
        tokenized
    }

    #[derive(Clone, Copy)]
    struct ContextOccurrence<'a> {
        entry: &'a ContextEntry,
        side: usize,
        start: usize,
        end: usize,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the bounded association rules are one ordered contract"
    )]
    pub(super) fn context_matches(
        input: &str,
        candidates: &[(ByteRange, IdentityDomain)],
    ) -> Vec<Vec<ContextMatch>> {
        let mut result = vec![Vec::new(); candidates.len()];
        for (candidate_index, (range, domain)) in candidates.iter().copied().enumerate() {
            let (line_start, line_end) = logical_line_bounds(input, range);
            let before_barrier = candidates
                .iter()
                .enumerate()
                .filter(|(index, (other, _))| {
                    *index != candidate_index
                        && other.end() <= range.start()
                        && other.end() >= line_start
                })
                .map(|(_, (other, _))| other.end())
                .max()
                .unwrap_or(line_start);
            let after_barrier = candidates
                .iter()
                .enumerate()
                .filter(|(index, (other, _))| {
                    *index != candidate_index
                        && other.start() >= range.end()
                        && other.start() <= line_end
                })
                .map(|(_, (other, _))| other.start())
                .min()
                .unwrap_or(line_end);
            let mut found = Vec::new();
            let before = normalize_context(&input[before_barrier..range.start()]);
            let after = normalize_context(&input[range.end()..after_barrier]);
            let before_offset = normalize_context(&input[line_start..before_barrier])
                .chars()
                .count();
            let after_offset = normalize_context(&input[line_start..range.end()])
                .chars()
                .count();
            for entry in pii_context_table::CONTEXT_ENTRIES
                .iter()
                .filter(|entry| entry.domains.contains(&domain))
            {
                for form in entry.forms {
                    for (side, view) in [(0usize, before.as_str()), (1usize, after.as_str())] {
                        if entry.kind == ContextKind::FieldLabel && side == 1 {
                            continue;
                        }
                        let normalized_form = normalize_context(form);
                        for (position, _) in view.match_indices(&normalized_form) {
                            let byte_end = position + normalized_form.len();
                            let boundary_ok = view[..position]
                                .chars()
                                .next_back()
                                .is_none_or(|character| is_context_boundary(entry, character))
                                && view[byte_end..]
                                    .chars()
                                    .next()
                                    .is_none_or(|character| is_context_boundary(entry, character));
                            if !boundary_ok {
                                continue;
                            }
                            let distance = if side == 0 {
                                view[byte_end..].chars().count()
                            } else {
                                view[..position].chars().count()
                            };
                            let limit = if entry.kind == ContextKind::FieldLabel {
                                16
                            } else {
                                64
                            };
                            if distance > limit {
                                continue;
                            }
                            if entry.kind == ContextKind::FieldLabel
                                && !view[byte_end..]
                                    .chars()
                                    .all(|character| is_field_gap(entry, character))
                            {
                                continue;
                            }
                            let local_start = view[..position].chars().count();
                            let scalar_span = normalized_form.chars().count();
                            let occurrence_start = if side == 0 {
                                before_offset
                            } else {
                                after_offset
                            } + local_start;
                            let occurrence_end = occurrence_start + scalar_span;
                            if equidistant_from_candidates(
                                input,
                                entry.kind,
                                line_start,
                                line_end,
                                occurrence_start,
                                occurrence_end,
                                candidates,
                            ) {
                                continue;
                            }
                            found.push(ContextOccurrence {
                                entry,
                                side,
                                start: occurrence_start,
                                end: occurrence_end,
                            });
                        }
                    }
                }
            }
            found.sort_by(|a, b| {
                (b.end - b.start)
                    .cmp(&(a.end - a.start))
                    .then_with(|| b.entry.strength.cmp(&a.entry.strength))
                    .then_with(|| b.entry.class.cmp(&a.entry.class))
                    .then_with(|| a.entry.id.as_bytes().cmp(b.entry.id.as_bytes()))
                    .then_with(|| a.start.cmp(&b.start))
            });
            let mut accepted_occurrences: Vec<ContextOccurrence<'_>> = Vec::new();
            let mut selected: Vec<ContextMatch> = Vec::new();
            for occurrence in found {
                if accepted_occurrences.iter().any(|accepted| {
                    accepted.side == occurrence.side
                        && accepted.start < occurrence.end
                        && occurrence.start < accepted.end
                }) {
                    continue;
                }
                accepted_occurrences.push(occurrence);
                if selected
                    .iter()
                    .all(|item| item.entry_id != occurrence.entry.id)
                {
                    selected.push(ContextMatch {
                        entry_id: occurrence.entry.id,
                        class: occurrence.entry.class,
                        strength: occurrence.entry.strength,
                    });
                }
            }
            result[candidate_index] = selected;
        }
        result
    }

    fn is_context_boundary(entry: &ContextEntry, character: char) -> bool {
        character.is_whitespace()
            || (entry.kind == ContextKind::FieldLabel && matches!(character, '"' | '\''))
            || is_positive_field_label_pipe(entry, character)
    }
    fn is_field_gap(entry: &ContextEntry, character: char) -> bool {
        character.is_whitespace()
            || matches!(character, '"' | '\'')
            || is_positive_field_label_pipe(entry, character)
    }

    /// A `|` field or cell delimiter bounds a positive field label and may sit
    /// in its gap, as whitespace does, so `a|b|email=V`, `x|phone: V`, and the
    /// `| ssn | V |` cells of a pipe table associate (`pii-context/v2`,
    /// `association.fieldLabel.pipeDelimiter: positive-field-labels`, issue #940).
    /// It is not a token separator, so two cells never join into one multi-word
    /// form. A negative or neutral entry and a natural-language label keep the
    /// whitespace-only boundary: a pipe adds association, never a suppression.
    fn is_positive_field_label_pipe(entry: &ContextEntry, character: char) -> bool {
        character == '|'
            && entry.kind == ContextKind::FieldLabel
            && entry.class == ContextClass::Positive
    }

    fn is_logical_line_break(character: char) -> bool {
        matches!(
            character,
            '\n' | '\r'
                | '\u{000B}'
                | '\u{000C}'
                | '\u{001C}'
                | '\u{001D}'
                | '\u{001E}'
                | '\u{0085}'
                | '\u{2028}'
                | '\u{2029}'
        )
    }

    fn logical_line_bounds(input: &str, range: ByteRange) -> (usize, usize) {
        let mut line_start = 0;
        for (index, character) in input[..range.start()].char_indices() {
            if is_logical_line_break(character) {
                line_start = index + character.len_utf8();
            }
        }
        let line_end = input[range.end()..]
            .char_indices()
            .find(|(_, character)| is_logical_line_break(*character))
            .map_or(input.len(), |(index, _)| range.end() + index);
        (line_start, line_end)
    }

    /// Whether a context occurrence is equally near two candidate occurrences
    /// it could associate with. A field label only associates with a candidate
    /// after it, so a candidate that ends before the label never makes it
    /// equidistant (`pii-context/v2`, issue #924); a natural-language label may
    /// associate either way and keeps the two-sided rule.
    fn equidistant_from_candidates(
        input: &str,
        kind: ContextKind,
        line_start: usize,
        line_end: usize,
        occurrence_start: usize,
        occurrence_end: usize,
        candidates: &[(ByteRange, IdentityDomain)],
    ) -> bool {
        // Equidistance separates two occurrences. Alternatives of different
        // identity domains at one exact range are one occurrence with two
        // interpretations, so each range counts once (issue #922).
        let ranges: BTreeSet<ByteRange> = candidates.iter().map(|(range, _)| *range).collect();
        let mut distances = Vec::new();
        for range in &ranges {
            if range.start() < line_start || range.end() > line_end {
                continue;
            }
            let candidate_start = normalize_context(&input[line_start..range.start()])
                .chars()
                .count();
            let candidate_end = candidate_start
                + normalize_context(&input[range.start()..range.end()])
                    .chars()
                    .count();
            if kind == ContextKind::FieldLabel && candidate_end <= occurrence_start {
                continue;
            }
            let distance = if candidate_end <= occurrence_start {
                occurrence_start - candidate_end
            } else {
                candidate_start.saturating_sub(occurrence_end)
            };
            distances.push(distance);
        }
        let Some(nearest) = distances.iter().min() else {
            return false;
        };
        distances
            .iter()
            .filter(|distance| *distance == nearest)
            .count()
            > 1
    }
}

/// `PiiDomain::contextualized` as it was before issue #902, over the oracle
/// association and the linear candidate lookup.
fn oracle_contextualized(domain: &PiiDomain, input: &str) -> Vec<Alternative> {
    let mut detected = Vec::new();
    for family in &domain.families {
        for mut alternative in family.detect(input) {
            alternative.family_id = family.id();
            alternative.reject_invisible_normalization = family.reject_invisible_normalization();
            detected.push(FamilyAlternative {
                alternative,
                context_requirement: family.context_requirement(),
                occurrence_exclusions: family.occurrence_exclusions(),
                reinforced_sensitivity_confidence: family.reinforced_sensitivity_confidence(),
            });
        }
    }
    let context_candidates: Vec<_> = detected
        .iter()
        .filter(|item| item.alternative.identity == IdentityState::Established)
        .map(|item| (item.alternative.range, item.alternative.domain))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let contexts = oracle::context_matches(input, &context_candidates);
    let mut contextualized = Vec::with_capacity(detected.len());
    for mut item in detected {
        let alternative = &mut item.alternative;
        if alternative.identity == IdentityState::Established {
            let matches = context_candidates
                .iter()
                .position(|candidate| *candidate == (alternative.range, alternative.domain))
                .map_or(&[][..], |index| contexts[index].as_slice());
            apply_context_contract(
                alternative,
                item.context_requirement,
                matches,
                item.occurrence_exclusions,
                item.reinforced_sensitivity_confidence,
            );
        }
        contextualized.push(item.alternative);
    }
    contextualized
}

/// Every production family, and each family alone as the identity
/// evaluator runs it.
fn domains() -> Vec<(String, PiiDomain)> {
    let mut domains = vec![(
        "all".to_owned(),
        production_domain(PiiSelection::parse(&["pii:global", "pii:us"]).unwrap()),
    )];
    assert_eq!(domains[0].1.families.len(), AVAILABLE_FAMILIES.len());
    for family in AVAILABLE_FAMILIES {
        let evaluator = IdentityEvaluator::new(family).unwrap();
        domains.push(((*family).to_owned(), evaluator.domain));
    }
    domains
}

/// The candidate lists the adapter builds for `input`: the distinct
/// established `(range, domain)` pairs, and every alternative's pair.
fn family_candidates(domain: &PiiDomain, input: &str) -> [Vec<(ByteRange, IdentityDomain)>; 2] {
    let mut established = BTreeSet::new();
    let mut every = BTreeSet::new();
    for family in &domain.families {
        for alternative in family.detect(input) {
            every.insert((alternative.range, alternative.domain));
            if alternative.identity == IdentityState::Established {
                established.insert((alternative.range, alternative.domain));
            }
        }
    }
    [
        established.into_iter().collect(),
        every.into_iter().collect(),
    ]
}

/// Asserts both associations agree and returns how many candidates
/// associated with at least one context entry.
fn assert_same_association(
    vocabulary: &ContextVocabulary,
    label: &str,
    input: &str,
    candidates: &[(ByteRange, IdentityDomain)],
) -> usize {
    let matches = vocabulary.matches(input, candidates);
    assert_eq!(
        matches,
        oracle::context_matches(input, candidates),
        "{label}: association differs for {input:?} with {candidates:?}"
    );
    matches.iter().filter(|matches| !matches.is_empty()).count()
}

fn assert_same_contextualized(domains: &[(String, PiiDomain)], label: &str, input: &str) {
    for (name, domain) in domains {
        assert_eq!(
            format!("{:?}", domain.contextualized(input)),
            format!("{:?}", oracle_contextualized(domain, input)),
            "{label} under {name}: contextualized alternatives differ for {input:?}"
        );
    }
}

/// Every `input` string and every string of an `inputs` array in a fixture.
fn fixture_inputs(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                match (key.as_str(), value) {
                    ("input", serde_json::Value::String(text)) => found.push(text.clone()),
                    ("inputs", serde_json::Value::Array(items)) => found.extend(
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(str::to_owned)),
                    ),
                    _ => fixture_inputs(value, found),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                fixture_inputs(item, found);
            }
        }
        _ => {}
    }
}

#[test]
fn association_equals_the_pre_902_oracle_over_the_pii_conformance_corpus() {
    let vocabulary = ContextVocabulary::new();
    let domains = domains();
    let mut inputs = 0;
    let mut associated = 0;
    for (file, text) in fixtures::PII_FIXTURES {
        let fixture: serde_json::Value = serde_json::from_str(text).unwrap();
        let mut found = Vec::new();
        fixture_inputs(&fixture, &mut found);
        assert!(!found.is_empty(), "{file}: no inputs");
        for input in found {
            inputs += 1;
            // The adapter scans the copy with governed invisible code points
            // removed; the identity evaluator does the same.
            let normalized = crate::normalize::NormalizedInput::new(&input);
            for text in [input.as_str(), normalized.text()] {
                for candidates in family_candidates(&domains[0].1, text) {
                    associated += assert_same_association(&vocabulary, file, text, &candidates);
                }
                assert_same_contextualized(&domains, file, text);
            }
        }
    }
    assert!(inputs > 200, "only {inputs} fixture inputs");
    assert!(
        associated > 200,
        "only {associated} candidates associated with context"
    );
}

/// Fixture inputs joined eight at a time, so candidates of different cases
/// share one logical line or sit on neighbouring ones.
#[test]
fn association_equals_the_pre_902_oracle_over_joined_fixture_inputs() {
    let vocabulary = ContextVocabulary::new();
    let domains = domains();
    for (file, text) in fixtures::PII_FIXTURES {
        let fixture: serde_json::Value = serde_json::from_str(text).unwrap();
        let mut found = Vec::new();
        fixture_inputs(&fixture, &mut found);
        for chunk in found.chunks(8) {
            for separator in [" ", "\n", " | ", "\r\n"] {
                let joined = chunk.join(separator);
                for candidates in family_candidates(&domains[0].1, &joined) {
                    assert_same_association(&vocabulary, file, &joined, &candidates);
                }
                assert_same_contextualized(&domains, file, &joined);
            }
        }
    }
}

/// A small deterministic generator (xorshift64*), so the corpus is the same
/// on every run and platform.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

/// Synthetic candidate-like values: documentation addresses, reserved
/// domains, published test card and IBAN numbers, fictional phone numbers.
const VALUES: &[&str] = &[
    "192.0.2.1",
    "198.51.100.7",
    "2001:db8::1",
    "test@example.com",
    "user.name@example.org",
    "4111111111111111",
    "4111 1111 1111 1111",
    "+1 202-555-0142",
    "(202) 555-0142",
    "890-62-6879",
    "GB82WEST12345698765432",
    "GB82 WEST 1234 5698 7654 32",
];

const JOINERS: &[&str] = &[
    "", " ", "  ", "=", ": ", ":", "|", " | ", "\"", "'", "=\"", "-", "_", "\t", "\u{a0}",
    "\u{3000}",
];

const FILLERS: &[&str] = &[
    "the",
    "customer",
    "value",
    "not",
    "x",
    "a|b",
    "note",
    "연락처",
    "값",
    "예시",
    "아님",
    "고객",
    "e\u{301}",
    "\u{1100}\u{1161}\u{11a8}",
    "\u{1100}",
    "\u{1161}",
    "\u{11a8}",
    "\u{301}",
    "\u{327}",
    "\u{200b}",
    "\u{ad}",
    "\u{3164}",
    "\u{fe0f}",
    "\u{212b}",
    "\u{ff21}",
    "\u{fb01}",
    "\u{130}",
    "\u{344}",
    "\u{f73}",
];

const BREAKS: &[&str] = &[
    "\n", "\r\n", "\r", "\u{b}", "\u{c}", "\u{1c}", "\u{85}", "\u{2028}", "\u{2029}",
];

/// A vocabulary form with its ASCII letters in a random case and its spaces
/// replaced by a random separator run.
fn label(generator: &mut Generator) -> String {
    let entry = &pii_context_table::CONTEXT_ENTRIES
        [generator.below(pii_context_table::CONTEXT_ENTRIES.len())];
    let form = entry.forms[generator.below(entry.forms.len())];
    let space = generator.pick(&[" ", "_", "-", "  ", " \u{200b}"]);
    let case = generator.below(3);
    form.chars()
        .map(|character| match character {
            ' ' => space.to_owned(),
            _ if case == 1 => character.to_ascii_uppercase().to_string(),
            _ if case == 2 && generator.below(2) == 0 => character.to_ascii_uppercase().to_string(),
            _ => character.to_string(),
        })
        .collect()
}

fn generated_text(generator: &mut Generator) -> String {
    let mut text = String::new();
    for _ in 0..=generator.below(24) {
        match generator.below(12) {
            0..=3 => {
                text.push_str(&label(generator));
                text.push_str(generator.pick(&["=", ": ", " ", "|", "=\"", " | ", " is "]));
                text.push_str(generator.pick(VALUES));
            }
            4 => text.push_str(&label(generator)),
            5..=6 => text.push_str(generator.pick(VALUES)),
            7..=8 => text.push_str(generator.pick(JOINERS)),
            9..=10 => text.push_str(generator.pick(FILLERS)),
            _ => text.push_str(generator.pick(BREAKS)),
        }
    }
    text
}

/// Random non-empty character-aligned ranges of `text`, some sharing a range
/// under another identity domain (issue #922), some spanning a line break.
fn random_candidates(generator: &mut Generator, text: &str) -> Vec<(ByteRange, IdentityDomain)> {
    let boundaries: Vec<usize> = text
        .char_indices()
        .map(|(index, _)| index)
        .chain([text.len()])
        .collect();
    let mut candidates = BTreeSet::new();
    if boundaries.len() < 2 {
        return Vec::new();
    }
    for _ in 0..generator.below(10) {
        let first = generator.below(boundaries.len() - 1);
        let last = first + 1 + generator.below((boundaries.len() - 1 - first).min(12));
        let range = ByteRange::new(boundaries[first], boundaries[last]).unwrap();
        let domain = IdentityDomain::ALL[generator.below(IdentityDomain::ALL.len())];
        candidates.insert((range, domain));
        if generator.below(4) == 0 {
            let other = IdentityDomain::ALL[generator.below(IdentityDomain::ALL.len())];
            candidates.insert((range, other));
        }
    }
    candidates.into_iter().collect()
}

#[test]
fn association_equals_the_pre_902_oracle_over_a_generated_corpus() {
    let vocabulary = ContextVocabulary::new();
    let domains = domains();
    let mut generator = Generator(0x9e37_79b9_7f4a_7c15);
    let mut associated = 0;
    for case in 0..3_000 {
        let text = generated_text(&mut generator);
        let label = format!("generated case {case}");
        for candidates in family_candidates(&domains[0].1, &text) {
            associated += assert_same_association(&vocabulary, &label, &text, &candidates);
        }
        let candidates = random_candidates(&mut generator, &text);
        associated += assert_same_association(&vocabulary, &label, &text, &candidates);
        // The adapter never passes an unsorted list, but the association is
        // defined index for index on any order.
        let mut reversed = candidates;
        reversed.reverse();
        assert_same_association(&vocabulary, &label, &text, &reversed);
        if case % 4 == 0 {
            assert_same_contextualized(&domains, &label, &text);
        }
    }
    assert!(
        associated > 1_500,
        "only {associated} candidates associated with context"
    );
}

#[test]
fn line_offsets_equal_the_normalized_prefix_length_at_every_boundary() {
    let mut generator = Generator(0x5151_2026_0902_0001);
    for _ in 0..500 {
        let text = generated_text(&mut generator);
        let positions: Vec<usize> = text
            .char_indices()
            .map(|(index, _)| index)
            .chain([text.len()])
            .collect();
        let offsets = LineOffsets::new(&text, 0, positions.clone());
        for position in positions {
            assert_eq!(
                offsets.at(position),
                normalize_context(&text[..position]).chars().count(),
                "{text:?} at {position}"
            );
        }
    }
}

// Issue #1058: each side's view is clipped to the scalars an accepted
// occurrence can reach before it is normalized and searched. The unclipped
// association (`ContextVocabulary::associate_unclipped`) and the pre-#902
// oracle above are the references.

/// Fillers for long lines: ASCII words and separator runs, combining marks
/// and conjoining jamo that compose across a cut, Hangul and CJK text with
/// no ASCII to cut at, invisible runs, and scalars NFC expands or maps.
const LONG_FILLERS: &[&str] = &[
    "lorem ",
    "ipsum",
    "x",
    " ",
    "  \t ",
    "--__::==",
    " - ",
    "e\u{301}",
    "\u{301}",
    "\u{301}\u{327}",
    "\u{1100}\u{1161}",
    "\u{1161}",
    "\u{11a8}",
    "고객 ",
    "값",
    "연락처",
    "中文字符",
    "中",
    "привет ",
    "a|b",
    "\"",
    "'",
    "\u{200b}\u{200b}\u{200b}",
    "\u{ad}",
    "\u{fe0f}",
    "\u{344}",
    "\u{f73}",
    "\u{212b}",
    "\u{2000}",
    "\u{3000}",
    "\u{a0}",
    "EMAIL",
    "Ip",
    // Overlapping occurrences of a form, so the non-overlapping search
    // depends on where a clipped view starts.
    "examplexample",
    "exampl",
    " example",
];

fn long_filler(generator: &mut Generator, scalars: usize) -> String {
    let mut text = String::new();
    while text.chars().count() < scalars {
        if generator.below(40) == 0 {
            // A long invisible run: invisible scalars never count towards
            // the clip, however many there are.
            text.push_str(&"\u{200b}".repeat(generator.below(400)));
        } else {
            text.push_str(generator.pick(LONG_FILLERS));
        }
    }
    text
}

/// A gap that normalizes to about `distance` scalars. Quotes, pipes and
/// single spaces keep a field label's gap valid; letters make it invalid.
fn distance_gap(generator: &mut Generator, distance: usize) -> String {
    let mut gap = String::new();
    let mut previous_separator = false;
    for index in 0..distance {
        let character = if index == 0 || index + 1 == distance {
            ' '
        } else if previous_separator {
            ['"', '\'', '|', 'y'][generator.below(4)]
        } else {
            [' ', '"', '\'', '|', 'y', '"'][generator.below(6)]
        };
        previous_separator = character == ' ';
        gap.push(character);
    }
    gap
}

fn natural_language_label(generator: &mut Generator) -> String {
    loop {
        let text = label(generator);
        let lowered = text.to_lowercase();
        if [
            "contact",
            "example",
            "documentation",
            "not",
            "연락처",
            "예시",
            "아님",
        ]
        .iter()
        .any(|form| lowered.contains(form))
        {
            return text;
        }
    }
}

/// A long logical line (or a few) with labels at distances around the
/// field-label (16) and natural-language (64) limits and the clip reach,
/// behind and ahead of values.
fn long_line(generator: &mut Generator) -> String {
    const DISTANCES: &[usize] = &[
        0, 1, 2, 14, 15, 16, 17, 18, 62, 63, 64, 65, 66, 95, 96, 97, 98, 99, 100, 130,
    ];
    let padding = generator.below(260);
    let mut text = long_filler(generator, padding);
    for _ in 0..=generator.below(4) {
        text.push_str(&label(generator));
        let before = DISTANCES[generator.below(DISTANCES.len())];
        text.push_str(&distance_gap(generator, before));
        text.push_str(generator.pick(VALUES));
        let after = DISTANCES[generator.below(DISTANCES.len())];
        text.push_str(&distance_gap(generator, after));
        text.push_str(&natural_language_label(generator));
        let padding = generator.below(260);
        text.push_str(&long_filler(generator, padding));
        if generator.below(8) == 0 {
            text.push_str(generator.pick(BREAKS));
        }
    }
    text
}

fn assert_clipping_is_exact(
    vocabulary: &ContextVocabulary,
    label: &str,
    input: &str,
    candidates: &[(ByteRange, IdentityDomain)],
) -> usize {
    let matches = vocabulary.matches(input, candidates);
    assert_eq!(
        matches,
        vocabulary.matches_by(input, candidates, ContextVocabulary::associate_unclipped),
        "{label}: clipped association differs for {input:?} with {candidates:?}"
    );
    matches.iter().filter(|matches| !matches.is_empty()).count()
}

#[test]
fn no_vocabulary_form_overlap_follows_a_boundary_so_views_are_clipped() {
    let vocabulary = ContextVocabulary::new();
    let longest = vocabulary
        .entries
        .iter()
        .flat_map(|(_, forms)| forms)
        .map(|form| form.scalars)
        .max()
        .unwrap();
    assert_eq!(vocabulary.reach, Some(MAX_CONTEXT_DISTANCE + longest + 1));
    // `example` overlaps itself (`examplexample`), but the later occurrence
    // follows an `l`, which never bounds an occurrence.
    assert!(!overlap_follows_boundary("example") && !overlap_follows_boundary("a"));
    assert!(overlap_follows_boundary("a a") && overlap_follows_boundary("ab'ab"));
    assert!(overlap_follows_boundary("") && !overlap_follows_boundary("e mail address"));
}

#[test]
fn normalize_context_equals_the_pre_902_normalization() {
    let mut generator = Generator(0x1058_0000_0000_0001);
    let mut texts: Vec<String> = (0..2_000)
        .map(|_| long_filler(&mut generator, 40))
        .collect();
    texts.extend((0..500).map(|_| generated_text(&mut generator)));
    texts.extend((0u8..128).map(|byte| char::from(byte).to_string()));
    texts.push("MiXeD--Case__Ascii::==  Text\t\u{b}".to_owned());
    for text in texts {
        assert_eq!(
            normalize_context(&text),
            oracle::normalize_context(&text),
            "{text:?}"
        );
    }
}

/// The two views are a suffix and a prefix of the whole ones, with the
/// dropped scalars accounted for, and never shorter than the reach unless
/// whole.
#[test]
fn clipped_views_are_exact_parts_of_the_whole_views() {
    let vocabulary = ContextVocabulary::new();
    let reach = vocabulary.reach.unwrap();
    let mut generator = Generator(0x1058_0000_0000_0002);
    let mut clipped = [0usize; 2];
    for _ in 0..400 {
        let length = 50 + generator.below(400);
        let text = long_filler(&mut generator, length);
        let boundaries: Vec<usize> = text
            .char_indices()
            .map(|(index, _)| index)
            .chain([text.len()])
            .collect();
        for _ in 0..20 {
            let mut pair = [
                boundaries[generator.below(boundaries.len())],
                boundaries[generator.below(boundaries.len())],
            ];
            pair.sort_unstable();
            let [start, end] = pair;
            let whole = normalize_context(&text[start..end]);
            let whole_scalars = whole.chars().count();

            let (before, dropped) = vocabulary.before_view(&text, start, end);
            assert!(whole.ends_with(&before), "{text:?} {start}..{end}");
            assert_eq!(dropped + before.chars().count(), whole_scalars);
            assert!(before == whole || before.chars().count() >= reach);
            clipped[0] += usize::from(dropped > 0);

            let after = vocabulary.after_view(&text, start, end);
            assert!(whole.starts_with(&after), "{text:?} {start}..{end}");
            assert!(after == whole || after.chars().count() >= reach);
            clipped[1] += usize::from(after != whole);
        }
    }
    assert!(clipped.iter().all(|count| *count > 300), "{clipped:?}");
}

#[test]
fn clipped_association_equals_the_unclipped_one_over_long_lines() {
    let vocabulary = ContextVocabulary::new();
    let domains = domains();
    let mut generator = Generator(0x1058_0000_0000_0003);
    let mut associated = 0;
    for case in 0..1_500 {
        let text = long_line(&mut generator);
        let label = format!("long line {case}");
        for candidates in family_candidates(&domains[0].1, &text) {
            associated += assert_clipping_is_exact(&vocabulary, &label, &text, &candidates);
            if case % 5 == 0 {
                assert_same_association(&vocabulary, &label, &text, &candidates);
            }
        }
        let candidates = random_candidates(&mut generator, &text);
        assert_clipping_is_exact(&vocabulary, &label, &text, &candidates);
        if case % 10 == 0 {
            assert_same_contextualized(&domains, &label, &text);
        }
    }
    assert!(
        associated > 800,
        "only {associated} candidates associated with context"
    );
}

/// Every PII fixture input with a long filler on the same line before and
/// after it, so the fixture's own context sits near the clip.
#[test]
fn clipped_association_equals_the_unclipped_one_over_padded_fixture_inputs() {
    let vocabulary = ContextVocabulary::new();
    let domains = domains();
    let mut generator = Generator(0x1058_0000_0000_0004);
    let mut associated = 0;
    for (file, text) in fixtures::PII_FIXTURES {
        let fixture: serde_json::Value = serde_json::from_str(text).unwrap();
        let mut found = Vec::new();
        fixture_inputs(&fixture, &mut found);
        for input in found {
            for _ in 0..3 {
                let [before, after] = [generator.below(200), generator.below(200)];
                let padded = format!(
                    "{}{input}{}",
                    long_filler(&mut generator, before),
                    long_filler(&mut generator, after),
                );
                for candidates in family_candidates(&domains[0].1, &padded) {
                    associated += assert_clipping_is_exact(&vocabulary, file, &padded, &candidates);
                }
            }
            let padded = format!("{} {input} {}", "lorem ".repeat(40), "ipsum ".repeat(40));
            assert_same_contextualized(&domains, file, &padded);
        }
    }
    assert!(
        associated > 200,
        "only {associated} candidates associated with context"
    );
}

/// The view searched for a candidate no longer grows with its distance to
/// the line start or the previous candidate: a 256 KiB line normalizes and
/// searches a bounded window on each side.
#[test]
fn a_long_line_is_clipped_to_a_bounded_view_on_each_side() {
    let vocabulary = ContextVocabulary::new();
    let reach = vocabulary.reach.unwrap();
    for filler in [
        "lorem ipsum ",
        "e\u{301}x ",
        "고객 값 ",
        "\u{200b}a\u{200b} ",
    ] {
        let text = format!(
            "{}ip=192.0.2.1 {}",
            filler.repeat(256 * 1024 / filler.len()),
            filler.repeat(256 * 1024 / filler.len())
        );
        let start = text.find("192.0.2.1").unwrap();
        let end = start + "192.0.2.1".len();
        let (before, dropped) = vocabulary.before_view(&text, 0, start);
        let after = vocabulary.after_view(&text, end, text.len());
        assert!(dropped > 50_000, "{filler:?}");
        // Snapping to a segment start adds at most one filler token.
        let bound = reach + 2 * filler.len();
        assert!(before.chars().count() < bound, "{filler:?}: {before:?}");
        assert!(after.chars().count() < bound, "{filler:?}: {after:?}");
        let candidates = [(
            ByteRange::new(start, end).unwrap(),
            IdentityDomain::NetworkAddress,
        )];
        assert_clipping_is_exact(&vocabulary, filler, &text, &candidates);
    }
}

/// Every form of every entry, before and after a candidate of each of its
/// domains, at every distance within two scalars of each limit and of the
/// reach, behind fillers that put the cut at, inside and away from it.
#[test]
fn clipped_association_is_exact_for_every_form_around_each_distance_limit() {
    let vocabulary = ContextVocabulary::new();
    let reach = vocabulary.reach.unwrap();
    let mut generator = Generator(0x1058_0000_0000_0005);
    let mut associated = 0;
    let mut distances: Vec<usize> = [16, MAX_CONTEXT_DISTANCE, reach]
        .iter()
        .flat_map(|limit| limit - 2..=limit + 2)
        .collect();
    distances.extend([0, 1]);
    let fillers = [
        "lorem ipsum ",
        "\"",
        "e\u{301}",
        "고객값",
        "\u{200b}",
        " \u{3000}- ",
    ];
    for entry in pii_context_table::CONTEXT_ENTRIES {
        for form in entry.forms {
            for domain in entry.domains {
                for &distance in &distances {
                    for filler in fillers {
                        let gap = distance_gap(&mut generator, distance);
                        let mut text = filler.repeat(1 + generator.below(40));
                        text.push_str(form);
                        text.push_str(&gap);
                        let start = text.len();
                        text.push_str("192.0.2.1");
                        let end = text.len();
                        text.push_str(&gap);
                        text.push_str(form);
                        text.push_str(&filler.repeat(1 + generator.below(40)));
                        let candidates = [(ByteRange::new(start, end).unwrap(), *domain)];
                        associated +=
                            assert_clipping_is_exact(&vocabulary, form, &text, &candidates);
                    }
                }
            }
        }
    }
    assert!(
        associated > 500,
        "only {associated} candidates associated with context"
    );
}
