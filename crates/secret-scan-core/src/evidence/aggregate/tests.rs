//! Tests of the shadow aggregation contract (issue #770). Every value is
//! synthetic.

use super::*;
use crate::detectors::built_in_detectors;
use crate::types::{ByteRange, DetectorContext};

/// Index of `min_entropy_q16` in [`FEATURE_NAMES`].
const MIN_ENTROPY_FEATURE: usize = 6;
/// Index of `alphabet_efficiency_permille` in [`FEATURE_NAMES`].
const ALPHABET_EFFICIENCY_FEATURE: usize = 18;
/// Index of `distinct_ratio_permille` in [`FEATURE_NAMES`].
const DISTINCT_RATIO_FEATURE: usize = 19;

/// Four correlated randomness measurements that all saturate on a
/// random-looking value: the case the halving rule and the cap exist for.
const CORRELATED_RANDOMNESS: [SignalRule; MAX_GROUP_SIGNALS] = [
    SignalRule::FeatureRamp {
        feature: SHANNON_ENTROPY_FEATURE,
        lo: 254_345,
        hi: 313_536,
        max: 60,
    },
    SignalRule::FeatureRamp {
        feature: MIN_ENTROPY_FEATURE,
        lo: 200_000,
        hi: 300_000,
        max: 60,
    },
    SignalRule::FeatureRamp {
        feature: ALPHABET_EFFICIENCY_FEATURE,
        lo: 500,
        hi: 800,
        max: 60,
    },
    SignalRule::FeatureRamp {
        feature: DISTINCT_RATIO_FEATURE,
        lo: 500,
        hi: 900,
        max: 60,
    },
];

/// The product model with `signals` in place of its randomness group and
/// `randomness_cap` as that group's cap.
const fn with_randomness(signals: &'static [SignalRule], randomness_cap: u32) -> AggregationModel {
    let mut model = SHADOW_MODEL;
    model.id = "test-only";
    model.groups[EvidenceGroup::Randomness as usize].signals = signals;
    model.groups[EvidenceGroup::Randomness as usize].cap = randomness_cap;
    model
}

/// Deterministic synthetic text: a xorshift stream over base62.
fn synthetic(seed: u64, len: usize) -> String {
    let alphabet: Vec<char> = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            alphabet[usize::try_from(state % 62).unwrap()]
        })
        .collect()
}

/// Random-looking values of several lengths.
fn random_values() -> impl Iterator<Item = String> {
    (1_u64..=120).map(|seed| synthetic(seed, usize::try_from(seed % 60 + 8).unwrap()))
}

fn inputs(value: &str, context: ContextClass) -> ShadowInputs {
    ShadowInputs::of_value(value, context)
}

fn statistical(value: &str, context: ContextClass) -> EvidenceExplanation {
    aggregate(&SHADOW_MODEL, &inputs(value, context))
}

/// Each candidate the built-in detectors emit for `input`, with its value.
fn candidates(input: &str) -> Vec<(Candidate, &str)> {
    let context = DetectorContext::new(input.len());
    built_in_detectors()
        .iter()
        .flat_map(|detector| detector.detect(input, &context).unwrap())
        .map(|candidate| {
            let range = candidate.range();
            (candidate, &input[range.start()..range.end()])
        })
        .collect()
}

/// 20 distinct symbols, each once: Shannon entropy `log2(20)`, between the
/// randomness ramp's ends.
const AMBIGUOUS_VALUE: &str = "k3Z9pQ7vW2mX8nR4tL6y";
/// 32 distinct symbols: Shannon entropy 5 bits, above the ramp's top.
const RANDOM_VALUE: &str = "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa";

// --- the model and its invariants ---------------------------------------

#[test]
fn the_product_model_satisfies_the_contract_invariants() {
    let model = SHADOW_MODEL;
    assert_eq!(model.violation(), None);
    let bands = model.bands;
    assert!(0 < bands.low && bands.low < bands.medium && bands.medium < bands.high);
    for config in model.groups {
        if !config.group.is_negative() {
            assert!(config.cap < bands.high, "{config:?}");
        }
    }
    let cap = |group: EvidenceGroup| model.groups[group as usize].cap;
    assert!(cap(EvidenceGroup::Randomness) + cap(EvidenceGroup::Lexical) < bands.high);
    assert_eq!(model.groups.map(|config| config.group), EvidenceGroup::ALL);
    assert_eq!(model.feature_schema, FEATURE_SCHEMA_VERSION);
    assert_eq!(
        FEATURE_NAMES[SHANNON_ENTROPY_FEATURE],
        "shannon_entropy_q16"
    );
    assert_eq!(FEATURE_NAMES[MIN_ENTROPY_FEATURE], "min_entropy_q16");
    assert_eq!(
        FEATURE_NAMES[ALPHABET_EFFICIENCY_FEATURE],
        "alphabet_efficiency_permille"
    );
    assert_eq!(
        FEATURE_NAMES[DISTINCT_RATIO_FEATURE],
        "distinct_ratio_permille"
    );
}

#[test]
fn the_product_model_is_the_calibrated_selection() {
    // redact-secret-benchmarks#300 (PR #330,
    // e18efa2d0802c030925b9306a5dca33057185936). Changing any value
    // here is a new model identity (ADR section 10).
    let model = SHADOW_MODEL;
    assert_eq!(model.id, "evidence-aggregation/v2");
    let caps = model
        .groups
        .map(|config| (config.group.as_str(), config.cap));
    assert_eq!(
        caps,
        [
            ("randomness", 30),
            ("lexical", 0),
            ("contextual", 50),
            ("validation", 50),
            ("negative", 130),
        ]
    );
    assert_eq!(
        model.groups[0].signals,
        [SignalRule::FeatureRamp {
            feature: SHANNON_ENTROPY_FEATURE,
            lo: 226_998,
            hi: 265_935,
            max: 30,
        }]
    );
    assert_eq!(
        model.groups[2].signals,
        [SignalRule::Context {
            classes: &[
                ContextClass::CredentialName,
                ContextClass::AuthorizationHeader,
                ContextClass::UrlUserinfo,
            ],
            points: 50,
        }]
    );
    assert!(model.groups[1].signals.is_empty());
    assert!(model.groups[3].signals.is_empty());
    assert_eq!(
        model.groups[4].signals,
        [SignalRule::StrictExclusion { points: 130 }]
    );
    assert_eq!(
        model.bands,
        BandThresholds {
            low: 35,
            medium: 40,
            high: 51
        }
    );
}

#[test]
fn models_that_break_an_invariant_are_rejected() {
    type Breaker = fn(&mut AggregationModel);
    let broken: [(&str, Breaker); 9] = [
        ("thresholds", |m| m.bands.medium = m.bands.low),
        ("zero low", |m| m.bands.low = 0),
        ("cap at t_high", |m| m.groups[2].cap = m.bands.high),
        ("randomness plus lexical", |m| m.groups[1].cap = 1),
        ("negative cap", |m| m.groups[4].cap = 129),
        ("group order", |m| m.groups.swap(0, 1)),
        ("exclusion outside negative", |m| {
            m.groups[0].signals = &[SignalRule::StrictExclusion { points: 1 }];
        }),
        ("statistics inside negative", |m| {
            m.groups[4].signals = &CORRELATED_RANDOMNESS[..1];
        }),
        ("ramp", |m| {
            m.groups[0].signals = &[SignalRule::FeatureRamp {
                feature: FEATURE_COUNT,
                lo: 0,
                hi: 1,
                max: 1,
            }];
        }),
    ];
    for (name, breaker) in broken {
        let mut model = SHADOW_MODEL;
        breaker(&mut model);
        assert!(model.violation().is_some(), "{name}");
    }
    let mut context_elsewhere = SHADOW_MODEL;
    context_elsewhere.groups[3].signals = context_elsewhere.groups[2].signals;
    assert!(context_elsewhere.violation().is_some());
}

#[test]
fn bands_follow_the_integer_thresholds() {
    let model = SHADOW_MODEL;
    for (total, band) in [
        (0, ShadowBand::None),
        (34, ShadowBand::None),
        (35, ShadowBand::Low),
        (39, ShadowBand::Low),
        (40, ShadowBand::Medium),
        (50, ShadowBand::Medium),
        (51, ShadowBand::High),
        (u32::MAX, ShadowBand::High),
    ] {
        assert_eq!(model.band(total), band, "{total}");
    }
}

#[test]
fn ramp_is_zero_below_capped_above_and_floors_between() {
    assert_eq!(ramp(0, 10, 20, 60), 0);
    assert_eq!(ramp(10, 10, 20, 60), 0);
    assert_eq!(ramp(11, 10, 20, 60), 6);
    assert_eq!(ramp(19, 10, 20, 60), 54);
    assert_eq!(ramp(20, 10, 20, 60), 60);
    assert_eq!(ramp(u32::MAX, 10, 20, 60), 60);
    // floor(60 * (283241 - 254345) / (313536 - 254345)) = floor(29.29...)
    assert_eq!(ramp(283_241, 254_345, 313_536, 60), 29);
    assert_eq!(ramp(u32::MAX - 1, 0, u32::MAX, u32::MAX), u32::MAX - 1);
}

// --- the halving rule -----------------------------------------------------

#[test]
fn halving_follows_the_contract_formula() {
    assert_eq!(halving_sum(&mut [], 100), 0);
    assert_eq!(halving_sum(&mut [60], 100), 60);
    // Sorted descending first: 60 + (40 >> 1) + (10 >> 2).
    assert_eq!(halving_sum(&mut [10, 60, 40], 1000), 60 + 20 + 2);
    // Four equal correlated signals: 60 + 30 + 15 + 7, not 240.
    assert_eq!(halving_sum(&mut [60; 4], 1000), 112);
    assert_eq!(halving_sum(&mut [60; 4], 60), 60);
    // Saturating, and a shift past the width is zero.
    assert_eq!(halving_sum(&mut [u32::MAX, u32::MAX], u32::MAX), u32::MAX);
    let mut many = [1_u32; 40];
    assert_eq!(halving_sum(&mut many, u32::MAX), 1);
}

/// Every vector of up to four contributions from `values`.
fn small_vectors(values: &[u32]) -> Vec<Vec<u32>> {
    let mut vectors = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..MAX_GROUP_SIGNALS {
        let mut next = Vec::new();
        for vector in &frontier {
            for &value in values {
                let mut longer: Vec<u32> = vector.clone();
                longer.push(value);
                next.push(longer);
            }
        }
        vectors.extend(next.iter().cloned());
        frontier = next;
    }
    vectors
}

#[test]
fn halving_is_monotone_in_each_signal_and_in_adding_a_signal() {
    // ADR section 4, exhaustively over small vectors.
    let values = [0, 1, 2, 3, 5, 7, 8, 13, 31, 60];
    for cap in [7, 60, u32::MAX] {
        for vector in small_vectors(&values) {
            let base = halving_sum(&mut vector.clone(), cap);
            assert!(base <= cap);
            for index in 0..vector.len() {
                for raise in [1, 2, 17] {
                    let mut raised = vector.clone();
                    raised[index] += raise;
                    assert!(halving_sum(&mut raised, cap) >= base, "{vector:?}");
                }
            }
            if vector.len() < MAX_GROUP_SIGNALS {
                for &added in &values {
                    let mut extended = vector.clone();
                    extended.push(added);
                    assert!(halving_sum(&mut extended, cap) >= base, "{vector:?}");
                }
            }
        }
    }
}

// --- correlated randomness cannot manufacture `high` ------------------------

#[test]
fn correlated_randomness_signals_do_not_accumulate_linearly() {
    // Test-only model: four correlated randomness signals, each saturating
    // on a random-looking value, with a cap large enough to show the rule.
    let uncapped = with_randomness(&CORRELATED_RANDOMNESS, 50);
    let explanation = aggregate(&uncapped, &inputs(RANDOM_VALUE, ContextClass::Bare));
    let randomness = explanation.groups[EvidenceGroup::Randomness as usize];
    assert_eq!(
        randomness
            .signals()
            .iter()
            .map(|s| s.points)
            .collect::<Vec<_>>(),
        [60, 60, 60, 60]
    );
    // 60 + 30 + 15 + 7 before the cap, not 4 * 60.
    assert_eq!(randomness.uncapped, 112);
    assert_eq!(randomness.contribution, 50);
    assert!(randomness.is_capped());
    assert_eq!(explanation.band, ShadowBand::Medium);
}

#[test]
fn correlated_randomness_never_reaches_high_by_quantity_alone() {
    let models = [
        SHADOW_MODEL,
        with_randomness(&CORRELATED_RANDOMNESS[..1], 30),
        with_randomness(&CORRELATED_RANDOMNESS[..2], 30),
        with_randomness(&CORRELATED_RANDOMNESS[..3], 30),
        with_randomness(&CORRELATED_RANDOMNESS, 30),
    ];
    for model in models {
        assert_eq!(model.violation(), None);
        for value in random_values().chain([RANDOM_VALUE.to_owned()]) {
            for context in [ContextClass::Bare, ContextClass::OtherName] {
                let explanation = aggregate(&model, &inputs(&value, context));
                assert!(explanation.band <= ShadowBand::Medium, "{explanation:?}");
            }
        }
    }
    // The selected product randomness group alone stays below `low`.
    assert_eq!(
        statistical(RANDOM_VALUE, ContextClass::Bare).band,
        ShadowBand::None
    );
}

#[test]
fn adding_a_correlated_signal_never_lowers_the_score() {
    for value in random_values() {
        let mut previous = 0;
        for count in 0..=MAX_GROUP_SIGNALS {
            let model = with_randomness(&CORRELATED_RANDOMNESS[..count], 60);
            let score = aggregate(&model, &inputs(&value, ContextClass::Bare)).score;
            assert!(score >= previous, "{value}: {count}");
            previous = score;
        }
    }
}

// --- independent context strengthens an ambiguous candidate ---------------

#[test]
fn context_plus_randomness_strengthens_an_ambiguous_candidate() {
    let alone = statistical(AMBIGUOUS_VALUE, ContextClass::Bare);
    assert_eq!(alone.band, ShadowBand::None);
    assert_eq!(
        alone.contributing_groups().collect::<Vec<_>>(),
        [EvidenceGroup::Randomness]
    );
    for context in [
        ContextClass::CredentialName,
        ContextClass::AuthorizationHeader,
        ContextClass::UrlUserinfo,
    ] {
        let with_context = statistical(AMBIGUOUS_VALUE, context);
        assert_eq!(with_context.band, ShadowBand::High, "{context:?}");
        assert_eq!(with_context.score, alone.score + 50);
        assert_eq!(
            with_context.contributing_groups().collect::<Vec<_>>(),
            [EvidenceGroup::Randomness, EvidenceGroup::Contextual]
        );
    }
    // Context alone proposes `medium`; `other-name` is not credential-bearing.
    assert_eq!(
        statistical("aaaaaaaaaaaaaaaa", ContextClass::CredentialName).band,
        ShadowBand::Medium
    );
    assert_eq!(
        statistical(AMBIGUOUS_VALUE, ContextClass::OtherName).score,
        alone.score
    );
}

#[test]
fn a_real_contextual_candidate_is_strengthened_through_its_detector_signals() {
    let input = format!("API_KEY={AMBIGUOUS_VALUE}");
    let found = candidates(&input);
    let (candidate, value) = found
        .iter()
        .find(|(c, _)| c.type_name() == "contextual_secret")
        .unwrap();
    assert_eq!(*value, AMBIGUOUS_VALUE);
    let shadow = shadow_evidence(&SHADOW_MODEL, candidate, value);
    assert_eq!(shadow.authority, ShadowAuthority::Statistical);
    assert_eq!(shadow.band, ShadowBand::High);
    let explanation = shadow.explanation.unwrap();
    assert_eq!(explanation.context, ContextClass::CredentialName);
    // The same value as an entropy-only candidate has no context.
    let bare = Candidate::new("x", Confidence::Medium, candidate.range())
        .with_specificity(Specificity::Entropy);
    assert_eq!(
        shadow_evidence(&SHADOW_MODEL, &bare, value).band,
        ShadowBand::None
    );
}

// --- negative evidence is structurally bounded ------------------------------

#[test]
fn a_full_exclusion_grammar_match_floors_the_score() {
    for value in [
        "{{ secrets.API_KEY }}",
        "${API_KEY}",
        "$(cat /run/secrets/api_key)",
        "<your-api-key>",
        "****************",
        "your-api-key-here",
    ] {
        let explanation = statistical(value, ContextClass::CredentialName);
        assert!(explanation.exclusion.is_some(), "{value}");
        assert_eq!(explanation.negative, 130, "{value}");
        assert_eq!(explanation.score, 0, "{value}");
        assert_eq!(explanation.band, ShadowBand::None, "{value}");
    }
}

#[test]
fn attacker_controlled_lookalikes_do_not_suppress() {
    let lookalikes = [
        format!("EXAMPLE{RANDOM_VALUE}"),
        format!("{RANDOM_VALUE}_placeholder"),
        format!("your-{RANDOM_VALUE}-here"),
        format!("{{{{ x }}}}{RANDOM_VALUE}"),
        format!("{RANDOM_VALUE}{{{{ x }}}}"),
        format!("${{API_KEY}}{RANDOM_VALUE}"),
        format!("{RANDOM_VALUE}$API_KEY"),
        format!("<API_KEY>{RANDOM_VALUE}"),
        format!("****{RANDOM_VALUE}****"),
        format!("$(x){RANDOM_VALUE}"),
        // The product does not treat dotted references as negative: the same
        // shape matches dotted credential grammars.
        "SG.Q7vK2mZp9LxR4tWb.8NcY3hJd6FsG1eUa".to_owned(),
    ];
    for value in &lookalikes {
        let with = statistical(value, ContextClass::CredentialName);
        assert_eq!(with.exclusion, None, "{value}");
        assert_eq!(with.negative, 0, "{value}");
        // The band comes from the positive groups alone.
        assert_eq!(with.score, with.positive, "{value}");
        assert_eq!(with.band, ShadowBand::High, "{value}");
    }
}

// --- deterministic authority ------------------------------------------------

#[test]
fn deterministic_candidates_are_invariant_under_statistical_manipulation() {
    let range = ByteRange::new(0, 1).unwrap();
    let manipulations = [
        RANDOM_VALUE.to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "{{ secrets.API_KEY }}".to_owned(),
        "your-api-key-here".to_owned(),
        "****************".to_owned(),
        "k3Z9".repeat(64),
        String::new(),
    ];
    for specificity in [
        Specificity::PrivateKey,
        Specificity::Provider,
        Specificity::Structural,
    ] {
        for confidence in [Confidence::Low, Confidence::Medium, Confidence::High] {
            let candidate = Candidate::new("authoritative", confidence, range)
                .with_specificity(specificity)
                .with_signals(["high-signal-name"]);
            for value in &manipulations {
                let shadow = shadow_evidence(&SHADOW_MODEL, &candidate, value);
                assert_eq!(
                    shadow,
                    ShadowEvidence {
                        authority: ShadowAuthority::Deterministic,
                        band: ShadowBand::of_confidence(confidence),
                        explanation: None,
                    }
                );
            }
        }
    }
}

#[test]
fn real_detector_candidates_keep_their_authority_and_are_not_changed() {
    // Synthetic inputs across detector classes: structural (Authorization,
    // Bearer, connection URL), private-key and contextual shapes.
    let inputs = [
        "Authorization: Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk".to_owned(),
        format!("Authorization: Bearer {RANDOM_VALUE}"),
        "postgres://fakeuser:Zp9LxR4tWb8NcY3h@db.example.invalid:5432/app".to_owned(),
        format!("API_KEY={AMBIGUOUS_VALUE}"),
        format!("password = \"{RANDOM_VALUE}\""),
        [
            "-----BEGIN PRIVATE KEY-----",
            "U1lOVEhFVElDX1JFVk9LRURfTk8=",
            "-----END PRIVATE KEY-----",
        ]
        .join("\n"),
    ];
    let mut seen_deterministic = 0;
    let mut seen_statistical = 0;
    for input in &inputs {
        for (candidate, value) in candidates(input) {
            let before = candidate.clone();
            let first = shadow_evidence(&SHADOW_MODEL, &candidate, value);
            let second = shadow_evidence(&SHADOW_MODEL, &candidate, value);
            assert_eq!(first, second, "deterministic");
            assert_eq!(candidate, before, "the candidate is untouched");
            match candidate.effective_specificity() {
                Specificity::PrivateKey | Specificity::Provider | Specificity::Structural => {
                    seen_deterministic += 1;
                    assert_eq!(first.authority, ShadowAuthority::Deterministic);
                    assert_eq!(
                        first.band,
                        ShadowBand::of_confidence(candidate.confidence())
                    );
                    assert!(first.explanation.is_none());
                }
                Specificity::Contextual | Specificity::Entropy => {
                    seen_statistical += 1;
                    assert_eq!(first.authority, ShadowAuthority::Statistical);
                    assert!(first.explanation.is_some());
                }
            }
        }
    }
    assert!(seen_deterministic >= 4, "{seen_deterministic}");
    assert!(seen_statistical >= 2, "{seen_statistical}");
}

// --- monotonicity (ADR section 4) ---------------------------------------------

#[test]
fn raising_a_positive_signal_never_lowers_the_score() {
    let base = inputs(RANDOM_VALUE, ContextClass::Bare);
    let mut previous = 0;
    for entropy in (0..=400_000).step_by(997) {
        let mut raised = base;
        raised.features.shannon_entropy_q16 = entropy;
        let score = aggregate(&SHADOW_MODEL, &raised).score;
        assert!(score >= previous, "{entropy}");
        previous = score;
    }
    for value in random_values() {
        let bare_score = statistical(&value, ContextClass::Bare).score;
        let credential_score = statistical(&value, ContextClass::CredentialName).score;
        assert!(credential_score >= bare_score, "{value}");
    }
}

#[test]
fn raising_the_negative_contribution_never_raises_the_score() {
    for value in random_values() {
        for context in [ContextClass::Bare, ContextClass::CredentialName] {
            let without = inputs(&value, context);
            let mut with = without;
            with.exclusion = Some(ExclusionGrammar::Mask);
            assert!(
                aggregate(&SHADOW_MODEL, &with).score <= aggregate(&SHADOW_MODEL, &without).score
            );
        }
    }
}

#[test]
fn the_band_is_a_non_decreasing_step_function_of_the_score() {
    let model = SHADOW_MODEL;
    for total in 0..=500 {
        assert!(model.band(total) <= model.band(total + 1), "{total}");
    }
}

// --- explanation ----------------------------------------------------------------

#[test]
fn every_band_is_explained_by_its_groups() {
    let contexts = [
        ContextClass::Bare,
        ContextClass::OtherName,
        ContextClass::CredentialName,
    ];
    let values =
        random_values().chain([AMBIGUOUS_VALUE, "{{ x }}", "aaaaaaaa", ""].map(str::to_owned));
    for value in values {
        for context in contexts {
            let explanation = statistical(&value, context);
            let mut positive = 0;
            let mut negative = 0;
            for (group, config) in explanation.groups.iter().zip(SHADOW_MODEL.groups) {
                assert_eq!(group.group, config.group);
                let mut points: Vec<u32> = group.signals().iter().map(|s| s.points).collect();
                assert_eq!(group.uncapped, halving_sum(&mut points, u32::MAX));
                assert_eq!(group.contribution, group.uncapped.min(config.cap));
                if group.group.is_negative() {
                    negative += group.contribution;
                } else {
                    positive += group.contribution;
                }
            }
            assert_eq!(explanation.positive, positive);
            assert_eq!(explanation.negative, negative);
            assert_eq!(explanation.score, positive.saturating_sub(negative));
            assert_eq!(explanation.band, SHADOW_MODEL.band(explanation.score));
            assert_eq!(explanation.model, SHADOW_MODEL.id);
            assert_eq!(explanation.context, context);
            assert_eq!(explanation.band == ShadowBand::None, explanation.score < 35);
        }
    }
}

#[test]
fn explanations_carry_no_part_of_the_value() {
    let value = "SYNTHETICvalueMARKERq7Zk";
    let range = ByteRange::new(0, value.len()).unwrap();
    let candidate = Candidate::new("contextual_secret", Confidence::High, range)
        .with_specificity(Specificity::Contextual)
        .with_signals(["high-signal-name"]);
    let shadow = shadow_evidence(&SHADOW_MODEL, &candidate, value);
    let rendered = format!("{shadow:?}");
    for fragment in ["SYNTHETIC", "MARKER", "value", "q7Zk"] {
        assert!(!rendered.contains(fragment), "{rendered}");
    }
    let signals: Vec<&str> = shadow
        .explanation
        .unwrap()
        .groups
        .iter()
        .flat_map(|group| group.signals().iter().map(|s| s.signal))
        .collect();
    assert_eq!(
        signals,
        [
            "shannon_entropy_q16",
            "credential-context",
            "strict-exclusion"
        ]
    );
}
