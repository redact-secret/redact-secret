//! Drift check between the compiled shadow scorer and its reviewed scoring
//! artifact (issue #798).
//!
//! The reviewed artifact is `docs/contracts/scoring/shadow-scoring-artifact.json`.
//! Core source may not read files (`scripts/check-rust-workspace.py`, check
//! 7), so the check has two halves that meet at [`REVIEWED_MODEL_JSON`]:
//!
//! 1. this test renders the **compiled** [`SHADOW_MODEL`], feature schema and
//!    exclusion vocabulary into canonical JSON and requires it to equal
//!    [`REVIEWED_MODEL_JSON`] byte for byte;
//! 2. `scripts/check-scoring-artifact.py` (`npm run scoring-artifact:check`,
//!    part of `npm run ci`) requires [`REVIEWED_MODEL_JSON`] to equal the
//!    artifact's `model` object, and the artifact's fingerprint and identity
//!    ledger to match it.
//!
//! So a constant changed in Rust fails here, and a value changed only in the
//! artifact fails the script. Updating both without a new model identity is
//! caught by the script's identity ledger and, on a pull request, by its
//! comparison with the base branch's artifact. Nothing here is loaded at
//! runtime: this module exists only under `cfg(test)`.

use super::*;
use crate::evidence::context::CREDENTIAL_NAME_SIGNALS;
use crate::evidence::exclusion::{
    MASK_SYMBOLS, MIN_MASK_LEN, PLACEHOLDER_MARKERS, PLACEHOLDER_WORDS,
};
use crate::evidence::features::{MAX_ANALYSED_CHARS, MAX_AUTOCORRELATION_LAG};
use crate::evidence::fixed_point::Q16_FRACTION_BITS;
use std::fmt::Write as _;

/// The golden inputs of `docs/specs/engine.md` ("Golden vectors"). Their
/// compiled feature vectors are part of the rendering, so a change to feature
/// semantics shows up as drift even when no named constant moved.
const GOLDEN_INPUTS: [&str; 8] = [
    "",
    "aaaaaaaaaaaaaaaa",
    "abcabcabcabcabcabc",
    "XXXX-XXXX-XXXX-XXXX",
    "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa",
    "\u{1F600}a\u{1F603}b\u{1F600}a\u{1F603}b",
    "ab",
    "aabc",
];

/// Every exclusion grammar, in the order [`exclusion_grammar`] checks them.
const GRAMMARS: [ExclusionGrammar; 6] = [
    ExclusionGrammar::TemplateReference,
    ExclusionGrammar::EnvironmentReference,
    ExclusionGrammar::CommandSubstitution,
    ExclusionGrammar::AnglePlaceholder,
    ExclusionGrammar::Mask,
    ExclusionGrammar::PlaceholderVocabulary,
];

/// Every context class, in declaration order.
const CONTEXT_CLASSES: [ContextClass; 5] = [
    ContextClass::UrlUserinfo,
    ContextClass::AuthorizationHeader,
    ContextClass::CredentialName,
    ContextClass::OtherName,
    ContextClass::Bare,
];

/// Fails to compile when a grammar or context class is added without being
/// listed above, so the rendering cannot silently miss one.
const fn listed(grammar: ExclusionGrammar, class: ContextClass) -> (usize, usize) {
    let grammar = match grammar {
        ExclusionGrammar::TemplateReference => 0,
        ExclusionGrammar::EnvironmentReference => 1,
        ExclusionGrammar::CommandSubstitution => 2,
        ExclusionGrammar::AnglePlaceholder => 3,
        ExclusionGrammar::Mask => 4,
        ExclusionGrammar::PlaceholderVocabulary => 5,
    };
    let class = match class {
        ContextClass::UrlUserinfo => 0,
        ContextClass::AuthorizationHeader => 1,
        ContextClass::CredentialName => 2,
        ContextClass::OtherName => 3,
        ContextClass::Bare => 4,
    };
    (grammar, class)
}

/// The reviewed rendering. It must equal the `model` object of
/// `docs/contracts/scoring/shadow-scoring-artifact.json`
/// (`scripts/check-scoring-artifact.py` extracts it from this file). Change
/// it only together with that artifact, a new model identity and a new
/// artifact revision (`docs/specs/engine.md`, "Shadow scoring artifact").
const REVIEWED_MODEL_JSON: &str = r##"{
  "featureSchema": {
    "id": "evidence-features/v1",
    "maxAnalysedChars": 256,
    "maxAutocorrelationLag": 32,
    "fixedPointFractionBits": 16,
    "features": ["byte_len", "analysed_chars", "truncated", "distinct_symbols", "max_symbol_count", "shannon_entropy_q16", "min_entropy_q16", "information_bits_q16", "class_lower", "class_upper", "class_digit", "class_symbol", "class_space_control", "class_non_ascii", "class_count", "class_transitions", "class_alphabet_size", "entropy_efficiency_permille", "alphabet_efficiency_permille", "distinct_ratio_permille", "length_permille", "longest_run", "adjacent_repeat_permille", "repeated_bigram_permille", "smallest_period", "max_autocorrelation_permille", "max_autocorrelation_lag"],
    "goldenVectors": [
      {"input": "", "vector": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]},
      {"input": "aaaaaaaaaaaaaaaa", "vector": [16, 16, 0, 1, 16, 0, 0, 0, 16, 0, 0, 0, 0, 0, 1, 0, 26, 0, 0, 62, 62, 16, 1000, 933, 1, 1000, 2]},
      {"input": "abcabcabcabcabcabc", "vector": [18, 18, 0, 3, 6, 103872, 103872, 1869696, 18, 0, 0, 0, 0, 0, 1, 0, 26, 1000, 337, 166, 70, 1, 0, 823, 3, 1000, 3]},
      {"input": "XXXX-XXXX-XXXX-XXXX", "vector": [19, 19, 0, 2, 16, 41239, 16248, 783541, 0, 16, 0, 3, 0, 0, 2, 6, 58, 629, 107, 105, 74, 4, 666, 833, 5, 1000, 5]},
      {"input": "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa", "vector": [32, 32, 0, 32, 1, 327680, 327680, 10485760, 12, 12, 8, 0, 0, 0, 3, 31, 62, 1000, 839, 1000, 125, 1, 0, 0, 0, 0, 0]},
      {"input": "\ud83d\ude00a\ud83d\ude03b\ud83d\ude00a\ud83d\ude03b", "vector": [20, 8, 0, 4, 2, 131072, 131072, 1048576, 4, 0, 0, 0, 0, 4, 2, 7, 28, 1000, 416, 500, 31, 1, 0, 428, 4, 1000, 4]},
      {"input": "ab", "vector": [2, 2, 0, 2, 1, 65536, 65536, 131072, 2, 0, 0, 0, 0, 0, 1, 0, 26, 1000, 212, 1000, 7, 1, 0, 0, 0, 0, 0]},
      {"input": "aabc", "vector": [4, 4, 0, 3, 2, 98304, 65536, 393216, 4, 0, 0, 0, 0, 0, 1, 0, 26, 946, 319, 750, 15, 2, 333, 0, 0, 0, 0]}
    ]
  },
  "aggregation": {
    "id": "evidence-aggregation/v2",
    "featureSchema": "evidence-features/v1",
    "maxGroupSignals": 4,
    "groups": [
      {"group": "randomness", "direction": "positive", "rule": "halving-diminishing-returns", "cap": 30, "signals": [{"kind": "feature-ramp", "signal": "shannon_entropy_q16", "feature": 5, "lo": 226998, "hi": 265935, "max": 30}]},
      {"group": "lexical", "direction": "positive", "rule": "halving-diminishing-returns", "cap": 0, "signals": []},
      {"group": "contextual", "direction": "positive", "rule": "halving-diminishing-returns", "cap": 50, "signals": [{"kind": "context", "signal": "credential-context", "classes": ["credential-name", "authorization-header", "url-userinfo"], "points": 50}]},
      {"group": "validation", "direction": "positive", "rule": "halving-diminishing-returns", "cap": 50, "signals": []},
      {"group": "negative", "direction": "negative", "rule": "halving-diminishing-returns", "cap": 130, "signals": [{"kind": "strict-exclusion", "signal": "strict-exclusion", "points": 130}]}
    ],
    "bands": {"low": 35, "medium": 40, "high": 51},
    "contextClasses": ["url-userinfo", "authorization-header", "credential-name", "other-name", "bare"],
    "credentialNameSignals": ["high-signal-name", "ambiguous-name"],
    "exclusionGrammars": ["template-reference", "environment-reference", "command-substitution", "angle-placeholder", "mask", "placeholder-vocabulary"],
    "placeholderWords": ["a", "access", "an", "api", "auth", "change", "changeme", "client", "dummy", "example", "fake", "goes", "here", "id", "insert", "key", "me", "my", "nil", "none", "null", "password", "placeholder", "redacted", "replace", "replaceme", "sample", "secret", "tbd", "the", "todo", "token", "undefined", "value", "your"],
    "placeholderMarkers": ["changeme", "dummy", "example", "fake", "here", "insert", "nil", "none", "null", "placeholder", "redacted", "replace", "replaceme", "sample", "tbd", "todo", "undefined", "your"],
    "maskSymbols": ["*", "x", "X", "\u2022", "#", ".", "-", "0"],
    "minMaskLength": 3
  }
}"##;

/// A JSON string literal: ASCII only, non-ASCII escaped as UTF-16 `\u`
/// units, as Python's `json.dumps(ensure_ascii=True)` writes it.
fn string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0_u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

fn strings<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    let items: Vec<String> = values.into_iter().map(string).collect();
    format!("[{}]", items.join(", "))
}

fn numbers(values: impl IntoIterator<Item = u32>) -> String {
    let items: Vec<String> = values.into_iter().map(|v| v.to_string()).collect();
    format!("[{}]", items.join(", "))
}

fn signal(rule: SignalRule) -> String {
    match rule {
        SignalRule::FeatureRamp {
            feature,
            lo,
            hi,
            max,
        } => format!(
            "{{\"kind\": \"feature-ramp\", \"signal\": {}, \"feature\": {feature}, \"lo\": {lo}, \"hi\": {hi}, \"max\": {max}}}",
            string(rule.id())
        ),
        SignalRule::Context { classes, points } => format!(
            "{{\"kind\": \"context\", \"signal\": {}, \"classes\": {}, \"points\": {points}}}",
            string(rule.id()),
            strings(classes.iter().map(|class| class.as_str()))
        ),
        SignalRule::StrictExclusion { points } => format!(
            "{{\"kind\": \"strict-exclusion\", \"signal\": {}, \"points\": {points}}}",
            string(rule.id())
        ),
    }
}

/// The compiled scorer as canonical, indented JSON.
fn render_compiled_model() -> String {
    let model = SHADOW_MODEL;
    let mut out = String::from("{\n  \"featureSchema\": {\n");
    let _ = writeln!(out, "    \"id\": {},", string(FEATURE_SCHEMA_VERSION));
    let _ = writeln!(out, "    \"maxAnalysedChars\": {MAX_ANALYSED_CHARS},");
    let _ = writeln!(
        out,
        "    \"maxAutocorrelationLag\": {MAX_AUTOCORRELATION_LAG},"
    );
    let _ = writeln!(out, "    \"fixedPointFractionBits\": {Q16_FRACTION_BITS},");
    let _ = writeln!(out, "    \"features\": {},", strings(FEATURE_NAMES));
    out.push_str("    \"goldenVectors\": [\n");
    let golden: Vec<String> = GOLDEN_INPUTS
        .iter()
        .map(|input| {
            let vector = extract_features(input).to_vector().map(|(_, value)| value);
            format!(
                "      {{\"input\": {}, \"vector\": {}}}",
                string(input),
                numbers(vector)
            )
        })
        .collect();
    out.push_str(&golden.join(",\n"));
    out.push_str("\n    ]\n  },\n  \"aggregation\": {\n");
    let _ = writeln!(out, "    \"id\": {},", string(model.id));
    let _ = writeln!(
        out,
        "    \"featureSchema\": {},",
        string(model.feature_schema)
    );
    let _ = writeln!(out, "    \"maxGroupSignals\": {MAX_GROUP_SIGNALS},");
    out.push_str("    \"groups\": [\n");
    let groups: Vec<String> = model
        .groups
        .iter()
        .map(|config| {
            let rule = match config.rule {
                GroupRule::HalvingDiminishingReturns => "halving-diminishing-returns",
            };
            let direction = if config.group.is_negative() {
                "negative"
            } else {
                "positive"
            };
            let signals: Vec<String> = config.signals.iter().map(|s| signal(*s)).collect();
            format!(
                "      {{\"group\": {}, \"direction\": {}, \"rule\": {}, \"cap\": {}, \"signals\": [{}]}}",
                string(config.group.as_str()),
                string(direction),
                string(rule),
                config.cap,
                signals.join(", ")
            )
        })
        .collect();
    out.push_str(&groups.join(",\n"));
    out.push_str("\n    ],\n");
    let bands = model.bands;
    let _ = writeln!(
        out,
        "    \"bands\": {{\"low\": {}, \"medium\": {}, \"high\": {}}},",
        bands.low, bands.medium, bands.high
    );
    let _ = writeln!(
        out,
        "    \"contextClasses\": {},",
        strings(CONTEXT_CLASSES.iter().map(|class| class.as_str()))
    );
    let _ = writeln!(
        out,
        "    \"credentialNameSignals\": {},",
        strings(CREDENTIAL_NAME_SIGNALS)
    );
    let _ = writeln!(
        out,
        "    \"exclusionGrammars\": {},",
        strings(GRAMMARS.iter().map(|grammar| grammar.as_str()))
    );
    let _ = writeln!(
        out,
        "    \"placeholderWords\": {},",
        strings(PLACEHOLDER_WORDS)
    );
    let _ = writeln!(
        out,
        "    \"placeholderMarkers\": {},",
        strings(PLACEHOLDER_MARKERS)
    );
    let masks: Vec<String> = MASK_SYMBOLS.iter().map(char::to_string).collect();
    let _ = writeln!(
        out,
        "    \"maskSymbols\": {},",
        strings(masks.iter().map(String::as_str))
    );
    let _ = writeln!(out, "    \"minMaskLength\": {MIN_MASK_LEN}");
    out.push_str("  }\n}");
    out
}

#[test]
fn every_grammar_and_context_class_is_listed_once() {
    for (index, grammar) in GRAMMARS.iter().enumerate() {
        assert_eq!(listed(*grammar, ContextClass::Bare).0, index);
    }
    for (index, class) in CONTEXT_CLASSES.iter().enumerate() {
        assert_eq!(listed(ExclusionGrammar::TemplateReference, *class).1, index);
    }
}

#[test]
fn the_compiled_scorer_matches_the_reviewed_scoring_artifact() {
    // On failure: a scorer constant, feature formula or vocabulary word
    // changed. That is a new model identity (and, for feature semantics, a
    // new feature schema identity). Bump the identity in the source, then
    // record the new rendering here and in the artifact together with a new
    // artifact revision; `npm run scoring-artifact:check` explains the rest.
    assert_eq!(
        render_compiled_model(),
        REVIEWED_MODEL_JSON,
        "the compiled shadow scorer drifted from docs/contracts/scoring/shadow-scoring-artifact.json"
    );
}
