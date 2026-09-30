//! Issue #1038: a keyed environment store, `os.environ["NAME"] = "<v>"` and
//! its siblings (`os.environ.setdefault("NAME", "<v>")`, `os.putenv(...)`,
//! `process.env["NAME"] = ...`, Ruby `ENV["NAME"] = ...`, any
//! `<target>["name"] = ...`), is read as the assignment `NAME = "<v>"`. A
//! provider name gives the provider's typed finding and any other credential
//! name gives `generic-token` at its usual floors. Reads, references,
//! placeholders, empty strings and non-credential names stay silent. Every
//! value is built at run time from low-entropy filler and was never issued
//! by a provider.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence, DefaultPolicy, DetectorRegistry, Finding, scan};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

fn mistral() -> String {
    "Q7wE3rT9yU".repeat(3) + "aB"
}

fn deepgram() -> String {
    "a1b2c3d4e5f6a7b8c9d0".repeat(2)
}

fn mixed() -> String {
    "aB3dE5gH7j".repeat(4)
}

fn findings(input: &str) -> Vec<Finding> {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan(input, &registry, &DefaultPolicy).unwrap()
}

/// (input, value, expected type) for every positive form.
fn positives() -> Vec<(String, String, &'static str)> {
    let (m, d, c) = (mistral(), deepgram(), mixed());
    vec![
        (
            format!("os.environ[\"MISTRAL_API_KEY\"] = \"{m}\""),
            m.clone(),
            "mistral_api_key",
        ),
        (
            format!("os.environ[\"DEEPGRAM_API_KEY\"] = \"{d}\""),
            d.clone(),
            "deepgram_api_key",
        ),
        (
            format!("os.environ[\"CO_API_KEY\"] = \"{c}\""),
            c.clone(),
            "cohere_api_key",
        ),
        (
            format!("os.environ[\"API_TOKEN\"] = \"{c}\""),
            c.clone(),
            "contextual_secret",
        ),
        (
            format!("settings[\"api_key\"] = \"{c}\""),
            c.clone(),
            "contextual_secret",
        ),
        (
            format!("ENV[\"MISTRAL_API_KEY\"] = \"{m}\""),
            m.clone(),
            "mistral_api_key",
        ),
        (
            format!("ENV[\"API_TOKEN\"] = \"{c}\""),
            c.clone(),
            "contextual_secret",
        ),
        (
            format!("os.environ['MISTRAL_API_KEY'] = '{m}'"),
            m.clone(),
            "mistral_api_key",
        ),
        (
            format!("os.environ['API_TOKEN'] = '{c}'"),
            c.clone(),
            "contextual_secret",
        ),
        (
            format!("os.environ.setdefault(\"MISTRAL_API_KEY\", \"{m}\")"),
            m.clone(),
            "mistral_api_key",
        ),
        (
            format!("os.environ.setdefault('API_TOKEN', '{c}')"),
            c.clone(),
            "contextual_secret",
        ),
        (
            format!("os.putenv(\"CO_API_KEY\", \"{c}\")"),
            c.clone(),
            "cohere_api_key",
        ),
        (
            format!("os.putenv(\"API_TOKEN\", \"{c}\")"),
            c.clone(),
            "contextual_secret",
        ),
        (
            format!("process.env.MISTRAL_API_KEY = \"{m}\""),
            m.clone(),
            "mistral_api_key",
        ),
        (
            format!("process.env[\"MISTRAL_API_KEY\"] = \"{m}\""),
            m.clone(),
            "mistral_api_key",
        ),
        (
            format!("process.env[\"API_TOKEN\"] = \"{c}\""),
            c.clone(),
            "contextual_secret",
        ),
    ]
}

#[test]
fn every_keyed_store_is_one_redacted_finding_with_the_exact_span() {
    for (input, value, type_name) in positives() {
        let found = findings(&input);
        assert_eq!(found.len(), 1, "{input}: {found:?}");
        let start = input.find(&value).unwrap();
        assert_eq!(found[0].range().start(), start, "{input}");
        assert_eq!(found[0].range().end(), start + value.len(), "{input}");
        assert_eq!(found[0].type_name(), type_name, "{input}");
        assert_eq!(found[0].confidence(), Confidence::High, "{input}");
        assert_eq!(found[0].action(), Action::Redact, "{input}");
    }
    // The issue's spans.
    let spans = [(0, 33), (1, 34), (2, 28), (3, 27), (4, 23), (5, 26)];
    let rows = positives();
    for (row, start) in spans {
        assert_eq!(
            findings(&rows[row].0)[0].range().start(),
            start,
            "{}",
            rows[row].0
        );
    }
}

#[test]
fn reads_references_placeholders_and_non_credential_names_stay_silent() {
    let c = mixed();
    for input in [
        "key = os.environ[\"MISTRAL_API_KEY\"]".to_owned(),
        "os.environ[\"MISTRAL_API_KEY\"] = os.environ[\"OTHER\"]".to_owned(),
        "os.environ[\"MISTRAL_API_KEY\"] = config.key".to_owned(),
        "os.environ[\"MISTRAL_API_KEY\"] = get_secret(\"mistral\")".to_owned(),
        "os.environ[\"MISTRAL_API_KEY\"] = \"your-api-key\"".to_owned(),
        "os.environ['API_TOKEN'] = '<your-token>'".to_owned(),
        "os.environ[\"MISTRAL_API_KEY\"] = \"\"".to_owned(),
        "os.environ.setdefault(\"API_TOKEN\", \"${API_TOKEN}\")".to_owned(),
        "if os.environ[\"API_TOKEN\"] == \"expected\": pass".to_owned(),
        format!("if os.environ[\"API_TOKEN\"] == \"{c}\": pass"),
        format!("os.environ[\"LOG_LEVEL\"] = \"{c}\""),
        format!("os.environ[\"MISTRAL_PROJECT_ID\"] = \"{c}\""),
        format!("os.environ.setdefault(\"LOG_LEVEL\", \"{c}\")"),
        format!("os.environ.get(\"API_TOKEN\", \"{c}\")"),
        format!("os.putenv(\"API_TOKEN\", {c})"),
        format!("items[0] = \"{c}\""),
        format!("[\"API_TOKEN\"] = \"{c}\""),
    ] {
        assert!(
            findings(&input).is_empty(),
            "{input}: {:?}",
            findings(&input)
        );
    }
}

#[test]
fn the_mistral_kubernetes_env_entry_of_1016_is_covered() {
    let m = mistral();
    let input = format!("env:\n  - name: MISTRAL_API_KEY\n    value: \"{m}\"\n");
    let found = findings(&input);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].type_name(), "mistral_api_key");
    assert_eq!(found[0].range().start(), 43);
    assert_eq!(found[0].action(), Action::Redact);
}

#[test]
fn incremental_scanning_matches_the_whole_input_across_every_two_chunk_split() {
    for (line, _, _) in positives() {
        for input in [line.clone(), format!("import os\n{line}\nprint('ok')\n")] {
            let (expected_text, expected_findings) = whole_input(&input);
            for pieces in utf8_byte_partitions(&input) {
                let session = run(&as_chunks(&pieces));
                assert_eq!(session.text(), expected_text, "{input}: {pieces:?}");
                assert_eq!(
                    session.findings().len(),
                    expected_findings.len(),
                    "{input}: {pieces:?}"
                );
            }
        }
    }
}
