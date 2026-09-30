//! Issue #1016: a Kubernetes container `env` entry puts the variable name and
//! its value on two lines (`- name: <NAME>` / `value: "<v>"`). The pair is
//! read as the one-line assignment `<NAME>=<v>`: a provider name gives the
//! provider's typed finding, any other credential name gives
//! `generic-token` at its usual floors, and everything the one-line form
//! excludes stays excluded. Every value is built at run time from
//! low-entropy filler and was never issued by a provider.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, DefaultPolicy, DetectorRegistry, Finding, scan};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

fn deepgram_value() -> String {
    "a1b2c3d4e5f6g7h8i9j0".repeat(2)
}

fn mixed_value() -> String {
    "aB3dE5gH7j".repeat(4)
}

fn uuid_value() -> String {
    format!(
        "{}-{}-4{}-8{}-{}",
        "0123abcd", "4567", "cde", "f01", "23456789abcd"
    )
}

fn findings(input: &str) -> Vec<Finding> {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan(input, &registry, &DefaultPolicy).unwrap()
}

fn env_entry(name: &str, value: &str) -> String {
    format!("env:\n  - name: {name}\n    value: \"{value}\"\n")
}

/// (name, value, expected type) for every positive row of the issue.
fn positive_rows() -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("DEEPGRAM_API_KEY", deepgram_value(), "deepgram_api_key"),
        ("CO_API_KEY", mixed_value(), "cohere_api_key"),
        ("API_TOKEN", mixed_value(), "contextual_secret"),
        ("HEROKU_API_KEY", uuid_value(), "contextual_secret"),
    ]
}

fn assert_one_redacted(input: &str, value: &str, type_name: &str) {
    let found = findings(input);
    assert_eq!(found.len(), 1, "{input:?}: {found:?}");
    let start = input.find(value).unwrap();
    assert_eq!(found[0].range().start(), start, "{input:?}");
    assert_eq!(found[0].range().end(), start + value.len(), "{input:?}");
    assert_eq!(found[0].type_name(), type_name, "{input:?}");
    assert_eq!(found[0].action(), Action::Redact, "{input:?}");
}

#[test]
fn a_credential_named_env_entry_is_redacted_with_the_exact_span() {
    for (name, value, type_name) in positive_rows() {
        let input = env_entry(name, &value);
        assert_one_redacted(&input, &value, type_name);
    }
    // The issue's spans, byte for byte.
    let deepgram = env_entry("DEEPGRAM_API_KEY", &deepgram_value());
    assert_eq!(findings(&deepgram)[0].range().start(), 44);
    assert_eq!(findings(&deepgram)[0].range().end(), 84);
    let cohere = env_entry("CO_API_KEY", &mixed_value());
    assert_eq!(findings(&cohere)[0].range().start(), 38);
    let token = env_entry("API_TOKEN", &mixed_value());
    assert_eq!(findings(&token)[0].range().start(), 37);
    let heroku = env_entry("HEROKU_API_KEY", &uuid_value());
    assert_eq!(findings(&heroku)[0].range().start(), 42);
    assert_eq!(findings(&heroku)[0].range().end(), 78);
}

#[test]
fn the_pair_is_read_in_either_order_quoted_names_and_crlf_included() {
    let value = mixed_value();
    for input in [
        format!("env:\n  - value: \"{value}\"\n    name: API_TOKEN\n"),
        format!("env:\n  - name: \"API_TOKEN\"\n    value: {value}\n"),
        format!("env:\r\n  - name: API_TOKEN\r\n    value: '{value}'\r\n"),
        format!("env:\n- name: API_TOKEN  # the CI token\n  value: \"{value}\"\n"),
        format!("containers:\n  - env:\n      - name: CO_API_KEY\n        value: \"{value}\"\n"),
    ] {
        assert_eq!(findings(&input).len(), 1, "{input:?}");
        assert_eq!(findings(&input)[0].action(), Action::Redact, "{input:?}");
    }
}

#[test]
fn references_placeholders_and_empty_values_stay_silent() {
    for name in ["DEEPGRAM_API_KEY", "CO_API_KEY", "API_TOKEN"] {
        for input in [
            format!(
                "env:\n  - name: {name}\n    valueFrom:\n      secretKeyRef:\n        name: app\n        key: token\n"
            ),
            env_entry(name, "<your-key>"),
            env_entry(name, "YOUR_API_KEY"),
            env_entry(name, "${API_TOKEN}"),
            env_entry(name, ""),
            format!("env:\n  - name: {name}\n    value:\n"),
        ] {
            assert!(
                findings(&input).is_empty(),
                "{input:?}: {:?}",
                findings(&input)
            );
        }
    }
}

#[test]
fn non_secret_names_and_other_list_shapes_are_not_paired() {
    let value = mixed_value();
    for input in [
        // Non-secret names.
        env_entry("LOG_LEVEL", &value),
        env_entry("DEEPGRAM_PROJECT_ID", &deepgram_value()),
        env_entry("COHERE_BASE_URL", &value),
        // The value on a separate, non-adjacent or deeper item.
        format!("env:\n  - name: API_TOKEN\n  - value: \"{value}\"\n"),
        format!("env:\n  - name: API_TOKEN\n    image: app\n    value: \"{value}\"\n"),
        format!("env:\n  - name: API_TOKEN\n\n    value: \"{value}\"\n"),
        format!("env:\n  - name: API_TOKEN\n      value: \"{value}\"\n"),
        format!("- name: API_TOKEN\n- name: OTHER\n  other: 1\n  value: \"{value}\"\n"),
        // Other list shapes: flow mapping, JSON, and a plain mapping.
        format!("env:\n  - {{name: API_TOKEN, value: \"{value}\"}}\n"),
        format!("[{{\"name\": \"API_TOKEN\",\n  \"value\": \"{value}\"}}]\n"),
        format!("name: API_TOKEN\nvalue: \"{value}\"\n"),
        // `name:` holding something other than a name.
        format!("env:\n  - name: \"api token for ci\"\n    value: \"{value}\"\n"),
    ] {
        assert!(
            findings(&input).is_empty(),
            "{input:?}: {:?}",
            findings(&input)
        );
    }
}

#[test]
fn incremental_scanning_matches_the_whole_input_across_every_two_chunk_split() {
    let mut inputs: Vec<String> = positive_rows()
        .into_iter()
        .map(|(name, value, _)| env_entry(name, &value))
        .collect();
    inputs.push(format!(
        "env:\n  - value: \"{}\"\n    name: CO_API_KEY\n",
        mixed_value()
    ));
    inputs.push(format!(
        "env:\n  - name: API_TOKEN\n  - value: \"{}\"\n",
        mixed_value()
    ));
    for input in inputs {
        let (expected_text, expected_findings) = whole_input(&input);
        for pieces in utf8_byte_partitions(&input) {
            let session = run(&as_chunks(&pieces));
            assert_eq!(session.text(), expected_text, "{input:?}: {pieces:?}");
            assert_eq!(
                session.findings().len(),
                expected_findings.len(),
                "{input:?}: {pieces:?}"
            );
        }
        // The chunk boundary exactly between the `name:` and `value:` lines,
        // and one chunk per line.
        let lines: Vec<&str> = input.split_inclusive('\n').collect();
        let head = lines[..2].concat();
        let tail = lines[2..].concat();
        assert_eq!(run(&[&head, &tail]).text(), expected_text, "{input:?}");
        assert_eq!(run(&lines).text(), expected_text, "{input:?}");
    }
}
