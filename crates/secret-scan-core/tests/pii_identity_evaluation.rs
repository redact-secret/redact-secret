//! Source equivalence of the maintainer-local PII identity evaluation
//! (issue #910) over the family conformance fixtures.
//!
//! Runs the `pii_identity_evaluation` example binary that `cargo test` builds
//! next to this test, feeds it every conformance case of every production
//! family with every candidate range on a character boundary (and a null
//! candidate), and requires, for every line, `sensitivity == "sensitive"`
//! exactly when the public Rust surface reports exactly one finding of that
//! family at exactly that range. It also pins the exact header and line key
//! sets and that no output line repeats an input.
//!
//! The binary is located beside this test's own executable
//! (`target/<profile>/examples/`), where `cargo test -p redact-secret`
//! builds every example before running any test. Running this test file on
//! its own (`--test pii_identity_evaluation`) does not build examples; build
//! it first with `cargo build -p redact-secret --example pii_identity_evaluation`.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use redact_secret::{DefaultPolicy, DetectorRegistry, PiiSelection, scan};
use serde_json::{Value, json};

const FIXTURES: [(&str, &str); 6] = [
    (
        "pii:global:email",
        include_str!("../../../conformance/fixtures/pii-email-v1.json"),
    ),
    (
        "pii:global:iban",
        include_str!("../../../conformance/fixtures/pii-iban-v1.json"),
    ),
    (
        "pii:global:network-address",
        include_str!("../../../conformance/fixtures/pii-network-address-v1.json"),
    ),
    (
        "pii:global:payment-card",
        include_str!("../../../conformance/fixtures/pii-payment-card-v1.json"),
    ),
    (
        "pii:global:phone",
        include_str!("../../../conformance/fixtures/pii-phone-v1.json"),
    ),
    (
        "pii:us:ssn",
        include_str!("../../../conformance/fixtures/pii-us-ssn-v1.json"),
    ),
];

fn example_binary() -> PathBuf {
    let current = std::env::current_exe().unwrap();
    let profile_dir = current.parent().unwrap().parent().unwrap();
    let binary = profile_dir.join("examples").join(format!(
        "pii_identity_evaluation{}",
        std::env::consts::EXE_SUFFIX
    ));
    assert!(
        binary.is_file(),
        "{} is missing; `cargo test -p redact-secret` builds it, or run \
         `cargo build -p redact-secret --example pii_identity_evaluation` first",
        binary.display()
    );
    binary
}

struct Run {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], input: &str) -> Run {
    let mut child = Command::new(example_binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_owned();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    Run {
        status: output.status,
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn public_type(family: &str) -> String {
    match family.split(':').collect::<Vec<_>>().as_slice() {
        ["pii", "global", slug] => format!("pii_global_{}", slug.replace('-', "_")),
        ["pii", cc, slug] => format!("pii_jurisdiction_{cc}_{}", slug.replace('-', "_")),
        _ => panic!("{family}"),
    }
}

fn selector(family: &str) -> String {
    format!("pii:family:{}", family.strip_prefix("pii:").unwrap())
}

fn keys(value: &Value) -> Vec<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn check_header(line: &str, family: &str) {
    let header: Value = serde_json::from_str(line).unwrap();
    assert_eq!(
        keys(&header),
        ["activationIdentity", "family", "format", "vocabulary"]
    );
    let selection = PiiSelection::parse(&[selector(family).as_str()]).unwrap();
    let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
    assert_eq!(
        header,
        json!({
            "format": "redact-secret/pii-identity-evaluation/1",
            "family": family,
            "vocabulary": "pii-context/v2",
            "activationIdentity": registry.activation_identity(),
        })
    );
}

#[test]
fn sensitive_iff_exactly_one_public_finding_over_every_fixture_range() {
    for (family, corpus) in FIXTURES {
        let document: Value = serde_json::from_str(corpus).unwrap();
        assert_eq!(document["family"], family);
        let selection = PiiSelection::parse(&[document["selector"].as_str().unwrap()]).unwrap();
        let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
        let finding_type = public_type(family);

        // (case index, candidate) per input line, and the lines themselves.
        let cases = document["cases"].as_array().unwrap();
        let mut expected = Vec::new();
        let mut stdin = String::new();
        for (index, case) in cases.iter().enumerate() {
            let text = case["input"].as_str().unwrap();
            let boundaries: Vec<usize> = text
                .char_indices()
                .map(|(offset, _)| offset)
                .chain(std::iter::once(text.len()))
                .collect();
            let mut candidates = vec![None];
            for (position, start) in boundaries.iter().enumerate() {
                for end in &boundaries[position + 1..] {
                    candidates.push(Some((*start, *end)));
                }
            }
            for candidate in candidates {
                let id = format!("{}#{}", case["id"].as_str().unwrap(), expected.len());
                let line = json!({
                    "id": id,
                    "family": family,
                    "text": text,
                    "candidate": candidate.map(|(start, end)| json!({"start": start, "end": end})),
                });
                stdin.push_str(&line.to_string());
                stdin.push('\n');
                expected.push((id, index, candidate));
            }
        }

        let output = run(&["--family", family], &stdin);
        assert!(output.status.success(), "{family}: {}", output.stderr);
        let mut lines = output.stdout.lines();
        check_header(lines.next().unwrap(), family);
        let lines: Vec<&str> = lines.collect();
        assert_eq!(lines.len(), expected.len(), "{family}");

        let findings: Vec<Vec<(usize, usize)>> = cases
            .iter()
            .map(|case| {
                scan(case["input"].as_str().unwrap(), &registry, &DefaultPolicy)
                    .unwrap()
                    .iter()
                    .filter(|finding| finding.type_name() == finding_type)
                    .map(|finding| (finding.range().start(), finding.range().end()))
                    .collect()
            })
            .collect();

        let mut sensitive_lines = 0;
        for (line, (id, index, candidate)) in lines.iter().zip(&expected) {
            let text = cases[*index]["input"].as_str().unwrap();
            assert!(!line.contains(text), "{family} {id}: output repeats input");
            let record: Value = serde_json::from_str(line).unwrap();
            assert_eq!(
                keys(&record),
                ["family", "id", "identity", "sensitivity"],
                "{family} {id}"
            );
            assert_eq!(record["id"], id.as_str());
            assert_eq!(record["family"], family);
            let identity = record["identity"].as_str().unwrap();
            let sensitivity = record["sensitivity"].as_str().unwrap();
            assert!(
                matches!(
                    (identity, sensitivity),
                    ("unmatched", "not-established")
                        | (
                            "established",
                            "sensitive" | "non-sensitive" | "not-established"
                        )
                ),
                "{family} {id}: {identity}/{sensitivity}"
            );
            let public = candidate.map_or(0, |range| {
                findings[*index]
                    .iter()
                    .filter(|found| **found == range)
                    .count()
            });
            assert_eq!(
                sensitivity == "sensitive",
                public == 1,
                "{family} {id}: seam {identity}/{sensitivity}, {public} public finding(s)"
            );
            if sensitivity == "sensitive" {
                sensitive_lines += 1;
            }
        }
        // Every public finding of this family was reached by some range.
        let public_total: usize = findings.iter().map(Vec::len).sum();
        assert_eq!(sensitive_lines, public_total, "{family}");
        assert!(public_total > 0, "{family}: fixtures carry no positive");
    }
}

#[test]
fn malformed_input_fails_closed_without_echoing_content() {
    let marker = "fixture910-marker@x4z8v2n6.synthetic";
    for (args, input) in [
        (vec![], String::new()),
        (vec!["--family", "pii:global"], String::new()),
        (vec!["--family", "pii:global:us-ssn"], String::new()),
        (
            vec!["--family", "pii:global:email"],
            format!(
                "{{\"id\":\"x\",\"family\":\"pii:global:iban\",\"text\":\"{marker}\",\"candidate\":null}}\n"
            ),
        ),
        (
            vec!["--family", "pii:global:email"],
            format!("{{\"id\":\"x\",\"family\":\"pii:global:email\",\"text\":\"{marker}\"}}\n"),
        ),
        (
            vec!["--family", "pii:global:email"],
            format!(
                "{{\"id\":\"x\",\"family\":\"pii:global:email\",\"text\":\"{marker}\",\"candidate\":null,\"extra\":1}}\n"
            ),
        ),
        (
            vec!["--family", "pii:global:email"],
            format!(
                "{{\"id\":\"x\",\"family\":\"pii:global:email\",\"text\":\"{marker}\",\"candidate\":{{\"start\":-1,\"end\":3}}}}\n"
            ),
        ),
        (
            vec!["--family", "pii:global:email"],
            format!(
                "{{\"id\":\"x\",\"family\":\"pii:global:email\",\"text\":\"{marker}\",\"candidate\":[0,3]}}\n"
            ),
        ),
        (vec!["--family", "pii:global:email"], format!("{marker}\n")),
    ] {
        let output = run(&args, &input);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(!output.stderr.contains(marker), "{args:?}");
        assert!(!output.stdout.contains(marker), "{args:?}");
        assert!(output.stdout.lines().count() <= 1, "{args:?}");
    }
}

#[test]
fn empty_input_writes_only_the_header() {
    let output = run(&["--family", "pii:us:ssn"], "\n\n");
    assert!(output.status.success(), "{}", output.stderr);
    let lines: Vec<&str> = output.stdout.lines().collect();
    assert_eq!(lines.len(), 1);
    check_header(lines[0], "pii:us:ssn");
}
