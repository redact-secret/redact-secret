//! Batching closed lines is invisible over the canonical corpora (issue #985).
//!
//! An incremental session detects every line that closes in one `append`
//! call together. Fed one line per `append`, it processes each unit alone,
//! exactly as before batching. So for every input and chunking, the session
//! must release the same text, findings and error as the same input fed a
//! line at a time. `src/incremental/batch_tests.rs` covers what needs crate
//! internals: callback order, custom registries, overlap ties and the
//! retention peak.
//!
//! Every fixture input is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{
    Finding, IncrementalLimits, IncrementalSanitizer, PiiSelection, SecretScanError,
    SecretScanErrorCode,
};
use support::{incremental_corpus, synchronous_corpus};

type Outcome = Result<(String, Vec<Finding>), SecretScanErrorCode>;

fn drive(mut sanitizer: IncrementalSanitizer, chunks: &[&str]) -> Outcome {
    let mut text = String::new();
    let mut findings = Vec::new();
    for chunk in chunks {
        let result = sanitizer.append(chunk).map_err(SecretScanError::code)?;
        text.push_str(result.text());
        findings.extend_from_slice(result.findings());
    }
    let result = sanitizer.finalize().map_err(SecretScanError::code)?;
    text.push_str(result.text());
    findings.extend_from_slice(result.findings());
    Ok((text, findings))
}

/// `input` split right after every `\n` and `\r`, so no `append` closes more
/// than one line.
fn one_line_per_chunk(input: &str) -> Vec<&str> {
    input.split_inclusive(['\n', '\r']).collect::<Vec<_>>()
}

/// `input` in chunks of at least `bytes` bytes, split on char boundaries.
fn chunked(input: &str, bytes: usize) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let mut end = (cursor + bytes).min(input.len());
        while !input.is_char_boundary(end) {
            end += 1;
        }
        chunks.push(&input[cursor..end]);
        cursor = end;
    }
    chunks
}

/// The CLI's construct limits, so no fixture fails on a limit.
fn limits() -> IncrementalLimits {
    let construct = 1 << 20;
    IncrementalLimits::new(
        1 << 26,
        IncrementalLimits::minimum_buffered_bytes(construct, construct),
        construct,
        construct,
    )
    .unwrap()
}

fn full() -> IncrementalSanitizer {
    IncrementalSanitizer::new(limits()).unwrap()
}

fn common() -> IncrementalSanitizer {
    IncrementalSanitizer::with_common_built_in(limits()).unwrap()
}

fn full_with_pii() -> IncrementalSanitizer {
    let selection = PiiSelection::parse(&["pii:global"]).unwrap();
    IncrementalSanitizer::with_built_in_and_pii(limits(), &selection).unwrap()
}

fn assert_batching_is_invisible(
    session: fn() -> IncrementalSanitizer,
    label: &str,
    input: &str,
    chunk_sizes: &[usize],
) {
    let expected = drive(session(), &one_line_per_chunk(input));
    for &size in chunk_sizes {
        let actual = drive(session(), &chunked(input, size));
        assert_eq!(actual, expected, "{label}, {size}-byte chunks");
    }
}

/// `inputs` joined into one document, one after another on their own lines,
/// under each line-ending convention.
fn documents(inputs: &[String]) -> Vec<(&'static str, String)> {
    let joined = inputs.join("\n");
    vec![
        ("LF", joined.clone()),
        ("CRLF", joined.replace('\n', "\r\n")),
        ("CR", joined.replace('\n', "\r")),
    ]
}

/// Every `input` string anywhere in the PII conformance fixtures.
fn pii_corpus() -> Vec<String> {
    fn collect(value: &serde_json::Value, into: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    match value {
                        serde_json::Value::String(input) if key == "input" => {
                            into.push(input.clone());
                        }
                        _ => collect(value, into),
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    collect(value, into);
                }
            }
            _ => {}
        }
    }
    let mut inputs = Vec::new();
    for source in [
        include_str!("../../../conformance/fixtures/pii-cross-family-v1.json"),
        include_str!("../../../conformance/fixtures/pii-email-v1.json"),
        include_str!("../../../conformance/fixtures/pii-iban-v1.json"),
        include_str!("../../../conformance/fixtures/pii-network-address-v1.json"),
        include_str!("../../../conformance/fixtures/pii-payment-card-v1.json"),
        include_str!("../../../conformance/fixtures/pii-phone-v1.json"),
        include_str!("../../../conformance/fixtures/pii-us-ssn-v1.json"),
    ] {
        collect(&serde_json::from_str(source).unwrap(), &mut inputs);
    }
    inputs
}

/// The layouts the per-detector audit found a detector reads across a unit
/// boundary ([`docs/audits/evidence/985/README.md`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/985/README.md)). Scanned together with the
/// unit before them they would differ from per-unit processing; the session
/// starts a new batch at each of them instead.
fn cross_unit_layouts() -> Vec<String> {
    let value = "SYNTHETICq8vN3xR7tLm2Kp9Wd";
    let hex32 = "0123456789abcdef".repeat(2);
    let hex40 = format!("{hex32}01234567");
    // Token-shaped values are assembled at run time, so no literal in this
    // file reads as a credential to a scanner.
    let uuid = ["01234567", "89ab", "cdef", "0123", "456789abcdef"].join("-");
    let okta = format!("00SYNTHETIC{}abcdef", "0".repeat(25));
    let base64 = "SyNtHeTiC0".repeat(6) + "Zq9x";
    vec![
        // generic-token: a name on one line, its operator on the next.
        format!("`password\n= {value}\n"),
        format!("x\"password\"\n: \"{value}\"\n"),
        format!("{{\"kty\":\"oct\",\"k\"\n: \"{value}\"}}\n"),
        format!("api_key\n\n  = {value}\n"),
        format!("{{\"kty\":\"oct\",\r\"k\":\"{value}\"}}\n"),
        // bearer-token: a header continued on the next line.
        "X-Authorization:\nBearer Zq9SyntheticRevokedTok\n".to_owned(),
        "Proxy-Authorization:\nBearer Zq9SynthRev0k\n".to_owned(),
        "Authorization\n: Bearer Zq9SyntheticRevokedTok\n".to_owned(),
        "x-authorization:\n\n  bearer Zq9SyntheticRevokedTok\n".to_owned(),
        // Keyword-gated detectors that split lines at `\n` only.
        "mistral\rapi_key = SYNTHETIC0000000000000000000Zq9x\r".to_owned(),
        format!("datadog\r{hex32}\r"),
        format!("{hex32}\rDD_API_KEY\r"),
        format!("mailchimp\rhttps://x/{hex32}-us1\r"),
        "mailgun\rkey-synthetic0000000000000000000009z\r".to_owned(),
        format!("newrelic\r{hex40}\r"),
        format!("okta\rvalue {okta}\n"),
        format!("value {okta}\rokta\n"),
        "# travis\rvalue SYNTH0000000000000000x\n".to_owned(),
        format!(
            "# pinecone\rapi_key=0000abcd-0000-4000-8000-{}\n",
            "0".repeat(12)
        ),
        format!("heroku\r{uuid}\r"),
        format!("twilio\r{}\r", "fedcba9876543210".repeat(2)),
        format!("confluent\r{base64}\r"),
        // PII phone: a word extension marker judged by the next line.
        "phone: 212-456-7890 ext\nhello\n".to_owned(),
        "phone: 212-456-7890 EXT.\r\n\r\nhello\n".to_owned(),
        "call 212-456-7890 extension  \n\n42\n".to_owned(),
    ]
}

#[test]
fn batching_is_invisible_across_every_layout_the_audit_found_reading_across_units() {
    for layout in cross_unit_layouts() {
        for input in [
            layout.clone(),
            format!("plain line\n{layout}plain line\n"),
            format!("{layout}{layout}"),
        ] {
            assert_batching_is_invisible(full, &input, &input, &[usize::MAX, 5]);
            assert_batching_is_invisible(full_with_pii, &input, &input, &[usize::MAX]);
        }
    }
}

fn is_adversarial(tier: &str, kind: &str) -> bool {
    tier == "adversarial" || kind == "adversarial"
}

#[test]
fn batching_is_invisible_over_the_incremental_corpus() {
    let inputs: Vec<String> = incremental_corpus()
        .into_iter()
        .map(|fixture| fixture.input)
        .collect();
    for input in &inputs {
        assert_batching_is_invisible(full, input, input, &[usize::MAX, 64, 7]);
    }
    for (endings, document) in documents(&inputs) {
        for session in [full, common, full_with_pii] {
            assert_batching_is_invisible(session, endings, &document, &[1 << 16, 4_096, 333]);
        }
    }
}

#[test]
fn batching_is_invisible_over_the_synchronous_corpus() {
    let inputs: Vec<String> = synchronous_corpus()
        .into_iter()
        .filter(|fixture| !is_adversarial(&fixture.tier, &fixture.kind))
        .map(|fixture| fixture.input)
        .collect();
    assert!(inputs.len() > 2_000, "the synchronous corpus shrank");
    for input in &inputs {
        assert_batching_is_invisible(full, input, input, &[usize::MAX]);
    }
    for (endings, document) in documents(&inputs) {
        assert_batching_is_invisible(full, endings, &document, &[1 << 16, 4_096]);
        assert_batching_is_invisible(full_with_pii, endings, &document, &[1 << 16]);
    }
}

#[test]
fn batching_is_invisible_over_the_adversarial_corpus() {
    let inputs: Vec<String> = synchronous_corpus()
        .into_iter()
        .filter(|fixture| is_adversarial(&fixture.tier, &fixture.kind))
        .map(|fixture| fixture.input)
        .collect();
    assert!(inputs.len() >= 26, "the adversarial corpus shrank");
    for input in &inputs {
        assert!(
            drive(full(), &[input]).is_ok(),
            "no fixture fails on a limit"
        );
        assert_batching_is_invisible(full, "adversarial", input, &[1 << 16]);
    }
}

#[test]
fn batching_is_invisible_over_the_pii_corpus_with_pii_active() {
    let inputs = pii_corpus();
    assert!(inputs.len() > 250, "the PII corpus shrank");
    for input in &inputs {
        assert_batching_is_invisible(full_with_pii, input, input, &[usize::MAX]);
    }
    for (endings, document) in documents(&inputs) {
        assert_batching_is_invisible(full_with_pii, endings, &document, &[1 << 16, 1_000]);
    }
}
