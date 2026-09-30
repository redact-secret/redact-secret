//! Issue #866: `generic-token` reads a quoted literal bound to a
//! secret-named keyword argument of a single-line call, and the sole quoted
//! argument of a call whose own name is a high-signal credential name.
//!
//! Driven through the public default pipeline. Every value is locally
//! constructed at test time from parts, is provider-free, and was never
//! issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{ByteRange, DefaultPolicy, DetectorRegistry, scan};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// 22 mixed-case alphanumerics with digits: clears the high-confidence
/// length (16) and entropy (3.0) floors, matches no provider shape.
fn value() -> String {
    ["Sy7nth", "Arg9Kq", "2Lm4Xv", "8Zt3"].concat()
}

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

fn findings_of(input: &str) -> Vec<(String, ByteRange)> {
    scan(input, &registry(), &DefaultPolicy)
        .unwrap()
        .into_iter()
        .map(|finding| (finding.detector().to_owned(), finding.range()))
        .collect()
}

/// One call-argument form per language, each with the value as `{v}`.
const POSITIVES: &[&str] = &[
    // Python keyword arguments.
    "client = Client(api_key=\"{v}\")",
    "client = Client(api_key='{v}')",
    "client = Client(timeout=5, secret=\"{v}\", retries=2)",
    "client = Client( password = \"{v}\" )",
    "client = Client(client_secret=\"{v}\", region=\"us\")",
    "def connect(api_key=\"{v}\"):",
    // JavaScript / TypeScript object and named-argument forms.
    "const client = new Client({ apiKey: \"{v}\" });",
    "const client = new Client({ apiKey: '{v}', region: 'us' });",
    "const client = createClient(apiKey: \"{v}\");",
    // Java and Rust builder methods named for the credential.
    "Client client = new Client().setApiKey(\"{v}\");",
    "let client = Client::builder().api_key(\"{v}\").build();",
    "let client = Client::builder().set_secret_key(\"{v}\");",
    // Go options and struct literals.
    "c := NewClient(WithAPIKey(\"{v}\"))",
    "cfg := Config{APIKey: \"{v}\"}",
    "c := NewClient(APIKey: \"{v}\")",
];

#[test]
fn every_in_scope_form_is_one_exact_span_generic_token_finding() {
    let v = value();
    for template in POSITIVES {
        let input = template.replace("{v}", &v);
        let start = input.find(&v).unwrap();
        let expected = ByteRange::new(start, start + v.len()).unwrap();
        assert_eq!(
            findings_of(&input),
            vec![("generic-token".to_owned(), expected)],
            "{input}"
        );
    }
}

#[test]
fn out_of_scope_forms_and_benign_controls_are_silent() {
    let v = value();
    let unterminated = format!("Client(api_key=\"{v}");
    let next_line = format!("Client(\n    api_key=\n\"{v}\")");
    let inputs: Vec<String> = vec![
        // Placeholders, references and short values keep their existing floors.
        "Client(api_key=\"your_api_key_here\")".to_owned(),
        "Client(api_key=\"<token>\")".to_owned(),
        "Client(api_key=\"${API_KEY}\")".to_owned(),
        "Client(api_key=\"{{ api_key }}\")".to_owned(),
        "Client(api_key=\"short1\")".to_owned(),
        // Dynamic expressions and variable references.
        "Client(api_key=os.environ[\"API_KEY\"])".to_owned(),
        "Client(api_key=os.getenv(\"API_KEY\"))".to_owned(),
        "Client(timeout=5, api_key=os.getenv(\"API_KEY\"))".to_owned(),
        "Client(api_key=process.env.API_KEY)".to_owned(),
        "Client(api_key=api_key)".to_owned(),
        "Client(api_key=API_KEY)".to_owned(),
        // An unquoted call argument is never claimed, even when literal-like.
        format!("Client(api_key={v})"),
        // Multi-line: an unterminated literal and a value on the next line.
        unterminated,
        next_line,
        // Non-credential argument names, including identifier siblings.
        format!("Client(model=\"{v}\")"),
        format!("Client(api_key_id=\"{v}\")"),
        // A masking lead over a masked value (#1018: an unmasked value under
        // `redacted_api_key` is judged as `api_key`).
        "Client(redacted_api_key=\"Sy7n********************Zt3\")".to_owned(),
        // The bare `token` name stays unmatched (#702), as an argument too.
        format!("Client(token=\"{v}\")"),
        // A positional literal to a constructor with no credential name.
        format!("client = Client(\"{v}\")"),
        format!("const client = new Client(\"{v}\");"),
        format!("exa = Exa(\"{v}\")"),
        // A credential-named callee with a non-secret or non-sole argument.
        "field.password(\"Enter your password\")".to_owned(),
        "secret(\"aws-credentials-prod-eu-1\")".to_owned(),
        "secret(\"MY_SECRET_NAME_1\")".to_owned(),
        "api_key(\"short1\")".to_owned(),
        format!("api_key({v})"),
        format!("api_key(\"{v}\", extra)"),
        format!("auth(\"{v}\")"),
        format!("token(\"{v}\")"),
        // Prose and bare values.
        "Pass your key as Client(api_key=...) when constructing it.".to_owned(),
        "Set api_key (the value) before you call Client().".to_owned(),
        v.clone(),
        format!("the key is {v} ok"),
    ];
    for input in inputs {
        assert_eq!(findings_of(&input), Vec::new(), "{input}");
    }
}

/// A provider-typed finding wins and nothing is reported twice, including
/// for the keyword-gated providers of #868.
#[test]
fn a_provider_detector_keeps_the_span_and_nothing_is_reported_twice() {
    let mistral = ["aB3dE5gH", "7jK9mN1p", "Q3sT5vW7", "yZ9xC2Lq"].concat();
    let cohere = ["zY9xW7vU", "5tS3rQ1p", "O9nM7lK5", "jI3hG1fE", "aB3dE5gH"].concat();
    let ai21 = ["Zz9Yy8Xx", "7Ww6Vv5U", "u4Tt3Ss2", "Rr1Qq0Pp"].concat();
    let deepgram = ["q7w3e9r1", "t5y8u2i4", "o6p0a1s3", "d5f7g9h2", "j4k6l8z0"].concat();
    let cases = [
        (
            "mistral-api-key",
            format!("Mistral(api_key=\"{mistral}\")"),
            mistral.clone(),
        ),
        (
            "mistral-api-key",
            format!("ChatMistralAI(mistral_api_key='{mistral}')"),
            mistral,
        ),
        (
            "cohere-api-key",
            format!("cohere.ClientV2(api_key=\"{cohere}\")"),
            cohere,
        ),
        (
            "ai21-api-key",
            format!("AI21Client(api_key=\"{ai21}\")"),
            ai21,
        ),
        (
            "deepgram-api-key",
            format!("DeepgramClient(api_key=\"{deepgram}\")"),
            deepgram,
        ),
    ];
    for (detector, input, value) in cases {
        let start = input.find(&value).unwrap();
        let expected = ByteRange::new(start, start + value.len()).unwrap();
        assert_eq!(
            findings_of(&input),
            vec![(detector.to_owned(), expected)],
            "{input}"
        );
    }
}

#[test]
fn every_byte_partition_reproduces_the_whole_input_result() {
    let v = value();
    for template in [
        "client = Client(api_key=\"{v}\")",
        "let client = Client::builder().api_key(\"{v}\").build();",
    ] {
        let input = template.replace("{v}", &v);
        let (expected_text, expected_findings) = whole_input(&input);
        assert_eq!(expected_findings.len(), 1, "{input}");
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
