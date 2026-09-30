//! Issue #1017: Deepgram forms the keyword-gated contract missed or typed as
//! `generic-token`: the JS SDK v3 `createClient(...)` factory, the browser
//! WebSocket `token` subprotocol, a token header whose request line or
//! `Host:` header names the Deepgram API host on an earlier line, and a
//! sibling `provider: deepgram` field (YAML block or JSON). Each is
//! `deepgram_api_key` / redact, the negative twins stay silent, and a bare
//! 40-hex run (a Git SHA-1 shape) stays unreported. Every value is built at
//! run time from low-entropy filler and was never issued by Deepgram.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence, DefaultPolicy, DetectorRegistry, Finding, scan};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

fn key() -> String {
    "d4e5f6a7b8".repeat(4)
}

fn findings(input: &str) -> Vec<Finding> {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan(input, &registry, &DefaultPolicy).unwrap()
}

/// Every positive of the issue, with the value it must redact.
fn positives() -> Vec<String> {
    let k = key();
    vec![
        // 1. JS SDK v3 factory.
        format!(
            "import {{ createClient }} from '@deepgram/sdk';\n\nconst deepgram = createClient(\"{k}\");\n"
        ),
        format!("const deepgram = createClient({{ key: \"{k}\" }});"),
        format!("import {{ createClient }} from '@deepgram/sdk'; const c = createClient('{k}');"),
        // 2. WebSocket token subprotocol.
        format!(
            "GET wss://api.deepgram.com/v1/listen HTTP/1.1\nSec-WebSocket-Protocol: token, {k}\n"
        ),
        format!("new WebSocket(\"wss://api.deepgram.com/v1/listen\", [\"token\", \"{k}\"]);"),
        format!(
            "GET /v1/listen HTTP/1.1\r\nHost: api.deepgram.com\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: token, {k}\r\n"
        ),
        // 3. Adjacent-line or sibling-field context.
        format!("POST /v1/chat HTTP/1.1\nHost: api.deepgram.com\nAuthorization: Token {k}\n"),
        format!("stt:\n  provider: deepgram\n  api_key: {k}\n"),
        format!(
            "stt:\n  provider: \"deepgram\"\n  model: nova-2\n  language: en\n  api_key: {k}\n"
        ),
        format!("providers:\n  - provider: deepgram\n    api_key: {k}\n"),
        format!("{{\"provider\":\"deepgram\",\"auth\":\"{k}\"}}"),
    ]
}

#[test]
fn every_form_is_a_redacted_deepgram_finding_with_the_exact_span() {
    let k = key();
    for input in positives() {
        let found = findings(&input);
        assert_eq!(found.len(), 1, "{input:?}: {found:?}");
        let start = input.find(&k).unwrap();
        assert_eq!(found[0].range().start(), start, "{input:?}");
        assert_eq!(found[0].range().end(), start + k.len(), "{input:?}");
        assert_eq!(found[0].type_name(), "deepgram_api_key", "{input:?}");
        assert_eq!(found[0].confidence(), Confidence::High, "{input:?}");
        assert_eq!(found[0].action(), Action::Redact, "{input:?}");
    }
    // The issue's offsets.
    assert_eq!(findings(&positives()[0])[0].range().start(), 78);
    assert_eq!(findings(&positives()[3])[0].range().start(), 77);
    assert_eq!(findings(&positives()[6])[0].range().start(), 67);
    assert_eq!(findings(&positives()[7])[0].range().start(), 37);
}

#[test]
fn a_subprotocol_naming_deepgram_only_as_a_word_warns() {
    let k = key();
    let input =
        format!("// deepgram streaming\nnew WebSocket(url, [\"token\", \"{k}\"]); // deepgram");
    let found = findings(&input);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].type_name(), "deepgram_api_key");
    assert_eq!(found[0].confidence(), Confidence::Medium);
}

#[test]
fn the_negative_twins_and_a_bare_run_stay_silent_for_the_typed_family() {
    let k = key();
    for input in [
        // An unrelated factory, and `createClient` with no Deepgram context.
        format!("import {{ createWidget }} from 'widget-sdk';\nconst w = createWidget(\"{k}\");\n"),
        format!("import {{ createClient }} from 'widget-sdk';\nconst w = createClient(\"{k}\");\n"),
        // The same subprotocol to another host.
        format!(
            "GET wss://api.example.invalid/v1/listen HTTP/1.1\nSec-WebSocket-Protocol: token, {k}\n"
        ),
        format!("new WebSocket(\"wss://api.example.invalid/v1/listen\", [\"token\", \"{k}\"]);"),
        // A look-alike host, a blank line ending the request, a body line.
        format!(
            "GET /v1/listen HTTP/1.1\nHost: api.deepgram.com.example.test\nSec-WebSocket-Protocol: token, {k}\n"
        ),
        format!("POST /v1/chat HTTP/1.1\nHost: api.deepgram.com\n\nAuthorization: Token {k}\n"),
        // A sibling of another provider, another column, a new item.
        format!("stt:\n  provider: whisper\n  api_key: {k}\n"),
        format!("stt:\n    provider: deepgram\n  api_key: {k}\n"),
        format!("- provider: deepgram\n- api_key: {k}\n"),
        format!("{{\"provider\":\"deepgrammar\",\"auth\":\"{k}\"}}"),
        // A bare 40-hex run is a SHA-1 shape.
        format!("commit {k}\nAuthor: someone\n"),
        k.clone(),
    ] {
        let typed: Vec<_> = findings(&input)
            .into_iter()
            .filter(|found| found.type_name() == "deepgram_api_key")
            .collect();
        assert!(typed.is_empty(), "{input:?}: {typed:?}");
    }
}

#[test]
fn forms_that_were_redacted_before_are_still_redacted() {
    let k = key();
    for input in [
        format!("POST /v1/chat HTTP/1.1\nHost: api.example.invalid\nAuthorization: Token {k}\n"),
        format!("stt:\n  provider: whisper\n  api_key: {k}\n"),
    ] {
        let found = findings(&input);
        assert_eq!(found.len(), 1, "{input:?}: {found:?}");
        assert_eq!(found[0].action(), Action::Redact, "{input:?}");
    }
}

#[test]
fn incremental_scanning_matches_the_whole_input_across_every_two_chunk_split() {
    for input in positives() {
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
        let lines: Vec<&str> = input.split_inclusive('\n').collect();
        assert_eq!(run(&lines).text(), expected_text, "{input:?}");
    }
}

/// The windows end exactly where the retention hints stop holding lines: a
/// request header eight lines below the `Host:` header, or a credential key
/// six keys below `provider:`, is the last one read, and one line further is
/// not. Whole-input and chunked scans agree on both sides of each edge.
#[test]
fn the_window_edges_agree_between_whole_input_and_chunked_scans() {
    let k = key();
    let request = |pads: usize| {
        format!(
            "GET /v1/listen HTTP/1.1\nHost: api.deepgram.com\n{}Sec-WebSocket-Protocol: token, {k}\n",
            "X-Pad: 1\n".repeat(pads)
        )
    };
    let mapping = |pads: usize| {
        format!(
            "stt:\n  provider: deepgram\n{}  api_key: {k}\n",
            "  pad: 1\n".repeat(pads)
        )
    };
    for (input, typed) in [
        (request(7), true),
        (request(8), false),
        (mapping(5), true),
        (mapping(6), false),
    ] {
        let (expected_text, expected_findings) = whole_input(&input);
        assert_eq!(
            expected_findings
                .iter()
                .any(|found| found.type_name() == "deepgram_api_key"),
            typed,
            "{input:?}"
        );
        let lines: Vec<&str> = input.split_inclusive('\n').collect();
        assert_eq!(run(&lines).text(), expected_text, "{input:?}");
        for pieces in utf8_byte_partitions(&input) {
            assert_eq!(run(&as_chunks(&pieces)).text(), expected_text, "{input:?}");
        }
    }
}
