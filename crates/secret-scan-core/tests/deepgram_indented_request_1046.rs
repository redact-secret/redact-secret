//! Issue #1046: the #1017 HTTP-block rule read a request line or header
//! line only at column 0, so an indented request (an indented Markdown code
//! block, a YAML block scalar, a nested log dump, or the benchmark's
//! `context.indent` metamorphic variant) lost the Deepgram host and the
//! token slot below it went unreported. Indentation by spaces or tabs is
//! now read as the same line unindented, in the whole-input rule and the
//! incremental retention hint alike. Every value is built at run time from
//! low-entropy filler and was never issued by Deepgram.
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

fn positives() -> Vec<String> {
    let k = key();
    vec![
        // The benchmark variant: only the first line indented.
        format!(
            "    GET wss://api.deepgram.com/v1/listen HTTP/1.1\nSec-WebSocket-Protocol: token, {k}\n"
        ),
        // A uniformly indented block, spaces and tabs.
        format!(
            "    GET wss://api.deepgram.com/v1/listen HTTP/1.1\n    Sec-WebSocket-Protocol: token, {k}\n"
        ),
        format!(
            "\tGET /v1/listen HTTP/1.1\r\n\tHost: api.deepgram.com\r\n\tSec-WebSocket-Protocol: token, {k}\r\n"
        ),
        format!(
            "request: |\n  POST /v1/listen HTTP/1.1\n  Host: api.deepgram.com\n  Authorization: Token {k}\n"
        ),
        // Only the header indented, below an unindented `Host:` header.
        format!("POST /v1/listen HTTP/1.1\nHost: api.deepgram.com\n  Authorization: Token {k}\n"),
    ]
}

#[test]
fn an_indented_request_block_is_a_redacted_deepgram_finding_with_the_exact_span() {
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
}

#[test]
fn indentation_gives_the_same_finding_as_the_unindented_request() {
    let k = key();
    let canonical = format!(
        "GET wss://api.deepgram.com/v1/listen HTTP/1.1\nSec-WebSocket-Protocol: token, {k}\n"
    );
    let indented = format!("    {canonical}");
    let (a, b) = (findings(&canonical), findings(&indented));
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(a[0].type_name(), b[0].type_name());
    assert_eq!(a[0].confidence(), b[0].confidence());
    assert_eq!(a[0].action(), b[0].action());
    assert_eq!(b[0].range().start(), a[0].range().start() + 4);
}

#[test]
fn indented_negative_twins_stay_silent_for_the_typed_family() {
    let k = key();
    for input in [
        // Another host, indented.
        format!(
            "    GET wss://api.example.invalid/v1/listen HTTP/1.1\n    Sec-WebSocket-Protocol: token, {k}\n"
        ),
        // A look-alike host, indented.
        format!(
            "  GET /v1/listen HTTP/1.1\n  Host: api.deepgram.com.example.test\n  Sec-WebSocket-Protocol: token, {k}\n"
        ),
        // A blank line still ends the request.
        format!(
            "  POST /v1/chat HTTP/1.1\n  Host: api.deepgram.com\n\n  Authorization: Token {k}\n"
        ),
        // Indented prose between the request and the header ends it too.
        format!(
            "  GET /v1/listen HTTP/1.1\n  Host: api.deepgram.com\n  see the notes below\n  Sec-WebSocket-Protocol: token, {k}\n"
        ),
    ] {
        let typed: Vec<_> = findings(&input)
            .into_iter()
            .filter(|found| found.type_name() == "deepgram_api_key")
            .collect();
        assert!(typed.is_empty(), "{input:?}: {typed:?}");
    }
}

#[test]
fn incremental_scanning_matches_the_whole_input_across_every_two_chunk_split() {
    for input in positives() {
        let (expected_text, expected_findings) = whole_input(&input);
        assert_eq!(expected_findings.len(), 1, "{input:?}");
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
