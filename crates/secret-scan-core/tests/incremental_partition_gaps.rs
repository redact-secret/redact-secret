//! Partition invariance for the layouts the #985 audit found where a
//! per-line incremental session and a whole-input scan disagreed (issue
//! #990).
//!
//! Each input is run through a session at every UTF-8 byte boundary, every
//! host-native `&str` boundary, one byte at a time and one line per
//! `append`, and the concatenated text and findings are compared with the
//! whole-input reference under the same profile. Every case also pins the
//! reference's finding count, so a change that made both paths agree by
//! losing the finding everywhere fails here too. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{
    DefaultPolicy, DetectorRegistry, Finding, IncrementalLimits, IncrementalSanitizer,
    PiiSelection, SecretScanError, default_placeholder_formatter, redact, scan,
};
use support::{
    as_chunks, char_boundary_partitions, incremental_corpus, single_byte_partition,
    utf8_byte_partitions,
};

/// A synthetic 16-byte generic-token value.
const VALUE: &str = "Zx9SYNTHq7Lw3RtK";
/// A synthetic 20-byte Bearer value: above the bare `Bearer` floor (16).
const BEARER_LONG: &str = "SYNTHETICrevoked0x7Q";
/// A synthetic 13-byte Bearer value: above the header floor (12) only.
const BEARER_SHORT: &str = "SYNTHrevoked7";
/// A synthetic 32-hex value in the Datadog and Twilio shapes.
const HEX32: &str = "fedcba9876543210fedcba9876543210";
/// A synthetic legacy Pinecone-shaped UUID.
const UUID: &str = "12345678-90ab-cdef-1234-567890abcdef";

#[derive(Clone, Copy, Debug)]
enum Profile {
    Full,
    FullWithPii,
}

impl Profile {
    fn registry(self) -> DetectorRegistry {
        match self {
            Self::Full => DetectorRegistry::with_built_in([]).unwrap(),
            Self::FullWithPii => DetectorRegistry::with_built_in_and_pii(
                &PiiSelection::parse(&["pii:global"]).unwrap(),
            )
            .unwrap(),
        }
    }

    fn session(self, limits: IncrementalLimits) -> IncrementalSanitizer {
        match self {
            Self::Full => IncrementalSanitizer::new(limits).unwrap(),
            Self::FullWithPii => IncrementalSanitizer::with_built_in_and_pii(
                limits,
                &PiiSelection::parse(&["pii:global"]).unwrap(),
            )
            .unwrap(),
        }
    }
}

fn generous_limits() -> IncrementalLimits {
    IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap()
}

fn whole_input(profile: Profile, input: &str) -> (String, Vec<Finding>) {
    let findings = scan(input, &profile.registry(), &DefaultPolicy).unwrap();
    let text = redact(input, &findings, &default_placeholder_formatter).unwrap();
    (text, findings)
}

fn drive(
    profile: Profile,
    limits: IncrementalLimits,
    chunks: &[&str],
) -> Result<(String, Vec<Finding>), SecretScanError> {
    let mut session = profile.session(limits);
    let mut text = String::new();
    let mut findings = Vec::new();
    for chunk in chunks {
        let (piece, found) = session.append(chunk)?.into_parts();
        text.push_str(&piece);
        findings.extend(found);
    }
    let (piece, found) = session.finalize()?.into_parts();
    text.push_str(&piece);
    findings.extend(found);
    Ok((text, findings))
}

/// `input` cut after every `\n` and every `\r`: one closed line per
/// `append`, the partition that processes each unit on its own.
fn one_line_per_chunk(input: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    for (index, byte) in input.bytes().enumerate() {
        if byte == b'\n' || byte == b'\r' {
            chunks.push(&input[start..=index]);
            start = index + 1;
        }
    }
    if start < input.len() {
        chunks.push(&input[start..]);
    }
    chunks
}

/// Asserts every partition of `input` reproduces the whole-input reference.
fn assert_partition_invariant(label: &str, profile: Profile, input: &str) {
    let expected = whole_input(profile, input);
    let check = |partition: &str, chunks: &[&str]| {
        let actual = drive(profile, generous_limits(), chunks)
            .unwrap_or_else(|error| panic!("{label}, {partition}: {:?}", error.code()));
        assert_eq!(actual, expected, "{label}, {partition}");
    };
    check("one line per append", &one_line_per_chunk(input));
    for (index, chunks) in char_boundary_partitions(input).iter().enumerate() {
        check(&format!("char boundary #{index}"), chunks);
    }
    for (index, pieces) in utf8_byte_partitions(input).iter().enumerate() {
        check(&format!("byte boundary #{index}"), &as_chunks(pieces));
    }
    check(
        "one byte per append",
        &as_chunks(&single_byte_partition(input)),
    );
}

/// Asserts the whole-input reference reports `count` findings from
/// `detector`, then that every partition reproduces it.
fn assert_case(label: &str, profile: Profile, input: &str, detector: &str, count: usize) {
    let (_, findings) = whole_input(profile, input);
    let found = findings
        .iter()
        .filter(|finding| finding.detector() == detector)
        .count();
    assert_eq!(found, count, "{label}: whole-input {detector} findings");
    assert_partition_invariant(label, profile, input);
}

#[test]
fn a_generic_token_name_the_grammar_joins_to_a_later_operator_is_retained() {
    for (label, input, count) in [
        ("backticked name", format!("`password\n= {VALUE}\n"), 1),
        (
            "glued quoted name",
            format!("x\"password\"\n: \"{VALUE}\"\n"),
            1,
        ),
        (
            "glued single-quoted name",
            format!("x'secret'\n= '{VALUE}'\n"),
            1,
        ),
        (
            "escaped quoted name",
            format!("{{\\\"password\\\"\n: \\\"{VALUE}\\\"}}\n"),
            1,
        ),
        (
            "JWK member",
            format!("{{\"kty\":\"oct\",\"k\"\n: \"{VALUE}\"}}\n"),
            1,
        ),
        (
            "JWK member, CRLF",
            format!("{{\"kty\":\"oct\",\"k\"\r\n: \"{VALUE}\"}}\r\n"),
            1,
        ),
        (
            "JWK member, blank lines before the operator",
            format!("{{\"kty\":\"oct\",\"d\"\n\n  \n: \"{VALUE}\"}}\n"),
            1,
        ),
        (
            "JWK member, kty on a later line",
            format!("{{\"k\"\n: \"{VALUE}\", \"kty\":\"oct\"}}\n"),
            0,
        ),
        (
            "backticked name among log lines",
            format!("start\n`api_key\n\n= {VALUE}\nend\n"),
            1,
        ),
    ] {
        assert_case(label, Profile::Full, &input, "generic-token", count);
    }
}

#[test]
fn a_bearer_credential_after_a_header_on_an_earlier_line_matches_the_whole_input_scan() {
    for (label, input, count) in [
        (
            "X-Authorization on the line before",
            format!("X-Authorization:\nBearer {BEARER_LONG}\n"),
            1,
        ),
        (
            "X-Authorization on the same line",
            format!("X-Authorization: Bearer {BEARER_LONG}\n"),
            1,
        ),
        (
            "X-Authorization, a value below the bare floor",
            format!("X-Authorization:\nBearer {BEARER_SHORT}\n"),
            0,
        ),
        (
            "Proxy-Authorization on the line before, header floor",
            format!("Proxy-Authorization:\nBearer {BEARER_SHORT}\n"),
            1,
        ),
        (
            "Proxy-Authorization with the colon on its own line",
            format!("Proxy-Authorization\n:\n  Bearer {BEARER_SHORT}\n"),
            1,
        ),
        (
            "Proxy-Authorization, CRLF",
            format!("Proxy-Authorization:\r\nBearer {BEARER_SHORT}\r\n"),
            1,
        ),
        (
            "an identifier before proxy- blocks the header",
            format!("xproxy-authorization:\nBearer {BEARER_SHORT}\n"),
            0,
        ),
    ] {
        assert_case(label, Profile::Full, &input, "bearer-token", count);
    }
}

#[test]
fn a_lone_carriage_return_ends_a_line_for_every_detector() {
    for (label, input, detector, count) in [
        (
            "keyword on the line before",
            format!("datadog\r{HEX32}\r"),
            "datadog-api-key",
            0,
        ),
        (
            "keyword on the same line",
            format!("datadog {HEX32}\r"),
            "datadog-api-key",
            1,
        ),
        (
            "keyword on the line before, CRLF",
            format!("datadog\r\n{HEX32}\r\n"),
            "datadog-api-key",
            0,
        ),
        (
            "pinecone keyword on the line before",
            format!("# pinecone\rapi_key={UUID}\n"),
            "pinecone-api-key",
            0,
        ),
        (
            "pinecone keyword on the same line",
            format!("# pinecone api_key={UUID}\r"),
            "pinecone-api-key",
            1,
        ),
        (
            "twilio CLI table",
            format!(
                "$ twilio profiles:list --properties authToken\rID     Auth Token\rprod   {HEX32}\r"
            ),
            "twilio-auth-token",
            1,
        ),
        (
            "JWK kty on the line before",
            format!("{{\"kty\":\"oct\",\r\"k\":\"{VALUE}\"}}\r"),
            "generic-token",
            0,
        ),
    ] {
        assert_case(label, Profile::Full, &input, detector, count);
    }
}

/// Every fixture of the canonical incremental corpus, with its line endings
/// rewritten to lone `\r` and to CRLF, is partition invariant: the
/// multi-line layouts (Heroku, Twilio, Confluent, private keys, contextual
/// assignments) included.
#[test]
fn the_incremental_corpus_is_partition_invariant_under_cr_and_crlf_line_endings() {
    for fixture in incremental_corpus() {
        if !fixture.input.contains('\n') {
            continue;
        }
        let crlf = fixture.input.replace("\r\n", "\n").replace('\n', "\r\n");
        let cr = fixture.input.replace("\r\n", "\n").replace('\n', "\r");
        for (ending, input) in [("CRLF", crlf), ("CR", cr)] {
            let label = format!("{} ({ending})", fixture.id);
            let expected = whole_input(Profile::Full, &input);
            let check = |partition: &str, chunks: &[&str]| {
                let actual = drive(Profile::Full, generous_limits(), chunks)
                    .unwrap_or_else(|error| panic!("{label}, {partition}: {:?}", error.code()));
                assert_eq!(actual, expected, "{label}, {partition}");
            };
            check("one line per append", &one_line_per_chunk(&input));
            for (index, chunks) in char_boundary_partitions(&input).iter().enumerate() {
                check(&format!("char boundary #{index}"), chunks);
            }
        }
    }
}

#[test]
fn a_twilio_command_under_lone_carriage_returns_closes_at_its_next_line() {
    let mut input = String::from("$ twilio profiles:list x\r");
    for _ in 0..3_000 {
        input.push_str("row\r");
    }
    let expected = whole_input(Profile::Full, &input);
    // Construct limits far below the input: the command's unit must close
    // instead of holding every row.
    let limits = IncrementalLimits::new(
        1 << 20,
        IncrementalLimits::minimum_buffered_bytes(1_024, 1_024),
        1_024,
        1_024,
    )
    .unwrap();
    for chunks in [vec![input.as_str()], one_line_per_chunk(&input)] {
        let actual = drive(Profile::Full, limits, &chunks)
            .unwrap_or_else(|error| panic!("{:?}", error.code()));
        assert_eq!(actual, expected);
    }
}

#[test]
fn a_phone_extension_marker_is_judged_on_its_own_line() {
    for (label, input, count) in [
        (
            "marker at a line end, prose after",
            "phone: 212-456-7890 ext\nhello\n",
            0,
        ),
        (
            "marker at a line end, digits after",
            "phone: 212-456-7890 ext\n123\n",
            0,
        ),
        (
            "marker at a line end, CRLF",
            "phone: 212-456-7890 ext\r\nhello\r\n",
            0,
        ),
        (
            "marker at a line end, CR",
            "phone: 212-456-7890 ext.\rhello\r",
            0,
        ),
        (
            "marker then spaces at a line end",
            "phone: 212-456-7890 extension  \nhello\n",
            0,
        ),
        (
            "extension on the same line",
            "phone: 212-456-7890 ext 123\nhello\n",
            1,
        ),
        (
            "ordinary word after the number",
            "phone: 212-456-7890 extra\nhello\n",
            1,
        ),
    ] {
        assert_case(label, Profile::FullWithPii, input, "pii-domain", count);
    }
}
