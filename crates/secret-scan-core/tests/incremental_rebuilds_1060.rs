//! The incremental session's finding, lead and lookback bookkeeping (issue
//! #1060) is invisible: over generated inputs cut at pseudo-random chunk
//! partitions, every session releases exactly what the whole-input path
//! (`scan_and_redact`) returns for the same input.
//!
//! The inputs mix what that bookkeeping touches: lines above an AWS secret
//! that a detector reads as a lead (issue #1040), CRLF and lone-CR line ends
//! (a lead completed by the `\n` of its CRLF pair), private-key blocks split
//! across chunks, the layouts every lookback hint holds open, and non-ASCII
//! and invisible code points at split points. Partitions include empty
//! chunks and splits right after every invisible code point.
//!
//! Every value is synthetic and generated at run time.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    DefaultPolicy, DetectorRegistry, Finding, IncrementalLimits, IncrementalSanitizer,
    PiiSelection, default_placeholder_formatter, scan_and_redact,
};

const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A deterministic linear congruential generator.
struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(self.0 >> 33).unwrap() % bound
    }

    fn filler(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }
}

/// One generated piece of input; most end a line, some deliberately do not.
fn piece(rng: &mut Rng) -> String {
    let aws_id = |rng: &mut Rng| format!("AKIA{}", rng.filler(UPPER_ALNUM, 16));
    match rng.below(34) {
        0 => format!("{}\n", aws_id(rng)),
        1 => format!("{}\r\n", aws_id(rng)),
        2 => format!("{}\r", aws_id(rng)),
        3 | 4 => format!("{}\n", rng.filler(BASE64, 40)),
        5 => format!("aws_access_key_id = {}\n", aws_id(rng)),
        6 => format!("aws_secret_access_key = {}\r\n", rng.filler(BASE64, 40)),
        7 => format!("API_KEY=ghp_{}\n", rng.filler(ALNUM, 36)),
        8 => format!("token: ghp_{}", rng.filler(ALNUM, 36)),
        9 => format!("Authorization: Bearer {}\n", rng.filler(ALNUM, 32)),
        10 => "Authorization:\n".to_string(),
        11 => "api_key =\n".to_string(),
        12 => "-----BEGIN PRIVATE KEY-----\n".to_string(),
        13 => format!("{}\n", rng.filler(BASE64, 64)),
        14 => "-----END PRIVATE KEY-----\n".to_string(),
        15 => "machine api.heroku.com\n  login user@example.invalid\n".to_string(),
        16 => "$ twilio api:core:accounts:list\nSID  Auth Token\n".to_string(),
        17 => "schema.registry.url=https://psrc.example.invalid\n".to_string(),
        18 => "- name: API_KEY\n".to_string(),
        19 => "provider: mistral\n".to_string(),
        20 => "GET /v1/listen HTTP/1.1\nHost: api.deepgram.com\n".to_string(),
        21 => "plain words \u{e9}\u{65e5} here\n".to_string(),
        // Invisible and non-ASCII code points never end a piece: one directly
        // before a secret-named key on the same line panics the whole-input
        // `aws-secret-access-key` detector (a separate, pre-existing defect).
        22 => format!("API_\u{200B}KEY=ghp_{}\n", rng.filler(ALNUM, 36)),
        23 => "log\u{FEFF}line\n".to_string(),
        24 => "soft\u{00AD}hyphen \u{200B}\n".to_string(),
        25 => "a\u{2028}b\n".to_string(),
        26 => "\n".to_string(),
        27 => "\r\n".to_string(),
        28 => "\r".to_string(),
        29 => "   \t".to_string(),
        30 => "contact: someone@example.invalid\n".to_string(),
        31 => format!("AWS_{}KEY={}\n", "\u{200B}", rng.filler(BASE64, 40)),
        32 => format!("{}\u{200B}{}\n", aws_id(rng), rng.filler(BASE64, 8)),
        _ => format!("log line {} ok\n", rng.filler(ALNUM, 12)),
    }
}

/// `input` cut at pseudo-random char boundaries, with some empty chunks.
fn random_partition<'a>(input: &'a str, rng: &mut Rng) -> Vec<&'a str> {
    let mut chunks = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        if rng.below(8) == 0 {
            chunks.push("");
        }
        let mut end = (cursor + 1 + rng.below(48)).min(input.len());
        while !input.is_char_boundary(end) {
            end += 1;
        }
        chunks.push(&input[cursor..end]);
        cursor = end;
    }
    chunks.push("");
    chunks
}

/// `input` cut right after every invisible or non-ASCII code point and every
/// line terminator.
fn split_after_special(input: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    for (at, ch) in input.char_indices() {
        if !ch.is_ascii() || ch == '\n' || ch == '\r' {
            let end = at + ch.len_utf8();
            chunks.push(&input[start..end]);
            start = end;
        }
    }
    chunks.push(&input[start..]);
    chunks
}

fn limits() -> IncrementalLimits {
    let construct = 1 << 16;
    IncrementalLimits::new(
        1 << 24,
        IncrementalLimits::minimum_buffered_bytes(construct, construct),
        construct,
        construct,
    )
    .unwrap()
}

fn drive(mut sanitizer: IncrementalSanitizer, chunks: &[&str]) -> (String, Vec<Finding>) {
    let mut text = String::new();
    let mut findings = Vec::new();
    for chunk in chunks {
        let result = sanitizer.append(chunk).unwrap();
        text.push_str(result.text());
        findings.extend_from_slice(result.findings());
    }
    let result = sanitizer.finalize().unwrap();
    text.push_str(result.text());
    findings.extend_from_slice(result.findings());
    (text, findings)
}

/// A whole-input registry and the incremental session of the same profile.
type Profile = fn(&PiiSelection) -> (DetectorRegistry, IncrementalSanitizer);

#[test]
fn every_partition_of_generated_inputs_releases_the_whole_input_result() {
    let selection = PiiSelection::parse(&["pii:global"]).unwrap();
    let profiles: [(&str, Profile); 3] = [
        ("full", |_| {
            (
                DetectorRegistry::with_built_in([]).unwrap(),
                IncrementalSanitizer::new(limits()).unwrap(),
            )
        }),
        ("common", |_| {
            (
                DetectorRegistry::with_common_built_in([]).unwrap(),
                IncrementalSanitizer::with_common_built_in(limits()).unwrap(),
            )
        }),
        ("full+pii", |selection| {
            (
                DetectorRegistry::with_built_in_and_pii(selection).unwrap(),
                IncrementalSanitizer::with_built_in_and_pii(limits(), selection).unwrap(),
            )
        }),
    ];
    let mut rng = Rng(0x1060_D1CE_5EED_0001);
    let mut findings_seen = 0;
    for case in 0..160 {
        let pieces = 1 + rng.below(24);
        let input: String = (0..pieces).map(|_| piece(&mut rng)).collect();
        for (label, make) in &profiles {
            let (registry, _) = make(&selection);
            let whole = scan_and_redact(
                &input,
                &registry,
                &DefaultPolicy,
                &default_placeholder_formatter,
            )
            .unwrap();
            let expected = (whole.text().to_string(), whole.findings().to_vec());
            findings_seen += expected.1.len();

            let mut partitions = vec![vec![input.as_str()], split_after_special(&input)];
            for _ in 0..4 {
                partitions.push(random_partition(&input, &mut rng));
            }
            for chunks in &partitions {
                let actual = drive(make(&selection).1, chunks);
                assert_eq!(
                    actual,
                    expected,
                    "case {case}, {label}, {} chunks",
                    chunks.len()
                );
            }
        }
    }
    // The generator must actually produce findings for the check to bite.
    assert!(findings_seen > 500, "{findings_seen} findings");
}
