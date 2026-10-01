//! Issue #1146: the `otpauth://` detector now jumps to each exact scheme
//! instead of testing both prefixes at every character. The unit tests in
//! `detectors/otpauth.rs` compare candidates with the old per-character walk;
//! this file pins the public whole-input findings (ranges and detector id) and
//! checks that every byte partition of the incremental surface reproduces the
//! whole-input result for sparse, dense, nested, unsupported-type and
//! Unicode-neighbour inputs. All values are synthetic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{as_chunks, run, single_byte_partition, utf8_byte_partitions, whole_input};

const SECRET: &str = "JBSWY3DPEHPK3PXP";
const OTHER: &str = "NB2HI4DTHIXS6IDU";

/// Byte ranges of the `otpauth-uri` findings, in report order.
fn otpauth_ranges(findings: &[redact_secret::Finding]) -> Vec<(usize, usize)> {
    findings
        .iter()
        .filter(|finding| finding.detector() == "otpauth-uri")
        .map(|finding| (finding.range().start(), finding.range().end()))
        .collect()
}

fn cases() -> Vec<(String, Vec<&'static str>)> {
    // (input, secrets expected to be reported, in order)
    let uri = |kind: &str, secret: &str| {
        format!("otpauth://{kind}/Example:a@example.com?secret={secret}&issuer=Example")
    };
    vec![
        (uri("totp", SECRET), vec![SECRET]),
        (
            format!("{}\n{}\n", uri("totp", SECRET), uri("hotp", OTHER)),
            vec![SECRET, OTHER],
        ),
        (
            format!("log line \u{d55c}\u{1f600} {}\r\n", uri("hotp", SECRET)),
            vec![SECRET],
        ),
        (
            format!("otpauth://push/x {}", uri("totp", SECRET)),
            vec![SECRET],
        ),
        (
            format!("otpauth://otpauth://totp/A?secret={SECRET}"),
            vec![SECRET],
        ),
        (format!("xotpauth://totp/A?secret={SECRET}"), vec![]),
        (
            format!("otpauth://totp/A?secret=SHORT&u=otpauth://hotp/B?secret={OTHER}"),
            vec![OTHER],
        ),
        (
            format!("OTPAUTH://TOTP/A?secret={SECRET} otpauth://totpx/A?secret={SECRET}"),
            vec![],
        ),
    ]
}

#[test]
fn whole_input_findings_are_pinned() {
    for (input, secrets) in cases() {
        let (_, findings) = whole_input(&input);
        let ranges = otpauth_ranges(&findings);
        let mut expected = Vec::new();
        let mut from = 0;
        for secret in &secrets {
            let at =
                input[from..].find(&format!("secret={secret}")).unwrap() + from + "secret=".len();
            expected.push((at, at + secret.len()));
            from = at + secret.len();
        }
        assert_eq!(ranges, expected, "{input:?}");
    }
}

#[test]
fn every_byte_partition_reproduces_the_whole_input_result() {
    for (input, _) in cases() {
        let (expected_text, expected_findings) = whole_input(&input);
        let expected = otpauth_ranges(&expected_findings);
        let mut partitions = utf8_byte_partitions(&input);
        partitions.push(single_byte_partition(&input));
        for pieces in partitions {
            let session = run(&as_chunks(&pieces));
            assert_eq!(
                session.text(),
                expected_text,
                "{input:?}: text at {pieces:?}"
            );
            assert_eq!(
                otpauth_ranges(&session.findings()),
                expected,
                "{input:?}: findings at {pieces:?}"
            );
        }
    }
}

#[test]
fn dense_and_sparse_inputs_agree_between_whole_and_chunked_scans() {
    let filler = "The quick brown fox, request id 12345, status ok; path /var/log/app.log\n";
    let uri = format!("otpauth://totp/Example:alice@example.com?secret={SECRET}&issuer=Example\n");
    let sparse = format!("{}{uri}{}", filler.repeat(400), filler.repeat(400));
    let dense = uri.repeat(300);
    for input in [sparse, dense] {
        let (expected_text, expected_findings) = whole_input(&input);
        let expected = otpauth_ranges(&expected_findings);
        assert!(!expected.is_empty());
        for size in [1usize, 7, 64, 4_096] {
            let pieces: Vec<String> = input
                .as_bytes()
                .chunks(size)
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect();
            // ASCII input, so byte chunks are valid UTF-8 pieces.
            let session = run(&as_chunks(&pieces));
            assert_eq!(session.text(), expected_text, "chunk size {size}");
            assert_eq!(
                otpauth_ranges(&session.findings()),
                expected,
                "chunk size {size}"
            );
        }
    }
}
