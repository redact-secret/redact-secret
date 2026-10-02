//! Issue #1164: the JWT detector now jumps to each exact `eyJ` instead of
//! testing three bytes at every offset. The unit tests in `detectors/jwt.rs`
//! compare candidates with the old per-byte scan; this file pins the public
//! whole-input findings (ranges and detector id) and checks that every byte
//! partition of the incremental surface reproduces the whole-input result for
//! sparse, dense, prefix-noise, malformed, blocked and Unicode-neighbour
//! inputs. All values are synthetic and revoked-looking.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{as_chunks, run, single_byte_partition, utf8_byte_partitions, whole_input};

const SIG: &str = "SYNTHETIC_REVOKED_SIGNATURE";

fn good() -> String {
    format!("eyJTYNTH.eyJSYNTHETIC.{SIG}")
}

/// Byte ranges of the `jwt` findings, in report order.
fn jwt_ranges(findings: &[redact_secret::Finding]) -> Vec<(usize, usize)> {
    findings
        .iter()
        .filter(|finding| finding.detector() == "jwt")
        .map(|finding| (finding.range().start(), finding.range().end()))
        .collect()
}

/// (input, number of expected jwt findings)
fn cases() -> Vec<(String, usize)> {
    let g = good();
    vec![
        (g.clone(), 1),
        (format!("Authorization: Bearer {g}\n"), 1),
        (format!("{g}\n{g}\n"), 2),
        (format!("log \u{d55c}\u{1f600} {g}\r\n"), 1),
        // Glued to a preceding token byte: blocked, then the next one is found.
        (format!("x{g} {g}"), 1),
        (format!("{g}. {g}"), 1),
        (format!("{g}.{g}"), 0),
        // Failed attempts advance by one byte.
        (format!("eyJTYNTH.eyJTYNTH.{g}"), 0),
        (format!("eyJeyJeyJ {g}"), 1),
        (format!("eyJTYNTH.eyJSYNTHETIC.SHORT {g}"), 1),
        ("eyJ eyJ. eyJ.eyJ. eyJ.eyJ.eyJ".to_owned(), 0),
    ]
}

#[test]
fn whole_input_findings_are_pinned() {
    let g = good();
    let (_, findings) = whole_input(&format!("x {g}\n{g}"));
    assert_eq!(
        jwt_ranges(&findings),
        vec![(2, 2 + g.len()), (3 + g.len(), 3 + 2 * g.len())]
    );
    for (input, expected) in cases() {
        let (_, findings) = whole_input(&input);
        assert_eq!(jwt_ranges(&findings).len(), expected, "{input:?}");
    }
}

#[test]
fn every_byte_partition_reproduces_the_whole_input_result() {
    for (input, _) in cases() {
        let (expected_text, expected_findings) = whole_input(&input);
        let expected = jwt_ranges(&expected_findings);
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
                jwt_ranges(&session.findings()),
                expected,
                "{input:?}: findings at {pieces:?}"
            );
        }
    }
}

#[test]
fn dense_sparse_and_noise_inputs_agree_between_whole_and_chunked_scans() {
    let g = good();
    let filler = "The quick brown fox, request id 12345, status ok; path /var/log/app.log\n";
    let sparse = format!("{}{g}\n{}", filler.repeat(400), filler.repeat(400));
    let dense = format!("{g}\n").repeat(300);
    let noise = format!("{}{g}\n", "eyJ ".repeat(2000));
    let malformed = format!("{}{g}\n", "eyJTYNTH.eyJ\n".repeat(500));
    for input in [sparse, dense, noise, malformed] {
        let (expected_text, expected_findings) = whole_input(&input);
        let expected = jwt_ranges(&expected_findings);
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
                jwt_ranges(&session.findings()),
                expected,
                "chunk size {size}"
            );
        }
    }
}
