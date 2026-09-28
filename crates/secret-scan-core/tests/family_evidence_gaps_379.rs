//! Product gaps found by the Beta.11 family-evidence corpus
//! (redact-secret-benchmarks#379), driven through the public default
//! pipeline. Each section names its issue.
//!
//! The benchmark issues carry fixture ids and offsets only; every input here
//! is independently re-authored for this test, and every credential-shaped
//! value is synthetic material built at run time, never provider-issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// `len` bytes cycled from `alphabet` with a stride, so the value is not a
/// run of one character and carries no provider marker of its own.
fn synthetic(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed) % alphabet.len()]))
        .collect()
}

const LOWER_HEX: &[u8] = b"0123456789abcdef";

/// Whole-input findings, and the same result under every two-chunk byte
/// partition and a line-per-chunk partition.
fn findings_with_parity(input: &str) -> Vec<Finding> {
    let (expected_text, expected) = whole_input(input);
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), expected_text, "{input:?}: {pieces:?}");
        assert_eq!(session.findings(), expected, "{input:?}: {pieces:?}");
    }
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let session = run(&lines);
    assert_eq!(session.text(), expected_text, "{input:?}: per line");
    assert_eq!(session.findings(), expected, "{input:?}: per line");
    expected
}

fn span(input: &str, finding: &Finding) -> String {
    input[finding.range().start()..finding.range().end()].to_owned()
}

// ---------------------------------------------------------------- #934

fn legacy_uuid() -> String {
    let hex = synthetic(LOWER_HEX, 32, 5);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[test]
fn issue_934_filler_placeholders_produce_no_finding() {
    for input in [
        "# release pipeline settings\nHEROKU_API_KEY=00000000-0000-0000-0000-000000000000\n"
            .to_owned(),
        "heroku token: ffffffff-ffff-ffff-ffff-ffffffffffff\n".to_owned(),
        format!(
            "# payments settings\nSTRIPE_SECRET_KEY=sk_test_{}\n",
            "x".repeat(24)
        ),
        format!("stripe key: sk_live_{}\n", "X".repeat(32)),
        format!("STRIPE_WEBHOOK_SECRET=whsec_{}\n", "0".repeat(32)),
    ] {
        let findings = findings_with_parity(&input);
        assert!(findings.is_empty(), "{input:?}: {findings:?}");
    }
}

#[test]
fn issue_934_real_shaped_twins_stay_redacted() {
    let uuid = legacy_uuid();
    let body = synthetic(
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789",
        24,
        3,
    );
    for (input, value) in [
        (
            format!("# release pipeline settings\nHEROKU_API_KEY={uuid}\n"),
            uuid.clone(),
        ),
        (
            format!("# payments settings\nSTRIPE_SECRET_KEY=sk_test_{body}\n"),
            format!("sk_test_{body}"),
        ),
    ] {
        let findings = findings_with_parity(&input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
        assert_eq!(span(&input, &findings[0]), value);
        assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    }
}

// ---------------------------------------------------------------- #935

#[test]
fn issue_935_a_driver_qualified_sql_url_password_is_redacted() {
    let password = synthetic(
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789",
        22,
        9,
    );
    for scheme in ["postgresql+psycopg", "postgres+asyncpg", "mysql+pymysql"] {
        for host in ["db.example.test:5432", "[2001:db8::5]:5432"] {
            let input = format!(
                "engine = create_engine(\"{scheme}://report:{password}@{host}/reports\")\n"
            );
            let findings = findings_with_parity(&input);
            assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
            assert_eq!(span(&input, &findings[0]), password);
            assert_eq!(findings[0].type_name(), "connection_string_password");
            assert_eq!(findings[0].action(), Action::Redact);
        }
    }
    // Benign twins: no password, a reference password, a driver on an
    // unsupported scheme.
    for input in [
        "engine = create_engine(\"postgresql+psycopg://report@db.example.test/reports\")\n".to_owned(),
        "engine = create_engine(\"postgresql+psycopg://report:${DB_PASSWORD}@db.example.test/r\")\n"
            .to_owned(),
        format!("broker = \"redis+sentinel://report:{password}@cache.example.test/0\"\n"),
    ] {
        let findings = findings_with_parity(&input);
        assert!(findings.is_empty(), "{input:?}: {findings:?}");
    }
}
