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

// ---------------------------------------------------------------- #941

#[test]
fn issue_941_an_auth_token_assignment_is_redacted() {
    let token = synthetic(LOWER_HEX, 32, 11);
    let literal = synthetic(
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789",
        28,
        4,
    );
    for (input, value, type_name) in [
        (
            format!("[validator] twilio auth_token={token} status=ok\n"),
            token.clone(),
            "twilio_auth_token",
        ),
        (
            format!("config:\n  auth_token: \"{literal}\"\n"),
            literal.clone(),
            "contextual_secret",
        ),
    ] {
        let findings = findings_with_parity(&input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
        assert_eq!(span(&input, &findings[0]), value);
        assert_eq!(findings[0].type_name(), type_name);
        assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    }
    // Placeholder, reference and #911 identifier shapes stay silent, and the
    // twin with the gate renamed to a non-credential key stays silent too.
    for input in [
        "export TWILIO_AUTH_TOKEN=your_auth_token\n".to_owned(),
        "auth_token: ${AUTH_TOKEN}\n".to_owned(),
        "auth_token=TWILIO_AUTH_TOKEN\n".to_owned(),
        format!("[validator] cache etag={token} status=ok\n"),
    ] {
        let findings = findings_with_parity(&input);
        assert!(findings.is_empty(), "{input:?}: {findings:?}");
    }
}

// ---------------------------------------------------------------- #939

#[test]
fn issue_939_a_bearer_join_stops_before_the_next_record_field() {
    let token = synthetic(
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789",
        32,
        6,
    );
    for tail in ["|email=fixture@example.test", "|x=1", "|user: alice"] {
        let input = format!("Authorization: Bearer {token}{tail}\n");
        let findings = findings_with_parity(&input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
        assert_eq!(span(&input, &findings[0]), token, "{input:?}");
        let (text, _) = whole_input(&input);
        assert!(text.ends_with(&format!("{tail}\n")), "{text:?}");
        assert!(!text.contains(&token), "{text:?}");
    }
    // A logfmt record without a credential is untouched.
    let benign = "level=info msg=\"token refreshed\" user=alice|x=1 status=200\n";
    assert!(findings_with_parity(benign).is_empty());
}

#[test]
fn issue_939_a_bearer_name_at_host_value_is_covered_whole() {
    let input =
        "curl -H 'Authorization: Bearer svc-deploy-bot@ci.example.test' https://x.invalid\n";
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(span(input, &findings[0]), "svc-deploy-bot@ci.example.test");
    // A short local part stays below the floor: no finding, not a partial.
    assert!(findings_with_parity("Authorization: Bearer ops@example.test\n").is_empty());
}

// ---------------------------------------------------------------- #932

#[test]
fn issue_932_same_line_provider_forms_are_detected_through_the_pipeline() {
    let deepgram = synthetic(b"abcdefghijklmnopqrstuvwxyz0123456789", 40, 2);
    let cohere = synthetic(
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789",
        40,
        8,
    );
    for (input, value, type_name) in [
        (
            format!(
                "http --verbose POST https://api.deepgram.com/v1/listen model==nova-3 'Authorization:Token {deepgram}' < call.wav\n"
            ),
            deepgram.clone(),
            "deepgram_api_key",
        ),
        (
            format!(
                "package transcribe\n\nvar client = deepgram.NewRESTWithDefaults(context.Background(), \"{deepgram}\")\n"
            ),
            deepgram.clone(),
            "deepgram_api_key",
        ),
        (
            format!(
                "Cohere cohere = Cohere.builder().token(\"{cohere}\").clientName(\"search-api\").build();\n"
            ),
            cohere.clone(),
            "cohere_api_key",
        ),
    ] {
        let findings = findings_with_parity(&input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
        assert_eq!(span(&input, &findings[0]), value);
        assert_eq!(findings[0].type_name(), type_name, "{input:?}");
    }
    // Twins: another host, and a 39-byte value beside the same call.
    for input in [
        format!(
            "http POST https://api.example-speech.test/v1/listen 'Authorization:Token {deepgram}'\n"
        ),
        format!(
            "var client = deepgram.NewRESTWithDefaults(context.Background(), \"{}\")\n",
            &deepgram[..39]
        ),
    ] {
        let findings = findings_with_parity(&input);
        assert!(
            findings
                .iter()
                .all(|f| !f.type_name().starts_with("deepgram")),
            "{input:?}: {findings:?}"
        );
    }
}

// ---------------------------------------------------------------- #933

#[test]
fn issue_933_previous_line_provider_context_is_read_in_bounded_layouts() {
    let uuid = legacy_uuid();
    let twilio = synthetic(LOWER_HEX, 32, 13);
    let key_id = synthetic(b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 16, 1);
    let confluent = synthetic(
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789+/",
        64,
        5,
    );
    for (input, value, type_name) in [
        (
            format!(
                "$ heroku authorizations:info $AUTH_ID\nClient:      <none>\nDescription: ci deploy\nScope:       global\nToken:       {uuid}\nUpdated at:  2026-09-02T10:14:31Z\n"
            ),
            uuid.clone(),
            "heroku_api_key_legacy",
        ),
        (
            format!(
                "schema.registry.url=https://psrc-7q2x1.us-east-2.aws.confluent.cloud\nbasic.auth.credentials.source=USER_INFO\nbasic.auth.user.info={key_id}:{confluent}\n"
            ),
            confluent.clone(),
            "confluent_cloud_api_secret_legacy",
        ),
        (
            format!(
                "$ twilio profiles:list --properties authToken\nID     Auth Token\nprod   {twilio}\n"
            ),
            twilio.clone(),
            "twilio_auth_token",
        ),
    ] {
        let findings = findings_with_parity(&input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
        assert_eq!(span(&input, &findings[0]), value);
        assert_eq!(findings[0].type_name(), type_name, "{input:?}");
    }
    // Twins: the value row relabelled, another registry host, the column
    // relabelled.
    for input in [
        format!(
            "$ heroku authorizations:info $AUTH_ID\nScope:       global\nClient ID:   {uuid}\n"
        ),
        format!(
            "schema.registry.url=https://registry.example.test\nbasic.auth.user.info={key_id}:{confluent}\n"
        ),
        format!(
            "$ twilio profiles:list --properties authToken\nID     Account SID\nprod   {twilio}\n"
        ),
    ] {
        let findings = findings_with_parity(&input);
        assert!(
            findings.iter().all(|f| !matches!(
                f.type_name(),
                "heroku_api_key_legacy" | "confluent_cloud_api_secret_legacy" | "twilio_auth_token"
            )),
            "{input:?}: {findings:?}"
        );
    }
}
